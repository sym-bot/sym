'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * MMP §18.3.2 at every signature check sym makes. The vector cases are in authority-vectors.test.js;
 * this file shows that each verification site uses the one rule, by handing it two signatures that
 * Node's own crypto.verify (OpenSSL's cofactorless check) ACCEPTS and the rule rejects:
 *
 *   - the universal forgery: the identity point as the key, R = the identity, S = 0. It verifies any
 *     message under crypto.verify; nobody holds a private key for it.
 *   - an odd signature by a real key: R = the identity, S = k·a (a the key's secret scalar). The key
 *     is honest and prime order; R is not of prime order. A signer can make it for any message, and
 *     a verifier that accepts it holds a different valid set from one that does not.
 *
 * And a structural guard: no crypto.verify outside lib/core/ed25519.js.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { verifyStrict, L } = require('../lib/core/ed25519');
const core = require('../lib/core');
const handshake = require('../lib/core/handshake-v2');
const roomGrant = require('../lib/core/room-grant');
const tether = require('../lib/core/tether-attestation');
const A = require('../lib/core/authority');
const { AuthorityStore } = require('../lib/authority-store');
const { identity, signedRecord } = require('./_core-secure');

const SPKI = Buffer.from('302a300506032b6570032100', 'hex');
const IDENTITY = Buffer.concat([Buffer.from([1]), Buffer.alloc(31)]);
const UNIVERSAL_KEY = IDENTITY.toString('base64url');
const UNIVERSAL_SIG = Buffer.concat([IDENTITY, Buffer.alloc(32)]).toString('base64url');

const leToBig = (b) => { let n = 0n; for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]); return n; };
const bigToLe = (n, len) => { const b = Buffer.alloc(len); for (let i = 0; i < len; i++) { b[i] = Number(n & 0xffn); n >>= 8n; } return b; };

/** R = identity, S = k·a mod L: what crypto.verify accepts from the holder of `privateKey` for any message. */
function oddSign(message, privateKeyB64url, publicKeyB64url) {
  const h = crypto.createHash('sha512').update(Buffer.from(privateKeyB64url, 'base64url')).digest();
  const s = Buffer.from(h.subarray(0, 32)); s[0] &= 248; s[31] &= 127; s[31] |= 64;
  const a = leToBig(s) % L;
  const k = leToBig(crypto.createHash('sha512').update(IDENTITY).update(Buffer.from(publicKeyB64url, 'base64url')).update(message).digest()) % L;
  return Buffer.concat([IDENTITY, bigToLe((k * a) % L, 32)]).toString('base64url');
}
/** Node's own check, with no pre-checks: what a verifier that skipped §18.3.2 would say. */
function lenient(message, keyB64url, sigB64url) {
  const key = crypto.createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(keyB64url, 'base64url')]), format: 'der', type: 'spki' });
  return crypto.verify(null, message, key, Buffer.from(sigB64url, 'base64url'));
}

describe('§18.3.2: the forgeries this file uses are accepted by crypto.verify, rejected by the rule', () => {
  it('the universal forgery verifies any message under crypto.verify', () => {
    for (const m of ['one', 'two', crypto.randomBytes(40).toString('hex')]) {
      assert.strictEqual(lenient(Buffer.from(m), UNIVERSAL_KEY, UNIVERSAL_SIG), true);
      assert.strictEqual(verifyStrict(Buffer.from(m), UNIVERSAL_KEY, UNIVERSAL_SIG), false);
    }
  });
  it('an odd signature by a real key verifies under crypto.verify, and an honest one under both', () => {
    const id = identity('odd');
    const m = Buffer.from('any message at all');
    const odd = oddSign(m, id.privateKey, id.publicKey);
    assert.strictEqual(lenient(m, id.publicKey, odd), true);
    assert.strictEqual(verifyStrict(m, id.publicKey, odd), false);
    const honest = crypto.sign(null, m, crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(id.privateKey, 'base64url')]), format: 'der', type: 'pkcs8' })).toString('base64url');
    assert.strictEqual(verifyStrict(m, id.publicKey, honest), true);
  });
});

describe('§18.3.2 at every verification site in sym', () => {
  const id = identity('signer');
  /** Each site: an honest signed object, its signed bytes, and the verdict function. */
  const sites = {
    'records (verifyCMB, v2.0 suite)': () => {
      const cmb = signedRecord(id);
      return { obj: cmb, bytes: () => core.signingPayloadV2_0(cmb), set: (sig) => { cmb.metadata.sig = sig; }, ok: () => core.verifyCMB(cmb, id.publicKey).valid };
    },
    'handshake proofs (verifyProof)': () => {
      const transcript = crypto.randomBytes(64);
      let proof = handshake.signProof('client', transcript, id.privateKey);
      return { bytes: () => handshake.proofPayload('client', transcript), set: (sig) => { proof = sig; }, ok: () => handshake.verifyProof('client', transcript, proof, id.publicKey) };
    },
    'attestations (verifyAttestation)': () => {
      const att = core.signAttestation({ of: 'cmb-' + 'a'.repeat(64), by: id.nodeId, at: 1, roster: 'default', verdict: 'aligned', categories: {}, seq: 1, prev: 'genesis', role: 'participant', method: 'svaf' }, id.privateKey);
      return { bytes: () => core.attestationPayload(att), set: (sig) => { att.sig = sig; }, ok: () => core.verifyAttestation(att, id.publicKey).valid };
    },
    'checkpoints (verifyCheckpoint)': () => {
      const cp = core.signCheckpoint({ by: id.nodeId, roster: 'default', uptoSeq: 3, root: 'r'.repeat(64), at: 1 }, id.privateKey);
      return { bytes: () => core.checkpointPayload(cp), set: (sig) => { cp.sig = sig; }, ok: () => core.verifyCheckpoint(cp, id.publicKey).valid };
    },
    'witnesses (verifyWitness)': () => {
      const w = core.signWitness({ attester: id.nodeId, by: id.nodeId, roster: 'default', uptoSeq: 3, root: 'r'.repeat(64), role: 'participant', at: 1 }, id.privateKey);
      return { bytes: () => core.witnessPayload(w), set: (sig) => { w.sig = sig; }, ok: () => core.verifyWitness(w, id.publicKey).valid };
    },
    'room-join grants (verifyRoomGrant)': () => {
      const grantee = identity('grantee');
      const g = roomGrant.signRoomGrant({ room: 'gated-room', grantee: grantee.nodeId, granteeKey: grantee.publicKey, grantedBy: id.nodeId }, id.privateKey);
      return { bytes: () => roomGrant.roomGrantPayload(g), set: (sig) => { g.sig = sig; }, ok: () => roomGrant.verifyRoomGrant(g, id.publicKey, { room: 'gated-room', grantee: grantee.nodeId, provenKey: grantee.publicKey }).ok };
    },
    'tether attestations (verifyTetherAttestation)': () => {
      const t = tether.signTetherAttestation({ of: 'cmb-' + 'b'.repeat(64), anchor: 'cmb-' + 'c'.repeat(64), kernelId: 'k1', drift: 0.1, verdict: 'tethered', by: id.nodeId, at: 1 }, id.privateKey);
      return { bytes: () => tether.tetherPayload(t), set: (sig) => { t.sig = sig; }, ok: () => tether.verifyTetherAttestation(t, id.publicKey).valid };
    },
    'authority statements (MMP §6.6, a pinned single-key anchor)': () => {
      let s = A.signStatement({ kind: 'grant', authorisedBy: 'anchor', subject: { nodeId: '018f47a0-7b21-7abc-8def-0000000000b1', key: identity('x').publicKey }, role: 'validator', nonce: A.freshNonce() }, id.privateKey, id.publicKey);
      const store = () => new AuthorityStore({ pin: A.parsePin({ threshold: 1, keys: [{ key: id.publicKey }] }) });
      return { bytes: () => A.payload(s), set: (sig) => { s = { ...s, sigs: [{ key: id.publicKey, sig }] }; }, ok: () => store().ingest(s).result === 'held' };
    },
  };
  for (const [name, make] of Object.entries(sites)) {
    it(name, () => {
      const site = make();
      assert.strictEqual(site.ok(), true, 'the honest signature verifies');
      const odd = oddSign(site.bytes(), id.privateKey, id.publicKey);
      assert.strictEqual(lenient(site.bytes(), id.publicKey, odd), true, 'crypto.verify alone would accept the odd signature');
      site.set(odd);
      assert.strictEqual(site.ok(), false, 'sym rejects it');
    });
  }

  it('records and authority statements under the universal key are rejected too', () => {
    const cmb = signedRecord(id);
    cmb.metadata.sig = UNIVERSAL_SIG;
    assert.strictEqual(lenient(core.signingPayloadV2_0(cmb), UNIVERSAL_KEY, UNIVERSAL_SIG), true);
    assert.strictEqual(core.verifyCMB(cmb, UNIVERSAL_KEY).valid, false);
    // A pin naming the identity point is refused outright (§6.6.1: a pinned key is of prime order).
    assert.throws(() => A.parsePin({ threshold: 1, keys: [{ key: UNIVERSAL_KEY }] }));
    // A grant naming the identity point as its subject key is not well formed: nothing it signs can count.
    const s = A.signStatement({ kind: 'grant', authorisedBy: 'anchor', subject: { nodeId: '018f47a0-7b21-7abc-8def-0000000000b2', key: UNIVERSAL_KEY }, role: 'admin', nonce: A.freshNonce() }, id.privateKey, id.publicKey);
    const store = new AuthorityStore({ pin: A.parsePin({ threshold: 1, keys: [{ key: id.publicKey }] }) });
    assert.strictEqual(store.ingest(s).result, 'invalid');
  });

  it('relocation: a bundle header carrying an odd signature is refused', async () => {
    const { SymNode } = require('../lib/node');
    const { NullDiscovery } = require('../lib/discovery');
    const relocation = require('../lib/relocation');
    const name = `strict-reloc-${Date.now().toString(36)}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    const nodeId = node.nodeId; const pub = node._identity.publicKey; const priv = node._identity.privateKey;
    await node.stop();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bundle-'));
    const out = path.join(dir, 'node.bundle');
    relocation.exportNode({ name, out, passphrase: 'a long operator passphrase', copyable: true });
    const bundle = JSON.parse(fs.readFileSync(out, 'utf8'));
    const { ciphertext, nonce, headerSig, ...header } = bundle;
    void ciphertext; void nonce; void headerSig;
    const bytes = Buffer.from(`sym-node-bundle-v1-header\n${Object.keys(header).sort().map((k) => `${k}=${header[k]}`).join('\n')}`, 'utf8');
    assert.strictEqual(verifyStrict(bytes, pub, bundle.headerSig), true, 'the test rebuilds the header\'s signed bytes');
    const odd = oddSign(bytes, priv, pub);
    assert.strictEqual(lenient(bytes, pub, odd), true);
    const forged = path.join(dir, 'odd.bundle');
    fs.writeFileSync(forged, JSON.stringify({ ...bundle, headerSig: odd }));
    assert.throws(() => relocation.importNode({ from: forged, passphrase: 'a long operator passphrase', expect: { nodeId, key: pub } }), /header is not signed/);
  });

  it('no crypto.verify outside lib/core/ed25519.js', () => {
    const root = path.join(__dirname, '..');
    const offenders = [];
    const walk = (dir) => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const p = path.join(dir, e.name);
        if (e.isDirectory()) walk(p);
        else if (/\.(c|m)?js$/.test(e.name) && p !== path.join(root, 'lib', 'core', 'ed25519.js')) {
          const text = fs.readFileSync(p, 'utf8');
          if (/crypto\.verify\s*\(|createVerify\s*\(|\.verify\(null,/.test(text)) offenders.push(path.relative(root, p));
        }
      }
    };
    walk(path.join(root, 'lib'));
    walk(path.join(root, 'bin'));
    assert.deepStrictEqual(offenders, []);
  });
});
