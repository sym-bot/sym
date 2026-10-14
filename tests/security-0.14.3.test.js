'use strict';

process.env.SYM_SEMANTIC_ENCODER = process.env.SYM_SEMANTIC_ENCODER || 'off';
require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * The 0.14.3 security review (R2): each finding fixed here as a regression test that fails on the
 * 0.14.3 base (632b95d) for its own reason.
 *
 *   R2-1   a delegating grant, even a scoped one, bound any unbound nodeId to its holder's key
 *   R2-2   a relay editing a sealed record's clear metadata got an honest peer banned as a forger
 *   R2-3   one admitted peer's large records cost CPU, memory and disk without bound
 *   R2-6   actionable room records were de-duplicated by cognition key, not assertion identity
 *   R2-9   durable key bindings earned by one record never aged out, and nothing capped a source
 *   R2-22  the delivery ledger was never pruned
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const A = require('../lib/core/authority');
const { identity, connectNodes, admitAs, deliver, signedRecord, applicationFor, until } = require('./_core-secure');

const uniq = (b) => `${b}-${process.pid}-${Math.random().toString(36).slice(2, 7)}`;
const made = [];
function mk(base, extra = {}) {
  const n = new SymNode({ name: uniq(base), silent: true, discovery: new NullDiscovery(), room: 'sec', ...extra });
  made.push(n);
  return n;
}
async function stopAll() {
  for (const n of made.splice(0)) {
    try { await n.stop(); } catch { /* */ }
    try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ }
  }
}
const sign = (byId, by, fields) => A.signStatement({ ...fields, authorisedBy: byId, nonce: A.freshNonce(), sigs: [] }, by.privateKey, by.publicKey);

describe('R2-1: a grant binds a key only when it is unscoped and its chain is the anchor and admins', () => {
  const anchor = identity('anchor');
  const PIN = { threshold: 1, keys: [{ key: anchor.publicKey }] };

  it('R2-1: a scoped issuer seating one world binds no key: the victim nodeId stays unbound, a record forged in its name is not verified, and the victim connects', async () => {
    try {
      const R = mk('r21-recv', { anchor: PIN });
      const V = mk('r21-victim', { anchor: PIN });
      const I = identity('issuer');
      const gI = sign('anchor', anchor, { kind: 'grant', subject: { nodeId: I.nodeId, key: I.publicKey }, role: 'issuer', scope: 'xmesh-world:w1' });
      const gSquat = sign(A.statementId(gI), I, { kind: 'grant', subject: { nodeId: V.nodeId, key: I.publicKey }, role: 'participant', scope: 'xmesh-world:w1' });
      assert.strictEqual(R.submitAuthority(gI).status, 'in-force');
      assert.strictEqual(R.submitAuthority(gSquat).status, 'in-force', 'the scoped grant is in force (it confers its role in its scope)');
      assert.strictEqual(R._identityKey(V.nodeId), undefined, 'but binds no key for the victim nodeId');
      assert.strictEqual(R._keySource(V.nodeId), undefined);
      const sess = admitAs(R, { nodeId: I.nodeId, name: 'issuer', publicKey: I.publicKey });
      let accepted = null;
      R.on('verified-record', (e) => { accepted = e; });
      deliver(R, sess, { type: 'cmb', timestamp: Date.now(), cmb: signedRecord({ nodeId: V.nodeId, name: 'victim', privateKey: I.privateKey }, { categories: { focus: 'forged in the victim name' }, room: 'sec' }) });
      await until(() => accepted, 300);
      assert.strictEqual(accepted, null, 'a record in the victim\'s name signed by the issuer key is not verified');
      await connectNodes(V, R, { timeoutMs: 3000 });
      assert.ok(R._peers.has(V.nodeId), 'the victim\'s own session is admitted');
    } finally { await stopAll(); }
  });

  it('R2-1: an unscoped grant under an issuer (not an admin) binds no key either; one under the anchor or an admin does', async () => {
    try {
      const R = mk('r21-chain', { anchor: PIN });
      const I = identity('issuer'); const Ad = identity('admin');
      const x = identity('x'); const y = identity('y'); const z = identity('z');
      const gI = sign('anchor', anchor, { kind: 'grant', subject: { nodeId: I.nodeId, key: I.publicKey }, role: 'issuer' });
      const gAd = sign('anchor', anchor, { kind: 'grant', subject: { nodeId: Ad.nodeId, key: Ad.publicKey }, role: 'admin' });
      for (const s of [gI, gAd,
        sign(A.statementId(gI), I, { kind: 'grant', subject: { nodeId: x.nodeId, key: x.publicKey }, role: 'participant' }),
        sign(A.statementId(gAd), Ad, { kind: 'grant', subject: { nodeId: y.nodeId, key: y.publicKey }, role: 'participant' }),
        sign('anchor', anchor, { kind: 'grant', subject: { nodeId: z.nodeId, key: z.publicKey }, role: 'validator' })]) {
        assert.strictEqual(R.submitAuthority(s).status, 'in-force');
      }
      assert.strictEqual(R._identityKey(x.nodeId), undefined, 'issuer-chained: no binding');
      assert.strictEqual(R._identityKey(y.nodeId), y.publicKey, 'admin-chained, unscoped: a binding (a view)');
      assert.strictEqual(R._identityKey(z.nodeId), z.publicKey, 'anchor-issued, unscoped: a binding');
      assert.strictEqual(R._identityKey(I.nodeId), I.publicKey);
    } finally { await stopAll(); }
  });

  it('R2-1: a grant view never refuses a proving session: the session is admitted and the conflict recorded', async () => {
    try {
      const R = mk('r21-norefuse', { anchor: PIN });
      const V = mk('r21-victim2', { anchor: PIN });
      const evil = identity('evil');
      const g = sign('anchor', anchor, { kind: 'grant', subject: { nodeId: V.nodeId, key: evil.publicKey }, role: 'participant' });
      assert.strictEqual(R.submitAuthority(g).status, 'in-force');
      assert.strictEqual(R._identityKey(V.nodeId), evil.publicKey, 'the scene: the view names another key');
      await connectNodes(V, R, { timeoutMs: 3000 });
      assert.ok(R._peers.has(V.nodeId), 'admitted on its own proof');
      assert.strictEqual(R._identityKey(V.nodeId), V._identity.publicKey, 'its proven key verifies, not the view\'s');
      assert.ok(R._roster.conflicts().some((c) => c.nodeId === V.nodeId && c.hadSource === 'grant' && c.got === V._identity.publicKey), 'the disagreement is recorded');
    } finally { await stopAll(); }
  });

  it('R2-1: a session proving the key a grant names is never promoted to proven; a revoke removes what the grant bound', async () => {
    try {
      const R = mk('r21-sticky', { anchor: PIN });
      const V = mk('r21-victim3', { anchor: PIN });
      const S = mk('r21-squatter', { anchor: PIN });
      S.nodeId = V.nodeId; if (S._identity) S._identity.nodeId = V.nodeId;
      const Ad = identity('admin');
      const gAd = sign('anchor', anchor, { kind: 'grant', subject: { nodeId: Ad.nodeId, key: Ad.publicKey }, role: 'admin' });
      const gSquat = sign(A.statementId(gAd), Ad, { kind: 'grant', subject: { nodeId: V.nodeId, key: S._identity.publicKey }, role: 'participant' });
      R.submitAuthority(gAd); R.submitAuthority(gSquat);
      assert.strictEqual(R._roster.source(V.nodeId), 'grant');
      await connectNodes(S, R, { timeoutMs: 3000 });
      assert.notStrictEqual(R._roster.source(V.nodeId), 'proven', 'never promoted to proven');
      assert.strictEqual(R._roster.durable(V.nodeId), undefined, 'nothing stored');
      assert.strictEqual(R.submitAuthority(sign('anchor', anchor, { kind: 'revoke', targets: [A.statementId(gAd)] })).status, 'in-force');
      for (const s of [...R._sessions]) s.close('test');
      await new Promise((r) => setTimeout(r, 100));
      assert.strictEqual(R._roster.source(V.nodeId), undefined, 'the revoke removed what the grant bound');
      await connectNodes(V, R, { timeoutMs: 3000 });
      assert.ok(R._peers.has(V.nodeId) && R._peers.get(V.nodeId).identityKey === V._identity.publicKey, 'the real owner of the nodeId connects');
    } finally { await stopAll(); }
  });
});

describe('R2-2: a record whose signed bytes the AEAD did not authenticate is dropped and counted, never charged', () => {
  const CATS = (focus) => ({ focus, issue: 'x', intent: 'y', motivation: 'z', commitment: 'none', perspective: 'p', mood: { text: 'calm', valence: 0, arousal: 0 } });
  for (const [what, edit] of [
    ['createdBy', (m) => { m.createdBy += 'X'; }],
    ['createdTimestamp', (m) => { m.createdTimestamp += 1; }],
    ['the signature', (m) => { m.sig = (m.sig[0] === 'A' ? 'B' : 'A') + m.sig.slice(1); }],
  ]) {
    it(`R2-2: a relay editing ${what} in a sealed record's clear metadata cannot get the honest sender closed or refused`, async () => {
      try {
        const a = mk('r22-a'); const b = mk('r22-b');
        const metrics = []; b.on('metric', (m) => metrics.push(m));
        await a.start(); await b.start();
        let tampered = 0;
        await connectNodes(a, b, { kind: 'relay', tap: (f, dir) => {
          if (dir === 'a→b' && f.type === 'cmb-encrypted' && f.metadata && f.metadata.createdBy) { edit(f.metadata); tampered++; }
        } });
        a.remember(CATS(`an honest observation from a (${what})`));
        await until(() => metrics.some((m) => m.type === 'cmb-signature-rejected'), 3000);
        assert.ok(tampered >= 1, 'the scene: the relay altered the frame');
        assert.ok(metrics.some((m) => m.type === 'cmb-signature-rejected'), 'the altered record is refused');
        assert.ok(!metrics.some((m) => m.type === 'forged-signature'), 'and nobody is called a forger');
        assert.ok(b._peers.has(a.nodeId), 'the honest peer keeps its session');
        assert.strictEqual(b._penalised(a.nodeId), false, 'and is not refused admission');
        if (what !== 'the signature') assert.ok(metrics.some((m) => m.type === 'cmb-clear-metadata-altered'), 'the assertion identity is checked first (§8.8.5)');
      } finally { await stopAll(); }
    });
  }
});
