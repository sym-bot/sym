'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * Design D9 — what sym gives cognitive nodes:
 *   1. identities addressed by nodeId (nodes/by-id/<nodeId>/, the name an index), loaded without
 *      minting (`create: false` throws when absent), a one-time idempotent move of the 0.13 layout
 *      that leaves `nodes/<name>` as a symlink for one release;
 *   2. relocation, not copying: export tombstones the source first, and import verifies against an
 *      independently pinned key, refusing a re-keyed bundle;
 *   3. the interior submission path: a per-mind capability, the node's checks, one mind per node.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const config = require('../lib/config');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const relocation = require('../lib/relocation');
const { keyFingerprint } = require('../lib/roster-keys');
const { until, identity } = require('./_core-secure');

const uniq = (b) => `${b}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;

describe('identities by nodeId (D9.1)', () => {
  it('create: false on a missing identity throws, and mints nothing', () => {
    const name = uniq('id-missing');
    assert.throws(() => config.loadIdentity({ name, create: false }), (e) => e.code === 'EIDENTITYABSENT');
    assert.throws(() => config.loadIdentity({ nodeId: config.uuidv7(), create: false }), (e) => e.code === 'EIDENTITYABSENT');
    assert.strictEqual(config.nodeIdForName(name), null, 'no index was written');
    assert.throws(() => new SymNode({ name, create: false, silent: true, discovery: new NullDiscovery() }), (e) => e.code === 'EIDENTITYABSENT');
  });

  it('a new agent lives at nodes/by-id/<nodeId>, indexed by name, with nodes/<name> as a link for 0.13', () => {
    const name = uniq('id-new');
    const id = config.loadIdentity({ name });
    const dir = config.nodeDirById(id.nodeId);
    assert.ok(fs.existsSync(path.join(dir, 'identity.json')));
    assert.strictEqual(config.nodeIdForName(name), id.nodeId);
    const link = path.join(config.NODES_DIR, name);
    assert.ok(fs.lstatSync(link).isSymbolicLink());
    assert.strictEqual(fs.realpathSync(link), fs.realpathSync(dir));
    assert.deepStrictEqual(config.loadIdentity({ name, create: false }), id, 'loaded, not minted');
    assert.deepStrictEqual(config.loadIdentity({ nodeId: id.nodeId, create: false }), id);
    // Renaming changes the index, never the identity.
    const other = uniq('id-renamed');
    assert.strictEqual(config.renameIdentity(name, other), id.nodeId);
    assert.strictEqual(config.loadIdentity({ name: other, create: false }).nodeId, id.nodeId);
    assert.throws(() => config.loadIdentity({ name, create: false }), (e) => e.code === 'EIDENTITYABSENT');
  });

  it('a 0.13 node dir is moved once, idempotently, and a 0.13 reader still finds it at the old path', () => {
    const name = uniq('id-legacy');
    const legacy = path.join(config.NODES_DIR, name);
    fs.mkdirSync(path.join(legacy, 'cmbs'), { recursive: true });
    const kp = crypto.generateKeyPairSync('ed25519');
    const ident = {
      nodeId: config.uuidv7(), name, hostname: 'h.local', createdAt: 1,
      publicKey: kp.publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('base64url'),
      privateKey: kp.privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(16).toString('base64url'),
    };
    fs.writeFileSync(path.join(legacy, 'identity.json'), JSON.stringify(ident));
    fs.writeFileSync(path.join(legacy, 'cmbs', 'x.json'), '{}');
    const r1 = config.migrateIdentities();
    assert.ok(r1.moved >= 1);
    assert.ok(fs.lstatSync(legacy).isSymbolicLink(), 'the old path is a link');
    assert.ok(fs.existsSync(path.join(config.nodeDirById(ident.nodeId), 'cmbs', 'x.json')), 'the store moved with it');
    // What a 0.13 reader does: read nodes/<name>/identity.json.
    assert.strictEqual(JSON.parse(fs.readFileSync(path.join(legacy, 'identity.json'), 'utf8')).nodeId, ident.nodeId);
    const r2 = config.migrateIdentities();
    assert.strictEqual(r2.moved, 0, 'idempotent');
    assert.strictEqual(config.loadIdentity({ name, create: false }).publicKey, ident.publicKey, 'the same key: identity files do not change');
  });
});

describe('relocation (D9.2)', () => {
  it('export tombstones the source before the bundle exists; the source then refuses to start it; import verifies against a pinned key', async () => {
    const name = uniq('id-move');
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    const nodeId = node.nodeId;
    const pub = node._identity.publicKey;
    node.remember({ focus: 'a memory that must travel', issue: 'i', intent: 'x', motivation: 'y', commitment: 'z', perspective: 'p', mood: { text: 'calm', valence: 0, arousal: 0 } });
    await node.stop();
    const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'bundle-')), 'node.bundle');
    assert.throws(() => relocation.exportNode({ name, out }), /passphrase/, 'no sealing given: refused, and not tombstoned');
    assert.strictEqual(config.readTombstone(nodeId), null);
    const r = relocation.exportNode({ name, out, passphrase: 'a long operator passphrase' });
    assert.strictEqual(r.nodeId, nodeId);
    assert.ok(config.readTombstone(nodeId), 'tombstoned');
    assert.ok(!fs.readFileSync(out, 'utf8').includes(node._identity.privateKey), 'the private key is not in the clear');
    assert.throws(() => new SymNode({ name, silent: true, discovery: new NullDiscovery() }), (e) => e.code === 'EIDENTITYTOMBSTONED', 'the source refuses to start it');
    // Import: the wrong passphrase does not open it; no pin refuses it; the pinned key admits it.
    assert.throws(() => relocation.importNode({ from: out, passphrase: 'not the passphrase at all' }), /does not open/);
    const imported = relocation.importNode({ from: out, passphrase: 'a long operator passphrase', expect: { nodeId, fingerprint: keyFingerprint(pub) } });
    assert.strictEqual(imported.nodeId, nodeId);
    assert.strictEqual(config.readTombstone(nodeId), null, 'it lives here again');
    const back = new SymNode({ name, nodeId, create: false, silent: true, discovery: new NullDiscovery() });
    try {
      assert.strictEqual(back._identity.publicKey, pub);
      const files = fs.readdirSync(path.join(config.nodeDirById(nodeId), 'cmbs')).filter((f) => f.endsWith('.json'));
      assert.ok(files.length >= 1, 'its store came with it');
    } finally { await back.stop(); }
  });

  it('an import with a re-signed key is refused, and one with no independent pin is refused', async () => {
    const name = uniq('id-rekey');
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    const nodeId = node.nodeId;
    const realPub = node._identity.publicKey;
    await node.stop();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bundle-'));
    const out = path.join(dir, 'node.bundle');
    relocation.exportNode({ name, out, passphrase: 'a long operator passphrase' });
    // An attacker re-keys the identity in a copy of the bundle (they cannot sign as the node).
    const { importNode } = relocation;
    const tampered = path.join(dir, 'rekeyed.bundle');
    {
      const crypto2 = require('crypto');
      const b = JSON.parse(fs.readFileSync(out, 'utf8'));
      const key = crypto2.scryptSync('a long operator passphrase', Buffer.from(b.salt, 'base64url'), 32, { N: b.N, r: b.r, p: b.p, maxmem: 128 * 1024 * 1024 });
      const sealed = Buffer.from(b.ciphertext, 'base64url');
      const d = crypto2.createDecipheriv('aes-256-gcm', key, Buffer.from(b.nonce, 'base64url'));
      d.setAuthTag(sealed.subarray(sealed.length - 16));
      const plain = JSON.parse(Buffer.concat([d.update(sealed.subarray(0, sealed.length - 16)), d.final()]).toString('utf8'));
      const evil = identity('evil');
      for (const f of plain.files) {
        if (f.path !== 'identity.json') continue;
        const ident = JSON.parse(Buffer.from(f.data, 'base64').toString('utf8'));
        f.data = Buffer.from(JSON.stringify({ ...ident, publicKey: evil.publicKey, privateKey: evil.privateKey })).toString('base64');
      }
      const nonce = crypto2.randomBytes(12);
      const c = crypto2.createCipheriv('aes-256-gcm', key, nonce);
      const body = Buffer.concat([c.update(Buffer.from(JSON.stringify(plain))), c.final()]);
      fs.writeFileSync(tampered, JSON.stringify({ ...b, nonce: nonce.toString('base64url'), ciphertext: Buffer.concat([body, c.getAuthTag()]).toString('base64url') }));
    }
    assert.throws(() => importNode({ from: tampered, passphrase: 'a long operator passphrase', expect: { nodeId, key: realPub } }), /re-keyed bundle/);
    assert.throws(() => importNode({ from: out, passphrase: 'a long operator passphrase' }), /no independently pinned key/);
  });

  it('a bundle can be sealed to the target host\'s key instead of a passphrase', async () => {
    const name = uniq('id-host');
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    const nodeId = node.nodeId; const pub = node._identity.publicKey;
    await node.stop();
    const host = relocation.hostKey();
    const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'bundle-')), 'node.bundle');
    relocation.exportNode({ name, out, toHostKey: host.publicKey });
    const r = relocation.importNode({ from: out, expect: { nodeId, key: pub } });
    assert.strictEqual(r.nodeId, nodeId);
  });
});

describe('the interior (D9.3)', () => {
  function cats(focus) { return { focus, issue: 'i', intent: 'x', motivation: 'y', commitment: 'z', perspective: 'p', mood: { text: 'calm' } }; }

  it('a submission without a live capability is refused; the node checks audience, size, rate, intent and lineage before it signs', async () => {
    const node = new SymNode({ name: uniq('id-mind'), silent: true, discovery: new NullDiscovery() });
    try {
      const interior = node.interior();
      assert.deepStrictEqual(interior.submit('no-such-capability', { kind: 'observation', categories: cats('x') }), { ok: false, reason: 'no-live-capability' });
      const allowed = identity('allowed').nodeId;
      const { capability } = interior.startMind({ id: 'mission-1', kinds: ['observation'], allowTo: [allowed], ratePerMinute: 3 });
      assert.strictEqual(interior.submit(capability, { kind: 'command', categories: cats('x') }).reason, 'kind-not-declared');
      assert.strictEqual(interior.submit(capability, { kind: 'observation', to: identity('other').nodeId, categories: cats('x') }).reason, 'audience-not-allowed');
      assert.strictEqual(interior.submit(capability, { kind: 'observation', categories: cats('x'.repeat(70 * 1024)) }).reason, 'categories-too-large');
      assert.strictEqual(interior.submit(capability, { kind: 'observation', categories: cats('x'), payload: { blob: 'y'.repeat(600 * 1024) } }).reason, 'application-too-large');
      assert.strictEqual(interior.submit(capability, { kind: 'observation', categories: cats('x'), parents: ['cmb-' + '0'.repeat(64)] }).reason, 'parent-not-in-store');
      const ok = interior.submit(capability, { kind: 'observation', categories: cats('a mind observation') });
      assert.strictEqual(ok.ok, true);
      assert.match(ok.assertionId, /^asrt-/);
      assert.strictEqual(node._store.get(ok.key).cmb.metadata.createdByNodeId, node.nodeId, 'signed by the node: the mind holds no key');
      assert.strictEqual(interior.submit(capability, { kind: 'observation', categories: cats('second'), parents: [ok.key] }).ok, true, 'a parent in the store is fine');
      assert.strictEqual(interior.submit(capability, { kind: 'observation', categories: cats('third') }).ok, true);
      assert.strictEqual(interior.submit(capability, { kind: 'observation', categories: cats('fourth') }).reason, 'rate');
      // The mind exits: its capability is revoked.
      assert.strictEqual(interior.endMind(capability), true);
      assert.strictEqual(interior.submit(capability, { kind: 'observation', categories: cats('after exit') }).reason, 'no-live-capability');
    } finally { await node.stop(); }
  });

  it('one mind per node: a second concurrent mind is refused, a queued one starts when the first ends', async () => {
    const node = new SymNode({ name: uniq('id-one'), silent: true, discovery: new NullDiscovery() });
    try {
      const interior = node.interior();
      const first = interior.startMind({ kinds: ['observation'] });
      assert.throws(() => interior.startMind({ kinds: ['observation'] }), (e) => e.code === 'EMINDBUSY');
      let second = null;
      const queued = interior.queueMind({ id: 'next', kinds: ['observation'] }).then((m) => { second = m; });
      assert.strictEqual(second, null);
      interior.endMind(first.capability);
      await queued;
      assert.ok(second && second.capability !== first.capability);
      assert.strictEqual(interior.mind().mission, 'next');
    } finally { await node.stop(); }
  });

  it('the interior socket takes submissions with the capability', async () => {
    const node = new SymNode({ name: uniq('id-sock'), silent: true, discovery: new NullDiscovery() });
    try {
      const interior = node.interior();
      const sockPath = await interior.listen();
      const { capability } = interior.startMind({ kinds: ['observation'] });
      const ask = (req) => new Promise((resolve, reject) => {
        const s = net.createConnection(sockPath);
        let buf = '';
        s.on('data', (d) => { buf += d; if (buf.includes('\n')) { resolve(JSON.parse(buf.split('\n')[0])); s.end(); } });
        s.on('error', reject);
        s.write(JSON.stringify(req) + '\n');
      });
      assert.deepStrictEqual(await ask({ id: 1, type: 'submit', capability: 'forged', kind: 'observation', categories: cats('x') }), { id: 1, type: 'refused', reason: 'no-live-capability' });
      const r = await ask({ id: 2, type: 'submit', capability, kind: 'observation', categories: cats('over the socket') });
      assert.strictEqual(r.type, 'submitted');
      assert.ok(node._store.get(r.key));
      if (process.platform !== 'win32') assert.strictEqual(fs.statSync(sockPath).mode & 0o777, 0o600);
    } finally { await node.stop(); }
  });
});

void until;
