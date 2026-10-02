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
const { until, identity, connectNodes } = require('./_core-secure');

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
    // Security review: once the bundle is durable the source loses the key and the 0.13 path to it.
    const left = JSON.parse(fs.readFileSync(path.join(config.nodeDirById(nodeId), 'identity.json'), 'utf8'));
    assert.strictEqual(left.privateKey, null, 'the source keeps no private key');
    assert.strictEqual(left.publicKey, pub);
    assert.throws(() => fs.lstatSync(path.join(config.NODES_DIR, name)), /ENOENT/, 'the 0.13-compatible nodes/<name> link is gone');
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
    // No first-contact fallback (security review): the pin is explicit, whatever this host learned.
    assert.throws(() => importNode({ from: out, passphrase: 'a long operator passphrase' }), /no explicit pinned key/);
  });

  it('a bundle is signed by its node: a changed header or contents is refused, and a host-key bundle cannot be re-wrapped for another host', async () => {
    const name = uniq('id-signed');
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    const nodeId = node.nodeId; const pub = node._identity.publicKey;
    await node.stop();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bundle-'));
    const out = path.join(dir, 'node.bundle');
    relocation.exportNode({ name, out, passphrase: 'a long operator passphrase' });
    const crypto2 = require('crypto');
    const open = (b) => {
      const key = crypto2.scryptSync('a long operator passphrase', Buffer.from(b.salt, 'base64url'), 32, { N: b.N, r: b.r, p: b.p, maxmem: 128 * 1024 * 1024 });
      const sealed = Buffer.from(b.ciphertext, 'base64url');
      const d = crypto2.createDecipheriv('aes-256-gcm', key, Buffer.from(b.nonce, 'base64url'));
      d.setAuthTag(sealed.subarray(sealed.length - 16));
      return { key, plain: JSON.parse(Buffer.concat([d.update(sealed.subarray(0, sealed.length - 16)), d.final()]).toString('utf8')) };
    };
    const reseal = (b, key, plain, file) => {
      const nonce = crypto2.randomBytes(12);
      const c = crypto2.createCipheriv('aes-256-gcm', key, nonce);
      const body = Buffer.concat([c.update(Buffer.from(JSON.stringify(plain))), c.final()]);
      fs.writeFileSync(file, JSON.stringify({ ...b, nonce: nonce.toString('base64url'), ciphertext: Buffer.concat([body, c.getAuthTag()]).toString('base64url') }));
      return file;
    };
    const b = JSON.parse(fs.readFileSync(out, 'utf8'));
    const { key, plain } = open(b);
    assert.match(plain.signature, /^[A-Za-z0-9_-]{86}$/, 'the bundle carries the node\'s signature');
    // A file added to the contents (someone holding the passphrase, not the key): refused.
    const added = reseal(b, key, { ...plain, files: [...plain.files, { path: 'cmbs/planted.json', data: Buffer.from('{}').toString('base64') }] }, path.join(dir, 'added.bundle'));
    assert.throws(() => relocation.importNode({ from: added, passphrase: 'a long operator passphrase', expect: { nodeId, key: pub } }), /not signed by the node/);
    // The signature removed: refused.
    const { signature, ...unsigned } = plain; void signature;
    const stripped = reseal(b, key, unsigned, path.join(dir, 'stripped.bundle'));
    assert.throws(() => relocation.importNode({ from: stripped, passphrase: 'a long operator passphrase', expect: { nodeId, key: pub } }), /not signed by the node/);
    // The genuine one imports.
    assert.strictEqual(relocation.importNode({ from: out, passphrase: 'a long operator passphrase', expect: { nodeId, key: pub } }).nodeId, nodeId);
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
  /** A persistent line-oriented connection to the interior socket. */
  function conn(sockPath) {
    const s = net.createConnection(sockPath);
    let buf = '';
    const lines = [];
    const waiters = [];
    s.on('data', (d) => {
      buf += d;
      let i;
      while ((i = buf.indexOf('\n')) !== -1) {
        const m = JSON.parse(buf.slice(0, i)); buf = buf.slice(i + 1);
        lines.push(m);
        for (const w of [...waiters]) if (w.test(m)) { waiters.splice(waiters.indexOf(w), 1); w.resolve(m); }
      }
    });
    const next = (test) => new Promise((resolve) => {
      const hit = lines.find(test);
      if (hit) { lines.splice(lines.indexOf(hit), 1); resolve(hit); return; }
      waiters.push({ test: (m) => { if (!test(m)) return false; lines.splice(lines.indexOf(m), 1); return true; }, resolve });
    });
    let n = 0;
    const ask = (req) => { const id = ++n; s.write(JSON.stringify({ ...req, id }) + '\n'); return next((m) => m.id === id); };
    return { s, ask, next, close: () => new Promise((r) => { s.once('close', r); s.end(); }) };
  }

  // The kind is the signed intent (security review): a mind's categories leave intent to it.
  function cats(focus) { return { focus, issue: 'i', motivation: 'y', commitment: 'z', perspective: 'p', mood: { text: 'calm' } }; }

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
      assert.strictEqual(interior.submit(capability, { kind: 'observation', categories: { ...cats('x'), intent: 'command' } }).reason, 'intent-is-not-the-kind', 'an intent that is not the declared kind is refused');
      const ok = interior.submit(capability, { kind: 'observation', categories: cats('a mind observation') });
      assert.strictEqual(ok.ok, true);
      assert.match(ok.assertionId, /^asrt-/);
      assert.strictEqual(node._store.get(ok.key).cmb.metadata.createdByNodeId, node.nodeId, 'signed by the node: the mind holds no key');
      assert.strictEqual(node._store.get(ok.key).cmb.categories.intent.text, 'observation', 'the kind is what the node signed as the intent');
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

  it('the capability is bound to the first connection that presents it; end takes the capability, not the mindId; the read side serves verified deliveries', async () => {
    const a = new SymNode({ name: uniq('id-read-a'), silent: true, discovery: new NullDiscovery(), room: 'mind-room' });
    const node = new SymNode({ name: uniq('id-read'), silent: true, discovery: new NullDiscovery(), room: 'mind-room' });
    try {
      await a.start(); await node.start();
      const interior = node.interior();
      const sockPath = await interior.listen();
      if (process.platform !== 'win32') assert.strictEqual(fs.statSync(path.dirname(sockPath)).mode & 0o777, 0o700, 'the socket lives in a 0700 directory');
      const { capability, mindId } = interior.startMind({ id: 'reader', kinds: ['observation'], allowTo: [a.nodeId] });
      const c1 = conn(sockPath);
      const mission = await c1.ask({ type: 'mission', capability });
      assert.deepStrictEqual({ ...mission, id: undefined }, { id: undefined, type: 'mission', mindId, missionId: 'reader', kinds: ['observation'], allowTo: [a.nodeId], ratePerMinute: 60, nodeId: node.nodeId, name: node.name, room: 'mind-room' });
      // Another connection presenting the same capability: refused. The mindId ends nothing.
      const c2 = conn(sockPath);
      assert.strictEqual((await c2.ask({ type: 'submit', capability, kind: 'observation', categories: cats('replayed elsewhere') })).reason, 'capability-bound-to-another-connection');
      assert.strictEqual((await c2.ask({ type: 'end', capability: mindId })).reason, 'no-live-capability');
      assert.ok(interior.busy, 'the mind still runs');
      await c2.close();
      // The read side: subscribe, then a verified delivery from a peer arrives as an item.
      assert.strictEqual((await c1.ask({ type: 'subscribe', capability })).type, 'subscribed');
      await connectNodes(a, node);
      node._svafEvaluator.evaluate = async () => ({ decision: 'aligned', total_drift: 0.1, category_drifts: { focus: 0.1 }, gate_values: { g: 1 } });
      a.remember({ focus: 'for the mind', issue: 'i', intent: 'inform', motivation: 'm', commitment: 'c', perspective: 'p', mood: { text: 'calm' } }, { to: node.nodeId });
      const pushed = await c1.next((m) => m.type === 'delivery');
      assert.strictEqual(pushed.item.kind, 'directed');
      assert.strictEqual(pushed.item.record.metadata.createdByNodeId, a.nodeId);
      assert.strictEqual(pushed.item.verification.authorNodeId, a.nodeId);
      assert.strictEqual(pushed.item.session.nodeId, a.nodeId);
      const d = await c1.ask({ type: 'deliveries', capability, peek: true });
      assert.ok(d.items.some((x) => x.id === pushed.item.id), 'the same item, by pull');
      assert.strictEqual((await c1.ask({ type: 'ack', capability, delivery: pushed.item.id })).type, 'acked');
      const rec = await c1.ask({ type: 'recall', capability, query: 'mind' });
      assert.ok(Array.isArray(rec.items));
      // end takes the capability; then the capability is dead.
      assert.strictEqual((await c1.ask({ type: 'end', capability })).type, 'ended');
      assert.strictEqual(interior.busy, false);
      assert.strictEqual((await c1.ask({ type: 'mission', capability })).reason, 'no-live-capability');
      await c1.close();
      // A capability's connection closing ends its mind.
      const m2 = interior.startMind({ kinds: ['observation'] });
      const c3 = conn(sockPath);
      assert.strictEqual((await c3.ask({ type: 'mission', capability: m2.capability })).type, 'mission');
      await c3.close();
      await until(() => !interior.busy, 2000);
      assert.strictEqual(interior.busy, false, 'the connection that held the capability closed: the mind ended');
    } finally { await node.stop(); await a.stop(); }
  });

  it('one mind per identity: two SymNode objects for one nodeId cannot both run a mind', async () => {
    const name = uniq('id-twominds');
    const a = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    const b = new SymNode({ name, nodeId: a.nodeId, create: false, silent: true, discovery: new NullDiscovery() });
    try {
      const m = a.interior().startMind({ kinds: ['note'] });
      assert.throws(() => b.interior().startMind({ kinds: ['note'] }), (e) => e.code === 'EMINDBUSY');
      a.interior().endMind(m.capability);
      assert.ok(b.interior().startMind({ kinds: ['note'] }).capability, 'the slot is free once the first ends');
    } finally { await a.stop(); await b.stop(); }
  });

  it('the tmp fallback never follows a planted symlink, and listen refuses a path that is not a socket', async () => {
    if (process.platform === 'win32') return;
    const node = new SymNode({ name: uniq('id-tmp'), silent: true, discovery: new NullDiscovery() });
    const planted = fs.mkdtempSync(path.join(os.tmpdir(), 'planted-'));
    try {
      const { ownedPrivateDir } = require('../lib/interior');
      const link = path.join(os.tmpdir(), `sym-planted-${process.pid}-${Date.now()}`);
      fs.symlinkSync(planted, link);
      assert.throws(() => ownedPrivateDir(link), (e) => e.code === 'EINTERIORDIR', 'a symlink is not this node\'s directory');
      fs.unlinkSync(link);
      const notSock = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'ns-')), 'file');
      fs.writeFileSync(notSock, 'x');
      await assert.rejects(node.interior().listen(notSock), (e) => e.code === 'EINTERIORDIR');
    } finally { await node.stop(); fs.rmSync(planted, { recursive: true, force: true }); }
  });
});

void until;
