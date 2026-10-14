'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * Dismissing a CMB, publicly (0.14.1). 0.14.0 could validate on a node (`node.validateCMB`) but not dismiss: the
 * store's dismissCMB was private, ungated and returned nothing. Now (MMP §6.4, §6.5: dismissal takes the same
 * earned authority as validation, validator or above):
 *
 *   - `node.dismissCMB(key)` resolves the node's authority over that record exactly as validateCMB does and
 *     returns `{ ok, reason? }`;
 *   - `openStore(dir, name)` (`@sym-bot/sym/store`) opens a STOPPED identity's store, never creating the
 *     directory, with `get`, `validateCMB` and `dismissCMB`, the last two taking the caller's stated authority.
 *
 * Everything here runs against real node directories under the temp HOME, and reads the result back from the file.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir, nodeDirById, loadOrCreateIdentity } = require('../lib/config');
const { MemoryStore } = require('../lib/memory-store');
const { createCMB } = require('../lib/core');
const { openStore } = require('../lib/public/store');

const uniq = (b) => `${b}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
const cat7 = (t) => ({ focus: t, issue: t, intent: t, motivation: t, commitment: t, perspective: 'peerA', mood: { text: 'neutral' } });

/** A node of `role` holding one peer record; its store file is read back from disk. */
async function withNode(role, fn, opts = {}) {
  const name = uniq(`dismiss-${role}`);
  const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), lifecycleRole: role, ...opts });
  await node.start();
  const cmb = createCMB({ categories: cat7(`an observation held by ${name}`), createdBy: 'peerA' });
  node._store.receiveFromPeer('peerA', { key: cmb.metadata.key, content: 'x', source: 'peerA', cmb, _cmbVerified: true });
  const onDisk = (k) => JSON.parse(fs.readFileSync(path.join(node._cmbsDir, `${k}.json`), 'utf8'));
  try { return await fn(node, cmb.metadata.key, onDisk); } finally {
    await node.stop();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  }
}

describe('MemoryStore.dismissCMB takes the same authority as validateCMB (§6.5)', () => {
  const make = () => {
    const dir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'sym-dismiss-store-'));
    const store = new MemoryStore(dir, 'holder');
    const cmb = createCMB({ categories: cat7('held'), createdBy: 'peerA' });
    store.receiveFromPeer('peerA', { key: cmb.metadata.key, content: 'x', source: 'peerA', cmb, _cmbVerified: true });
    return { dir, store, key: cmb.metadata.key };
  };

  it('no authority (none, absent, unknown): refused, and the record is exactly as it was', () => {
    const { dir, store, key } = make();
    try {
      const before = JSON.stringify(store.get(key));
      for (const opts of [undefined, {}, { lifecycle: 'none' }, { lifecycle: 'dismissed' }, { lifecycle: 'anchor' }, { byRole: 'validator' }]) {
        assert.deepStrictEqual(store.dismissCMB(key, opts), { ok: false, reason: 'insufficient-authority' }, JSON.stringify(opts));
      }
      assert.strictEqual(JSON.stringify(store.get(key)), before);
      assert.notStrictEqual(store.get(key).lifecycle, 'dismissed');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('validator or canonical authority: dismissed at weight 0.5, persisted, and a fresh store reads it', () => {
    for (const lifecycle of ['validated', 'canonical']) {
      const { dir, store, key } = make();
      try {
        assert.deepStrictEqual(store.dismissCMB(key, { lifecycle }), { ok: true });
        assert.strictEqual(store.getLifecycle(key), 'dismissed');
        const reread = new MemoryStore(dir, 'holder').get(key);
        assert.strictEqual(reread.lifecycle, 'dismissed');
        assert.strictEqual(reread.anchorWeight, 0.5);
      } finally { fs.rmSync(dir, { recursive: true, force: true }); }
    }
  });

  it('an unknown key is reported, not ignored', () => {
    const { dir, store } = make();
    try { assert.deepStrictEqual(store.dismissCMB('cmb-' + '0'.repeat(64), { lifecycle: 'validated' }), { ok: false, reason: 'unknown-cmb' }); }
    finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('a validated record can be dismissed, and a canonical one: the Canon leaves by an explicit dismiss (§6.5)', () => {
    const { dir, store, key } = make();
    try {
      assert.deepStrictEqual(store.validateCMB(key, { lifecycle: 'validated' }), { ok: true });
      assert.strictEqual(store.get(key).anchorWeight, 2.0);
      assert.deepStrictEqual(store.canonizeCMB(key, { lifecycle: 'canonical' }), { ok: true });
      assert.deepStrictEqual(store.dismissCMB(key, { lifecycle: 'validated' }), { ok: true });
      assert.deepStrictEqual([store.get(key).lifecycle, store.get(key).anchorWeight], ['dismissed', 0.5]);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
});

describe('node.dismissCMB (public)', () => {
  it('a participant is refused and the record is untouched; validateCMB agrees', async () => {
    await withNode('participant', async (node, key, onDisk) => {
      assert.deepStrictEqual(node.dismissCMB(key), { ok: false, reason: 'insufficient-authority' });
      assert.deepStrictEqual(node.validateCMB(key), { ok: false, reason: 'insufficient-authority' });
      assert.notStrictEqual(onDisk(key).lifecycle, 'dismissed');
    });
  });

  it('a validator dismisses: lifecycle dismissed, weight 0.5, written to the store file at once', async () => {
    await withNode('validator', async (node, key, onDisk) => {
      assert.deepStrictEqual(node.dismissCMB(key), { ok: true });
      assert.deepStrictEqual([onDisk(key).lifecycle, onDisk(key).anchorWeight], ['dismissed', 0.5]);
      assert.strictEqual(node._store.getLifecycle(key), 'dismissed');
    });
  });

  it('an unknown key is reported as such, by a node with the authority', async () => {
    await withNode('validator', async (node) => {
      assert.deepStrictEqual(node.dismissCMB('cmb-' + '1'.repeat(64)), { ok: false, reason: 'unknown-cmb' });
    });
  });

  it('a validator dismisses a record it had validated (a verdict changed)', async () => {
    await withNode('validator', async (node, key, onDisk) => {
      assert.deepStrictEqual(node.validateCMB(key), { ok: true });
      assert.strictEqual(onDisk(key).anchorWeight, 2.0);
      assert.deepStrictEqual(node.dismissCMB(key), { ok: true });
      assert.strictEqual(onDisk(key).anchorWeight, 0.5);
    });
  });

  it('with an anchor pinned, authority is the in-force set, not the configured role: a configured validator without a grant is refused', async () => {
    const other = crypto.generateKeyPairSync('ed25519');
    const pub = other.publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('base64url');
    await withNode('validator', async (node, key, onDisk) => {
      assert.deepStrictEqual(node.dismissCMB(key), { ok: false, reason: 'insufficient-authority' });
      assert.deepStrictEqual(node.validateCMB(key), { ok: false, reason: 'insufficient-authority' });
      assert.notStrictEqual(onDisk(key).lifecycle, 'dismissed');
    }, { room: 'g', anchor: { nodeId: '0190a000-0000-7000-8000-0000000000aa', publicKey: pub } });
  });

  it('the node that is itself the pinned anchor dismisses', async () => {
    const name = uniq('dismiss-anchor');
    const id = loadOrCreateIdentity(name);
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: 'g', anchor: { nodeId: id.nodeId, publicKey: id.publicKey } });
    await node.start();
    try {
      const cmb = createCMB({ categories: cat7('held by the anchor'), createdBy: 'peerA' });
      node._store.receiveFromPeer('peerA', { key: cmb.metadata.key, content: 'x', source: 'peerA', cmb, _cmbVerified: true });
      assert.deepStrictEqual(node.dismissCMB(cmb.metadata.key), { ok: true });
      assert.strictEqual(node._store.get(cmb.metadata.key).anchorWeight, 0.5);
    } finally { await node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });
});

describe('openStore (@sym-bot/sym/store): a stopped identity\'s store', () => {
  /** A node that held a record, stopped; returns what an operator would know: the store directory and the key. */
  async function stoppedIdentity() {
    const name = uniq('stopped');
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    await node.start();
    const entry = node.remember(cat7(`work done by ${name}`));
    const privateDir = node._cmbsDir;
    await node.stop();
    // What an operator has once the process is gone: the name. The store is found with the main entry's public
    // `identity` helpers, as README "Public API" says: <node directory>/cmbs.
    const { identity } = require('../lib/node');
    const dir = path.join(identity.nodeDirById(identity.nodeIdForName(name)), 'cmbs');
    assert.strictEqual(dir, privateDir, 'the documented way to find a stopped identity\'s store finds it');
    return { name, dir, key: entry.key, cleanup: () => fs.rmSync(nodeDirById(node.nodeId), { recursive: true, force: true }) };
  }

  it('records a validated and a dismissed verdict in the stopped node\'s store, and a restarted node sees them', async () => {
    const a = await stoppedIdentity();
    const b = await stoppedIdentity();
    try {
      const sa = openStore(a.dir, a.name);
      assert.deepStrictEqual(sa.validateCMB(a.key, { lifecycle: 'validated' }), { ok: true });
      assert.deepStrictEqual([sa.get(a.key).lifecycle, sa.get(a.key).anchorWeight], ['validated', 2.0]);
      const sb = openStore(b.dir, b.name);
      assert.deepStrictEqual(sb.dismissCMB(b.key, { lifecycle: 'validated' }), { ok: true });
      assert.deepStrictEqual([sb.get(b.key).lifecycle, sb.get(b.key).anchorWeight], ['dismissed', 0.5]);
      // read back by an independent store over the same directory, as a restarted node would
      assert.deepStrictEqual([new MemoryStore(b.dir, b.name).get(b.key).lifecycle, new MemoryStore(a.dir, a.name).get(a.key).lifecycle], ['dismissed', 'validated']);
    } finally { a.cleanup(); b.cleanup(); }
  });

  it('a directory that is not there is ENOSTORE and is NOT created (opening must not litter the disk)', () => {
    const missing = path.join(require('os').tmpdir(), uniq('no-such-store'), 'cmbs');
    assert.throws(() => openStore(missing, 'ghost'), (e) => e.code === 'ENOSTORE');
    assert.strictEqual(fs.existsSync(missing), false);
    assert.strictEqual(fs.existsSync(path.dirname(missing)), false);
    const file = path.join(require('os').tmpdir(), uniq('a-file'));
    fs.writeFileSync(file, 'x');
    try { assert.throws(() => openStore(file, 'ghost'), (e) => e.code === 'ENOSTORE', 'a file is not a store'); } finally { fs.rmSync(file); }
  });

  it('arguments are checked', () => {
    for (const args of [[], [undefined, 'n'], ['', 'n'], [123, 'n'], [process.cwd(), ''], [process.cwd()], [process.cwd(), 5]]) {
      assert.throws(() => openStore(...args), TypeError, JSON.stringify(args));
    }
  });

  it('a caller that states no authority is refused and the entry is unchanged', async () => {
    const s = await stoppedIdentity();
    try {
      const h = openStore(s.dir, s.name);
      const before = JSON.stringify(h.get(s.key));
      for (const verb of ['validateCMB', 'dismissCMB']) {
        assert.deepStrictEqual(h[verb](s.key, undefined), { ok: false, reason: 'insufficient-authority' }, verb);
        assert.deepStrictEqual(h[verb](s.key, { lifecycle: 'none' }), { ok: false, reason: 'insufficient-authority' }, verb);
      }
      assert.strictEqual(JSON.stringify(h.get(s.key)), before);
    } finally { s.cleanup(); }
  });

  it('an unknown key: get is null, the verbs say unknown-cmb', async () => {
    const s = await stoppedIdentity();
    try {
      const h = openStore(s.dir, s.name);
      const k = 'cmb-' + '2'.repeat(64);
      assert.strictEqual(h.get(k), null);
      assert.deepStrictEqual(h.validateCMB(k, { lifecycle: 'validated' }), { ok: false, reason: 'unknown-cmb' });
      assert.deepStrictEqual(h.dismissCMB(k, { lifecycle: 'validated' }), { ok: false, reason: 'unknown-cmb' });
    } finally { s.cleanup(); }
  });

  it('the handle is exactly get, validateCMB, dismissCMB; frozen; and get returns a copy, not the store\'s own entry', async () => {
    const s = await stoppedIdentity();
    try {
      const h = openStore(s.dir, s.name);
      assert.deepStrictEqual(Object.keys(h).sort(), ['dismissCMB', 'get', 'validateCMB']);
      assert.ok(Object.isFrozen(h));
      const e = h.get(s.key);
      e.anchorWeight = 99; e.lifecycle = 'canonical'; delete e.cmb;
      assert.notStrictEqual(h.get(s.key).anchorWeight, 99, 'writing to a returned entry changes nothing');
      assert.ok(h.get(s.key).cmb);
      assert.notStrictEqual(JSON.parse(fs.readFileSync(path.join(s.dir, `${s.key}.json`), 'utf8')).anchorWeight, 99);
    } finally { s.cleanup(); }
  });
});
