'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * The final re-review of f0d936a (BLOCK): the founder's three rulings and the findings beside them,
 * each as a regression test that fails on f0d936a. The reviewer's repros are in
 * /private/tmp/claude-501/-Users-hongwei-sym-agent-a/sym-014-final-review/ (grant-probes.js P1-P4,
 * node-probes.js Q1, digest-churn.js, fork-a, fork-b).
 *
 *   A, B  retired with the time-replay grant rule (MMP §6.6; see below)
 *   C  the interior read side is scoped to the mind's mission (Finding 6)
 *   3  the cost of relayed forgeries is bounded without blaming the relayer
 *   7  relocation: in-process locks, replays, staging, modes, the header checked first
 *   lows
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const config = require('../lib/config');
const relocation = require('../lib/relocation');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const { identity, connectNodes, until, signedRecord, admitAs, deliver } = require('./_core-secure');

const uniq = (b) => `${b}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
function mk(base, extra = {}) { return new SymNode({ name: uniq(base), silent: true, discovery: new NullDiscovery(), room: extra.room || 'fr', ...extra }); }
async function stopAll(...nodes) {
  for (const n of nodes) { try { await n.stop(); } catch { /* */ } try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ } }
}

// A (the kept grant set as a function of the records held: Findings 1, 2) and B (ratification and
// backdating: Finding 4, Low 8a) tested the time-replay grant rule that MMP §6.6 retired. The new rule
// is a function of the set by construction: authority-vectors.test.js resolves every published case in
// every order and with forged copies; authority-attacks.test.js holds backdating, arrival order and the
// review attacks; authority-node.test.js shows two nodes reaching one root over real sessions. B's
// last test (an attestation dated before the record it attests) went with the rule: authority carries
// no time, so an attestation's time is no part of its weight (§6.6.10).

describe('C: the interior read side is scoped to the mind\'s mission (Finding 6)', () => {
  function conn(p) {
    const s = net.createConnection(p); let buf = ''; const waiters = new Map(); let n = 0;
    s.on('data', (d) => { buf += d; let i; while ((i = buf.indexOf('\n')) !== -1) { const m = JSON.parse(buf.slice(0, i)); buf = buf.slice(i + 1); const w = waiters.get(m.id); if (w) { waiters.delete(m.id); w(m); } } });
    return { ask: (req) => new Promise((r) => { const id = ++n; waiters.set(id, r); s.write(JSON.stringify({ ...req, id }) + '\n'); }), close: () => new Promise((r) => { s.once('close', r); s.end(); }) };
  }
  const cats = (focus) => ({ focus, issue: 'i', intent: 'inform', motivation: 'm', commitment: 'c', perspective: 'p', mood: { text: 'calm' } });
  // A mind's categories leave intent to its kind (the signed intent).
  const mindCats = (focus) => ({ focus, issue: 'i', motivation: 'm', commitment: 'c', perspective: 'p', mood: { text: 'calm' } });

  it('mission B never sees mission A\'s deliveries or notes, and a mind never moves the host\'s inbox', async () => {
    const peerA = mk('peer-a', { room: 'r' });
    const node = mk('scoped', { room: 'r' });
    try {
      await peerA.start(); await node.start();
      node._svafEvaluator.evaluate = async () => ({ decision: 'aligned', total_drift: 0.1, category_drifts: { focus: 0.1 }, gate_values: { g: 1 } });
      const interior = node.interior();
      const sock = await interior.listen();
      const mA = interior.startMind({ id: 'mission-A', kinds: ['observation'], allowTo: [peerA.nodeId] });
      await connectNodes(peerA, node);
      peerA.remember(cats('customer A secret for mission A'), { to: node.nodeId });
      peerA.remember(cats('a room broadcast heard during mission A'));
      await until(() => node.inboxStatus().seq >= 2, 3000);
      const ca = conn(sock);
      const dA = await ca.ask({ type: 'deliveries', capability: mA.capability, peek: true });
      assert.deepStrictEqual(dA.items.map((x) => x.record.categories.focus.text), ['customer A secret for mission A', 'a room broadcast heard during mission A'], 'mission A sees its own counterparty, and the room');
      const sub = await ca.ask({ type: 'submit', capability: mA.capability, kind: 'observation', categories: mindCats('mission A private note'), to: peerA.nodeId });
      assert.strictEqual(sub.type, 'submitted');
      await ca.close();
      await until(() => !interior.busy, 2000);
      const before = node.inboxStatus();
      const mB = interior.startMind({ id: 'mission-B', kinds: ['observation'], allowTo: [] });
      const c = conn(sock);
      const d = await c.ask({ type: 'deliveries', capability: mB.capability, after: 0 });
      assert.deepStrictEqual(d.items, [], 'no delivery from before mission B');
      const r = await c.ask({ type: 'recall', capability: mB.capability, query: '' });
      assert.deepStrictEqual(r.items, [], 'recall holds nothing of mission A');
      for (const m of node.inbox({ peek: true }).messages) {
        const ack = await c.ask({ type: 'ack', capability: mB.capability, delivery: m.id });
        assert.strictEqual(ack.reason, 'not-in-view', `${m.directed ? 'directed' : 'broadcast'} from before mission B`);
      }
      const recalled = await c.ask({ type: 'recall', capability: mB.capability, query: 'broadcast heard during mission' });
      assert.deepStrictEqual(recalled.items, [], 'a broadcast from before mission B is not recalled either');
      // During mission B: a directed record from a node outside its allowTo is not in its view; a
      // room broadcast is.
      peerA.remember(cats('for the node, not for mission B'), { to: node.nodeId });
      peerA.remember(cats('a room broadcast during mission B'));
      await until(() => node.inboxStatus().seq >= 4, 3000);
      const during = await c.ask({ type: 'deliveries', capability: mB.capability, peek: true });
      assert.deepStrictEqual(during.items.map((x) => x.record.categories.focus.text), ['a room broadcast during mission B']);
      const cite = await c.ask({ type: 'submit', capability: mB.capability, kind: 'observation', categories: mindCats('cites A'), parents: [sub.key] });
      assert.strictEqual(cite.reason, 'parent-not-in-store', 'a key outside the scope is refused as if absent');
      await c.ask({ type: 'deliveries', capability: mB.capability });
      assert.strictEqual(node.inboxStatus().cursor, before.cursor, 'the host\'s inbox cursor is untouched');
      assert.strictEqual(node.inbox({ peek: true }).messages.length, 4);
      // Reads are rate-limited per mind.
      let limited = 0;
      for (let i = 0; i < 40; i++) if ((await c.ask({ type: 'mission', capability: mB.capability })).reason === 'rate') limited++;
      assert.ok(limited > 0, 'past the burst, reads are refused');
      await c.close();
    } finally { await stopAll(node, peerA); }
  });
});

describe('3: relayed forgeries cost bounded work, and nobody is blamed (Finding 3)', () => {
  it('Q1: 400 forged 200 KiB records relayed in another\'s name are mostly dropped before any work, with bounded logs and decisions', async () => {
    const b = mk('q1', {});
    try {
      await b.start();
      const logs = []; b._log = (m) => logs.push(m);
      const metrics = {}; b.on('metric', (m) => { metrics[m.type] = (metrics[m.type] || 0) + 1; });
      const X = identity('x'); const M = identity('m');
      admitAs(b, X);
      const sM = admitAs(b, M);
      const big = 'z'.repeat(200 * 1024);
      const before = b._decisionLog.count();
      for (let i = 0; i < 400; i++) {
        const rec = signedRecord(M, { categories: { focus: `forged ${i} ${big}` }, room: b._room });
        rec.metadata.createdByNodeId = X.nodeId;
        deliver(b, sM, { type: 'cmb', cmb: rec });
      }
      assert.strictEqual(sM.closed, false, 'the relayer is not blamed');
      assert.ok((metrics['relayed-signature-unverified'] || 0) <= 8, `verified and failed at most 8: ${metrics['relayed-signature-unverified']}`);
      assert.ok((metrics['relayed-signer-muted'] || 0) + (metrics['cmb-over-verify-budget'] || 0) >= 380, 'the rest dropped before any work');
      assert.ok(logs.length <= 10, `log lines: ${logs.length}`);
      assert.ok(b._decisionLog.count() - before <= 2, 'decision-log entries bounded');
    } finally { await stopAll(b); }
  });
});

describe('3b: the verification lane bounds work on records naming many signers', () => {
  it('400 records naming 400 unknown authors: most are dropped before any schema, hash or signature work', async () => {
    const b = mk('lane', {});
    try {
      await b.start();
      const metrics = {}; b.on('metric', (m) => { metrics[m.type] = (metrics[m.type] || 0) + 1; });
      const M = identity('m');
      const sM = admitAs(b, M);
      // Small records, so the loop runs well inside a second and the lane's refill stays small.
      const one = signedRecord(M, { categories: { focus: `forged ${'z'.repeat(1024)}` }, room: b._room });
      for (let i = 0; i < 400; i++) {
        const rec = JSON.parse(JSON.stringify(one));
        rec.metadata.createdByNodeId = crypto.randomUUID();
        deliver(b, sM, { type: 'cmb', cmb: rec });
      }
      assert.ok((metrics['cmb-over-verify-budget'] || 0) >= 200, `dropped before any work: ${metrics['cmb-over-verify-budget']}`);
    } finally { await stopAll(b); }
  });
});

describe('7: relocation (Finding 7)', () => {
  it('7a: a same-process re-acquire of an identity lock returns a release that does nothing; export refuses while a node in this process runs', async () => {
    const node = mk('reloc-live', {});
    try {
      await node.start();
      const lockFile = path.join(node._dir, 'lock.pid');
      const release = config.acquireIdentityLock(node.name, { dir: node._dir });
      release();
      assert.ok(fs.existsSync(lockFile), 'the running node keeps its lock');
      const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'b-')), 'n.bundle');
      assert.throws(() => relocation.exportNode({ name: node.name, out, toHostKey: relocation.hostKey().publicKey }), /running in this process/);
      assert.strictEqual(config.readTombstone(node.nodeId), null, 'not tombstoned');
    } finally { await stopAll(node); }
  });

  it('7b: an import is staged and refused whole, a replayed or consumed bundle is refused, file modes travel, and the header is checked before its scrypt parameters are used', async () => {
    const name = uniq('reloc');
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    const nodeId = node.nodeId; const pub = node._identity.publicKey;
    node.remember({ focus: 'travels' });
    await node.stop();
    const dir = config.nodeDirById(nodeId);
    fs.writeFileSync(path.join(dir, 'secret-0600.txt'), 'x', { mode: 0o600 });
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'b-'));
    const out = path.join(tmp, 'n.bundle');
    assert.throws(() => relocation.exportNode({ name, out, passphrase: 'a long operator passphrase' }), /a copy, not a move/, 'a passphrase bundle needs copyable');
    relocation.exportNode({ name, out, passphrase: 'a long operator passphrase', copyable: true });
    const pass = 'a long operator passphrase';
    // A header whose scrypt parameters were raised is refused before scrypt runs.
    const b = JSON.parse(fs.readFileSync(out, 'utf8'));
    const hostile = path.join(tmp, 'hostile.bundle');
    fs.writeFileSync(hostile, JSON.stringify({ ...b, N: 1 << 20 }));
    const t = Date.now();
    assert.throws(() => relocation.importNode({ from: hostile, passphrase: pass, expect: { nodeId, key: pub } }), /header is not signed/);
    assert.ok(Date.now() - t < 500, 'no scrypt was run');
    // The bundle of the move away, back on this host: a replay.
    assert.throws(() => relocation.importNode({ from: out, passphrase: pass, expect: { nodeId, key: pub } }), /at or before this host moved/);
    // Another host (this host's copy removed): a name already indexing another node refuses the whole
    // import, and nothing is installed.
    fs.rmSync(dir, { recursive: true, force: true });
    if (config.identityDirById(nodeId) !== dir) fs.rmSync(config.identityDirById(nodeId), { recursive: true, force: true });
    const other = config.loadIdentity({ name: uniq('other') });
    assert.throws(() => relocation.importNode({ from: out, passphrase: pass, expect: { nodeId, key: pub }, name: config.nodeIdForName ? other.name : other.name }), /already indexes another node/);
    assert.strictEqual(fs.existsSync(dir), false, 'nothing installed');
    assert.deepStrictEqual(fs.readdirSync(path.dirname(dir)).filter((f) => f.startsWith(path.basename(dir))), [], 'no staged directory left');
    relocation.importNode({ from: out, passphrase: pass, expect: { nodeId, key: pub } });
    assert.strictEqual(fs.statSync(path.join(dir, 'secret-0600.txt')).mode & 0o777, 0o600, 'its mode travelled');
    assert.strictEqual(fs.statSync(path.join(config.identityDirById(nodeId), 'identity.json')).mode & 0o777, 0o600);
    // Imported once here: never again.
    fs.rmSync(dir, { recursive: true, force: true });
    if (config.identityDirById(nodeId) !== dir) fs.rmSync(config.identityDirById(nodeId), { recursive: true, force: true });
    assert.throws(() => relocation.importNode({ from: out, passphrase: pass, expect: { nodeId, key: pub } }), /already imported on this host/);
    fs.rmSync(config.nodeDirById(other.nodeId), { recursive: true, force: true });
  });
});

describe('lows', () => {
  it('emit releases the identity\'s lock when it cannot connect', async () => {
    const { connect } = require('../lib/emit');
    const name = uniq('emitter');
    const receiver = { nodeId: crypto.randomUUID(), key: identity('r').publicKey };
    await assert.rejects(() => connect({ server: '127.0.0.1:1', receiver, name, timeoutMs: 500 }));
    const id = config.loadIdentity({ name, create: false });
    assert.strictEqual(config.lockHeldInProcess(config.nodeDirById(id.nodeId)), false, 'the lock was released');
    assert.strictEqual(fs.existsSync(path.join(config.nodeDirById(id.nodeId), 'lock.pid')), false);
    await assert.rejects(() => connect({ server: 'not-an-address', receiver, name }));
    assert.strictEqual(config.lockHeldInProcess(config.nodeDirById(id.nodeId)), false);
  });
});
