'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * The redelivery and inbox-id bugs (founder, via agent-b, 2026-10; mesh-channel 0.10.1 on sym 0.13.16,
 * and reproduced on 0.14.0 at 6510bac):
 *
 *   Bug 1: after a hot-swap (a new SymNode for the same identity) or a reconnect, CMBs already
 *          received and read came back as new deliveries with new inbox ids. The dedup was a TTL
 *          cache flushed to disk every 5 s, so it did not survive an instance.
 *   Bug 2: inbox ids restarted when an instance ended between a delivery and the inbox's throttled
 *          write: an announced id then fetched "not found", and the next instance announced it for
 *          another record. An unread item could also be evicted by the ring.
 *
 * The rule (docs in node.js and frame-handler.js):
 *   - a CMB delivered to a node identity, keyed by author and CMB key (and, directed, its assertion),
 *     is surfaced once for the life of that identity's store, whatever transport or instance;
 *   - an inbox id is assigned only once the record is durably in the inbox, is unique for the life of
 *     the store, is never evicted while unread, and always fetches the record it announced;
 *   - fetch reads the inbox the announcement came from (one owner per inbox in a process).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const { connectNodes, until } = require('./_core-secure');

const uniq = (b) => `${b}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
const cats = (focus) => ({ focus, issue: 'i', intent: 'inform', motivation: 'm', commitment: 'c', perspective: 'p', mood: { text: 'calm' } });
const aligned = (n) => { n._svafEvaluator.evaluate = async () => ({ decision: 'aligned', total_drift: 0.1, category_drifts: { focus: 0.1 }, gate_values: { g: 1 } }); return n; };
const text = (m) => (m && m.record && m.record.categories && m.record.categories.focus && m.record.categories.focus.text) || null;
const settle = (ms = 300) => new Promise((r) => setTimeout(r, ms));
async function stopAll(...nodes) {
  for (const n of nodes) { try { await n.stop(); } catch { /* */ } }
  for (const n of nodes) { try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ } }
}
/** The process ends without stop(): its timers never fire and its lock goes with it. */
function crash(node) {
  clearTimeout(node._inboxPersistTimer); node._inboxPersistTimer = null;
  if (node._releaseIdentityLock) { node._releaseIdentityLock(); node._releaseIdentityLock = null; }
  for (const s of [...node._sessions]) { try { s.close('crash', { notify: false }); } catch { /* */ } }
  node._running = false;
}

describe('delivery ledger and inbox ids (redelivery and id-reuse bugs)', () => {
  it('a record already delivered and read is not delivered again after a hot-swap and a re-push (Bug 1)', async () => {
    const name = uniq('swap-b');
    const P = new SymNode({ name: uniq('swap-p'), silent: true, discovery: new NullDiscovery(), room: 'r' });
    let B = aligned(new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: 'r' }));
    const nodeId = B.nodeId;
    try {
      await P.start(); await B.start();
      await connectNodes(P, B);
      const bc = P.remember(cats('a broadcast, read before the swap'));
      const dr = P.remember(cats('a directed record, read before the swap'), { to: B.nodeId });
      await until(() => B.inboxStatus().seq >= 2, 3000);
      assert.strictEqual(B.inbox({ limit: 10 }).messages.length, 2, 'both delivered, and read');
      // The swap, at once (inside the old dedup cache's 5 s flush), then the same records again.
      await B.stop();
      B = aligned(new SymNode({ name, nodeId, create: false, silent: true, discovery: new NullDiscovery(), room: 'r' }));
      const hooked = [];
      B.on('verified-record', (e) => hooked.push(e));
      await B.start();
      await connectNodes(P, B);
      const s = P._peers.get(B.nodeId).transport;
      s.trySend({ type: 'cmb', cmb: bc.cmb }); s.trySend({ type: 'cmb', cmb: dr.cmb });
      await settle(500);
      assert.deepStrictEqual(B.inbox({ peek: true }).messages.map((m) => m.id), [], 'nothing comes back as unread');
      assert.strictEqual(B.inboxStatus().seq, 2, 'no new inbox id');
      assert.strictEqual(hooked.length, 0, 'and the host hook is not raised again');
      // A new assertion of the same words, directed, is a new delivery (re-review F9 stands).
      P.remember(cats('a directed record, read before the swap'), { to: B.nodeId });
      await until(() => B.inboxStatus().seq >= 3, 3000);
      assert.strictEqual(B.inboxStatus().seq, 3);
    } finally { await stopAll(B, P); }
  });

  it('an announced id survives the process ending at once, and is never announced for another record (Bug 2)', async () => {
    const name = uniq('crash-b');
    const P = new SymNode({ name: uniq('crash-p'), silent: true, discovery: new NullDiscovery(), room: 'r' });
    const Q = new SymNode({ name: uniq('crash-q'), silent: true, discovery: new NullDiscovery(), room: 'r' });
    let B = aligned(new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: 'r' }));
    const nodeId = B.nodeId;
    try {
      await P.start(); await Q.start(); await B.start();
      await connectNodes(P, B); await connectNodes(Q, B);
      const announced = new Map();
      B.on('cmb-accepted', (e) => announced.set(e.inboxId, e.cmb.categories.focus.text));
      // Two concurrent pushes from two authors, and a duplicate re-push of the first.
      const pr = P.remember(cats('from P, concurrently'), { to: B.nodeId });
      Q.remember(cats('from Q, concurrently'), { to: B.nodeId });
      P._peers.get(B.nodeId).transport.trySend({ type: 'cmb', cmb: pr.cmb });
      await until(() => announced.size >= 2, 3000);
      await settle(200);
      assert.strictEqual(announced.size, 2, 'the duplicate got no id of its own');
      for (const [id, t] of announced) assert.strictEqual(text(B.inboxGet(id)), t, `${id} fetches its own record`);
      crash(B);
      B = aligned(new SymNode({ name, nodeId, create: false, silent: true, discovery: new NullDiscovery(), room: 'r' }));
      await B.start();
      for (const [id, t] of announced) assert.strictEqual(text(B.inboxGet(id)), t, `${id} still fetches its record after the process ended`);
      await connectNodes(Q, B);
      const next = [];
      B.on('cmb-accepted', (e) => next.push(e.inboxId));
      Q.remember(cats('from Q, after the restart'), { to: B.nodeId });
      await until(() => next.length >= 1, 3000);
      assert.ok(!announced.has(next[0]), `the next delivery gets a new id (${next[0]}), never one already announced`);
      for (const [id, t] of announced) assert.strictEqual(text(B.inboxGet(id)), t, `${id} is still its own record`);
    } finally { await stopAll(B, P, Q); }
  });

  it('a delivery already read stays read after the process ends at once (the drain is journalled)', async () => {
    const name = uniq('drain-b');
    const P = new SymNode({ name: uniq('drain-p'), silent: true, discovery: new NullDiscovery(), room: 'r' });
    let B = aligned(new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: 'r' }));
    const nodeId = B.nodeId;
    try {
      await P.start(); await B.start();
      await connectNodes(P, B);
      P.remember(cats('read, then the process ends'), { to: B.nodeId });
      await until(() => B.inboxStatus().seq >= 1, 3000);
      assert.strictEqual(B.inbox().messages.length, 1);
      const acked = P.remember(cats('acked by id, then the process ends'), { to: B.nodeId });
      void acked;
      await until(() => B.inboxStatus().seq >= 2, 3000);
      B.inboxAck('in0002');
      crash(B);
      B = new SymNode({ name, nodeId, create: false, silent: true, discovery: new NullDiscovery(), room: 'r' });
      assert.strictEqual(B.inboxStatus().cursor, 1, 'the drain held');
      assert.strictEqual(B.inboxGet('in0002').acked, true, 'and the ack');
      assert.strictEqual(B.inboxStatus().undrained, 0);
    } finally { await stopAll(B, P); }
  });

  it('two instances of one identity in one process: only the newer assigns ids and writes; the older writes nothing', async () => {
    const name = uniq('two-b');
    const old = new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: 'r' });
    await old.start();
    const e1 = { cmb: { categories: { focus: { text: 'one' } } }, content: 'one' };
    old.emit('cmb-accepted', e1);
    assert.strictEqual(e1.inboxId, 'in0001');
    const newer = new SymNode({ name, nodeId: old.nodeId, create: false, silent: true, discovery: new NullDiscovery(), room: 'r' });
    const e2 = { cmb: { categories: { focus: { text: 'two' } } }, content: 'two' };
    old.emit('cmb-accepted', e2);
    assert.strictEqual(e2.inboxId, undefined, 'the older instance announces nothing');
    const e3 = { cmb: { categories: { focus: { text: 'three' } } }, content: 'three' };
    newer.emit('cmb-accepted', e3);
    assert.strictEqual(e3.inboxId, 'in0002', 'the newer numbers on from what the older made durable');
    // The newer's own snapshot never comes (it ends at once); the older's throttled one comes due.
    clearTimeout(newer._inboxPersistTimer); newer._inboxPersistTimer = null;
    await new Promise((r) => setTimeout(r, 1100));
    await old.stop();
    const again = new SymNode({ name, nodeId: old.nodeId, create: false, silent: true, discovery: new NullDiscovery(), room: 'r' });
    assert.strictEqual(again.inboxGet('in0002').content, 'three', 'the older instance\'s stop did not overwrite the newer\'s inbox');
    await stopAll(newer, again);
  });

  it('a torn last journal line is ignored: its change never took effect', () => {
    const name = uniq('torn-b');
    const n = new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: 'r' });
    const e = { cmb: { categories: { focus: { text: 'kept' } } }, content: 'kept' };
    n.emit('cmb-accepted', e);
    fs.appendFileSync(path.join(n._dir, 'inbox.log'), '{"e":{"seq":2,"id":"in0002"');
    clearTimeout(n._inboxPersistTimer);
    if (n._releaseIdentityLock) n._releaseIdentityLock();
    const m = new SymNode({ name, nodeId: n.nodeId, create: false, silent: true, discovery: new NullDiscovery(), room: 'r' });
    try {
      assert.strictEqual(m.inboxGet('in0001').content, 'kept');
      assert.strictEqual(m.inboxGet('in0002'), null);
      assert.strictEqual(m.inboxStatus().seq, 1);
    } finally { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); }
  });
});
