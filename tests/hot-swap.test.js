'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * HOT-SWAP (mesh-channel's sym_join_room): the host stops its node and builds a new SymNode for the
 * same identity (nodeId, create: false) in the same room, again and again. On 0.13 this broke as
 * "Cannot read properties of null (reading 'close')" and redelivered what had been read under new
 * inbox ids. Here, over a real TCP connection on the loopback (BonjourDiscovery without mDNS: the
 * same-host registry finds the peer, and the lower nodeId dials) and over a relay, every round must:
 *   - deliver the peer's new broadcast and directed record, each fetchable by the id it announced;
 *   - send this node's own broadcast and directed record to the peer, without a throw;
 *   - deliver nothing again that was read before (the peer re-pushes every earlier record);
 *   - keep every inbox id announced so far fetching its own record, and never reuse one;
 *   - log no null-dereference and raise no uncaught error.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { BonjourDiscovery, NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const { fakeRelay } = require('./_fake-relay');
const { until } = require('./_core-secure');

const uniq = (b) => `${b}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
const cats = (focus) => ({ focus, issue: 'i', intent: 'inform', motivation: 'm', commitment: 'c', perspective: 'p', mood: { text: 'calm' } });
const TOKEN = 'x'.repeat(40);
const ROUNDS = 4;
const focusOf = (m) => (m && m.record && m.record.categories && m.record.categories.focus ? m.record.categories.focus.text : null);
const confirmed = (n, other) => { const p = n._peers.get(other.nodeId); return !!(p && p.transport && p.transport.confirmed && !p.transport.closed); };

/** Hot-swap `B` into the same room `rounds` times; `make(nodeId)` builds B (a new instance each time). */
async function scene(t, { make, makePeer, cleanup = async () => {} }) {
  const errors = [];
  const onError = (e) => errors.push(e && e.stack ? e.stack : String(e));
  process.on('uncaughtException', onError);
  process.on('unhandledRejection', onError);
  const logs = [];
  const watch = (n) => { const log = n._log.bind(n); n._log = (m) => { logs.push(String(m)); log(m); }; return n; };
  const aligned = (n) => { n._svafEvaluator.evaluate = async () => ({ decision: 'aligned', total_drift: 0.1, category_drifts: { focus: 0.1 }, gate_values: { g: 1 } }); return n; };
  // B first, so its nodeId is the lower and it dials the peer at each start (§5.1 tie-break).
  let B = watch(aligned(make(null)));
  const nodeId = B.nodeId;
  const P = watch(aligned(makePeer()));
  const announced = new Map(); // inbox id -> the focus it announced
  const sentByP = [];
  const heardByP = [];
  P.on('verified-record', (e) => heardByP.push(e.record.categories.focus.text));
  try {
    await B.start(); await P.start();
    for (let round = 1; round <= ROUNDS; round++) {
      if (round > 1) {
        // sym_join_room: stop the node, build the next for the same identity, start it.
        await B.stop();
        B = watch(aligned(make(nodeId)));
        await B.start();
      }
      const now = [];
      B.on('cmb-accepted', (e) => { if (e.inboxId) now.push(e); });
      await until(() => confirmed(B, P) && confirmed(P, B), 15000);
      assert.ok(confirmed(B, P) && confirmed(P, B), `round ${round}: the pair is joined`);
      // The peer re-pushes every record it sent before: none is delivered again.
      const s = P._peers.get(nodeId).transport;
      for (const r of sentByP) assert.doesNotThrow(() => s.trySend({ type: 'cmb', cmb: r.cmb }));
      // And sends two new ones.
      const bc = P.remember(cats(`round ${round}: a broadcast from the peer`));
      const dr = P.remember(cats(`round ${round}: directed from the peer`), { to: nodeId });
      sentByP.push(bc, dr);
      await until(() => now.length >= 2, 8000);
      await new Promise((r) => setTimeout(r, 300));
      const texts = now.map((e) => e.cmb.categories.focus.text).sort();
      assert.deepStrictEqual(texts, [`round ${round}: a broadcast from the peer`, `round ${round}: directed from the peer`], `round ${round}: exactly the two new records, nothing redelivered`);
      for (const e of now) {
        assert.ok(!announced.has(e.inboxId), `round ${round}: ${e.inboxId} is a new id`);
        announced.set(e.inboxId, e.cmb.categories.focus.text);
      }
      for (const [id, text] of announced) assert.strictEqual(focusOf(B.inboxGet(id)), text, `round ${round}: ${id} still fetches its own record`);
      B.inbox({ limit: 100 }); // the host reads them
      assert.strictEqual(B.inboxStatus().undrained, 0);
      // This node sends: a broadcast and a directed record, no throw, and the peer hears both.
      const before = heardByP.length;
      assert.doesNotThrow(() => B.remember(cats(`round ${round}: a broadcast from B`)));
      assert.doesNotThrow(() => B.remember(cats(`round ${round}: directed from B`), { to: P.nodeId }));
      await until(() => heardByP.length >= before + 2, 8000);
      assert.deepStrictEqual(heardByP.slice(before).sort(), [`round ${round}: a broadcast from B`, `round ${round}: directed from B`]);
    }
    assert.strictEqual(announced.size, ROUNDS * 2);
    assert.deepStrictEqual(logs.filter((l) => /Cannot read propert|of null|of undefined|TypeError/.test(l)), [], 'no null dereference anywhere');
    assert.deepStrictEqual(errors, [], 'no uncaught error');
  } finally {
    process.removeListener('uncaughtException', onError);
    process.removeListener('unhandledRejection', onError);
    for (const n of [B, P]) { try { await n.stop(); } catch { /* */ } }
    for (const n of [B, P]) { try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ } }
    await cleanup();
  }
  void t;
}

describe('hot-swap into the same room, again and again (sym_join_room)', () => {
  it('over TCP on the loopback: every round delivers, fetches and sends; nothing is redelivered; ids are stable', async (t) => {
    const room = `swap-lan-${Math.random().toString(36).slice(2, 8)}`;
    const name = uniq('swap-lan-b');
    const lan = () => new BonjourDiscovery({ mdns: false, room, serviceType: `_${room}._tcp` });
    await scene(t, {
      make: (nodeId) => new SymNode({ name, ...(nodeId ? { nodeId, create: false } : {}), silent: true, discovery: lan(), room }),
      makePeer: () => new SymNode({ name: uniq('swap-lan-p'), silent: true, discovery: lan(), room }),
    });
  });

  it('over a relay: every round delivers, fetches and sends; nothing is redelivered; ids are stable', async (t) => {
    const relay = fakeRelay();
    const room = 'swap-relay-room';
    const name = uniq('swap-relay-b');
    await scene(t, {
      make: (nodeId) => new SymNode({ name, ...(nodeId ? { nodeId, create: false } : {}), silent: true, relayOnly: true, discovery: new NullDiscovery(), relay: relay.url, relayToken: TOKEN, room }),
      makePeer: () => new SymNode({ name: uniq('swap-relay-p'), silent: true, relayOnly: true, discovery: new NullDiscovery(), relay: relay.url, relayToken: TOKEN, room }),
      cleanup: () => relay.close(),
    });
  });
});

describe('the loaded version (for a host\'s status)', () => {
  it('node.version, status().version and the module\'s version are the package.json version', () => {
    const pkg = require('../package.json');
    const sym = require('../lib/node');
    const n = new SymNode({ name: uniq('version'), silent: true, discovery: new NullDiscovery() });
    try {
      assert.strictEqual(n.version, pkg.version);
      assert.strictEqual(n.status().version, pkg.version);
      assert.strictEqual(sym.version, pkg.version);
      assert.strictEqual(n._implementation.version, pkg.version, 'the same string the hello announces');
    } finally { n.stop().catch(() => {}); fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); }
  });
});
