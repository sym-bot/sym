'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * R3-4 (0.14.3): directed records lost on a relay drop while reported dispatched.
 *
 * `dispatched` counts records a session took. On a relay session a record then waits in the pacer
 * (20 frames a second), and at 632b95d the pacer was emptied when the connection closed: R3 measured
 * 260 directed records reported dispatched and 227 never arriving after one drop. Now what the pacer
 * still holds when the connection closes — or when the session it was sealed for ends while the
 * connection stays up — is held for that peer's key and offered again, sealed afresh, to the next
 * session proving that key; until a socket has written it, it is listed in pendingDeliveries().
 *
 * These tests stay under the receiver's own record budget (8 a second, burst 32): past it the
 * receiver drops records unevaluated, which is a separate loss (reported, not changed here).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const { fakeRelay } = require('./_fake-relay');
const { until } = require('./_core-secure');

const TOKEN = 'x'.repeat(40);
const uniq = (b) => `${b}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
const cats = (focus) => ({ focus, issue: 'redelivery', intent: 'inform', motivation: 'm', commitment: 'c', perspective: 'p', mood: { text: 'calm' } });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const N = 20;
/**
 * A fake relay that drops a link (kick) while it routes the second record b sends, synchronously, so
 * nothing else of b's is in flight (b's pacer is slowed to 2 frames a second for the sends, see
 * slowPacer): every record lost at 632b95d was then in b's pacer. With `dropCarried`, the record the
 * relay was carrying is lost with the link: the RESIDUAL — a frame b's socket wrote, which no
 * sender-side fix can see.
 */
function relayKickingAfter(victim, { dropCarried = false } = {}) {
  let records = 0;
  let relay = null;
  let kicked = false;
  const ids = {};
  relay = fakeRelay({
    tap: ({ from, payload }) => {
      if (!ids.armed || from !== ids.b || !payload || payload.type !== 'cmb-encrypted') return undefined;
      if (++records !== 2 || kicked) return undefined;
      kicked = true;
      if (ids.atKick) relay.waitingAtKick = ids.atKick();
      relay.kick(ids[victim]);
      return dropCarried ? false : undefined;
    },
  });
  relay.ids = ids;
  relay.kickedYet = () => kicked;
  return relay;
}

/** b's pacer at 2 frames a second (burst 1) while the records go out, and back to its rate after the drop. */
function slowPacer(b) {
  const r = b._relay;
  const was = { rate: r._rate, burst: r._burst };
  r._rate = 2; r._burst = 1; r._bucket = { tokens: 1, at: Date.now() };
  return () => { r._rate = was.rate; r._burst = was.burst; };
}

function pair(relay, { bRate } = {}) {
  const mk = (name, extra = {}) => new SymNode({ name: uniq(name), silent: true, relayOnly: true, discovery: new NullDiscovery(), relay: relay.url, relayToken: TOKEN, room: 'redeliver', ...extra });
  const a = mk('rd-a');
  // b paces slowly, so its directed records are still in the pacer when its link drops.
  const b = mk('rd-b', bRate ? { relayRate: bRate } : {});
  const metrics = [];
  b.on('metric', (m) => { if (/^cmb-(requeued|redelivered|undelivered)$/.test(m.type)) metrics.push(m); });
  const got = new Set();
  a.on('cmb-accepted', (e) => { const t = e.cmb && e.cmb.categories && e.cmb.categories.focus && e.cmb.categories.focus.text; if (t) got.add(t); });
  const paired = () => a._peers.has(b.nodeId) && b._peers.has(a.nodeId);
  return { a, b, metrics, got, paired };
}
async function cleanup(relay, ...nodes) {
  for (const n of nodes) { try { await n.stop(); } catch { /* */ } }
  try { await relay.close(); } catch { /* */ }
  for (const n of nodes) { try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ } }
}

describe('records the relay pacer never wrote are held and offered again (R3-4)', () => {
  it('the sender\'s relay link drops with directed records in its pacer: every one arrives on the next session', async () => {
    const relay = relayKickingAfter('b'); // the network drops b's relay link
    const { a, b, metrics, got, paired } = pair(relay);
    relay.ids.a = a.nodeId; relay.ids.b = b.nodeId;
    relay.ids.atKick = () => b._relay.state().queued;
    try {
      await a.start(); await b.start();
      assert.ok(await until(paired, 20000), 'paired over the relay');
      await sleep(400);
      const restore = slowPacer(b);
      relay.ids.armed = true;
      for (let i = 0; i < N; i++) {
        const e = b.remember(cats(`directed ${i}`), { to: a.nodeId });
        assert.strictEqual(e.delivery.dispatched, 1);
      }
      assert.ok(await until(() => relay.kickedYet(), 10000));
      restore();
      const waiting = relay.waitingAtKick;
      assert.ok(waiting >= N / 2, `most records were still waiting in b's pacer at the drop (${waiting})`);
      assert.ok(await until(() => got.size === N, 15000), `a received every directed record after the drop (${got.size} of ${N}; missing ${[...Array(N).keys()].filter((i) => !got.has(`directed ${i}`))})`);
      assert.ok(await until(() => b.pendingDeliveries().length === 0, 5000), 'nothing is left held once they are sent');
      const requeued = metrics.filter((m) => m.type === 'cmb-requeued').length;
      const redelivered = metrics.filter((m) => m.type === 'cmb-redelivered').length;
      assert.ok(requeued >= waiting - 2, `the records the pacer held were requeued (${requeued}, ${waiting} waiting)`);
      assert.strictEqual(redelivered, requeued, 'and each was sent on the next session');
      assert.strictEqual(metrics.filter((m) => m.type === 'cmb-undelivered').length, 0);
    } finally { await cleanup(relay, a, b); }
  });

  it('while they are held they are reported as not delivered, and a stop drops them as undelivered', async () => {
    const relay = fakeRelay();
    const { a, b, metrics, paired } = pair(relay, { bRate: { perSecond: 4, burst: 1 } });
    try {
      await a.start(); await b.start();
      assert.ok(await until(paired, 20000));
      await sleep(400);
      for (let i = 0; i < 8; i++) b.remember(cats(`held ${i}`), { to: a.nodeId });
      await sleep(50);
      relay.kick(b.nodeId);
      assert.ok(await until(() => b.pendingDeliveries().length > 0, 3000), 'held after the drop');
      const held = b.pendingDeliveries();
      assert.ok(held.every((h) => h.to === a.nodeId && typeof h.key === 'string' && h.key), 'each names its peer and its record');
      assert.strictEqual(b.status().pendingDeliveries, held.length);
      await b.stop(); // before the reconnect (1 s): the held records cannot be sent
      const dropped = metrics.filter((m) => m.type === 'cmb-undelivered' && m.reason === 'node-stopped');
      assert.strictEqual(dropped.length, held.length, 'each held record is said undelivered when the node stops');
      assert.strictEqual(b.pendingDeliveries().length, 0);
    } finally { await cleanup(relay, a, b); }
  });

  it('the receiver\'s link drops instead: the records sealed for its ended session come back and reach it on its next one', async () => {
    // a's link drops: the relay tells b it left, and b's session with a ends. The record the relay was
    // carrying to a is lost with a's link (the residual): every other one arrives.
    const relay = relayKickingAfter('a', { dropCarried: true });
    const { a, b, got, paired } = pair(relay);
    relay.ids.a = a.nodeId; relay.ids.b = b.nodeId;
    try {
      await a.start(); await b.start();
      assert.ok(await until(paired, 20000));
      await sleep(400);
      const restore = slowPacer(b);
      relay.ids.armed = true;
      for (let i = 0; i < N; i++) b.remember(cats(`to a ${i}`), { to: a.nodeId });
      assert.ok(await until(() => relay.kickedYet(), 10000));
      restore();
      assert.ok(await until(() => got.size === N - 1, 15000), `a received every record once back but the one lost in flight (${got.size} of ${N})`);
      assert.ok(await until(() => b.pendingDeliveries().length === 0, 5000));
      await sleep(300);
      assert.deepStrictEqual([...Array(N).keys()].filter((i) => !got.has(`to a ${i}`)), [1], 'the one missing is the one the relay lost: the residual');
    } finally { await cleanup(relay, a, b); }
  });

  it('a re-offer waits for room in the pacer and comes back by itself when there is some', async () => {
    const n = new SymNode({ name: uniq('rd-room'), silent: true, discovery: new NullDiscovery() });
    const to = '01900000-0000-7000-8000-00000000000b';
    try {
      n._running = true;
      let room = false;
      const sent = [];
      const fake = { closed: false, confirmed: true, kind: 'relay', identityKey: 'k', sessionId: 's2', name: 'fake', pendingBytes: () => 0,
        transport: { hasRoom: () => room }, trySend: (frame, meta) => { sent.push(meta.recordKey); return { ok: true }; } };
      n._peers.set(to, { peerId: to, name: 'fake', transport: fake, transports: new Map([['relay', fake]]) });
      const items = [0, 1, 2].map((i) => ({ to, bytes: 100, meta: { redeliver: true, to, key: 'k', sessionId: 's1', frame: { type: 'cmb' }, recordKey: `cmb-${i}`, since: i, attempts: 1, held: false, offered: false, bytes: 0 } }));
      n._holdUnflushed(items);
      await new Promise((r) => setImmediate(r));
      assert.deepStrictEqual(sent, [], 'no room: nothing is offered (a refused sealed frame would end the session)');
      room = true;
      await until(() => sent.length === 3, 2000);
      assert.deepStrictEqual(sent, ['cmb-0', 'cmb-1', 'cmb-2'], 'offered once there was room, with nothing else to re-arm it');
    } finally { n._running = false; n._dropRedelivery('test'); await n.stop(); fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); }
  });

  it('the held list is bounded: past the bound the oldest is dropped and said undelivered', () => {
    const n = new SymNode({ name: uniq('rd-bound'), silent: true, discovery: new NullDiscovery() });
    const said = [];
    n.on('metric', (m) => { if (m.type === 'cmb-undelivered') said.push(m); });
    try {
      const to = '01900000-0000-7000-8000-00000000000a';
      const items = [];
      for (let i = 0; i < 2050; i++) items.push({ to, bytes: 100, meta: { redeliver: true, to, key: 'k', sessionId: 's', frame: { type: 'cmb' }, recordKey: `cmb-${i}`, since: i, attempts: 1, held: false, offered: false, bytes: 0 } });
      n._running = true; // as a running node holds them (a stopped one says them undelivered at once)
      n._holdUnflushed(items);
      n._running = false;
      const held = n.pendingDeliveries();
      assert.strictEqual(held.length, 2048, 'at most 2048 a peer');
      assert.strictEqual(held[0].key, 'cmb-2', 'the oldest went first');
      assert.deepStrictEqual(said.map((m) => [m.key, m.reason]), [['cmb-0', 'redelivery-overflow'], ['cmb-1', 'redelivery-overflow']]);
    } finally { n.stop(); fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); }
  });
});
