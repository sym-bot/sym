'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads
process.env.SYM_SEMANTIC_ENCODER = process.env.SYM_SEMANTIC_ENCODER || 'off'; // what is measured here is not SVAF

/**
 * Flow control for directed and room records (0.14.3): delivery end to end, with real nodes.
 *
 * A receiver applies a record budget per session (8 a second after a burst of 32; 128 KiB of record
 * text a second after 1.5 MiB). Until 0.14.3 a record past it was DROPPED unevaluated while its
 * sender reported it dispatched, and nothing offered it again. Measured on 9f6847c (and 0.14.2):
 * 49 directed messages in a burst arrived as 38 over a relay (32 over the LAN); 12 records of
 * 200 KB as 7; 40 of 50 KB as 30; 120 records held across a relay drop and re-offered as 37, the
 * sender saying 115 redelivered. Now the receiver queues what is past its budget (delay, never a
 * silent drop), advertises its budget, and the sender paces every record to it.
 *
 * Every test here fails on 9f6847c (a `git archive` of it) and passes now. The mixed-version tests
 * stand a 0.14.3 node in for 0.14.2 the way 0.14.2 behaves (it drops past a count-only budget and
 * knows no flow-control frame; it writes everything at once): on 9f6847c the stock node already
 * behaves so. The same runs against a real 0.14.2 tree are in the CHANGELOG.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery, BonjourDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const { fakeRelay } = require('./_fake-relay');
const { until } = require('./_core-secure');

const TOKEN = 'f'.repeat(40);
const uniq = (b) => `${b}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const CATS = (focus, issue = 'flow control') => ({ focus, issue, intent: 'deliver', motivation: 'm', commitment: 'c', perspective: 'p', mood: { text: 'calm', valence: 0, arousal: 0 } });
const text = (kb, seed) => { let t = ''; let j = 0; while (t.length < kb * 1024) t += `report ${seed} line ${j++} lorem ipsum dolor sit amet `; return t.slice(0, kb * 1024); };

/** Two nodes in one room over the LAN (TCP on the loopback, found through the loopback registry). */
function lanPair(extraR = {}) {
  const room = uniq('flow-lan');
  const mk = (n, extra = {}) => new SymNode({ name: uniq(n), room, silent: true, discovery: new BonjourDiscovery({ mdns: false, room }), ...extra });
  return { s: mk('fl-s'), r: mk('fl-r', extraR) };
}
/** Two nodes in one room over a relay. */
function relayPair(relay, { sRate } = {}) {
  const room = uniq('flow-relay');
  const mk = (n, extra = {}) => new SymNode({ name: uniq(n), room, silent: true, relayOnly: true, relay: relay.url, relayToken: TOKEN, discovery: new NullDiscovery(), ...extra });
  return { s: mk('fr-s', sRate ? { relayRate: sRate } : {}), r: mk('fr-r') };
}
const paired = (s, r) => () => s._peers.has(r.nodeId) && r._peers.has(s.nodeId);
async function stopAll(...nodes) {
  for (const n of nodes) { try { await n.stop(); } catch { /* */ } }
  for (const n of nodes) { try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ } }
}

/** What a node surfaced, in order: the focus of each record ('cmb-accepted'), or a message's text. */
function surfaced(node) {
  const seen = [];
  node.on('cmb-accepted', (e) => { const f = e && e.cmb && e.cmb.categories && e.cmb.categories.focus; const t = f && (f.text || f); if (typeof t === 'string') seen.push(t); });
  node.on('message', (_from, t) => seen.push(t));
  return seen;
}
/** Every metric a node emits, by type. */
function metrics(node) {
  const by = {};
  node.on('metric', (m) => { (by[m.type] || (by[m.type] = [])).push(m); });
  by.count = (t) => (by[t] || []).length;
  return by;
}
const distinct = (seen, re) => new Set(seen.filter((t) => re.test(t)));
const dups = (seen) => seen.length - new Set(seen).size;
const pending = (n) => (typeof n.pendingDeliveries === 'function' ? n.pendingDeliveries().length : 0);

/**
 * The sender's counts are true: everything it took is accounted for — written at once, or held and
 * written later — nothing left pending, nothing given up, and every record it held it later wrote.
 */
function assertSenderTrue(s, m, total, { dispatched, queued }) {
  assert.strictEqual(dispatched + queued, total, `the sender took every record (${dispatched} written at once, ${queued} held for the budget)`);
  assert.strictEqual(pending(s), 0, 'nothing is left pending');
  assert.strictEqual(m.count('cmb-undelivered'), 0, 'nothing was given up');
  const held = new Set((m['cmb-requeued'] || []).map((x) => x.key));
  const written = new Set((m['cmb-redelivered'] || []).map((x) => x.key));
  assert.deepStrictEqual([...written].sort(), [...held].sort(), 'every record it held, it then wrote');
  assert.strictEqual(typeof s.undelivered, 'function', 'the sender lists what it gives up (undelivered())');
  assert.deepStrictEqual(s.undelivered(), []);
}

/** Send `n` directed records (remember) of `kb` KiB each; count what the sender said of each. */
function burst(s, to, n, kb, label = 'rec') {
  let dispatched = 0;
  let queued = 0;
  for (let i = 0; i < n; i++) {
    const e = s.remember(CATS(`${label} ${i}`, kb ? text(kb, `${label}${i}`) : 'flow control'), { to });
    if (e.delivery.dispatched) dispatched++;
    else if (e.delivery.queued) queued++;
  }
  return { dispatched, queued };
}

// ── 0.14.2 as the other end ───────────────────────────────────────────────────────────────────
/**
 * Make `node` receive as 0.14.2 does: a record past its count budget (8 a second, burst 32; 0.14.2
 * had no size budget) is dropped unevaluated, and no flow-control frame is sent or understood. On
 * 9f6847c the stock node drops past its budget already (with the size budget too), so nothing is done.
 */
function asLegacyReceiver(node) {
  const fh = node._frameHandler;
  if (!fh._admission) return;
  fh.flowBudget = () => ({ type: 'x-not-a-budget' }); // advertises nothing (a frame a receiver ignores, §7.3)
  // 0.14.2's lanes by count only: 32 a second (burst 128) before verification, 8 (burst 32) before SVAF.
  const holds = (session, slot, rate, burst) => {
    const b = session[slot];
    return !b || Math.min(burst, b.tokens + ((Date.now() - b.at) * rate) / 1000) >= 1;
  };
  fh._admission.offer = (session, peerId, peerName, msg, chars) => {
    if (!holds(session, '_verifyBucket', 32, 128) || !holds(session, '_recordBucket', 8, 32)) { node.emit('metric', { type: 'cmb-over-budget', from: peerName }); return undefined; }
    return fh._admission._o.run({ session, peerId, peerName, msg, chars });
  };
}
/** Make `node` send as 0.14.2 does: every record written at once, whatever the receiver says. */
function asLegacySender(node) {
  if (typeof node._flowSession === 'function') node._flowSession = () => false;
}

describe('flow control: honest bursts are delivered, not dropped', () => {
  it('49 directed messages sent in one burst over the LAN: all 49 surface, once each and in order, and the sender\'s counts are true', async () => {
    const { s, r } = lanPair();
    const seen = surfaced(r);
    const m = metrics(s);
    const rm = metrics(r);
    try {
      await s.start(); await r.start();
      assert.ok(await until(paired(s, r), 20000), 'paired over the LAN');
      await sleep(300);
      let taken = 0;
      for (let i = 0; i < 49; i++) taken += s.send(`message number ${i}`, { to: r.nodeId });
      assert.strictEqual(taken, 49, 'the sender took all 49');
      assert.ok(await until(() => distinct(seen, /^message number/).size === 49 && pending(s) === 0, 20000), `all 49 surfaced (${distinct(seen, /^message number/).size})`);
      await sleep(300);
      assert.strictEqual(dups(seen), 0, 'each once');
      assert.deepStrictEqual(seen.filter((t) => /^message number/.test(t)), Array.from({ length: 49 }, (_, i) => `message number ${i}`), 'in the order sent');
      assert.strictEqual(rm.count('cmb-over-budget') + rm.count('cmb-queue-refused'), 0, 'the receiver dropped and refused nothing');
      assert.strictEqual(pending(s), 0);
      assert.strictEqual(m.count('cmb-undelivered'), 0);
    } finally { await stopAll(s, r); }
  });

  it('12 directed records of 200 KB over the LAN: all 12 surface once, and the sender says how many it held for the size budget', async () => {
    const { s, r } = lanPair();
    const seen = surfaced(r);
    const m = metrics(s);
    try {
      await s.start(); await r.start();
      assert.ok(await until(paired(s, r), 20000));
      await sleep(300);
      const counts = burst(s, r.nodeId, 12, 200, 'big');
      assert.ok(counts.queued > 0, `past the 1.5 MiB burst the sender held records for the budget (${counts.queued})`);
      assert.ok(await until(() => distinct(seen, /^big /).size === 12 && pending(s) === 0, 40000), `all 12 surfaced (${distinct(seen, /^big /).size})`);
      await sleep(300);
      assert.strictEqual(dups(seen), 0);
      assertSenderTrue(s, m, 12, counts);
    } finally { await stopAll(s, r); }
  });

  it('40 directed records of 50 KB over the LAN: all 40 surface once', async () => {
    const { s, r } = lanPair();
    const seen = surfaced(r);
    const m = metrics(s);
    try {
      await s.start(); await r.start();
      assert.ok(await until(paired(s, r), 20000));
      await sleep(300);
      const counts = burst(s, r.nodeId, 40, 50, 'mid');
      assert.ok(await until(() => distinct(seen, /^mid /).size === 40 && pending(s) === 0, 40000), `all 40 surfaced (${distinct(seen, /^mid /).size})`);
      await sleep(300);
      assert.strictEqual(dups(seen), 0);
      assertSenderTrue(s, m, 40, counts);
    } finally { await stopAll(s, r); }
  });

  it('49 directed messages 15 ms apart over a relay (the review\'s r-msgloss): all 49 surface once, in order', async () => {
    const relay = fakeRelay();
    const { s, r } = relayPair(relay);
    const seen = surfaced(r);
    const m = metrics(s);
    try {
      await s.start(); await r.start();
      assert.ok(await until(paired(s, r), 20000), 'paired over the relay');
      await sleep(400);
      for (let i = 0; i < 49; i++) { s.send(`message number ${i}`, { to: r.nodeId }); await sleep(15); }
      assert.ok(await until(() => distinct(seen, /^message number/).size === 49 && pending(s) === 0, 20000), `all 49 surfaced (${distinct(seen, /^message number/).size})`);
      await sleep(300);
      assert.strictEqual(dups(seen), 0);
      assert.deepStrictEqual(seen.filter((t) => /^message number/.test(t)), Array.from({ length: 49 }, (_, i) => `message number ${i}`), 'in the order sent');
      assert.strictEqual(m.count('cmb-undelivered'), 0);
    } finally { await stopAll(s, r); await relay.close(); }
  });
});

describe('flow control: records held across a drop are re-offered within the receiver\'s budget', () => {
  it('120 directed records across a relay drop (both links cut, the pacer back to 20/s burst 200): all 120 surface once; the sender\'s counts are true', async () => {
    let relay = null;
    let cut = false;
    let rRef = null;
    // Both links are cut from inside the receiver's own delivery of the 5th record: nothing of the
    // sender's is then in flight in the relay (its pacer writes one frame every 250 ms), so what this
    // test measures is the held list and the budget, not the residual.
    relay = fakeRelay();
    const { s, r } = relayPair(relay, { sRate: { perSecond: 4, burst: 1 } });
    rRef = r;
    const seen = surfaced(r);
    r.on('cmb-accepted', () => {
      if (!cut && distinct(seen, /^held /).size >= 5) { cut = true; relay.kick(s.nodeId); relay.kick(rRef.nodeId); }
    });
    const m = metrics(s);
    const rm = metrics(r);
    try {
      await s.start(); await r.start();
      assert.ok(await until(paired(s, r), 20000));
      await sleep(400);
      const counts = burst(s, r.nodeId, 120, 0, 'held');
      assert.ok(await until(() => cut, 15000), 'the links were cut mid-stream');
      // The review's FASTPACER: the re-offer goes out of a pacer that would write 200 frames at once.
      s._relay._rate = 20; s._relay._burst = 200; s._relay._bucket = { tokens: 200, at: Date.now() };
      assert.ok(await until(() => distinct(seen, /^held /).size === 120 && pending(s) === 0, 60000), `all 120 surfaced (${distinct(seen, /^held /).size}; pending ${pending(s)})`);
      await sleep(500);
      assert.strictEqual(dups(seen), 0, 'each once');
      assert.strictEqual(rm.count('cmb-over-budget') + rm.count('cmb-queue-refused'), 0, 'the receiver dropped and refused nothing');
      assertSenderTrue(s, m, 120, counts);
    } finally { await stopAll(s, r); await relay.close(); }
  });

  it('120 directed records across a LAN drop: the records not yet written wait, and all 120 surface once on the next session', async () => {
    const { s, r } = lanPair();
    const seen = surfaced(r);
    let cut = false;
    r.on('cmb-accepted', () => {
      if (cut || distinct(seen, /^lan /).size < 60) return;
      cut = true;
      // The receiver's socket closes under the sender, between two of its paced writes.
      const sess = r._peers.get(s.nodeId) && r._peers.get(s.nodeId).transports.get('bonjour');
      if (sess && sess.transport) sess.transport.close();
      setTimeout(() => { try { s._discovery._scanLoopback(); r._discovery._scanLoopback(); } catch { /* */ } }, 300);
    });
    const m = metrics(s);
    try {
      await s.start(); await r.start();
      assert.ok(await until(paired(s, r), 20000));
      await sleep(300);
      const counts = burst(s, r.nodeId, 120, 0, 'lan');
      assert.ok(await until(() => cut, 20000), 'the LAN connection was cut mid-stream');
      assert.ok(await until(() => distinct(seen, /^lan /).size === 120 && pending(s) === 0, 60000), `all 120 surfaced (${distinct(seen, /^lan /).size}; pending ${pending(s)})`);
      await sleep(300);
      assert.strictEqual(dups(seen), 0, 'each once');
      assertSenderTrue(s, m, 120, counts);
    } finally { await stopAll(s, r); }
  });
});

describe('flow control with a 0.14.2 node at the other end', () => {
  it('new sender → 0.14.2 receiver (drops past 8/s burst 32, advertises nothing): 49 messages and 12 × 200 KB all surface, none dropped', async () => {
    const { s, r } = lanPair();
    asLegacyReceiver(r);
    const seen = surfaced(r);
    const rm = metrics(r);
    const m = metrics(s);
    try {
      await s.start(); await r.start();
      assert.ok(await until(paired(s, r), 20000));
      await sleep(300);
      for (let i = 0; i < 49; i++) s.send(`message number ${i}`, { to: r.nodeId });
      const counts = burst(s, r.nodeId, 12, 200, 'old-big');
      assert.ok(await until(() => distinct(seen, /^message number/).size === 49 && distinct(seen, /^old-big /).size === 12 && pending(s) === 0, 40000),
        `all delivered (${distinct(seen, /^message number/).size} of 49 messages, ${distinct(seen, /^old-big /).size} of 12 records)`);
      await sleep(300);
      assert.strictEqual(rm.count('cmb-over-budget'), 0, 'the old receiver dropped nothing: the sender kept to its budget, with a margin');
      assert.strictEqual(dups(seen), 0);
      assert.strictEqual(m.count('cmb-undelivered'), 0);
      assert.strictEqual(counts.dispatched + counts.queued, 12);
    } finally { await stopAll(s, r); }
  });

  it('0.14.2 sender (writes everything at once, hears nothing) → new receiver: 49 messages and 12 × 200 KB all surface, queued and not dropped', async () => {
    const { s, r } = lanPair();
    asLegacySender(s);
    const seen = surfaced(r);
    const rm = metrics(r);
    try {
      await s.start(); await r.start();
      assert.ok(await until(paired(s, r), 20000));
      await sleep(300);
      for (let i = 0; i < 49; i++) s.send(`message number ${i}`, { to: r.nodeId });
      burst(s, r.nodeId, 12, 200, 'from-old');
      assert.ok(await until(() => distinct(seen, /^message number/).size === 49 && distinct(seen, /^from-old /).size === 12, 40000),
        `all delivered (${distinct(seen, /^message number/).size} of 49 messages, ${distinct(seen, /^from-old /).size} of 12 records)`);
      await sleep(300);
      assert.strictEqual(dups(seen), 0);
      assert.ok(rm.count('cmb-queued') > 0, 'what was past the budget waited in the queue');
      assert.strictEqual(rm.count('cmb-queue-refused'), 0, 'and nothing was refused');
      assert.deepStrictEqual(seen.filter((t) => /^message number/.test(t)), Array.from({ length: 49 }, (_, i) => `message number ${i}`), 'in the order sent');
    } finally { await stopAll(s, r); }
  });
});
