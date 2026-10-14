'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads
process.env.SYM_SEMANTIC_ENCODER = process.env.SYM_SEMANTIC_ENCODER || 'off'; // what is measured here is not SVAF

/**
 * Flow control (0.14.3): the receiver's bounds, the two control frames, and what a sender does when
 * it is told. See tests/flow-control.test.js for delivery end to end and lib/flow-control.js for the
 * design. Every test here fails on 9f6847c (most because what it checks is new: the queue, the
 * frames, the held list's new states) and passes now; each guard the design adds is pinned by one.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery, BonjourDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const { connectNodes, until, signedRecord } = require('./_core-secure');

const uniq = (b) => `${b}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const CATS = (focus) => ({ focus, issue: 'flow control', intent: 'deliver', motivation: 'm', commitment: 'c', perspective: 'p', mood: { text: 'calm', valence: 0, arousal: 0 } });
const big = (n, seed) => { let t = ''; let j = 0; while (t.length < n) t += `queue bound ${seed} line ${j++} `; return t.slice(0, n); };
function mk(base, extra = {}) { return new SymNode({ name: uniq(base), silent: true, discovery: new NullDiscovery(), room: extra.room || 'flow', ...extra }); }
async function stopAll(...nodes) {
  for (const n of nodes) { try { await n.stop(); } catch { /* */ } }
  for (const n of nodes) { try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ } }
}
function metrics(node) {
  const by = {};
  node.on('metric', (m) => { (by[m.type] || (by[m.type] = [])).push(m); });
  by.count = (t) => (by[t] || []).length;
  return by;
}
/** A node's identity as the test helpers take it (to sign records in its name). */
const authorOf = (n) => ({ nodeId: n.nodeId, name: n.name, publicKey: n._identity.publicKey, privateKey: n._identity.privateKey });
/** Make `node` send as 0.14.2 does: every record written at once, whatever the receiver says. */
const asLegacySender = (node) => { if (typeof node._flowSession === 'function') node._flowSession = () => false; };
/** The refusal frames a node receives, as they arrive (frame-handler dispatch). */
function refusalsAt(node) {
  const got = [];
  const orig = node._frameHandler._dispatch.bind(node._frameHandler);
  node._frameHandler._dispatch = (session, peerId, peerName, msg) => {
    if (msg && msg.type === 'cmb-refused') got.push({ at: Date.now(), frame: JSON.parse(JSON.stringify(msg)) });
    return orig(session, peerId, peerName, msg);
  };
  return got;
}
const flowOf = (n) => (n.status().flowControl || {}).receiver || {};
/** Count record frames on a pipe, by direction, with when each went. */
function pipeTap() {
  const frames = [];
  return { frames, tap: (f, dir) => { if (f && f.type === 'cmb-encrypted') frames.push({ dir, at: Date.now() }); } };
}

describe('flow control, the receiver: past its budget a record waits; past its queue it is refused and its sender told', () => {
  it('a flood from a peer that ignores everything: the work stays within the budget, the queue within its bound, every refusal is reported, and the peer is cut', async () => {
    const N = mk('fb-n'); const E = mk('fb-e');
    asLegacySender(E);
    const nm = metrics(N);
    try {
      await N.start(); await E.start();
      await connectNodes(E, N);
      const refused = refusalsAt(E);
      // The work: records that passed every check and are evaluated (the host hook fires for each).
      const spent = [];
      N.on('verified-record', () => spent.push(Date.now()));
      const s = E._peers.get(N.nodeId).transport;
      const author = authorOf(E);
      const sent = new Set();
      const wave = (from, n) => {
        for (let i = from; i < from + n; i++) {
          const cmb = signedRecord(author, { room: 'flow', to: N.nodeId, categories: { focus: `flood ${i}` } });
          sent.add(cmb.metadata.assertionId);
          if (!s.send({ type: 'cmb', cmb })) break;
        }
      };
      const t0 = Date.now();
      wave(0, 1700);
      assert.ok(await until(() => refused.length > 0, 5000), 'told');
      assert.strictEqual(flowOf(N).cut, 0, 'refusals before the peer was told never count toward the cut');
      wave(1700, 600); // and it keeps on, told
      assert.ok(await until(() => s.closed || nm.count('record-flood-cut') > 0, 15000), 'the peer that kept on past its queue after it was told was cut');
      const elapsed = (Date.now() - t0) / 1000;
      const f = flowOf(N);
      assert.ok(spent.length <= 32 + 8 * elapsed + 2, `the work stayed within the budget (${spent.length} evaluated in ${elapsed.toFixed(1)} s)`);
      assert.ok(f.peakRecords <= 512, `the queue held at most 512 of the session's records (${f.peakRecords})`);
      assert.ok(f.refused > 1000, `past it, records were refused (${f.refused})`);
      assert.ok(f.notices >= 1 && f.notices <= Math.ceil(elapsed) + 2, `the sender was told, at most once a second (${f.notices} notices in ${elapsed.toFixed(1)} s)`);
      assert.ok(f.unlisted > 0, 'refusals past what a notice can carry were counted, not listed');
      assert.ok(refused.length >= 1, 'the refusal reached the sender');
      for (const r of refused) {
        assert.ok(r.frame.assertionIds.length >= 1 && r.frame.assertionIds.length <= 256, 'a notice names at most 256 records');
        assert.ok(r.frame.assertionIds.every((id) => sent.has(id)), 'and only records this peer sent');
        assert.ok(Number.isInteger(r.frame.retryAfterMs) && r.frame.retryAfterMs >= 1000 && r.frame.retryAfterMs <= 64000, `with a retry-after within its bounds (${r.frame.retryAfterMs})`);
      }
      assert.ok(refused[0].frame.retryAfterMs >= 30000, `the retry-after is the time the full queue needs to drain (${refused[0].frame.retryAfterMs} ms for ~512 records at 8/s)`);
      assert.ok(N._floodPenalised(E.nodeId), 'and its peer is not admitted again for a while');
      assert.ok(await until(() => flowOf(N).queuedRecords === 0, 3000), `what it had queued is dropped, not evaluated (${flowOf(N).queuedRecords} left)`);
      assert.ok(nm.count('cmb-queue-dropped') > 100);
      assert.ok(nm.count('cmb-queue-refused') === f.refused && nm.count('cmb-queued') === f.queued, 'every refusal and every queued record is a metric');
    } finally { await stopAll(N, E); }
  });

  it('large records: the queue is bounded by size as well (8 Mi characters a session)', async () => {
    const N = mk('fs-n'); const E = mk('fs-e');
    asLegacySender(E);
    try {
      await N.start(); await E.start();
      await connectNodes(E, N);
      const s = E._peers.get(N.nodeId).transport;
      const author = authorOf(E);
      for (let i = 0; i < 40; i++) s.send({ type: 'cmb', cmb: signedRecord(author, { room: 'flow', to: N.nodeId, categories: { focus: big(200000, `f${i}`), issue: big(200000, `i${i}`) } }) });
      assert.ok(await until(() => flowOf(N).refused > 0, 10000), 'past 8 Mi characters, records are refused');
      const f = flowOf(N);
      assert.ok(f.peakChars <= 8 * 1024 * 1024, `the queue held at most 8 Mi characters (${f.peakChars})`);
      assert.ok(f.peakRecords >= 15, `which is ~20 records of 400 K (${f.peakRecords})`);
    } finally { await stopAll(N, E); }
  });

  it('the queue in all is bounded by count: a record past it is refused for whichever session brings it, its sender told when to retry, never cut', async () => {
    const N = mk('ft-n'); const E1 = mk('ft-e1'); const E2 = mk('ft-e2');
    asLegacySender(E1); asLegacySender(E2);
    const nm = metrics(N);
    try {
      await N.start(); await E1.start(); await E2.start();
      N._frameHandler._admission.limits.totalRecords = 40;
      N._frameHandler._admission.limits.refusalsBeforeCut = 5;
      await connectNodes(E1, N); await connectNodes(E2, N);
      const told2 = refusalsAt(E2);
      for (const [E, tag] of [[E1, 'a'], [E2, 'b']]) {
        const s = E._peers.get(N.nodeId).transport;
        const author = authorOf(E);
        for (let i = 0; i < 100; i++) s.send({ type: 'cmb', cmb: signedRecord(author, { room: 'flow', to: N.nodeId, categories: { focus: `total ${tag} ${i}` } }) });
        // E1's queue holds the queue in all for the rest of the test: its session's lane, spent far ahead.
        if (E === E1) {
          assert.ok(await until(() => flowOf(N).queuedRecords === 40, 3000));
          N._peers.get(E1.nodeId).transport._recordBucket = { tokens: -1e6, at: Date.now() };
        }
        await sleep(200);
      }
      assert.ok(await until(() => told2.length > 0, 5000), 'the second sender was told');
      // Told, it sends on while the queue in all is still full (others' records): refused, never cut.
      const s2 = E2._peers.get(N.nodeId).transport;
      for (let i = 100; i < 120; i++) s2.send({ type: 'cmb', cmb: signedRecord(authorOf(E2), { room: 'flow', to: N.nodeId, categories: { focus: `total b ${i}` } }) });
      await sleep(300);
      const f = flowOf(N);
      assert.ok(f.peakRecords <= 40, `at most the total bound waited (${f.peakRecords})`);
      assert.ok(f.refused >= 90, `the rest was refused (${f.refused})`);
      assert.ok((nm['cmb-queue-refused'] || []).every((m) => m.reason === 'queue-full'), 'for the queue in all');
      assert.ok(told2[0].frame.retryAfterMs >= 3000, `told to retry once the longest queue has drained (${told2[0].frame.retryAfterMs} ms; ~40 records at 8/s)`);
      assert.ok(f.refused >= 108, `E2's records sent after it was told were refused too (${f.refused})`);
      assert.strictEqual(f.cut, 0, 'a sender refused for others\' records is never cut');
      assert.ok(!E1._peers.get(N.nodeId).transport.closed && !E2._peers.get(N.nodeId).transport.closed);
    } finally { await stopAll(N, E1, E2); }
  });

  it('the queue in all is bounded by size too', async () => {
    const N = mk('fc-n'); const E = mk('fc-e');
    asLegacySender(E);
    try {
      await N.start(); await E.start();
      N._frameHandler._admission.limits.totalChars = 300 * 1024;
      await connectNodes(E, N);
      const s = E._peers.get(N.nodeId).transport;
      const author = authorOf(E);
      // 100 records of 60 K: the first ~25 within the 1.5 Mi burst, then the queue, at most 300 K of it.
      for (let i = 0; i < 100; i++) s.send({ type: 'cmb', cmb: signedRecord(author, { room: 'flow', to: N.nodeId, categories: { focus: big(60000, `c${i}`) } }) });
      assert.ok(await until(() => flowOf(N).refused > 0, 10000));
      const f = flowOf(N);
      assert.ok(f.peakChars <= 300 * 1024, `the queue in all held at most its size bound (${f.peakChars})`);
      assert.ok(f.peakRecords <= 5, `about 5 records of 60 K (${f.peakRecords})`);
    } finally { await stopAll(N, E); }
  });

  it('a peer no longer admitted while its records wait: what it queued is dropped, counted, never evaluated', async () => {
    const N = mk('fd-n'); const E = mk('fd-e');
    asLegacySender(E);
    const nm = metrics(N);
    const seen = [];
    N.on('cmb-accepted', (e) => seen.push(e.cmb.categories.focus.text || e.cmb.categories.focus));
    try {
      await N.start(); await E.start();
      await connectNodes(E, N);
      const s = E._peers.get(N.nodeId).transport;
      const author = authorOf(E);
      for (let i = 0; i < 60; i++) s.send({ type: 'cmb', cmb: signedRecord(author, { room: 'flow', to: N.nodeId, categories: { focus: `door ${i}` } }) });
      assert.ok(await until(() => nm.count('cmb-queued') >= 20, 5000), 'records past the budget wait');
      // The door now refuses that peer (evicted from the room, say): what waits for it is not admitted.
      const door = N._roomDoor.bind(N);
      N._roomDoor = (peerId) => (peerId === E.nodeId ? { pass: false, reason: 'evicted' } : door(peerId));
      assert.ok(await until(() => nm.count('cmb-queue-dropped') > 0 && flowOf(N).queuedRecords === 0, 8000), 'what waited was dropped');
      await sleep(300);
      const after = seen.length;
      assert.ok(after <= 33, `nothing that waited was evaluated (${after} surfaced: the burst only)`);
      assert.ok(nm['cmb-queue-dropped'].every((m) => m.reason === 'not-admitted'));
    } finally { await stopAll(N, E); }
  });

  it('a peer penalised for a forgery while its records wait: what it queued is dropped', async () => {
    const N = mk('fpn-n'); const E = mk('fpn-e');
    asLegacySender(E);
    const nm = metrics(N);
    try {
      await N.start(); await E.start();
      await connectNodes(E, N);
      const s = E._peers.get(N.nodeId).transport;
      const author = authorOf(E);
      for (let i = 0; i < 60; i++) s.send({ type: 'cmb', cmb: signedRecord(author, { room: 'flow', to: N.nodeId, categories: { focus: `penalty ${i}` } }) });
      assert.ok(await until(() => nm.count('cmb-queued') >= 20, 5000));
      if (!N._forgeryPenalty) N._forgeryPenalty = new Map();
      N._forgeryPenalty.set(E.nodeId, Date.now() + 60_000);
      assert.ok(await until(() => flowOf(N).queuedRecords === 0, 3000), 'dropped at once');
      assert.ok(nm.count('cmb-queue-dropped') >= 20);
    } finally { await stopAll(N, E); }
  });

  it('a session\'s records are admitted in arrival order: a small one never overtakes a large one waiting for the size budget', async () => {
    const N = mk('fo-n'); const E = mk('fo-e');
    asLegacySender(E);
    const seen = [];
    N.on('cmb-accepted', (e) => { const t = e.cmb.categories.focus.text || e.cmb.categories.focus; if (/^order /.test(t)) seen.push(t.slice(0, 12)); });
    N.on('message', (_f, t) => { if (/^order /.test(t)) seen.push(t); });
    try {
      await N.start(); await E.start();
      await connectNodes(E, N);
      const s = E._peers.get(N.nodeId).transport;
      const author = authorOf(E);
      for (let i = 0; i < 12; i++) s.send({ type: 'cmb', cmb: signedRecord(author, { room: 'flow', to: N.nodeId, categories: { focus: `order big ${String(i).padStart(2, '0')} ${big(200000, `o${i}`)}` } }) });
      await sleep(100);
      for (let i = 0; i < 3; i++) E.send(`order small ${i}`, { to: N.nodeId });
      assert.ok(await until(() => seen.length === 15, 30000), `all surfaced (${seen.length})`);
      assert.deepStrictEqual(seen.slice(12), ['order small 0', 'order small 1', 'order small 2'], 'the small ones after every large one before them');
    } finally { await stopAll(N, E); }
  });

  it('a notice goes at most once a second, whatever asks for it (a new session of the peer included), and what waits is sent a second later', async () => {
    const { RecordAdmission } = require('../lib/flow-control');
    const sent = [];
    const session = { nodeId: 'p', confirmed: true, closed: false, trySend: (f) => { sent.push({ f, at: Date.now() }); return { ok: true }; } };
    const adm = new RecordAdmission({ wait: () => 1000, run: () => {}, admitted: () => true, sessionFor: () => session, cut: () => {}, fail: () => {}, metric: () => {}, say: () => {} });
    adm.limits.queueRecords = 0;
    const msg = (i) => ({ cmb: { metadata: { assertionId: `asrt-${i.toString(16).padStart(64, '0')}` } } });
    let flushes = 0;
    const flush = adm.flush.bind(adm);
    adm.flush = (...a) => { flushes++; return flush(...a); };
    adm.offer(session, 'p', 'p', msg(1), 100);
    adm.flush('p');
    assert.strictEqual(sent.length, 1, 'the first notice goes at once');
    adm.offer(session, 'p', 'p', msg(2), 100);
    adm.flushFor('p');
    adm.flush('p');
    assert.strictEqual(sent.length, 1, 'a second within the second waits');
    flushes = 0;
    await until(() => sent.length === 2, 2000);
    assert.strictEqual(sent.length, 2, 'and goes a second after the first');
    assert.ok(sent[1].at - sent[0].at >= 990, `${sent[1].at - sent[0].at} ms apart`);
    assert.ok(flushes <= 3, `one timer waited the second out, nothing spun (${flushes} flushes)`);
    adm.stop();
  });

  it('only a peer that keeps on past ITS OWN queue in one episode is cut: refusals start over once its queue has drained', async () => {
    const N = mk('fe-n'); const E = mk('fe-e');
    asLegacySender(E);
    try {
      await N.start(); await E.start();
      N._frameHandler._admission.limits.queueRecords = 8;
      N._frameHandler._admission.limits.refusalsBeforeCut = 20;
      await connectNodes(E, N);
      const s = E._peers.get(N.nodeId).transport;
      const author = authorOf(E);
      const told = refusalsAt(E);
      const send = (tag, from, n) => { for (let i = from; i < from + n; i++) s.send({ type: 'cmb', cmb: signedRecord(author, { room: 'flow', to: N.nodeId, categories: { focus: `episode ${tag} ${i}` } }) }); };
      // An episode: a burst past the queue (32 now, 8 queued, the rest refused before the peer is
      // told), then, told, `after` more while its queue is still full.
      const episode = async (tag, after) => {
        const n = told.length;
        send(tag, 0, 60);
        assert.ok(await until(() => told.length > n, 5000), `told in episode ${tag}`);
        send(tag, 60, after);
        await until(() => flowOf(N).queuedRecords === 0, 15000);
        await sleep(1100);
      };
      await episode('a', 15);
      await episode('b', 15);
      assert.strictEqual(flowOf(N).cut, 0, 'two episodes under the bound (15 refused after being told, of 20) do not add up to a cut');
      assert.ok(!s.closed);
      await episode('c', 40);
      assert.ok(await until(() => flowOf(N).cut === 1, 8000), 'one episode past the bound is a cut');
    } finally { await stopAll(N, E); }
  });

  it('copies of a record already delivered spend the pre-verification lane: at most its burst and 32 a second are checked', async () => {
    const N = mk('fv-n'); const E = mk('fv-e');
    asLegacySender(E);
    const nm = metrics(N);
    try {
      await N.start(); await E.start();
      await connectNodes(E, N);
      const s = E._peers.get(N.nodeId).transport;
      const rec = signedRecord(authorOf(E), { room: 'flow', to: N.nodeId, categories: { focus: 'once only' } });
      s.send({ type: 'cmb', cmb: rec });
      assert.ok(await until(() => N._frameHandler._ledger.size > 0, 5000), 'the record surfaced');
      await sleep(4500); // the lanes refill
      const t0 = Date.now();
      for (let i = 0; i < 400; i++) s.send({ type: 'cmb', cmb: JSON.parse(JSON.stringify(rec)) });
      await sleep(1000);
      const t = (Date.now() - t0) / 1000;
      const checked = nm.count('cmb-already-delivered');
      assert.ok(checked >= 100, `the burst was checked (${checked})`);
      assert.ok(checked <= 128 + 32 * t + 4, `and no more than the lane holds (${checked} in ${t.toFixed(1)} s)`);
      assert.ok(await until(() => nm.count('cmb-already-delivered') === 400, 15000), `every copy was checked in the end, none dropped unchecked (${nm.count('cmb-already-delivered')} of 400)`);
    } finally { await stopAll(N, E); }
  });

  it('the node stopping refuses what waits and tells the sender, which offers it again to the next session: every record surfaces once', async () => {
    const room = uniq('flow-stop');
    const s = new SymNode({ name: uniq('fz-s'), room, silent: true, discovery: new BonjourDiscovery({ mdns: false, room }) });
    const r = new SymNode({ name: uniq('fz-r'), room, silent: true, discovery: new BonjourDiscovery({ mdns: false, room }) });
    const seen = [];
    r.on('cmb-accepted', (e) => { const t = e.cmb.categories.focus.text || e.cmb.categories.focus; if (/^stop /.test(t)) seen.push(t); });
    const sm = metrics(s);
    try {
      // r advertises far more than it keeps, so s writes the whole burst at once and r queues most of it.
      const fb = r._frameHandler.flowBudget.bind(r._frameHandler);
      r._frameHandler.flowBudget = () => ({ ...fb(), recordsPerSecond: 1000, recordsBurst: 1000, charsPerSecond: 1e9, charsBurst: 1e9 });
      await s.start(); await r.start();
      assert.ok(await until(() => s._peers.has(r.nodeId) && r._peers.has(s.nodeId), 20000));
      assert.ok(await until(() => s._peers.get(r.nodeId).transport._outFlow && s._peers.get(r.nodeId).transport._outFlow.advertised, 5000));
      for (let i = 0; i < 100; i++) s.remember(CATS(`stop ${i}`), { to: r.nodeId });
      assert.ok(await until(() => flowOf(r).queuedRecords > 20, 5000), `r has records waiting (${flowOf(r).queuedRecords})`);
      await r.stop();
      assert.ok(await until(() => sm.count('cmb-refused-by-peer') > 0, 5000), 'the stopping receiver told the sender what it had not taken');
      assert.ok(s.pendingDeliveries().some((p) => p.state === 'refused'), 'held again, waiting for the retry-after');
      await r.start();
      setTimeout(() => { try { s._discovery._scanLoopback(); r._discovery._scanLoopback(); } catch { /* */ } }, 300);
      assert.ok(await until(() => new Set(seen).size === 100 && s.pendingDeliveries().length === 0, 40000), `every record surfaced (${new Set(seen).size} of 100; pending ${s.pendingDeliveries().length})`);
      assert.strictEqual(seen.length, 100, 'each once');
      assert.strictEqual(sm.count('cmb-undelivered'), 0);
    } finally { await stopAll(s, r); }
  });
});

describe('flow control, the advertisement (`cmb-budget`)', () => {
  it('once a session is admitted each side advertises its record budget and queue bound, and the other paces to it', async () => {
    const a = mk('fa-a'); const b = mk('fa-b');
    const am = metrics(a);
    try {
      await a.start(); await b.start();
      await connectNodes(a, b);
      assert.ok(await until(() => am.count('peer-budget') > 0, 3000), 'a heard b\'s budget');
      const flow = a._peers.get(b.nodeId).transport._outFlow;
      assert.ok(flow && flow.advertised);
      assert.deepStrictEqual({ ...flow.budget }, { recordsPerSecond: 8, recordsBurst: 32, charsPerSecond: 131072, charsBurst: 1572864, queueRecords: 512, queueChars: 8388608 });
      const back = b._peers.get(a.nodeId).transport._outFlow;
      assert.ok(back && back.advertised, 'and b heard a\'s');
    } finally { await stopAll(a, b); }
  });

  it('a malformed advertisement or refusal notice is refused, counted, and changes nothing', async () => {
    const a = mk('fm-a'); const b = mk('fm-b');
    try {
      await a.start(); await b.start();
      await connectNodes(a, b);
      await until(() => a._peers.get(b.nodeId).transport._outFlow && a._peers.get(b.nodeId).transport._outFlow.advertised, 3000);
      const s = b._peers.get(a.nodeId).transport;
      const good = { type: 'cmb-budget', recordsPerSecond: 8, recordsBurst: 32, charsPerSecond: 131072, charsBurst: 1572864, queueRecords: 512, queueChars: 8388608 };
      const id = `asrt-${'a'.repeat(64)}`;
      const bad = [
        { ...good, extra: 1 },
        { ...good, recordsPerSecond: -1 },
        { ...good, recordsBurst: 0 },
        { ...good, charsPerSecond: 'fast' },
        { ...good, charsBurst: Infinity },
        { ...good, queueRecords: -5 },
        (() => { const g = { ...good }; delete g.queueChars; return g; })(),
        { type: 'cmb-refused', assertionIds: [id], retryAfterMs: 1000, extra: true },
        { type: 'cmb-refused', assertionIds: [], retryAfterMs: 1000 },
        { type: 'cmb-refused', assertionIds: ['asrt-zz'], retryAfterMs: 1000 },
        { type: 'cmb-refused', assertionIds: Array.from({ length: 257 }, (_, i) => `asrt-${i.toString(16).padStart(64, '0')}`), retryAfterMs: 1000 },
        { type: 'cmb-refused', assertionIds: [id], retryAfterMs: 1.5 },
        { type: 'cmb-refused', assertionIds: [id], retryAfterMs: -1 },
        { type: 'cmb-refused', assertionIds: [id] },
      ];
      const before = a._sessionStats.refusedByReason.malformed || 0;
      for (const f of bad) s.send(f);
      await until(() => (a._sessionStats.refusedByReason.malformed || 0) - before === bad.length, 3000);
      assert.strictEqual((a._sessionStats.refusedByReason.malformed || 0) - before, bad.length, 'each malformed frame was refused and counted');
      const flow = a._peers.get(b.nodeId).transport._outFlow;
      assert.strictEqual(flow.budget.recordsPerSecond, 8, 'the budget is unchanged');
      assert.strictEqual(flow.backoffUntil, 0, 'and nothing was backed off');
    } finally { await stopAll(a, b); }
  });

  it('before, or without, an advertisement a peer is paced to 0.14.2\'s budget with a margin: 24 at once, then 6 a second', async () => {
    const s = mk('fl-s'); const r = mk('fl-r');
    // r advertises nothing (as 0.14.2).
    r._frameHandler.flowBudget = () => ({ type: 'x-not-a-budget' });
    const { frames, tap } = pipeTap();
    try {
      await s.start(); await r.start();
      await connectNodes(s, r, { tap });
      await sleep(300);
      const t0 = Date.now();
      for (let i = 0; i < 60; i++) s.send(`legacy pace ${i}`, { to: r.nodeId });
      await sleep(1000);
      const toR = () => frames.filter((f) => f.dir === 'a→b' && f.at >= t0);
      const inFirst = toR().filter((f) => f.at - t0 < 100).length;
      assert.ok(inFirst <= 24, `at most 24 at once (${inFirst})`);
      assert.ok(inFirst >= 20, `and the burst went at once (${inFirst})`);
      const inSecond = toR().length;
      assert.ok(inSecond <= 24 + 7, `then about 6 a second (${inSecond} in the first second)`);
    } finally { await stopAll(s, r); }
  });

  it('anchors spend the session\'s budget: the burst after them is what the receiver still holds', async () => {
    const s = mk('fan-s'); const r = mk('fan-r');
    try {
      await s.start(); await r.start();
      for (let i = 0; i < 5; i++) s.remember(CATS(`anchor ${i}`));
      await connectNodes(s, r);
      assert.ok(await until(() => s._peers.get(r.nodeId).transport._outFlow && s._peers.get(r.nodeId).transport._outFlow.advertised, 3000));
      await sleep(50);
      for (let i = 0; i < 40; i++) s.send(`after anchors ${i}`, { to: r.nodeId });
      await sleep(1500);
      const f = flowOf(r);
      assert.ok(f.peakRecords <= 2, `the receiver never had more than jitter waiting (${f.peakRecords})`);
    } finally { await stopAll(s, r); }
  });

  it('an advertisement that arrives after records were sent starts from what the receiver can still hold (its burst less what was sent)', async () => {
    const s = mk('fla-s'); const r = mk('fla-r');
    const fb = r._frameHandler.flowBudget.bind(r._frameHandler);
    // r advertises nothing at first, then (400 ms later) its real budget.
    r._frameHandler.flowBudget = () => ({ type: 'x-not-yet' });
    const greet = r._greetSession.bind(r);
    r._greetSession = (peer, session, isNew) => { greet(peer, session, isNew); setTimeout(() => { if (!session.closed) session.send(fb()); }, 400); };
    try {
      await s.start(); await r.start();
      await connectNodes(s, r);
      const t0 = Date.now();
      for (let i = 0; i < 60; i++) s.send(`late budget ${i}`, { to: r.nodeId });
      assert.ok(await until(() => s._peers.get(r.nodeId).transport._outFlow.advertised, 3000));
      await until(() => Date.now() - t0 > 2500, 3000);
      const f = flowOf(r);
      assert.ok(f.peakRecords <= 4, `the receiver never had more than jitter waiting (${f.peakRecords})`);
      assert.strictEqual(f.refused, 0);
    } finally { await stopAll(s, r); }
  });
});

describe('flow control, the sender told a record was refused (`cmb-refused`)', () => {
  it('refused records are held again in their place and offered first after the retry-after, nothing goes to that session meanwhile, and every record surfaces once', async () => {
    const s = mk('fr-s'); const r = mk('fr-r');
    const fb = r._frameHandler.flowBudget.bind(r._frameHandler);
    // r advertises more than it keeps: 60 at once and 20 a second (it keeps 32 and 8, and queues 16).
    r._frameHandler.flowBudget = () => ({ ...fb(), recordsPerSecond: 20, recordsBurst: 60, charsPerSecond: 1e9, charsBurst: 1e9 });
    const seen = [];
    r.on('message', (_f, t) => seen.push(t));
    const sm = metrics(s);
    const { frames, tap } = pipeTap();
    try {
      await s.start(); await r.start();
      r._frameHandler._admission.limits.queueRecords = 16;
      await connectNodes(s, r, { tap });
      const told = refusalsAt(s);
      assert.ok(await until(() => s._peers.get(r.nodeId).transport._outFlow.advertised, 3000));
      // 60 written at once, 40 held for the (advertised) budget; past r's queue some of the 60 are refused.
      for (let i = 0; i < 100; i++) s.send(`refused ${i}`, { to: r.nodeId });
      assert.ok(await until(() => told.length > 0, 5000), 'the sender was told');
      const first = told[0];
      // Sent while the session is backed off: they wait for the retry-after too.
      for (let i = 100; i < 105; i++) s.send(`refused ${i}`, { to: r.nodeId });
      assert.ok(await until(() => new Set(seen).size === 105 && s.pendingDeliveries().length === 0, 40000), `every record surfaced (${new Set(seen).size} of 105)`);
      assert.strictEqual(seen.length, 105, 'each once');
      // 32 now and 16 queued, in order; after the retry-after the first refused record goes first,
      // ahead of the 40 held behind it. (Later, a record written before the next notice reaches the
      // sender can be taken ahead of one refused: order across a refusal is not kept, see CHANGELOG.)
      assert.deepStrictEqual(seen.slice(0, 49), Array.from({ length: 49 }, (_, i) => `refused ${i}`), 'a refused record went back in its place, ahead of those held behind it');
      const quiet = frames.filter((f) => f.dir === 'a→b' && f.at > first.at + 50 && f.at < first.at + first.frame.retryAfterMs - 50);
      assert.deepStrictEqual(quiet, [], `nothing was written to that session during the ${first.frame.retryAfterMs} ms retry-after`);
      assert.ok((sm['cmb-requeued'] || []).some((m) => m.reason === 'refused'), 'refused records were requeued');
      assert.ok(sm.count('cmb-refused-by-peer') >= 1);
      assert.strictEqual(sm.count('cmb-undelivered'), 0);
      assert.strictEqual(flowOf(r).cut, 0, 'an honest sender is never cut');
      assert.ok(s.status().flowControl.sender.refusedByPeers > 0, 'counted in status');
    } finally { await stopAll(s, r); }
  });

  it('a refused record waits for its retry-after on any session, a new one included', async () => {
    const s = mk('fn-s'); const r = mk('fn-r');
    const got = [];
    r.on('message', (_f, t) => got.push({ t, at: Date.now() }));
    try {
      await s.start(); await r.start();
      // r refuses the first record it is brought (its queue in all full of others'), then takes them.
      const adm = r._frameHandler._admission;
      const offer = adm.offer.bind(adm);
      let once = false;
      adm.offer = (session, peerId, peerName, msg, chars) => {
        if (!once) { once = true; return adm._refuse({ session, peerId, peerName, msg, chars }, 'queue-full', Date.now()); }
        return offer(session, peerId, peerName, msg, chars);
      };
      await connectNodes(s, r);
      const told = refusalsAt(s);
      await sleep(200);
      s.send('wait for it', { to: r.nodeId });
      assert.ok(await until(() => told.length > 0, 3000), 'refused, and told');
      const retryAt = told[0].at + told[0].frame.retryAfterMs;
      // A new session supersedes the old one at once: it has no back-off of its own.
      await connectNodes(s, r);
      assert.ok(await until(() => got.length === 1, 5000), 'delivered on the new session');
      assert.ok(got[0].at >= retryAt - 50, `not before the retry-after (${got[0].at - retryAt} ms after it)`);
    } finally { await stopAll(s, r); }
  });

  it('a record refused more than 8 times is given up: said undelivered, listed, raised as an event, and no longer pending', async () => {
    const s = mk('fg-s'); const r = mk('fg-r');
    const events = [];
    s.on('undelivered', (u) => events.push(u));
    try {
      await s.start(); await r.start();
      // r refuses every record (its queue in all is full of others').
      const adm = r._frameHandler._admission;
      adm.offer = (session, peerId, peerName, msg, chars) => adm._refuse({ session, peerId, peerName, msg, chars }, 'queue-full', Date.now());
      await connectNodes(s, r);
      const told = refusalsAt(s);
      await sleep(200);
      const e = s.remember(CATS('never taken'), { to: r.nodeId });
      assert.ok(e.delivery.dispatched === 1, 'written within the budget');
      assert.ok(await until(() => events.length > 0, 30000), 'given up');
      assert.strictEqual(events[0].reason, 'refused');
      assert.strictEqual(events[0].refusals, 9, 'after the 8th retry was refused');
      assert.strictEqual(events[0].key, e.key);
      assert.deepStrictEqual(s.undelivered().map((u) => [u.key, u.reason]), [[e.key, 'refused']]);
      assert.strictEqual(s.pendingDeliveries().length, 0);
      assert.strictEqual(s.status().flowControl.sender.undelivered, 1);
      assert.strictEqual(flowOf(r).cut, 0);
      assert.ok(told.length >= 9 && told.every((t) => t.frame.retryAfterMs >= 1000), 'every notice carried at least the one-second retry-after, even with nothing queued');
    } finally { await stopAll(s, r); }
  });

  it('a room record refused by one peer is retried to that peer only', async () => {
    const a = mk('fp-a'); const b = mk('fp-b'); const c = mk('fp-c'); const d = mk('fp-d');
    const at = { b: [], c: [], d: [] };
    b.on('verified-record', (e) => at.b.push(e.record.metadata.key));
    c.on('verified-record', (e) => at.c.push(e.record.metadata.key));
    d.on('verified-record', (e) => at.d.push(e.record.metadata.key));
    const taps = { b: pipeTap(), c: pipeTap(), d: pipeTap() };
    try {
      await a.start(); await b.start(); await c.start(); await d.start();
      // c, the second of three peers a broadcasts to, refuses the first record it is brought.
      const adm = c._frameHandler._admission;
      const offer = adm.offer.bind(adm);
      let once = false;
      adm.offer = (session, peerId, peerName, msg, chars) => {
        if (!once && msg && msg.cmb && msg.cmb.metadata && msg.cmb.metadata.assertionId) { once = true; return adm._refuse({ session, peerId, peerName, msg, chars }, 'queue-full', Date.now()); }
        return offer(session, peerId, peerName, msg, chars);
      };
      await connectNodes(a, b, { tap: taps.b.tap });
      await connectNodes(a, c, { tap: taps.c.tap });
      await connectNodes(a, d, { tap: taps.d.tap });
      await sleep(300);
      const t0 = Date.now();
      const e = a.remember(CATS('to the room'));
      assert.ok(await until(() => at.c.includes(e.key), 10000), 'c took it on the retry');
      await sleep(300);
      for (const p of ['b', 'c', 'd']) assert.strictEqual(at[p].filter((k) => k === e.key).length, 1, `${p} took it once`);
      const frames = (p) => taps[p].frames.filter((f) => f.dir === 'a→b' && f.at >= t0).length;
      assert.deepStrictEqual({ b: frames('b'), c: frames('c'), d: frames('d') }, { b: 1, c: 2, d: 1 }, 'only c was sent it again');
    } finally { await stopAll(a, b, c, d); }
  });

  it('a refusal naming a record written over a minute ago (or never) changes nothing, and is counted', async () => {
    const s = mk('fw-s'); const r = mk('fw-r');
    const sm = metrics(s);
    try {
      await s.start(); await r.start();
      await connectNodes(s, r);
      await sleep(200);
      const e = s.remember(CATS('long gone'), { to: r.nodeId });
      const k = `${r.nodeId}|${e.cmb.metadata.assertionId}`;
      assert.ok(s._sentWindow && s._sentWindow.has(k), 'remembered while it may still be refused');
      s._sentWindow.get(k).sentAt -= 61_000;
      s._pruneSentWindow();
      r._peers.get(s.nodeId).transport.send({ type: 'cmb-refused', assertionIds: [e.cmb.metadata.assertionId], retryAfterMs: 1000 });
      assert.ok(await until(() => sm.count('cmb-refused-unmatched') > 0, 3000), 'counted as a refusal of nothing held');
      assert.strictEqual(s.pendingDeliveries().length, 0, 'nothing was held again');
      // The peer's queue is full all the same: nothing more goes to it until the retry-after.
      const t0 = Date.now();
      const got = [];
      r.on('message', (_f, t) => got.push(Date.now()));
      assert.ok(s.send('after the refusal', { to: r.nodeId }) === 1, 'taken');
      assert.strictEqual(s.pendingDeliveries().length, 1, 'held for the retry-after');
      assert.ok(await until(() => got.length === 1, 4000));
      assert.ok(got[0] - t0 >= 800, `written once the retry-after had passed (${got[0] - t0} ms)`);
    } finally { await stopAll(s, r); }
  });

  it('a record refused while it still waits in the relay pacer (its write not yet seen) is held again when the write is seen, not counted delivered', async () => {
    const n = mk('fq-n');
    const to = '01900000-0000-7000-8000-0000000000bb';
    try {
      await n.start();
      const metas = [];
      const fake = { closed: false, confirmed: true, kind: 'relay', identityKey: 'k', sessionId: 's1', nodeId: to, name: 'fake', pendingBytes: () => 0,
        transport: { hasRoom: () => true }, trySend: (frame, meta) => { metas.push(meta); return { ok: true }; }, send: () => true };
      n._peers.set(to, { peerId: to, name: 'fake', transport: fake, transports: new Map([['relay', fake]]) });
      const rec = signedRecord(authorOf(n), { room: 'flow', to, categories: { focus: 'in the pacer' } });
      assert.strictEqual(n._dispatchCmb(rec, Date.now(), to).dispatched, 1, 'written to the session (into the pacer)');
      n._onPeerRefused(fake, { type: 'cmb-refused', assertionIds: [rec.metadata.assertionId], retryAfterMs: 1000 });
      n._redeliveryFlushed(metas[0]);
      const p = n.pendingDeliveries();
      assert.strictEqual(p.length, 1, 'still pending');
      assert.strictEqual(p[0].state, 'refused', 'waiting for its retry-after');
      assert.strictEqual(p[0].refusals, 1);
    } finally { n._peers.clear(); await stopAll(n); }
  });

  it('a held record older than 23 h by its signed timestamp is given up (a receiver would refuse it as a replay)', async () => {
    const s = mk('fx-s');
    const events = [];
    s.on('undelivered', (u) => events.push(u));
    try {
      await s.start();
      const to = '01900000-0000-7000-8000-0000000000aa';
      const old = signedRecord(authorOf(s), { room: 'flow', to, categories: { focus: 'old' } });
      old.metadata.createdTimestamp = Date.now() - 24 * 3600 * 1000;
      s._holdUnflushed([{ to, bytes: 100, meta: { redeliver: true, to, key: 'k', frame: { type: 'cmb', cmb: old }, recordKey: 'cmb-old', since: Date.now(), attempts: 1, held: false, offered: false, bytes: 0 } }]);
      assert.strictEqual(s.pendingDeliveries().length, 1, 'held');
      s._sweepHeld();
      assert.strictEqual(s.pendingDeliveries().length, 0, 'and given up');
      assert.deepStrictEqual(events.map((u) => [u.key, u.reason]), [['cmb-old', 'expired']]);
      // And a pass that would write one gives it up instead.
      const to2 = '01900000-0000-7000-8000-0000000000ab';
      const written = [];
      const fake = { closed: false, confirmed: true, kind: 'bonjour', identityKey: 'k2', sessionId: 's9', nodeId: to2, name: 'fake', pendingBytes: () => 0, trySend: (f) => { written.push(f); return { ok: true }; } };
      const old2 = signedRecord(authorOf(s), { room: 'flow', to: to2, categories: { focus: 'old too' } });
      old2.metadata.createdTimestamp = Date.now() - 24 * 3600 * 1000;
      s._holdUnflushed([{ to: to2, bytes: 100, meta: { redeliver: true, to: to2, key: 'k2', frame: { type: 'cmb', cmb: old2 }, recordKey: 'cmb-old2', since: Date.now(), attempts: 1, held: false, offered: false, bytes: 0 } }]);
      s._reofferHeld(to2, fake);
      assert.deepStrictEqual(written, [], 'not written');
      assert.deepStrictEqual(events.map((u) => u.key), ['cmb-old', 'cmb-old2']);
    } finally { await stopAll(s); }
  });

  it('a record the session refuses outright on its first write is not held: the send says why, as before', async () => {
    const s = mk('fy-s');
    try {
      await s.start();
      const { admitAs, identity } = require('./_core-secure');
      const peer = identity('fy-peer');
      const sess = admitAs(s, peer);
      sess.trySend = () => ({ ok: false, reason: 'write-failed' });
      const e = s.remember(CATS('the socket failed'), { to: peer.nodeId });
      assert.strictEqual(e.delivery.undelivered, true);
      assert.strictEqual(e.delivery.reason, 'write-failed');
      assert.strictEqual(s.pendingDeliveries().length, 0, 'not held');
    } finally { s._peers.clear(); await stopAll(s); }
  });

  it('the held list is bounded by size too: past 8 Mi characters for a peer a new record is not held', async () => {
    const s = mk('fk-s'); const r = mk('fk-r');
    try {
      await s.start(); await r.start();
      await connectNodes(s, r);
      await until(() => s._peers.get(r.nodeId).transport._outFlow && s._peers.get(r.nodeId).transport._outFlow.advertised, 3000);
      const body = big(200 * 1024, 'held');
      let taken = 0;
      for (let i = 0; i < 60; i++) taken += s.send(`${i} ${body}`, { to: r.nodeId });
      assert.ok(taken >= 25 && taken <= 50, `the held list took what 8 Mi characters hold, past the 1.5 Mi written at once (${taken} of 60)`);
    } finally { await stopAll(s, r); }
  });

  it('past the held list\'s bound a new record is not held: a directed send says so (held-full)', async () => {
    const s = mk('fh-s'); const r = mk('fh-r');
    try {
      await s.start(); await r.start();
      await connectNodes(s, r);
      await until(() => s._peers.get(r.nodeId).transport._outFlow && s._peers.get(r.nodeId).transport._outFlow.advertised, 3000);
      let taken = 0;
      for (let i = 0; i < 2100; i++) taken += s.send(`bound ${i}`, { to: r.nodeId });
      assert.ok(taken < 2100 && taken >= 2048, `the held list took up to its bound (${taken})`);
      const e = s.remember(CATS('one too many'), { to: r.nodeId });
      assert.strictEqual(e.delivery.undelivered, true);
      assert.strictEqual(e.delivery.reason, 'held-full');
      assert.ok(s.pendingDeliveries().length <= 2048);
    } finally { await stopAll(s, r); }
  });
});

describe('flow control, the buckets', () => {
  it('a clock stepped back refills nothing and takes nothing; a back-off holds a session\'s records until it ends', () => {
    const { refillBucket, bucketWait, OutboundBudget } = require('../lib/flow-control');
    const b = { tokens: 5, at: 10_000 };
    refillBucket(b, 8, 32, 9_000);
    assert.strictEqual(b.tokens, 5, 'nothing taken by a clock stepped back');
    assert.strictEqual(b.at, 10_000, 'and the bucket keeps its time');
    refillBucket(b, 8, 32, 10_500);
    assert.strictEqual(b.tokens, 9);
    assert.strictEqual(bucketWait({ tokens: 0, at: 0 }, 8, 32, 1, 0), 125, 'one record at 8 a second waits 125 ms');
    assert.strictEqual(bucketWait({ tokens: 0, at: 0 }, 10, 100, 1000, 0), 10_000, 'a need past the burst waits for the burst');
    const o = new OutboundBudget(0);
    assert.strictEqual(o.budget.recordsBurst, 24);
    assert.strictEqual(o.wait(100, 0), 0);
    o.backOff(2000, 0);
    assert.strictEqual(o.wait(100, 1000), 1000, 'a back-off holds what the buckets would allow');
    assert.strictEqual(o.wait(100, 2000), 0);
  });
});
