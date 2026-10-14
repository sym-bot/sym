'use strict';

process.env.SYM_SEMANTIC_ENCODER = process.env.SYM_SEMANTIC_ENCODER || 'off';
require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * The independent review of release/0.14.3 (9f6847c): four defects in records, attestation summaries,
 * text and recall, each a regression test that fails on 9f6847c for its own reason and passes here.
 * The same defects against a real 0.14.2 node: tests/integration/mixed-0142-records.js.
 *
 *   S3  an actionable record was keyed by its cognition key on two paths: a room record SVAF admitted
 *       under a key the store held was never delivered, and remember() never sent a second action
 *       under the same categories (the R2-6 fix covered only the redundant branch)
 *   B2  aggregateAttestations returned total 0 on a node that does not hold the record (XMesh's
 *       observers), instead of weighing the one assertion its attestations name
 *   M2  a record whose text holds a lone surrogate (a 0.14.2 author's text cut inside a pair) was
 *       refused: the signed bytes are UTF-8, where it can only be U+FFFD, so it is held as U+FFFD
 *   M1  with the store's cache bounded, recall() read a file for every entry the cache did not hold
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const core = require('../lib/core');
const pub = require('../lib/public/core');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const MS = require('../lib/memory-store');
const { identity, connectNodes, admitAs, deliver, signedRecord, applicationFor, until } = require('./_core-secure');
const { settle } = require('./_settle');

const ROOM = 'sec';
const made = [];
function mk(base, extra = {}) {
  const n = new SymNode({ name: `${base}-${process.pid}-${Math.random().toString(36).slice(2, 7)}`, silent: true, discovery: new NullDiscovery(), room: ROOM, checkpointInterval: 0, ...extra });
  made.push(n);
  return n;
}
async function stopAll() {
  for (const n of made.splice(0)) {
    try { await n.stop(); } catch { /* not started */ }
    try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ }
  }
}
const CATS = { focus: 'deploy the build', issue: 'release 0.14.3', intent: 'act', motivation: 'ship', commitment: 'today', perspective: 'operator', mood: { text: 'calm' } };
const payloadOf = (e) => JSON.stringify(e.cmb && e.cmb.payload !== undefined ? e.cmb.payload : null);
const authorOf = (e) => (e.author && e.author.name) || (e.cmb && e.cmb.metadata && e.cmb.metadata.createdBy);
/** What a node surfaces to its host (cmb-accepted), as `author:payload:remixed`. */
function deliveries(node) {
  const got = [];
  node.on('cmb-accepted', (e) => got.push(`${authorOf(e)}:${payloadOf(e)}:${e.remixed}`));
  return got;
}
/**
 * Connect nodes through the real handshake over in-memory pipes that share ONE wire: every frame sent
 * in one turn is delivered in one later turn, as a socket hands several frames to one read. Records
 * sent together so reach SVAF together, before any of them is stored: the aligned path the review
 * measured on the LAN (SVAF admits each, and the store then holds the key for all but the first).
 */
function sharedWire() {
  const queue = [];
  let scheduled = false;
  const flush = () => { scheduled = false; for (const [end, frame] of queue.splice(0)) if (!end._closed) end.emit('message', frame); };
  function pipe() {
    const mk = () => {
      const listeners = {};
      return {
        _closed: false,
        on(ev, fn) { (listeners[ev] ||= []).push(fn); return this; },
        once(ev, fn) { const w = (...a) => { this.off(ev, w); fn(...a); }; return this.on(ev, w); },
        off(ev, fn) { listeners[ev] = (listeners[ev] || []).filter((f) => f !== fn); return this; },
        removeListener(ev, fn) { return this.off(ev, fn); },
        removeAllListeners(ev) { if (ev) listeners[ev] = []; else for (const k of Object.keys(listeners)) listeners[k] = []; return this; },
        emit(ev, ...a) { for (const f of [...(listeners[ev] || [])]) f(...a); },
      };
    };
    const a = mk(); const b = mk();
    for (const [self, other] of [[a, b], [b, a]]) {
      self.trySend = (frame) => {
        if (self._closed) return { ok: false, reason: 'not-connected' };
        queue.push([other, JSON.parse(JSON.stringify(frame))]);
        if (!scheduled) { scheduled = true; setImmediate(flush); }
        return { ok: true };
      };
      self.send = (frame) => self.trySend(frame).ok;
      self.close = () => {
        if (self._closed) return;
        self._closed = true; setImmediate(() => self.emit('close'));
        if (!other._closed) { other._closed = true; setImmediate(() => other.emit('close')); }
      };
      self.destroy = self.close;
      self.end = () => setImmediate(() => self.close());
    }
    return [a, b];
  }
  return async function connect(client, server) {
    const [tc, ts] = pipe();
    server.connectTransport(ts, { role: 'server' });
    client.connectTransport(tc, { role: 'client', expectNodeId: server.nodeId });
    const joined = (n, o) => { const s = n._peers.get(o.nodeId)?.transports?.get('bonjour'); return !!(s && s.confirmed && !s.closed); };
    await until(() => joined(client, server) && joined(server, client), 5000);
    if (!joined(client, server) || !joined(server, client)) throw new Error('the pair did not confirm');
  };
}

/** The SVAF decisions a node records, by the payload of the record decided. */
function decisions(node) {
  const out = [];
  const rec = node._recordDecision.bind(node);
  node._recordDecision = (d) => { out.push(d.decision); return rec(d); };
  return out;
}

describe('S3: an actionable record is a message, identified by its assertion everywhere', () => {
  it('S3: real nodes, the room path SVAF admits: two authors under the same categories, and one author\'s two actions, are each delivered once', async () => {
    try {
      const A = mk('s3-a'); const B = mk('s3-b'); const C = mk('s3-c');
      await Promise.all([A, B, C].map((n) => n.start()));
      const connect = sharedWire();
      await connect(A, B); await connect(C, B);
      const got = deliveries(B);
      const decided = decisions(B);
      const a1 = A.remember(CATS, { payload: { act: 'v1' } });
      const a2 = A.remember(CATS, { payload: { act: 'v2' } });
      const c1 = C.remember(CATS, { payload: { act: 'c1' } });
      assert.strictEqual(a1.key, a2.key, 'the scene: one cognition key');
      assert.strictEqual(a1.key, c1.key);
      await until(() => got.length >= 3, 4000); await settle(200);
      // 9f6847c: A's second action was never sent (collapsed onto HEAD) and C's, which SVAF admitted under a
      // key B's store held, reached nobody: only A's first was delivered.
      assert.ok(a2.delivery && a2.delivery.dispatched === 1, 'the second action is sent');
      assert.deepStrictEqual([...got].sort(), [`${A.name}:{"act":"v1"}:true`, `${A.name}:{"act":"v2"}:false`, `${C.name}:{"act":"c1"}:false`].sort());
      assert.ok(decided.slice(1).every((d) => d === 'aligned' || d === 'guarded'), `the aligned path (SVAF admitted each): ${decided}`);
      // A true replay of each (the same signed record again) is not delivered again.
      A._dispatchCmb(a1.cmb, Date.now(), null); A._dispatchCmb(a2.cmb, Date.now(), null); C._dispatchCmb(c1.cmb, Date.now(), null);
      await settle(300);
      assert.strictEqual(got.length, 3, 'a replay of the same assertion is delivered once');
      assert.strictEqual(B._store.count(), 1, 'memory holds the cognition once');
    } finally { await stopAll(); }
  });

  it('S3: the neural admit path: a record SVAF admits under a key memory holds is delivered by its assertion', async () => {
    try {
      const node = mk('s3-neural');
      await node._store.load();
      node._svafEvaluator = { evaluate: async () => ({ decision: 'aligned', total_drift: 0.05, category_drifts: {}, gate_values: {} }) };
      const decided = decisions(node);
      const mallory = identity('mallory'); const alice = identity('alice');
      const sm = admitAs(node, mallory); const sa = admitAs(node, alice);
      const cats = { focus: 'release 0.14.3 approved', intent: 'deploy' };
      const front = signedRecord(mallory, { categories: cats, room: ROOM, application: applicationFor(Buffer.from('{"deploy":"mallory-build"}')) });
      const real = signedRecord(alice, { categories: cats, room: ROOM, application: applicationFor(Buffer.from('{"deploy":"official-build"}')) });
      const memo = signedRecord(alice, { categories: cats, room: ROOM });
      deliver(node, sm, { type: 'cmb', cmb: front }); await settle(100);
      deliver(node, sa, { type: 'cmb', cmb: real }); await settle(100);
      deliver(node, sa, { type: 'cmb', cmb: memo }); await settle(100);
      for (const r of [front, real, memo]) { deliver(node, sa, { type: 'cmb', cmb: JSON.parse(JSON.stringify(r)) }); await settle(30); }
      assert.deepStrictEqual(decided, ['aligned', 'aligned', 'aligned'], 'the neural gate admitted each');
      const app = (m) => (m.record && m.record.metadata.application ? Buffer.from(m.record.metadata.application.data, 'base64url').toString() : 'none');
      const got = node.inbox({ peek: true }).messages.map((m) => `${m.from}:${app(m)}:${m.remixed}`);
      // 9f6847c: alice's action, admitted under the key mallory's record holds, was not delivered.
      assert.deepStrictEqual(got.sort(), ['alice:{"deploy":"official-build"}:false', 'mallory:{"deploy":"mallory-build"}:true'].sort(),
        'both actions, once each; a memory memory already holds (no application) is not delivered again');
    } finally { await stopAll(); }
  });

  it('S3: remember() sends every action by its own assertion, whatever memory holds; the same assertion given twice is not sent again', async () => {
    try {
      const X = mk('s3-x'); const Y = mk('s3-y');
      await Promise.all([X, Y].map((n) => n.start()));
      await connectNodes(X, Y);
      const got = deliveries(Y);
      const r1 = X.remember(CATS, { payload: { n: 1 } });
      // HEAD's cognition: 9f6847c collapsed it ({ collapsed, duplicate }, not sent).
      const r2 = X.remember(CATS, { payload: { n: 2 } });
      assert.ok(r2.delivery && r2.delivery.dispatched === 1 && r2.delivery.directed === false, 'sent to the room');
      assert.strictEqual(r2.cognitionHeld, true);
      assert.ok(!r2.collapsed && !r2.duplicate, 'not a duplicate: mesh-channel reads it as published');
      assert.notStrictEqual(r2.cmb.metadata.assertionId, r1.cmb.metadata.assertionId);
      assert.strictEqual(X._head, r1.key, 'HEAD does not move');
      // Held, not HEAD: 9f6847c returned { key, duplicate: true } and sent nothing.
      const other = X.remember({ ...CATS, focus: 'another observation' });
      const r3 = X.remember(CATS, { payload: { n: 3 } });
      assert.ok(r3.delivery && r3.delivery.dispatched === 1, 'an action under a held (not HEAD) cognition is sent');
      assert.strictEqual(X._head, other.key);
      // Directed.
      const r4 = X.remember(CATS, { payload: { n: 4 }, to: Y.nodeId });
      assert.ok(r4.delivery && r4.delivery.directed === true && r4.delivery.dispatched === 1);
      // A peer's record holds the cognition: X's own action under it still goes.
      const ycats = { ...CATS, focus: 'the peer said it first' };
      Y.remember(ycats, { payload: { y: 1 } });
      await until(() => X._store.count() >= 3, 3000); await settle(100);
      const r5 = X.remember(ycats, { payload: { x: 1 } });
      assert.ok(r5.delivery && r5.delivery.dispatched === 1, 'an action under a peer\'s cognition is sent');
      // The same assertion, already stored as it is: a duplicate, not sent again.
      const again = X.remember(CATS, { cmb: JSON.parse(JSON.stringify(r1.cmb)) });
      assert.strictEqual(again.duplicate, true);
      assert.ok(!again.delivery, 'not sent');
      await until(() => got.length >= 6, 4000); await settle(200);
      const mine = got.filter((g) => g.startsWith(`${X.name}:`)).map((g) => g.split(':').slice(1).join(':'));
      assert.deepStrictEqual(mine.sort(), ['{"n":1}:true', '{"n":2}:false', '{"n":3}:false', '{"n":4}:false', '{"x":1}:false', 'null:true'].sort());
      assert.strictEqual(X._store.count(), 3, 'memory: three cognitions');
    } finally { await stopAll(); }
  });

  it('S3: an action is sent when memory cannot store it, and one citing the record whose cognition it repeats is sent without that self-parent', async () => {
    try {
      const X = mk('s3-fail'); const Y = mk('s3-fail-y');
      await Promise.all([X, Y].map((n) => n.start()));
      await connectNodes(X, Y);
      const got = deliveries(Y);
      const persist = X._store._persist;
      X._store._persist = () => false;
      const lost = X.remember({ ...CATS, focus: 'memory cannot take this' }, { payload: { go: 1 } });
      X._store._persist = persist;
      assert.ok(lost && lost.delivery && lost.delivery.dispatched === 1, 'its delivery is not memory: sent');
      assert.strictEqual(lost.persisted, false);
      const memo = X.remember({ ...CATS, focus: 'a memory nobody could store' });
      assert.ok(memo, 'the scene: a memory');
      X._store._persist = () => false;
      assert.strictEqual(X.remember({ ...CATS, focus: 'another memory' }), null, 'a memory the store cannot write is still not sent');
      X._store._persist = persist;
      const first = X.remember(CATS, { payload: { v: 1 } });
      const cites = X.remember(CATS, { payload: { v: 2 }, parents: [first] });
      assert.ok(cites.delivery && cites.delivery.dispatched === 1);
      assert.strictEqual(cites.cmb.metadata.lineage, null, 'K -> K dropped, as the collapse onto HEAD drops it');
      assert.strictEqual(pub.verifyCMB(cites.cmb, X._identity.publicKey).valid, true, 're-signed');
      await until(() => got.length >= 4, 4000); await settle(200);
      assert.deepStrictEqual(got.map((g) => g.split(':').slice(1).join(':')).sort(), ['{"go":1}:true', 'null:true', '{"v":1}:true', '{"v":2}:false'].sort());
    } finally { await stopAll(); }
  });
});

describe('B2: an attestation summary is about one named assertion', () => {
  const hex = () => crypto.randomBytes(32).toString('hex');
  const ACATS = { focus: 'admit', issue: 'admit', intent: 'admit', motivation: 'admit', commitment: 'admit', perspective: 'admit', mood: 'admit' };
  function attestation(by, seq, extra = {}) {
    const a = { of: `cmb-${hex()}`, assertionId: `asrt-${hex()}`, by: by.nodeId, at: 1, roster: ROOM, method: 'neural', verdict: 'aligned', categories: ACATS, role: 'participant', seq, prev: 'genesis', ...extra };
    core.signAttestation(a, by.privateKey);
    return a;
  }
  const attest = (V, T, a) => V._receiveSessionFrame(admitAs(V, T), { type: 'sym-attest-attestation', attestation: core.toWireAttestation(a) });

  it('B2: real nodes: an observer without the record (cliHostMode, no store) weighs the one assertion its attestations name', async () => {
    try {
      const P = mk('b2-author'); const Q = mk('b2-gater'); const O = mk('b2-observer', { cliHostMode: true });
      await Promise.all([P, Q, O].map((n) => n.start()));
      await connectNodes(P, Q); await connectNodes(Q, O); await connectNodes(P, O);
      const r = P.remember(CATS);
      const key = r.key;
      await until(() => O.attestationsFor(key).length > 0, 4000); await settle(200);
      assert.strictEqual(O._store.get(key), null, 'the scene: the observer does not hold the record');
      const agg = O.aggregateAttestations(key);
      // 9f6847c: total 0, every attestation excluded as assertion-unknown.
      assert.strictEqual(agg.total, 1, JSON.stringify(agg.excluded));
      assert.strictEqual(agg.basis, 'sole');
      assert.strictEqual(agg.assertionId, r.cmb.metadata.assertionId, 'and says which assertion');
      assert.ok(agg.overall.dominant, 'a verdict');
      assert.deepStrictEqual(Object.keys(agg.byAssertion), [r.cmb.metadata.assertionId]);
      const held = Q.aggregateAttestations(key);
      assert.strictEqual(held.basis, 'held');
      assert.strictEqual(held.total, 1);
    } finally { await stopAll(); }
  });

  it('B2: attestations naming several assertions: no single verdict, every one in byAssertion; the held or given one is still weighed alone (R2-8)', async () => {
    try {
      const V = mk('b2-several');
      const key = `cmb-${hex()}`; const X = `asrt-${hex()}`; const Y = `asrt-${hex()}`;
      const t1 = identity('t1'); const t2 = identity('t2'); const t3 = identity('t3');
      attest(V, t1, attestation(t1, 1, { of: key, assertionId: X, verdict: 'aligned' }));
      attest(V, t2, attestation(t2, 1, { of: key, assertionId: X, verdict: 'aligned' }));
      attest(V, t3, attestation(t3, 1, { of: key, assertionId: Y, verdict: 'rejected' }));
      assert.strictEqual(V.attestationsFor(key).length, 3);
      const agg = V.aggregateAttestations(key);
      // 9f6847c: total 0, no per-assertion summaries.
      assert.strictEqual(agg.total, 3, 'every verified attestation is counted, never a silent 0');
      assert.strictEqual(agg.basis, 'several');
      assert.strictEqual(agg.assertionId, null);
      assert.strictEqual(agg.overall.dominant, null, 'no single verdict');
      assert.deepStrictEqual(agg.categories, {});
      assert.strictEqual(agg.assertions, 2);
      assert.strictEqual(agg.byAssertion[X].total, 2);
      assert.strictEqual(agg.byAssertion[X].overall.dominant, 'aligned');
      assert.strictEqual(agg.byAssertion[Y].overall.dominant, 'rejected');
      const given = V.aggregateAttestations(key, { assertionId: Y });
      assert.strictEqual(given.basis, 'given');
      assert.strictEqual(given.total, 1);
      assert.strictEqual(given.overall.dominant, 'rejected');
      assert.deepStrictEqual(given.excluded.map((e) => e.reason), ['other-assertion', 'other-assertion'], 'an attestation about another assertion is never a vote on this one');
      assert.strictEqual(V.aggregateAttestations(`cmb-${hex()}`).basis, 'none');
    } finally { await stopAll(); }
  });
});

describe('M2: well-formed text is normalised, not refused', () => {
  /** A record as a 0.14.2 author signed it: its text cut inside a surrogate pair (the same signed bytes). */
  function cutRecord(author, extra = {}) {
    const rec = signedRecord(author, { categories: { focus: 'Release note 🚀�', issue: 'surrogate' }, room: ROOM, ...extra });
    const wire = JSON.parse(JSON.stringify(rec).replace('🚀�', '🚀\\ud83d'));
    assert.ok(!wire.categories.focus.text.isWellFormed(), 'the scene: a lone surrogate on the wire');
    return { rec, wire };
  }

  it('M2: a record holding a lone surrogate is delivered, verified, and held as its U+FFFD spelling (room and directed)', async () => {
    try {
      const node = mk('m2-recv');
      await node._store.load();
      const alice = identity('alice');
      const s = admitAs(node, alice);
      const refused = []; node.on('metric', (m) => { if (/refus|reject|malformed/.test(m.type)) refused.push(m.type); });
      const room = cutRecord(alice);
      const directed = cutRecord(alice, { to: node.nodeId, categories: { focus: 'Direct 🚀�', issue: 'surrogate' } });
      deliver(node, s, { type: 'cmb', cmb: room.wire }); await settle(100);
      deliver(node, s, { type: 'cmb', cmb: directed.wire }); await settle(100);
      const got = node.inbox({ peek: true }).messages;
      // 9f6847c: both refused as malformed (a lone surrogate), silently.
      assert.deepStrictEqual(got.map((m) => m.categories.focus.text).sort(), ['Direct 🚀�', 'Release note 🚀�'].sort());
      assert.ok(got.every((m) => m.verified === true && m.record.categories.focus.text.isWellFormed()));
      assert.deepStrictEqual(refused, []);
      const stored = node._store.get(room.rec.metadata.key);
      assert.strictEqual(stored.cmb.categories.focus.text, 'Release note 🚀�', 'held as the one string its signature covers');
      assert.strictEqual(pub.verifyCMB(stored.cmb, alice.publicKey).valid, true);
      // Two spellings of one record are one record: the U+FFFD spelling is a replay.
      deliver(node, s, { type: 'cmb', cmb: room.rec }); await settle(100);
      assert.strictEqual(node.inbox({ peek: true }).messages.length, 2);
    } finally { await stopAll(); }
  });

  it('M2: sym\'s own cuts fall on code point boundaries (a message preview, a wire name, the SVAF text)', async () => {
    try {
      const X = mk('m2-msg');
      const to = identity('peer').nodeId;
      const text = 'x'.repeat(4095) + '🚀' + 'tail';
      const cmb = X._mintMessage(text, to);
      // 9f6847c: the preview was cut inside the pair and minted as U+FFFD.
      assert.ok(!cmb.categories.focus.text.includes('�'), 'no U+FFFD where sym cut the text');
      assert.ok(cmb.categories.focus.text.endsWith('x…'));
    } finally { await stopAll(); }
    const enc = require('../lib/core/context-encoder');
    const svaf = 'y'.repeat(16 * 1024 - 1) + '🚀';
    const a = await enc.svafKernel().encode(svaf);
    const b = await enc.svafKernel().encode('y'.repeat(16 * 1024 - 1));
    assert.deepStrictEqual(a.h1, b.h1, 'the kernel reads up to the pair, never half of it');
    const { wireName } = require('../lib/wire-identity');
    const longName = 'n'.repeat(255) + '🚀🚀';
    assert.ok(wireName(longName).isWellFormed(), 'a wire name');
    assert.ok(wireName('lone \ud83d end').isWellFormed());
    assert.strictEqual(core.cutText('ab🚀cd', 3), 'ab', 'a pair is never split');
    assert.strictEqual(core.cutText('ab🚀cd', 4), 'ab🚀');
    assert.strictEqual(core.cutText('abc', 9), 'abc');
  });

  it('M2: a store written by 0.14.2 that holds a lone surrogate is read back well formed', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'm2-store-'));
    try {
      const alice = identity('alice');
      const { rec } = cutRecord(alice);
      const entry = { key: rec.metadata.key, content: 'focus: Release note 🚀\ud83d', source: 'old', tags: [], storedAt: 1, timestamp: 1, peerId: alice.nodeId, tier: 'hot', lifecycle: 'observed', cmb: JSON.parse(JSON.stringify(rec).replace('🚀�', '🚀\\ud83d')), lineage: { parents: [], ancestors: [], method: null } };
      fs.writeFileSync(path.join(dir, `${entry.key}.json`), JSON.stringify(entry, null, 2));
      const store = new MS.MemoryStore(dir, 'reader');
      const got = store.get(entry.key);
      // 9f6847c: the lone surrogate as stored.
      assert.strictEqual(got.cmb.categories.focus.text, 'Release note 🚀�');
      assert.ok(got.content.isWellFormed());
      assert.strictEqual(pub.verifyCMB(got.cmb, alice.publicKey).valid, true);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('M2: a caller\'s own record and a Legacy Import record are held in their well-formed spelling; createCMB mints references so', async () => {
    try {
      const X = mk('m2-caller');
      const own = { nodeId: X.nodeId, name: X.name, publicKey: X._identity.publicKey, privateKey: X._identity.privateKey };
      const rec = signedRecord(own, { categories: { focus: 'caller cut 🚀\ufffd' }, room: ROOM });
      const wire = JSON.parse(JSON.stringify(rec).replace('🚀\ufffd', '🚀\\ud83d'));
      const e = X.remember(null, { cmb: wire });
      assert.strictEqual(X._store.get(e.key).cmb.categories.focus.text, 'caller cut 🚀\ufffd', 'stored as the one string its signature covers');
      assert.ok(!wire.categories.focus.text.isWellFormed(), 'the caller\'s object is not changed');
      // Given again: nothing is stored (it collapses onto HEAD), and the record handed back is the canonical one.
      const back = X.remember(null, { cmb: JSON.parse(JSON.stringify(wire)) });
      assert.ok(back.collapsed && back.cmb.categories.focus.text.isWellFormed(), 'what remember() hands back holds the one string');
      // A 0.13-suite record on a Legacy Import route.
      const alice = identity('alice');
      const legacy = core.createCMB({ categories: { focus: 'legacy cut 🚀\ufffd' }, createdBy: 'alice', room: ROOM });
      core.signCMB(legacy, alice.privateKey);
      const msg = { type: 'cmb', cmb: JSON.parse(JSON.stringify(legacy).replace('🚀\ufffd', '🚀\\ud83d')), _legacyImport: true, _legacyPinnedKey: alice.publicKey, _legacyRoutedNodeId: alice.nodeId };
      // 9f6847c: refused (malformed-string).
      assert.strictEqual(X._frameHandler._rejectLegacyImport(alice.nodeId, 'alice', msg), false, 'taken, quarantined as before');
      assert.strictEqual(msg.cmb.categories.focus.text, 'legacy cut 🚀\ufffd');
      const minted = core.createCMB({ categories: { focus: 'p' }, categoryParents: { focus: ['ref-\ud800'] }, lineage: { parents: [`cmb-${'a'.repeat(64)}`], method: 'm\udc00' }, createdBy: 'x', room: ROOM });
      assert.deepStrictEqual(minted.categories.focus.meta.parents, ['ref-\ufffd']);
      assert.strictEqual(minted.metadata.lineage.method, 'm\ufffd');
    } finally { await stopAll(); }
  });
});

describe('M1: recall is matched in memory and reads only what it returns', () => {
  const N = 3000; // past the entry cache's 2,048
  function filled(dir, n = N, opts = {}) {
    const store = new MS.MemoryStore(dir, 'rp');
    let t = 1_000_000;
    const now = Date.now;
    try {
      Date.now = () => t;
      for (let i = 0; i < n; i++) {
        t += 1;
        const cmb = core.createCMB({ categories: { focus: `entry ${i} ${opts.long && i % 500 === 0 ? 'z'.repeat(6000) + ` deepneedle${i}` : ''}`, issue: 'recall perf ' + 'x'.repeat(100), intent: 'i', motivation: 'm', commitment: 'c', perspective: 'p', mood: { text: 'calm', valence: 0, arousal: 0 } }, createdBy: 'rp', room: 'default' });
        store.write(core.renderContent(cmb), { cmb, tags: i % 7 === 0 ? ['Tagged'] : [] });
      }
    } finally { Date.now = now; }
    return store;
  }
  /** The recall of 9f6847c, over every entry read whole: the reference for what recall returns. */
  function reference(store, query) {
    const out = [];
    for (const idx of store._index.byKey.values()) {
      const e = store._load(idx.filePath);
      if (!query || !query.trim()) { out.push(e); continue; }
      const parts = [e.content || '', e.key || '', ...(e.tags || [])];
      for (const v of Object.values(e.cmb.categories)) if (v && v.text) parts.push(v.text);
      if (parts.join(' ').toLowerCase().includes(query.toLowerCase())) out.push(e);
    }
    return out.sort((a, b) => (b.storedAt || 0) - (a.storedAt || 0)).map((e) => e.key);
  }
  function counting(store) {
    const c = { n: 0 };
    const load = store._load.bind(store);
    store._load = (p) => { c.n++; return load(p); };
    return c;
  }

  it('M1: a query reads no file for an entry it does not return, and with a limit only that many; what it returns is unchanged', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'm1-recall-'));
    try {
      filled(dir);
      const store = new MS.MemoryStore(dir, 'rp');
      await store.load();
      assert.strictEqual(store.count(), N);
      const reads = counting(store);
      assert.deepStrictEqual(store.recall('needle-not-there'), []);
      // 9f6847c: one file read for each of the 952 entries the cache did not hold.
      assert.strictEqual(reads.n, 0, 'a miss reads nothing');
      const few = store.recall('entry 123 ');
      assert.deepStrictEqual(few.map((e) => e.key), reference(store, 'entry 123 '));
      reads.n = 0;
      const limited = store.recall('entry 1', { limit: 5 });
      assert.strictEqual(limited.length, 5);
      assert.ok(reads.n <= 5, `a limit reads at most that many (${reads.n})`);
      assert.strictEqual(limited.total, reference(store, 'entry 1').length, '`total` counts every match');
      assert.deepStrictEqual(limited.map((e) => e.key), reference(store, 'entry 1').slice(0, 5));
      for (const q of ['', 'entry 1', 'ENTRY 29', 'tagged', 'recall perf', 'calm (v:0', 'neutral', limited[0].key.slice(4, 20), 'focus: entry 2999']) {
        assert.deepStrictEqual(store.recall(q).map((e) => e.key), reference(store, q), `the same entries for ${JSON.stringify(q)}`);
      }
      reads.n = 0;
      const where = store.recall('', { limit: 3, where: (e) => e.tags.includes('Tagged') });
      assert.ok(where.length === 3 && where.every((e) => e.tags.includes('Tagged')));
      assert.ok(reads.n <= 21, `only as many read as it takes to fill the limit (${reads.n})`);
      reads.n = 0;
      store.recall('needle-not-there');
      assert.strictEqual(store.newestOwnCreatedAt() > 0, true);
      const oldest = store._index.byTime[store._index.byTime.length - 1];
      assert.ok(!store.__cache.has(oldest), 'the scene: an entry the cache does not hold');
      assert.strictEqual(store.getLifecycle(oldest), 'observed');
      assert.strictEqual(reads.n, 0, 'nor do the timestamp ratchet\'s scan and the lifecycle read a file');
      const old = reference(store, 'entry 7 ')[0];
      assert.strictEqual(store.validateCMB(old, { lifecycle: 'validated' }).ok, true);
      store.__cache.delete(old);
      reads.n = 0;
      assert.strictEqual(store.getLifecycle(old), 'validated', 'the index follows every write of the lifecycle');
      assert.strictEqual(reads.n, 0);
      assert.strictEqual(new MS.MemoryStore(dir, 'rp').getLifecycle(old), 'validated', 'and is rebuilt from the files');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('M1: the cache starts with the newest entries; a recall reads through it, never into it', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'm1-cache-'));
    try {
      filled(dir);
      for (const sync of [false, true]) {
        const store = new MS.MemoryStore(dir, 'rp');
        if (sync) store._ensureIndex(); else await store.load();
        const newest = store._index.recentKeys(MS.CACHE_MAX_ENTRIES);
        // 9f6847c: the cache held the last 2,048 files read (the directory's order).
        assert.deepStrictEqual([...store.__cache.keys()].sort(), [...newest].sort(), `the newest ${MS.CACHE_MAX_ENTRIES} (${sync ? 'sync' : 'async'} build)`);
        const before = [...store.__cache.keys()];
        store.recall('');
        assert.deepStrictEqual([...store.__cache.keys()], before, 'a scan does not reorder or replace the working set');
      }
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('M1: the search index is bounded; an entry past the bound, or longer than its share, is still found', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'm1-bound-'));
    try {
      filled(dir, 1200, { long: true });
      const store = new MS.MemoryStore(dir, 'rp');
      await store.load();
      const s = store.__search;
      // 9f6847c: no index apart from the cache; a recall read every entry it did not hold.
      assert.ok(s && typeof s.chars === 'number' && s.size === 1200, 'a search index, apart from the entry cache, holds every entry\'s text');
      assert.ok(s.chars <= MS.SEARCH_MAX_CHARS);
      for (const v of s._map.values()) assert.ok(v.text.length <= MS.SEARCH_ENTRY_CHARS, 'each entry\'s share is bounded');
      assert.deepStrictEqual(store.recall('deepneedle500').map((e) => e.key), reference(store, 'deepneedle500'), 'a match past an entry\'s share is found');
      // A small bound: only the newest entries keep their text; the rest are read, and still found.
      const small = new MS.SearchIndex({ maxChars: 40_000, entryChars: 256 });
      for (const [k, idx] of store._index.byKey) small.stage(k, store._load(idx.filePath), idx.storedAt);
      small.commit();
      store.__search = small;
      assert.ok(small.chars <= 40_000 && small.size < 1200, `bounded (${small.size} entries, ${small.chars} characters)`);
      const newestKey = store._index.byTime[0];
      assert.ok(small.get(newestKey), 'the newest keep their text');
      assert.ok(!small.get(store._index.byTime[store._index.byTime.length - 1]), 'the oldest let theirs go');
      const tiny = new MS.SearchIndex({ maxChars: 2000, entryChars: 256 });
      for (const [k, idx] of store._index.byKey) tiny.stage(k, store._load(idx.filePath), idx.storedAt);
      assert.ok(tiny._stagedChars <= 4000, 'held aside within twice the bound while a store loads');
      tiny.commit();
      assert.ok(tiny.chars <= 2000 && tiny.get(newestKey));
      const written = new MS.MemoryStore(dir, 'rp');
      written.__search = new MS.SearchIndex({ maxChars: 3000, entryChars: 256 });
      const fresh = core.createCMB({ categories: { focus: 'freshly written needle' }, createdBy: 'rp', room: 'default' });
      written.write(core.renderContent(fresh), { cmb: fresh });
      assert.ok(written.__search.get(fresh.metadata.key) && written.__search.chars <= 3000, 'a new entry is indexed as the newest, within the bound');
      for (const q of ['entry 3 ', 'entry 1199 ', 'deepneedle1000', 'tagged']) {
        assert.deepStrictEqual(store.recall(q).map((e) => e.key), reference(store, q), `found past the bound: ${q}`);
      }
      const gone = store._index.byTime[0];
      store._index.get(gone).tier = 'cold';
      assert.strictEqual(store.purge(), 1);
      assert.strictEqual(small.get(gone), undefined, 'a purged entry\'s text goes with it');
      assert.deepStrictEqual(store.recall('').map((e) => e.key), reference(store, ''));
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
});
