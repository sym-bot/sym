'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * The session frames as MMP 2.0 update 1 (meshcognition-website PR #43, 2660ab9) defines them: the
 * mood frame by the founder's ruling, cmb-fetch and cmb-fetch-result as their schemas close them,
 * fetched records verified by the whole of §8.8.5 (D4), cmb-anchors as §9.4 sends it, a clear 1011
 * acted on only when it names this node's session or answers its probe, sealed ping and pong, and the
 * control envelope's bounds. Each test fails on 958592a.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const crypto = require('crypto');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const { isControlFrame, buildControlFrame } = require('../lib/core/sealed-control');
const { identity, connectNodes, until, signedRecord, signerOf, admitAs, deliver } = require('./_core-secure');

const uniq = (b) => `${b}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
const made = [];
function node(base, opts = {}) {
  const n = new SymNode({ name: uniq(base), silent: true, discovery: new NullDiscovery(), room: 'frames', ...opts });
  made.push(n);
  return n;
}
async function stopAll() {
  for (const n of made.splice(0)) { try { await n.stop(); } catch { /* */ } try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ } }
}
const sessionTo = (n, other) => { const p = n._peers.get(other.nodeId); return p && p.transport; };
/** Every inner frame `n` sends on `session`, captured before it is sealed. */
function capture(session) {
  const out = [];
  const real = session.trySend.bind(session);
  session.trySend = (f) => { out.push(JSON.parse(JSON.stringify(f))); return real(f); };
  return out;
}
const HEX = () => crypto.randomBytes(32).toString('hex');

describe('the mood frame: {type, mood, context, timestamp} (founder ruling, #26)', () => {
  it('is sent with no sender fields, and the text and context are bounded', async () => {
    try {
      const A = node('m-a'); const B = node('m-b');
      await A.start(); await B.start();
      await connectNodes(B, A);
      const sent = capture(sessionTo(A, B));
      A.broadcastMood('calm, focused', { context: 'after the review' });
      const f = sent.find((x) => x.type === 'mood');
      assert.deepStrictEqual(Object.keys(f).sort(), ['context', 'mood', 'timestamp', 'type']);
      assert.strictEqual(f.context, 'after the review');
      assert.throws(() => A.broadcastMood('x'.repeat(1025)), (e) => e.code === 'EMOODFRAME');
      assert.throws(() => A.broadcastMood('ok', { context: 'c'.repeat(4097) }), (e) => e.code === 'EMOODFRAME');
      assert.doesNotThrow(() => A.broadcastMood('\u{1F600}'.repeat(1024)), '1,024 characters, counted as code points');
    } finally { await stopAll(); }
  });

  it('on receipt it is the session\'s proven peer\'s, by that peer\'s name; a frame naming a sender is refused', async () => {
    try {
      const A = node('m-recv');
      A._moodThreshold = 2; // accept any drift: the label is what is tested
      const P = identity('proven-peer');
      const s = admitAs(A, P);
      const got = [];
      A.on('mood-delivered', (e) => got.push(e));
      deliver(A, s, { type: 'mood', mood: 'calm', context: null, timestamp: 1 });
      assert.strictEqual(got.length, 1);
      assert.strictEqual(got[0].from, 'proven-peer');
      assert.strictEqual(got[0].authorNodeId, P.nodeId);
      const refusedBefore = A._metrics.framesRefusedByType.mood || 0;
      deliver(A, s, { type: 'mood', from: P.nodeId, fromName: 'mallory', mood: 'calm', context: null, timestamp: 1 });
      deliver(A, s, { type: 'mood', mood: 'x'.repeat(1025) });
      deliver(A, s, { type: 'mood', mood: 'calm', valence: 0.5 });
      assert.strictEqual(got.length, 1, 'none of the three is delivered');
      assert.strictEqual((A._metrics.framesRefusedByType.mood || 0) - refusedBefore, 3);
    } finally { await stopAll(); }
  });
});

describe('cmb-fetch and cmb-fetch-result as their schemas close them (#26)', () => {
  it('a fetch names no sender, and its result carries no timestamp', async () => {
    try {
      const A = node('f-a'); const B = node('f-b');
      await A.start(); await B.start();
      await connectNodes(B, A);
      const asked = capture(sessionTo(A, B));
      const answered = capture(sessionTo(B, A));
      const r = await A.fetchCMB(`cmb-${HEX()}`, { timeoutMs: 1500 });
      assert.strictEqual(r, null);
      const fetch = asked.find((f) => f.type === 'cmb-fetch');
      assert.deepStrictEqual(Object.keys(fetch).sort(), ['key', 'reqId', 'timestamp', 'type']);
      const result = answered.find((f) => f.type === 'cmb-fetch-result');
      assert.deepStrictEqual(Object.keys(result).sort(), ['missing', 'reqId', 'returned', 'type']);
    } finally { await stopAll(); }
  });

  it('a fetch carrying a keys array, or a from, is refused, not served', async () => {
    try {
      const A = node('f-srv');
      const own = signedRecord(signerOf(A), { room: A._room, categories: { focus: 'served once' } });
      A._store.receiveFromPeer('self', { key: own.metadata.key, content: 'x', source: A.name, cmb: own, _cmbVerified: true });
      const s = admitAs(A, identity('asker'));
      deliver(A, s, { type: 'cmb-fetch', reqId: 'r1', key: own.metadata.key, keys: [own.metadata.key] });
      deliver(A, s, { type: 'cmb-fetch', reqId: 'r2', key: own.metadata.key, from: s.nodeId });
      assert.deepStrictEqual(s.sent, [], 'neither is answered');
      assert.strictEqual(A._metrics.framesRefusedByType['cmb-fetch'], 2);
      deliver(A, s, { type: 'cmb-fetch', reqId: 'r3', key: own.metadata.key });
      assert.deepStrictEqual(s.sent.map((f) => f.type), ['cmb', 'cmb-fetch-result']);
    } finally { await stopAll(); }
  });
});

describe('D4: a fetched record is attributed only after the whole of §8.8.5 (#26)', () => {
  it('a record whose author this node cannot resolve comes back as its categories only, unverified', async () => {
    try {
      const A = node('d4-a'); const B = node('d4-b');
      await A.start(); await B.start();
      await connectNodes(B, A);
      const M = identity('stranger');
      const root = signedRecord(M, { room: B._room, categories: { focus: 'a lineage root by a stranger' } });
      B._store.receiveFromPeer(M.nodeId, { key: root.metadata.key, content: 'x', source: 'stranger', cmb: root, _cmbVerified: true });
      const r = await A.fetchCMB(root.metadata.key, { timeoutMs: 3000 });
      assert.ok(r, 'answered');
      assert.strictEqual(r.verified, false);
      assert.strictEqual(r.reason, 'unresolvable-author');
      assert.strictEqual(r.cmb, undefined, 'no metadata handed out as if attributed');
      assert.strictEqual(r.categories.focus.text, 'a lineage root by a stranger');
    } finally { await stopAll(); }
  });

  it('a record by an author this node has proven comes back verified, with its author', async () => {
    try {
      const A = node('d4v-a'); const B = node('d4v-b');
      await A.start(); await B.start();
      await connectNodes(B, A);
      const own = signedRecord(signerOf(B), { room: B._room, categories: { focus: 'by the serving node itself' } });
      B._store.receiveFromPeer('self-older', { key: own.metadata.key, content: 'x', source: B.name, cmb: own, _cmbVerified: true });
      const r = await A.fetchCMB(own.metadata.key, { timeoutMs: 3000 });
      assert.strictEqual(r.verified, true);
      assert.strictEqual(r.authorNodeId, B.nodeId);
      assert.strictEqual(r.cmb.metadata.assertionId, own.metadata.assertionId);
    } finally { await stopAll(); }
  });

  it('a record it holds under Legacy Import answers as its categories only', async () => {
    try {
      const A = node('d4-local');
      const rec = signedRecord(identity('legacy'), { room: A._room, categories: { focus: 'imported' } });
      A._store.receiveFromPeer('legacy', { key: rec.metadata.key, content: 'x', source: 'legacy', cmb: rec, _cmbVerified: false });
      const e = A._store.get(rec.metadata.key); e.verified = false; e.profile = 'legacy-import';
      const r = await A.fetchCMB(rec.metadata.key);
      assert.strictEqual(r.verified, false);
      assert.strictEqual(r.cmb, undefined);
    } finally { await stopAll(); }
  });
});

describe('cmb-anchors (§9.4, #30)', () => {
  it('an admission with nothing to replay does not hold back the next one\'s context', async () => {
    try {
      const A = node('an-a');
      const P = identity('peer');
      const peer = { peerId: P.nodeId, name: 'peer' };
      const s1 = admitAs(A, P);
      A._greetSession(peer, s1, true);
      assert.deepStrictEqual(s1.sent.filter((f) => f.type === 'cmb-anchors').map((f) => f.keys), [[]]);
      A.remember({ focus: 'my own context', issue: 'i', intent: 'n', motivation: 'm', commitment: 'c', perspective: 'p', mood: { text: 'calm' } });
      const s2 = admitAs(A, P);
      A._greetSession(peer, s2, false);
      const anchors = s2.sent.filter((f) => f.type === 'cmb-anchors');
      assert.strictEqual(anchors.length, 1);
      assert.strictEqual(anchors[0].keys.length, 1, 'the record made after the empty list is replayed');
      const s3 = admitAs(A, P);
      A._greetSession(peer, s3, false);
      assert.deepStrictEqual(s3.sent.filter((f) => f.type === 'cmb-anchors').map((f) => f.keys), [[]], 'a non-empty list at most once a minute; the empty one every time');
    } finally { await stopAll(); }
  });

  it('a record signed for another room is not replayed, nor announced', async () => {
    try {
      const A = node('an-room');
      const old = signedRecord(signerOf(A), { room: 'elsewhere', categories: { focus: 'said in another room' } });
      A._store.write('x', { cmb: old });
      const s = admitAs(A, identity('peer'));
      A._greetSession({ peerId: s.nodeId, name: 'peer' }, s, true);
      assert.deepStrictEqual(s.sent.filter((f) => f.type === 'cmb-anchors').map((f) => f.keys), [[]]);
      assert.strictEqual(s.sent.filter((f) => f.type === 'cmb').length, 0);
    } finally { await stopAll(); }
  });

  it('a cmb-anchors frame that is not the schema\'s is refused whole', async () => {
    try {
      const A = node('an-recv');
      const s = admitAs(A, identity('peer'));
      deliver(A, s, { type: 'cmb-anchors', keys: Array.from({ length: 51 }, () => `cmb-${HEX()}`) });
      deliver(A, s, { type: 'cmb-anchors', keys: ['not-a-key'] });
      deliver(A, s, { type: 'cmb-anchors', keys: [], note: 'x' });
      assert.strictEqual(A._metrics.framesRefusedByType['cmb-anchors'], 3);
      deliver(A, s, { type: 'cmb-anchors', keys: [`cmb-${HEX()}`] });
      assert.strictEqual(s._anchorKeys.size, 1);
    } finally { await stopAll(); }
  });
});

describe('a clear 1011 over a relay (§5.2.2, #23)', () => {
  function relayClient() {
    const A = node('u-a');
    const from = 'ffffffff-ffff-7fff-bfff-ffffffffffff'; // larger than any v7 nodeId: A is the client
    const held = { confirmed: true, closed: false, sessionId: crypto.randomBytes(16).toString('hex'), probeSince: 0 };
    A._relay = { present: new Set([from]), sendTo() {} };
    A._relaySessions = new Map([[from, { client: null, server: null, confirmed: new Set([held]) }]]);
    const started = [];
    A._startRelayClient = (id) => started.push(id);
    return { A, from, held, started };
  }
  it('prompts a handshake only when its detail names this node\'s session or its probe is outstanding', async () => {
    try {
      const { A, from, held, started } = relayClient();
      A._relayEnvelope(from, 'peer', { type: 'error', code: 1011, message: 'unknown session' });
      A._relayEnvelope(from, 'peer', { type: 'error', code: 1011, message: 'unknown session', detail: `session:${'0'.repeat(32)}` });
      assert.deepStrictEqual(started, [], 'no detail, or another session: nothing');
      A._relayEnvelope(from, 'peer', { type: 'error', code: 1011, message: 'unknown session', detail: `session:${held.sessionId}` });
      assert.deepStrictEqual(started, [from]);
    } finally { await stopAll(); }
  });
  it('prompts nothing while a newer session with that peer waits to supersede the one named', async () => {
    try {
      const { A, from, held, started } = relayClient();
      const waiting = { confirmed: true, closed: false, sessionId: crypto.randomBytes(16).toString('hex'), _supersedes: held };
      A._relaySessions.get(from).confirmed.add(waiting);
      A._relayEnvelope(from, 'peer', { type: 'error', code: 1011, message: 'unknown session', detail: `session:${held.sessionId}` });
      assert.deepStrictEqual(started, []);
    } finally { await stopAll(); }
  });
  it('a probe outstanding is answered by a 1011 with no detail; the prompts are paced by the retry backoff', async () => {
    try {
      const { A, from, held, started } = relayClient();
      held.probeSince = Date.now();
      A._relayEnvelope(from, 'peer', { type: 'error', code: 1011, message: 'unknown session' });
      assert.strictEqual(started.length, 1);
      for (let i = 0; i < 20; i++) A._relayEnvelope(from, 'peer', { type: 'error', code: 1011, message: 'unknown session', detail: `session:${held.sessionId}` });
      assert.strictEqual(started.length, 1, 'forged repeats within the backoff prompt nothing more');
    } finally { await stopAll(); }
  });
});

describe('ping and pong sealed, and the control envelope\'s bounds (§7.1, #26)', () => {
  it('a sealed ping is answered with a pong; a sealed pong ends an outstanding probe', async () => {
    try {
      const A = node('p-a'); const B = node('p-b');
      await A.start(); await B.start();
      await connectNodes(B, A);
      const sA = sessionTo(A, B); const sB = sessionTo(B, A);
      const refused = [];
      sB.on('refused', (t, r) => refused.push([t, r]));
      const wired = [];
      const realWire = sB._wire.bind(sB);
      sB._wire = (f) => { wired.push(f.type); return realWire(f); };
      sA.probeSince = Date.now();
      const pos = sA._mmp.nextSend();
      sA._wire(buildControlFrame({ frame: { type: 'ping' }, sessionId: sA.sessionId, direction: pos.direction, sequence: pos.sequence, trafficKey: pos.trafficKey }));
      await until(() => wired.includes('pong'), 1000);
      assert.ok(wired.includes('pong'));
      assert.deepStrictEqual(refused, []);
      await until(() => sA.probeSince === 0, 1000);
      assert.strictEqual(sA.probeSince, 0);
    } finally { await stopAll(); }
  });
  it('a cmb-encrypted envelope is bounded as encrypted-cmb-frame.schema.json bounds it (5417176)', () => {
    const { openEncryptedSealed } = require('../lib/core/cmb-encrypted-frame');
    const base = { type: 'cmb-encrypted', protocolVersion: '2.0', suite: 'X25519-HKDF-SHA256-ChaCha20-Poly1305', sessionId: 'a'.repeat(32), sequence: '1', direction: 'client-to-server', metadata: {}, sealed: 'A'.repeat(22) };
    const key = crypto.randomBytes(32);
    for (const [label, f] of [['30 digits', { ...base, sequence: '1'.repeat(30) }], ['shorter than the tag', { ...base, sealed: 'A'.repeat(21) }], ['longer than a 720 KiB record seals to', { ...base, sealed: 'A'.repeat(983063) }], ['a sessionId that is not 32 hex', { ...base, sessionId: 'x' }], ['a sequence that is a number', { ...base, sequence: 1 }]]) {
      assert.throws(() => openEncryptedSealed({ frame: f, trafficKey: key }), /bad (sequence|sealed value|sessionId)/, label);
    }
  });
  it('an envelope with a 30-digit sequence, a sealed value shorter than the tag, or another member is not a control envelope', () => {
    const ok = { type: 'control-encrypted', protocolVersion: '2.0', suite: 'X25519-HKDF-SHA256-ChaCha20-Poly1305', sessionId: 'a'.repeat(32), sequence: '1', direction: 'client-to-server', sealed: 'A'.repeat(22) };
    assert.strictEqual(isControlFrame(ok), true);
    assert.strictEqual(isControlFrame({ ...ok, sequence: '1'.repeat(30) }), false);
    assert.strictEqual(isControlFrame({ ...ok, sealed: 'A'.repeat(21) }), false);
    assert.strictEqual(isControlFrame({ ...ok, note: 'x' }), false);
    assert.strictEqual(isControlFrame({ ...ok, sessionId: 'not-hex' }), false);
  });
});
