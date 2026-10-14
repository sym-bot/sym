'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads
process.env.SYM_SEMANTIC_ENCODER = process.env.SYM_SEMANTIC_ENCODER || 'off';

/**
 * 0.14.3 security review R2, the sym-attest-v1 findings: each a regression test that fails on 632b95d
 * for its own reason.
 *
 *   R2-4   the signature checks a node makes grow with the number of sessions (the global ceiling was
 *          spent only after verification): one global budget, spent before, shared fairly
 *   R2-7   a flood of free identities evicts equivocation evidence and own-witness memory, and the node
 *          then witnesses a third history
 *   R2-8   aggregateAttestations weighs every attestation under a cognition key, of any assertion
 *   R2-15  a successor checkpoint whose prev is not the root of the checkpoint held before it is stored
 *          and witnessed
 *   R2-16  a second attestation at one (attester, seq) silently replaces the first
 *   R2-17  an honest witness of an equivocator's other checkpoint is muted, its other witnesses dropped
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const core = require('../lib/core');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const { AttestationStore } = require('../lib/attestation-store');
const A = require('../lib/core/attestation');
const { identity, admitAs } = require('./_core-secure');

const ROOM = 'team-room';
const hex = () => crypto.randomBytes(32).toString('hex');
const CATS = { focus: 'admit', issue: 'admit', intent: 'admit', motivation: 'admit', commitment: 'admit', perspective: 'admit', mood: 'admit' };
const nodes = [];
function mk(opts = {}) {
  const n = new SymNode({ name: `sec-attest-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`, silent: true, discovery: new NullDiscovery(), room: ROOM, checkpointInterval: 0, ...opts });
  nodes.push(n);
  return n;
}
async function stopAll() {
  for (const n of nodes.splice(0)) {
    for (const r of n._dropReports?.values() || []) clearTimeout(r.timer);
    try { await n.stop(); } catch { /* not started */ }
    try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ }
  }
}
function cp(id, { from = 1, upto = 1, prev = 'genesis', root = hex() } = {}) {
  const c = { by: id.nodeId, roster: ROOM, from_seq: from, upto_seq: upto, prev, root, at: Date.now() };
  core.signCheckpoint(c, id.privateKey);
  return c;
}
const cpFrame = (c) => ({ type: 'sym-attest-checkpoint', checkpoint: core.toWireCheckpoint(c) });
function witness(by, c) {
  const w = { attester: c.by, roster: ROOM, from_seq: c.from_seq, upto_seq: c.upto_seq, root: c.root, by: by.nodeId, role: 'participant', at: Date.now() };
  core.signWitness(w, by.privateKey);
  return w;
}
const witFrame = (w) => ({ type: 'sym-attest-witness', witness: core.toWireWitness(w) });
function attestation(by, seq, extra = {}) {
  const a = { of: `cmb-${hex()}`, assertionId: `asrt-${hex()}`, by: by.nodeId, at: 1, roster: ROOM, method: 'neural', verdict: 'aligned', categories: CATS, role: 'participant', seq, prev: 'genesis', ...extra };
  core.signAttestation(a, by.privateKey);
  return a;
}
const forgedAttestation = (by, seq) => ({ ...attestation(by, seq), sig: crypto.randomBytes(64).toString('base64url') });

describe('R2-4: one global budget of signature checks, spent before verification, shared fairly', () => {
  it('R2-4: the checks made are bounded by the global budget whatever the number of sessions', async () => {
    try {
      const V = mk({ gossipBudget: { globalPerSecond: 200, globalBurst: 200 } });
      let now = 1_000_000; V._gossipClock = () => now;
      const K = 10;
      const peers = Array.from({ length: K }, (_, i) => identity(`p${i}`));
      for (const p of peers) V._roster.bind(p.nodeId, p.publicKey, 'proven');
      let checks = 0;
      // One simulated second: every peer sends one forged attestation in its own name a millisecond, well
      // inside its own lane (2,000 a second). Each that reaches the signature check fails it.
      for (let ms = 0; ms < 1000; ms++) {
        now += 1;
        for (const p of peers) if (V._ingestAttestation(forgedAttestation(p, ms + 1), p.nodeId, p.name).reason === 'bad-signature') checks++;
      }
      // 632b95d: each lane bought its own checks, K × 1,000 = 10,000 (the ceiling counted only after).
      assert.ok(checks <= 200 + 200 + K, `checks ${checks} stay within the global budget (burst 200 + 200 a second)`);
    } finally { await stopAll(); }
  });

  it('R2-4: a flooding peer spends its own share; an honest peer\'s statements are still checked and taken', async () => {
    try {
      const V = mk({ gossipBudget: { globalPerSecond: 100, globalBurst: 100 } });
      let now = 1_000_000; V._gossipClock = () => now;
      const F = identity('flooder'); const H = identity('honest');
      for (const p of [F, H]) V._roster.bind(p.nodeId, p.publicKey, 'proven');
      const flood = Array.from({ length: 2000 }, (_, i) => attestation(F, i + 1));
      const honest = Array.from({ length: 20 }, (_, i) => attestation(H, i + 1));
      let taken = 0;
      for (let ms = 0; ms < 2000; ms++) {
        now += 1;
        V._ingestAttestation(flood[ms], F.nodeId, F.name);
        if (ms % 100 === 0 && V._ingestAttestation(honest[ms / 100], H.nodeId, H.name).ok) taken++;
      }
      // 632b95d: the flooder's verified statements spent the shared ceiling, and the honest peer's were
      // then checked and dropped over it.
      assert.strictEqual(taken, 20, `every honest statement taken (${taken})`);
    } finally { await stopAll(); }
  });
});

describe('R2-7: equivocation evidence and own-witness memory are never evicted', () => {
  it('R2-7: a flood of fresh attesters leaves the evidence held, and the node witnesses no further history of the equivocator', async () => {
    try {
      const V = mk();
      const E = identity('equivocator'); const sE = admitAs(V, E);
      const first = cp(E);
      V._receiveSessionFrame(sE, cpFrame(first));
      V._receiveSessionFrame(sE, cpFrame(cp(E)));   // a second root for the same position: the evidence
      assert.strictEqual(V._attestations.attesterEquivocated(E.nodeId), true);
      for (let i = 0; i < 1100; i++) {
        const S = identity(`s${i}`); const s = admitAs(V, S);
        V._receiveSessionFrame(s, cpFrame(cp(S)));
        s.close(); V._peers.delete(S.nodeId); V._sessionKeys.delete(S.nodeId);
      }
      // 632b95d: the flood evicted E (least recently updated) with its evidence and own-witness memory.
      assert.strictEqual(V._attestations.attesterEquivocated(E.nodeId), true, 'the evidence is still held');
      const third = cp(E);
      V._receiveSessionFrame(sE, cpFrame(third));
      assert.strictEqual(V._attestations.checkpointAt(E.nodeId, 1).root, first.root, 'the first copy stays the position\'s');
      const roots = new Set(sE.sent.filter((f) => f.type === 'sym-attest-witness' && f.witness.attester === E.nodeId && f.witness.by === V.nodeId).map((f) => f.witness.root));
      assert.deepStrictEqual([...roots], [first.root], 'this node countersigned one root for E@1, never a third');
    } finally { await stopAll(); }
  });

  it('R2-7 (store): an attester holding evidence keeps its place; when every place holds evidence a newcomer is refused, counted', () => {
    const st = new AttestationStore({ maxAttesters: 2 });
    const c = (by, root, from = 1, upto = 1, prev = 'genesis') => ({ by, from_seq: from, upto_seq: upto, prev, root, sig: `${by}-${root}` });
    st.recordCheckpoint(c('E', 'r1'));
    assert.strictEqual(st.recordCheckpoint(c('E', 'r2')).reason, 'conflict');
    for (const by of ['B', 'C', 'D']) assert.strictEqual(st.recordCheckpoint(c(by, 'r')).stored, true, `${by} takes the evictable place`);
    assert.strictEqual(st.attesterEquivocated('E'), true);
    assert.deepStrictEqual([...st._checkpoints.keys()].sort(), ['D', 'E']);
    st.recordCheckpoint(c('D', 'x'));   // D equivocates too: now every place holds evidence
    assert.strictEqual(st.recordCheckpoint(c('N', 'r')).reason, 'full');
    assert.strictEqual(st.refusedReport().checkpointsFull, 1);
    assert.strictEqual(st.attesterEquivocated('D') && st.attesterEquivocated('E'), true);
  });

  it('R2-7 (store): what this node witnessed is remembered past the attester cap (watermark), and across a rotation and restart', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-own-'));
    try {
      const opts = { dir, selfId: 'me', maxAttesters: 2, maxOwnWatermarks: 3, rotateBytes: 256, log: () => {} };
      const st = new AttestationStore(opts);
      for (const a of ['A', 'B', 'C', 'D']) {
        st.recordCheckpoint({ by: a, upto_seq: 7, root: 'r', sig: `c${a}` });
        st.recordWitness({ attester: a, upto_seq: 7, root: 'r', by: 'me', sig: `w${a}` });
      }
      // 632b95d: A's and B's own-witness memory left with the cap of 2 attesters.
      for (const a of ['A', 'B', 'C', 'D']) assert.strictEqual(st.hasWitnessed(a, 7, 'me'), true, `${a}@7 still known as witnessed`);
      assert.strictEqual(st.hasWitnessed('A', 3, 'me'), true, 'a position below the watermark counts as witnessed (never signed again)');
      for (let i = 0; i < 40; i++) st.recordCheckpoint({ by: 'D', upto_seq: 100 + i, root: `r${i}`, sig: `cd${i}` });
      assert.strictEqual(st._rotate('witnesses.jsonl'), true, 'a rotation writes own-witness memory as its lines');
      const again = new AttestationStore(opts);
      for (const a of ['A', 'B', 'C', 'D']) assert.strictEqual(again.hasWitnessed(a, 7, 'me'), true, `${a}@7 known after a restart`);
      // Full: a new attester cannot be remembered, so it is not witnessed (counted).
      assert.strictEqual(again.canRememberOwnWitness('E'), true, 'one watermark place left');
      again.recordWitness({ attester: 'E', upto_seq: 1, root: 'r', by: 'me', sig: 'wE' });
      again.recordWitness({ attester: 'F', upto_seq: 1, root: 'r', by: 'me', sig: 'wF' });
      assert.strictEqual(again.canRememberOwnWitness('G'), false);
      assert.ok(again.refusedReport().ownWitnessFull >= 1);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
});

describe('R2-8: aggregateAttestations weighs only the held assertion', () => {
  it('R2-8: attestations of another assertion under the same cognition key are excluded; one naming the held assertion counts', async () => {
    try {
      const V = mk();
      const r = V.remember({ focus: 'deploy plan', issue: 'i', intent: 'n', motivation: 'm', commitment: 'c', perspective: 'p', mood: { text: 'calm' } });
      const key = r.key;
      const held = V._store.get(key).cmb.metadata.assertionId;
      for (let i = 0; i < 2; i++) {
        const T = identity(`t${i}`); const s = admitAs(V, T);
        V._receiveSessionFrame(s, { type: 'sym-attest-attestation', attestation: core.toWireAttestation(attestation(T, 1, { of: key, verdict: 'rejected' })) });
      }
      assert.strictEqual(V.attestationsFor(key).length, 2, 'the audit trail holds both');
      const agg = V.aggregateAttestations(key);
      // 632b95d: total 2, overall 'rejected' with confidence 1, about another record.
      assert.strictEqual(agg.total, 0);
      assert.deepStrictEqual(agg.excluded.map((e) => e.reason), ['other-assertion', 'other-assertion']);
      const T = identity('t-held'); const s = admitAs(V, T);
      V._receiveSessionFrame(s, { type: 'sym-attest-attestation', attestation: core.toWireAttestation(attestation(T, 1, { of: key, assertionId: held })) });
      const again = V.aggregateAttestations(key);
      assert.strictEqual(again.total, 1);
      assert.strictEqual(again.assertionId, held);
      assert.strictEqual(again.overall.dominant, 'aligned');
      assert.strictEqual(V.aggregateAttestations('cmb-not-held').total, 0, 'no record held, no assertion named: nothing weighed');
    } finally { await stopAll(); }
  });
});

describe('R2-15: a checkpoint must fit the chain held', () => {
  it('R2-15: a successor whose prev is not the root of the checkpoint held right before it is refused, never stored or witnessed (either order)', async () => {
    try {
      const V = mk();
      const E = identity('e'); const sE = admitAs(V, E);
      const a = cp(E, { from: 1, upto: 8 });
      const b = cp(E, { from: 9, upto: 16, prev: hex() });   // right after a, chained to another root
      assert.deepStrictEqual(core.checkpointConflict(a, b), [], 'no §5.2 conflict: not evidence');
      V._receiveSessionFrame(sE, cpFrame(a));
      assert.strictEqual(V._ingestCheckpoint(A.fromWireCheckpoint(core.toWireCheckpoint(b)), E.nodeId, sE).reason, 'malformed-link');
      // 632b95d: b held (prev X) and witnessed.
      assert.deepStrictEqual(V._attestations.checkpointsOf(E.nodeId).map((c) => c.upto_seq), [8]);
      assert.strictEqual(V._attestations.witnessAt(E.nodeId, 16, V.nodeId), null, 'not witnessed');
      const good = cp(E, { from: 9, upto: 16, prev: a.root });
      V._receiveSessionFrame(sE, cpFrame(good));
      assert.deepStrictEqual(V._attestations.checkpointsOf(E.nodeId).map((c) => c.upto_seq), [8, 16], 'the linked successor is taken');
      // The other order: a predecessor whose root is not the prev of the held successor.
      const G = identity('g'); const sG = admitAs(V, G);
      const succ = cp(G, { from: 9, upto: 16, prev: hex() });
      V._receiveSessionFrame(sG, cpFrame(succ));
      const pred = cp(G, { from: 1, upto: 8 });
      assert.strictEqual(V._ingestCheckpoint(A.fromWireCheckpoint(core.toWireCheckpoint(pred)), G.nodeId, sG).reason, 'malformed-link');
      assert.strictEqual(V._attestations.checkpointAt(G.nodeId, 8), null);
      // A conflicting copy is still the evidence, whatever the link rule says.
      assert.strictEqual(V._ingestCheckpoint(A.fromWireCheckpoint(core.toWireCheckpoint(cp(E, { from: 1, upto: 8 }))), E.nodeId, sE).reason, 'conflict');
      assert.strictEqual(V._attestations.attesterEquivocated(E.nodeId), true);
    } finally { await stopAll(); }
  });
});

describe('R2-16: one attestation per (attester, seq)', () => {
  const v = require('./fixtures/sym-attest-v1.json');
  const main = v.attestations.map((x) => A.fromWireAttestation(x.attestation));
  const fork = v.forkAttestations.map((x) => A.fromWireAttestation(x.attestation));

  it('R2-16: a second, different attestation at a held seq is refused as a fork and kept as evidence, never a replacement; a restart re-derives it', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-fork-'));
    try {
      const st = new AttestationStore({ dir, log: () => {} });
      for (const a of main) st.record(a, { ingested: true });
      const by = main[0].by;
      const before = st.chainOf(by).map((a) => a.sig);
      const r5 = st.record(fork.find((x) => x.seq === 5), { ingested: true });
      assert.strictEqual(r5.reason, 'conflict');
      assert.strictEqual(r5.first, true);
      assert.strictEqual(st.record(fork.find((x) => x.seq === 6), { ingested: true }).reason, 'conflict');
      // 632b95d: seq 5 and 6 were replaced by the fork's copies, silently.
      assert.deepStrictEqual(st.chainOf(by).map((a) => a.sig), before, 'the chain held is unchanged');
      assert.strictEqual(st.attesterEquivocated(by), true, 'the fork is evidence');
      assert.strictEqual(st.has(fork.find((x) => x.seq === 5).sig), true, 'a repeat of the evidence is a duplicate');
      const again = new AttestationStore({ dir, log: () => {} });
      assert.deepStrictEqual(again.chainOf(by).map((a) => a.sig), before);
      assert.strictEqual(again.attesterEquivocated(by), true, 're-derived after a restart');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('R2-16 (node): the fork is said once, and that attester\'s checkpoints are no longer taken', async () => {
    try {
      const V = mk();
      const T = identity('t'); const s = admitAs(V, T);
      const metrics = []; V.on('metric', (m) => metrics.push(m));
      V._receiveSessionFrame(s, { type: 'sym-attest-attestation', attestation: core.toWireAttestation(attestation(T, 1)) });
      V._receiveSessionFrame(s, { type: 'sym-attest-attestation', attestation: core.toWireAttestation(attestation(T, 1)) });
      assert.ok(metrics.some((m) => m.type === 'attestation-conflict' && m.kind === 'attestation' && m.attester === T.nodeId));
      assert.strictEqual(V._attestations.chainOf(T.nodeId).length, 1);
      V._receiveSessionFrame(s, cpFrame(cp(T)));
      assert.strictEqual(V._attestations.checkpointsOf(T.nodeId).length, 0, 'an equivocator\'s checkpoint is not taken or witnessed');
    } finally { await stopAll(); }
  });
});

describe('R2-17: only the equivocator is held to account', () => {
  it('R2-17: an honest witness of the equivocator\'s other checkpoint is not muted, and its witnesses of others are taken', async () => {
    try {
      const V = mk();
      const E = identity('equivocator'); const sE = admitAs(V, E);
      const W = identity('honest-witness'); const sW = admitAs(V, W);
      const ca = cp(E); const cb = cp(E);
      V._receiveSessionFrame(sE, cpFrame(ca));
      V._receiveSessionFrame(sW, cpFrame(cb));   // W was shown the other history and relays it
      assert.strictEqual(V._attestations.attesterEquivocated(E.nodeId), true);
      V._receiveSessionFrame(sW, witFrame(witness(W, cb)));
      // 632b95d: W was muted for ten minutes as a witness that contradicts a held checkpoint.
      assert.strictEqual(V._witnessMuted(W.nodeId), false);
      const O = identity('other'); const sO = admitAs(V, O);
      const co = cp(O);
      V._receiveSessionFrame(sO, cpFrame(co));
      assert.strictEqual(V._ingestWitness(A.fromWireWitness(core.toWireWitness(witness(W, co))), W.nodeId, sW).ok, true);
    } finally { await stopAll(); }
  });

  it('R2-17: a witness muted before the equivocation was known is heard again once it is', async () => {
    try {
      const V = mk();
      const E = identity('equivocator'); const sE = admitAs(V, E);
      const W = identity('honest-witness'); const sW = admitAs(V, W);
      const ca = cp(E); const cb = cp(E);
      V._receiveSessionFrame(sE, cpFrame(ca));
      V._receiveSessionFrame(sW, witFrame(witness(W, cb)));   // W's witness of B arrives before B
      assert.strictEqual(V._witnessMuted(W.nodeId), true, 'until B is seen, W contradicts a held checkpoint');
      V._receiveSessionFrame(sW, cpFrame(cb));                 // B: E signed two histories
      assert.strictEqual(V._witnessMuted(W.nodeId), false, 'the equivocator was E');
    } finally { await stopAll(); }
  });
});
