'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * sym-attest-v1's chained checkpoint (MMP 2.0 update 1, PR #43 at 5417176; D1): every case of the
 * draft sym-attest-v1 vector against sym's own constructions and the reference lib.mjs, then the
 * store's and the node's rules — link checks, equivocation as overlapping ranges or a shared prev, no
 * witnessing an attester after a conflict, a chain that ends visibly when its segment is lost. Each
 * test fails on bacab72.
 */

const { describe, it, before } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const core = require('../lib/core');
const { AttestationStore } = require('../lib/attestation-store');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const { identity, admitAs } = require('./_core-secure');

const FIX = path.join(__dirname, 'fixtures');
const sources = JSON.parse(fs.readFileSync(path.join(FIX, 'SOURCES.json'), 'utf8'));
function vendored(name) {
  const bytes = fs.readFileSync(path.join(FIX, name));
  assert.strictEqual(crypto.createHash('sha256').update(bytes).digest('hex'), sources.files[name].sha256);
  return JSON.parse(bytes.toString('utf8'));
}
const V = vendored('sym-attest-v1.json');
const KEY = { attester: V.testKeys.attester.publicKeyBase64url, witness: V.testKeys.witness.publicKeyBase64url };
const segmentOf = (atts, cp) => atts.map((x) => x.attestation).filter((a) => a.seq >= cp.fromSeq && a.seq <= cp.uptoSeq).sort((a, b) => a.seq - b.seq);
const store = (cp) => core.fromWireCheckpoint(cp);

describe('the sym-attest-v1 vector: the four signed constructions and the chained root', () => {
  let L;
  before(async () => { L = await import(path.join(FIX, 'mmp-lib.mjs')); });

  for (const [label, list] of [['attestations', V.attestations], ['forkAttestations', V.forkAttestations]]) {
    it(`${label}: payload bytes, signature and chain link`, () => {
      for (const x of list) {
        const a = core.fromWireAttestation(x.attestation);
        assert.ok(a, 'the wire form is the schema\'s');
        assert.strictEqual(core.attestationPayload(a).toString('hex'), x.payloadHex);
        assert.strictEqual(core.verifyAttestation(a, KEY.attester).valid, true);
        if (x.chainLinkOfThis) assert.strictEqual(core.chainLink(a.sig), x.chainLinkOfThis);
        assert.deepStrictEqual(core.attestationPayload(a), L.attestationPayloadV1(x.attestation));
      }
    });
  }

  it('checkpoints: 1-, 2- and 3-leaf segments, the chained root, the payload and the signature', () => {
    for (const [list, atts] of [[V.checkpoints, V.attestations], [Object.values(V.forkCheckpoints), V.forkAttestations]]) {
      for (const x of list) {
        const cp = x.checkpoint;
        const sigs = segmentOf(atts, cp).map((a) => a.sig);
        assert.strictEqual(sigs.length, cp.uptoSeq - cp.fromSeq + 1, 'the whole segment is in the vector');
        assert.strictEqual(core.attestMerkleRoot(sigs), x.segmentRootHex);
        assert.strictEqual(L.attestSegmentRoot(sigs), x.segmentRootHex);
        const root = core.attestCheckpointRoot({ prev: cp.prev, fromSeq: cp.fromSeq, uptoSeq: cp.uptoSeq, segmentRoot: x.segmentRootHex });
        assert.strictEqual(root, cp.root);
        assert.strictEqual(L.attestCheckpointRoot({ prev: cp.prev, fromSeq: cp.fromSeq, uptoSeq: cp.uptoSeq, segmentRoot: x.segmentRootHex }), cp.root);
        const held = store(cp);
        assert.ok(held, 'the wire form is the schema\'s');
        assert.strictEqual(core.checkpointPayload(held).toString('hex'), x.payloadHex);
        assert.deepStrictEqual(core.checkpointPayload(held), L.attestCheckpointPayloadV1(cp));
        assert.strictEqual(core.verifyCheckpoint(held, KEY.attester).valid, true);
      }
    }
    assert.deepStrictEqual(V.checkpoints.map((x) => x.checkpoint.uptoSeq - x.checkpoint.fromSeq + 1), [1, 2, 3]);
    for (let i = 1; i < V.checkpoints.length; i++) {
      assert.strictEqual(V.checkpoints[i].checkpoint.prev, V.checkpoints[i - 1].checkpoint.root, 'chained to the one before');
      assert.strictEqual(V.checkpoints[i].checkpoint.fromSeq, V.checkpoints[i - 1].checkpoint.uptoSeq + 1);
    }
  });

  it('the witness carries and signs fromSeq', async () => {
    const w = core.fromWireWitness(V.witness.witness);
    assert.ok(w);
    assert.strictEqual(core.witnessPayload(w).toString('hex'), V.witness.payloadHex);
    assert.deepStrictEqual(core.witnessPayload(w), L.attestWitnessPayloadV1(V.witness.witness));
    assert.strictEqual(core.verifyWitness(w, KEY.witness).valid, true);
    assert.strictEqual(core.verifyWitness({ ...w, from_seq: w.from_seq + 1 }, KEY.witness).valid, false, 'fromSeq is signed');
  });

  it('conflicts: overlapping ranges or a shared prev, never the same checkpoint or a chain', () => {
    for (const c of V.conflicts) {
      const because = core.checkpointConflict(store(c.a), store(c.b));
      assert.deepStrictEqual(because.sort(), [...c.expected.because].sort(), c.label);
      assert.deepStrictEqual(because.sort(), L.attestCheckpointConflict(c.a, c.b).sort());
    }
    for (const c of V.notConflicts) {
      assert.deepStrictEqual(core.checkpointConflict(store(c.a), store(c.b)), [], c.label);
      assert.deepStrictEqual(L.attestCheckpointConflict(c.a, c.b), []);
    }
  });

  it('link checks: malformed, not evidence', () => {
    for (const c of V.linkChecks) {
      // A reversed range is refused at the wire already; the rule is checked on the raw shape too.
      const cp = { ...c.checkpoint, from_seq: c.checkpoint.fromSeq, upto_seq: c.checkpoint.uptoSeq };
      const prev = c.prev ? { ...c.prev, from_seq: c.prev.fromSeq, upto_seq: c.prev.uptoSeq } : null;
      assert.strictEqual(core.checkpointLinkValid(cp, prev), c.expected.valid, c.label);
      assert.strictEqual(L.attestCheckpointLinkValid(c.checkpoint, c.prev || null), c.expected.valid);
    }
  });
});

describe('the store holds one chain per attester (§5.2)', () => {
  const s = () => new AttestationStore({});
  it('the vector\'s chain is taken in order; each conflicting pair\'s second copy is evidence, and then the attester is dropped', () => {
    const st = s();
    for (const x of V.checkpoints) assert.strictEqual(st.recordCheckpoint(store(x.checkpoint)).stored, true);
    for (const c of V.conflicts) {
      const t = s();
      assert.strictEqual(t.recordCheckpoint(store(c.a)).stored, true, `${c.label}: the first is held`);
      const r = t.recordCheckpoint(store(c.b));
      assert.strictEqual(r.reason, 'conflict', c.label);
      assert.strictEqual(r.first, true);
      assert.strictEqual(t.attesterEquivocated(c.a.by), true);
      // A later checkpoint from that attester adds nothing.
      const later = store({ ...V.checkpoints[2].checkpoint, fromSeq: 7, uptoSeq: 7, prev: V.checkpoints[2].checkpoint.root });
      assert.strictEqual(t.recordCheckpoint(later).reason, 'attester-equivocated');
    }
  });
  it('a checkpoint that does not start right after the one its prev names is malformed, not evidence', () => {
    const c = V.linkChecks[0];
    const st = s();
    assert.strictEqual(st.recordCheckpoint(store(c.prev)).stored, true);
    assert.strictEqual(st.recordCheckpoint(store(c.checkpoint)).reason, 'malformed-link');
    assert.strictEqual(st.attesterEquivocated(c.prev.by), false);
  });
  it('a witness naming another range or root than the checkpoint held is refused, and never frames the attester', () => {
    const st = s();
    for (const x of V.checkpoints) st.recordCheckpoint(store(x.checkpoint));
    const w = core.fromWireWitness(V.witness.witness);
    assert.strictEqual(st.recordWitness(w).stored, true);
    const other = { ...w, by: '018f47a0-7b21-7abc-8def-a77e57000003', from_seq: 5, sig: w.sig.replace(/^./, (ch) => (ch === 'A' ? 'B' : 'A')) };
    assert.strictEqual(st.recordWitness(other).reason, 'disagrees');
    assert.strictEqual(st.attesterEquivocated(w.attester), false);
  });
});

describe('the node chains its own checkpoints and stops witnessing an equivocating attester', () => {
  const made = [];
  const mk = (b, o = {}) => { const n = new SymNode({ name: `${b}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`, silent: true, discovery: new NullDiscovery(), room: 'team-room', checkpointInterval: 0, ...o }); made.push(n); return n; };
  const stopAll = async () => { for (const n of made.splice(0)) { try { await n.stop(); } catch { /* */ } try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ } } };
  const CATS7 = { focus: 'admit', issue: 'admit', intent: 'admit', motivation: 'admit', commitment: 'admit', perspective: 'admit', mood: 'admit' };
  const hex = () => crypto.randomBytes(32).toString('hex');
  const attest = (n) => n._buildAdmissionAttestation(`cmb-${hex()}`, 'aligned', CATS7, 'heuristic', `asrt-${hex()}`);

  it('each checkpoint covers the segment since the last, chained to its root, and verifies as the vector\'s do', async () => {
    try {
      const A = mk('chain');
      for (let i = 0; i < 3; i++) attest(A);
      const c1 = A._emitCheckpoint();
      for (let i = 0; i < 2; i++) attest(A);
      const c2 = A._emitCheckpoint();
      assert.deepStrictEqual([c1.from_seq, c1.upto_seq, c1.prev], [1, 3, 'genesis']);
      assert.deepStrictEqual([c2.from_seq, c2.upto_seq, c2.prev], [4, 5, c1.root]);
      const seg = A._attestations.chainOf(A.nodeId).filter((a) => a.seq >= 4).map((a) => a.sig);
      assert.strictEqual(c2.root, core.attestCheckpointRoot({ prev: c1.root, fromSeq: 4, uptoSeq: 5, segmentRoot: core.attestMerkleRoot(seg) }));
      assert.strictEqual(core.verifyCheckpoint(c2, A._identity.publicKey).valid, true);
      assert.strictEqual(A._emitCheckpoint(), null, 'nothing new since the last');
      assert.strictEqual(A.reconcileChain(A.nodeId).consistent, true);
    } finally { await stopAll(); }
  });

  it('a lost segment ends the chain visibly: no root is signed over fewer', async () => {
    try {
      const A = mk('ended');
      const metrics = [];
      A.on('metric', (m) => { if (m.type === 'checkpoint-chain-ended') metrics.push(m); });
      for (let i = 0; i < 3; i++) attest(A);
      A._emitCheckpoint();
      for (let i = 0; i < 3; i++) attest(A);
      const full = A._attestations.chainOf(A.nodeId);
      A._attestations.chainOf = () => full.filter((a) => a.seq !== 5); // the store lost seq 5
      assert.strictEqual(A._emitCheckpoint(), null);
      assert.strictEqual(metrics.length, 1);
      A._attestations.chainOf = () => full;
      assert.strictEqual(A._emitCheckpoint(), null, 'and none is signed under that chain again');
    } finally { await stopAll(); }
  });

  it('a witness contradicting an attester-signed checkpoint held counts against the witness, which is muted; never against the attester', async () => {
    try {
      const A = mk('wmute');
      const X = { nodeId: V.testKeys.attester.nodeId, publicKey: KEY.attester };
      A._roster.bind(X.nodeId, X.publicKey, 'pinned');
      const Wi = identity('lying-witness');
      A._roster.bind(Wi.nodeId, Wi.publicKey, 'pinned');
      A._gossipToRoster = () => {};
      A._witnessCheckpoint = () => {};
      const s = admitAs(A, identity('relayer'));
      for (const x of V.checkpoints) assert.strictEqual(A._ingestCheckpoint(store(x.checkpoint), s.nodeId, s).ok, true);
      const held = V.checkpoints[2].checkpoint;
      const lie = core.signWitness({ attester: X.nodeId, roster: A._room, from_seq: held.fromSeq, upto_seq: held.uptoSeq, root: crypto.randomBytes(32).toString('hex'), by: Wi.nodeId, role: 'participant', at: 1 }, Wi.privateKey);
      assert.strictEqual(A._ingestWitness(lie, s.nodeId, s).reason, 'disagrees');
      assert.strictEqual(A._attestations.attesterEquivocated(X.nodeId), false, 'the attester signed nothing wrong');
      const honest = core.signWitness({ attester: X.nodeId, roster: A._room, from_seq: held.fromSeq, upto_seq: held.uptoSeq, root: held.root, by: Wi.nodeId, role: 'participant', at: 2 }, Wi.privateKey);
      assert.strictEqual(A._ingestWitness(honest, s.nodeId, s).reason, 'witness-muted', 'its next witness is dropped unverified');
    } finally { await stopAll(); }
  });

  it('a reversed range is refused at the schema step (§6 step 1), before anything else', () => {
    const c = V.linkChecks.find((x) => /reversed/.test(x.label));
    assert.strictEqual(core.fromWireCheckpoint(c.checkpoint), null);
  });

  it('after a conflict this node never witnesses the attester again, and drops its further checkpoints unverified', async () => {
    try {
      const A = mk('witness');
      const X = identity('x');
      X.nodeId = V.testKeys.attester.nodeId; X.publicKey = KEY.attester;
      A._roster.bind(X.nodeId, X.publicKey, 'pinned');
      const witnessed = [];
      A._gossipToRoster = (f) => { if (f.type === core.ATTEST_FRAME.witness) witnessed.push(f.witness); };
      const s = admitAs(A, identity('relayer'));
      const c = V.conflicts[1]; // overlapping ranges at different boundaries
      assert.strictEqual(A._ingestCheckpoint(store(V.checkpoints[0].checkpoint), s.nodeId, s).ok, true);
      assert.strictEqual(A._ingestCheckpoint(store(c.a), s.nodeId, s).ok, true);
      assert.strictEqual(witnessed.length, 2, 'both witnessed before the conflict');
      assert.strictEqual(A._ingestCheckpoint(store(c.b), s.nodeId, s).reason, 'conflict');
      const later = store(V.checkpoints[2].checkpoint);
      assert.strictEqual(A._ingestCheckpoint(later, s.nodeId, s).reason, 'attester-equivocated');
      assert.strictEqual(witnessed.length, 2, 'nothing witnessed since');
      assert.ok(witnessed.every((w) => Number.isInteger(w.fromSeq)), 'witnesses carry fromSeq');
    } finally { await stopAll(); }
  });
});
