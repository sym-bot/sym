'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * sym-attest-v1 as MMP 2.0 update 1 registers it (#27), and the founder's rulings for it: what this
 * node never attests or relays (S3), the wire grammar (closed attestation, lowercase UUID signers, a
 * role of up to 64 characters, a method of up to 32), equivocation relayed once as evidence, the
 * scope of an attester's role judged on the record its assertion names, and no checkpoint root over
 * a suffix (D1). Each test fails on 390b4af.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const crypto = require('crypto');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const { signAttestation, signCheckpoint, fromWireAttestation, toWireAttestation, ATTEST_FRAME } = require('../lib/core');
const { identity, connectNodes, until, signedRecord, signerOf, admitAs } = require('./_core-secure');

const uniq = (b) => `${b}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
const made = [];
function node(base, opts = {}) {
  const n = new SymNode({ name: uniq(base), silent: true, discovery: new NullDiscovery(), room: 'att', ...opts });
  made.push(n);
  return n;
}
async function stopAll() {
  for (const n of made.splice(0)) { try { await n.stop(); } catch { /* */ } try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ } }
}
const ALIGNED = { decision: 'aligned', total_drift: 0.1, category_drifts: { focus: 0.1 }, gate_values: { g: 1 } };
const CATS7 = { focus: 'admit', issue: 'admit', intent: 'admit', motivation: 'admit', commitment: 'admit', perspective: 'admit', mood: 'admit' };
const hex = () => crypto.randomBytes(32).toString('hex');

describe('S3: no attestation about a directed or a Legacy Import record leaves this node', () => {
  it('a directed record this node gates is attested by nobody: nothing signed, nothing gossiped; a broadcast is', async () => {
    try {
      const A = node('s3-a'); const B = node('s3-b');
      A._svafEvaluator.evaluate = async () => ALIGNED;
      await A.start(); await B.start();
      await connectNodes(B, A);
      const gossiped = [];
      const real = A._gossipToRoster.bind(A);
      A._gossipToRoster = (f, x) => { gossiped.push(f.type); return real(f, x); };
      const got = [];
      A.on('cmb-accepted', (e) => got.push(e));
      B.remember({ focus: 'for A only', issue: 'i', intent: 'n', motivation: 'm', commitment: 'c', perspective: 'p', mood: { text: 'calm' } }, { to: A.nodeId });
      B.remember({ focus: 'for the room', issue: 'i', intent: 'n', motivation: 'm', commitment: 'c', perspective: 'p', mood: { text: 'calm' } });
      await until(() => got.length >= 2, 5000);
      await new Promise((r) => setTimeout(r, 200));
      const atts = A._attestations.chainOf(A.nodeId);
      const directed = got.find((e) => e.cmb && e.cmb.metadata && e.cmb.metadata.to);
      const broadcast = got.find((e) => e.cmb && e.cmb.metadata && !e.cmb.metadata.to);
      assert.ok(directed && broadcast, 'both were delivered');
      assert.ok(!atts.some((x) => x.assertionId === directed.cmb.metadata.assertionId), 'no attestation about the directed record');
      assert.ok(atts.some((x) => x.assertionId === broadcast.cmb.metadata.assertionId), 'the broadcast is attested');
      assert.strictEqual(gossiped.filter((t) => t === ATTEST_FRAME.attestation).length, 1, 'one attestation went out: the broadcast\'s');
    } finally { await stopAll(); }
  });

  it('nothing is signed about a Legacy Import record', async () => {
    try {
      const A = node('s3-legacy');
      assert.strictEqual(A._buildAdmissionAttestation(`cmb-${hex()}`, 'aligned', CATS7, 'heuristic', `asrt-${hex()}`, { quarantined: true }), null);
      assert.strictEqual(A._attestations.chainOf(A.nodeId).length, 0);
    } finally { await stopAll(); }
  });

  it('a peer\'s attestation about a directed record this node holds is kept, never relayed', async () => {
    try {
      const A = node('s3-relay');
      const X = identity('x'); const M = identity('m');
      A._roster.bind(X.nodeId, X.publicKey, 'proven');
      const rec = signedRecord(M, { room: A._room, to: A.nodeId, categories: { focus: 'between M and A' } });
      A._store.receiveFromPeer(M.nodeId, { key: rec.metadata.key, content: 'x', source: 'm', cmb: rec, _cmbVerified: true });
      const att = signAttestation({ of: rec.metadata.key, assertionId: rec.metadata.assertionId, by: X.nodeId, at: Date.now(), roster: A._room, method: 'heuristic', verdict: 'aligned', categories: CATS7, role: 'participant', seq: 1, prev: 'genesis' }, X.privateKey);
      const gossiped = [];
      A._gossipToRoster = (f) => gossiped.push(f.type);
      const s = admitAs(A, identity('relayer'));
      const r = A._ingestAttestation(att, s.nodeId, 'relayer', s);
      assert.strictEqual(r.ok, true, 'kept as evidence');
      assert.deepStrictEqual(gossiped, [], 'not relayed');
    } finally { await stopAll(); }
  });
});

describe('the sym-attest-v1 wire grammar (#27)', () => {
  const X = identity('w');
  const base = () => toWireAttestation(signAttestation({ of: `cmb-${hex()}`, assertionId: `asrt-${hex()}`, by: X.nodeId, at: 1, roster: 'att', method: 'heuristic', verdict: 'aligned', categories: CATS7, role: 'participant', seq: 1, prev: 'genesis' }, X.privateKey));
  it('the attestation object is closed, with exactly seven verdicts', () => {
    assert.ok(fromWireAttestation(base()));
    assert.strictEqual(fromWireAttestation({ ...base(), note: 'x' }), null, 'a member the schema does not define');
    const b = base(); b.categories = { ...b.categories, extra: 'admit' };
    assert.strictEqual(fromWireAttestation(b), null);
  });
  it('the attester is a lowercase UUID', () => {
    assert.strictEqual(fromWireAttestation({ ...base(), by: 'node-x' }), null);
    assert.strictEqual(fromWireAttestation({ ...base(), by: X.nodeId.toUpperCase() }), null);
  });
  it('a role up to 64 characters (any role a grant confers), a method up to 32', () => {
    const r64 = `a${'b'.repeat(63)}`;
    assert.ok(fromWireAttestation({ ...base(), role: r64 }), 'a 64-character role');
    assert.strictEqual(fromWireAttestation({ ...base(), role: `${r64}c` }), null);
    assert.ok(fromWireAttestation({ ...base(), method: `m${'x'.repeat(31)}` }));
    assert.strictEqual(fromWireAttestation({ ...base(), method: `m${'x'.repeat(32)}` }), null);
  });
});

describe('equivocation, the attester\'s role and checkpoints (#27)', () => {
  it('a conflicting checkpoint is relayed once, as evidence', async () => {
    try {
      const A = node('eq');
      const X = identity('x');
      A._roster.bind(X.nodeId, X.publicKey, 'proven');
      const gossiped = [];
      A._gossipToRoster = (f) => gossiped.push(f.type);
      A._witnessCheckpoint = () => {};
      const s = admitAs(A, identity('relayer'));
      const cp = (root) => { const o = { type: 'checkpoint', by: X.nodeId, roster: A._room, upto_seq: 8, root, at: Date.now() }; signCheckpoint(o, X.privateKey); return o; };
      assert.strictEqual(A._ingestCheckpoint(cp(hex()), s.nodeId, s).ok, true);
      assert.strictEqual(gossiped.length, 1);
      const r = A._ingestCheckpoint(cp(hex()), s.nodeId, s);
      assert.strictEqual(r.reason, 'conflict');
      assert.strictEqual(gossiped.length, 2, 'the conflicting copy went out once');
      A._ingestCheckpoint(cp(hex()), s.nodeId, s);
      assert.strictEqual(gossiped.length, 2, 'a third root adds nothing');
    } finally { await stopAll(); }
  });

  it('an attester\'s scoped role is judged on the record its assertion names, not on another under the same key', async () => {
    try {
      const an = identity('anchor');
      const world = (p, cmb) => !!(cmb && cmb.metadata && cmb.metadata.room === p);
      const A = node('scope', { anchor: { threshold: 1, keys: [{ key: an.publicKey }] }, authorityScopes: { 'test-room': world } });
      const V = identity('v');
      const Auth = require('../lib/core/authority');
      const g = Auth.signStatement({ kind: 'grant', authorisedBy: 'anchor', subject: { nodeId: V.nodeId, key: V.publicKey }, role: 'validator', scope: 'test-room:att', nonce: Auth.freshNonce(), sigs: [] }, an.privateKey, an.publicKey);
      assert.strictEqual(A.submitAuthority(g).status, 'in-force');
      A._roster.bind(V.nodeId, V.publicKey, 'proven');
      const M = identity('m');
      const rec = signedRecord(M, { room: 'att', categories: { focus: 'in the att room' } });
      A._store.receiveFromPeer(M.nodeId, { key: rec.metadata.key, content: 'x', source: 'm', cmb: rec, _cmbVerified: true });
      const att = (assertionId) => ({ of: rec.metadata.key, assertionId, by: V.nodeId });
      assert.strictEqual(A._attesterRole(att(rec.metadata.assertionId)), 'validator', 'the record it names is inside the scope');
      assert.strictEqual(A._attesterRole(att(`asrt-${hex()}`)), 'participant', 'another assertion under the same key judges no scope');
    } finally { await stopAll(); }
  });

  it('no checkpoint root is signed over a suffix of this node\'s chain (D1)', async () => {
    try {
      const A = node('d1');
      for (let i = 0; i < 3; i++) A._buildAdmissionAttestation(`cmb-${hex()}`, 'aligned', CATS7, 'heuristic', `asrt-${hex()}`);
      const full = A._attestations.chainOf(A.nodeId);
      assert.strictEqual(full.length, 3);
      assert.ok(A._emitCheckpoint(), 'over the whole chain, a checkpoint');
      A._attestations.chainOf = () => full.slice(1); // the store evicted seq 1
      assert.strictEqual(A._emitCheckpoint(), null, 'over a suffix, none');
    } finally { await stopAll(); }
  });
});
