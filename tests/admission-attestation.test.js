'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * Phase C — the node builds + signs an Admission Attestation when it gates a CMB,
 * and the store persists it on the remix.
 *
 * Deterministic (no encoder / no SVAF run): exercises node._buildAdmissionAttestation
 * directly and the memory-store preservation of cmb.admission. The full receive-path
 * wiring (frame-handler attaches it on admit) is covered by the integration test
 * tests/integration/e2e-admission.js.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const { verifyAttestation, verifyAttestationRole } = require('@sym-bot/core');

// Construct (no start) — the builder needs only identity / group / role / chain state.
function withNode(baseName, opts, fn) {
  const name = `${baseName}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), ...opts });
  try { return fn(node); } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
}

const verdicts = { focus: 'admit', issue: 'reject', intent: 'guard', motivation: 'admit', commitment: 'silent', perspective: 'redundant', mood: 'admit' };

describe('node._buildAdmissionAttestation', () => {
  it('builds a signed attestation bound to the gated CMB, verifiable by this node', () => {
    withNode('att-sign', { lifecycleRole: 'validator', group: 'sym-bot-team' }, (node) => {
      const att = node._buildAdmissionAttestation('cmb-gated-1', 'guarded', verdicts, 'heuristic');
      assert.ok(att, 'returns an attestation');
      assert.strictEqual(att.of, 'cmb-gated-1');
      assert.strictEqual(att.by, node.nodeId);
      assert.strictEqual(att.roster, 'sym-bot-team');
      assert.strictEqual(att.role, 'validator');
      assert.strictEqual(att.method, 'heuristic');
      assert.strictEqual(att.verdict, 'guarded');
      assert.deepStrictEqual(att.fields, verdicts);
      assert.deepStrictEqual(verifyAttestation(att, node._identity.publicKey), { signed: true, valid: true });
    });
  });

  it('advances the per-attester hash-chain (seq monotonic, prev = hash of previous sig)', () => {
    withNode('att-chain', { lifecycleRole: 'participant', group: 'g' }, (node) => {
      const a1 = node._buildAdmissionAttestation('cmb-1', 'aligned', verdicts, 'heuristic');
      const a2 = node._buildAdmissionAttestation('cmb-2', 'aligned', verdicts, 'heuristic');
      assert.strictEqual(a1.seq, 1);
      assert.strictEqual(a1.prev, 'genesis');
      assert.strictEqual(a2.seq, 2);
      assert.strictEqual(a2.prev, crypto.createHash('sha256').update(a1.sig).digest('hex'), 'a2.prev links a1');
      assert.notStrictEqual(a1.sig, a2.sig);
    });
  });

  it('stamps the claimed role; verifyAttestationRole weights by the RESOLVED role, not the stamp', () => {
    withNode('att-role', { lifecycleRole: 'anchor', group: 'g' }, (node) => {
      const att = node._buildAdmissionAttestation('cmb-x', 'aligned', verdicts, 'heuristic');
      assert.strictEqual(att.role, 'anchor', 'node stamps its configured role');
      const r = verifyAttestationRole(att, () => 'participant'); // chain disagrees with the stamp
      assert.strictEqual(r.matches, false);
      assert.strictEqual(r.rank, 0, 'a self-stamped anchor weighs as the resolved participant');
    });
  });
});

describe('memory-store persists cmb.admission on the remix', () => {
  it('preserves a signed admission attestation through receiveFromPeer', () => {
    withNode('att-store', { lifecycleRole: 'participant', group: 'g' }, (node) => {
      const att = node._buildAdmissionAttestation('cmb-of', 'aligned', verdicts, 'heuristic');
      const entry = {
        source: `${node.name}+peer`, content: 'x',
        cmb: { key: 'remix-1', fields: { focus: { text: 'f' } }, admission: att },
        storedAt: Date.now(),
      };
      const stored = node._store.receiveFromPeer('peer-id', entry);
      assert.ok(stored && stored.cmb && stored.cmb.admission, 'admission preserved on the stored remix');
      assert.strictEqual(stored.cmb.admission.of, 'cmb-of');
      assert.deepStrictEqual(verifyAttestation(stored.cmb.admission, node._identity.publicKey), { signed: true, valid: true });
    });
  });
});

describe('node indexes its own attestations (every gating event)', () => {
  it('records each built attestation; chain verifies; CMB trail is queryable', () => {
    withNode('att-index', { lifecycleRole: 'participant', group: 'g' }, (node) => {
      const a1 = node._buildAdmissionAttestation('cmb-1', 'aligned', verdicts, 'heuristic');
      const a2 = node._buildAdmissionAttestation('cmb-2', 'rejected', verdicts, 'neural'); // reject is attested too
      const a3 = node._buildAdmissionAttestation('cmb-1', 'guarded', verdicts, 'heuristic'); // re-gate cmb-1
      assert.strictEqual(node.attestationsFor('cmb-1').length, 2, 'both gatings of cmb-1 are in its trail');
      assert.strictEqual(node.attestationsFor('cmb-2').length, 1);
      assert.deepStrictEqual([a1.seq, a2.seq, a3.seq], [1, 2, 3], 'one contiguous chain across admit + reject');
      assert.deepStrictEqual(node.verifyAttestationChain(), { ok: true, gaps: [], breaks: [] });
    });
  });
});

describe('node checkpoints its chain; reconciliation catches omission (D3)', () => {
  it('commits a checkpoint at the interval; reconcile is consistent, then detects a dropped attestation', () => {
    withNode('att-cp', { lifecycleRole: 'participant', group: 'g', checkpointInterval: 4 }, (node) => {
      for (let i = 1; i <= 4; i++) node._buildAdmissionAttestation(`cmb-${i}`, 'aligned', verdicts, 'heuristic');
      const cp = node._attestations.latestCheckpoint(node.nodeId);
      assert.ok(cp, 'a checkpoint was committed at the interval');
      assert.strictEqual(cp.upto_seq, 4);

      let r = node.reconcileChain(node.nodeId);
      assert.strictEqual(r.consistent, true, 'committed root matches the held chain');
      assert.strictEqual(r.complete, true);
      assert.deepStrictEqual(r.gaps, []);

      // Suppress seq 2 from the held chain — the omission test must catch it.
      node._attestations._byAttester.get(node.nodeId).delete(2);
      r = node.reconcileChain(node.nodeId);
      assert.strictEqual(r.complete, false);
      assert.deepStrictEqual(r.gaps, [2], 'the dropped seq is a detectable gap');
      assert.strictEqual(r.consistent, false, 'recomputed root no longer matches the witnessed-committed root');
    });
  });
});
