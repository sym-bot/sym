'use strict';

/**
 * Phase D1 — the per-node Admission Attestation index: by gated-CMB (audit trail)
 * and by attester chain (omission-evidence), deduped by sig, bounded.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { AttestationStore, chainHash } = require('../lib/attestation-store');

/** A well-linked chain of `n` attestations from one attester (seq 1..n, prev links). */
function makeChain(by, n) {
  const atts = [];
  let prev = 'genesis';
  for (let s = 1; s <= n; s++) {
    const sig = `sig-${by}-${s}`;
    atts.push({ of: `cmb-${s}`, by, seq: s, prev, sig, verdict: 'aligned', fields: {} });
    prev = chainHash(sig);
  }
  return atts;
}

describe('AttestationStore — index by CMB + by attester chain', () => {
  it('indexes attestations by gated CMB (the audit trail)', () => {
    const st = new AttestationStore();
    st.record({ of: 'cmb-x', by: 'A', seq: 1, prev: 'genesis', sig: 'sa' });
    st.record({ of: 'cmb-x', by: 'B', seq: 1, prev: 'genesis', sig: 'sb' });
    st.record({ of: 'cmb-y', by: 'A', seq: 2, prev: chainHash('sa'), sig: 'sa2' });
    const trail = st.byCmb('cmb-x');
    assert.strictEqual(trail.length, 2, 'both receivers\' verdicts about cmb-x');
    assert.deepStrictEqual(new Set(trail.map(a => a.by)), new Set(['A', 'B']));
    assert.strictEqual(st.byCmb('cmb-y').length, 1);
    assert.strictEqual(st.byCmb('cmb-none').length, 0);
  });

  it('dedups by signature (idempotent record / relay-once)', () => {
    const st = new AttestationStore();
    assert.strictEqual(st.record({ of: 'c', by: 'A', seq: 1, prev: 'genesis', sig: 's1' }).stored, true);
    const again = st.record({ of: 'c', by: 'A', seq: 1, prev: 'genesis', sig: 's1' });
    assert.deepStrictEqual(again, { stored: false, reason: 'duplicate' });
    assert.strictEqual(st.size(), 1);
    assert.ok(st.has('s1'));
  });

  it('rejects malformed attestations', () => {
    const st = new AttestationStore();
    for (const bad of [null, {}, { of: 'c', by: 'A', sig: 's' /* no seq */ }, { of: 'c', seq: 1, sig: 's' /* no by */ }]) {
      assert.strictEqual(st.record(bad).stored, false);
    }
    assert.strictEqual(st.size(), 0);
  });

  it('chainOf returns an attester\'s chain ordered by seq', () => {
    const st = new AttestationStore();
    const chain = makeChain('A', 3);
    // record out of order
    st.record(chain[2]); st.record(chain[0]); st.record(chain[1]);
    assert.deepStrictEqual(st.chainOf('A').map(a => a.seq), [1, 2, 3]);
  });

  it('verifyChain: a contiguous, well-linked chain is ok', () => {
    const st = new AttestationStore();
    for (const a of makeChain('A', 4)) st.record(a);
    assert.deepStrictEqual(st.verifyChain('A'), { ok: true, gaps: [], breaks: [] });
    assert.deepStrictEqual(st.verifyChain('nobody'), { ok: true, gaps: [], breaks: [] });
  });

  it('verifyChain: a dropped attestation shows as a seq gap (omission)', () => {
    const st = new AttestationStore();
    const chain = makeChain('A', 4);
    st.record(chain[0]); st.record(chain[1]); /* skip seq 3 */ st.record(chain[3]);
    const r = st.verifyChain('A');
    assert.strictEqual(r.ok, false);
    assert.deepStrictEqual(r.gaps, [3]);
  });

  it('verifyChain: a re-linked chain shows as a prev break (tamper)', () => {
    const st = new AttestationStore();
    const chain = makeChain('A', 3);
    chain[2].prev = 'forged-prev'; // seq 3 no longer links seq 2
    for (const a of chain) st.record(a);
    const r = st.verifyChain('A');
    assert.strictEqual(r.ok, false);
    assert.deepStrictEqual(r.breaks, [3]);
  });

  it('rate-limits INGESTED attestations per (of,by); own gating output is never limited', () => {
    const st = new AttestationStore({ ratePerWindow: 2, rateWindowMs: 1000 });
    const now = 10000;
    assert.strictEqual(st.record({ of: 'c', by: 'A', seq: 1, prev: 'genesis', sig: 'i1' }, { ingested: true, now }).stored, true);
    assert.strictEqual(st.record({ of: 'c', by: 'A', seq: 2, prev: 'x', sig: 'i2' }, { ingested: true, now }).stored, true);
    assert.deepStrictEqual(st.record({ of: 'c', by: 'A', seq: 3, prev: 'y', sig: 'i3' }, { ingested: true, now }), { stored: false, reason: 'rate-limited' });
    // a different (of,by) is independent
    assert.strictEqual(st.record({ of: 'c2', by: 'A', seq: 1, prev: 'genesis', sig: 'i4' }, { ingested: true, now }).stored, true);
    // own (non-ingested) output is never rate-limited
    assert.strictEqual(st.record({ of: 'c', by: 'A', seq: 9, prev: 'z', sig: 'own1' }, { ingested: false, now }).stored, true);
    // window slides: after it elapses, ingest is allowed again
    assert.strictEqual(st.record({ of: 'c', by: 'A', seq: 4, prev: 'w', sig: 'i5' }, { ingested: true, now: now + 1001 }).stored, true);
  });

  it('bounds memory by evicting the oldest', () => {
    const st = new AttestationStore({ max: 2 });
    st.record({ of: 'c1', by: 'A', seq: 1, prev: 'genesis', sig: 's1' });
    st.record({ of: 'c2', by: 'A', seq: 2, prev: chainHash('s1'), sig: 's2' });
    st.record({ of: 'c3', by: 'A', seq: 3, prev: chainHash('s2'), sig: 's3' });
    assert.strictEqual(st.size(), 2, 'capped at max');
    assert.strictEqual(st.has('s1'), false, 'oldest evicted');
    assert.strictEqual(st.byCmb('c1').length, 0, 'evicted from the CMB index too');
    assert.ok(st.has('s3'));
  });
});

describe('AttestationStore — checkpoints + witnesses', () => {
  it('records + dedups checkpoints, ordered by upto_seq', () => {
    const st = new AttestationStore();
    assert.strictEqual(st.recordCheckpoint({ by: 'A', upto_seq: 8, root: 'r8', sig: 'c8' }).stored, true);
    assert.strictEqual(st.recordCheckpoint({ by: 'A', upto_seq: 16, root: 'r16', sig: 'c16' }).stored, true);
    assert.deepStrictEqual(st.recordCheckpoint({ by: 'A', upto_seq: 8, root: 'r8', sig: 'c8' }), { stored: false, reason: 'duplicate' });
    assert.deepStrictEqual(st.checkpointsOf('A').map(c => c.upto_seq), [8, 16]);
    assert.strictEqual(st.latestCheckpoint('A').upto_seq, 16);
    assert.strictEqual(st.latestCheckpoint('nobody'), null);
  });

  it('records witnesses keyed by (attester, upto_seq, witness) and filters by root', () => {
    const st = new AttestationStore();
    st.recordWitness({ attester: 'A', upto_seq: 8, root: 'r8', by: 'W1', sig: 'w1' });
    st.recordWitness({ attester: 'A', upto_seq: 8, root: 'r8', by: 'W2', sig: 'w2' });
    assert.deepStrictEqual(st.recordWitness({ attester: 'A', upto_seq: 8, root: 'r8', by: 'W1', sig: 'w1' }), { stored: false, reason: 'duplicate' });
    assert.strictEqual(st.witnessesFor('A', 8, 'r8').length, 2, 'two distinct witnesses');
    assert.strictEqual(st.witnessesFor('A', 8, 'r-other').length, 0, 'filtered by the committed root');
  });
});
