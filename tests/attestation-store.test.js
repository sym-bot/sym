'use strict';

/**
 * Phase D1 — the per-node Admission Attestation index: by gated-CMB (audit trail)
 * and by attester chain (omission-evidence), deduped by sig, bounded.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { AttestationStore, chainHash } = require('../lib/attestation-store');

/** A well-linked chain of `n` attestations from one attester (seq 1..n, prev links). */
function makeChain(by, n) {
  const atts = [];
  let prev = 'genesis';
  for (let s = 1; s <= n; s++) {
    const sig = `sig-${by}-${s}`;
    atts.push({ of: `cmb-${s}`, by, seq: s, prev, sig, verdict: 'aligned', categories: {} });
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
    st.recordCheckpoint({ by: 'A', upto_seq: 8, root: 'r8', sig: 'c8' }); // a witness is kept for a held checkpoint
    st.recordWitness({ attester: 'A', upto_seq: 8, root: 'r8', by: 'W1', sig: 'w1' });
    st.recordWitness({ attester: 'A', upto_seq: 8, root: 'r8', by: 'W2', sig: 'w2' });
    assert.deepStrictEqual(st.recordWitness({ attester: 'A', upto_seq: 8, root: 'r8', by: 'W1', sig: 'w1' }), { stored: false, reason: 'duplicate' });
    assert.strictEqual(st.witnessesFor('A', 8, 'r8').length, 2, 'two distinct witnesses');
    assert.strictEqual(st.witnessesFor('A', 8, 'r-other').length, 0, 'filtered by the committed root');
  });
});

describe('AttestationStore — durable persistence (append-only, reload on construct)', () => {
  function tmpdir() { return fs.mkdtempSync(path.join(os.tmpdir(), 'att-store-')); }

  it('reloads attestations, checkpoints, and witnesses from disk into a fresh store', () => {
    const dir = tmpdir();
    try {
      const s1 = new AttestationStore({ dir });
      s1.record({ of: 'cmb-1', by: 'A', seq: 1, prev: 'genesis', sig: 's1' });
      s1.record({ of: 'cmb-1', by: 'B', seq: 1, prev: 'genesis', sig: 's2' });
      s1.record({ of: 'cmb-2', by: 'A', seq: 2, prev: chainHash('s1'), sig: 's3' });
      s1.recordCheckpoint({ by: 'A', upto_seq: 2, root: 'r2', sig: 'cp' });
      s1.recordWitness({ attester: 'A', upto_seq: 2, root: 'r2', by: 'B', sig: 'wit' });

      const s2 = new AttestationStore({ dir }); // "restart" — reload from disk
      assert.strictEqual(s2.byCmb('cmb-1').length, 2, 'both cmb-1 attestations reloaded');
      assert.deepStrictEqual(s2.chainOf('A').map(a => a.seq), [1, 2], 'A chain reloaded in order');
      assert.deepStrictEqual(s2.verifyChain('A'), { ok: true, gaps: [], breaks: [] }, 'reloaded chain verifies');
      assert.strictEqual(s2.latestCheckpoint('A')?.upto_seq, 2, 'checkpoint reloaded');
      assert.strictEqual(s2.witnessesFor('A', 2, 'r2').length, 1, 'witness reloaded');
      assert.strictEqual(s2.size(), 3);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('reload does not re-append (append-only file is unchanged)', () => {
    const dir = tmpdir();
    try {
      const s1 = new AttestationStore({ dir });
      s1.record({ of: 'c', by: 'A', seq: 1, prev: 'genesis', sig: 's1' });
      const file = path.join(dir, 'attestations.jsonl');
      const before = fs.readFileSync(file, 'utf8');
      new AttestationStore({ dir }); // reload must not write
      assert.strictEqual(fs.readFileSync(file, 'utf8'), before, 'reload appended nothing');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('with no dir, nothing is persisted (pure in-memory)', () => {
    const st = new AttestationStore();
    assert.strictEqual(st.record({ of: 'c', by: 'A', seq: 1, prev: 'genesis', sig: 's1' }).stored, true);
    // no throw, no files — purely in-memory
    assert.strictEqual(st.size(), 1);
  });
});

// The witness storm (2026-10-01): a node that witnessed a checkpoint again after a restart signed a
// second copy of the same statement. The store kept only the latest copy per witness, so the two
// copies were new to each other forever, and every node stored and relayed each one again whenever
// the other arrived: 625,079 witness lines, 257 MB, re-read on every start.
describe('AttestationStore — one record per statement, bounded', () => {
  const w = (sig, extra = {}) => ({ attester: 'A', upto_seq: 8, root: 'r8', by: 'W1', sig, ...extra });

  it('a second copy of a held witness is a duplicate, and the first copy is not new again', () => {
    const st = new AttestationStore();
    st.recordCheckpoint({ by: 'A', upto_seq: 8, root: 'r8', sig: 'c8' });
    assert.strictEqual(st.recordWitness(w('copy-1')).stored, true);
    assert.strictEqual(st.recordWitness(w('copy-2', { at: 2 })).reason, 'duplicate');
    assert.strictEqual(st.recordWitness(w('copy-1')).reason, 'duplicate');
    assert.strictEqual(st.recordWitness(w('other-root', { root: 'r-other' })).reason, 'conflict');
    assert.strictEqual(st.witnessesFor('A', 8).length, 1);
    assert.strictEqual(st.hasWitnessed('A', 8, 'W1'), true);
  });

  it('a second copy of a held checkpoint is a duplicate; another root is a conflict, remembered once', () => {
    const st = new AttestationStore();
    assert.strictEqual(st.recordCheckpoint({ by: 'A', upto_seq: 8, root: 'r8', sig: 'c8' }).stored, true);
    assert.strictEqual(st.recordCheckpoint({ by: 'A', upto_seq: 8, root: 'r8', sig: 'c8-resigned' }).reason, 'duplicate');
    const c1 = st.recordCheckpoint({ by: 'A', upto_seq: 8, root: 'r-forked', sig: 'x1' });
    assert.deepStrictEqual([c1.reason, c1.keptRoot, c1.first], ['conflict', 'r8', true]);
    assert.strictEqual(st.recordCheckpoint({ by: 'A', upto_seq: 8, root: 'r-forked', sig: 'x2' }).first, false);
    assert.strictEqual(st.hasConflict('A', 8), true);
    assert.strictEqual(st.latestCheckpoint('A').root, 'r8', 'the first copy stays held');
  });

  it('a position is an integer: its text spelling is refused, so one signature cannot mint many positions', () => {
    const st = new AttestationStore();
    assert.strictEqual(st.recordCheckpoint({ by: 'A', upto_seq: '8', root: 'r', sig: 's' }).reason, 'malformed');
    assert.strictEqual(st.recordCheckpoint({ by: 'A', upto_seq: -1, root: 'r', sig: 's' }).reason, 'malformed');
    assert.strictEqual(st.recordWitness({ attester: 'A', upto_seq: '8', root: 'r', by: 'W', sig: 's' }).reason, 'malformed');
    assert.strictEqual(st.recordWitness({ attester: 'A', upto_seq: 8.5, root: 'r', by: 'W', sig: 's' }).reason, 'malformed');
  });

  it('checkpoints are bounded per attester (with their witnesses) and in attesters', () => {
    const st = new AttestationStore({ maxCheckpointsPerAttester: 3, maxAttesters: 2 });
    for (const n of [1, 2, 3]) { st.recordCheckpoint({ by: 'A', upto_seq: n, root: `r${n}`, sig: `c${n}` }); st.recordWitness({ attester: 'A', upto_seq: n, root: `r${n}`, by: 'W', sig: `w${n}` }); }
    st.recordCheckpoint({ by: 'A', upto_seq: 4, root: 'r4', sig: 'c4' });
    assert.deepStrictEqual(st.checkpointsOf('A').map((c) => c.upto_seq), [2, 3, 4]);
    assert.strictEqual(st.witnessesFor('A', 1).length, 0, 'the dropped position takes its witnesses');
    assert.strictEqual(st.recordCheckpoint({ by: 'A', upto_seq: 1, root: 'r1', sig: 'c1' }).reason, 'stale');
    st.recordCheckpoint({ by: 'B', upto_seq: 1, root: 'r', sig: 'b' });
    st.recordCheckpoint({ by: 'C', upto_seq: 1, root: 'r', sig: 'c' });
    assert.strictEqual(st.latestCheckpoint('A'), null, 'the attester updated least recently gave up its place');
    assert.strictEqual(st.witnessesFor('A', 2).length + st.witnessesFor('A', 3).length, 0);
  });

  it('a witness waits for its checkpoint, in memory only, then is kept; one for nothing never reaches the log', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'att-pending-'));
    try {
      const st = new AttestationStore({ dir, maxPending: 3 });
      assert.strictEqual(st.recordWitness({ attester: 'A', upto_seq: 8, root: 'r8', by: 'W', sig: 'w' }).reason, 'pending');
      for (let i = 0; i < 100; i++) st.recordWitness({ attester: `fake-${i}`, upto_seq: i, root: 'r', by: 'flooder', sig: `f${i}` });
      assert.ok(!fs.existsSync(path.join(dir, 'witnesses.jsonl')), 'nothing for an uncommitted position is written');
      assert.strictEqual(st._pending.size, 3, 'and the waiting set is bounded');
      const st2 = new AttestationStore({ dir, maxPending: 3 });
      st2.recordWitness({ attester: 'A', upto_seq: 8, root: 'r8', by: 'W', sig: 'w' });
      st2.recordCheckpoint({ by: 'A', upto_seq: 8, root: 'r8', sig: 'c8' });
      assert.strictEqual(st2.witnessesFor('A', 8).length, 1, 'the waiting witness is kept once its checkpoint arrives');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('witnesses are bounded per position, and in all by dropping the oldest positions first', () => {
    const st = new AttestationStore({ maxWitnessesPerPosition: 3, maxWitnesses: 10 });
    st.recordCheckpoint({ by: 'A', upto_seq: 1, root: 'r', sig: 'c1' });
    for (let i = 0; i < 5; i++) st.recordWitness({ attester: 'A', upto_seq: 1, root: 'r', by: `W${i}`, sig: `w${i}` });
    assert.strictEqual(st.witnessesFor('A', 1).length, 3, 'a position holds at most its cap');
    for (let n = 2; n <= 5; n++) {
      st.recordCheckpoint({ by: 'A', upto_seq: n, root: 'r', sig: `c${n}` });
      for (let i = 0; i < 3; i++) st.recordWitness({ attester: 'A', upto_seq: n, root: 'r', by: `W${i}`, sig: `w${n}-${i}` });
    }
    assert.strictEqual(st.witnessesFor('A', 1).length, 0, 'the oldest position went first');
    assert.strictEqual(st.witnessesFor('A', 5).length, 3, 'the newest keeps all of its witnesses');
    assert.ok(st._witnessCount <= 10);
  });

  it('ids with any characters index cleanly (no delimited keys)', () => {
    const st = new AttestationStore({ maxWitnessesPerPosition: 2 });
    st.recordCheckpoint({ by: 'a|b', upto_seq: 1, root: 'r', sig: 'c' });
    for (let i = 0; i < 6; i++) st.recordWitness({ attester: 'a|b', upto_seq: 1, root: 'r', by: `w|${i}`, sig: `s${i}` });
    assert.strictEqual(st.witnessesFor('a|b', 1).length, 2);
    assert.strictEqual(st._witnessCount, 2);
  });

  it('a node remembers the checkpoints it witnessed itself, even after its index drops the witness', () => {
    const st = new AttestationStore({ selfId: 'me', maxWitnesses: 1 });
    st.recordCheckpoint({ by: 'A', upto_seq: 1, root: 'r', sig: 'c1' });
    st.recordWitness({ attester: 'A', upto_seq: 1, root: 'r', by: 'me', sig: 'mine' });
    st.recordCheckpoint({ by: 'A', upto_seq: 2, root: 'r2', sig: 'c2' });
    st.recordWitness({ attester: 'A', upto_seq: 2, root: 'r2', by: 'other', sig: 'theirs' });
    assert.strictEqual(st.witnessAt('A', 1, 'me'), null, 'dropped from the index under the cap');
    assert.strictEqual(st.hasWitnessed('A', 1, 'me'), true, 'still known as witnessed by this node');
  });

  it('a conflict is re-derived after a restart', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'att-conflict-'));
    try {
      const st = new AttestationStore({ dir });
      st.recordCheckpoint({ by: 'A', upto_seq: 8, root: 'r8', sig: 'c8' });
      st.recordCheckpoint({ by: 'A', upto_seq: 8, root: 'r-forked', sig: 'x' });
      st.recordCheckpoint({ by: 'A', upto_seq: 8, root: 'r-forked', sig: 'x2' });
      const lines = fs.readFileSync(path.join(dir, 'checkpoints.jsonl'), 'utf8').trim().split('\n').length;
      assert.strictEqual(lines, 2, 'the conflicting copy is appended once');
      const again = new AttestationStore({ dir });
      assert.strictEqual(again.hasConflict('A', 8), true);
      assert.strictEqual(again.latestCheckpoint('A').root, 'r8', 'and the first copy stays the one held');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('an oversized log is read from its newest part only, and is never rewritten', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'att-legacy-'));
    try {
      const lines = [];
      for (let i = 0; i < 2000; i++) lines.push(JSON.stringify({ by: 'A', upto_seq: i, root: `r${i}`, sig: `c${i}` }));
      const text = lines.join('\n') + '\n';
      fs.writeFileSync(path.join(dir, 'checkpoints.jsonl'), text);
      const st = new AttestationStore({ dir, maxReadBytes: 8192, maxCheckpointsPerAttester: 5000 });
      assert.ok(st.checkpointAt('A', 1999), 'the newest records are read');
      assert.strictEqual(st.checkpointAt('A', 0), null, 'the head of the oversized log is not');
      assert.strictEqual(fs.readFileSync(path.join(dir, 'checkpoints.jsonl'), 'utf8'), text, 'the log is unchanged');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
});

describe('AttestationStore — start-up reads cover what the caps hold (0.13.15 review F1)', () => {
  it('a log of 50,000 attestations is read whole, so this node\'s chain survives a restart', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'att-50k-'));
    try {
      const pad = 'x'.repeat(400);
      const lines = [];
      let prev = 'genesis';
      for (let seq = 1; seq <= 50000; seq++) { const sig = `s${seq}`; lines.push(JSON.stringify({ of: `c${seq}`, by: 'me', seq, prev, sig, note: pad })); prev = chainHash(sig); }
      fs.writeFileSync(path.join(dir, 'attestations.jsonl'), lines.join('\n') + '\n');
      const st = new AttestationStore({ dir });
      assert.strictEqual(st.chainOf('me').length, 50000, 'the whole chain is reloaded');
      assert.deepStrictEqual(st.verifyChain('me'), { ok: true, gaps: [], breaks: [] });
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
});

// 0.13.16: the 0.13.15 hotfix review's last round (F1-F5).
describe('AttestationStore — 0.13.15 review follow-ups', () => {
  it('the checkpoint read budget covers what its caps hold (F1)', () => {
    const st = new AttestationStore({ maxCheckpointsPerAttester: 32, maxAttesters: 1024 });
    assert.ok(st._readBudget['checkpoints.jsonl'] >= 32 * 1024 * 400, String(st._readBudget['checkpoints.jsonl']));
  });

  it('a waiting witness that signs a second root is a conflict, surfaced once (F2)', () => {
    const st = new AttestationStore();
    st.recordWitness({ attester: 'A', upto_seq: 8, root: 'r8', by: 'W', sig: 'w1' });
    const c = st.recordWitness({ attester: 'A', upto_seq: 8, root: 'other', by: 'W', sig: 'w2' });
    assert.deepStrictEqual([c.reason, c.keptRoot, c.first], ['conflict', 'r8', true]);
    assert.strictEqual(st.recordWitness({ attester: 'A', upto_seq: 8, root: 'other', by: 'W', sig: 'w3' }).first, false);
  });

  it('this node remembers its own witness even while it waits for its checkpoint (F3)', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'att-own-'));
    try {
      const st = new AttestationStore({ selfId: 'me', maxPending: 1 });
      st.recordWitness({ attester: 'A', upto_seq: 8, root: 'r8', by: 'me', sig: 'mine' });
      st.recordWitness({ attester: 'B', upto_seq: 1, root: 'r', by: 'other', sig: 'x' }); // pushes mine out of the waiting set
      assert.strictEqual(st.hasWitnessed('A', 8, 'me'), true);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('a conflict on a held position is not forgotten while the position can be held (F4)', () => {
    const st = new AttestationStore({ maxCheckpointsPerAttester: 1, maxAttesters: 1200 });
    for (let a = 0; a < 1100; a++) {
      st.recordCheckpoint({ by: `A${a}`, upto_seq: 1, root: 'r', sig: `c${a}` });
      st.recordCheckpoint({ by: `A${a}`, upto_seq: 1, root: 'other', sig: `x${a}` });
    }
    assert.strictEqual(st.hasConflict('A0', 1), true, 'the first conflict is still known after 1,100 more');
    assert.strictEqual(st.recordCheckpoint({ by: 'A0', upto_seq: 1, root: 'other', sig: 'again' }).first, false);
  });

  it('a waiting witness read from the log is not appended again when its checkpoint arrives (F5)', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'att-promote-'));
    try {
      const line = JSON.stringify({ attester: 'A', upto_seq: 8, root: 'r8', by: 'W', sig: 'w' }) + '\n';
      fs.writeFileSync(path.join(dir, 'witnesses.jsonl'), line);
      const st = new AttestationStore({ dir });
      st.recordCheckpoint({ by: 'A', upto_seq: 8, root: 'r8', sig: 'c8' });
      assert.strictEqual(st.witnessesFor('A', 8).length, 1, 'promoted');
      assert.strictEqual(fs.readFileSync(path.join(dir, 'witnesses.jsonl'), 'utf8'), line, 'and not written twice');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
});

// 0.14.0 review follow-up: a position was unlisted with findIndex over every witnessed position (up
// to 32,768), once per position dropped.
describe('AttestationStore — position eviction is O(1)', () => {
  it('a dropped checkpoint unlists its position by key, and the global cap takes the oldest from the head, never scanning', () => {
    const st = new AttestationStore({ maxCheckpointsPerAttester: 2, maxAttesters: 2000, maxWitnessesPerPosition: 1, maxWitnesses: 100000 });
    for (let a = 0; a < 1000; a++) {
      for (const n of [1, 2]) {
        st.recordCheckpoint({ by: `A${a}`, upto_seq: n, root: 'r', sig: `c${a}-${n}` });
        st.recordWitness({ attester: `A${a}`, upto_seq: n, root: 'r', by: 'W', sig: `w${a}-${n}` });
      }
    }
    let iterations = 0;   // iterator steps taken over the position index
    const counted = (it) => ({ next() { iterations++; return it.next(); }, [Symbol.iterator]() { return this; } });
    class Counted extends Map {
      entries() { return counted(super.entries()); }
      keys() { return counted(super.keys()); }
      values() { return counted(super.values()); }
      forEach(fn, self) { for (const [k, v] of this) fn.call(self, v, k, this); }
      [Symbol.iterator]() { return counted(super.entries()); }
    }
    st._positions = new Counted(st._positions);
    iterations = 0;
    // 500 attesters commit a third checkpoint: each drops its oldest position, with its witness.
    for (let a = 0; a < 500; a++) st.recordCheckpoint({ by: `A${a}`, upto_seq: 3, root: 'r', sig: `c${a}-3` });
    assert.strictEqual(iterations, 0, 'unlisting a dropped position looks at nothing else');
    assert.strictEqual(st._positions.size, 1500);
    assert.strictEqual(st.witnessesFor('A0', 1).length, 0);
    // The global cap: 100 more positions than it allows, each drop one look at the head.
    st._maxWitnesses = st._witnessCount;
    for (let a = 500; a < 600; a++) {
      st.recordCheckpoint({ by: `A${a}`, upto_seq: 3, root: 'r', sig: `c${a}-3x` });   // drops A${a}'s position 1
      st.recordWitness({ attester: `A${a}`, upto_seq: 3, root: 'r', by: 'W', sig: `w${a}-3` });
    }
    st._maxWitnesses -= 100;
    iterations = 0;
    st.recordCheckpoint({ by: 'B', upto_seq: 1, root: 'r', sig: 'b1' });
    st.recordWitness({ attester: 'B', upto_seq: 1, root: 'r', by: 'W', sig: 'wb1' });
    assert.strictEqual(iterations, 101, 'one step at the head per position the cap drops');
    assert.strictEqual(st._witnessCount, st._maxWitnesses);
    assert.strictEqual(st.witnessesFor('A0', 2).length + st.witnessesFor('A100', 2).length, 0, 'the oldest positions went first');
    assert.strictEqual(st.witnessesFor('A101', 2).length, 1, 'and no more');
    assert.strictEqual(st.witnessesFor('B', 1).length, 1, 'the newest stayed');
  });
});

// 0.14.0 review follow-up: the 50,000 cap was one FIFO across attesters, so one attester signing many
// attestations flushed every other attester's chain (and with it the omission evidence).
describe('AttestationStore — the cap is shared out by attester', () => {
  it("one attester signing far beyond its share leaves every other attester's chain intact", () => {
    const st = new AttestationStore({ max: 1000, maxAttesters: 16 });
    const honest = Array.from({ length: 10 }, (_, k) => `H${k}`);
    for (let s = 0; s < 50; s++) for (const by of honest) st.record(makeChain(by, 50)[s]);
    for (const a of makeChain('F', 100000)) st.record(a);
    for (const by of honest) {
      assert.strictEqual(st.chainOf(by).length, 50, `${by} keeps its whole chain`);
      assert.deepStrictEqual(st.verifyChain(by), { ok: true, gaps: [], breaks: [] });
    }
    assert.strictEqual(st.size(), 1000, 'the global bound holds');
    assert.strictEqual(st.chainOf('F').length, 500, 'the flooder keeps what is left, its newest');
    assert.strictEqual(st.chainOf('F')[0].seq, 99501);
    assert.deepStrictEqual(st.verifyChain('F'), { ok: true, gaps: [], breaks: [] });
  });

  it('when full, attesters over their share lose their oldest until each holds its share', () => {
    const st = new AttestationStore({ max: 1000, maxAttesters: 16 });
    const chains = ['A', 'B', 'C', 'D'].map((by) => makeChain(by, 1000));
    for (let s = 0; s < 1000; s++) for (const c of chains) st.record(c[s]);
    for (const by of ['A', 'B', 'C', 'D']) {
      assert.strictEqual(st.chainOf(by).length, 250, `${by} holds max / 4`);
      assert.strictEqual(st.chainOf(by)[0].seq, 751, 'its newest');
    }
    // A fifth attester takes its share from the others, not from itself.
    for (const a of makeChain('E', 300)) st.record(a);
    for (const by of ['A', 'B', 'C', 'D', 'E']) assert.strictEqual(st.chainOf(by).length, 200, `${by} holds max / 5`);
  });

  it("holds at most maxAttesters chains, dropping the one updated least recently, never this node's own", () => {
    const st = new AttestationStore({ max: 1000, maxAttesters: 4, selfId: 'me' });
    st.record(makeChain('me', 1)[0]);
    for (const by of ['A', 'B', 'C']) st.record(makeChain(by, 1)[0]);
    st.record(makeChain('D', 1)[0]);   // 'me' is least recently updated, so A goes
    assert.deepStrictEqual(['me', 'A', 'B', 'C', 'D'].map((by) => st.chainOf(by).length), [1, 0, 1, 1, 1]);
    st.record(makeChain('E', 1)[0]);   // then B
    assert.deepStrictEqual(['me', 'B', 'E'].map((by) => st.chainOf(by).length), [1, 0, 1]);
    assert.strictEqual(st.size(), 4);
  });

  it('two attestations at one position: dropping the older leaves the newer in the chain', () => {
    const st = new AttestationStore({ max: 2 });
    st.record({ of: 'c1', by: 'A', seq: 1, prev: 'genesis', sig: 'old' });
    st.record({ of: 'c2', by: 'A', seq: 1, prev: 'genesis', sig: 'restarted' });
    st.record({ of: 'c3', by: 'A', seq: 2, prev: chainHash('restarted'), sig: 's2' });   // drops 'old'
    assert.deepStrictEqual(st.chainOf('A').map((a) => a.sig), ['restarted', 's2']);
  });
});
