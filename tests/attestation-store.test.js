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
describe('AttestationStore — one record per statement, bounded, archived', () => {
  const w = (sig, extra = {}) => ({ attester: 'A', upto_seq: 8, root: 'r8', by: 'W1', sig, ...extra });

  it('a second copy of a held witness is a duplicate, never stored or relayed again', () => {
    const st = new AttestationStore();
    assert.strictEqual(st.recordWitness(w('copy-1')).stored, true);
    assert.deepStrictEqual(st.recordWitness(w('copy-2', { at: 2 })), { stored: false, reason: 'duplicate' });
    assert.deepStrictEqual(st.recordWitness(w('copy-1')), { stored: false, reason: 'duplicate' }, 'and the first copy is not new again');
    assert.strictEqual(st.recordWitness(w('other-root', { root: 'r-other' })).reason, 'conflict');
    assert.strictEqual(st.witnessesFor('A', 8).length, 1);
    assert.strictEqual(st.hasWitnessed('A', 8, 'W1'), true);
  });

  it('a second copy of a held checkpoint is a duplicate; another root for the same position is a conflict', () => {
    const st = new AttestationStore();
    assert.strictEqual(st.recordCheckpoint({ by: 'A', upto_seq: 8, root: 'r8', sig: 'c8' }).stored, true);
    assert.deepStrictEqual(st.recordCheckpoint({ by: 'A', upto_seq: 8, root: 'r8', sig: 'c8-resigned' }), { stored: false, reason: 'duplicate' });
    const c = st.recordCheckpoint({ by: 'A', upto_seq: 8, root: 'r-forked', sig: 'c8x' });
    assert.strictEqual(c.reason, 'conflict');
    assert.strictEqual(c.kept.root, 'r8', 'the first copy stays the one held');
    assert.deepStrictEqual(st.conflictsOf('A').map((x) => [x.upto_seq, x.kept.root, x.conflicting.root]), [[8, 'r8', 'r-forked']], 'and the other is kept as evidence');
    assert.strictEqual(st.hasConflict('A', 8), true);
  });

  it('checkpoints are bounded per attester, and a dropped checkpoint takes its witnesses with it', () => {
    const st = new AttestationStore({ maxCheckpointsPerAttester: 3 });
    for (const n of [1, 2, 3]) { st.recordCheckpoint({ by: 'A', upto_seq: n, root: `r${n}`, sig: `c${n}` }); st.recordWitness({ attester: 'A', upto_seq: n, root: `r${n}`, by: 'W', sig: `w${n}` }); }
    st.recordCheckpoint({ by: 'A', upto_seq: 4, root: 'r4', sig: 'c4' });
    assert.deepStrictEqual(st.checkpointsOf('A').map((c) => c.upto_seq), [2, 3, 4]);
    assert.strictEqual(st.witnessesFor('A', 1).length, 0);
    assert.deepStrictEqual(st.recordCheckpoint({ by: 'A', upto_seq: 1, root: 'r1', sig: 'c1' }), { stored: false, reason: 'stale' });
  });

  it('witnesses are bounded in total, oldest first', () => {
    const st = new AttestationStore({ maxWitnesses: 100 });
    for (let i = 0; i < 250; i++) st.recordWitness({ attester: 'A', upto_seq: i, root: `r${i}`, by: 'W', sig: `w${i}` });
    assert.strictEqual(st.witnessesFor('A', 249).length, 1);
    assert.strictEqual(st.witnessesFor('A', 0).length, 0);
    let held = 0; for (let i = 0; i < 250; i++) held += st.witnessesFor('A', i).length;
    assert.strictEqual(held, 100);
  });

  it('a log past its limit is archived whole and restarted from what is held; a reload sees the same', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'att-rotate-'));
    try {
      const st = new AttestationStore({ dir, maxWitnesses: 10, maxLiveBytes: 4096 });
      for (let i = 0; i < 200; i++) st.recordWitness({ attester: 'A', upto_seq: i, root: `r${i}`, by: 'W', sig: `w${i}`.padEnd(64, 'x') });
      const archived = fs.readdirSync(path.join(dir, 'archive'));
      assert.ok(archived.length >= 1 && archived.every((f) => /^witnesses\..+\.jsonl$/.test(f)), archived.join(','));
      const archivedLines = archived.map((f) => fs.readFileSync(path.join(dir, 'archive', f), 'utf8').trim().split('\n').length).reduce((a, b) => a + b, 0);
      const liveLines = fs.readFileSync(path.join(dir, 'witnesses.jsonl'), 'utf8').trim().split('\n').length;
      assert.ok(fs.statSync(path.join(dir, 'witnesses.jsonl')).size <= 4096 * 2, 'the live log stays bounded');
      assert.ok(archivedLines + liveLines >= 200, 'every line appended is still on disk');
      const again = new AttestationStore({ dir, maxWitnesses: 10, maxLiveBytes: 4096 });
      assert.strictEqual(again.witnessesFor('A', 199).length, 1, 'the newest is reloaded');
      assert.strictEqual(again.witnessesFor('A', 0).length, 0);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('an oversized log from an earlier release is read from its tail only, then archived', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'att-legacy-'));
    try {
      const lines = [];
      for (let i = 0; i < 2000; i++) lines.push(JSON.stringify({ attester: 'A', upto_seq: i, root: `r${i}`, by: 'W', sig: `w${i}` }));
      fs.writeFileSync(path.join(dir, 'witnesses.jsonl'), lines.join('\n') + '\n');
      const size = fs.statSync(path.join(dir, 'witnesses.jsonl')).size;
      const st = new AttestationStore({ dir, maxLiveBytes: 8192 });
      assert.strictEqual(st.witnessesFor('A', 1999).length, 1, 'the newest records are read');
      assert.strictEqual(st.witnessesFor('A', 0).length, 0, 'the head of the oversized log is not');
      const archived = fs.readdirSync(path.join(dir, 'archive'));
      assert.strictEqual(fs.statSync(path.join(dir, 'archive', archived[0])).size, size, 'the original is archived unchanged');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
});

// 0.13.15 hotfix review (F1, F2, F4, F5, F9, F10, F12, F13).
describe('AttestationStore — rotation, archive and per-witness bounds', () => {
  const tmp = (p) => fs.mkdtempSync(path.join(os.tmpdir(), p));
  const wit = (i, by = 'W') => ({ attester: 'A', upto_seq: i, root: `r${i}`, by, sig: `w${i}`.padEnd(80, 'x') });
  const archives = (dir) => (fs.existsSync(path.join(dir, 'archive')) ? fs.readdirSync(path.join(dir, 'archive')) : []);

  it('a held set larger than the budget rotates once per budget appended, not on every append (F1, F13)', () => {
    const dir = tmp('att-thrash-');
    try {
      const st = new AttestationStore({ dir, maxWitnesses: 100000, maxWitnessesPerWitness: 100000, maxLiveBytes: 2048, maxArchiveBytes: 1e9 });
      for (let i = 0; i < 2000; i++) st.recordWitness(wit(i));
      const n = archives(dir).length;
      // ~280 KB appended against a 2 KB budget: thrash would make ~2000 archives; doubling makes ~10.
      assert.ok(n > 0 && n < 40, `${n} archives for 2000 appends`);
      const again = new AttestationStore({ dir, maxWitnesses: 100000, maxWitnessesPerWitness: 100000 });
      assert.strictEqual(again.witnessesFor('A', 1999).length, 1);
      assert.strictEqual(again.witnessesFor('A', 0).length, 1, 'every held record is in the live log');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('two rotations in the same millisecond keep both archives (F2)', () => {
    const dir = tmp('att-same-ms-');
    try {
      const st = new AttestationStore({ dir, maxArchiveBytes: 1e9 });
      st.recordWitness(wit(1));
      const RealDate = global.Date;
      const fixed = RealDate.now();
      global.Date = class extends RealDate { constructor(...a) { super(...(a.length ? a : [fixed])); } static now() { return fixed; } };
      try {
        st._rotate('witnesses.jsonl');
        st.recordWitness(wit(2));
        st._rotate('witnesses.jsonl');
      } finally { global.Date = RealDate; }
      assert.strictEqual(archives(dir).length, 2, archives(dir).join(','));
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('a failure part way through a rotation leaves a complete live log (F5)', () => {
    const dir = tmp('att-crash-');
    try {
      const st = new AttestationStore({ dir });
      for (let i = 0; i < 5; i++) st.recordWitness(wit(i));
      const before = fs.readFileSync(path.join(dir, 'witnesses.jsonl'), 'utf8');
      const realRename = fs.renameSync;
      fs.renameSync = () => { throw Object.assign(new Error('disk gone'), { code: 'EIO' }); };
      try { st._rotate('witnesses.jsonl'); } finally { fs.renameSync = realRename; }
      assert.strictEqual(fs.readFileSync(path.join(dir, 'witnesses.jsonl'), 'utf8'), before, 'the live log is untouched');
      assert.strictEqual(new AttestationStore({ dir }).witnessesFor('A', 4).length, 1);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('archive/ is bounded per log, oldest first, never the newest (F12)', () => {
    const dir = tmp('att-archive-');
    try {
      const st = new AttestationStore({ dir, maxLiveBytes: 1024, maxArchiveBytes: 4096, maxWitnesses: 10 });
      for (let i = 0; i < 500; i++) st.recordWitness(wit(i));
      const files = archives(dir);
      const total = files.reduce((s, f) => s + fs.statSync(path.join(dir, 'archive', f)).size, 0);
      const newest = Math.max(...files.map((f) => fs.statSync(path.join(dir, 'archive', f)).size));
      assert.ok(files.length >= 1 && total <= 4096 + newest, `${files.length} archives, ${total} bytes`);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('one witnessing node cannot evict another\'s witnesses (F4)', () => {
    const st = new AttestationStore({ maxWitnessesPerWitness: 50, maxWitnesses: 120 });
    for (let i = 0; i < 20; i++) st.recordWitness(wit(i, 'honest'));
    for (let i = 0; i < 5000; i++) st.recordWitness({ ...wit(1000 + i, 'flooder'), attester: `fake-${i}` });
    let honest = 0; for (let i = 0; i < 20; i++) honest += st.witnessesFor('A', i).length;
    assert.strictEqual(honest, 20, 'the honest witness keeps all of its own');
  });

  it('a refused checkpoint leaves no empty entry, and the attester count is bounded (F9)', () => {
    const st = new AttestationStore({ maxAttesters: 3 });
    st.recordCheckpoint({ by: 'A', upto_seq: 1, root: 'r', sig: 's' });
    st.recordCheckpoint({ by: 'A', upto_seq: 1, root: 'r', sig: 's2' });
    for (const by of ['B', 'C', 'D', 'E']) st.recordCheckpoint({ by, upto_seq: 1, root: 'r', sig: by });
    assert.strictEqual(st._checkpoints.size, 3);
    assert.strictEqual(st.latestCheckpoint('A'), null, 'the least recently updated gave up its place');
  });

  it('ids containing the old separator are evicted cleanly (F10)', () => {
    const st = new AttestationStore({ maxWitnessesPerWitness: 2 });
    for (let i = 0; i < 6; i++) st.recordWitness({ attester: 'a|b', upto_seq: i, root: 'r', by: 'w|x', sig: `s${i}` });
    let held = 0; for (let i = 0; i < 6; i++) held += st.witnessesFor('a|b', i).length;
    assert.strictEqual(held, 2);
    assert.strictEqual(st._witnessCount, 2);
  });
});
