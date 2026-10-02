'use strict';

/**
 * 0.14.0: the attestation logs are rotated. A log is rotated once the bytes in it beyond the records
 * the store holds exceed the larger of the rotation budget and the bytes held; the live log is
 * complete at every instant; archive names never collide; archive/ is bounded per log, the newest
 * archive included. The earlier, rejected attempts thrashed (a rotation on every append once the held
 * set outgrew the budget), rotated on every start, renamed before writing, ignored short writes, left
 * an archive name on the live log after a failure, clobbered archives made in one millisecond, and
 * exempted the newest archive from the bound. Each case below fails on one of those.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { tmpdir } = require('./_tmpdir');
const { AttestationStore } = require('../lib/attestation-store');

const ATT = 'attestations.jsonl';
const CP = 'checkpoints.jsonl';
const WIT = 'witnesses.jsonl';

/** An attestation of about 120 bytes. */
const att = (i, by = 'A') => ({ of: `cmb-${i}`, by, seq: i, prev: 'p', sig: `sig-${by}-${i}`, pad: 'x'.repeat(60) });
const lineOf = (o) => JSON.stringify(o) + '\n';
const read = (dir, file) => { try { return fs.readFileSync(path.join(dir, file), 'utf8'); } catch { return ''; } };
const archives = (dir) => { try { return fs.readdirSync(path.join(dir, 'archive')).sort(); } catch { return []; } };
const archiveBytes = (dir) => archives(dir).reduce((s, n) => s + fs.statSync(path.join(dir, 'archive', n)).size, 0);
const leftovers = (dir) => fs.readdirSync(dir).filter((n) => n.endsWith('.rotating') || n.endsWith('.archiving'));
/** The pid of a process that has exited: what a crashed rotation's leftovers are named with. */
const deadPid = () => require('node:child_process').spawnSync(process.execPath, ['-e', '0']).pid;

/** Spy on a store's rotations: the bytes it had appended (in all) at each one. */
function spyRotations(st, appended) {
  const at = [];
  const real = st._rotate;
  st._rotate = function (file) { at.push({ file, appended: appended(), held: this._held[file] }); return real.call(this, file); };
  return at;
}

describe('attestation log rotation — when', () => {
  it('does not cascade when the records held exceed the budget', () => {
    const dir = tmpdir('att-rot-cascade-');
    // 200 held attestations are ~24 KB, twelve times the 2 KB budget.
    const st = new AttestationStore({ dir, max: 200, rotateBytes: 2048, maxArchiveBytes: 1e9, log: () => {} });
    let appended = 0;
    const at = spyRotations(st, () => appended);
    for (let i = 1; i <= 3000; i++) { const a = att(i); st.record(a); appended += Buffer.byteLength(lineOf(a)); }
    const held = st._held[ATT];
    assert.ok(held > 10 * 2048, `held ${held}`);
    assert.ok(at.length >= 1, 'it does rotate');
    // Each rotation needs more than max(budget, held) bytes appended and dropped since the last.
    assert.ok(at.length <= Math.ceil(appended / held), `${at.length} rotations for ${appended} bytes appended, ${held} held`);
    for (let i = 1; i < at.length; i++) {
      assert.ok(at[i].appended - at[i - 1].appended > at[i - 1].held, `rotation ${i} came ${at[i].appended - at[i - 1].appended} bytes after the last`);
    }
    assert.strictEqual(st._rotations[ATT], at.length, 'every rotation succeeded');
    assert.strictEqual(archives(dir).length, at.length, 'one archive per rotation');
    const size = fs.statSync(path.join(dir, ATT)).size;
    assert.ok(size <= 2 * held + 200, `the live log stays within held + max(budget, held): ${size}`);
  });

  it('does not rotate a log that holds little beyond its records, and does reclaim one that holds a lot', () => {
    const dir = tmpdir('att-rot-small-');
    const st = new AttestationStore({ dir, max: 50, rotateBytes: 4096, log: () => {} });
    for (let i = 1; i <= 50; i++) st.record(att(i));        // 6 KB, all held: nothing to reclaim
    assert.strictEqual(st._rotations[ATT], 0, 'a log of only held records is not rotated');
    for (let i = 51; i <= 120; i++) st.record(att(i));      // 70 dropped: ~8.4 KB beyond the 6 KB held
    assert.strictEqual(st._rotations[ATT], 1);
    assert.strictEqual(read(dir, ATT).trim().split('\n').length <= 50 + 20, true);
  });
});

describe('attestation log rotation — at start', () => {
  it('a start of a log under budget does not rotate, even when the records held exceed the budget', () => {
    const dir = tmpdir('att-rot-start-');
    const opts = { dir, max: 200, rotateBytes: 2048, log: () => {} };
    const st = new AttestationStore(opts);
    for (let i = 1; i <= 700; i++) st.record(att(i));       // rotated at least once
    assert.ok(st._rotations[ATT] >= 1);
    const before = read(dir, ATT);
    const arch = archives(dir);
    for (let n = 0; n < 3; n++) {
      const again = new AttestationStore(opts);
      assert.strictEqual(again._rotations[ATT], 0, `restart ${n} did not rotate`);
      assert.strictEqual(again.size(), 200);
    }
    assert.strictEqual(read(dir, ATT), before, 'the live log is untouched');
    assert.deepStrictEqual(archives(dir), arch, 'and nothing was archived');
  });

  it('a start of a log over budget rotates it once (the storm log), keeping what is held', () => {
    const dir = tmpdir('att-rot-storm-');
    fs.writeFileSync(path.join(dir, CP), lineOf({ type: 'checkpoint', by: 'A', upto_seq: 8, root: 'r8', sig: 'c8' }));
    const copies = [];
    for (let i = 0; i < 5000; i++) copies.push(lineOf({ type: 'witness', attester: 'A', upto_seq: 8, root: 'r8', by: 'W', sig: `copy-${i % 2}`, at: i % 2 }));
    fs.writeFileSync(path.join(dir, WIT), copies.join(''));
    const st = new AttestationStore({ dir, rotateBytes: 8192, maxArchiveBytes: 1e9, log: () => {} });
    assert.strictEqual(st._rotations[WIT], 1);
    assert.strictEqual(read(dir, WIT), copies[0], 'the live log holds the one witness held');
    assert.strictEqual(fs.readFileSync(path.join(dir, 'archive', archives(dir)[0]), 'utf8'), copies.join(''), 'the old log is archived whole');
    const again = new AttestationStore({ dir, rotateBytes: 8192, maxArchiveBytes: 1e9, log: () => {} });
    assert.strictEqual(again._rotations[WIT], 0, 'and the next start leaves it alone');
    assert.strictEqual(again.witnessesFor('A', 8).length, 1);
  });

  it('the checkpoint and witness logs are read whole, so a quiet attester at the head of a rotated log survives a restart', () => {
    const dir = tmpdir('att-rot-quiet-');
    const opts = { dir, maxCheckpointsPerAttester: 2, maxAttesters: 4, rotateBytes: 4096, log: () => {} };
    const st = new AttestationStore(opts);
    st.recordCheckpoint({ by: 'Q', upto_seq: 1, root: 'rq', sig: 'cq' });   // a quiet attester
    let n = 0;
    while (st._rotations[CP] === 0) { n++; st.recordCheckpoint({ by: 'A', upto_seq: n, root: `r${n}`, sig: `c${n}` }); }
    // Q is now at the head of the live log; A churns until just before the next rotation.
    while (fs.statSync(path.join(dir, CP)).size - st._held[CP] < 4096 - 200) { n++; st.recordCheckpoint({ by: 'A', upto_seq: n, root: `r${n}`, sig: `c${n}` }); }
    assert.strictEqual(st._rotations[CP], 1);
    assert.ok(fs.statSync(path.join(dir, CP)).size > st._held[CP] * 4, 'the live log is mostly churn');
    const again = new AttestationStore(opts);
    assert.ok(again.checkpointAt('Q', 1), 'the quiet attester is still held');
    assert.deepStrictEqual(again.checkpointsOf('A').map((c) => c.upto_seq), [n - 1, n]);
  });

  it('read budgets: every log whole at its caps (what the caps hold, and as much again before a rotation)', () => {
    const st = new AttestationStore();
    const b = st._readBudget;
    // Measured lines: an attestation ~520 bytes, a checkpoint ~315, a witness ~380.
    assert.ok(b[ATT] >= 2 * 50000 * 520 * 1.3, `attestations ${b[ATT]}`);
    assert.ok(b[CP] >= 2 * 32 * 1024 * 315 * 1.3, `checkpoints ${b[CP]}`);
    assert.ok(b[WIT] >= 2 * (50000 * 380 + 1024 * 2048), `witnesses ${b[WIT]}`);
  });

  it("a quiet attester's attestations at the head of a rotated log survive a restart", () => {
    const dir = tmpdir('att-rot-quiet-att-');
    // What the caps hold (6 attestations) is far less than may sit beyond it before a rotation (8 KiB).
    const opts = { dir, max: 6, rotateBytes: 8192, log: () => {} };
    const st = new AttestationStore(opts);
    for (let i = 1; i <= 2; i++) st.record(att(i, 'Q'));   // a quiet attester
    let i = 0;
    while (st._rotations[ATT] === 0) st.record(att(++i, 'F'));
    // Q is now at the head of the live log; F churns until just before the next rotation.
    while (fs.statSync(path.join(dir, ATT)).size - st._held[ATT] < 8192 - 200) st.record(att(++i, 'F'));
    assert.strictEqual(st._rotations[ATT], 1);
    assert.ok(fs.statSync(path.join(dir, ATT)).size > 6 * 720, 'the live log is longer than what the caps hold');
    const again = new AttestationStore(opts);
    assert.deepStrictEqual(again.chainOf('Q').map((a) => a.seq), [1, 2], "the quiet attester's chain is reloaded");
  });

  it('a rotation that crashed after linking is tidied at the next start', () => {
    const dir = tmpdir('att-rot-crash-');
    const st = new AttestationStore({ dir, log: () => {} });
    for (let i = 1; i <= 5; i++) st.record(att(i));
    const before = read(dir, ATT);
    // What a crash between the link and the rename leaves: an archive name on the live inode, and the temp file.
    const pid = deadPid();
    fs.mkdirSync(path.join(dir, 'archive'));
    fs.linkSync(path.join(dir, ATT), path.join(dir, 'archive', `attestations.000000000001.20261002T000000000Z.${pid}.jsonl`));
    fs.writeFileSync(path.join(dir, `${ATT}.${pid}.1.rotating`), 'partial');
    const again = new AttestationStore({ dir, log: () => {} });
    assert.deepStrictEqual(archives(dir), [], 'the archive name on the live log is removed');
    assert.deepStrictEqual(leftovers(dir), [], 'and so is the temp file');
    assert.strictEqual(read(dir, ATT), before, 'the live log is untouched');
    assert.strictEqual(again.size(), 5);
  });
});

describe('attestation log rotation — how', () => {
  /** A store about to rotate its attestation log on the next record. */
  function nearRotation(extra = {}) {
    const dir = tmpdir('att-rot-fail-');
    const said = [];
    const st = new AttestationStore({ dir, max: 20, rotateBytes: 2048, maxArchiveBytes: 1e9, log: (m) => said.push(m), ...extra });
    let i = 0;
    st.record(att(++i));
    while (fs.statSync(path.join(dir, ATT)).size - st._held[ATT] + 130 <= Math.max(2048, st._held[ATT])) st.record(att(++i));
    assert.strictEqual(st._rotations[ATT], 0);
    return { dir, st, said, next: () => att(++i) };
  }

  /** Make one fs call fail, for the rotation's temp file only (appends to the live log go on). */
  function onTemp(name, fail) {
    const realOpen = fs.openSync;
    const real = fs[name];
    const temps = new Set();
    fs.openSync = (p, ...a) => { const fd = realOpen(p, ...a); if (String(p).endsWith('.rotating')) temps.add(fd); return fd; };
    fs[name] = (fd, ...a) => (temps.has(fd) ? fail(fd, ...a) : real(fd, ...a));
    return () => { fs.openSync = realOpen; fs[name] = real; };
  }
  const failures = {
    'opening the temp file': () => { const real = fs.openSync; fs.openSync = (p, ...a) => { if (String(p).endsWith('.rotating')) throw Object.assign(new Error('no'), { code: 'EMFILE' }); return real(p, ...a); }; return () => { fs.openSync = real; }; },
    'writing it': () => onTemp('writeSync', () => { throw Object.assign(new Error('full'), { code: 'ENOSPC' }); }),
    'a write that makes no progress': () => onTemp('writeSync', () => 0),
    'fsyncing it': () => onTemp('fsyncSync', () => { throw Object.assign(new Error('io'), { code: 'EIO' }); }),
    'linking the old log into the archive': () => { const real = fs.linkSync; fs.linkSync = () => { throw Object.assign(new Error('io'), { code: 'EIO' }); }; return () => { fs.linkSync = real; }; },
    'renaming it over the live log': () => { const real = fs.renameSync; fs.renameSync = () => { throw Object.assign(new Error('busy'), { code: 'EBUSY' }); }; return () => { fs.renameSync = real; }; },
  };

  for (const [step, inject] of Object.entries(failures)) {
    it(`a failure ${step} leaves the live log complete, is said once, and is retried after another budget`, () => {
      const { dir, st, said, next } = nearRotation();
      const before = read(dir, ATT);
      const arch = archives(dir);
      const calls = spyRotations(st, () => 0);
      const restore = inject();
      let a;
      try { a = next(); st.record(a); } finally { restore(); }
      assert.strictEqual(calls.length, 1, 'a rotation was attempted');
      assert.strictEqual(st._rotations[ATT], 0, 'and failed');
      assert.strictEqual(read(dir, ATT), before + lineOf(a), 'the live log is every line appended, whole');
      assert.deepStrictEqual(archives(dir), arch, 'no archive name is left (none on the live log)');
      assert.deepStrictEqual(leftovers(dir), [], 'no temp file is left');
      assert.strictEqual(said.length, 1, said.join('\n'));
      // Not retried on the next append, only after another budget.
      const restore2 = inject();
      try {
        for (let k = 0; k < 5; k++) st.record(next());
        assert.strictEqual(calls.length, 1, 'not retried at once');
        while (calls.length === 1) st.record(next());
      } finally { restore2(); }
      assert.strictEqual(calls.length, 2, 'retried after another budget');
      assert.strictEqual(said.length, 1, 'the same error is said once');
      while (st._rotations[ATT] === 0) st.record(next());   // and once it can, it does
      const again = new AttestationStore({ dir, max: 20, rotateBytes: 2048, log: () => {} });
      assert.deepStrictEqual(again.chainOf('A').map((x) => x.seq), st.chainOf('A').map((x) => x.seq), 'nothing held was lost');
    });
  }

  it('a short write is completed, never installed short', () => {
    const { dir, st, next } = nearRotation();
    const real = fs.writeSync;
    const restore = onTemp('writeSync', (fd, buf, off, len, ...rest) => real(fd, buf, off, Math.min(len, 100), ...rest));
    try { st.record(next()); } finally { restore(); }
    assert.strictEqual(st._rotations[ATT], 1);
    const expected = [...st._heldRecords(ATT)].map(lineOf).join('');
    assert.strictEqual(read(dir, ATT), expected, 'the live log is every record held');
  });

  it('archive names never collide: rotations in one millisecond, two stores on one directory, a name already taken', () => {
    const realIso = Date.prototype.toISOString;
    Date.prototype.toISOString = () => '2026-10-02T00:00:00.000Z';   // every rotation in the same millisecond
    try {
      const { dir, st, next } = nearRotation();
      for (let k = 0; k < 400; k++) st.record(next());
      const made = st._rotations[ATT];
      assert.ok(made >= 3, `${made} rotations`);
      assert.strictEqual(archives(dir).length, made, 'one archive per rotation');
      // A second store on the same directory rotating in turn with the first.
      const other = new AttestationStore({ dir, max: 20, rotateBytes: 2048, maxArchiveBytes: 1e9, log: () => {} });
      let j = 100000;
      while (other._rotations[ATT] < 2) other.record(att(++j, 'B'));
      while (st._rotations[ATT] < made + 2) st.record(next());
      assert.strictEqual(archives(dir).length, made + 4, 'every rotation kept its own archive');
      // A name taken by someone else between its choice and the link is refused, not overwritten.
      const realName = st._archiveName;
      let taken = null;
      st._archiveName = function (...a) {
        const name = realName.apply(this, a);
        if (!taken) { taken = path.join(dir, 'archive', name); fs.writeFileSync(taken, 'not yours\n'); }
        return name;
      };
      while (st._rotations[ATT] < made + 3) st.record(next());
      assert.strictEqual(fs.readFileSync(taken, 'utf8'), 'not yours\n', 'an existing name is never overwritten');
      assert.strictEqual(archives(dir).length, made + 4 + 2, 'and the rotation took another');
    } finally { Date.prototype.toISOString = realIso; }
  });

  it('where the filesystem has no hard links, the old log is copied', () => {
    const { dir, st, next } = nearRotation();
    const before = read(dir, ATT);
    const real = fs.linkSync;
    fs.linkSync = () => { throw Object.assign(new Error('no links'), { code: 'EPERM' }); };
    let a;
    try { a = next(); st.record(a); } finally { fs.linkSync = real; }
    assert.strictEqual(st._rotations[ATT], 1);
    assert.strictEqual(fs.readFileSync(path.join(dir, 'archive', archives(dir)[0]), 'utf8'), before + lineOf(a), 'the archive is the old log, whole');
  });
});

describe('attestation log rotation — the archive bound', () => {
  it('holds including the newest archive', () => {
    const dir = tmpdir('att-rot-bound-');
    const bound = 12 * 1024;
    const st = new AttestationStore({ dir, max: 20, rotateBytes: 2048, maxArchiveBytes: bound, log: () => {} });
    const at = spyRotations(st, () => 0);
    for (let i = 1; i <= 3000; i++) {
      st.record(att(i));
      if (at.length && i % 50 === 0) assert.ok(archiveBytes(dir) <= bound, `archive ${archiveBytes(dir)} > ${bound}`);
    }
    assert.ok(st._rotations[ATT] > 20, `${st._rotations[ATT]} rotations`);
    assert.ok(archiveBytes(dir) <= bound && archives(dir).length >= 1);
  });

  it('an archive that alone exceeds the bound is dropped too', () => {
    const dir = tmpdir('att-rot-bound1-');
    const st = new AttestationStore({ dir, max: 20, rotateBytes: 2048, maxArchiveBytes: 1024, log: () => {} });
    for (let i = 1; i <= 200; i++) st.record(att(i));
    assert.ok(st._rotations[ATT] >= 1);
    assert.deepStrictEqual(archives(dir), [], 'nothing over the bound is kept, the newest included');
  });

  it('prunes oldest first by sequence, whatever the file times', () => {
    const dir = tmpdir('att-rot-order-');
    fs.mkdirSync(path.join(dir, 'archive'));
    const name = (seq) => `attestations.${String(seq).padStart(12, '0')}.20261002T000000000Z.1.jsonl`;
    const t = new Date('2026-10-01T00:00:00Z');
    for (const seq of [2, 9, 10, 11]) {
      const p = path.join(dir, 'archive', name(seq));
      fs.writeFileSync(p, 'x'.repeat(1000) + '\n');
      // Equal times for 9, 10 and 11; the newest made to look the oldest.
      fs.utimesSync(p, t, seq === 11 ? new Date('2026-09-01T00:00:00Z') : t);
    }
    new AttestationStore({ dir, maxArchiveBytes: 2100, log: () => {} });   // a start holds the bound
    assert.deepStrictEqual(archives(dir), [name(10), name(11)], 'the two newest by sequence are kept');
  });
});

describe('attestation log rotation — nothing held is lost', () => {
  it('a restart after rotating every log rebuilds the same store: chains, checkpoints and their order, conflicts, witnesses, and what this node witnessed', () => {
    const dir = tmpdir('att-rot-same-');
    const opts = { dir, selfId: 'me', max: 40, maxCheckpointsPerAttester: 3, maxAttesters: 4, maxWitnesses: 12, maxWitnessesPerPosition: 2, rotateBytes: 1024, log: () => {} };
    const st = new AttestationStore(opts);
    for (let i = 1; i <= 100; i++) st.record(att(i, i % 2 ? 'A' : 'B'));
    st.recordCheckpoint({ by: 'Q', upto_seq: 5, root: 'rq', sig: 'cq' });
    st.recordCheckpoint({ by: 'Q', upto_seq: 5, root: 'forked', sig: 'xq' });      // a conflict on a held position
    st.recordWitness({ attester: 'Q', upto_seq: 5, root: 'rq', by: 'W1', sig: 'wq1' });
    st.recordWitness({ attester: 'Q', upto_seq: 5, root: 'rq', by: 'W2', sig: 'wq2' });
    st.recordWitness({ attester: 'Q', upto_seq: 5, root: 'rq', by: 'me', sig: 'mine-full' });   // its position is full
    for (let n = 1; n <= 60; n++) {
      st.recordCheckpoint({ by: 'A', upto_seq: n, root: `ra${n}`, sig: `ca${n}` });
      st.recordWitness({ attester: 'A', upto_seq: n, root: `ra${n}`, by: 'me', sig: `ma${n}` });
      st.recordWitness({ attester: 'A', upto_seq: n, root: `ra${n}`, by: 'W1', sig: `wa${n}` });
    }
    for (const f of [ATT, CP, WIT]) assert.ok(st._rotations[f] >= 1, `${f} rotated`);
    const snap = (s) => ({
      chains: [s.chainOf('A').map((a) => a.sig), s.chainOf('B').map((a) => a.sig)],
      attesters: [...s._checkpoints.keys()],
      checkpoints: ['Q', 'A'].map((by) => s.checkpointsOf(by).map((c) => [c.upto_seq, c.root])),
      conflicted: s.hasConflict('Q', 5),
      positions: [...s._positions.values()].map((p) => p.join(':')),
      witnesses: [...s._positions.values()].map(([a, seq]) => s.witnessesFor(a, seq).map((w) => w.sig)),
      own: [s.hasWitnessed('Q', 5, 'me'), s.hasWitnessed('A', 1, 'me'), s.hasWitnessed('A', 60, 'me')],
    });
    const before = snap(st);
    assert.deepStrictEqual(before.own, [true, true, true]);
    assert.strictEqual(before.conflicted, true);
    const again = new AttestationStore(opts);
    assert.deepStrictEqual(snap(again), before);
    for (const f of [ATT, CP, WIT]) assert.strictEqual(again._rotations[f], 0, `${f} not rotated again at start`);
  });

  it('a waiting witness read from the log is kept through a rotation and a restart, then promoted once (0.14.0 review A1-F4)', () => {
    const dir = tmpdir('att-rot-wait-');
    const opts = { dir, maxCheckpointsPerAttester: 2, rotateBytes: 1024, log: () => {} };
    const waiting = lineOf({ attester: 'Z', upto_seq: 3, root: 'rz', by: 'W', sig: 'wz' });
    fs.writeFileSync(path.join(dir, WIT), waiting);
    const st = new AttestationStore(opts);   // the witness waits for Z's checkpoint
    st.recordWitness({ attester: 'Y', upto_seq: 1, root: 'ry', by: 'W', sig: 'wy' });   // heard on the network: memory only
    st.recordCheckpoint({ by: 'A', upto_seq: 1, root: 'r1', sig: 'c1' });
    for (let n = 1; st._rotations[WIT] === 0; n++) {
      st.recordCheckpoint({ by: 'A', upto_seq: n, root: `r${n}`, sig: `c${n}` });
      st.recordWitness({ attester: 'A', upto_seq: n, root: `r${n}`, by: 'W', sig: `w${n}` });
    }
    assert.ok(read(dir, WIT).includes('"wz"'), 'the waiting witness read from the log is in the rotated log');
    assert.ok(!read(dir, WIT).includes('"wy"'), 'one heard on the network still never reaches it');
    const again = new AttestationStore(opts);   // a restart before Z's checkpoint arrives
    assert.strictEqual(again._rotations[WIT], 0, 'and the next start does not rotate');
    const size = () => fs.statSync(path.join(dir, WIT)).size;
    assert.strictEqual(again._held[WIT], size(), 'the rotated log is all held, the waiting witness included: no waste');
    again.recordCheckpoint({ by: 'Z', upto_seq: 3, root: 'rz', sig: 'cz' });
    assert.strictEqual(again._held[WIT], size(), 'and promoting it counts it once');
    assert.strictEqual(again.witnessesFor('Z', 3).length, 1, 'it was still waiting, and is promoted');
    assert.strictEqual(read(dir, WIT).split('"wz"').length - 1, 1, 'without being written twice');
    assert.strictEqual(new AttestationStore(opts).witnessesFor('Z', 3).length, 1);
  });
});

describe('conflicts are held with their positions', () => {
  it("a held position's conflict is not pushed out by another attester's conflicts on positions since dropped", () => {
    const st = new AttestationStore({ maxCheckpointsPerAttester: 2, maxAttesters: 4 });
    st.recordCheckpoint({ by: 'A', upto_seq: 1, root: 'r', sig: 'a1' });
    st.recordCheckpoint({ by: 'A', upto_seq: 1, root: 'fork', sig: 'a1x' });
    for (let q = 1; q <= 100; q++) {   // B commits and forks position after position; each is dropped two later
      st.recordCheckpoint({ by: 'B', upto_seq: q, root: 'r', sig: `b${q}` });
      st.recordCheckpoint({ by: 'B', upto_seq: q, root: 'fork', sig: `b${q}x` });
    }
    assert.strictEqual(st.hasConflict('A', 1), true, "A's position is still held, and so is its conflict");
    assert.strictEqual(st.recordCheckpoint({ by: 'A', upto_seq: 1, root: 'fork', sig: 'again' }).first, false, 'not reported again');
    assert.strictEqual(st.hasConflict('B', 1), false, 'a dropped position took its conflict with it');
    assert.strictEqual([...st._conflicted.values()].reduce((n, m) => n + m.size, 0), 3, 'only held positions are counted');
  });
});

// 0.14.0 release review, part A1 (lib/attestation-store.js).
describe('0.14.0 release review A1', () => {
  const sig64 = () => require('crypto').randomBytes(64).toString('base64url');
  const { chainHash } = require('../lib/attestation-store');

  it('a log that cannot be read at start is never rotated or rewritten, only appended to, and that is said once (F1)', () => {
    const dir = tmpdir('att-a1-unread-');
    const opts = { dir, max: 100, rotateBytes: 2048 };
    const seed = new AttestationStore({ ...opts, log: () => {} });
    for (let i = 1; i <= 100; i++) seed.record(att(i));   // ~12 KB, well over the budget
    const before = read(dir, ATT);
    const said = [];
    const real = fs.readFileSync;
    fs.readFileSync = (p, ...a) => (String(p).endsWith(ATT) ? (() => { throw Object.assign(new Error('out of memory'), { code: 'ENOMEM' }); })() : real(p, ...a));
    let st;
    try { st = new AttestationStore({ ...opts, log: (m) => said.push(m) }); } finally { fs.readFileSync = real; }
    assert.strictEqual(st._rotations[ATT], 0, 'not rotated');
    assert.strictEqual(read(dir, ATT), before, 'the log is as it was');
    assert.deepStrictEqual(archives(dir), [], 'and nothing was archived (or pruned)');
    assert.strictEqual(said.filter((m) => /could not be read at start \(ENOMEM\)/.test(m)).length, 1, said.join('\n'));
    // Far more than it holds is appended (and dropped) after the start: a log it read would rotate.
    const added = [];
    for (let i = 101; i <= 500; i++) { const a = att(i); st.record(a); added.push(lineOf(a)); }
    assert.strictEqual(st._rotations[ATT], 0, 'and not later either, however much is appended');
    assert.strictEqual(read(dir, ATT), before + added.join(''), 'it is only appended to');
    const again = new AttestationStore({ ...opts, log: () => {} });
    assert.deepStrictEqual([again.size(), again.chainOf('A').at(-1).seq], [100, 500], 'a start that reads it has the newest records');
  });

  it('a read that returns short is completed, and one that cannot be completed leaves the log alone (F8)', () => {
    const dir = tmpdir('att-a1-short-');
    const seed = new AttestationStore({ dir, max: 100, rotateBytes: 2048, log: () => {} });
    for (let i = 1; i <= 300; i++) seed.record(att(i));
    const before = read(dir, ATT);
    const opts = { dir, max: 100, rotateBytes: 2048, maxReadBytes: 16384, log: () => {} };   // the tail branch
    const real = fs.readSync;
    fs.readSync = (fd, buf, off, len, pos) => real(fd, buf, off, Math.min(len, 1000), pos);   // short reads
    let st;
    try { st = new AttestationStore(opts); } finally { fs.readSync = real; }
    assert.deepStrictEqual(st.chainOf('A').map((a) => a.seq).slice(-3), [298, 299, 300], 'the newest records are read');
    assert.strictEqual(st.size(), 100);
    // A read that stops early (the file changed under it) is not taken as read.
    fs.readSync = (fd, buf, off, len, pos) => (off > 0 ? 0 : real(fd, buf, off, Math.min(len, 1000), pos));
    let partial;
    try { partial = new AttestationStore({ ...opts, dir: (() => { const d = tmpdir('att-a1-short2-'); fs.writeFileSync(path.join(d, ATT), before); return d; })() }); } finally { fs.readSync = real; }
    assert.strictEqual(partial._rotations[ATT], 0);
    assert.strictEqual(partial._unread.has(ATT), true);
  });

  it('a re-spelled signature in a log written before 0.14.0 is read as the canonical one: no false break, counted once (F2)', () => {
    const dir = tmpdir('att-a1-spell-');
    const sigs = Array.from({ length: 8 }, sig64);
    const lines = [];
    let prev = 'genesis';
    sigs.forEach((sig, i) => {
      const a = { of: `cmb-${i + 1}`, by: 'A', seq: i + 1, prev, sig };
      // 0.13.16 kept a relay's re-spelling of seq 5, which arrived before the canonical copy.
      if (i === 4) lines.push(lineOf({ ...a, sig: `${sig}=` }));
      lines.push(lineOf(a));
      prev = chainHash(sig);
    });
    fs.writeFileSync(path.join(dir, ATT), lines.join(''));
    const said = [];
    const st = new AttestationStore({ dir, log: (m) => said.push(m) });
    assert.deepStrictEqual(st.verifyChain('A'), { ok: true, gaps: [], breaks: [] }, 'no false break');
    assert.deepStrictEqual(st.chainOf('A').map((a) => a.sig), sigs, 'every signature as its signer wrote it');
    assert.strictEqual(st.size(), 8, 'the canonical copy is the same attestation');
    assert.strictEqual(said.filter((m) => /1 attestation\(s\) in attestations.jsonl carried a signature not spelled/.test(m)).length, 1, said.join('\n'));
    assert.strictEqual(st.has(`${sigs[4]}==`), true, 'any spelling of it is known as held');
  });

  it('a log of witnesses waiting for their checkpoints is held, so a start does not rotate it (F4)', () => {
    const dir = tmpdir('att-a1-waiting-');
    fs.writeFileSync(path.join(dir, WIT), Array.from({ length: 50 }, (_, i) => lineOf({ attester: `Z${i}`, upto_seq: 1, root: 'r', by: 'W', sig: `w${i}` })).join(''));
    const before = read(dir, WIT);
    const st = new AttestationStore({ dir, rotateBytes: 1024, log: () => {} });
    assert.strictEqual(st._rotations[WIT], 0);
    assert.strictEqual(read(dir, WIT), before);
  });

  it('the checkpoint log is read whole even when every held position also holds a conflicting copy (F3)', () => {
    const st = new AttestationStore();
    assert.ok(st._readBudget[CP] >= 4 * 32 * 1024 * 315, `checkpoints ${st._readBudget[CP]}`);
    // Functionally, with checkpoint lines near the budget's allowance (448 bytes).
    const dir = tmpdir('att-a1-conflicts-');
    const opts = { dir, maxCheckpointsPerAttester: 2, maxAttesters: 4, rotateBytes: 512, log: () => {} };
    const pad = 'p'.repeat(360);
    const cp = (by, n, root) => ({ by, upto_seq: n, root, sig: `${by}${n}${root}`, pad });
    const s1 = new AttestationStore(opts);
    for (const by of ['B', 'C', 'D', 'A']) for (const n of [1, 2]) { s1.recordCheckpoint(cp(by, n, 'r')); s1.recordCheckpoint(cp(by, n, 'fork')); }
    // A churns: its positions (and their conflicts) are dropped, B-D's stay held at the head of the log.
    // Each step adds two lines of waste (~900 bytes); stop while one more would reach a rotation.
    const waste = () => fs.statSync(path.join(dir, CP)).size - s1._held[CP];
    for (let n = 3; waste() + 2000 < Math.max(512, s1._held[CP]); n++) {
      s1.recordCheckpoint(cp('A', n, 'r'));
      s1.recordCheckpoint(cp('A', n, 'fork'));
    }
    assert.strictEqual(s1._rotations[CP], 0);
    assert.ok(fs.statSync(path.join(dir, CP)).size > 14336 * 0.7, `the live log is near its most: ${fs.statSync(path.join(dir, CP)).size}`);
    const again = new AttestationStore(opts);
    for (const by of ['B', 'C', 'D']) for (const n of [1, 2]) assert.strictEqual(again.hasConflict(by, n), true, `${by}@${n} is still known as conflicted`);
  });

  it("this node's own witness at a full position is written once, and what is written is reclaimed by a rotation (F5)", () => {
    const dir = tmpdir('att-a1-own-');
    const st = new AttestationStore({ dir, selfId: 'me', maxWitnessesPerPosition: 2, maxCheckpointsPerAttester: 1000, rotateBytes: 4096, log: () => {} });
    const fill = (n) => {
      st.recordCheckpoint({ by: 'A', upto_seq: n, root: 'r', sig: `c${n}` });
      st.recordWitness({ attester: 'A', upto_seq: n, root: 'r', by: 'W1', sig: `w1-${n}` });
      st.recordWitness({ attester: 'A', upto_seq: n, root: 'r', by: 'W2', sig: `w2-${n}` });
    };
    fill(1);
    for (let i = 0; i < 100; i++) assert.strictEqual(st.recordWitness({ attester: 'A', upto_seq: 1, root: 'r', by: 'me', sig: `mine-1-${i}` }).reason, 'position-full');
    assert.strictEqual(read(dir, WIT).split('"by":"me"').length - 1, 1, 'one line, however many copies arrive');
    assert.strictEqual(st.hasWitnessed('A', 1, 'me'), true);
    // Then nothing but this node's own witnesses for full positions: their lines alone reach a rotation.
    for (let n = 2; n <= 20; n++) fill(n);
    const rotations = st._rotations[WIT];
    const pad = 'x'.repeat(2000);
    for (let n = 2; n <= 20; n++) st.recordWitness({ attester: 'A', upto_seq: n, root: 'r', by: 'me', sig: `mine-${n}`, pad });
    assert.ok(st._rotations[WIT] > rotations, 'the own-witness lines count toward a rotation like any waste');
  });

  it("the start-up tidy leaves a rotation another live process has in flight (F6)", () => {
    const dir = tmpdir('att-a1-tidy-');
    const st = new AttestationStore({ dir, log: () => {} });
    for (let i = 1; i <= 5; i++) st.record(att(i));
    const child = require('node:child_process').spawn(process.execPath, ['-e', 'setTimeout(() => {}, 30000)'], { stdio: 'ignore' });
    try {
      // Mid-rotation in that process: its temp file written, the old log just linked into archive/.
      fs.mkdirSync(path.join(dir, 'archive'));
      const name = `attestations.000000000001.20261002T000000000Z.${child.pid}.jsonl`;
      fs.linkSync(path.join(dir, ATT), path.join(dir, 'archive', name));
      fs.writeFileSync(path.join(dir, `${ATT}.${child.pid}.1.rotating`), 'in flight');
      new AttestationStore({ dir, log: () => {} });
      assert.deepStrictEqual(archives(dir), [name], 'its archive is left to it');
      assert.deepStrictEqual(leftovers(dir), [`${ATT}.${child.pid}.1.rotating`], 'and so is its temp file');
    } finally { child.kill(); }
  });

  it('a copy-fallback rotation that crashed before the rename leaves no duplicate of the live log in archive/ (F7)', () => {
    const dir = tmpdir('att-a1-copy-');
    const st = new AttestationStore({ dir, log: () => {} });
    for (let i = 1; i <= 5; i++) st.record(att(i));
    const pid = deadPid();
    fs.mkdirSync(path.join(dir, 'archive'));
    // A crash after copying the live log (no hard links) and before replacing it.
    const dup = `attestations.000000000002.20261002T000000000Z.${pid}.jsonl`;
    fs.copyFileSync(path.join(dir, ATT), path.join(dir, 'archive', dup));
    fs.writeFileSync(path.join(dir, `${ATT}.${pid}.7.archiving`), dup);
    // And an older one whose rotation did replace the live log before the crash: a real archive.
    const real = `attestations.000000000001.20261002T000000000Z.${pid}.jsonl`;
    fs.writeFileSync(path.join(dir, 'archive', real), 'the old log\n');
    fs.writeFileSync(path.join(dir, `${ATT}.${pid}.6.archiving`), real);
    new AttestationStore({ dir, log: () => {} });
    assert.deepStrictEqual(archives(dir), [real], 'the copy of the live log is gone, the real archive kept');
    assert.deepStrictEqual(leftovers(dir), [], 'and the markers are cleared');
  });

  it('while a copied archive waits for the live log to be replaced, a marker names it (F7)', () => {
    const dir = tmpdir('att-a1-copy-mark-');
    const st = new AttestationStore({ dir, max: 20, rotateBytes: 2048, log: () => {} });
    const realLink = fs.linkSync;
    const realRename = fs.renameSync;
    let seen = null;
    fs.linkSync = () => { throw Object.assign(new Error('no links'), { code: 'EPERM' }); };
    fs.renameSync = (from, to) => {
      // The moment a crash would leave a copy of the live log in archive/.
      const marker = fs.readdirSync(dir).find((n) => n.endsWith('.archiving'));
      seen = marker && { names: fs.readFileSync(path.join(dir, marker), 'utf8'), archives: archives(dir) };
      return realRename(from, to);
    };
    try { for (let i = 1; st._rotations[ATT] === 0; i++) st.record(att(i)); } finally { fs.linkSync = realLink; fs.renameSync = realRename; }
    assert.ok(seen, 'a marker existed before the rename');
    assert.deepStrictEqual(seen.archives, [seen.names], 'naming the copy');
  });

  it('a copy-fallback rotation that succeeds leaves no marker', () => {
    const dir = tmpdir('att-a1-copy-ok-');
    const st = new AttestationStore({ dir, max: 20, rotateBytes: 2048, log: () => {} });
    const realLink = fs.linkSync;
    fs.linkSync = () => { throw Object.assign(new Error('no links'), { code: 'EPERM' }); };
    try { for (let i = 1; st._rotations[ATT] === 0; i++) st.record(att(i)); } finally { fs.linkSync = realLink; }
    assert.strictEqual(archives(dir).length, 1);
    assert.deepStrictEqual(leftovers(dir), []);
  });
});
