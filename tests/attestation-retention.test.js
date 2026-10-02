'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * Retention of the attestation audit trail. Rotation keeps each live log bounded; archive/ holds the
 * older history and is pruned oldest first past `archiveMaxBytes` (128 MiB per log by default), and
 * never when it is 0. The bound is the store's option (SymNode's `attestationArchiveMaxBytes`), else
 * SYM_ATTESTATION_ARCHIVE_MAX_BYTES; a value that is not a number of bytes ≥ 0 falls back to the
 * default, which is said once.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { tmpdir } = require('./_tmpdir');
const { AttestationStore } = require('../lib/attestation-store');

const ATT = 'attestations.jsonl';
const DEFAULT = 128 * 1024 * 1024;
const att = (i) => ({ of: `cmb-${i}`, by: 'A', seq: i, prev: 'p', sig: `sig-${i}`, pad: 'x'.repeat(60) });
const archives = (dir) => { try { return fs.readdirSync(path.join(dir, 'archive')).sort(); } catch { return []; } };
const archiveBytes = (dir) => archives(dir).reduce((n, f) => n + fs.statSync(path.join(dir, 'archive', f)).size, 0);

function withEnv(value, fn) {
  const had = Object.prototype.hasOwnProperty.call(process.env, 'SYM_ATTESTATION_ARCHIVE_MAX_BYTES');
  const prev = process.env.SYM_ATTESTATION_ARCHIVE_MAX_BYTES;
  if (value === undefined) delete process.env.SYM_ATTESTATION_ARCHIVE_MAX_BYTES; else process.env.SYM_ATTESTATION_ARCHIVE_MAX_BYTES = value;
  try { return fn(); } finally { if (had) process.env.SYM_ATTESTATION_ARCHIVE_MAX_BYTES = prev; else delete process.env.SYM_ATTESTATION_ARCHIVE_MAX_BYTES; }
}

/** Rotate the attestation log `n` times; returns the store. */
function rotate(dir, n, extra = {}) {
  const st = new AttestationStore({ dir, max: 20, rotateBytes: 2048, log: () => {}, ...extra });
  for (let i = 1; st._rotations[ATT] < n; i++) st.record(att(i));
  return st;
}

describe('attestation archive retention', () => {
  it('0 keeps every archive, however many rotations', () => {
    const dir = tmpdir('att-keep-all-');
    const st = rotate(dir, 40, { archiveMaxBytes: 0 });
    assert.equal(archives(dir).length, 40, 'one archive per rotation, none pruned');
    assert.ok(archiveBytes(dir) > 40 * 2048);
    assert.equal(st._maxArchiveBytes, 0);
    // And a later start does not prune them either.
    new AttestationStore({ dir, max: 20, rotateBytes: 2048, archiveMaxBytes: 0, log: () => {} });
    assert.equal(archives(dir).length, 40);
  });

  it('a small bound prunes oldest first, from the option or from the environment', () => {
    for (const [label, extra, env] of [['option', { archiveMaxBytes: 12 * 1024 }, undefined], ['environment', {}, String(12 * 1024)]]) {
      withEnv(env, () => {
        const dir = tmpdir('att-small-bound-');
        const st = rotate(dir, 40, extra);
        assert.equal(st._maxArchiveBytes, 12 * 1024, label);
        assert.ok(archiveBytes(dir) <= 12 * 1024, `${label}: ${archiveBytes(dir)}`);
        const seqs = archives(dir).map((n) => Number(n.split('.')[1]));
        assert.deepEqual(seqs, seqs.slice().sort((a, b) => a - b));
        assert.equal(seqs.at(-1), 40, `${label}: the newest archives are the ones kept`);
        assert.ok(seqs[0] > 1, `${label}: the oldest went`);
      });
    }
  });

  it('the option wins over the environment, and 0 in the environment keeps everything', () => {
    withEnv('0', () => {
      const dir = tmpdir('att-env-zero-');
      rotate(dir, 30);
      assert.equal(archives(dir).length, 30);
      assert.equal(new AttestationStore({ archiveMaxBytes: 5000, log: () => {} })._maxArchiveBytes, 5000);
    });
  });

  it('a value that is not a number of bytes ≥ 0 uses the default, and says so once', () => {
    for (const [option, env] of [[-5, undefined], ['lots', undefined], [Number.NaN, undefined], [undefined, 'abc'], [undefined, '-1'], [undefined, '1.5e3']]) {
      withEnv(env, () => {
        const said = [];
        const dir = tmpdir('att-bad-bound-');
        const st = new AttestationStore({ dir, archiveMaxBytes: option, log: (m) => said.push(m) });
        assert.equal(st._maxArchiveBytes, DEFAULT, `${String(option)} / ${env}`);
        assert.equal(said.filter((m) => /is not a number of bytes/.test(m)).length, 1, said.join('\n'));
      });
    }
    withEnv(undefined, () => assert.equal(new AttestationStore({ log: () => {} })._maxArchiveBytes, DEFAULT, 'unset: the default'));
  });

  it("a SymNode passes `attestationArchiveMaxBytes` to its store", () => {
    const { SymNode } = require('../lib/node');
    const { NullDiscovery } = require('../lib/discovery');
    const { nodeDir } = require('../lib/config');
    const name = `retention-${Date.now()}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), attestationArchiveMaxBytes: 0 });
    try { assert.equal(node._attestations._maxArchiveBytes, 0); } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });
});
