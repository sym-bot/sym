'use strict';

/**
 * The key registry (design D3): one place where a nodeId gets a key, and an explicit conflict matrix.
 * No source ever overrides a different key — the 0.13 rule "a strictly stronger source overrides" is
 * gone. Each row of the matrix is a test here; the anchor is configuration and never persisted; a
 * 0.13 file's `handshake` entries become `legacy-claim` (expected, never verifying) on first load.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { RosterKeyRegistry, FORMAT_MARKER } = require('../lib/roster-keys');

const key = () => crypto.generateKeyPairSync('ed25519').publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('base64url');
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'rk-'));
const lines = (dir) => fs.readFileSync(path.join(dir, 'roster-keys.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));

describe('the conflict matrix, row by row', () => {
  it('nodeId unbound, proven session → bind proven', () => {
    const r = new RosterKeyRegistry(); const k = key();
    assert.deepStrictEqual(r.bind('N', k, 'proven'), { bound: true, source: 'proven', created: true }, 'a new binding says so');
    assert.strictEqual(r.get('N'), k);
  });

  it('nodeId unbound, anchor-rooted grant in effect vouches a key → bound as a view (never stored)', () => {
    const k = key();
    let inEffect = true;
    const r = new RosterKeyRegistry({ grantView: (id) => (id === 'N' && inEffect ? k : undefined) });
    assert.strictEqual(r.bind('N', k, 'grant').bound, true);
    assert.strictEqual(r.source('N'), 'grant');
    assert.strictEqual(r.get('N'), k, 'a vouched key verifies');
    assert.strictEqual(r.size(), 0, 'nothing is stored for it');
    inEffect = false;
    assert.strictEqual(r.get('N'), undefined, 'the binding ends with the grant (security review C)');
    assert.strictEqual(new RosterKeyRegistry().bind('N', k, 'grant').reason, 'not-in-effect', 'a grant not in effect binds nothing');
  });

  it('this node\'s own nodeId is its own key: no source binds it to another, and no grant view applies', () => {
    const own = key(); const evil = key();
    const r = new RosterKeyRegistry({ self: { nodeId: 'me', publicKey: own }, grantView: () => evil });
    assert.strictEqual(r.get('me'), own);
    assert.strictEqual(r.source('me'), 'self');
    for (const src of ['proven', 'pinned', 'grant', 'legacy-claim']) assert.strictEqual(r.bind('me', evil, src).reason, 'conflict', src);
    assert.strictEqual(r.get('me'), own);
  });

  it('pinned outranks proven: a session proving a pinned key keeps it pinned (mesh-channel defect report)', () => {
    const r = new RosterKeyRegistry(); const k = key();
    r.bind('N', k, 'pinned');
    assert.strictEqual(r.bind('N', k, 'proven').source, 'pinned');
    assert.strictEqual(r.source('N'), 'pinned');
  });

  it('nodeId unbound, accepted invite names a key → bind pinned', () => {
    const r = new RosterKeyRegistry(); const k = key();
    assert.strictEqual(r.bind('N', k, 'pinned').source, 'pinned');
    assert.strictEqual(r.get('N'), k);
  });

  it('nodeId bound, same key from any source → keep, record the stronger source', () => {
    const r = new RosterKeyRegistry(); const k = key();
    r.bind('N', k, 'grant');
    assert.strictEqual(r.bind('N', k, 'proven').source, 'proven', 'stronger: recorded');
    assert.strictEqual(r.bind('N', k, 'grant').source, 'proven', 'weaker: the stronger stays');
    assert.strictEqual(r.conflicts().length, 0);
  });

  for (const [first, second] of [['grant', 'proven'], ['proven', 'grant'], ['pinned', 'proven'], ['proven', 'pinned'], ['proven', 'proven'], ['grant', 'pinned']]) {
    it(`nodeId bound (${first}), DIFFERENT key from ${second} → conflict: refused and recorded`, () => {
      const k1 = key(); const k2 = key();
      // A grant binding is a view over grants in effect (security review C): the first is one.
      const r = new RosterKeyRegistry(first === 'grant' ? { grantView: (id) => (id === 'N' ? k1 : undefined) } : {});
      r.bind('N', k1, first);
      const res = r.bind('N', k2, second);
      assert.strictEqual(res.bound, false);
      assert.strictEqual(res.reason, 'conflict');
      assert.strictEqual(r.get('N'), k1, 'the first binding holds, whatever the second source');
      assert.deepStrictEqual(r.conflicts().map((c) => [c.nodeId, c.had, c.got, c.hadSource, c.gotSource]), [['N', k1, k2, first, second]]);
    });
  }

  it('the configured anchor is always its configured key, and is never written to the file', () => {
    const dir = tmp();
    try {
      const A = key(); const evil = key();
      const r = new RosterKeyRegistry({ anchor: { nodeId: 'A', publicKey: A }, dir });
      assert.strictEqual(r.get('A'), A);
      assert.strictEqual(r.source('A'), 'anchor');
      assert.strictEqual(r.bind('A', evil, 'proven').reason, 'conflict');
      assert.strictEqual(r.bind('A', A, 'proven').source, 'anchor');
      assert.strictEqual(r.get('A'), A);
      assert.ok(!lines(dir).some((l) => l.nodeId === 'A'), 'no anchor line on disk');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('an anchor re-pinned out of band takes effect at the next start (nothing replays the old one)', () => {
    const dir = tmp();
    try {
      const oldA = key(); const newA = key();
      // A 0.13 file that persisted the old anchor binding.
      fs.writeFileSync(path.join(dir, 'roster-keys.jsonl'), JSON.stringify({ nodeId: 'A', key: oldA, source: 'anchor' }) + '\n');
      const r = new RosterKeyRegistry({ anchor: { nodeId: 'A', publicKey: newA }, dir });
      assert.strictEqual(r.get('A'), newA);
      assert.strictEqual(r.conflicts().length, 0, 'the old anchor line is dropped, not a conflict');
      const again = new RosterKeyRegistry({ anchor: { nodeId: 'A', publicKey: newA }, dir });
      assert.strictEqual(again.get('A'), newA);
      const unanchored = new RosterKeyRegistry({ dir });
      assert.strictEqual(unanchored.get('A'), undefined, 'without the configuration, no anchor is remembered');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('a legacy-claim is the expected key: proven with it binds proven, proven with another is a conflict', () => {
    const r = new RosterKeyRegistry(); const honest = key(); const squatter = key();
    r.bind('N', honest, 'legacy-claim');
    assert.strictEqual(r.get('N'), undefined, 'a legacy claim verifies nothing');
    assert.strictEqual(r.expected('N'), honest);
    assert.strictEqual(r.bind('N', squatter, 'proven').reason, 'conflict', 'a squatter racing the upgrade cannot win');
    assert.strictEqual(r.get('N'), undefined);
    assert.strictEqual(r.bind('N', honest, 'proven').source, 'proven', 'the honest node, whose identity file did not change, matches');
    assert.strictEqual(r.get('N'), honest);
  });

  it('an invite against an existing binding pins nothing: the operator resolves it', () => {
    const r = new RosterKeyRegistry(); const bound = key(); const invited = key();
    r.bind('N', bound, 'proven');
    assert.strictEqual(r.bind('N', invited, 'pinned').reason, 'conflict');
    assert.strictEqual(r.get('N'), bound);
    assert.deepStrictEqual(r.resolveConflict('N', invited), { resolved: true });
    assert.strictEqual(r.get('N'), invited);
    assert.strictEqual(r.source('N'), 'pinned');
    assert.strictEqual(r.conflicts().length, 0, 'resolved conflicts are cleared');
  });
});

describe('persistence and the 0.13 file', () => {
  it('bindings, conflicts and floor resets reload; the file carries a version marker', () => {
    const dir = tmp();
    try {
      const k = key(); const k2 = key();
      // The floor arms for a routed nodeId on a proof, as its own persisted fact (security review).
      const r1 = new RosterKeyRegistry({ dir, isRouted: (id) => id === 'N' || id === 'M' });
      r1.bind('N', k, 'proven');
      r1.bind('N', k2, 'grant');
      r1.bind('M', key(), 'proven');
      r1.resetFloor('M');
      assert.deepStrictEqual(lines(dir)[0], { ...FORMAT_MARKER });
      const r2 = new RosterKeyRegistry({ dir });
      assert.strictEqual(r2.get('N'), k);
      assert.strictEqual(r2.source('N'), 'proven');
      assert.strictEqual(r2.conflicts().length, 1);
      assert.strictEqual(r2.floor('N'), true, 'the sticky floor is persisted');
      assert.strictEqual(r2.floor('M'), false, 'and an operator reset survives too');
      assert.strictEqual(new RosterKeyRegistry({ dir }).floor('X'), false, 'an unrouted id never arms one');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('a 0.13 file is migrated once: handshake → legacy-claim, grant kept, anchor dropped; idempotent', () => {
    const dir = tmp();
    try {
      const h = key(); const g = key(); const a = key(); const later = key();
      const old = [
        { nodeId: 'H', key: h, source: 'handshake' },
        { nodeId: 'G', key: g, source: 'grant' },
        { nodeId: 'G', key: later, source: 'handshake' },   // 0.13: a handshake overrode the grant
        { nodeId: 'A', key: a, source: 'anchor' },
        { nodeId: 'X', key: 'not-a-key', source: 'handshake' },
      ];
      fs.writeFileSync(path.join(dir, 'roster-keys.jsonl'), old.map((o) => JSON.stringify(o)).join('\n') + '\n');
      const r = new RosterKeyRegistry({ dir });
      assert.deepStrictEqual(r.migration(), { read: 5, bindings: 2, legacyClaim: 2, grant: 0, droppedAnchor: 1, droppedMalformed: 1, droppedSelf: 0 });
      assert.strictEqual(r.source('H'), 'legacy-claim');
      assert.strictEqual(r.expected('G'), later, 'the binding 0.13 used is the one kept');
      assert.strictEqual(r.source('G'), 'legacy-claim');
      assert.strictEqual(r.get('H'), undefined);
      const file = lines(dir);
      assert.deepStrictEqual(file[0], { ...FORMAT_MARKER });
      assert.strictEqual(file.length, 3);
      const again = new RosterKeyRegistry({ dir });
      assert.strictEqual(again.migration(), null, 'a marked file is not migrated again');
      assert.strictEqual(again.source('H'), 'legacy-claim');
      assert.strictEqual(lines(dir).length, 3);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('a 0.13 `grant` entry migrates as a legacy claim: expected, never verifying (security review C, p1b-migrate-grant)', () => {
    const dir = tmp();
    try {
      const k = key(); const honest = key();
      fs.writeFileSync(path.join(dir, 'roster-keys.jsonl'), JSON.stringify({ nodeId: 'H', key: k, source: 'grant' }) + '\n');
      const r = new RosterKeyRegistry({ dir });
      assert.strictEqual(r.source('H'), 'legacy-claim');
      assert.strictEqual(r.get('H'), undefined, '0.13 pinned a grant key without checking its grantor: it verifies nothing');
      assert.strictEqual(r.migration().grant, 1);
      assert.strictEqual(r.bind('H', honest, 'proven').reason, 'conflict', 'the expected key: another is a conflict for the operator');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('a read-only registry (sym keys list) changes nothing on disk (p11-cli-compact)', () => {
    const dir = tmp();
    try {
      const k = key();
      const old = Date.now() - 31 * 864e5;
      fs.writeFileSync(path.join(dir, 'roster-keys.jsonl'), JSON.stringify(FORMAT_MARKER) + '\n' + JSON.stringify({ nodeId: 'L', key: k, source: 'proven', seen: old }) + '\n');
      const before = fs.readFileSync(path.join(dir, 'roster-keys.jsonl'), 'utf8');
      const ro = new RosterKeyRegistry({ dir, readOnly: true });
      assert.strictEqual(ro.get('L'), k, 'listed as it is');
      ro.noteSeen('L'); ro.bind('M', key(), 'proven'); ro.bind('L', key(), 'proven'); ro.resetFloor('L');
      assert.strictEqual(fs.readFileSync(path.join(dir, 'roster-keys.jsonl'), 'utf8'), before, 'nothing expired, compacted or written, whatever is called on it');
      assert.ok(!fs.existsSync(path.join(dir, 'roster-conflicts.jsonl')), 'not even a conflict');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('a 0.13 rollback reads the migrated file (it skips the marker) and its appends are relabelled on return', () => {
    const dir = tmp();
    try {
      const h = key(); const n = key();
      fs.writeFileSync(path.join(dir, 'roster-keys.jsonl'), JSON.stringify({ nodeId: 'H', key: h, source: 'handshake' }) + '\n');
      new RosterKeyRegistry({ dir });
      // What a 0.13 reader does with each line: JSON.parse, then pin(r.nodeId, r.key, r.source).
      const read013 = lines(dir).filter((r) => r.nodeId && r.key);
      assert.deepStrictEqual(read013.map((r) => r.nodeId), ['H'], 'the marker has no nodeId: 0.13 skips it as malformed');
      // The rollback appends a handshake line of its own; 0.14 reads it as a legacy claim.
      fs.appendFileSync(path.join(dir, 'roster-keys.jsonl'), JSON.stringify({ nodeId: 'R', key: n, source: 'handshake' }) + '\n');
      const back = new RosterKeyRegistry({ dir });
      assert.strictEqual(back.source('R'), 'legacy-claim');
      assert.strictEqual(back.get('R'), undefined);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('a malformed binding is refused, not stored', () => {
    const r = new RosterKeyRegistry();
    for (const [id, k, s] of [['', key(), 'proven'], ['N', 'short', 'proven'], ['N', { x: 1 }, 'proven'], ['N', key(), 'anchor'], ['N', key(), 'handshake']]) {
      assert.strictEqual(r.bind(id, k, s).reason, 'malformed');
    }
    assert.strictEqual(r.size(), 0);
  });
});
