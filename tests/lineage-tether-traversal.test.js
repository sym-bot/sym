'use strict';

/**
 * MMP §15.8 anchor resolution is VERIFIED LOCAL TRAVERSAL, ordered by receiver-local store time.
 *
 * The anchor decides whether a remix keeps its lineage, so whoever picks the anchor picks the
 * verdict. Two inputs the sender controls used to pick it:
 *   - `lineage.ancestors`, a transitive closure the sender writes. Naming any record the receiver
 *     happens to hold as an "ancestor" made that record the anchor — lineage amplification.
 *   - `originTimestamp`, the author's unsigned clock. A backdated time won the earliest-anchor race.
 * Anchor resolution now walks DIRECT parents through records this node stored, following each
 * stored record's own parents, and ranks by `storedAt`.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { resolveTetherAnchor } = require('../lib/core');

function store(records) {
  const m = new Map(records.map((r) => [r.key, r]));
  return (key) => m.get(key);
}
const cats = (t) => ({ focus: { text: t }, issue: { text: 'x' } });
const record = (key, storedAt, parents, extra = {}) =>
  ({ key, storedAt, cmb: { categories: cats(key), metadata: { lineage: { parents } }, ...extra } });

describe('§15.8 anchor resolution — sender-supplied inputs never pick the anchor', () => {
  it('a STORED record named only in lineage.ancestors is not the anchor', () => {
    // The receiver holds `unrelated` (stored earliest) for its own reasons; the sender names it as
    // an ancestor. It is not reachable through any parent, so it must not be chosen.
    const getEntry = store([
      record('unrelated', 100, []),
      record('p1', 900, []),
    ]);
    const incoming = { metadata: { lineage: { parents: ['p1'], ancestors: ['unrelated', 'p1'] } }, categories: cats('remix') };
    assert.strictEqual(resolveTetherAnchor(incoming, getEntry).key, 'p1');
  });

  it('a backdated author originTimestamp does not win the earliest-anchor race', () => {
    // Both are direct parents, so this isolates the ranking from the walk.
    const getEntry = store([
      record('root', 500, [], { originTimestamp: 500 }),
      record('p1', 900, [], { originTimestamp: 1 }),
    ]);
    const incoming = { metadata: { lineage: { parents: ['p1', 'root'] } }, categories: cats('remix') };
    assert.strictEqual(resolveTetherAnchor(incoming, getEntry).key, 'root');
  });

  it('a parents-only chain is walked through stored records to the earliest stored root', () => {
    const getEntry = store([
      record('root', 500, []),
      record('mid', 700, ['root']),
      record('p1', 900, ['mid']),
    ]);
    const incoming = { metadata: { lineage: { parents: ['p1'] } }, categories: cats('remix') };
    assert.strictEqual(resolveTetherAnchor(incoming, getEntry).key, 'root');
  });

  it('the walk cannot pass through a parent this node never stored', () => {
    // mid is missing locally, so root — though stored — is unreachable from p1.
    const getEntry = store([record('root', 500, []), record('p1', 900, ['mid'])]);
    const incoming = { metadata: { lineage: { parents: ['p1'], ancestors: ['root'] } }, categories: cats('remix') };
    assert.strictEqual(resolveTetherAnchor(incoming, getEntry).key, 'p1');
  });

  it('a cyclic chain terminates', () => {
    const getEntry = store([record('a', 800, ['b']), record('b', 700, ['a'])]);
    const incoming = { metadata: { lineage: { parents: ['a'] } }, categories: cats('remix') };
    assert.strictEqual(resolveTetherAnchor(incoming, getEntry).key, 'b');
  });

  it('nothing resolvable locally → the block anchors itself, never a wire claim', () => {
    const incoming = { metadata: { lineage: { parents: ['p1'], ancestors: ['root'] } }, categories: cats('remix') };
    assert.strictEqual(resolveTetherAnchor(incoming, store([])).resolvedFromStore, false);
  });
});
