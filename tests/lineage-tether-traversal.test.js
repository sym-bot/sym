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
 *
 * A third input was still the sender's: any STORED record counted as a step, including one this
 * node admitted without being able to verify who wrote it. §15.8 walks recursively VERIFIED
 * parents, so a step must be a record whose content address recomputes and whose authorship this
 * node established — it wrote the record itself, or verified the author's signature on admission.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { resolveTetherAnchor, storedRecordVerifies, createCMB } = require('../lib/core');

function store(entries) {
  const m = new Map(entries.map((e) => [e.key, e]));
  return (key) => m.get(key);
}
const cats = (t) => ({ focus: t, issue: 'x' });

/** A real record as the store holds it. `peerId: null` is a record this node wrote; a peer
 *  admission carries the frame handler's verification verdict in `_cmbVerified`. */
function entry(text, storedAt, parents = [], envelope = { peerId: null }) {
  const cmb = createCMB({
    categories: cats(text),
    createdBy: 'author',
    lineage: parents.length ? { parents, method: 'SVAF-v2' } : null,
  });
  return { key: cmb.metadata.key, storedAt, cmb, ...envelope };
}
const verifiedAdmission = { peerId: 'peer-1', _cmbVerified: true };
const unverifiedAdmission = { peerId: 'peer-1', _cmbVerified: false };

function remixOf(parents, extra = {}) {
  return { metadata: { key: 'cmb-' + 'e'.repeat(64), lineage: { parents, ...extra } }, categories: createCMB({ categories: cats('remix'), createdBy: 'peer' }).categories };
}

describe('§15.8 anchor resolution — sender-supplied inputs never pick the anchor', () => {
  it('a STORED record named only in lineage.ancestors is not the anchor', () => {
    // The receiver holds `unrelated` (stored earliest) for its own reasons; the sender names it as
    // an ancestor. It is not reachable through any parent, so it must not be chosen.
    const unrelated = entry('unrelated', 100);
    const p1 = entry('p1', 900);
    const getEntry = store([unrelated, p1]);
    const incoming = remixOf([p1.key], { ancestors: [unrelated.key, p1.key] });
    assert.strictEqual(resolveTetherAnchor(incoming, getEntry).key, p1.key);
  });

  it('a backdated author originTimestamp does not win the earliest-anchor race', () => {
    // Both are direct parents, so this isolates the ranking from the walk.
    const root = entry('root', 500, [], { peerId: null, originTimestamp: 500 });
    const p1 = entry('p1', 900, [], { peerId: null, originTimestamp: 1 });
    const incoming = remixOf([p1.key, root.key]);
    assert.strictEqual(resolveTetherAnchor(incoming, store([root, p1])).key, root.key);
  });

  it('a parents-only chain is walked through stored records to the earliest stored root', () => {
    const root = entry('root', 500);
    const mid = entry('mid', 700, [root.key], verifiedAdmission);
    const p1 = entry('p1', 900, [mid.key], verifiedAdmission);
    const r = resolveTetherAnchor(remixOf([p1.key]), store([root, mid, p1]));
    assert.strictEqual(r.key, root.key);
    assert.strictEqual(r.resolvedFromStore, true);
    assert.strictEqual(r.complete, true, 'every edge resolved and verified');
  });

  it('the walk cannot pass through a parent this node never stored', () => {
    // mid is missing locally, so root — though stored — is unreachable from p1.
    const root = entry('root', 500);
    const p1 = entry('p1', 900, ['cmb-' + '9'.repeat(64)]);
    const incoming = remixOf([p1.key], { ancestors: [root.key] });
    const r = resolveTetherAnchor(incoming, store([root, p1]));
    assert.strictEqual(r.key, p1.key);
    assert.strictEqual(r.complete, false, 'an unavailable parent is an incomplete proof, never a complete one (§15.2)');
  });

  it('a cyclic chain terminates', () => {
    // Content addresses cannot form a real cycle, so the lineage is set by hand to make one.
    const a = entry('a', 800);
    const b = entry('b', 700);
    a.cmb.metadata.lineage = { parents: [b.key] };
    b.cmb.metadata.lineage = { parents: [a.key] };
    assert.strictEqual(resolveTetherAnchor(remixOf([a.key]), store([a, b])).key, b.key);
  });

  it('a root is its own anchor', () => {
    const root = createCMB({ categories: cats('a root'), createdBy: 'peer' });
    const r = resolveTetherAnchor(root, store([]));
    assert.strictEqual(r.key, root.metadata.key);
    assert.strictEqual(r.resolvedFromStore, false);
    assert.strictEqual(r.complete, true);
  });

  it('nothing resolvable locally → the root is unverifiable, never the remix itself or a wire claim', () => {
    // A remix is not a root. Anchoring it to itself measured its drift from itself — always
    // "tethered" — and the integrator then signed that as a tether to a root nobody verified.
    const incoming = remixOf(['cmb-' + '1'.repeat(64)], { ancestors: ['cmb-' + '2'.repeat(64)] });
    const r = resolveTetherAnchor(incoming, store([]));
    assert.deepStrictEqual(r, { key: null, categories: null, resolvedFromStore: false, complete: false });
  });
});

describe('§15.8 anchor resolution — the walk passes only through VERIFIED records', () => {
  it('a stored parent admitted UNVERIFIED ends that branch — the root behind it is not reached', () => {
    // mid's parents are whatever its unverifiable author claimed. Following them let anyone who
    // could get one unsigned block admitted choose which stored record anchors the next remix.
    const root = entry('root', 500);
    const mid = entry('mid', 700, [root.key], unverifiedAdmission);
    const p1 = entry('p1', 900, [mid.key], verifiedAdmission);
    const r = resolveTetherAnchor(remixOf([p1.key]), store([root, mid, p1]));
    assert.strictEqual(r.key, p1.key, 'the oldest record reached through verified edges');
    assert.strictEqual(r.complete, false, 'the walk stopped at an unverifiable parent');
  });

  it('a remix whose only parent is an unverified admission has no anchor — the root is unverifiable', () => {
    const u = entry('unverified', 500, [], unverifiedAdmission);
    const r = resolveTetherAnchor(remixOf([u.key]), store([u]));
    assert.deepStrictEqual(r, { key: null, categories: null, resolvedFromStore: false, complete: false });
  });

  it('an admission with NO recorded verdict is unverified, not verified', () => {
    // A peer record stored without the frame handler's verdict (an older store, or an admission
    // path that never ran the signature check) proves nothing about its author.
    const u = entry('no verdict', 500, [], { peerId: 'peer-1' });
    assert.strictEqual(resolveTetherAnchor(remixOf([u.key]), store([u])).key, null);
  });

  it('a stored record whose categories no longer match its address is not walked', () => {
    const root = entry('root', 500);
    root.cmb.categories.focus.text = 'rewritten after it was addressed';
    const r = resolveTetherAnchor(remixOf([root.key]), store([root]));
    assert.strictEqual(r.key, null, 'content that does not answer to its key is not the content the key names');
  });

  it('two parents: the unverified branch ends, the verified branch still resolves', () => {
    const root = entry('root', 500);
    const u = entry('unverified older', 100, [], unverifiedAdmission);
    const r = resolveTetherAnchor(remixOf([u.key, root.key]), store([root, u]));
    assert.strictEqual(r.key, root.key, 'an older unverified record does not win the earliest-stored race');
    assert.strictEqual(r.complete, false);
  });
});

describe('storedRecordVerifies — what counts as a verified step', () => {
  it('a record this node wrote verifies', () => {
    const e = entry('own', 1);
    assert.strictEqual(storedRecordVerifies(e, e.key), true);
  });

  it('a peer admission verifies only with a recorded signature verdict', () => {
    const v = entry('peer verified', 1, [], verifiedAdmission);
    const u = entry('peer unverified', 1, [], unverifiedAdmission);
    assert.strictEqual(storedRecordVerifies(v, v.key), true);
    assert.strictEqual(storedRecordVerifies(u, u.key), false);
  });

  it('a record stored under a different key does not verify', () => {
    const e = entry('own', 1);
    assert.strictEqual(storedRecordVerifies(e, 'cmb-' + '3'.repeat(64)), false);
  });

  it('a pre-boundary record (no metadata section) does not verify — §7.8 unverified-legacy', () => {
    const e = entry('legacy', 1);
    const legacy = { key: e.key, peerId: null, cmb: { key: e.key, categories: e.cmb.categories } };
    assert.strictEqual(storedRecordVerifies(legacy, e.key), false);
  });

  it('a bare record with no store envelope does not verify', () => {
    const e = entry('bare', 1);
    assert.strictEqual(storedRecordVerifies(e.cmb, e.key), false);
  });
});

describe('§15.8 anchor resolution — the walk is bounded in work, not only in records visited', () => {
  // A record may name as many parents as fit in a frame. The walk counted only the stored records
  // it visited, so long parent lists grew the queue and the lookups without bound, and past its
  // budget the walk went on draining the queue instead of stopping (0.14.0 review C-F5).
  const unstored = (tag, n) => Array.from({ length: n }, (_, i) => `cmb-${tag}${String(i).padStart(63 - tag.length, '0')}`);
  function counting(entries) {
    const get = store(entries);
    const counter = { lookups: 0 };
    counter.getEntry = (key) => { counter.lookups++; return get(key); };
    return counter;
  }

  it('a record naming 30,000 parents costs at most 16,384 lookups, and is incomplete', () => {
    const c = counting([]);
    const r = resolveTetherAnchor(remixOf(unstored('a', 30000)), c.getEntry);
    assert.ok(c.lookups <= 4 * 4096, `${c.lookups} lookups`);
    assert.strictEqual(r.complete, false);
    assert.strictEqual(r.key, null);
  });

  it('long parent lists on the verified records it steps onto do not grow the walk', () => {
    // A verified chain of 40 records, each also naming 2,000 parents this node never stored.
    const chain = [];
    let parent = null;
    for (let i = 0; i < 40; i++) {
      const e = entry(`chain ${i}`, 1000 + i, parent ? [parent] : [], verifiedAdmission);
      e.cmb.metadata.lineage = { parents: [...(parent ? [parent] : []), ...unstored(`b${i}x`, 2000)], method: 'SVAF-v2' };
      chain.push(e);
      parent = e.key;
    }
    const c = counting(chain);
    const r = resolveTetherAnchor(remixOf([parent]), c.getEntry);
    assert.ok(c.lookups <= 4 * 4096, `${c.lookups} lookups`);
    assert.strictEqual(r.complete, false, 'what it could not queue is not proven');
    assert.strictEqual(r.resolvedFromStore, true, 'the verified records it did reach still anchor it');
  });
});
