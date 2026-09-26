'use strict';

/**
 * MMP §9.2.1 (2026-09-26 draft): coverage decides evaluability, α_f acts only in the aggregate.
 *
 * The defect this pins: evaluability used to be read off Σ_a α_f·max(cos,0)·decay·conf, so three
 * different situations — no memory of f, memory of f pointing away, and memory of f weighted small —
 * all read as "no anchor" and bootstrap-admitted a record against a populated store. Each case below
 * is one corner of that: the per-category cases drive computeCategoryDrifts with synthetic vectors
 * (the full evaluator re-encodes every vector from text, so geometry cannot be injected there); the
 * aggregate, lens and redundancy cases drive processHeuristicSVAF end to end with text fixtures.
 *
 * Mirrors xmesh-core's test of the same name: both implementations answer the same corners.
 */
const { describe, it } = require('node:test');
const assert = require('node:assert');
const { computeCategoryDrifts, processHeuristicSVAF, createCMB, computeLineageTether } = require('../lib/core');

const CAT7 = ['focus', 'issue', 'intent', 'motivation', 'commitment', 'perspective', 'mood'];
const NOW = 1_780_000_000_000;
const TAU = 1000; // seconds

const policy = (categoryWeights) => ({
  stableThreshold: 0.25, guardedThreshold: 0.5, temporalLambda: 0.3, freshnessSeconds: TAU,
  ...(categoryWeights ? { categoryWeights } : {}),
});
const uniform = (a) => Object.fromEntries(CAT7.map((f) => [f, a]));

// ── per-category geometry (synthetic vectors) ────────────────────────────────────────────────

const incoming = { focus: { text: 'incoming', vector: [1, 0, 0, 0] } };
const anchor = (vector, { ageTau = 0, confidence, text = 'stored' } = {}) => ({
  categories: { focus: { text, vector } },
  storedAt: NOW - ageTau * TAU * 1000,
  ...(confidence === undefined ? {} : { confidence }),
});
const drifts = (anchors, categoryWeights) =>
  computeCategoryDrifts({ incomingCategories: incoming, anchors, config: policy(categoryWeights), now: NOW, tau: TAU });

describe('§9.2.1 coverage decides evaluability — per category', () => {
  it('no anchor carries f → silent, cause no-anchor', () => {
    const r = drifts([]);
    assert.equal(r.categoryDrifts.focus, undefined);
    assert.equal(r.silentCauses.focus, 'no-anchor');
  });

  it('a similar anchor is judged near zero', () => {
    const r = drifts([anchor([1, 0.1, 0, 0])]);
    assert.ok(r.categoryDrifts.focus < 0.01, `δ=${r.categoryDrifts.focus}`);
    assert.equal(r.silentCauses.focus, undefined);
  });

  it('an ORTHOGONAL anchor is covered-but-foreign: δ=1, never silent', () => {
    const r = drifts([anchor([0, 1, 0, 0])]);
    assert.equal(r.categoryDrifts.focus, 1.0);
    assert.equal(r.nearestDrifts.focus, 1.0);
    assert.equal(r.silentCauses.focus, undefined, 'memory pointing away is not missing memory');
  });

  it('an OPPOSING anchor is covered-but-foreign: δ=1, never silent', () => {
    const r = drifts([anchor([-1, 0, 0, 0])]);
    assert.equal(r.categoryDrifts.focus, 1.0);
    assert.equal(r.nearestDrifts.focus, 1.0);
    assert.equal(r.silentCauses.focus, undefined);
  });

  it('F1: an old ALIGNED anchor near the coverage floor reads its direction (δ≈0.5), not foreign', () => {
    // presence = exp(-age/τ) = 1.5e-8, cos = 0.5 → Σw = 7.5e-9, which an absolute 1e-8 floor would
    // call foreign. The direction test compares Σw with ε·cover_f and sees an aligned anchor.
    const ageTau = -Math.log(1.5e-8);
    const r = drifts([anchor([0.5, Math.sqrt(0.75), 0, 0], { ageTau })]);
    assert.ok(Math.abs(r.categoryDrifts.focus - 0.5) < 1e-9, `δ=${r.categoryDrifts.focus}`);
  });

  it('coverage decays: an aligned anchor 20τ old no longer covers f', () => {
    const r = drifts([anchor([1, 0, 0, 0], { ageTau: 20 })]);
    assert.equal(r.categoryDrifts.focus, undefined);
    assert.equal(r.silentCauses.focus, 'no-anchor');
  });

  it('an anchor in a different vector space is skipped, not compared', () => {
    const r = drifts([anchor([1, 0, 0])]);
    assert.equal(r.categoryDrifts.focus, undefined);
    assert.equal(r.silentCauses.focus, 'no-anchor');
  });

  it('α_f never moves δ_f: 1e-12, 1 and 3 give identical per-category drifts', () => {
    const mixed = [anchor([1, 0.3, 0, 0]), anchor([0.2, 1, 0.1, 0], { ageTau: 0.5, confidence: 0.4 }), anchor([0, 0, 1, 0])];
    const base = drifts(mixed, { focus: 1 });
    assert.ok(base.categoryDrifts.focus > 0 && base.categoryDrifts.focus < 1, 'fixture must be interior');
    for (const a of [1e-12, 3]) {
      const r = drifts(mixed, { focus: a });
      assert.equal(r.categoryDrifts.focus, base.categoryDrifts.focus, `α=${a}`);
      assert.equal(r.nearestDrifts.focus, base.nearestDrifts.focus, `α=${a}`);
    }
  });

  it('a tiny α on a populated store is still judged, not read as missing memory', () => {
    const r = drifts([anchor([0, 1, 0, 0])], { focus: 1e-12 });
    assert.equal(r.categoryDrifts.focus, 1.0);
    assert.equal(r.silentCauses.focus, undefined);
  });
});

// ── the policy gate ──────────────────────────────────────────────────────────────────────────

const fullCategories = (over = {}) => ({
  focus: 'relay tls renewal', issue: 'certificate expires friday', intent: 'renew before expiry',
  motivation: 'avoid an outage', commitment: 'renewal scheduled', perspective: 'operator',
  mood: { text: 'steady', valence: 0.2, arousal: 0.2 }, ...over,
});
const record = (categories) => createCMB({ categories, createdBy: 'sender' });
// An anchor as the store holds it: categories carry text only; the evaluator encodes locally.
const stored = (categories) => {
  const cats = {};
  for (const f of CAT7) {
    if (categories[f] === undefined) continue;
    cats[f] = typeof categories[f] === 'string' ? { text: categories[f] } : { ...categories[f] };
  }
  return { categories: cats, storedAt: NOW };
};
const evaluate = (incomingCategories, anchors, categoryWeights) => processHeuristicSVAF({
  msg: { content: 'x', source: 'sender', cmb: record(incomingCategories), tags: [] },
  peerName: 'peer', localName: 'local',
  originTs: NOW, now: NOW, ageSeconds: 0, recentCMBs: anchors, config: policy(categoryWeights),
});

describe('§9.2.1 category weights are policy — complete or refused', () => {
  for (const [label, weights, pattern] of [
    ['all seven zero', uniform(0), /every category weight is 0/],
    ['NaN', { focus: NaN }, /finite numbers ≥ 0/],
    ['negative', { focus: -1 }, /finite numbers ≥ 0/],
    ['Infinity', { focus: Infinity }, /finite numbers ≥ 0/],
    ['a string', { focus: '1' }, /finite numbers ≥ 0/],
  ]) {
    it(`refuses ${label}`, async () => {
      await assert.rejects(evaluate(fullCategories(), [], weights), pattern);
    });
  }

  it('accepts a partial map whose unsupplied categories weigh 1', async () => {
    const r = await evaluate(fullCategories(), [], { focus: 0 });
    assert.equal(r.accepted, true);
  });
});

// ── aggregate, lens and redundancy (end to end) ──────────────────────────────────────────────

describe('§9.2.1 aggregate — α acts here and only here', () => {
  it('empty memory bootstraps as aligned, cause empty-memory', async () => {
    const r = await evaluate(fullCategories(), []);
    assert.equal(r.accepted, true);
    assert.equal(r.decision, 'aligned');
    assert.equal(r.coldStartCause, 'empty-memory');
  });

  it('a uniformly tiny α on a store holding the same record is JUDGED redundant, not bootstrapped', async () => {
    const cats = fullCategories();
    const r = await evaluate(cats, [stored(cats)], uniform(1e-12));
    assert.equal(r.decision, 'redundant');
    assert.equal(r.coldStartCause, undefined);
  });

  it('uniform scaling of α leaves the verdict and totalDrift unchanged (no cliff before 0)', async () => {
    const base = fullCategories();
    const moved = fullCategories({ issue: 'the certificate was already renewed on tuesday', commitment: 'nothing to do' });
    const results = [];
    for (const a of [1e-12, 1e-6, 1, 3]) results.push(await evaluate(moved, [stored(base)], uniform(a)));
    for (const r of results.slice(1)) {
      assert.equal(r.decision, results[0].decision);
      assert.ok(Math.abs(r.totalDrift - results[0].totalDrift) < 1e-12, `${r.totalDrift} vs ${results[0].totalDrift}`);
    }
  });

  it('α=0 disables a covered category: silent, cause zero-weight, and the rest are still judged', async () => {
    const cats = fullCategories();
    const weights = { ...uniform(0), focus: 1 };
    const r = await evaluate(cats, [stored(cats)], weights);
    assert.equal(r.decision, 'redundant', 'focus is covered and weighted, so the record is judged');
    assert.equal(r.coldStartCause, undefined);
    for (const f of CAT7.filter((c) => c !== 'focus')) {
      assert.equal(r.categoryVerdicts[f], 'silent', f);
      assert.equal(r.silentCauses[f], 'zero-weight', f);
    }
  });

  it('covered only where α=0 → lens-level cold start: admitted GUARDED, cause lens-uncovered', async () => {
    const cats = fullCategories();
    const r = await evaluate(cats, [stored({ issue: cats.issue })], { issue: 0 });
    assert.equal(r.accepted, true);
    assert.equal(r.decision, 'guarded', 'memory the receiver chose not to consult is not an alignment');
    assert.equal(r.coldStartCause, 'lens-uncovered');
    assert.equal(r.silentCauses.issue, 'zero-weight');
  });

  it('a disabled category is excluded from redundancy (differential against α=1)', async () => {
    const base = fullCategories();
    const moved = fullCategories({ issue: 'a completely unrelated question about lunch plans' });
    const weighed = await evaluate(moved, [stored(base)], uniform(1));
    assert.notEqual(weighed.decision, 'redundant', 'fixture: the moved issue must clear the redundancy floor');
    const disabled = await evaluate(moved, [stored(base)], { ...uniform(1), issue: 0 });
    assert.equal(disabled.decision, 'redundant');
  });
});

// ── §15.8 lineage tether — the same α rule ───────────────────────────────────────────────────

describe('§15.8 tether — α=0 disables a category, it does not weigh 1', () => {
  const remixCategories = { focus: { vector: [1, 0] }, issue: { vector: [1, 0] } };
  const anchorCategories = { focus: { vector: [1, 0] }, issue: { vector: [-1, 0] } };
  const tether = (categoryWeights) => computeLineageTether({ remixCategories, anchorCategories, categoryWeights, guardedThreshold: 0.5 });

  it('control: at α=1 the opposing category severs the chain', () => {
    const r = tether({ focus: 1, issue: 1 });
    assert.equal(r.tethered, false);
    assert.ok(Math.abs(r.drift - 1) < 1e-12);
  });

  it('at α=0 the disabled category neither severs nor keeps the chain', () => {
    const r = tether({ focus: 1, issue: 0 });
    assert.equal(r.checked, true);
    assert.equal(r.tethered, true);
    assert.deepEqual(r.evaluableCategories, ['focus']);
  });

  it('every comparable category disabled → not checked (never severed on ignorance)', () => {
    const r = tether({ focus: 0, issue: 0 });
    assert.equal(r.checked, false);
    assert.equal(r.drift, null);
  });
});
