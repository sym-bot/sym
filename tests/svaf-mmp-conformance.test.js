'use strict';
const { describe, it } = require('node:test');
const assert = require('node:assert');
const {
  computeCategoryVerdicts, CATEGORY_VERDICT, DEFAULT_REDUNDANCY_THRESHOLD,
} = require('../lib/core/svaf-heuristic.js');

/**
 * svaf-mmp-conformance.test.js — this engine is the REFERENCE for MMP §9.2, and nothing asserted it.
 *
 * dev-team-3 built a level-1 mechanic where an invited remote agent tells the mesh something, and
 * every word came back `focus: rejected`, so a mesh could never learn from a node it had just
 * consented to hear. The cause was in its own implementation, not here — but chasing it showed that
 * sym's conformance to these clauses rested entirely on nobody having changed the file. The
 * behaviour was right and unguarded, which is the state a defect walks into.
 *
 * Each case names the clause it holds this code to, so a failure says which sentence of MMP broke
 * rather than which number moved. Clause text is quoted from the published spec at
 * meshcognition.org/spec/mmp/coupling, read 2026-09-16.
 */

const CONFIG = { stableThreshold: 0.35, guardedThreshold: 0.75, redundancyThreshold: DEFAULT_REDUNDANCY_THRESHOLD };

describe('MMP §9.2 — SVAF decision rules, asserted against the reference implementation', () => {
  it('§9.2.1 invariant 4 — a category with NO anchor is silent and excluded, never scored as novel', () => {
    // "If A holds no anchor carrying category c, δf is undefined and that category MUST be
    //  excluded from the fieldDrift aggregation and the redundancy max — not treated as
    //  maximally novel."
    const verdicts = computeCategoryVerdicts({ focus: undefined, issue: 0.1 }, CONFIG, {});
    assert.strictEqual(verdicts.focus, CATEGORY_VERDICT.SILENT,
      'an unanchored category must be silent — the failure mode is scoring it 1.0 and rejecting a first word');
    assert.notStrictEqual(verdicts.focus, CATEGORY_VERDICT.REJECT);
  });

  it('§9.2 — silent is NOT a decision, and never appears as one of the four graded bands', () => {
    // "silent is not a decision: it reports that δf was undefined … a verifier MUST NOT read it
    //  as a decision."
    const graded = [CATEGORY_VERDICT.ADMIT, CATEGORY_VERDICT.GUARD, CATEGORY_VERDICT.REDUNDANT, CATEGORY_VERDICT.REJECT];
    assert.ok(!graded.includes(CATEGORY_VERDICT.SILENT), 'silent must not be one of the graded bands');
    const allUndefined = computeCategoryVerdicts({}, CONFIG, {});
    assert.ok(Object.values(allUndefined).every((v) => v === CATEGORY_VERDICT.SILENT),
      'with nothing evaluable every category is silent, not rejected');
  });

  it('§9.2 — a category is graded on ITS OWN drift, with no temporal term folded in', () => {
    // The temporal term is an AGGREGATE term: totalDrift = (1 − λ)·fieldDrift + λ·temporalDrift.
    // Folding age into a per-category band pushes every field toward rejection individually,
    // which is how an implementation can reject a field while the record is merely guarded.
    const drifts = { focus: 0.2, issue: 0.5, intent: 0.9 };
    const a = computeCategoryVerdicts(drifts, CONFIG, {});
    const b = computeCategoryVerdicts(drifts, { ...CONFIG }, {});
    assert.deepStrictEqual(a, b, 'the same drifts must grade identically — nothing else may enter the band');
    assert.strictEqual(a.focus, CATEGORY_VERDICT.ADMIT);
    assert.strictEqual(a.issue, CATEGORY_VERDICT.GUARD);
    assert.strictEqual(a.intent, CATEGORY_VERDICT.REJECT);
  });

  it('§9.2 — redundancy is decided on the NEAREST-anchor basis, and is unreachable without one', () => {
    // "κ = redundant if max(δ_f_near) < T_redundant". Without that basis the category is graded
    // on the fused readout and is never called redundant — a weaker claim, not a wrong one.
    const near = computeCategoryVerdicts({ focus: 0.2 }, CONFIG, { focus: DEFAULT_REDUNDANCY_THRESHOLD / 2 });
    assert.strictEqual(near.focus, CATEGORY_VERDICT.REDUNDANT);
    const noBasis = computeCategoryVerdicts({ focus: 0.2 }, CONFIG, {});
    assert.strictEqual(noBasis.focus, CATEGORY_VERDICT.ADMIT, 'no nearest basis ⇒ never redundant');
  });

  it('§9.2 — the five-value vocabulary is exactly the published one', () => {
    // "MUST use exactly these five values: admit, guard, redundant, reject, silent."
    assert.deepStrictEqual(
      Object.values(CATEGORY_VERDICT).slice().sort(),
      ['admit', 'guard', 'redundant', 'reject', 'silent']);
  });
});
