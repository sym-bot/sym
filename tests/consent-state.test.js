'use strict';

/**
 * Consent state machine unit tests — exhaustive 3×3 matrix.
 *
 * Mirrors `axonos-consent/tests/consent_interop.rs:286-311`
 * (the APPLY_FRAME — EXHAUSTIVE STATE×FRAME TABLE block) plus
 * the SM (state machine) and gossip helper tests.
 *
 * These tests do NOT load the canonical interop vector file —
 * the vector-driven tests live in `tests/consent-interop.test.js`
 * (to be added in step 8 of the implementation checklist). The
 * tests here exercise the state machine in isolation, including
 * the WITHDRAWN→any rejection path that no canonical vector
 * exercises (see §6.1.1 Observation 3 of the joint paper §6
 * design doc).
 *
 * Copyright (c) 2026 SYM.BOT Ltd. Apache 2.0 License.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  ConsentState,
  ALL_STATES,
  FrameType,
  TransitionError,
  TRANSITIONS,
  applyFrame,
  allowsCognitiveFrames,
  isValidState,
  isValidFrameType,
} = require('../lib/consent/state');

// ─── Helpers: build minimal frame objects ──────────────────────────
//
// The state machine consumes only the .type discriminator. These
// helpers produce the simplest possible valid frame shapes.

const wf = () => ({ type: FrameType.WITHDRAW });
const sf = () => ({ type: FrameType.SUSPEND  });
const rf = () => ({ type: FrameType.RESUME   });

// ─── Row 1: GRANTED ────────────────────────────────────────────────
// Mirrors axonos-consent/tests/consent_interop.rs:299-301

test('apply_frame: GRANTED + withdraw → WITHDRAWN', () => {
  const r = applyFrame(ConsentState.GRANTED, wf());
  assert.deepEqual(r, { ok: true, newState: ConsentState.WITHDRAWN });
});

test('apply_frame: GRANTED + suspend → SUSPENDED', () => {
  const r = applyFrame(ConsentState.GRANTED, sf());
  assert.deepEqual(r, { ok: true, newState: ConsentState.SUSPENDED });
});

test('apply_frame: GRANTED + resume → GRANTED (silently ignored, §4.2)', () => {
  const r = applyFrame(ConsentState.GRANTED, rf());
  assert.deepEqual(r, { ok: true, newState: ConsentState.GRANTED });
});

// ─── Row 2: SUSPENDED ──────────────────────────────────────────────
// Mirrors axonos-consent/tests/consent_interop.rs:304-306

test('apply_frame: SUSPENDED + withdraw → WITHDRAWN', () => {
  const r = applyFrame(ConsentState.SUSPENDED, wf());
  assert.deepEqual(r, { ok: true, newState: ConsentState.WITHDRAWN });
});

test('apply_frame: SUSPENDED + suspend → SUSPENDED (idempotent, §4.2)', () => {
  const r = applyFrame(ConsentState.SUSPENDED, sf());
  assert.deepEqual(r, { ok: true, newState: ConsentState.SUSPENDED });
});

test('apply_frame: SUSPENDED + resume → GRANTED', () => {
  const r = applyFrame(ConsentState.SUSPENDED, rf());
  assert.deepEqual(r, { ok: true, newState: ConsentState.GRANTED });
});

// ─── Row 3: WITHDRAWN — all rejected ───────────────────────────────
// Mirrors axonos-consent/tests/consent_interop.rs:309-311
//
// This row is *not* exercised by any canonical interop vector
// (see §6.1.1 Observation 3 of the joint paper §6 design doc).
// Its only test coverage in either implementation is here and in
// the AxonOS unit tests. The Node.js port preserves the same
// rejection semantics for cross-implementation parity (§6.5 Gap 1
// Interpretation A).

test('apply_frame: WITHDRAWN + withdraw → REJECT (§6.5 Gap 1 Interp A)', () => {
  const r = applyFrame(ConsentState.WITHDRAWN, wf());
  assert.deepEqual(r, { ok: false, error: TransitionError.ALREADY_WITHDRAWN });
});

test('apply_frame: WITHDRAWN + suspend → REJECT (§4.2 line 243)', () => {
  const r = applyFrame(ConsentState.WITHDRAWN, sf());
  assert.deepEqual(r, { ok: false, error: TransitionError.ALREADY_WITHDRAWN });
});

test('apply_frame: WITHDRAWN + resume → REJECT (§4.2 line 243)', () => {
  const r = applyFrame(ConsentState.WITHDRAWN, rf());
  assert.deepEqual(r, { ok: false, error: TransitionError.ALREADY_WITHDRAWN });
});

// ─── Exhaustiveness check ──────────────────────────────────────────
//
// Verify the transition table covers every (state, frame) pair.
// This catches future additions to either enum that forget to
// add a corresponding cell.

test('TRANSITIONS table is exhaustive over ALL_STATES × FrameType', () => {
  const allFrameTypes = Object.values(FrameType);
  for (const state of ALL_STATES) {
    const row = TRANSITIONS[state];
    assert.ok(row, `missing row for state ${state}`);
    for (const ft of allFrameTypes) {
      assert.ok(
        Object.prototype.hasOwnProperty.call(row, ft),
        `missing cell for (${state}, ${ft})`
      );
    }
    // No extra keys allowed.
    assert.equal(
      Object.keys(row).length,
      allFrameTypes.length,
      `state ${state} has unexpected keys: ${Object.keys(row).join(', ')}`
    );
  }
});

// ─── Frozen-table contract ─────────────────────────────────────────
//
// The transition table and its rows must be deeply immutable so
// that downstream code (or a malicious test) cannot mutate the
// state machine at runtime.

test('TRANSITIONS table is frozen', () => {
  assert.equal(Object.isFrozen(TRANSITIONS), true);
  for (const state of ALL_STATES) {
    assert.equal(
      Object.isFrozen(TRANSITIONS[state]),
      true,
      `row for ${state} is not frozen`
    );
  }
});

test('ConsentState enum is frozen', () => {
  assert.equal(Object.isFrozen(ConsentState), true);
});

test('FrameType enum is frozen', () => {
  assert.equal(Object.isFrozen(FrameType), true);
});

test('TransitionError enum is frozen', () => {
  assert.equal(Object.isFrozen(TransitionError), true);
});

// ─── allowsCognitiveFrames ─────────────────────────────────────────
// Mirrors axonos-consent/src/state.rs:104

test('allowsCognitiveFrames: GRANTED only', () => {
  assert.equal(allowsCognitiveFrames(ConsentState.GRANTED), true);
  assert.equal(allowsCognitiveFrames(ConsentState.SUSPENDED), false);
  assert.equal(allowsCognitiveFrames(ConsentState.WITHDRAWN), false);
});

// ─── Type discipline / programmer-error guards ─────────────────────
//
// applyFrame and allowsCognitiveFrames distinguish "programmer
// error" (TypeError) from "state-machine rejection" ({ok:false}).
// The two must never collapse into the same code path.

test('applyFrame throws TypeError on invalid state', () => {
  assert.throws(
    () => applyFrame('not-a-state', wf()),
    TypeError
  );
});

test('applyFrame throws TypeError on missing frame', () => {
  assert.throws(
    () => applyFrame(ConsentState.GRANTED, null),
    TypeError
  );
  assert.throws(
    () => applyFrame(ConsentState.GRANTED, undefined),
    TypeError
  );
});

test('applyFrame throws TypeError on invalid frame.type', () => {
  assert.throws(
    () => applyFrame(ConsentState.GRANTED, { type: 'consent-bogus' }),
    TypeError
  );
});

test('allowsCognitiveFrames throws TypeError on invalid state', () => {
  assert.throws(
    () => allowsCognitiveFrames('not-a-state'),
    TypeError
  );
});

// ─── isValidState / isValidFrameType helpers ───────────────────────

test('isValidState: positive cases', () => {
  for (const s of ALL_STATES) assert.equal(isValidState(s), true);
});

test('isValidState: negative cases', () => {
  for (const s of [null, undefined, '', 'GRANTED', 'unknown', 0, {}]) {
    assert.equal(isValidState(s), false);
  }
});

test('isValidFrameType: positive cases', () => {
  for (const ft of Object.values(FrameType)) {
    assert.equal(isValidFrameType(ft), true);
  }
});

test('isValidFrameType: negative cases', () => {
  for (const ft of [null, undefined, '', 'WITHDRAW', 'consent-bogus', 0]) {
    assert.equal(isValidFrameType(ft), false);
  }
});
