'use strict';

/**
 * Consent state machine — MMP Consent Extension v0.1.0, §4.
 *
 * Mirrors the AxonOS reference implementation at
 * `axonos-consent/src/state.rs` (state.rs:38-105). The Node.js port
 * preserves the exhaustive 3×3 transition table with no wildcard
 * fallback, frozen at module load so transitions cannot be mutated
 * at runtime.
 *
 * ## Spec mapping
 *
 * - States: §4 / `mmp-consent-v0.1.0.md` lines 64-72
 * - Transition table: §4 / `mmp-consent-v0.1.0.md` lines 220-225
 * - Idempotency: §4.2 / line 239
 * - "consent-resume from GRANTED MUST be silently ignored": §4.2 / line 243
 * - WITHDRAWN is terminal: §4 / line 227
 * - `consent-withdraw` from WITHDRAWN: SPEC GAP — see §6.5 Gap 1 of
 *   the joint paper §6 design doc. This implementation adopts
 *   AxonOS Interpretation A (reject) for cross-implementation parity
 *   with `axonos-consent/src/state.rs:49`.
 * - `allowsCognitiveFrames`: §6.1 / line 307 (cognitive frames flow
 *   only in GRANTED state)
 *
 * ## Result discipline
 *
 * `applyFrame` returns a discriminated result object, not an
 * exception. The caller MUST branch on `result.ok` before reading
 * either side. This is the JavaScript analogue of Rust's `Result<T, E>`
 * and `#[must_use]`. Throwing exceptions is reserved for programmer
 * errors (e.g. passing an undefined frame), not for state-machine
 * rejection of valid frames in invalid states.
 *
 * Copyright (c) 2026 SYM.BOT Ltd. Apache 2.0 License.
 */

// ─── State enum ────────────────────────────────────────────────────
//
// String literals are deliberate: they match the canonical wire
// format and the `state_before`/`state_after` field values in the
// AxonOS interop test vectors verbatim, eliminating any translation
// step in the test runner.

const ConsentState = Object.freeze({
  GRANTED:   'granted',
  SUSPENDED: 'suspended',
  WITHDRAWN: 'withdrawn',
});

const ALL_STATES = Object.freeze([
  ConsentState.GRANTED,
  ConsentState.SUSPENDED,
  ConsentState.WITHDRAWN,
]);

function isValidState(s) {
  return s === ConsentState.GRANTED
      || s === ConsentState.SUSPENDED
      || s === ConsentState.WITHDRAWN;
}

// ─── Frame type enum (state-machine-relevant subset) ───────────────
//
// The state machine cares only about the frame *kind*. Field-level
// validation is the responsibility of `invariants.js`. The frame
// objects passed in here have already been parsed by `frames.js`;
// the state machine consumes only the discriminator.

const FrameType = Object.freeze({
  WITHDRAW: 'consent-withdraw',
  SUSPEND:  'consent-suspend',
  RESUME:   'consent-resume',
});

function isValidFrameType(t) {
  return t === FrameType.WITHDRAW
      || t === FrameType.SUSPEND
      || t === FrameType.RESUME;
}

// ─── Transition errors ─────────────────────────────────────────────

const TransitionError = Object.freeze({
  ALREADY_WITHDRAWN: 'ALREADY_WITHDRAWN',
});

// ─── Transition table (exhaustive 3×3) ─────────────────────────────
//
// Mirrors `axonos-consent/src/state.rs:46-62` exactly. Every cell
// is explicit. There is no wildcard fallback. Adding a new state
// or frame type requires updating this table; the test runner
// asserts the table is exhaustive over `ALL_STATES × FrameType`.
//
// The table is doubly frozen: each row is frozen, and the outer
// object is frozen. Object.freeze is shallow, so we freeze rows
// individually to prevent any path of mutation.
//
// Spec source: §4 transition table at mmp-consent-v0.1.0.md:220-225
// AxonOS source: state.rs:46-62 (apply_frame match arms)
//
// Reading this table:
//   TRANSITIONS[currentState][frameType] = next state OR error code
//
// All values are either a ConsentState (success) or a string from
// TransitionError (failure). The applyFrame function below wraps
// these into discriminated result objects.

const _GRANTED_ROW = Object.freeze({
  [FrameType.WITHDRAW]: ConsentState.WITHDRAWN,
  [FrameType.SUSPEND]:  ConsentState.SUSPENDED,
  // §4.2 line 243: consent-resume from GRANTED MUST be silently
  // ignored. The "silently ignored" semantics are no error and no
  // state change — i.e. the result is Ok(GRANTED).
  [FrameType.RESUME]:   ConsentState.GRANTED,
});

const _SUSPENDED_ROW = Object.freeze({
  [FrameType.WITHDRAW]: ConsentState.WITHDRAWN,
  // §4.2 line 239: a second consent-suspend while suspended is a
  // no-op. Idempotent.
  [FrameType.SUSPEND]:  ConsentState.SUSPENDED,
  [FrameType.RESUME]:   ConsentState.GRANTED,
});

const _WITHDRAWN_ROW = Object.freeze({
  // §4 line 227: WITHDRAWN is terminal. AxonOS state.rs:49-51
  // rejects all three frame types from WITHDRAWN. The withdraw
  // case specifically is a documented spec gap — see §6.5 Gap 1
  // of the joint paper §6 design doc. This implementation adopts
  // AxonOS Interpretation A (reject) for cross-implementation
  // parity.
  [FrameType.WITHDRAW]: TransitionError.ALREADY_WITHDRAWN,
  [FrameType.SUSPEND]:  TransitionError.ALREADY_WITHDRAWN,
  [FrameType.RESUME]:   TransitionError.ALREADY_WITHDRAWN,
});

const TRANSITIONS = Object.freeze({
  [ConsentState.GRANTED]:   _GRANTED_ROW,
  [ConsentState.SUSPENDED]: _SUSPENDED_ROW,
  [ConsentState.WITHDRAWN]: _WITHDRAWN_ROW,
});

// ─── applyFrame ────────────────────────────────────────────────────

/**
 * Apply a consent frame to a current state.
 *
 * Returns a discriminated result object:
 *   - { ok: true,  newState: <ConsentState> } on success
 *   - { ok: false, error: <TransitionError> } on rejection
 *
 * Mirrors `axonos-consent/src/state.rs:46-62` (apply_frame).
 *
 * The function does NOT validate frame field invariants — that is
 * the responsibility of `invariants.js::checkFrame()`, which the
 * engine pipeline calls before this function. The state machine
 * consumes only the frame's `type` discriminator.
 *
 * @param {string} currentState - one of ConsentState
 * @param {{type: string}} frame - parsed consent frame with .type
 * @returns {{ok: true, newState: string} | {ok: false, error: string}}
 * @throws {TypeError} if currentState or frame.type are not valid
 *   enum values — this is a programmer error, not a state-machine
 *   rejection, and is intentionally distinct from a {ok:false} result.
 */
function applyFrame(currentState, frame) {
  if (!isValidState(currentState)) {
    throw new TypeError(
      `applyFrame: invalid currentState "${currentState}". ` +
      `Must be one of: ${ALL_STATES.join(', ')}`
    );
  }
  if (frame == null || typeof frame.type !== 'string') {
    throw new TypeError(
      `applyFrame: frame must be an object with a string .type field`
    );
  }
  if (!isValidFrameType(frame.type)) {
    throw new TypeError(
      `applyFrame: invalid frame.type "${frame.type}". ` +
      `Must be one of: ${Object.values(FrameType).join(', ')}`
    );
  }

  const next = TRANSITIONS[currentState][frame.type];

  // The transition table value is either a ConsentState string
  // (success) or a TransitionError string (failure). We branch
  // on whether it appears in the TransitionError set.
  if (next === TransitionError.ALREADY_WITHDRAWN) {
    return { ok: false, error: TransitionError.ALREADY_WITHDRAWN };
  }
  return { ok: true, newState: next };
}

// ─── allowsCognitiveFrames ─────────────────────────────────────────

/**
 * Per spec §6.1 (line 307): cognitive frames flow only when consent
 * is GRANTED. SUSPENDED and WITHDRAWN both gate cognitive frames.
 *
 * Mirrors `axonos-consent/src/state.rs:104` (allows_cognitive_frames).
 *
 * @param {string} state - one of ConsentState
 * @returns {boolean}
 */
function allowsCognitiveFrames(state) {
  if (!isValidState(state)) {
    throw new TypeError(
      `allowsCognitiveFrames: invalid state "${state}"`
    );
  }
  return state === ConsentState.GRANTED;
}

// ─── Module exports ────────────────────────────────────────────────

module.exports = {
  ConsentState,
  ALL_STATES,
  isValidState,
  FrameType,
  isValidFrameType,
  TransitionError,
  TRANSITIONS,
  applyFrame,
  allowsCognitiveFrames,
};
