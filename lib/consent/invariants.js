'use strict';

/**
 * Consent frame invariants — MMP Consent Extension v0.1.0, §10
 * conformance enforcement.
 *
 * Mirrors `axonos-consent/src/invariants.rs` (172 lines). The
 * Node.js port preserves the MUST/SHOULD distinction:
 *
 *   MUST violations  → InvariantViolation, frame is rejected
 *   SHOULD warnings  → InvariantWarning, frame is accepted, warning logged
 *   MAY              → no enforcement, no log entry
 *
 * The function is called by the engine pipeline AFTER `parseFrame`
 * has produced a typed frame. Field-shape rejections (missing type,
 * unknown scope) live in the parser; semantic invariants live here.
 *
 * ## Spec mapping
 *
 * | Check | Spec | AxonOS source |
 * |---|---|---|
 * | timestamp != 0 (MUST) | implicit (positive uint expected) | invariants.rs:113-114, 135-136, 150-151 |
 * | reason length <= MAX_REASON_LEN (MUST) | not in spec — Denis-defined bound | invariants.rs:117-121 |
 * | withdraw SHOULD have timestamp | §3.1 line 105 (timestamp marked OPTIONAL but recommended for audit) | invariants.rs:124-126 |
 * | withdraw SHOULD have reasonCode | §3.4 (reason code recommended for audit trail) | invariants.rs:129-131 |
 * | suspend SHOULD have reasonCode | §3.2 line 147 (reasonCode marked OPTIONAL but recommended) | invariants.rs:144-146 |
 *
 * ## Spec notes (§6.5 of joint paper §6 design doc)
 *
 * Two checks here are not directly mandated by spec text but are
 * preserved for cross-implementation parity with AxonOS:
 *
 * - **Zero-timestamp rejection.** Spec §3.1 declares timestamp as
 *   `uint64 OPTIONAL` and does not define semantics for the value 0.
 *   AxonOS treats `Some(0)` as a MUST violation (invariants.rs:113).
 *   The implicit reading: a timestamp value of 0 represents the unix
 *   epoch start, which is never a valid wire timestamp in 2026+. We
 *   adopt the same interpretation. This is logged as §6.5 Note 5
 *   for v0.1.1 spec clarification.
 *
 * - **MAX_REASON_LEN = 64 bytes.** The spec does not bound the
 *   `reason` string. AxonOS bounds it at 64 bytes via the ReasonBuf
 *   fixed-size buffer (frames.rs:16). Node.js has no such physical
 *   bound, but enforces the same 64-byte limit at the invariant
 *   layer for cross-implementation parity: any `reason` that AxonOS
 *   can carry must be acceptable to Node.js, and any `reason` that
 *   Node.js could carry but AxonOS cannot is rejected here so that
 *   no cross-implementation interop test would ever observe a
 *   reason that AxonOS would have truncated. Logged as §6.5 Note 6.
 *
 *   The byte count is over UTF-8 encoded length (matching the wire
 *   representation), not JavaScript `.length` (which counts UTF-16
 *   code units).
 *
 * Copyright (c) 2026 SYM.BOT Ltd. Apache 2.0 License.
 */

const { FrameType } = require('./state');

// ─── Spec / parity constants ───────────────────────────────────────

/**
 * Maximum byte length of the human-readable `reason` string.
 *
 * Source: `axonos-consent/src/frames.rs:16` (`MAX_REASON_LEN = 64`).
 * Cross-implementation parity choice — see §6.5 Note 6.
 */
const MAX_REASON_LEN = 64;

// ─── Discriminated enums ──────────────────────────────────────────
//
// Mirrors invariants.rs:21-44. Node.js uses string discriminants
// instead of Rust enum tags; the meaning is identical.

const InvariantViolation = Object.freeze({
  /** §3.1: timestamp_ms MUST NOT be zero if present (parity with AxonOS). */
  ZERO_TIMESTAMP_MS: 'ZERO_TIMESTAMP_MS',
  /** §3.1: timestamp_us MUST NOT be zero if present (parity with AxonOS). */
  ZERO_TIMESTAMP_US: 'ZERO_TIMESTAMP_US',
  /** Local: reason exceeds MAX_REASON_LEN bytes (parity with AxonOS). */
  REASON_TOO_LONG: 'REASON_TOO_LONG',
});

const InvariantWarning = Object.freeze({
  /** §3.1: consent-withdraw SHOULD have timestamp or timestamp_us. */
  WITHDRAW_MISSING_TIMESTAMP: 'WITHDRAW_MISSING_TIMESTAMP',
  /** §3.1: consent-withdraw SHOULD have reasonCode for audit trail. */
  WITHDRAW_MISSING_REASON_CODE: 'WITHDRAW_MISSING_REASON_CODE',
  /** §3.2: consent-suspend SHOULD have reasonCode. */
  SUSPEND_MISSING_REASON_CODE: 'SUSPEND_MISSING_REASON_CODE',
});

// ─── checkFrame ───────────────────────────────────────────────────

/**
 * Run all invariant checks for a typed consent frame.
 *
 * Mirrors `axonos-consent/src/invariants.rs::check_frame`
 * (lines 105-157).
 *
 * Returns a result object with both violation and warning lists.
 * Callers determine acceptance by `result.violations.length === 0`
 * — same as Denis's `is_valid()` (invariants.rs:78).
 *
 * The function is O(1) — fixed number of field checks, no loops.
 *
 * @param {object} frame - typed consent frame (output of parseFrame)
 * @returns {{
 *   ok: boolean,
 *   violations: string[],
 *   warnings: string[],
 * }}
 * @throws {TypeError} if frame is not a recognised consent frame
 */
function checkFrame(frame) {
  if (frame == null || typeof frame !== 'object') {
    throw new TypeError(`checkFrame: frame must be an object`);
  }
  if (typeof frame.type !== 'string') {
    throw new TypeError(`checkFrame: frame.type must be a string`);
  }

  const violations = [];
  const warnings = [];

  // Common timestamp + reason length checks for withdraw and suspend.
  // Resume has only timestamp checks (no reason field).

  if (frame.type === FrameType.WITHDRAW) {
    _checkTimestamps(frame, violations);
    _checkReasonLength(frame, violations);
    // §3.1 SHOULD: at least one timestamp
    if (frame.timestampMs === undefined && frame.timestampUs === undefined) {
      warnings.push(InvariantWarning.WITHDRAW_MISSING_TIMESTAMP);
    }
    // §3.4 SHOULD: reasonCode for audit
    if (frame.reasonCode === undefined) {
      warnings.push(InvariantWarning.WITHDRAW_MISSING_REASON_CODE);
    }
  } else if (frame.type === FrameType.SUSPEND) {
    _checkTimestamps(frame, violations);
    _checkReasonLength(frame, violations);
    // §3.2 SHOULD: reasonCode
    if (frame.reasonCode === undefined) {
      warnings.push(InvariantWarning.SUSPEND_MISSING_REASON_CODE);
    }
  } else if (frame.type === FrameType.RESUME) {
    _checkTimestamps(frame, violations);
    // §3.3: no reason, no reasonCode, no SHOULD warnings
  } else {
    throw new TypeError(`checkFrame: unknown frame type "${frame.type}"`);
  }

  return {
    ok: violations.length === 0,
    violations,
    warnings,
  };
}

/**
 * MUST: timestamp values MUST NOT be zero if present.
 * Mirrors invariants.rs:113-114, 135-136, 150-151.
 */
function _checkTimestamps(frame, violations) {
  if (frame.timestampMs === 0) {
    violations.push(InvariantViolation.ZERO_TIMESTAMP_MS);
  }
  if (frame.timestampUs === 0) {
    violations.push(InvariantViolation.ZERO_TIMESTAMP_US);
  }
}

/**
 * MUST: reason length (in UTF-8 bytes) MUST NOT exceed MAX_REASON_LEN.
 * Mirrors invariants.rs:117-121.
 *
 * The byte count is over UTF-8 encoded length (`Buffer.byteLength`)
 * to match the AxonOS ReasonBuf representation, not JS string
 * `.length` which counts UTF-16 code units.
 */
function _checkReasonLength(frame, violations) {
  if (frame.reason === undefined) return;
  if (typeof frame.reason !== 'string') return;
  const byteLen = Buffer.byteLength(frame.reason, 'utf8');
  if (byteLen > MAX_REASON_LEN) {
    violations.push(InvariantViolation.REASON_TOO_LONG);
  }
}

// ─── Module exports ────────────────────────────────────────────────

module.exports = {
  MAX_REASON_LEN,
  InvariantViolation,
  InvariantWarning,
  checkFrame,
};
