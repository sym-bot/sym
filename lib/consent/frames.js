'use strict';

/**
 * Consent frames — MMP Consent Extension v0.1.0, §3.
 *
 * Mirrors `axonos-consent/src/frames.rs` (frame structs) and
 * `axonos-consent/src/codec/json.rs` (JSON parser + encoder).
 *
 * The Node.js implementation handles JSON only. CBOR is the
 * canonical wire format on the constrained side (AxonOS Cortex-M4F)
 * but JSON is the canonical wire format at the relay boundary
 * (per spec §3 line 90: "The JSON encoding below is the canonical
 * representation used by the MMP reference implementations
 * (Node.js, Swift) over TCP/WebSocket"). The interop test vectors
 * are JSON; transport between SYM.BOT nodes and the relay is JSON.
 *
 * If a CBOR codec is added in a future module (`lib/consent/cbor.js`),
 * it will mirror `axonos-consent/src/codec/cbor.rs` separately.
 * The JSON path documented here is sufficient for the §6 interop
 * conformance claim.
 *
 * ## Spec mapping
 *
 * - §3.1 consent-withdraw: lines 94-138
 * - §3.2 consent-suspend: lines 140-163
 * - §3.3 consent-resume: lines 165-184
 * - §3.4 reason code registry: lines 186-198
 *
 * ## Field-level invariants
 *
 * `parseFrame` enforces only the wire-shape invariants needed to
 * produce a typed frame object: the `type` field must be present
 * and known, the `scope` field must be present and known when the
 * type is `consent-withdraw`. Everything else (timestamp positivity,
 * SHOULD warnings, MUST violations) is the responsibility of
 * `invariants.js::checkFrame()`, which the engine pipeline calls
 * after `parseFrame` succeeds.
 *
 * This separation mirrors AxonOS: the JSON decoder at `codec/json.rs`
 * produces a typed frame, and `invariants::check_frame()` is called
 * separately by the engine. Field validation does not happen inside
 * the parser.
 *
 * ## Forward compatibility
 *
 * Per spec §6.4 line 345 ("nodes that do not support [a field]
 * MUST ignore unrecognised fields per MMP Section 7"): unknown
 * fields in a consent frame are silently ignored. This mirrors
 * AxonOS `codec/cbor.rs:197` (`_ => { c.skip_value(0)?; }`) and
 * the implicit JSON-decoder behaviour at `codec/json.rs` (only
 * named fields are extracted; everything else passes through).
 *
 * Copyright (c) 2026 SYM.BOT Ltd. Apache 2.0 License.
 */

const { FrameType } = require('./state');
const { fromU8, toU8 } = require('./reason');

// ─── Scope enum (consent-withdraw only) ────────────────────────────
//
// Mirrors `axonos-consent/src/frames.rs:59-72` (Scope enum).
// String literals match the canonical wire format verbatim.

const Scope = Object.freeze({
  PEER: 'peer',
  ALL:  'all',
});

const ALL_SCOPES = Object.freeze([Scope.PEER, Scope.ALL]);

function isValidScope(s) {
  return s === Scope.PEER || s === Scope.ALL;
}

// ─── Parser errors ─────────────────────────────────────────────────
//
// Discriminated parse-error codes. Distinct from invariant violations
// (which live in invariants.js) and transition errors (state.js).
//
// Mirrors the structural rejection cases in
// `axonos-consent/src/codec/cbor.rs::DecodeError` (cbor.rs:48-65)
// — restricted to the JSON-relevant subset (we don't have CBOR
// major-type rejection, oversized-map detection, or duplicate-key
// detection at the JSON layer because the JSON parser handles those
// or because they're irrelevant to JSON).

const ParseError = Object.freeze({
  NOT_AN_OBJECT:       'NOT_AN_OBJECT',
  MISSING_TYPE:        'MISSING_TYPE',
  UNKNOWN_FRAME_TYPE:  'UNKNOWN_FRAME_TYPE',
  MISSING_SCOPE:       'MISSING_SCOPE',
  UNKNOWN_SCOPE:       'UNKNOWN_SCOPE',
  INVALID_FIELD_TYPE:  'INVALID_FIELD_TYPE',
});

// ─── Helpers ───────────────────────────────────────────────────────

/**
 * Read an optional non-negative integer field. Returns:
 *   - { ok: true, value: <integer> }     if field present and valid
 *   - { ok: true, value: undefined }     if field absent
 *   - { ok: false, error }               if field present but wrong type
 *
 * Spec §3.1 line 105-106: timestamp / timestamp_us are uint64.
 * JavaScript safe-integer range is 2^53 - 1, which is sufficient
 * for unix microseconds well past year 2287. The check enforces
 * non-negative integer only; range bound is implicit in JS Number.
 */
function _readOptionalUint(obj, key) {
  if (!Object.prototype.hasOwnProperty.call(obj, key)) {
    return { ok: true, value: undefined };
  }
  const v = obj[key];
  if (v == null) {
    // null is treated as absent (forward-compat: explicit null in
    // JSON is not a wire value the spec defines)
    return { ok: true, value: undefined };
  }
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 0) {
    return {
      ok: false,
      error: ParseError.INVALID_FIELD_TYPE,
      detail: `field "${key}" must be a non-negative integer, got ${typeof v}: ${v}`,
    };
  }
  return { ok: true, value: v };
}

/**
 * Read an optional string field.
 */
function _readOptionalString(obj, key) {
  if (!Object.prototype.hasOwnProperty.call(obj, key)) {
    return { ok: true, value: undefined };
  }
  const v = obj[key];
  if (v == null) return { ok: true, value: undefined };
  if (typeof v !== 'string') {
    return {
      ok: false,
      error: ParseError.INVALID_FIELD_TYPE,
      detail: `field "${key}" must be a string, got ${typeof v}`,
    };
  }
  return { ok: true, value: v };
}

/**
 * Read an optional reason code field. Always normalizes through
 * fromU8(), so unknown wire bytes collapse to UNSPECIFIED per
 * §6.5 Note 3 of the joint paper §6 design doc and per the
 * TV-012 expected_behavior contract.
 */
function _readOptionalReasonCode(obj, key) {
  const r = _readOptionalUint(obj, key);
  if (!r.ok) return r;
  if (r.value === undefined) return { ok: true, value: undefined };
  if (r.value > 0xFF) {
    return {
      ok: false,
      error: ParseError.INVALID_FIELD_TYPE,
      detail: `field "${key}" must be a byte (0..255), got ${r.value}`,
    };
  }
  return { ok: true, value: fromU8(r.value) };
}

// ─── parseFrame ────────────────────────────────────────────────────

/**
 * Parse a JSON value (already parsed from JSON.parse, i.e. a plain
 * JavaScript object) into a typed consent frame.
 *
 * Returns:
 *   - { ok: true,  frame: <typed frame object> } on success
 *   - { ok: false, error: <ParseError>, detail: <string> } on failure
 *
 * Mirrors `axonos-consent/src/codec/json.rs::decode_value`
 * (lines 9-35).
 *
 * The returned frame object is shaped to match what the engine
 * pipeline and the state machine expect:
 *
 *   consent-withdraw:
 *     { type: 'consent-withdraw', scope, reasonCode?, reason?,
 *       epoch?, timestampMs?, timestampUs? }
 *
 *   consent-suspend:
 *     { type: 'consent-suspend', reasonCode?, reason?,
 *       timestampMs?, timestampUs? }
 *
 *   consent-resume:
 *     { type: 'consent-resume', timestampMs?, timestampUs? }
 *
 * Optional fields are present on the object only if they were
 * present in the input JSON. The naming convention uses camelCase
 * for the field names on the typed object, distinct from the wire
 * format which uses the spec's `reasonCode`, `timestamp`, and
 * `timestamp_us`. The wire→typed mapping is documented in the
 * encoder below.
 *
 * @param {object} obj - parsed JSON object
 * @returns {{ok: true, frame: object} | {ok: false, error: string, detail: string}}
 */
function parseFrame(obj) {
  if (obj == null || typeof obj !== 'object' || Array.isArray(obj)) {
    return {
      ok: false,
      error: ParseError.NOT_AN_OBJECT,
      detail: `expected JSON object, got ${obj === null ? 'null' : Array.isArray(obj) ? 'array' : typeof obj}`,
    };
  }

  // §3 / line 90: "type" MUST be present
  const type = obj.type;
  if (typeof type !== 'string' || type.length === 0) {
    return {
      ok: false,
      error: ParseError.MISSING_TYPE,
      detail: `missing or non-string "type" field`,
    };
  }
  if (type !== FrameType.WITHDRAW && type !== FrameType.SUSPEND && type !== FrameType.RESUME) {
    return {
      ok: false,
      error: ParseError.UNKNOWN_FRAME_TYPE,
      detail: `unknown frame type "${type}"`,
    };
  }

  // Common optional fields shared by withdraw and suspend (resume
  // has only timestamps).
  const ts1 = _readOptionalUint(obj, 'timestamp');
  if (!ts1.ok) return ts1;
  const ts2 = _readOptionalUint(obj, 'timestamp_us');
  if (!ts2.ok) return ts2;

  if (type === FrameType.RESUME) {
    // §3.3: type only, optional timestamps. No reasonCode, no reason,
    // no scope, no epoch.
    const frame = { type: FrameType.RESUME };
    if (ts1.value !== undefined) frame.timestampMs = ts1.value;
    if (ts2.value !== undefined) frame.timestampUs = ts2.value;
    return { ok: true, frame };
  }

  // Withdraw and suspend share reasonCode + reason
  const rc = _readOptionalReasonCode(obj, 'reasonCode');
  if (!rc.ok) return rc;
  const reason = _readOptionalString(obj, 'reason');
  if (!reason.ok) return reason;

  if (type === FrameType.SUSPEND) {
    // §3.2: type only required; reasonCode, reason, timestamp,
    // timestamp_us all optional.
    const frame = { type: FrameType.SUSPEND };
    if (rc.value     !== undefined) frame.reasonCode  = rc.value;
    if (reason.value !== undefined) frame.reason      = reason.value;
    if (ts1.value    !== undefined) frame.timestampMs = ts1.value;
    if (ts2.value    !== undefined) frame.timestampUs = ts2.value;
    return { ok: true, frame };
  }

  // type === FrameType.WITHDRAW
  // §3.1 line 100: "scope" MUST be present
  if (!Object.prototype.hasOwnProperty.call(obj, 'scope')) {
    return {
      ok: false,
      error: ParseError.MISSING_SCOPE,
      detail: `consent-withdraw requires "scope" field`,
    };
  }
  const scope = obj.scope;
  if (typeof scope !== 'string') {
    return {
      ok: false,
      error: ParseError.INVALID_FIELD_TYPE,
      detail: `"scope" must be a string, got ${typeof scope}`,
    };
  }
  if (!isValidScope(scope)) {
    return {
      ok: false,
      error: ParseError.UNKNOWN_SCOPE,
      detail: `unknown scope "${scope}". Must be "${Scope.PEER}" or "${Scope.ALL}"`,
    };
  }

  const epoch = _readOptionalUint(obj, 'epoch');
  if (!epoch.ok) return epoch;

  const frame = {
    type: FrameType.WITHDRAW,
    scope,
  };
  if (rc.value     !== undefined) frame.reasonCode  = rc.value;
  if (reason.value !== undefined) frame.reason      = reason.value;
  if (epoch.value  !== undefined) frame.epoch       = epoch.value;
  if (ts1.value    !== undefined) frame.timestampMs = ts1.value;
  if (ts2.value    !== undefined) frame.timestampUs = ts2.value;
  return { ok: true, frame };
}

// ─── encodeFrame ───────────────────────────────────────────────────

/**
 * Encode a typed consent frame back to a plain JSON object suitable
 * for `JSON.stringify`.
 *
 * Mirrors `axonos-consent/src/codec/json.rs::encode_value`
 * (lines 38-64). The wire field names are restored: camelCase
 * `timestampMs` → wire `timestamp`, camelCase `timestampUs` →
 * wire `timestamp_us`. All other field names are unchanged.
 *
 * The function is the inverse of `parseFrame` for the field set
 * each defines: `parseFrame(encodeFrame(f))` returns a frame
 * object structurally equal to `f` for any frame `f` produced by
 * a previous `parseFrame` call (round-trip property).
 *
 * @param {object} frame - typed consent frame from parseFrame
 * @returns {object} plain JSON object suitable for JSON.stringify
 * @throws {TypeError} if the frame is not a recognised type
 */
function encodeFrame(frame) {
  if (frame == null || typeof frame !== 'object') {
    throw new TypeError(`encodeFrame: frame must be an object`);
  }

  if (frame.type === FrameType.WITHDRAW) {
    if (!isValidScope(frame.scope)) {
      throw new TypeError(
        `encodeFrame: consent-withdraw requires a valid scope, got "${frame.scope}"`
      );
    }
    const out = {
      type: FrameType.WITHDRAW,
      scope: frame.scope,
    };
    if (frame.reasonCode !== undefined) out.reasonCode = toU8(frame.reasonCode);
    if (frame.reason !== undefined) out.reason = frame.reason;
    if (frame.epoch !== undefined) out.epoch = frame.epoch;
    if (frame.timestampMs !== undefined) out.timestamp = frame.timestampMs;
    if (frame.timestampUs !== undefined) out.timestamp_us = frame.timestampUs;
    return out;
  }

  if (frame.type === FrameType.SUSPEND) {
    const out = { type: FrameType.SUSPEND };
    if (frame.reasonCode !== undefined) out.reasonCode = toU8(frame.reasonCode);
    if (frame.reason !== undefined) out.reason = frame.reason;
    if (frame.timestampMs !== undefined) out.timestamp = frame.timestampMs;
    if (frame.timestampUs !== undefined) out.timestamp_us = frame.timestampUs;
    return out;
  }

  if (frame.type === FrameType.RESUME) {
    const out = { type: FrameType.RESUME };
    if (frame.timestampMs !== undefined) out.timestamp = frame.timestampMs;
    if (frame.timestampUs !== undefined) out.timestamp_us = frame.timestampUs;
    return out;
  }

  throw new TypeError(`encodeFrame: unknown frame type "${frame.type}"`);
}

// ─── Module exports ────────────────────────────────────────────────

module.exports = {
  Scope,
  ALL_SCOPES,
  isValidScope,
  ParseError,
  parseFrame,
  encodeFrame,
};
