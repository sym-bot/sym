'use strict';

/**
 * Consent frame parser/encoder tests — MMP Consent Extension
 * v0.1.0, §3.
 *
 * Mirrors the rt_* (round-trip) tests at
 * `axonos-consent/tests/consent_interop.rs:23-57` and the JSON
 * vector round-trip at `axonos-consent/tests/consent_interop.rs:206-232`.
 *
 * Includes structural negative cases for the rejection paths
 * defined in `lib/consent/frames.js::ParseError`.
 *
 * Note: this file does NOT load the canonical interop vectors.
 * The canonical vector test runner lives at
 * `tests/consent-interop.test.js` (step 8 of the implementation
 * checklist), which exercises every vector through the full
 * pipeline. The tests here exercise the parser/encoder in
 * isolation.
 *
 * Copyright (c) 2026 SYM.BOT Ltd. Apache 2.0 License.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { FrameType } = require('../lib/consent/state');
const { ReasonCode } = require('../lib/consent/reason');
const {
  Scope,
  ALL_SCOPES,
  isValidScope,
  ParseError,
  parseFrame,
  encodeFrame,
} = require('../lib/consent/frames');

// ─── Scope enum ────────────────────────────────────────────────────

test('Scope enum is frozen', () => {
  assert.equal(Object.isFrozen(Scope), true);
});

test('Scope contains "peer" and "all"', () => {
  assert.equal(Scope.PEER, 'peer');
  assert.equal(Scope.ALL, 'all');
});

test('isValidScope: positive cases', () => {
  for (const s of ALL_SCOPES) assert.equal(isValidScope(s), true);
});

test('isValidScope: negative cases', () => {
  for (const s of [null, undefined, '', 'PEER', 'group', 0, {}]) {
    assert.equal(isValidScope(s), false);
  }
});

// ─── parseFrame: structural rejection ─────────────────────────────

test('parseFrame: null → NOT_AN_OBJECT', () => {
  const r = parseFrame(null);
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.NOT_AN_OBJECT);
});

test('parseFrame: array → NOT_AN_OBJECT', () => {
  const r = parseFrame([]);
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.NOT_AN_OBJECT);
});

test('parseFrame: missing type → MISSING_TYPE', () => {
  const r = parseFrame({});
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.MISSING_TYPE);
});

test('parseFrame: non-string type → MISSING_TYPE', () => {
  const r = parseFrame({ type: 42 });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.MISSING_TYPE);
});

test('parseFrame: empty string type → MISSING_TYPE', () => {
  const r = parseFrame({ type: '' });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.MISSING_TYPE);
});

test('parseFrame: unknown type → UNKNOWN_FRAME_TYPE', () => {
  const r = parseFrame({ type: 'consent-bogus' });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.UNKNOWN_FRAME_TYPE);
});

// ─── parseFrame: consent-withdraw happy paths ─────────────────────
// Mirror the TV-001..TV-003, TV-008, TV-011..TV-013, TV-015 shapes.

test('parseFrame: TV-001 shape (peer scope, USER_INITIATED, timestamp)', () => {
  // Verbatim from canonical vector file lines 24-30
  const r = parseFrame({
    type: 'consent-withdraw',
    scope: 'peer',
    reasonCode: 1,
    reason: 'user requested disconnect',
    timestamp: 1711540800000,
  });
  assert.equal(r.ok, true);
  assert.equal(r.frame.type, FrameType.WITHDRAW);
  assert.equal(r.frame.scope, Scope.PEER);
  assert.equal(r.frame.reasonCode, ReasonCode.USER_INITIATED);
  assert.equal(r.frame.reason, 'user requested disconnect');
  assert.equal(r.frame.timestampMs, 1711540800000);
  assert.equal(r.frame.timestampUs, undefined);
  assert.equal(r.frame.epoch, undefined);
});

test('parseFrame: TV-002 shape (all scope, SAFETY_VIOLATION, epoch + timestamp_us)', () => {
  // Verbatim from canonical vector file lines 46-52
  const r = parseFrame({
    type: 'consent-withdraw',
    scope: 'all',
    reasonCode: 2,
    epoch: 48291,
    timestamp_us: 1711540800000000,
  });
  assert.equal(r.ok, true);
  assert.equal(r.frame.scope, Scope.ALL);
  assert.equal(r.frame.reasonCode, ReasonCode.SAFETY_VIOLATION);
  assert.equal(r.frame.epoch, 48291);
  assert.equal(r.frame.timestampUs, 1711540800000000);
  assert.equal(r.frame.timestampMs, undefined);
});

test('parseFrame: TV-003 shape (AxonOS reason 0x10, microsecond timestamp)', () => {
  // Verbatim from canonical vector file lines 69-75
  const r = parseFrame({
    type: 'consent-withdraw',
    scope: 'peer',
    reasonCode: 16,
    reason: 'stimguard lockout: repeated charge density violations',
    timestamp_us: 1711540800123456,
  });
  assert.equal(r.ok, true);
  assert.equal(r.frame.reasonCode, ReasonCode.STIMGUARD_LOCKOUT);
});

test('parseFrame: TV-012 shape (unknown reasonCode 0xFF normalizes to UNSPECIFIED)', () => {
  // Verbatim from canonical vector file lines 233-238
  // This is the §6.5 Note 3 / TV-012 expected_behavior contract.
  const r = parseFrame({
    type: 'consent-withdraw',
    scope: 'peer',
    reasonCode: 255,
    timestamp: 1711540830000,
  });
  assert.equal(r.ok, true);
  assert.equal(
    r.frame.reasonCode,
    ReasonCode.UNSPECIFIED,
    'TV-012 contract: unknown reasonCode collapses to UNSPECIFIED'
  );
});

test('parseFrame: TV-013 shape (both timestamp and timestamp_us preserved)', () => {
  // Verbatim from canonical vector file lines 249-255
  const r = parseFrame({
    type: 'consent-withdraw',
    scope: 'peer',
    reasonCode: 1,
    timestamp: 1711540800000,
    timestamp_us: 1711540800123456,
  });
  assert.equal(r.ok, true);
  // Both fields preserved on the typed frame; precedence is decided
  // at the engine layer, not the parser.
  assert.equal(r.frame.timestampMs, 1711540800000);
  assert.equal(r.frame.timestampUs, 1711540800123456);
});

test('parseFrame: TV-015 shape (emergency button reason 0x12)', () => {
  // Verbatim from canonical vector file lines 286-292
  const r = parseFrame({
    type: 'consent-withdraw',
    scope: 'all',
    reasonCode: 18,
    reason: 'physical emergency button',
    timestamp_us: 1711540800000001,
  });
  assert.equal(r.ok, true);
  assert.equal(r.frame.reasonCode, ReasonCode.EMERGENCY_BUTTON);
  assert.equal(r.frame.scope, Scope.ALL);
});

// ─── parseFrame: consent-withdraw rejection paths ─────────────────

test('parseFrame: withdraw missing scope → MISSING_SCOPE', () => {
  const r = parseFrame({ type: 'consent-withdraw' });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.MISSING_SCOPE);
});

test('parseFrame: withdraw with non-string scope → INVALID_FIELD_TYPE', () => {
  const r = parseFrame({ type: 'consent-withdraw', scope: 1 });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.INVALID_FIELD_TYPE);
});

test('parseFrame: withdraw with unknown scope → UNKNOWN_SCOPE', () => {
  const r = parseFrame({ type: 'consent-withdraw', scope: 'group' });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.UNKNOWN_SCOPE);
});

test('parseFrame: invalid timestamp type → INVALID_FIELD_TYPE', () => {
  const r = parseFrame({
    type: 'consent-withdraw',
    scope: 'peer',
    timestamp: 'not-a-number',
  });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.INVALID_FIELD_TYPE);
});

test('parseFrame: negative timestamp → INVALID_FIELD_TYPE', () => {
  const r = parseFrame({
    type: 'consent-withdraw',
    scope: 'peer',
    timestamp: -1,
  });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.INVALID_FIELD_TYPE);
});

test('parseFrame: non-integer timestamp → INVALID_FIELD_TYPE', () => {
  const r = parseFrame({
    type: 'consent-withdraw',
    scope: 'peer',
    timestamp: 1.5,
  });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.INVALID_FIELD_TYPE);
});

test('parseFrame: reasonCode out of byte range → INVALID_FIELD_TYPE', () => {
  const r = parseFrame({
    type: 'consent-withdraw',
    scope: 'peer',
    reasonCode: 256,
  });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.INVALID_FIELD_TYPE);
});

// ─── parseFrame: consent-suspend ──────────────────────────────────

test('parseFrame: TV-004 shape (focus mode)', () => {
  // Verbatim from canonical vector file lines 92-97
  const r = parseFrame({
    type: 'consent-suspend',
    reasonCode: 1,
    reason: 'user entering focus mode',
    timestamp: 1711540800000,
  });
  assert.equal(r.ok, true);
  assert.equal(r.frame.type, FrameType.SUSPEND);
  assert.equal(r.frame.reasonCode, ReasonCode.USER_INITIATED);
  assert.equal(r.frame.reason, 'user entering focus mode');
  assert.equal(r.frame.timestampMs, 1711540800000);
});

test('parseFrame: TV-005 shape (minimal fields, type only)', () => {
  // Verbatim from canonical vector file lines 113-115
  const r = parseFrame({ type: 'consent-suspend' });
  assert.equal(r.ok, true);
  assert.equal(r.frame.type, FrameType.SUSPEND);
  assert.equal(r.frame.reasonCode, undefined);
  assert.equal(r.frame.reason, undefined);
  assert.equal(r.frame.timestampMs, undefined);
  assert.equal(r.frame.timestampUs, undefined);
});

test('parseFrame: TV-009 shape (idempotent suspend, no scope)', () => {
  // Verbatim from canonical vector file lines 183-187
  const r = parseFrame({
    type: 'consent-suspend',
    reasonCode: 1,
    timestamp: 1711540810000,
  });
  assert.equal(r.ok, true);
});

// ─── parseFrame: consent-resume ───────────────────────────────────

test('parseFrame: TV-006 shape (resume with timestamp)', () => {
  // Verbatim from canonical vector file lines 130-133
  const r = parseFrame({
    type: 'consent-resume',
    timestamp: 1711540860000,
  });
  assert.equal(r.ok, true);
  assert.equal(r.frame.type, FrameType.RESUME);
  assert.equal(r.frame.timestampMs, 1711540860000);
});

test('parseFrame: TV-007 shape (minimal fields, type only)', () => {
  // Verbatim from canonical vector file lines 148-150
  const r = parseFrame({ type: 'consent-resume' });
  assert.equal(r.ok, true);
  assert.equal(r.frame.type, FrameType.RESUME);
  assert.equal(r.frame.timestampMs, undefined);
  assert.equal(r.frame.timestampUs, undefined);
});

test('parseFrame: TV-010 shape (idempotent resume from granted)', () => {
  // Verbatim from canonical vector file lines 198-201
  const r = parseFrame({
    type: 'consent-resume',
    timestamp: 1711540820000,
  });
  assert.equal(r.ok, true);
});

// ─── parseFrame: forward compatibility (unknown fields ignored) ───

test('parseFrame: unknown fields are silently ignored (§6.4 forward compat)', () => {
  const r = parseFrame({
    type: 'consent-withdraw',
    scope: 'peer',
    reasonCode: 1,
    timestamp: 1711540800000,
    futureField: 'this is from a v0.2.0 frame',
    anotherUnknown: 42,
  });
  assert.equal(r.ok, true);
  assert.equal(r.frame.futureField, undefined, 'unknown fields not on typed frame');
  assert.equal(r.frame.anotherUnknown, undefined);
});

// ─── encodeFrame: basic shapes ────────────────────────────────────

test('encodeFrame: withdraw round-trip preserves fields', () => {
  const original = {
    type: FrameType.WITHDRAW,
    scope: Scope.PEER,
    reasonCode: ReasonCode.USER_INITIATED,
    reason: 'user requested disconnect',
    timestampMs: 1711540800000,
  };
  const encoded = encodeFrame(original);
  assert.equal(encoded.type, 'consent-withdraw');
  assert.equal(encoded.scope, 'peer');
  assert.equal(encoded.reasonCode, 1);
  assert.equal(encoded.reason, 'user requested disconnect');
  assert.equal(encoded.timestamp, 1711540800000);
  assert.equal(encoded.timestamp_us, undefined);
  // Round-trip through parseFrame
  const reparsed = parseFrame(encoded);
  assert.equal(reparsed.ok, true);
  assert.deepEqual(reparsed.frame, original);
});

test('encodeFrame: suspend round-trip preserves fields', () => {
  const original = {
    type: FrameType.SUSPEND,
    reasonCode: ReasonCode.USER_INITIATED,
    reason: 'user entering focus mode',
    timestampMs: 1711540800000,
  };
  const encoded = encodeFrame(original);
  assert.equal(encoded.type, 'consent-suspend');
  assert.equal(encoded.reasonCode, 1);
  assert.equal(encoded.timestamp, 1711540800000);
  const reparsed = parseFrame(encoded);
  assert.equal(reparsed.ok, true);
  assert.deepEqual(reparsed.frame, original);
});

test('encodeFrame: resume round-trip preserves fields', () => {
  const original = {
    type: FrameType.RESUME,
    timestampMs: 1711540860000,
  };
  const encoded = encodeFrame(original);
  assert.equal(encoded.type, 'consent-resume');
  assert.equal(encoded.timestamp, 1711540860000);
  const reparsed = parseFrame(encoded);
  assert.equal(reparsed.ok, true);
  assert.deepEqual(reparsed.frame, original);
});

test('encodeFrame: withdraw with timestamp_us preserves field name on wire', () => {
  const original = {
    type: FrameType.WITHDRAW,
    scope: Scope.ALL,
    reasonCode: ReasonCode.EMERGENCY_BUTTON,
    timestampUs: 1711540800000001,
  };
  const encoded = encodeFrame(original);
  // Wire format uses snake_case `timestamp_us`
  assert.equal(encoded.timestamp_us, 1711540800000001);
  assert.equal(encoded.timestamp, undefined);
  const reparsed = parseFrame(encoded);
  assert.deepEqual(reparsed.frame, original);
});

test('encodeFrame: omits absent optional fields', () => {
  const minimalSuspend = encodeFrame({ type: FrameType.SUSPEND });
  assert.deepEqual(minimalSuspend, { type: 'consent-suspend' });

  const minimalResume = encodeFrame({ type: FrameType.RESUME });
  assert.deepEqual(minimalResume, { type: 'consent-resume' });
});

test('encodeFrame: rejects unknown frame type', () => {
  assert.throws(
    () => encodeFrame({ type: 'consent-bogus' }),
    TypeError
  );
});

test('encodeFrame: rejects withdraw with invalid scope', () => {
  assert.throws(
    () => encodeFrame({ type: FrameType.WITHDRAW, scope: 'group' }),
    TypeError
  );
});

test('encodeFrame: rejects null/non-object', () => {
  assert.throws(() => encodeFrame(null), TypeError);
  assert.throws(() => encodeFrame('not-a-frame'), TypeError);
});

// ─── Round-trip property: parse → encode → parse is identity ─────
//
// Mirrors the rt() helper at axonos-consent/tests/consent_interop.rs:12-17
// applied to JSON instead of CBOR.

test('round-trip: every TV frame shape parses, encodes, re-parses identically', () => {
  // Subset of the canonical vectors that this module can independently
  // verify (the rest live in the canonical interop runner at step 8).
  const samples = [
    { type: 'consent-withdraw', scope: 'peer', reasonCode: 1, reason: 'user requested disconnect', timestamp: 1711540800000 },
    { type: 'consent-withdraw', scope: 'all', reasonCode: 2, epoch: 48291, timestamp_us: 1711540800000000 },
    { type: 'consent-withdraw', scope: 'peer', reasonCode: 16, reason: 'stimguard lockout: repeated charge density violations', timestamp_us: 1711540800123456 },
    { type: 'consent-suspend', reasonCode: 1, reason: 'user entering focus mode', timestamp: 1711540800000 },
    { type: 'consent-suspend' },
    { type: 'consent-resume', timestamp: 1711540860000 },
    { type: 'consent-resume' },
    { type: 'consent-withdraw', scope: 'peer', reasonCode: 1, timestamp: 1711540900000 },
    { type: 'consent-suspend', reasonCode: 1, timestamp: 1711540810000 },
    { type: 'consent-resume', timestamp: 1711540820000 },
    { type: 'consent-withdraw', scope: 'peer', reasonCode: 3, timestamp_us: 1711540800999999 },
    { type: 'consent-withdraw', scope: 'peer', reasonCode: 1, timestamp: 1711540800000, timestamp_us: 1711540800123456 },
    { type: 'consent-withdraw', scope: 'all', reasonCode: 18, reason: 'physical emergency button', timestamp_us: 1711540800000001 },
  ];
  for (const wire of samples) {
    const r1 = parseFrame(wire);
    assert.equal(r1.ok, true, `parse failed: ${JSON.stringify(wire)}`);
    const encoded = encodeFrame(r1.frame);
    const r2 = parseFrame(encoded);
    assert.equal(r2.ok, true, `re-parse failed for: ${JSON.stringify(wire)}`);
    assert.deepEqual(r1.frame, r2.frame, `round-trip not identical for: ${JSON.stringify(wire)}`);
  }
});
