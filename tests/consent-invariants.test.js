'use strict';

/**
 * Consent invariant checker tests — MMP Consent Extension v0.1.0,
 * §10 conformance.
 *
 * Mirrors `axonos-consent/tests/consent_interop.rs:140-195` (the
 * `inv_*` tests).
 *
 * Copyright (c) 2026 SYM.BOT Ltd. Apache 2.0 License.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { FrameType } = require('../lib/consent/state');
const { Scope } = require('../lib/consent/frames');
const { ReasonCode } = require('../lib/consent/reason');
const {
  MAX_REASON_LEN,
  InvariantViolation,
  InvariantWarning,
  checkFrame,
} = require('../lib/consent/invariants');

// ─── Constants ────────────────────────────────────────────────────

test('MAX_REASON_LEN matches AxonOS frames.rs:16 (64 bytes)', () => {
  assert.equal(MAX_REASON_LEN, 64);
});

test('InvariantViolation enum is frozen', () => {
  assert.equal(Object.isFrozen(InvariantViolation), true);
});

test('InvariantWarning enum is frozen', () => {
  assert.equal(Object.isFrozen(InvariantWarning), true);
});

// ─── Withdraw — happy paths ───────────────────────────────────────

test('checkFrame: valid withdraw (TV-001 shape) → ok, no warnings', () => {
  const r = checkFrame({
    type: FrameType.WITHDRAW,
    scope: Scope.PEER,
    reasonCode: ReasonCode.USER_INITIATED,
    timestampMs: 1711540800000,
  });
  assert.equal(r.ok, true);
  assert.deepEqual(r.violations, []);
  assert.deepEqual(r.warnings, []);
});

test('checkFrame: valid withdraw with reason string → ok, no warnings', () => {
  const r = checkFrame({
    type: FrameType.WITHDRAW,
    scope: Scope.PEER,
    reasonCode: ReasonCode.USER_INITIATED,
    reason: 'user requested disconnect',
    timestampMs: 1711540800000,
  });
  assert.equal(r.ok, true);
  assert.deepEqual(r.warnings, []);
});

test('checkFrame: withdraw with timestamp_us only → ok', () => {
  const r = checkFrame({
    type: FrameType.WITHDRAW,
    scope: Scope.ALL,
    reasonCode: ReasonCode.SAFETY_VIOLATION,
    timestampUs: 1711540800000000,
  });
  assert.equal(r.ok, true);
  assert.deepEqual(r.warnings, []);
});

// ─── Withdraw — SHOULD warnings ───────────────────────────────────

test('checkFrame: withdraw missing both timestamps → ok with WITHDRAW_MISSING_TIMESTAMP warning', () => {
  const r = checkFrame({
    type: FrameType.WITHDRAW,
    scope: Scope.PEER,
    reasonCode: ReasonCode.USER_INITIATED,
  });
  assert.equal(r.ok, true);  // SHOULD, not MUST — frame still valid
  assert.deepEqual(r.violations, []);
  assert.ok(r.warnings.includes(InvariantWarning.WITHDRAW_MISSING_TIMESTAMP));
});

test('checkFrame: withdraw missing reasonCode → ok with WITHDRAW_MISSING_REASON_CODE warning', () => {
  const r = checkFrame({
    type: FrameType.WITHDRAW,
    scope: Scope.PEER,
    timestampMs: 1711540800000,
  });
  assert.equal(r.ok, true);
  assert.ok(r.warnings.includes(InvariantWarning.WITHDRAW_MISSING_REASON_CODE));
});

test('checkFrame: withdraw missing both timestamps and reasonCode → both warnings', () => {
  const r = checkFrame({
    type: FrameType.WITHDRAW,
    scope: Scope.PEER,
  });
  assert.equal(r.ok, true);
  assert.equal(r.warnings.length, 2);
  assert.ok(r.warnings.includes(InvariantWarning.WITHDRAW_MISSING_TIMESTAMP));
  assert.ok(r.warnings.includes(InvariantWarning.WITHDRAW_MISSING_REASON_CODE));
});

// ─── Withdraw — MUST violations ───────────────────────────────────

test('checkFrame: withdraw with timestamp_us=0 → ZERO_TIMESTAMP_US violation', () => {
  // Mirrors axonos inv_withdraw_zero_timestamp_violates at line 161
  const r = checkFrame({
    type: FrameType.WITHDRAW,
    scope: Scope.PEER,
    timestampUs: 0,
  });
  assert.equal(r.ok, false);
  assert.ok(r.violations.includes(InvariantViolation.ZERO_TIMESTAMP_US));
});

test('checkFrame: withdraw with timestamp_ms=0 → ZERO_TIMESTAMP_MS violation', () => {
  const r = checkFrame({
    type: FrameType.WITHDRAW,
    scope: Scope.PEER,
    timestampMs: 0,
  });
  assert.equal(r.ok, false);
  assert.ok(r.violations.includes(InvariantViolation.ZERO_TIMESTAMP_MS));
});

test('checkFrame: withdraw with both timestamps zero → both violations', () => {
  const r = checkFrame({
    type: FrameType.WITHDRAW,
    scope: Scope.PEER,
    timestampMs: 0,
    timestampUs: 0,
  });
  assert.equal(r.ok, false);
  assert.equal(r.violations.length, 2);
});

// ─── Withdraw — reason length ─────────────────────────────────────

test('checkFrame: reason at exactly MAX_REASON_LEN bytes → ok', () => {
  const r = checkFrame({
    type: FrameType.WITHDRAW,
    scope: Scope.PEER,
    reasonCode: ReasonCode.USER_INITIATED,
    reason: 'x'.repeat(MAX_REASON_LEN),
    timestampMs: 1711540800000,
  });
  assert.equal(r.ok, true);
});

test('checkFrame: reason 65 bytes → REASON_TOO_LONG', () => {
  const r = checkFrame({
    type: FrameType.WITHDRAW,
    scope: Scope.PEER,
    reasonCode: ReasonCode.USER_INITIATED,
    reason: 'x'.repeat(MAX_REASON_LEN + 1),
    timestampMs: 1711540800000,
  });
  assert.equal(r.ok, false);
  assert.ok(r.violations.includes(InvariantViolation.REASON_TOO_LONG));
});

test('checkFrame: reason length is measured in UTF-8 bytes, not JS chars', () => {
  // 32 emoji = 32 chars but 128 bytes (each emoji = 4 UTF-8 bytes).
  // JS .length is 64 (UTF-16 surrogate pairs), but Buffer.byteLength is 128.
  // 128 > 64 → should reject.
  const r = checkFrame({
    type: FrameType.WITHDRAW,
    scope: Scope.PEER,
    reasonCode: ReasonCode.USER_INITIATED,
    reason: '🎵'.repeat(32),
    timestampMs: 1711540800000,
  });
  assert.equal(r.ok, false);
  assert.ok(r.violations.includes(InvariantViolation.REASON_TOO_LONG));
});

test('checkFrame: 16 emoji (64 UTF-8 bytes) → ok at exact boundary', () => {
  const r = checkFrame({
    type: FrameType.WITHDRAW,
    scope: Scope.PEER,
    reasonCode: ReasonCode.USER_INITIATED,
    reason: '🎵'.repeat(16),  // 16 × 4 bytes = 64 bytes exactly
    timestampMs: 1711540800000,
  });
  assert.equal(Buffer.byteLength('🎵'.repeat(16), 'utf8'), 64);
  assert.equal(r.ok, true);
});

// ─── Suspend ──────────────────────────────────────────────────────

test('checkFrame: valid suspend (TV-004 shape)', () => {
  const r = checkFrame({
    type: FrameType.SUSPEND,
    reasonCode: ReasonCode.USER_INITIATED,
    reason: 'user entering focus mode',
    timestampMs: 1711540800000,
  });
  assert.equal(r.ok, true);
  assert.deepEqual(r.warnings, []);
});

test('checkFrame: TV-005 minimal suspend → ok with SUSPEND_MISSING_REASON_CODE warning', () => {
  // Mirrors axonos inv_suspend_missing_reason_warns at line 188
  const r = checkFrame({ type: FrameType.SUSPEND });
  assert.equal(r.ok, true);
  assert.ok(r.warnings.includes(InvariantWarning.SUSPEND_MISSING_REASON_CODE));
});

test('checkFrame: suspend with timestamp_us=0 → ZERO_TIMESTAMP_US violation', () => {
  const r = checkFrame({
    type: FrameType.SUSPEND,
    reasonCode: ReasonCode.USER_INITIATED,
    timestampUs: 0,
  });
  assert.equal(r.ok, false);
  assert.ok(r.violations.includes(InvariantViolation.ZERO_TIMESTAMP_US));
});

test('checkFrame: suspend with overlong reason → REASON_TOO_LONG', () => {
  const r = checkFrame({
    type: FrameType.SUSPEND,
    reasonCode: ReasonCode.USER_INITIATED,
    reason: 'x'.repeat(MAX_REASON_LEN + 1),
    timestampMs: 1711540800000,
  });
  assert.equal(r.ok, false);
  assert.ok(r.violations.includes(InvariantViolation.REASON_TOO_LONG));
});

// ─── Resume ───────────────────────────────────────────────────────

test('checkFrame: valid resume (TV-006 shape)', () => {
  const r = checkFrame({
    type: FrameType.RESUME,
    timestampMs: 1711540860000,
  });
  assert.equal(r.ok, true);
  assert.deepEqual(r.warnings, []);
});

test('checkFrame: TV-007 minimal resume → ok, no warnings (resume has no SHOULD)', () => {
  const r = checkFrame({ type: FrameType.RESUME });
  assert.equal(r.ok, true);
  assert.deepEqual(r.warnings, []);
});

test('checkFrame: resume with timestamp_ms=0 → ZERO_TIMESTAMP_MS violation', () => {
  const r = checkFrame({
    type: FrameType.RESUME,
    timestampMs: 0,
  });
  assert.equal(r.ok, false);
  assert.ok(r.violations.includes(InvariantViolation.ZERO_TIMESTAMP_MS));
});

// ─── Programmer-error guards ──────────────────────────────────────

test('checkFrame throws on null/non-object', () => {
  assert.throws(() => checkFrame(null), TypeError);
  assert.throws(() => checkFrame('not-a-frame'), TypeError);
});

test('checkFrame throws on missing or non-string type', () => {
  assert.throws(() => checkFrame({}), TypeError);
  assert.throws(() => checkFrame({ type: 42 }), TypeError);
});

test('checkFrame throws on unknown type', () => {
  assert.throws(() => checkFrame({ type: 'consent-bogus' }), TypeError);
});
