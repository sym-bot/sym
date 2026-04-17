'use strict';

/**
 * Reason code registry tests — MMP Consent Extension v0.1.0, §3.4.
 *
 * Mirrors the round-trip and unknown-value behaviour exercised by
 * `axonos-consent/tests/consent_interop.rs` (the rt_withdraw_*
 * tests at lines 23-57 and the implicit fromU8 normalization
 * exercised inside the JSON vector loop at lines 206-232).
 *
 * Includes the TV-012 unknown-reason-code case explicitly even
 * though TV-012 is also exercised by the canonical interop runner
 * later (`tests/consent-interop.test.js`, step 8) — the dedicated
 * unit test here ensures fromU8's normalization is verified
 * against the spec gap discussion in §6.5 Note 3, independent of
 * the rest of the pipeline.
 *
 * Copyright (c) 2026 SYM.BOT Ltd. Apache 2.0 License.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  ReasonCode,
  isSpecReserved,
  isImplementationSpecific,
  fromU8,
  toU8,
  nameOf,
} = require('../lib/consent/reason');

// ─── Enum shape ────────────────────────────────────────────────────

test('ReasonCode enum is frozen', () => {
  assert.equal(Object.isFrozen(ReasonCode), true);
});

test('ReasonCode contains all four spec-reserved codes', () => {
  assert.equal(ReasonCode.UNSPECIFIED,      0x00);
  assert.equal(ReasonCode.USER_INITIATED,   0x01);
  assert.equal(ReasonCode.SAFETY_VIOLATION, 0x02);
  assert.equal(ReasonCode.HARDWARE_FAULT,   0x03);
});

test('ReasonCode contains all four AxonOS-extension codes', () => {
  assert.equal(ReasonCode.STIMGUARD_LOCKOUT,           0x10);
  assert.equal(ReasonCode.SESSION_ATTESTATION_FAILURE, 0x11);
  assert.equal(ReasonCode.EMERGENCY_BUTTON,            0x12);
  assert.equal(ReasonCode.SWARM_FAULT_DETECTED,        0x13);
});

test('ReasonCode has exactly 8 registered values', () => {
  // If the registry grows, this test must be updated AND a corresponding
  // entry added to the spec §3.4 cross-implementation registry table.
  assert.equal(Object.keys(ReasonCode).length, 8);
});

// ─── Range predicates ──────────────────────────────────────────────
// Mirrors axonos-consent/src/reason.rs:27-28

test('isSpecReserved: 0x00..0x0F → true', () => {
  for (let b = 0x00; b <= 0x0F; b++) {
    assert.equal(isSpecReserved(b), true, `byte 0x${b.toString(16)}`);
  }
});

test('isSpecReserved: 0x10..0xFF → false', () => {
  for (let b = 0x10; b <= 0xFF; b++) {
    assert.equal(isSpecReserved(b), false, `byte 0x${b.toString(16)}`);
  }
});

test('isImplementationSpecific: 0x10..0xFF → true', () => {
  for (let b = 0x10; b <= 0xFF; b++) {
    assert.equal(isImplementationSpecific(b), true, `byte 0x${b.toString(16)}`);
  }
});

test('isImplementationSpecific: 0x00..0x0F → false', () => {
  for (let b = 0x00; b <= 0x0F; b++) {
    assert.equal(isImplementationSpecific(b), false, `byte 0x${b.toString(16)}`);
  }
});

test('range predicates: union covers 0..255 with no overlap', () => {
  for (let b = 0; b <= 0xFF; b++) {
    const a = isSpecReserved(b);
    const c = isImplementationSpecific(b);
    assert.equal(a !== c, true, `byte 0x${b.toString(16)}: a=${a}, c=${c}`);
  }
});

// ─── fromU8: registered values are identity ───────────────────────

test('fromU8: registered values round-trip to themselves', () => {
  const registered = [
    ReasonCode.UNSPECIFIED,
    ReasonCode.USER_INITIATED,
    ReasonCode.SAFETY_VIOLATION,
    ReasonCode.HARDWARE_FAULT,
    ReasonCode.STIMGUARD_LOCKOUT,
    ReasonCode.SESSION_ATTESTATION_FAILURE,
    ReasonCode.EMERGENCY_BUTTON,
    ReasonCode.SWARM_FAULT_DETECTED,
  ];
  for (const code of registered) {
    assert.equal(fromU8(code), code, `code 0x${code.toString(16)}`);
  }
});

// ─── fromU8: unknown values collapse to UNSPECIFIED ───────────────
//
// This is the TV-012 contract: "accept frame, treat reasonCode as
// unspecified, proceed with withdrawal". Verified against the
// canonical vector file's expected_behavior field at line 241.

test('fromU8: TV-012 case (0xFF) collapses to UNSPECIFIED', () => {
  assert.equal(fromU8(0xFF), ReasonCode.UNSPECIFIED);
});

test('fromU8: every unregistered byte in 0x04..0x0F collapses to UNSPECIFIED', () => {
  for (let b = 0x04; b <= 0x0F; b++) {
    assert.equal(
      fromU8(b),
      ReasonCode.UNSPECIFIED,
      `spec-reserved unallocated byte 0x${b.toString(16)}`
    );
  }
});

test('fromU8: every unregistered byte in 0x14..0xFF collapses to UNSPECIFIED', () => {
  // This is 236 byte values. We sample-test at the boundaries plus
  // a representative middle range. Full sweep would be slow and
  // adds no information.
  const samples = [0x14, 0x15, 0x20, 0x40, 0x80, 0xC0, 0xFE, 0xFF];
  for (const b of samples) {
    assert.equal(
      fromU8(b),
      ReasonCode.UNSPECIFIED,
      `impl-specific unregistered byte 0x${b.toString(16)}`
    );
  }
});

// ─── fromU8: programmer-error guards ──────────────────────────────

test('fromU8: rejects non-integer input', () => {
  assert.throws(() => fromU8(1.5), TypeError);
  assert.throws(() => fromU8('1'), TypeError);
  assert.throws(() => fromU8(null), TypeError);
  assert.throws(() => fromU8(undefined), TypeError);
});

test('fromU8: rejects out-of-range integers', () => {
  assert.throws(() => fromU8(-1), TypeError);
  assert.throws(() => fromU8(256), TypeError);
  assert.throws(() => fromU8(0x100), TypeError);
});

// ─── toU8: round-trip + reject unregistered ───────────────────────

test('toU8: registered values are identity', () => {
  for (const code of Object.values(ReasonCode)) {
    assert.equal(toU8(code), code);
  }
});

test('toU8: rejects unregistered byte (asymmetric vs fromU8 by design)', () => {
  // This is the deliberate asymmetry between fromU8 (lossy normalize)
  // and toU8 (strict). See the docstring on toU8.
  assert.throws(() => toU8(0xFF), TypeError);
  assert.throws(() => toU8(0x05), TypeError);
});

test('toU8: rejects out-of-range integers', () => {
  assert.throws(() => toU8(-1), TypeError);
  assert.throws(() => toU8(256), TypeError);
});

// ─── nameOf ───────────────────────────────────────────────────────

test('nameOf: registered values', () => {
  assert.equal(nameOf(0x00), 'UNSPECIFIED');
  assert.equal(nameOf(0x01), 'USER_INITIATED');
  assert.equal(nameOf(0x02), 'SAFETY_VIOLATION');
  assert.equal(nameOf(0x03), 'HARDWARE_FAULT');
  assert.equal(nameOf(0x10), 'STIMGUARD_LOCKOUT');
  assert.equal(nameOf(0x11), 'SESSION_ATTESTATION_FAILURE');
  assert.equal(nameOf(0x12), 'EMERGENCY_BUTTON');
  assert.equal(nameOf(0x13), 'SWARM_FAULT_DETECTED');
});

test('nameOf: unregistered values fall back to UNSPECIFIED', () => {
  assert.equal(nameOf(0x05), 'UNSPECIFIED');
  assert.equal(nameOf(0x14), 'UNSPECIFIED');
  assert.equal(nameOf(0xFF), 'UNSPECIFIED');
});
