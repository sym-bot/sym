'use strict';

/**
 * Reason code registry — MMP Consent Extension v0.1.0, §3.4.
 *
 * Mirrors `axonos-consent/src/reason.rs` (29 lines). Two ranges:
 *
 *   0x00–0x0F  spec-reserved (this file: 0x00, 0x01, 0x02, 0x03)
 *   0x10–0xFF  implementation-specific (this file: 0x10, 0x11, 0x12, 0x13
 *              from the AxonOS extension registry, replicated here for
 *              cross-implementation parity in test vector parsing).
 *
 * ## Unknown-value handling
 *
 * Per §3.4 (lines 196-197 of the consent spec) and per the
 * `expected_behavior` field of TV-012 in the canonical interop
 * vector file:
 *
 *   "accept frame, treat reasonCode as unspecified, proceed with
 *    withdrawal"
 *
 * `fromU8` therefore collapses any value not in the registered
 * tables to UNSPECIFIED (0x00) without throwing. This matches
 * AxonOS `reason.rs:18-25` which uses a `_ => Self::Unspecified`
 * fallback in its `from_u8` match. The original byte value is
 * NOT preserved by this function — callers that need the raw byte
 * for audit must capture it from the wire frame before parsing.
 *
 * Both implementations preserve the same lossy normalization at
 * the engine layer: the `last_reason` field stores the normalized
 * code, not the original byte. This is the verified behaviour of
 * AxonOS `engine.rs:117-121` which extracts `reason_code` from
 * the parsed frame after CBOR decode (i.e. after `from_u8`).
 *
 * ## Spec gap clarification
 *
 * §6.5 Note 3 of the joint paper §6 design doc proposes a v0.1.1
 * spec clarification that would tighten this behaviour normatively.
 * Until that lands, the implementation choice here is the same
 * one made by AxonOS, justified by TV-012's `expected_behavior`
 * field as a de-facto interop expectation.
 *
 * Copyright (c) 2026 SYM.BOT Ltd. Apache 2.0 License.
 */

// ─── Reason code enum ──────────────────────────────────────────────
//
// String labels are the human-readable names from the spec §3.4
// table and the AxonOS extension registry. Numeric values are the
// canonical wire bytes.
//
// Spec source: mmp-consent-v0.1.0.md:190-198 (§3.4 Reason Code Registry)
// AxonOS source: src/reason.rs:6-15 (ReasonCode enum)
// Vector source: tests/vectors/consent-interop-vectors-v0.1.0.json:306-320

const ReasonCode = Object.freeze({
  // Spec-reserved (0x00–0x0F)
  UNSPECIFIED:                0x00,
  USER_INITIATED:             0x01,
  SAFETY_VIOLATION:           0x02,
  HARDWARE_FAULT:             0x03,
  // AxonOS implementation-specific (0x10–0x1F currently in use)
  STIMGUARD_LOCKOUT:          0x10,
  SESSION_ATTESTATION_FAILURE:0x11,
  EMERGENCY_BUTTON:           0x12,
  SWARM_FAULT_DETECTED:       0x13,
});

// Reverse map for the (small) registered set. Built once at module
// load and frozen. Anything not in this map collapses to UNSPECIFIED
// per fromU8 below.
const _BYTE_TO_NAME = Object.freeze({
  0x00: 'UNSPECIFIED',
  0x01: 'USER_INITIATED',
  0x02: 'SAFETY_VIOLATION',
  0x03: 'HARDWARE_FAULT',
  0x10: 'STIMGUARD_LOCKOUT',
  0x11: 'SESSION_ATTESTATION_FAILURE',
  0x12: 'EMERGENCY_BUTTON',
  0x13: 'SWARM_FAULT_DETECTED',
});

// ─── Range predicates ──────────────────────────────────────────────
//
// Mirrors `axonos-consent/src/reason.rs:27-28`.

/**
 * True if the byte is in the spec-reserved range 0x00–0x0F.
 *
 * @param {number} byte
 * @returns {boolean}
 */
function isSpecReserved(byte) {
  if (!Number.isInteger(byte) || byte < 0 || byte > 0xFF) {
    throw new TypeError(
      `isSpecReserved: byte must be an integer in 0..255, got ${byte}`
    );
  }
  return byte <= 0x0F;
}

/**
 * True if the byte is in the implementation-specific range 0x10–0xFF.
 *
 * @param {number} byte
 * @returns {boolean}
 */
function isImplementationSpecific(byte) {
  if (!Number.isInteger(byte) || byte < 0 || byte > 0xFF) {
    throw new TypeError(
      `isImplementationSpecific: byte must be an integer in 0..255, got ${byte}`
    );
  }
  return byte >= 0x10;
}

// ─── from / to byte ────────────────────────────────────────────────

/**
 * Normalize a wire byte into a registered ReasonCode value.
 *
 * Mirrors `axonos-consent/src/reason.rs:18-25` (from_u8). Unknown
 * values collapse to UNSPECIFIED — see the spec gap discussion in
 * the file header and §6.5 Note 3 of the joint paper §6 design doc.
 *
 * Inputs that are not integers in 0..255 throw TypeError; this is
 * a programmer error and is intentionally distinct from the
 * unknown-but-in-range case (which silently normalizes).
 *
 * @param {number} byte - integer in 0..255
 * @returns {number} - one of ReasonCode (always a registered value)
 */
function fromU8(byte) {
  if (!Number.isInteger(byte) || byte < 0 || byte > 0xFF) {
    throw new TypeError(
      `fromU8: byte must be an integer in 0..255, got ${byte}`
    );
  }
  // The byte-to-name table covers all registered values. If the
  // byte is in the table, return it as-is (the byte IS the enum
  // value). Otherwise normalize to UNSPECIFIED.
  if (Object.prototype.hasOwnProperty.call(_BYTE_TO_NAME, byte)) {
    return byte;
  }
  return ReasonCode.UNSPECIFIED;
}

/**
 * Identity for registered values; throws for anything else.
 *
 * Mirrors `axonos-consent/src/reason.rs:26` (to_u8). The Rust
 * version is total because the input is the enum type — the
 * compiler guarantees a registered value. The JavaScript version
 * has no such guarantee, so this function validates and throws on
 * unregistered input. Callers that have already passed through
 * fromU8 will always succeed.
 *
 * @param {number} code - one of ReasonCode
 * @returns {number} - the byte value
 */
function toU8(code) {
  if (!Number.isInteger(code) || code < 0 || code > 0xFF) {
    throw new TypeError(
      `toU8: code must be an integer in 0..255, got ${code}`
    );
  }
  if (!Object.prototype.hasOwnProperty.call(_BYTE_TO_NAME, code)) {
    throw new TypeError(
      `toU8: code 0x${code.toString(16).padStart(2, '0')} is not in the registered ReasonCode set. ` +
      `Use fromU8() to normalize an unknown wire value first.`
    );
  }
  return code;
}

/**
 * Human-readable name for a registered code; "UNSPECIFIED" for
 * anything not in the registry. This is for logging and error
 * messages, not for protocol-level semantics.
 *
 * @param {number} code
 * @returns {string}
 */
function nameOf(code) {
  if (!Number.isInteger(code) || code < 0 || code > 0xFF) {
    throw new TypeError(
      `nameOf: code must be an integer in 0..255, got ${code}`
    );
  }
  return _BYTE_TO_NAME[code] || 'UNSPECIFIED';
}

// ─── Module exports ────────────────────────────────────────────────

module.exports = {
  ReasonCode,
  isSpecReserved,
  isImplementationSpecific,
  fromU8,
  toU8,
  nameOf,
};
