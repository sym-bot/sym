'use strict';

/**
 * Consent gossip encoding — MMP Consent Extension v0.1.0, §6.4.
 *
 * Mirrors `axonos-consent/src/state.rs::to_gossip_bits` /
 * `from_gossip_bits` (state.rs:94-101). Denis keeps these inline
 * with the state enum because Rust enum-to-byte coercion is free;
 * the Node.js port splits them into a dedicated module so the
 * §6.4 encoding has its own surface and its own test file.
 *
 * ## Spec source
 *
 * `mmp-consent-v0.1.0.md:345` (§6.4 Constrained gossip encoding):
 *
 *   "Implementations operating under payload size constraints
 *    (e.g., BLE ATT MTU of 251 bytes) MAY use compressed consent
 *    state encoding: 2 bits per peer for the full state machine
 *    (00 = granted, 01 = suspended, 10 = withdrawn, 11 = reserved)."
 *
 * ## Vector source
 *
 * `consent-interop-vectors-v0.1.0.json:262-279` (TV-014):
 *
 *   "gossip_encoding": {
 *     "granted":   "0b00",
 *     "suspended": "0b01",
 *     "withdrawn": "0b10",
 *     "reserved":  "0b11"
 *   }
 *
 * The TV-014 vector is the canonical interop test for this encoding.
 * The vector has no `json` field — it is the only Class B vector in
 * the canonical file (see §6.1.1 of the joint paper §6 design doc).
 * The Node.js test runner asserts the encoding by encoding each of
 * the three valid ConsentState values and comparing to the literal
 * 2-bit values from TV-014, plus by attempting to decode `0b11` and
 * verifying it returns the reserved sentinel.
 *
 * Copyright (c) 2026 SYM.BOT Ltd. Apache 2.0 License.
 */

const { ConsentState } = require('./state');

// ─── Bit values ───────────────────────────────────────────────────
//
// Frozen so the encoding cannot be mutated at runtime. Numeric
// values match the spec table at line 345 verbatim.

const GossipBits = Object.freeze({
  GRANTED:   0b00,
  SUSPENDED: 0b01,
  WITHDRAWN: 0b10,
  RESERVED:  0b11,
});

const GOSSIP_BIT_MASK = 0b11;

// ─── toGossipBits ─────────────────────────────────────────────────

/**
 * Encode a ConsentState into the 2-bit gossip representation.
 *
 * Mirrors `axonos-consent/src/state.rs:94` (`to_gossip_bits`).
 *
 * @param {string} state - one of ConsentState
 * @returns {number} - 0b00, 0b01, or 0b10 (the reserved value 0b11
 *   is never produced by the encoder; it is only consumed by the
 *   decoder for forward-compat detection)
 * @throws {TypeError} for unknown state values
 */
function toGossipBits(state) {
  switch (state) {
    case ConsentState.GRANTED:   return GossipBits.GRANTED;
    case ConsentState.SUSPENDED: return GossipBits.SUSPENDED;
    case ConsentState.WITHDRAWN: return GossipBits.WITHDRAWN;
    default:
      throw new TypeError(`toGossipBits: unknown ConsentState "${state}"`);
  }
}

// ─── fromGossipBits ───────────────────────────────────────────────

/**
 * Decode a 2-bit gossip value back to a ConsentState.
 *
 * Mirrors `axonos-consent/src/state.rs:96-101` (`from_gossip_bits`).
 * The decoder masks the input to 2 bits and returns:
 *
 *   - one of ConsentState.{GRANTED, SUSPENDED, WITHDRAWN} for the
 *     three encoded states
 *   - undefined for the reserved value `0b11` (forward compatibility:
 *     a future spec extension might define semantics for `0b11`,
 *     and decoders that do not understand the new semantics MUST
 *     leave the field uninterpreted rather than crash)
 *
 * Mirrors Denis's `Option<Self>` return: `Some(state)` for the
 * three encoded values, `None` for the reserved cell.
 *
 * @param {number} bits - integer; only the low 2 bits are read
 * @returns {string | undefined} - one of ConsentState, or undefined
 *   for the reserved value
 * @throws {TypeError} for non-integer input
 */
function fromGossipBits(bits) {
  if (!Number.isInteger(bits)) {
    throw new TypeError(`fromGossipBits: input must be an integer, got ${bits}`);
  }
  switch (bits & GOSSIP_BIT_MASK) {
    case GossipBits.GRANTED:   return ConsentState.GRANTED;
    case GossipBits.SUSPENDED: return ConsentState.SUSPENDED;
    case GossipBits.WITHDRAWN: return ConsentState.WITHDRAWN;
    case GossipBits.RESERVED:  return undefined;  // reserved sentinel
    /* istanbul ignore next */ default:
      // Unreachable: 2-bit mask exhausted by the four cases above.
      throw new TypeError(`fromGossipBits: internal mask error for ${bits}`);
  }
}

// ─── Module exports ────────────────────────────────────────────────

module.exports = {
  GossipBits,
  GOSSIP_BIT_MASK,
  toGossipBits,
  fromGossipBits,
};
