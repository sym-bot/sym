'use strict';

/**
 * Consent gossip encoding tests — MMP Consent Extension v0.1.0,
 * §6.4. Mirrors `axonos-consent/tests/consent_interop.rs::sm_gossip`
 * at line 270, plus dedicated TV-014 vector assertions.
 *
 * Copyright (c) 2026 SYM.BOT Ltd. Apache 2.0 License.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { ConsentState, ALL_STATES } = require('../lib/consent/state');
const {
  GossipBits,
  GOSSIP_BIT_MASK,
  toGossipBits,
  fromGossipBits,
} = require('../lib/consent/gossip');

// ─── Constants from spec table (mmp-consent-v0.1.0.md:345) ────────

test('GossipBits matches spec §6.4 line 345 verbatim', () => {
  // The spec literal: "00 = granted, 01 = suspended, 10 = withdrawn, 11 = reserved"
  assert.equal(GossipBits.GRANTED,   0b00);
  assert.equal(GossipBits.SUSPENDED, 0b01);
  assert.equal(GossipBits.WITHDRAWN, 0b10);
  assert.equal(GossipBits.RESERVED,  0b11);
});

test('GossipBits is frozen', () => {
  assert.equal(Object.isFrozen(GossipBits), true);
});

test('GOSSIP_BIT_MASK is exactly 2 bits', () => {
  assert.equal(GOSSIP_BIT_MASK, 0b11);
});

// ─── TV-014 vector assertions ─────────────────────────────────────
// Verbatim from consent-interop-vectors-v0.1.0.json:266-270

test('TV-014 verbatim: granted → 0b00', () => {
  assert.equal(toGossipBits(ConsentState.GRANTED), 0b00);
});

test('TV-014 verbatim: suspended → 0b01', () => {
  assert.equal(toGossipBits(ConsentState.SUSPENDED), 0b01);
});

test('TV-014 verbatim: withdrawn → 0b10', () => {
  assert.equal(toGossipBits(ConsentState.WITHDRAWN), 0b10);
});

test('TV-014 verbatim: 0b11 is reserved (decoder returns undefined)', () => {
  assert.equal(fromGossipBits(0b11), undefined);
});

// ─── Round-trip property ──────────────────────────────────────────
// Mirrors axonos sm_gossip at line 270:
//   for s in [Granted, Suspended, Withdrawn] {
//     assert_eq!(ConsentState::from_gossip_bits(s.to_gossip_bits()), Some(s));
//   }

test('round-trip: every ConsentState survives encode → decode', () => {
  for (const state of ALL_STATES) {
    const bits = toGossipBits(state);
    const decoded = fromGossipBits(bits);
    assert.equal(decoded, state, `round-trip failed for ${state}`);
  }
});

// ─── Decoder masking (high bits ignored) ─────────────────────────

test('fromGossipBits: ignores bits above bit 1', () => {
  // 0xFC | 0b01 = suspended pattern with high bits set
  assert.equal(fromGossipBits(0b11111101), ConsentState.SUSPENDED);
  assert.equal(fromGossipBits(0xF0 | 0b00), ConsentState.GRANTED);
  assert.equal(fromGossipBits(0xF0 | 0b10), ConsentState.WITHDRAWN);
  assert.equal(fromGossipBits(0xF0 | 0b11), undefined);  // reserved
});

// ─── Programmer-error guards ─────────────────────────────────────

test('toGossipBits: throws on unknown state', () => {
  assert.throws(() => toGossipBits('not-a-state'), TypeError);
  assert.throws(() => toGossipBits(undefined), TypeError);
  assert.throws(() => toGossipBits(null), TypeError);
});

test('fromGossipBits: throws on non-integer input', () => {
  assert.throws(() => fromGossipBits(1.5), TypeError);
  assert.throws(() => fromGossipBits('1'), TypeError);
  assert.throws(() => fromGossipBits(null), TypeError);
});

// ─── Range sweep ──────────────────────────────────────────────────

test('fromGossipBits: every byte 0..255 returns one of {GRANTED, SUSPENDED, WITHDRAWN, undefined}', () => {
  for (let b = 0; b <= 0xFF; b++) {
    const r = fromGossipBits(b);
    assert.ok(
      r === ConsentState.GRANTED   ||
      r === ConsentState.SUSPENDED ||
      r === ConsentState.WITHDRAWN ||
      r === undefined,
      `byte 0x${b.toString(16)} returned unexpected ${r}`
    );
  }
});
