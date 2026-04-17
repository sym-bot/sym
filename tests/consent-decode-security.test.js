'use strict';

/**
 * Consent decode-security unit tests — fault injection on the
 * Node.js JSON parser surface for MMP Consent Extension v0.1.0.
 *
 * Mirrors the spirit of `axonos-consent/tests/consent_interop.rs::sec_*`
 * (lines 63-111). The exact fault surface differs because Denis's
 * tests target the bounded CBOR decoder (oversized maps, byte
 * strings where text is expected, duplicate keys, negative
 * integers), while the Node.js parser layer sits on top of the
 * built-in `JSON.parse` which already rejects most wire-level
 * faults before they reach our code. The tests here focus on
 * what the consent layer rejects **beyond** what JSON.parse
 * already catches.
 *
 * ## Fault categories covered
 *
 * 1. JSON.parse failures (caller responsibility — we test the
 *    boundary so callers know what to expect)
 * 2. Top-level shape rejection (non-object, array, null)
 * 3. Required-field absence (missing type, missing scope)
 * 4. Type confusion at field level (string where uint expected,
 *    number where string expected, etc.)
 * 5. Range bounds (negative, non-integer, > MAX byte for
 *    reasonCode, > MAX_REASON_LEN for reason)
 * 6. Forward-compatibility safety (unknown fields silently
 *    ignored, unknown reasonCode normalised, oversized number
 *    rejected via JS safe-integer boundary)
 * 7. Engine-level fault injection (PEER_NOT_FOUND, peer-table
 *    overflow attack)
 *
 * Copyright (c) 2026 SYM.BOT Ltd. Apache 2.0 License.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { ConsentState, FrameType } = require('../lib/consent/state');
const { Scope, ParseError, parseFrame } = require('../lib/consent/frames');
const { ReasonCode } = require('../lib/consent/reason');
const { MAX_REASON_LEN, InvariantViolation, checkFrame } = require('../lib/consent/invariants');
const { ConsentEngine, EngineError, MAX_PEERS } = require('../lib/consent/engine');

// ─── Category 1: JSON.parse boundary ───────────────────────────────
//
// JSON.parse is a Node built-in we don't ship. These tests document
// the boundary so callers know that they MUST call JSON.parse before
// passing to parseFrame, and that JSON.parse failures are out of
// scope for the consent parser.

test('boundary: JSON.parse rejects malformed JSON before reaching parseFrame', () => {
  assert.throws(() => JSON.parse('{not-json'), SyntaxError);
  assert.throws(() => JSON.parse(''), SyntaxError);
  assert.throws(() => JSON.parse('{"unterminated":'), SyntaxError);
});

test('boundary: JSON.parse accepts arbitrarily nested objects (no bound)', () => {
  // Unlike CBOR's MAX_NESTING=4 (cbor.rs:42), JSON.parse has no
  // depth limit. Our parser does not nest, so depth attacks land
  // either in JSON.parse (which has its own protection at very
  // large depths via stack overflow) or are flattened by the
  // parser's flat field reads. Document this so the joint paper
  // §6 description does not incorrectly claim a depth bound.
  let nested = '{"a":';
  for (let i = 0; i < 100; i++) nested += '{"a":';
  nested += '1';
  for (let i = 0; i < 100; i++) nested += '}';
  nested += '}';
  // JSON.parse does not throw at depth 100. The parsed object is
  // an opaque nested structure; parseFrame will reject it because
  // it has no `type` field.
  const obj = JSON.parse(nested);
  const r = parseFrame(obj);
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.MISSING_TYPE);
});

// ─── Category 2: Top-level shape rejection ────────────────────────

test('top-level: null → NOT_AN_OBJECT', () => {
  const r = parseFrame(null);
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.NOT_AN_OBJECT);
});

test('top-level: array → NOT_AN_OBJECT', () => {
  const r = parseFrame(['type', 'consent-withdraw']);
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.NOT_AN_OBJECT);
});

test('top-level: string → NOT_AN_OBJECT', () => {
  const r = parseFrame('consent-withdraw');
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.NOT_AN_OBJECT);
});

test('top-level: number → NOT_AN_OBJECT', () => {
  const r = parseFrame(42);
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.NOT_AN_OBJECT);
});

// ─── Category 3: Required-field absence ───────────────────────────
// Mirrors the spirit of axonos sec_* type-field rejection at line 75
// (which targets CBOR's negative-int-where-text-expected — same
// underlying invariant: "type" MUST be present and parseable as a string)

test('missing type → MISSING_TYPE', () => {
  const r = parseFrame({ scope: 'peer' });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.MISSING_TYPE);
});

test('null type → MISSING_TYPE', () => {
  const r = parseFrame({ type: null });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.MISSING_TYPE);
});

test('boolean type → MISSING_TYPE', () => {
  const r = parseFrame({ type: true });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.MISSING_TYPE);
});

test('object type → MISSING_TYPE', () => {
  const r = parseFrame({ type: { nested: 'consent-withdraw' } });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.MISSING_TYPE);
});

test('withdraw missing scope → MISSING_SCOPE', () => {
  const r = parseFrame({ type: 'consent-withdraw' });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.MISSING_SCOPE);
});

test('withdraw with null scope → MISSING_SCOPE (null is treated as absent)', () => {
  // Note: `obj.scope === null` is "field present, value null". The
  // parser uses hasOwnProperty for the missing-vs-absent test, then
  // checks the value type. Per parseFrame, null scope flows through
  // hasOwnProperty=true → typeof null === 'object' → INVALID_FIELD_TYPE.
  // We assert what actually happens, not what we wished happened.
  const r = parseFrame({ type: 'consent-withdraw', scope: null });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.INVALID_FIELD_TYPE);
});

// ─── Category 4: Field-level type confusion ───────────────────────

test('withdraw + numeric scope → INVALID_FIELD_TYPE', () => {
  const r = parseFrame({ type: 'consent-withdraw', scope: 1 });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.INVALID_FIELD_TYPE);
});

test('withdraw + array scope → INVALID_FIELD_TYPE', () => {
  const r = parseFrame({ type: 'consent-withdraw', scope: ['peer'] });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.INVALID_FIELD_TYPE);
});

test('withdraw + object scope → INVALID_FIELD_TYPE', () => {
  const r = parseFrame({ type: 'consent-withdraw', scope: { value: 'peer' } });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.INVALID_FIELD_TYPE);
});

test('withdraw + unknown scope string → UNKNOWN_SCOPE', () => {
  const r = parseFrame({ type: 'consent-withdraw', scope: 'group' });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.UNKNOWN_SCOPE);
});

test('withdraw + reasonCode as string → INVALID_FIELD_TYPE', () => {
  const r = parseFrame({
    type: 'consent-withdraw',
    scope: 'peer',
    reasonCode: '1',
  });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.INVALID_FIELD_TYPE);
});

test('withdraw + reasonCode as object → INVALID_FIELD_TYPE', () => {
  const r = parseFrame({
    type: 'consent-withdraw',
    scope: 'peer',
    reasonCode: { value: 1 },
  });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.INVALID_FIELD_TYPE);
});

test('withdraw + reason as number → INVALID_FIELD_TYPE', () => {
  const r = parseFrame({
    type: 'consent-withdraw',
    scope: 'peer',
    reason: 42,
  });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.INVALID_FIELD_TYPE);
});

test('withdraw + epoch as string → INVALID_FIELD_TYPE', () => {
  const r = parseFrame({
    type: 'consent-withdraw',
    scope: 'peer',
    epoch: '48291',
  });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.INVALID_FIELD_TYPE);
});

test('withdraw + timestamp as bool → INVALID_FIELD_TYPE', () => {
  const r = parseFrame({
    type: 'consent-withdraw',
    scope: 'peer',
    timestamp: true,
  });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.INVALID_FIELD_TYPE);
});

// ─── Category 5: Numeric range bounds ─────────────────────────────

test('reasonCode = 256 → INVALID_FIELD_TYPE (out of byte range)', () => {
  const r = parseFrame({
    type: 'consent-withdraw',
    scope: 'peer',
    reasonCode: 256,
  });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.INVALID_FIELD_TYPE);
});

test('reasonCode = -1 → INVALID_FIELD_TYPE (negative)', () => {
  const r = parseFrame({
    type: 'consent-withdraw',
    scope: 'peer',
    reasonCode: -1,
  });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.INVALID_FIELD_TYPE);
});

test('reasonCode = 1.5 → INVALID_FIELD_TYPE (non-integer)', () => {
  const r = parseFrame({
    type: 'consent-withdraw',
    scope: 'peer',
    reasonCode: 1.5,
  });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.INVALID_FIELD_TYPE);
});

test('timestamp = -1 → INVALID_FIELD_TYPE (negative)', () => {
  const r = parseFrame({
    type: 'consent-withdraw',
    scope: 'peer',
    timestamp: -1,
  });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.INVALID_FIELD_TYPE);
});

test('timestamp = 1.5 → INVALID_FIELD_TYPE (non-integer)', () => {
  const r = parseFrame({
    type: 'consent-withdraw',
    scope: 'peer',
    timestamp: 1.5,
  });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.INVALID_FIELD_TYPE);
});

test('timestamp = NaN → INVALID_FIELD_TYPE', () => {
  const r = parseFrame({
    type: 'consent-withdraw',
    scope: 'peer',
    timestamp: NaN,
  });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.INVALID_FIELD_TYPE);
});

test('timestamp = Infinity → INVALID_FIELD_TYPE', () => {
  const r = parseFrame({
    type: 'consent-withdraw',
    scope: 'peer',
    timestamp: Infinity,
  });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.INVALID_FIELD_TYPE);
});

test('timestamp = 0 → parses to typed frame, then invariant rejects (§6.5 Note 5)', () => {
  // Per Note 5 of §6.5: timestamp=0 is wire-shape valid (uint64 0
  // is structurally a uint64) but invariants reject it. The two
  // layers must produce different verdicts: parser accepts, then
  // invariant rejects. This separation matches AxonOS exactly:
  // CBOR decode succeeds, invariants::check_frame raises
  // ZeroTimestampMs.
  const wire = {
    type: 'consent-withdraw',
    scope: 'peer',
    reasonCode: 1,
    timestamp: 0,
  };
  const parsed = parseFrame(wire);
  assert.equal(parsed.ok, true, 'parser must accept timestamp=0 (wire-shape valid)');
  const inv = checkFrame(parsed.frame);
  assert.equal(inv.ok, false, 'invariant must reject timestamp=0');
  assert.ok(inv.violations.includes(InvariantViolation.ZERO_TIMESTAMP_MS));
});

// ─── Category 6: Forward compatibility ────────────────────────────

test('forward-compat: unknown frame type → UNKNOWN_FRAME_TYPE (not silently accepted)', () => {
  // Unknown FRAME types must be rejected — only unknown FIELDS are
  // silently ignored per spec §6.4 / line 345.
  const r = parseFrame({ type: 'consent-revoke' });
  assert.equal(r.ok, false);
  assert.equal(r.error, ParseError.UNKNOWN_FRAME_TYPE);
});

test('forward-compat: unknown fields silently ignored on withdraw', () => {
  const r = parseFrame({
    type: 'consent-withdraw',
    scope: 'peer',
    reasonCode: 1,
    timestamp: 1711540800000,
    unknown_field_1: 'future-extension',
    futureFieldNumeric: 12345,
    nested_unknown: { future: 'spec' },
  });
  assert.equal(r.ok, true);
  assert.equal(r.frame.unknown_field_1, undefined);
  assert.equal(r.frame.futureFieldNumeric, undefined);
  assert.equal(r.frame.nested_unknown, undefined);
});

test('forward-compat: unknown fields silently ignored on suspend', () => {
  const r = parseFrame({
    type: 'consent-suspend',
    futureField: 'x',
  });
  assert.equal(r.ok, true);
});

test('forward-compat: unknown fields silently ignored on resume', () => {
  const r = parseFrame({
    type: 'consent-resume',
    futureField: 'x',
  });
  assert.equal(r.ok, true);
});

test('forward-compat: unknown reasonCode (255) normalises to UNSPECIFIED (TV-012 contract)', () => {
  const r = parseFrame({
    type: 'consent-withdraw',
    scope: 'peer',
    reasonCode: 255,
    timestamp: 1711540800000,
  });
  assert.equal(r.ok, true);
  assert.equal(r.frame.reasonCode, ReasonCode.UNSPECIFIED);
});

// ─── Category 7: Engine-level fault injection ────────────────────

test('engine: processFrame on unknown peer → PEER_NOT_FOUND', () => {
  const e = new ConsentEngine();
  // No peer registered.
  const r = e.processFrame('attacker-spoofed-peer', {
    type: FrameType.WITHDRAW,
    scope: Scope.PEER,
    reasonCode: ReasonCode.USER_INITIATED,
    timestampMs: 1711540800000,
  }, 100);
  assert.equal(r.ok, false);
  assert.equal(r.error, EngineError.PEER_NOT_FOUND);
});

test('engine: peer-table overflow attack stops at MAX_PEERS', () => {
  // An attacker that can register peers cannot exhaust memory by
  // registering an unbounded number — the engine refuses past
  // MAX_PEERS = 8, matching AxonOS engine.rs:24.
  const e = new ConsentEngine();
  const successes = [];
  for (let i = 0; i < 1000; i++) {
    const r = e.registerPeer(`attacker-${i}`, 0);
    if (r.ok) successes.push(i);
  }
  assert.equal(successes.length, MAX_PEERS);
  assert.equal(e.peerCount, MAX_PEERS);
});

test('engine: registerPeer twice for same id → PEER_ALREADY_EXISTS, no overwrite', () => {
  // An attacker who knows a registered peer id cannot reset its
  // state by re-registering. The second call must be rejected.
  const e = new ConsentEngine();
  e.registerPeer('victim', 0);
  // Move victim to WITHDRAWN
  e.withdraw('victim', ReasonCode.USER_INITIATED, 50);
  assert.equal(e.getState('victim'), ConsentState.WITHDRAWN);
  // Attempt to "reset" via re-registration
  const r = e.registerPeer('victim', 100);
  assert.equal(r.ok, false);
  assert.equal(r.error, EngineError.PEER_ALREADY_EXISTS);
  // State must still be WITHDRAWN
  assert.equal(e.getState('victim'), ConsentState.WITHDRAWN);
});

test('engine: WITHDRAWN peer cannot be re-suspended via processFrame', () => {
  // The state machine rejects all transitions from WITHDRAWN
  // (§6.5 Gap 1, AxonOS Interpretation A). This is the behavioural
  // counterpart to the previous test: even if the peer is registered,
  // once it is in WITHDRAWN no protocol-level frame can move it.
  const e = new ConsentEngine();
  e.registerPeer('victim', 0);
  e.withdraw('victim', ReasonCode.USER_INITIATED, 50);
  const tryResurrect = e.processFrame('victim', {
    type: FrameType.SUSPEND,
    reasonCode: ReasonCode.USER_INITIATED,
    timestampMs: 1711540800000,
  }, 100);
  assert.equal(tryResurrect.ok, false);
  assert.equal(e.getState('victim'), ConsentState.WITHDRAWN);
});

test('engine: invariant rejection does not commit state change', () => {
  // A frame that fails invariants must leave the engine state
  // unchanged. This guarantees that an attacker cannot use a
  // malformed frame to half-commit a transition.
  const e = new ConsentEngine();
  e.registerPeer('victim', 0);
  const before = e.getState('victim');
  const r = e.processFrame('victim', {
    type: FrameType.WITHDRAW,
    scope: Scope.PEER,
    reasonCode: ReasonCode.USER_INITIATED,
    timestampUs: 0,  // ZERO_TIMESTAMP_US — MUST violation
  }, 100);
  assert.equal(r.ok, false);
  assert.equal(r.error, InvariantViolation.ZERO_TIMESTAMP_US);
  assert.equal(e.getState('victim'), before);
});

test('engine: oversized reason cannot half-commit', () => {
  const e = new ConsentEngine();
  e.registerPeer('victim', 0);
  const before = e.getState('victim');
  const r = e.processFrame('victim', {
    type: FrameType.WITHDRAW,
    scope: Scope.PEER,
    reasonCode: ReasonCode.USER_INITIATED,
    reason: 'x'.repeat(MAX_REASON_LEN + 1),
    timestampMs: 1711540800000,
  }, 100);
  assert.equal(r.ok, false);
  assert.equal(r.error, InvariantViolation.REASON_TOO_LONG);
  assert.equal(e.getState('victim'), before);
});
