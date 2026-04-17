'use strict';

/**
 * ConsentEngine tests — MMP Consent Extension v0.1.0, §5.1.
 *
 * Mirrors `axonos-consent/tests/consent_interop.rs:280-396` (the
 * ENGINE, APPLY_FRAME, PROCESS_FRAME blocks plus PROCESS_RAW which
 * we don't have a JS analogue for since we don't decode CBOR).
 *
 * Copyright (c) 2026 SYM.BOT Ltd. Apache 2.0 License.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { ConsentState, FrameType, TransitionError } = require('../lib/consent/state');
const { Scope, parseFrame } = require('../lib/consent/frames');
const { ReasonCode } = require('../lib/consent/reason');
const { InvariantViolation, InvariantWarning } = require('../lib/consent/invariants');
const { ConsentEngine, EngineError, MAX_PEERS } = require('../lib/consent/engine');

// ─── Helpers ──────────────────────────────────────────────────────

const PEER_A = 'peer-a-uuid';
const PEER_B = 'peer-b-uuid';
const PEER_C = 'peer-c-uuid';

const wf = () => ({
  type: FrameType.WITHDRAW,
  scope: Scope.PEER,
  reasonCode: ReasonCode.USER_INITIATED,
  timestampMs: 1711540800000,
});
const sf = () => ({
  type: FrameType.SUSPEND,
  reasonCode: ReasonCode.USER_INITIATED,
  timestampMs: 1711540800000,
});
const rf = () => ({
  type: FrameType.RESUME,
  timestampMs: 1711540860000,
});

// ─── Constants ────────────────────────────────────────────────────

test('MAX_PEERS = 8 (parity with axonos-consent engine.rs:24)', () => {
  assert.equal(MAX_PEERS, 8);
});

test('EngineError enum is frozen', () => {
  assert.equal(Object.isFrozen(EngineError), true);
});

// ─── Peer registration ────────────────────────────────────────────
// Mirrors axonos eng_register / eng_dup / eng_full (lines 280-282)

test('registerPeer: new peer enters GRANTED', () => {
  const e = new ConsentEngine();
  const r = e.registerPeer(PEER_A, 0);
  assert.equal(r.ok, true);
  assert.equal(e.getState(PEER_A), ConsentState.GRANTED);
  assert.equal(e.peerCount, 1);
});

test('registerPeer: duplicate registration → PEER_ALREADY_EXISTS', () => {
  // Mirrors axonos eng_dup at line 281
  const e = new ConsentEngine();
  e.registerPeer(PEER_A, 0);
  const r = e.registerPeer(PEER_A, 100);
  assert.equal(r.ok, false);
  assert.equal(r.error, EngineError.PEER_ALREADY_EXISTS);
  assert.equal(e.peerCount, 1);
});

test('registerPeer: rejects beyond MAX_PEERS', () => {
  // Mirrors axonos eng_full at line 282
  const e = new ConsentEngine();
  for (let i = 0; i < MAX_PEERS; i++) {
    const r = e.registerPeer(`peer-${i}`, 0);
    assert.equal(r.ok, true);
  }
  const r = e.registerPeer('peer-overflow', 0);
  assert.equal(r.ok, false);
  assert.equal(r.error, EngineError.PEER_TABLE_FULL);
  assert.equal(e.peerCount, MAX_PEERS);
});

test('registerPeer: throws on invalid peerId', () => {
  const e = new ConsentEngine();
  assert.throws(() => e.registerPeer('', 0), TypeError);
  assert.throws(() => e.registerPeer(null, 0), TypeError);
  assert.throws(() => e.registerPeer(42, 0), TypeError);
});

test('registerPeer: throws on invalid nowUs', () => {
  const e = new ConsentEngine();
  assert.throws(() => e.registerPeer(PEER_A, -1), TypeError);
  assert.throws(() => e.registerPeer(PEER_A, 1.5), TypeError);
  assert.throws(() => e.registerPeer(PEER_A, 'now'), TypeError);
});

test('getState: unknown peer returns undefined', () => {
  const e = new ConsentEngine();
  assert.equal(e.getState('nope'), undefined);
});

// ─── processFrame — happy paths ───────────────────────────────────
// Mirrors axonos pf_valid_withdraw at line 317

test('processFrame: GRANTED + valid withdraw → WITHDRAWN', () => {
  const e = new ConsentEngine();
  e.registerPeer(PEER_A, 0);
  const r = e.processFrame(PEER_A, wf(), 100);
  assert.equal(r.ok, true);
  assert.equal(r.newState, ConsentState.WITHDRAWN);
  assert.equal(e.getState(PEER_A), ConsentState.WITHDRAWN);
});

test('processFrame: GRANTED + valid suspend → SUSPENDED', () => {
  const e = new ConsentEngine();
  e.registerPeer(PEER_A, 0);
  const r = e.processFrame(PEER_A, sf(), 100);
  assert.equal(r.ok, true);
  assert.equal(r.newState, ConsentState.SUSPENDED);
});

test('processFrame: SUSPENDED + valid resume → GRANTED', () => {
  const e = new ConsentEngine();
  e.registerPeer(PEER_A, 0);
  e.processFrame(PEER_A, sf(), 100);
  const r = e.processFrame(PEER_A, rf(), 200);
  assert.equal(r.ok, true);
  assert.equal(r.newState, ConsentState.GRANTED);
});

test('processFrame: GRANTED + idempotent resume → GRANTED, no error (TV-010)', () => {
  const e = new ConsentEngine();
  e.registerPeer(PEER_A, 0);
  const r = e.processFrame(PEER_A, rf(), 100);
  assert.equal(r.ok, true);
  assert.equal(r.newState, ConsentState.GRANTED);
});

test('processFrame: SUSPENDED + idempotent suspend → SUSPENDED, no error (TV-009)', () => {
  const e = new ConsentEngine();
  e.registerPeer(PEER_A, 0);
  e.processFrame(PEER_A, sf(), 100);
  const r = e.processFrame(PEER_A, sf(), 200);
  assert.equal(r.ok, true);
  assert.equal(r.newState, ConsentState.SUSPENDED);
});

// ─── processFrame — invariant rejection ───────────────────────────
// Mirrors axonos pf_rejects_zero_timestamp at line 324

test('processFrame: zero timestamp_us → ZERO_TIMESTAMP_US', () => {
  const e = new ConsentEngine();
  e.registerPeer(PEER_A, 0);
  const bad = {
    type: FrameType.WITHDRAW,
    scope: Scope.PEER,
    reasonCode: ReasonCode.USER_INITIATED,
    timestampUs: 0,
  };
  const r = e.processFrame(PEER_A, bad, 100);
  assert.equal(r.ok, false);
  assert.equal(r.error, InvariantViolation.ZERO_TIMESTAMP_US);
  // State must NOT have changed
  assert.equal(e.getState(PEER_A), ConsentState.GRANTED);
});

// ─── processFrame — transition rejection ──────────────────────────
// Mirrors axonos pf_rejects_withdrawn_resume at line 334

test('processFrame: WITHDRAWN + resume → ALREADY_WITHDRAWN, state unchanged', () => {
  const e = new ConsentEngine();
  e.registerPeer(PEER_A, 0);
  e.withdraw(PEER_A, ReasonCode.USER_INITIATED, 50);
  assert.equal(e.getState(PEER_A), ConsentState.WITHDRAWN);
  const r = e.processFrame(PEER_A, rf(), 100);
  assert.equal(r.ok, false);
  assert.equal(r.error, TransitionError.ALREADY_WITHDRAWN);
  assert.equal(e.getState(PEER_A), ConsentState.WITHDRAWN);
});

test('processFrame: WITHDRAWN + withdraw → ALREADY_WITHDRAWN (§6.5 Gap 1)', () => {
  const e = new ConsentEngine();
  e.registerPeer(PEER_A, 0);
  e.withdraw(PEER_A, ReasonCode.USER_INITIATED, 50);
  const r = e.processFrame(PEER_A, wf(), 100);
  assert.equal(r.ok, false);
  assert.equal(r.error, TransitionError.ALREADY_WITHDRAWN);
});

// ─── processFrame — SHOULD warnings ───────────────────────────────
// Mirrors axonos pf_warns_missing_timestamp at line 341

test('processFrame: warns on missing timestamp, still applies transition', () => {
  const e = new ConsentEngine();
  e.registerPeer(PEER_A, 0);
  const noTs = {
    type: FrameType.WITHDRAW,
    scope: Scope.PEER,
    reasonCode: ReasonCode.USER_INITIATED,
  };
  const r = e.processFrame(PEER_A, noTs, 100);
  assert.equal(r.ok, true);
  assert.equal(r.newState, ConsentState.WITHDRAWN);
  assert.ok(r.warnings.includes(InvariantWarning.WITHDRAW_MISSING_TIMESTAMP));
});

// ─── processFrame — unknown peer ──────────────────────────────────

test('processFrame: unknown peer → PEER_NOT_FOUND', () => {
  const e = new ConsentEngine();
  const r = e.processFrame('unknown-peer', wf(), 100);
  assert.equal(r.ok, false);
  assert.equal(r.error, EngineError.PEER_NOT_FOUND);
});

// ─── processFrame — programmer-error guards ───────────────────────

test('processFrame: throws on invalid peerId', () => {
  const e = new ConsentEngine();
  assert.throws(() => e.processFrame('', wf(), 100), TypeError);
  assert.throws(() => e.processFrame(null, wf(), 100), TypeError);
});

test('processFrame: throws on invalid nowUs', () => {
  const e = new ConsentEngine();
  e.registerPeer(PEER_A, 0);
  assert.throws(() => e.processFrame(PEER_A, wf(), -1), TypeError);
});

// ─── Direct methods (bypass frame validation) ─────────────────────

test('direct withdraw: GRANTED → WITHDRAWN', () => {
  const e = new ConsentEngine();
  e.registerPeer(PEER_A, 0);
  const r = e.withdraw(PEER_A, ReasonCode.USER_INITIATED, 100);
  assert.equal(r.ok, true);
  assert.equal(r.newState, ConsentState.WITHDRAWN);
});

test('direct suspend → resume cycle', () => {
  const e = new ConsentEngine();
  e.registerPeer(PEER_A, 0);
  let r = e.suspend(PEER_A, ReasonCode.USER_INITIATED, 100);
  assert.equal(r.ok, true);
  assert.equal(r.newState, ConsentState.SUSPENDED);
  r = e.resume(PEER_A, 200);
  assert.equal(r.ok, true);
  assert.equal(r.newState, ConsentState.GRANTED);
});

test('direct withdraw on unknown peer → PEER_NOT_FOUND', () => {
  // Mirrors axonos eng_unknown at line 283
  const e = new ConsentEngine();
  const r = e.withdraw('unknown-peer', undefined, 0);
  assert.equal(r.ok, false);
  assert.equal(r.error, EngineError.PEER_NOT_FOUND);
});

test('direct withdraw on already-WITHDRAWN → ALREADY_WITHDRAWN', () => {
  const e = new ConsentEngine();
  e.registerPeer(PEER_A, 0);
  e.withdraw(PEER_A, ReasonCode.USER_INITIATED, 50);
  const r = e.withdraw(PEER_A, ReasonCode.USER_INITIATED, 100);
  assert.equal(r.ok, false);
  assert.equal(r.error, TransitionError.ALREADY_WITHDRAWN);
});

// ─── withdrawAll ──────────────────────────────────────────────────
// Mirrors axonos eng_withdraw_all at line 284

test('withdrawAll: 3 peers → 3 withdrawn, all in WITHDRAWN', () => {
  const e = new ConsentEngine();
  e.registerPeer(PEER_A, 0);
  e.registerPeer(PEER_B, 0);
  e.registerPeer(PEER_C, 0);
  const result = e.withdrawAll(ReasonCode.EMERGENCY_BUTTON, 100);
  assert.equal(result.count, 3);
  assert.deepEqual(result.withdrawnPeers, [PEER_A, PEER_B, PEER_C]);
  assert.equal(e.getState(PEER_A), ConsentState.WITHDRAWN);
  assert.equal(e.getState(PEER_B), ConsentState.WITHDRAWN);
  assert.equal(e.getState(PEER_C), ConsentState.WITHDRAWN);
});

test('withdrawAll: skips peers already in WITHDRAWN', () => {
  // Matches engine.rs:227 (`if peer.state != ConsentState::Withdrawn`)
  const e = new ConsentEngine();
  e.registerPeer(PEER_A, 0);
  e.registerPeer(PEER_B, 0);
  e.registerPeer(PEER_C, 0);
  e.withdraw(PEER_B, ReasonCode.USER_INITIATED, 50);  // B is already withdrawn
  const result = e.withdrawAll(ReasonCode.EMERGENCY_BUTTON, 100);
  assert.equal(result.count, 2);
  assert.deepEqual(result.withdrawnPeers, [PEER_A, PEER_C]);
});

test('withdrawAll: empty engine → count 0', () => {
  const e = new ConsentEngine();
  const result = e.withdrawAll(ReasonCode.EMERGENCY_BUTTON, 100);
  assert.equal(result.count, 0);
  assert.deepEqual(result.withdrawnPeers, []);
});

test('withdrawAll: preserves insertion order in withdrawnPeers', () => {
  const e = new ConsentEngine();
  // Insert in non-alphabetical order
  e.registerPeer('zebra', 0);
  e.registerPeer('alpha', 0);
  e.registerPeer('mango', 0);
  const result = e.withdrawAll(ReasonCode.EMERGENCY_BUTTON, 100);
  assert.deepEqual(result.withdrawnPeers, ['zebra', 'alpha', 'mango']);
});

// ─── allowsCognitiveFrames ────────────────────────────────────────

test('allowsCognitiveFrames: true only when GRANTED', () => {
  const e = new ConsentEngine();
  e.registerPeer(PEER_A, 0);
  assert.equal(e.allowsCognitiveFrames(PEER_A), true);
  e.suspend(PEER_A, undefined, 100);
  assert.equal(e.allowsCognitiveFrames(PEER_A), false);
  e.resume(PEER_A, 200);
  assert.equal(e.allowsCognitiveFrames(PEER_A), true);
  e.withdraw(PEER_A, undefined, 300);
  assert.equal(e.allowsCognitiveFrames(PEER_A), false);
});

test('allowsCognitiveFrames: unknown peer → false (engine.rs:241 unwrap_or)', () => {
  const e = new ConsentEngine();
  assert.equal(e.allowsCognitiveFrames('nope'), false);
});

// ─── End-to-end: parseFrame → engine.processFrame ─────────────────
// Verifies the parser → engine pipeline composes correctly. This is
// a precursor to the canonical interop runner at step 8.

test('end-to-end: parseFrame → processFrame for TV-001 shape', () => {
  const wire = {
    type: 'consent-withdraw',
    scope: 'peer',
    reasonCode: 1,
    reason: 'user requested disconnect',
    timestamp: 1711540800000,
  };
  const parsed = parseFrame(wire);
  assert.equal(parsed.ok, true);
  const e = new ConsentEngine();
  e.registerPeer(PEER_A, 0);
  const r = e.processFrame(PEER_A, parsed.frame, 100);
  assert.equal(r.ok, true);
  assert.equal(r.newState, ConsentState.WITHDRAWN);
  assert.deepEqual(r.warnings, []);  // TV-001 has reasonCode AND timestamp
});

test('end-to-end: parseFrame → processFrame for TV-005 minimal suspend', () => {
  const wire = { type: 'consent-suspend' };
  const parsed = parseFrame(wire);
  assert.equal(parsed.ok, true);
  const e = new ConsentEngine();
  e.registerPeer(PEER_A, 0);
  const r = e.processFrame(PEER_A, parsed.frame, 100);
  assert.equal(r.ok, true);
  assert.equal(r.newState, ConsentState.SUSPENDED);
  // TV-005 has no reasonCode → SUSPEND_MISSING_REASON_CODE warning expected
  assert.ok(r.warnings.includes(InvariantWarning.SUSPEND_MISSING_REASON_CODE));
});
