'use strict';

/**
 * Canonical interop test runner — MMP Consent Extension v0.1.0.
 *
 * Loads the byte-identical vendored copy of the AxonOS canonical
 * interop vector file and runs every vector through the Node.js
 * consent pipeline. Mirrors the test convention at
 * `axonos-consent/tests/consent_interop.rs::all_15_vectors`
 * (lines 206-232) and `state_transitions` (lines 234-248), with
 * the corrections documented in the joint paper §6 design doc:
 *
 *   - Branches on annotation class per §6.1.3 (10 enforcement-class
 *     + 4 expected_behavior-class + 1 gossip-class)
 *   - Fails loud on transition errors instead of using `unwrap_or`
 *     (see §6.5 Note 1)
 *   - Asserts the protocol-observable subset of `enforcement` only
 *     (`cognitive_frames_allowed`, `connection_closed`); skips
 *     hardware-only fields (`stim_guard_lockout`, `nvram_persisted`)
 *     per §10.2 out-of-scope (§6.2.3)
 *   - Asserts state-before/after transitions only for the 14
 *     frame-class vectors; TV-014 (gossip) is tested separately
 *   - Verifies vendored file SHA-256 to lock the byte-identical
 *     property
 *
 * This runner is the resolution gate for §6 Unverified Markers
 * U1 (Node.js test run results), U2 (two implementations agree),
 * and U3 (built independently against the spec — final claim
 * pending paper review).
 *
 * Copyright (c) 2026 SYM.BOT Ltd. Apache 2.0 License.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const { ConsentState, FrameType, TransitionError } = require('../lib/consent/state');
const { parseFrame } = require('../lib/consent/frames');
const { ConsentEngine } = require('../lib/consent/engine');
const { toGossipBits, fromGossipBits } = require('../lib/consent/gossip');
const { ReasonCode } = require('../lib/consent/reason');

// ─── Vendored file path + integrity check ─────────────────────────

const VECTOR_PATH = path.join(
  __dirname,
  'vendor',
  'consent-interop-vectors-v0.1.0.json'
);

/**
 * SHA-256 of the byte-identical vendored file.
 *
 * Source: this hash was computed at vendor time on 2026-04-07 by
 * running `shasum -a 256` against both the upstream file at
 * /tmp/axonos-v0.1.1/axonos-consent/tests/vectors/...
 * and the vendored copy at sym/tests/vendor/...
 * Both hashes were identical. The hash is recorded in the joint
 * paper §6 design doc Verified Sources table for cross-reference.
 *
 * If this assertion ever fails, the vendored file has been
 * tampered with. Re-vendor from upstream — do NOT update this
 * constant by hand.
 */
const EXPECTED_SHA256 =
  '29a8bf9f2b4dabe5d9641a8a4c416f361c2ba9815cca9b8e9e1d222d002fa50a';

// ─── Load + integrity check ───────────────────────────────────────

let RAW_BYTES;
let CANONICAL;
try {
  RAW_BYTES = fs.readFileSync(VECTOR_PATH);
  CANONICAL = JSON.parse(RAW_BYTES.toString('utf8'));
} catch (e) {
  // If the file is missing the entire suite must fail loudly —
  // this is not a soft skip.
  throw new Error(
    `Cannot load vendored interop vector file at ${VECTOR_PATH}. ` +
    `Run step 1 of the implementation checklist (vendor the file) first. ` +
    `Underlying error: ${e.message}`
  );
}

test('vendored vector file SHA-256 matches recorded hash', () => {
  const actual = crypto.createHash('sha256').update(RAW_BYTES).digest('hex');
  assert.equal(
    actual,
    EXPECTED_SHA256,
    `Vendored file has been tampered with. Re-vendor from upstream.\n` +
    `  expected: ${EXPECTED_SHA256}\n` +
    `  actual:   ${actual}`
  );
});

test('canonical file structure: 15 vectors', () => {
  assert.ok(Array.isArray(CANONICAL.vectors));
  assert.equal(CANONICAL.vectors.length, 15);
});

// ─── Vector classification ────────────────────────────────────────
//
// Per §6.1.1 of the design doc:
//   Class A: 14 vectors with `json` field (frame round-trip + transition)
//   Class B: 1 vector without `json` field (TV-014, gossip encoding)
//
// Within Class A:
//   A.1: 10 vectors with `enforcement` (programmatic effects assertion)
//   A.2:  4 vectors with `expected_behavior` (prose; transition only)

const FRAME_VECTORS = CANONICAL.vectors.filter(v => v.json && typeof v.json === 'object');
const GOSSIP_VECTORS = CANONICAL.vectors.filter(v => !v.json);

test('Class A vector count = 14 (matches §6.1.1 Observation 1)', () => {
  assert.equal(FRAME_VECTORS.length, 14);
});

test('Class B vector count = 1 (TV-014 only)', () => {
  assert.equal(GOSSIP_VECTORS.length, 1);
  assert.equal(GOSSIP_VECTORS[0].id, 'TV-014');
});

const ENFORCEMENT_VECTORS = FRAME_VECTORS.filter(v => v.enforcement);
const BEHAVIOR_VECTORS    = FRAME_VECTORS.filter(v => v.expected_behavior);

test('Class A.1 (enforcement) count = 10 (matches §6.1.1 Observation 2)', () => {
  assert.equal(ENFORCEMENT_VECTORS.length, 10);
});

test('Class A.2 (expected_behavior) count = 4 (matches §6.1.1 Observation 2)', () => {
  assert.equal(BEHAVIOR_VECTORS.length, 4);
});

test('Class A.1 ∪ A.2 = Class A (no frame vector lacks both annotations)', () => {
  assert.equal(
    ENFORCEMENT_VECTORS.length + BEHAVIOR_VECTORS.length,
    FRAME_VECTORS.length
  );
});

// ─── State string conversion ──────────────────────────────────────
//
// The vector file uses lowercase string state names which match
// the ConsentState enum values verbatim. This helper validates
// the assumption and throws on any mismatch.

function parseStateString(s) {
  if (s === ConsentState.GRANTED   ||
      s === ConsentState.SUSPENDED ||
      s === ConsentState.WITHDRAWN) {
    return s;
  }
  throw new Error(`unrecognised state string in vector: "${s}"`);
}

// ─── Engine fixture: register a peer at a specific state_before ──
//
// The engine always registers peers in GRANTED. To set up a vector
// whose state_before is "suspended", we register then directly
// suspend. For "withdrawn" we register then directly withdraw —
// note that no canonical vector has state_before: withdrawn (see
// §6.1.1 Observation 3), so the third branch is unreachable on
// the current vector set; it is included for forward compatibility
// per §6.5 Note 1 (the Node.js runner fails loud on future
// additions instead of silently masking them).

function setupPeer(engine, peerId, stateBefore) {
  const r = engine.registerPeer(peerId, 1);
  assert.equal(r.ok, true, 'peer registration must succeed');

  if (stateBefore === ConsentState.GRANTED) {
    return;
  }
  if (stateBefore === ConsentState.SUSPENDED) {
    const s = engine.suspend(peerId, ReasonCode.USER_INITIATED, 2);
    assert.equal(s.ok, true, 'fixture suspend must succeed');
    return;
  }
  if (stateBefore === ConsentState.WITHDRAWN) {
    const w = engine.withdraw(peerId, ReasonCode.USER_INITIATED, 2);
    assert.equal(w.ok, true, 'fixture withdraw must succeed');
    return;
  }
  throw new Error(`setupPeer: unknown state_before "${stateBefore}"`);
}

// ─── Per-vector test generation: Class A.1 (enforcement) ──────────

for (const v of ENFORCEMENT_VECTORS) {
  test(`${v.id} (Class A.1, §${v.section}): ${v.name}`, () => {
    const stateBefore = parseStateString(v.state_before);
    const stateAfter  = parseStateString(v.state_after);

    // Step 1: parse the wire frame
    const parsed = parseFrame(v.json);
    assert.equal(
      parsed.ok, true,
      `${v.id}: parseFrame failed: ${JSON.stringify(parsed)}`
    );

    // Step 2: set up the engine fixture for state_before
    const engine = new ConsentEngine();
    const peerId = 'interop-test-peer';
    setupPeer(engine, peerId, stateBefore);
    assert.equal(engine.getState(peerId), stateBefore);

    // Step 3: process the frame through the full pipeline
    const result = engine.processFrame(peerId, parsed.frame, 1000);

    // Step 4: assert {ok:true} and the resulting state
    assert.equal(
      result.ok, true,
      `${v.id}: processFrame failed: ${JSON.stringify(result)}`
    );
    assert.equal(
      result.newState, stateAfter,
      `${v.id}: state mismatch (expected ${stateAfter}, got ${result.newState})`
    );
    assert.equal(engine.getState(peerId), stateAfter);

    // Step 5: assert the protocol-observable subset of enforcement
    //
    // We check `cognitive_frames_allowed` against engine.allowsCognitiveFrames
    // and `connection_closed` against (state === WITHDRAWN). We do NOT
    // assert `stim_guard_lockout` or `nvram_persisted` — those are
    // §10.2 hardware concerns out of scope per §9 Division of
    // Responsibility (§6.1.3 Class A.1 pass criterion 5).

    const enf = v.enforcement;
    if (typeof enf.cognitive_frames_allowed === 'boolean') {
      assert.equal(
        engine.allowsCognitiveFrames(peerId),
        enf.cognitive_frames_allowed,
        `${v.id}: cognitive_frames_allowed mismatch`
      );
    }
    if (typeof enf.connection_closed === 'boolean') {
      const closed = result.newState === ConsentState.WITHDRAWN;
      assert.equal(
        closed,
        enf.connection_closed,
        `${v.id}: connection_closed mismatch`
      );
    }
  });
}

// ─── Per-vector test generation: Class A.2 (expected_behavior) ───

for (const v of BEHAVIOR_VECTORS) {
  test(`${v.id} (Class A.2, §${v.section}): ${v.name}`, () => {
    const stateBefore = parseStateString(v.state_before);
    const stateAfter  = parseStateString(v.state_after);

    const parsed = parseFrame(v.json);
    assert.equal(
      parsed.ok, true,
      `${v.id}: parseFrame failed: ${JSON.stringify(parsed)}`
    );

    const engine = new ConsentEngine();
    const peerId = 'interop-test-peer';
    setupPeer(engine, peerId, stateBefore);

    const result = engine.processFrame(peerId, parsed.frame, 1000);

    assert.equal(
      result.ok, true,
      `${v.id}: processFrame failed: ${JSON.stringify(result)}. ` +
      `expected_behavior: "${v.expected_behavior}"`
    );
    assert.equal(
      result.newState, stateAfter,
      `${v.id}: state mismatch (expected ${stateAfter}, got ${result.newState}). ` +
      `expected_behavior: "${v.expected_behavior}"`
    );

    // The expected_behavior string is preserved in the test name
    // and assertion messages but not parsed or asserted programmatically
    // — see §6.1.3 Class A.2 criterion.
  });
}

// ─── Class B: TV-014 gossip encoding ──────────────────────────────

test('TV-014 (Class B, §6.4): gossip encoding 2-bit map matches verbatim', () => {
  const v = GOSSIP_VECTORS[0];
  assert.ok(v.gossip_encoding, 'TV-014 must have gossip_encoding map');

  // Spec strings: "0b00", "0b01", "0b10", "0b11"
  // Parse the prefix and compare to our encoder/decoder.

  function parseBitString(s) {
    assert.match(s, /^0b[01]+$/, `gossip_encoding value must be 0b... binary literal, got ${s}`);
    return parseInt(s.slice(2), 2);
  }

  assert.equal(parseBitString(v.gossip_encoding.granted),   toGossipBits(ConsentState.GRANTED));
  assert.equal(parseBitString(v.gossip_encoding.suspended), toGossipBits(ConsentState.SUSPENDED));
  assert.equal(parseBitString(v.gossip_encoding.withdrawn), toGossipBits(ConsentState.WITHDRAWN));
  // Reserved cell: decoder returns undefined for the reserved value
  // (matches AxonOS Option<Self>::None semantics — see gossip.js
  // file header).
  assert.equal(fromGossipBits(parseBitString(v.gossip_encoding.reserved)), undefined);
});

test('TV-014 (Class B, §6.4): example_peer_info parses with consentState field intact', () => {
  // Verbatim from consent-interop-vectors-v0.1.0.json:272-278
  const v = GOSSIP_VECTORS[0];
  const example = v.example_peer_info;
  assert.ok(example, 'TV-014 must have example_peer_info');
  assert.equal(example.type, 'peer-info');
  assert.ok(Array.isArray(example.peers));
  assert.equal(example.peers.length, 2);
  // The two peers in the example carry consentState fields. Verify
  // they round-trip through fromGossipBits via the string-to-bit
  // mapping defined in TV-014.gossip_encoding.
  const map = {
    granted:   0b00,
    suspended: 0b01,
    withdrawn: 0b10,
  };
  for (const peer of example.peers) {
    assert.ok(peer.consentState in map, `unknown consentState string ${peer.consentState}`);
    const bits = map[peer.consentState];
    assert.equal(fromGossipBits(bits), peer.consentState);
  }
});

// ─── Final aggregate assertion ────────────────────────────────────
//
// Mirrors `axonos-consent/tests/consent_interop.rs:231` (`assert!(ok >= 14)`).
//
// We don't track an `ok` counter explicitly because the per-vector
// tests above already fail individually if any vector mismatches.
// This final test asserts the inventory the suite was designed
// against, so any future change to the vendored file (a new vector,
// a removed vector) is caught here.

test('inventory: 14 frame vectors + 1 gossip vector = 15 total', () => {
  assert.equal(FRAME_VECTORS.length + GOSSIP_VECTORS.length, 15);
  assert.equal(ENFORCEMENT_VECTORS.length, 10);
  assert.equal(BEHAVIOR_VECTORS.length, 4);
  assert.equal(GOSSIP_VECTORS.length, 1);
});
