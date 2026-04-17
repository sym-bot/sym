'use strict';

/**
 * ConsentEngine — per-peer consent state machine with the full
 * MMP Consent Extension v0.1.0 enforcement pipeline.
 *
 * Mirrors `axonos-consent/src/engine.rs` (251 lines). The Node.js
 * port preserves:
 *
 *   - Explicit `registerPeer` (no implicit registration on first
 *     frame). Mirrors `engine.rs:76-88`.
 *   - Single `processFrame` entry point that runs the full pipeline:
 *     invariants → state transition → enforcement effects. Mirrors
 *     `engine.rs:137-176`.
 *   - Direct `withdraw`/`suspend`/`resume` methods for emergency
 *     interrupt paths that bypass frame-level validation. Mirrors
 *     `engine.rs:180-211` ("Direct methods (bypass frame validation,
 *     for internal/emergency use)").
 *   - `withdrawAll` global kill-switch that returns a fixed-shape
 *     audit-trail object with the list of withdrawn peer ids and
 *     a count, in withdrawal order, skipping peers already in
 *     WITHDRAWN. Mirrors `engine.rs:220-238` (`withdraw_all`).
 *   - `allowsCognitiveFrames` per-peer gate for §6.1. Mirrors
 *     `engine.rs:241-243`.
 *
 * ## What this engine does NOT do
 *
 * - It does not parse JSON. The caller passes a typed frame object
 *   (output of `frames.parseFrame`). The engine's job starts after
 *   parsing succeeds.
 * - It does not perform transport. The §5.1 enforcement sequence
 *   step 5 (notification send) is the caller's responsibility — the
 *   engine signals "you should now send a notification frame to the
 *   peer" via the result object, but does not touch any socket.
 * - It does not implement §10.2 safety-critical conformance: no
 *   NVRAM persistence, no power-cycle no-auto-reconnect, no
 *   StimGuard mapping. Those are AxonOS-side concerns per the
 *   Division of Responsibility (§9). The Node.js implementation
 *   targets §10.1 general conformance only — see §6.2.3 of the
 *   joint paper §6 design doc.
 *
 * ## Result discipline
 *
 * Every public method returns a discriminated result object:
 *   { ok: true,  newState, warnings }
 *   { ok: false, error, ... }
 *
 * Exceptions are reserved for programmer errors (invalid argument
 * types, unknown enum values), never for state-machine rejection
 * of valid frames in invalid states or for invariant violations
 * on otherwise-shaped frames.
 *
 * ## Peer table
 *
 * Backed by a plain `Map<string, PeerConsent>` keyed by peer id
 * (an opaque string the caller provides — typically a hex-encoded
 * MMP nodeId). AxonOS uses a fixed `[Option<PeerConsent>; MAX_PEERS]`
 * array because no_std forbids heap allocation; Node.js has no
 * such constraint. The behavioural surface is identical: peers must
 * be explicitly registered, the engine rejects frames for unknown
 * peers, and `MAX_PEERS = 8` is enforced as a soft cap for parity.
 *
 * Copyright (c) 2026 SYM.BOT Ltd. Apache 2.0 License.
 */

const {
  ConsentState,
  FrameType,
  TransitionError,
  applyFrame,
  allowsCognitiveFrames: stateAllowsCognitiveFrames,
} = require('./state');
const { checkFrame, InvariantViolation } = require('./invariants');

// ─── Constants ────────────────────────────────────────────────────

/**
 * Maximum number of peers in the engine's table.
 * Mirrors `axonos-consent/src/engine.rs:24` (`MAX_PEERS: usize = 8`).
 *
 * The bound is a BLE mesh constraint per §6.4. Node.js could carry
 * more, but the cross-implementation parity choice is to enforce
 * the same cap so that any peer table state observable on the
 * Rust side is also reproducible on the Node.js side.
 */
const MAX_PEERS = 8;

// ─── Engine errors (distinct from invariant + transition errors) ─

const EngineError = Object.freeze({
  PEER_NOT_FOUND:       'PEER_NOT_FOUND',
  PEER_ALREADY_EXISTS:  'PEER_ALREADY_EXISTS',
  PEER_TABLE_FULL:      'PEER_TABLE_FULL',
});

// ─── ConsentEngine ────────────────────────────────────────────────

class ConsentEngine {
  constructor() {
    /**
     * @type {Map<string, {
     *   peerId: string,
     *   state: string,
     *   lastReason: number | undefined,
     *   lastTransitionUs: number,
     * }>}
     */
    this._peers = new Map();
  }

  // ─── Peer table management ──────────────────────────────────────

  /**
   * Register a new peer in GRANTED state.
   *
   * Mirrors `axonos-consent/src/engine.rs::register_peer` (lines 76-88).
   *
   * Returns a discriminated result. Refuses to overwrite an existing
   * peer (matches Denis's `Err("peer already registered")` at line 77)
   * and refuses to exceed `MAX_PEERS` (matches `Err("peer table full")`
   * at line 87).
   *
   * @param {string} peerId
   * @param {number} nowUs - monotonic clock in microseconds
   * @returns {{ok: true} | {ok: false, error: string}}
   */
  registerPeer(peerId, nowUs) {
    if (typeof peerId !== 'string' || peerId.length === 0) {
      throw new TypeError(`registerPeer: peerId must be a non-empty string`);
    }
    if (typeof nowUs !== 'number' || !Number.isInteger(nowUs) || nowUs < 0) {
      throw new TypeError(`registerPeer: nowUs must be a non-negative integer`);
    }
    if (this._peers.has(peerId)) {
      return { ok: false, error: EngineError.PEER_ALREADY_EXISTS };
    }
    if (this._peers.size >= MAX_PEERS) {
      return { ok: false, error: EngineError.PEER_TABLE_FULL };
    }
    this._peers.set(peerId, {
      peerId,
      state: ConsentState.GRANTED,
      lastReason: undefined,
      lastTransitionUs: nowUs,
    });
    return { ok: true };
  }

  /**
   * Get the current state for a peer, or undefined if not registered.
   * Mirrors `engine.rs::get_state` (line 90-92).
   *
   * @param {string} peerId
   * @returns {string | undefined}
   */
  getState(peerId) {
    const p = this._peers.get(peerId);
    return p ? p.state : undefined;
  }

  /**
   * Total number of registered peers.
   */
  get peerCount() {
    return this._peers.size;
  }

  // ─── processFrame — full pipeline ───────────────────────────────

  /**
   * Process a typed consent frame for a specific peer through the
   * full enforcement pipeline:
   *
   *   1. invariants.checkFrame() — MUST violations reject, SHOULD
   *      warnings recorded
   *   2. state.applyFrame() — exhaustive transition check
   *   3. State update (state, lastReason, lastTransitionUs)
   *
   * Mirrors `axonos-consent/src/engine.rs::process_frame` (lines
   * 137-176).
   *
   * The Node.js implementation does NOT trigger any StimGuard
   * callback (§10.2 safety-critical conformance is out of scope —
   * see file header). It also does not write to NVRAM, does not
   * close any transport connection, and does not send the §5.1
   * step-5 notification frame. Those are caller responsibilities.
   *
   * @param {string} peerId
   * @param {object} frame - typed consent frame from frames.parseFrame
   * @param {number} nowUs - monotonic clock in microseconds
   * @returns {{
   *   ok: true,
   *   newState: string,
   *   warnings: string[],
   * } | {
   *   ok: false,
   *   error: string,
   *   detail?: string,
   * }}
   */
  processFrame(peerId, frame, nowUs) {
    if (typeof peerId !== 'string' || peerId.length === 0) {
      throw new TypeError(`processFrame: peerId must be a non-empty string`);
    }
    if (typeof nowUs !== 'number' || !Number.isInteger(nowUs) || nowUs < 0) {
      throw new TypeError(`processFrame: nowUs must be a non-negative integer`);
    }

    // Step 1: Frame-level invariant check
    // Mirrors engine.rs:144-151
    const inv = checkFrame(frame);
    if (!inv.ok) {
      return {
        ok: false,
        error: inv.violations[0],  // first violation, matching engine.rs:148
        violations: inv.violations,
      };
    }

    // Step 2: Find peer
    // Mirrors engine.rs:153-155
    const peer = this._peers.get(peerId);
    if (!peer) {
      return {
        ok: false,
        error: EngineError.PEER_NOT_FOUND,
      };
    }

    // Step 3: Apply state transition
    // Mirrors engine.rs:157-158
    const trans = applyFrame(peer.state, frame);
    if (!trans.ok) {
      return {
        ok: false,
        error: trans.error,
      };
    }

    // Step 4: Commit state update
    // Mirrors engine.rs:160-163
    peer.state = trans.newState;
    peer.lastReason = frame.reasonCode;  // undefined for resume frames
    peer.lastTransitionUs = nowUs;

    // §10.2 step 5 (StimGuard callback) is not implemented — Node.js
    // targets §10.1 general conformance only. See file header.

    return {
      ok: true,
      newState: trans.newState,
      warnings: inv.warnings,
    };
  }

  // ─── Direct methods (bypass frame-level validation) ─────────────
  //
  // Mirrors engine.rs:180-211. These methods are for internal use
  // and emergency interrupt paths. They skip checkFrame() but still
  // run the state-machine transition check, so they cannot violate
  // the WITHDRAWN-is-terminal invariant.

  /**
   * Direct suspend, bypassing frame-level invariants.
   * Mirrors engine.rs::suspend (180-187).
   */
  suspend(peerId, reasonCode, nowUs) {
    return this._directTransition(peerId, FrameType.SUSPEND, reasonCode, nowUs);
  }

  /**
   * Direct resume, bypassing frame-level invariants.
   * Mirrors engine.rs::resume (189-196).
   */
  resume(peerId, nowUs) {
    return this._directTransition(peerId, FrameType.RESUME, undefined, nowUs);
  }

  /**
   * Direct withdrawal, bypassing frame-level invariants.
   * Mirrors engine.rs::withdraw (202-211).
   *
   * §8: physical button → direct interrupt → this function.
   * On the Node.js side this is for test fixtures and any future
   * caller that needs the same skip-validation surface; there is
   * no actual interrupt path.
   */
  withdraw(peerId, reasonCode, nowUs) {
    return this._directTransition(peerId, FrameType.WITHDRAW, reasonCode, nowUs);
  }

  _directTransition(peerId, frameType, reasonCode, nowUs) {
    if (typeof peerId !== 'string' || peerId.length === 0) {
      throw new TypeError(`peerId must be a non-empty string`);
    }
    if (typeof nowUs !== 'number' || !Number.isInteger(nowUs) || nowUs < 0) {
      throw new TypeError(`nowUs must be a non-negative integer`);
    }
    const peer = this._peers.get(peerId);
    if (!peer) {
      return { ok: false, error: EngineError.PEER_NOT_FOUND };
    }
    const trans = applyFrame(peer.state, { type: frameType });
    if (!trans.ok) {
      return { ok: false, error: trans.error };
    }
    peer.state = trans.newState;
    if (reasonCode !== undefined) peer.lastReason = reasonCode;
    peer.lastTransitionUs = nowUs;
    return { ok: true, newState: trans.newState };
  }

  // ─── withdrawAll — emergency global kill-switch ─────────────────

  /**
   * Withdraw consent from all currently-non-WITHDRAWN peers.
   *
   * Mirrors `axonos-consent/src/engine.rs::withdraw_all` (lines
   * 220-238). Returns a fixed-shape audit trail object: a list of
   * peer ids that were withdrawn (in iteration order, which on
   * `Map` matches insertion order) and a count.
   *
   * Peers already in WITHDRAWN are skipped — matches `engine.rs:227`
   * (`if peer.state != ConsentState::Withdrawn`).
   *
   * @param {number} reasonCode - applied to every withdrawn peer
   * @param {number} nowUs - monotonic clock in microseconds
   * @returns {{
   *   withdrawnPeers: string[],
   *   count: number,
   * }}
   */
  withdrawAll(reasonCode, nowUs) {
    if (typeof nowUs !== 'number' || !Number.isInteger(nowUs) || nowUs < 0) {
      throw new TypeError(`withdrawAll: nowUs must be a non-negative integer`);
    }
    const withdrawnPeers = [];
    for (const peer of this._peers.values()) {
      if (peer.state !== ConsentState.WITHDRAWN) {
        peer.state = ConsentState.WITHDRAWN;
        peer.lastReason = reasonCode;
        peer.lastTransitionUs = nowUs;
        withdrawnPeers.push(peer.peerId);
      }
    }
    return { withdrawnPeers, count: withdrawnPeers.length };
  }

  // ─── §6.1 cognitive-frame gate ──────────────────────────────────

  /**
   * Per spec §6.1: cognitive frames flow only when consent is
   * GRANTED for the given peer. Returns false for unknown peers
   * (matching `engine.rs:241-243` `unwrap_or(false)`).
   *
   * @param {string} peerId
   * @returns {boolean}
   */
  allowsCognitiveFrames(peerId) {
    const peer = this._peers.get(peerId);
    if (!peer) return false;
    return stateAllowsCognitiveFrames(peer.state);
  }
}

// ─── Module exports ────────────────────────────────────────────────

module.exports = {
  MAX_PEERS,
  EngineError,
  ConsentEngine,
};
