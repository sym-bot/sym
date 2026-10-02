'use strict';

const crypto = require('crypto');

const { recordKey, recordLineage, recordParents, recordCreatedBy, setRecordLineage } = require('./record');

/**
 * @module @sym-bot/sym/frame-handler
 * @description FrameHandler — processes inbound peer frames for a SymNode.
 *
 * Handles: handshake, state-sync, cmb (neural/heuristic SVAF),
 * mood, message, xmesh-insight, wake-channel, peer-info, ping/pong.
 *
 * Moved from @sym-bot/core in v0.3.80 — this is protocol plumbing
 * (frame routing, store writes, event emission), not cognitive core.
 *
 * See MMP v0.2.0 Section 9: Coupling & SVAF.
 * See MMP v0.2.0 Section 12: xMesh (Layer 6).
 * Echo loop prevention: the anti-echo rule of MMP v2.0 §15.7 (it was Section 14 in v0.2.0).
 *
 * Copyright (c) 2026 SYM.BOT. Apache 2.0 License.
 */

const fs = require('fs');
const path = require('path');
const { encode, processHeuristicSVAF, buildFusedRecord, computeCategoryVerdicts, decryptCategories, resolveTetherAnchor, tetherOfRecord, signTetherAttestation, verifyTetherAttestation, classifyAddress, categoriesAsSigned } = require('./core');

/** Entry members this node writes about an admission, which a frame must never supply. */
const ENTRY_ANNOTATIONS = Object.freeze(['admission', 'tether', 'provenance', 'collapsed', 'svaf']);

// Receive-path dedup window (MMP §4.2 O2 — rejoin-without-replay convergence).
// A CMB whose content-hash key we have already processed within this window is
// suppressed rather than re-evaluated/re-remixed/re-emitted. Bounds the dedup
// cache so a long-lived node does not grow it without limit.
// SEVEN DAYS, not one hour. The hour was sized for the replay-STORM class — anchor floods on
// Bonjour reconnects, minutes apart — and it held for that. It did not hold for the slower
// sender: the daemon's delivery spool re-flushed directed envelopes ~30 HOURS old on a seat's
// reconnect, far outside the window, so three already-drained messages re-surfaced as live
// pushes with fresh ids and "7s ago" ages — one of them an imperative to redo work its own
// successor recorded as committed (dev-team-3, 2026-08-31 22:5x). A stale DIRECTIVE dressed as
// fresh is the worst member of the invisible-failure class, in the very tool seats coordinate
// through. Record-after-surface semantics make a long TTL safe: only keys that genuinely
// reached the application layer are suppressed, and a deliberate identical re-send already
// disambiguates itself with a salt (mesh-channel send path). The TTL must exceed the slowest
// sender's replay horizon, and the spool's is unbounded — seven days covers every horizon
// observed while the size cap still bounds the cache.
/**
 * A stable identity for a signature: sha256 of its decoded bytes, or null when there are none.
 * @param {string} sig base64url
 * @returns {string|null}
 */
function signatureMark(sig) {
  if (typeof sig !== 'string' || !sig) return null;
  const bytes = Buffer.from(sig, 'base64url');
  return bytes.length ? `sig:${crypto.createHash('sha256').update(bytes).digest('hex')}` : null;
}

/**
 * The identity of a verified record's ASSERTION (§8.8.2), for directed de-duplication: the digest
 * of the preimage its signature covers, recomputed here, never a value the frame carries. A hedged
 * Ed25519 signer (WebKit) signs one assertion differently each time, so the signature bytes would
 * name one assertion twice; for a deterministic signer the two marks are equivalent. The signature
 * hash is the fallback for a record whose preimage cannot be rebuilt.
 * @param {object} cmb a record whose signature verified
 * @returns {string|null}
 */
function assertionMark(cmb) {
  const { assertionIdV2_0, sigDigestV2 } = require('./core');
  try {
    return cmb?.metadata?.signatureSuite === 'mmp-sig-v2.0' ? assertionIdV2_0(cmb) : `sd:${sigDigestV2(cmb)}`;
  } catch {
    return signatureMark(cmb?.metadata?.sig);
  }
}

const SEEN_CMB_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const SEEN_CMB_MAX = 10000;
/** A directed de-duplication key: the record key, `#`, and its assertion mark. */
const DIRECTED_MARK = /#(asrt-|sd:|sig:)/;
/** The most `peer-info` entries read from one frame. */
const PEER_INFO_MAX = 256;
/** A record refused for its audience is said at most once per this many ms per peer and reason. */
const AUDIENCE_REPORT_MS = 60_000;

/**
 * Processes inbound peer frames for a SymNode.
 *
 * Routes each frame type to the appropriate handler method.
 */
class FrameHandler {

  /**
   * @param {object} node - SymNode reference for emitting events and accessing internals.
   * @param {object} [opts]
   * @param {boolean} [opts.cliHostMode=false] - Local CLI-host peer mode.
   *   The node hosts the IPC surface for the sym CLI on a single machine.
   *   It does NOT participate in mesh cognition: skips SVAF evaluation,
   *   skips CMB persistence, and forwards frames without storing them.
   *   This is distinct from MMP §16 mesh relays (the public sym-relay
   *   on Render) — that's a separate concern handled at transport layer.
   */
  constructor(node, opts = {}) {
    this._node = node;
    this._cliHostMode = opts.cliHostMode || false;
    this._unsignedWarned = new Set();
    this._attDropSaid = new Map(); // `${peerId}|${reason}` -> { at, more }: a dropped attestation is said once a minute
    this._audienceSaid = new Map(); // `${peerId}|${reason}` -> { at, more }: a refused audience, the same way
    // THE ADMISSION SEAM (sym-core split). Frame routing is open; the engine that judges an
    // inbound block is injectable. Stock nodes run the open §9.2 baseline; a consumer may
    // substitute its own engine with the same call contract. The post-admission observer is a
    // NAMELESS hook: something may happen after every admission outcome, this file does not
    // know what — a consumer registers its observer, and stock nodes observe nothing.
    this._admit = opts.admit ?? processHeuristicSVAF;
    this._afterAdmission = opts.afterAdmission ?? null;
    // Receive-path dedup cache: CMB content-hash key -> last-seen timestamp.
    // Distinct from the local store (which holds *remix* keys); this tracks the
    // raw *incoming* keys so the same CMB re-sent on reconnect/resync converges
    // instead of cycling. See _handleMemoryShare and MMP §4.2 O2.
    this._seenCmbKeys = new Map();
    // Directed assertion marks (key#sig:…) get their own map and cap, so a broadcast flood cannot
    // evict them and make a replayed directed record surface again, and the reverse.
    this._seenDirectedKeys = new Map();
    // Keys whose first copy is still being processed (an async SVAF pass): see _handleMemoryShare.
    this._inFlightKeys = new Set();
    // Persist the dedup cache across plugin reloads / process restarts. Without this,
    // a reload wipes the cache and every already-processed CMB re-surfaces as new — a
    // primary trigger of the cross-node echo storm (MMP §15.7, anti-echo). Best-effort: any FS error
    // degrades silently to in-memory-only. Stored as a dotfile WITHOUT a .json extension
    // so the store's own *.json scan never mistakes it for a CMB entry.
    this._seenKeysPath = null;
    this._seenFlushAt = 0;
    this._loadSeenCmbKeys();
  }

  /** Hydrate the receive-path dedup cache from disk (TTL-pruned). Best-effort. */
  _loadSeenCmbKeys() {
    try {
      const dir = this._node && this._node._store && this._node._store._dir;
      if (!dir) return;
      this._seenKeysPath = path.join(dir, '.seen-cmb-keys');
      if (!fs.existsSync(this._seenKeysPath)) return;
      const now = Date.now();
      const raw = JSON.parse(fs.readFileSync(this._seenKeysPath, 'utf8'));
      for (const k of Object.keys(raw)) {
        const ts = raw[k];
        if (typeof ts === 'number' && (now - ts) < SEEN_CMB_TTL_MS) this._seenKeysFor(k).set(k, ts);
      }
    } catch { /* degrade to in-memory only */ }
  }

  /** Flush the dedup cache to disk, throttled to at most once per 5s. Best-effort. */
  _persistSeenCmbKeys(now) {
    if (!this._seenKeysPath) return;
    if (this._seenFlushAt && (now - this._seenFlushAt) < 5000) return;
    this._seenFlushAt = now;
    try {
      const obj = {};
      for (const [k, ts] of this._seenCmbKeys) obj[k] = ts;
      for (const [k, ts] of this._seenDirectedKeys) obj[k] = ts;
      fs.writeFileSync(this._seenKeysPath, JSON.stringify(obj));
    } catch { /* ignore */ }
  }

  /**
   * Record an incoming CMB key in the receive-path dedup cache, pruning to
   * stay within TTL and size bounds. Expired entries are dropped first; if
   * still over the cap, the oldest-inserted keys are evicted.
   * @private
   */
  _recordSeenCmbKey(key, now) {
    const map = this._seenKeysFor(key);
    map.set(key, now);
    if (map.size > SEEN_CMB_MAX) {
      for (const [k, ts] of map) {
        if (map.size <= SEEN_CMB_MAX) break;
        if (now - ts >= SEEN_CMB_TTL_MS) map.delete(k);
      }
      while (map.size > SEEN_CMB_MAX) {
        const oldest = map.keys().next().value;
        map.delete(oldest);
      }
    }
    this._persistSeenCmbKeys(now);
  }

  /** The de-dup map a key belongs to: directed assertion marks are kept apart from content keys. @private */
  _seenKeysFor(key) {
    // A directed mark is `<key>#<assertion mark>` (assertionMark): `asrt-…`, `sd:…`, or `sig:…`
    // (the signature hash, and every mark 0.13.14 persisted).
    return typeof key === 'string' && DIRECTED_MARK.test(key) ? this._seenDirectedKeys : this._seenCmbKeys;
  }

  /**
   * Mark an inbound CMB's content-hash key as having actually surfaced to the
   * application layer (admitted/stored, mood delivered, or CLI-host forwarded).
   * This is the record half of the receive-path dedup: only keys that have been
   * delivered once are remembered, so a true re-send (anchor replay on Bonjour
   * reconnect, or the same CMB arriving via multiple peers) is suppressed —
   * while a CMB that has NOT yet surfaced is never poisoned and always gets the
   * chance to be delivered. Idempotent and no-op when the key is absent.
   * @private
   */
  _markCmbSurfaced(key) {
    if (!key) return;
    this._recordSeenCmbKey(key, Date.now());
  }

  /**
   * Main dispatch for an inbound peer frame.
   *
   * @param {string} peerId - Unique identifier of the sending peer.
   * @param {string} peerName - Display name of the sending peer.
   * @param {object} msg - The frame payload with a .type category.
   * @returns {void}
   */
  handle(peerId, peerName, msg) {
    // THE DOOR (MMP §5.8.1). Admission is decided from the handshake; this consults that decision
    // on every frame that carries meaning, so a peer that speaks without ever having been judged
    // does not reach SVAF. Exempt: `handshake`, which is how a peer ASKS to be admitted — gating
    // it would lock out the grant-holders it exists for — and `ping`/`pong`, which carry no
    // content and tell a refused peer nothing a closed socket does not.
    //
    // DENY BY DEFAULT, deliberately. An allow-list of gated types is one forgotten `case` away
    // from a hole, and this switch has fourteen of them — including `checkpoint`, `witness`,
    // `role-grant` and `node-stats`, which mutate state without going near SVAF. Listing the
    // three exemptions instead means a new frame type is gated the day it is added.
    if (msg.type !== 'handshake' && msg.type !== 'ping' && msg.type !== 'pong'
        && typeof this._node._roomDoor === 'function') {
      const door = this._node._roomDoor(peerId);
      if (!door.pass) {
        this._node._log(`Door refused '${msg.type}' from ${peerName}: ${door.reason}`);
        return;
      }
    }
    // One frame must never end the node. The TCP parser catches a throw from here, but the relay
    // path calls this from a WebSocket handler with nothing above it, so a throw there was an
    // uncaught exception and the daemon exited. A frame that throws is dropped and said so.
    try {
      this._dispatch(peerId, peerName, msg);
    } catch (err) {
      this._node._log(`Frame '${msg && msg.type}' from ${peerName} dropped: ${err && err.message ? err.message : err}`);
      this._node.emit('metric', { type: 'frame-handler-error', from: peerName, frameType: msg && msg.type, error: String(err && err.message ? err.message : err) });
    }
  }

  _dispatch(peerId, peerName, msg) {
    switch (msg.type) {
      case 'handshake':
        this._handleHandshake(peerId, peerName, msg);
        break;

      case 'state-sync':
        // MMP v0.2.2: state-sync is deprecated. Hidden states never cross
        // the wire under SVAF (Xu, 2026, arXiv:2604.03955, §3.4). Frames
        // received from older v0.2.0/v0.2.1 peers are silently dropped —
        // they are NOT fed into the local CfC. Cognitive signals arrive
        // on the canonical 'cmb' channel.
        this._node._log(`state-sync: dropping deprecated frame from ${peerName} (MMP v0.2.0; upgrade peer to v0.2.2+)`);
        break;

      case 'cmb':
        this._handleMemoryShare(peerId, peerName, msg);
        break;

      case 'mood':
        this._handleMood(peerId, peerName, msg);
        break;

      case 'wake-channel':
        this._handleWakeChannel(peerId, peerName, msg);
        break;

      case 'peer-info':
        this._handlePeerInfo(peerId, peerName, msg);
        break;

      case 'attestation':
        this._handleAttestation(peerId, peerName, msg);
        break;

      case 'cmb-fetch':
        this._handleCmbFetch(peerId, peerName, msg);
        break;

      case 'cmb-fetch-result':
        this._handleCmbFetchResult(peerId, peerName, msg);
        break;

      case 'checkpoint':
        if (msg.checkpoint) this._node._ingestCheckpoint(msg.checkpoint, peerId);
        break;

      case 'witness':
        if (msg.witness) this._node._ingestWitness(msg.witness, peerId);
        break;

      case 'role-grant':
      case 'role-revoke':
        if (msg.grant) this._node._ingestRoleGrant(msg.grant, peerId);
        break;

      case 'node-stats':
        if (msg.stats) this._node._ingestNodeStats(msg.stats, peerId);
        break;

      case 'message':
        this._handleMessage(peerId, peerName, msg);
        break;

      case 'xmesh-insight':
        this._handleXMeshInsight(peerId, peerName, msg);
        break;

      case 'ping': {
        const peer = this._node._peers.get(peerId);
        if (peer) peer.transport.send({ type: 'pong' });
        break;
      }

      case 'pong':
        break;
    }
  }

  // ── Sub-handlers ──────────────────────────────────────────

  /**
   * Handle handshake: extract E2E public key and derive shared secret.
   * @private
   */
  _handleHandshake(peerId, peerName, msg) {
    // THE OTHER HALF OF THE ADMISSION DECISION. When WE dialled, the peer is already in the set
    // before its handshake arrives — this is the first moment its room claim exists on this side,
    // so the check has to run here too, or it covers only the half of the orderings in which we
    // happen to be the one accepting. It also RECORDS the verdict, which is what the door above
    // consults; without this call a peer has no verdict at all and, in a gated room, is refused.
    if (typeof this._node._roomAdmission === 'function') {
      const admission = this._node._roomAdmission(peerId, msg);
      if (!admission.admit) {
        this._node._log(`Refused ${peerName} into '${this._node._room}': ${admission.reason}`);
        const peer = this._node._peers && this._node._peers.get(peerId);
        if (peer) {
          this._node._peers.delete(peerId);
          try { peer.transport.close(); } catch { /* already gone */ }
        }
        return;
      }
    }
    if (msg.e2ePublicKey && typeof this._node._deriveAndStoreSecret === 'function') {
      this._node._deriveAndStoreSecret(peerId, msg.e2ePublicKey);
    }
    // Store the peer's Ed25519 identity public key (base64url) to verify the
    // signature on every inbound signed CMB from this peer (MMP §8.3).
    if (msg.publicKey && this._node._peerIdentityKeys) {
      this._node._pinPeerKey(peerId, msg.publicKey);
    }
    // Section 3.5 + 6.4: store peer lifecycle role for validator-origin weight.
    if (msg.lifecycleRole && this._node._peerLifecycleRoles) {
      this._node._peerLifecycleRoles.set(peerId, msg.lifecycleRole);
    }
  }

  /**
   * Get the lifecycle role of the CMB's creator.
   * Checks: 1) peer role from handshake, 2) CMB createdBy matching a known peer.
   * @private
   */
  _getCreatorRole(peerId, msg) {
    // Anchored mode: authority is EARNED and resolved through the signed grant
    // chain to the pinned anchor — NEVER the self-declared handshake lifecycleRole
    // (which any peer can stamp). Elevation additionally requires a verified
    // signature: the CMB signature verifies against the transport peer's key, so a
    // verified CMB is authored by peerId, and resolveRole(peerId) is that author's
    // earned role. An unverified CMB — or one relayed by another author (whose
    // signature would fail against peerId's key) — gets no elevation. This closes
    // the self-declaration→2.0×-weight poisoning primitive.
    if (this._node._anchor) {
      if (msg._cmbVerified && typeof this._node.resolveRole === 'function') {
        return this._node.resolveRole(peerId, Date.now());
      }
      return 'participant';
    }
    // Unanchored (dev/legacy — no root of trust): the self-declared handshake role.
    // This path carries NO cryptographic authority; production MUST pin an anchor.
    const peerRole = this._node._peerLifecycleRoles?.get(peerId);
    if (peerRole) return peerRole;
    const createdBy = msg.cmb?.metadata?.createdBy ?? msg.cmb?.createdBy;
    if (createdBy && this._node._peerLifecycleRoles) {
      for (const [id, role] of this._node._peerLifecycleRoles) {
        const peer = this._node._peers?.get(id);
        if (peer?.name === createdBy) return role;
      }
    }
    return 'participant';
  }

  /**
   * Re-attach the incoming CMB's opaque payload onto the fused remix before it
   * is stored and surfaced. SVAF fusion rebuilds the CMB from its CAT7 categories —
   * the heuristic path returns a freshly-built `fusedEntry.cmb` that does NOT
   * carry the sibling `payload`. The effect was direction/verdict-dependent and
   * invisible: a directed CMB that SVAF ADMITTED was stored as a remix whose
   * cmb had no payload (so the inbox surfaced `payload:null`), while the SAME
   * CMB REJECTED-but-directed surfaced the raw msg and kept its payload. So
   * payload delivery silently depended on the receiver's per-node SVAF drift —
   * the root of the cross-device "payload arrives on some peers, not others"
   * bug (Mac→Windows dropped because Windows admitted; Windows→Mac survived
   * because Mac rejected). The payload rides ALONGSIDE CAT7 and is never part
   * of the cmbKey hash, so copying it onto the admitted remix is correct: an
   * ingested llm-request/response remix must still carry its substrate data for
   * the receiving agent to act on.
   * @private
   */
  _preserveIncomingPayload(fusedEntry, msg) {
    const payload = msg?.cmb?.payload;
    if (payload !== undefined && payload !== null && fusedEntry && fusedEntry.cmb) {
      fusedEntry.cmb.payload = payload;
    }
  }

  /**
   * **DEPRECATED in MMP v0.2.2.** Legacy state-sync handler from MMP v0.2.0.
   * Hidden states never cross the wire under SVAF (Xu, 2026,
   * arXiv:2604.03955, §3.4). Retained as a stub so external callers
   * (tests, etc.) do not break. Cognitive signals arrive on the canonical
   * 'cmb' channel and are evaluated at SVAF Layer 4.
   * @deprecated MMP v0.2.2: hidden states do not cross the wire.
   * @private
   */
  _handleStateSync(peerId, peerName, msg) {
    // No-op. The case dispatcher above logs and drops the frame.
  }

  /**
   * Handle cmb: neural SVAF with heuristic fallback.
   * See MMP v0.2.0 Section 9: Coupling & SVAF.
   * @private
   */
  /**
   * Surface a directed (peer-bound) CMB to the application layer when SVAF
   * has REJECTED it for memory. MMP §4.4.4: a CMB addressed to this node is a
   * request between two agents and MUST reach the agent regardless of the SVAF
   * verdict — SVAF governs memory admission only, not delivery. On the ADMIT
   * path the stored remix already surfaces via the receiveFromPeer cmb-accepted
   * emit, so this is invoked only from reject/redundant branches to fill the
   * one gap where a directed CMB would otherwise be dropped. Returns true if it
   * surfaced. The §9.3 mood channel is separate (`mood-delivered`) and is still
   * delivered for a rejected directed CMB: it has no directed exemption.
   *
   * The surfaced entry carries `remixed: false` — the receiver delivered the
   * CMB to the agent but did NOT ingest it into memory (no remix, no lineage).
   * Consumers check this flag to distinguish a delivered-only directed CMB from
   * one that was ingested (see node.js receiveFromPeer, which sets remixed:true).
   * `decision` says why it was not stored: the SVAF verdict (redundant/rejected),
   * or 'not-stored' when SVAF admitted it and the store's write failed.
   * @private
   */
  _surfaceDirectedReject(msg, peerName, peerId, now, decision) {
    if (!msg._directedToMe) return false;
    const entry = {
      ...msg,
      content: msg.content,
      source: msg.source || peerName,
      peerId,
      storedAt: now,
      directed: true,
      remixed: false,
      decision: decision || 'rejected',
    };
    this._node._log(`Directed CMB from ${peerName} (peer-bound, MMP §4.4.4) — SVAF ${decision || 'rejected'} for memory; surfacing to agent anyway (remixed:false)`);
    this._markCmbSurfaced(msg._incomingKey);
    this._node.emit('cmb-accepted', entry);
    return true;
  }

  /**
   * Verify the Ed25519 signature on an inbound CMB (MMP §8.3). Returns true if
   * the CMB must be REJECTED (a present-but-invalid signature — forged/tampered;
   * or unsigned when the node is configured to require signatures). Sets
   * msg._cmbVerified.
   *
   * The key is resolved from the DELIVERING peer, but a CMB is signed by its
   * AUTHOR (`signingPayload` binds `cmb.createdBy`). Those coincide only when
   * the author handed the block over directly. For a RELAYED CMB the resolved
   * key is the wrong node's, and the verdict is meaningless — so a signed CMB
   * whose named author is not the deliverer is passed through flagged
   * unverified rather than reported as forged. Also passed through unverified:
   * unsigned CMBs, and signed CMBs from a peer whose key we have not seen yet.
   * Strict mode still rejects unsigned.
   *
   * What this does NOT do is authenticate a relayed CMB — it cannot, because
   * the author's key is unresolvable from a name (see the comment at the
   * rejection branch). It stops mislabelling unverifiable as forged.
   * @private
   */
  _rejectOnBadSignature(peerId, peerName, msg) {
    const cmb = msg.cmb;
    // v2 carries the address in metadata; a pre-boundary record at the top level. Logs and
    // metrics must name the block either way — an undefined key in a security log is worse
    // than no log, because it reads as a record with no address.
    const cmbKeyOf = recordKey;   // shared accessor — see lib/record.js
    if (!cmb) { msg._cmbVerified = false; return false; }
    const { verifyCMB, assertionIdV2_0 } = require('./core');

    // Published v2.0 records (mmp-sig-v2.0) sign the author's NODE ID, so the verifying key is the
    // one held for createdByNodeId, never the delivering peer's (§8.8.4, §18.3.1): verified against
    // the deliverer, a peer could vouch for a record by signing it itself under someone else's id.
    // Their assertionId must also be the one the preimage yields (§8.8.5 step 5).
    const md = cmb.metadata;
    if (md && md.signatureSuite === 'mmp-sig-v2.0' && typeof md.createdByNodeId === 'string' && md.createdByNodeId) {
      const authorKey = typeof this._node._identityKey === 'function'
        ? this._node._identityKey(md.createdByNodeId)
        : this._node._peerIdentityKeys?.get(md.createdByNodeId);
      // No key for the author yet is key-distribution latency, not forgery: unverified, as for v1.
      // Its audience is still the one it carries (see _audienceRefused).
      if (!authorKey) { msg._cmbVerified = false; return this._audienceRefused(peerId, peerName, cmb, false); }
      const v2 = verifyCMB(cmb, authorKey);
      // A record that declares the v2.0 suite but is malformed for it (no room, no key, …) has no
      // preimage: assertionIdV2_0 throws. That is a mismatch to reject, never an exception: on the
      // relay path nothing above this catches it, and one such frame ended the daemon.
      let derivedId = null;
      try { derivedId = assertionIdV2_0(cmb); } catch { /* not a well-formed v2.0 record */ }
      const idOk = md.assertionId === undefined || md.assertionId === derivedId;
      // Verified is not addressed here: the audience the author signed is checked next, as on every
      // suite. Returning here skipped it, so a v2.0 record signed for another room or node was stored.
      if (v2.valid && idOk) {
        msg._cmbVerified = true;
        msg._verifiedAuthorNodeId = md.createdByNodeId;
        return this._audienceRefused(peerId, peerName, cmb, true);
      }
      const reason = !v2.valid ? (v2.error || 'invalid') : 'assertion-id-mismatch';
      const k = recordKey(cmb);
      this._node._log(`[sym-security] v2.0 CMB ${String(k || '').slice(0, 16)} from ${peerName} rejected — ${reason} (author ${md.createdByNodeId.slice(0, 8)})`);
      this._node.emit('metric', { type: 'cmb-signature-rejected', from: peerName, key: k, reason: 'invalid', error: reason });
      if (typeof this._node._recordDecision === 'function') {
        this._node._recordDecision({ method: 'signature', source: msg.source || peerName, cmbKey: k, decision: 'rejected-signature', totalDrift: null, categoryDrifts: null, gateValues: null, focusLabel: reason, remix: recordParents(cmb).length > 0 });
      }
      return true;
    }
    // On any other suite no signature covers an assertionId, so a carried one is an unsigned claim
    // a relay could set. It is dropped rather than kept beside verified fields.
    if (md && Object.prototype.hasOwnProperty.call(md, 'assertionId')) delete md.assertionId;

    // Resolve through the roster registry (anchor > handshake > grant-vouched)
    // so CMBs relayed from peers we never directly handshook still verify,
    // falling back to the direct-handshake map.
    const senderKey = typeof this._node._identityKey === 'function'
      ? this._node._identityKey(peerId)
      : this._node._peerIdentityKeys?.get(peerId);
    const v = verifyCMB(cmb, senderKey);

    if (!v.signed) {
      msg._cmbVerified = false;
      if (this._node._requireSignedCmb && senderKey) {
        this._node._log(`[sym-security] UNSIGNED CMB from ${peerName} rejected (SYM_REQUIRE_SIGNED_CMB)`);
        this._node.emit('metric', { type: 'cmb-signature-rejected', from: peerName, key: cmbKeyOf(cmb), reason: 'unsigned' });
        return true;
      }
      return false;
    }

    if (!senderKey) {
      // Signed, but this peer's identity key isn't known on this transport yet
      // (handshake not processed). Cannot verify — do not reject; treat unverified. A two-section
      // record's audience is still checked (see _audienceRefused).
      msg._cmbVerified = false;
      return cmb.metadata ? this._audienceRefused(peerId, peerName, cmb, false) : false;
    }

    // §7.8 GRANDFATHERING — a pre-boundary block is UNATTESTED, not FORGED (P-6).
    //
    // `verifyCMB` returns {valid:false} for three different situations and core keeps them
    // apart deliberately. Collapsing them here was the defect: a v1-signed record minted under
    // a scheme we still recognise carries no v2 attestation, so it cannot be *verified* — but it
    // was never *refused*, and every node's entire pre-boundary history is exactly this shape.
    // Treating it as a forgery would mean that on the first packet after the boundary, every node
    // rejects every peer's whole history AND writes `forged/tampered` into the security log for
    // records whose only fault is being old. That corrupts the audit trail as well as the data
    // path, and an audit trail that cries forgery about ordinary history is worse than none.
    //
    // `legacy-key-rejected` MUST keep rejecting: those keys were refused by the §19.1 fail-closed
    // membrane BEFORE the boundary and are refused identically after. Preserve core's split;
    // widening it would quietly promote a refused block into a merely-unattested one.
    const grandfathered = v.error === 'unverified-legacy';

    if (!v.valid && !grandfathered) {
      const keyShort = String(cmbKeyOf(cmb) || '').slice(0, 16);
      // RELAYED ≠ FORGED. The key resolved above belongs to the node that DELIVERED this
      // CMB (`_identityKey` is keyed by the transport peer), but the signature is made by the
      // AUTHOR — the signing payload binds `createdBy`. On a relayed CMB those are different
      // nodes, so the verdict above was computed against the WRONG key and says nothing about
      // authenticity: an untouched, genuinely-signed block fails it every time. Only the case
      // we can PROVE is the wrong key relaxes — a named author that is not the deliverer. An
      // absent author, or an author that IS the deliverer, still hard-rejects below, so
      // omitting `createdBy` cannot dodge rejection. The author's own key is deliberately NOT
      // resolved here: the roster is keyed by nodeId while `createdBy` is a NAME, and a name
      // index would silently resolve the wrong key the first time two nodes share a name —
      // binding `createdByNodeId` into the signing payload is the correct fix and is an MMP
      // schema change. Passing unverified matches the posture already taken for a key we
      // cannot resolve: unresolvable passes, provably-wrong-key passes as UNVERIFIED, and
      // only a verdict computed against the RIGHT key rejects.
      const author = (cmb.metadata && cmb.metadata.createdBy) || cmb.createdBy || null;
      if (author && author !== peerName) {
        // Try the AUTHOR'S key before concluding anything. Three outcomes, each earned:
        // resolvable and VALID → a genuine relay, verified against the key that signed it;
        // resolvable and INVALID → a true forgery, falls through to the rejection below
        // (the P-6 arm: a bad signature against the RIGHT key is still forged);
        // unresolvable → unverifiable, passed unverified — the posture already taken for a
        // key we cannot resolve, now consistent instead of branding every relay a forgery.
        const authorKey = typeof this._node._identityKey === 'function'
          ? this._node._identityKey(author)
          : this._node._peerIdentityKeys?.get(author);
        if (authorKey) {
          const va = verifyCMB(cmb, authorKey);
          if (va.valid) { msg._cmbVerified = true; return this._audienceRefused(peerId, peerName, cmb, true); }
          // fall through: verified against the author's own key and it is wrong — forged.
        } else {
          msg._cmbVerified = false;
          this._node._log(`[sym-security] UNVERIFIABLE CMB ${keyShort} authored by ${author}, relayed via ${peerName} — this node holds no key for the author; passing unverified${v.error ? ' (' + v.error + ')' : ''}`);
          this._node.emit('metric', { type: 'cmb-signature-unverifiable', from: peerName, author, key: cmbKeyOf(cmb), reason: v.error || 'author-key-unavailable' });
          return cmb.metadata ? this._audienceRefused(peerId, peerName, cmb, false) : false;
        }
      }
      // verifyCMB distinguishes WHY it refused — 'legacy-key-rejected', 'bad-signature',
      // 'content-mismatch', 'no-public-key'. Recording the constant instead of the reason
      // made 1,538 rejections on this host — 32% of all SVAF decisions — indistinguishable:
      // version-skew peers, real signature failures and content mismatches under one label.
      // (§7.8 above already grandfathers 'unverified-legacy'; this branch is the REFUSED set.)
      const reason = v.error || 'bad-signature';
      // A pre-v1 key is VERSION SKEW, not an attack: a peer that has not upgraded must not
      // read as hostile in the security log.
      const legacyKey = reason === 'legacy-key-rejected';
      // Root vs remix, captured HERE because a rejected CMB is dropped and never stored —
      // this decision record is the only place the distinction can survive. Lineage lives in
      // metadata on the two-section record; the top-level fallback reads pre-boundary frames.
      const lin = (cmb.metadata && cmb.metadata.lineage) || cmb.lineage;
      const remix = !!(lin && Array.isArray(lin.parents) && lin.parents.length);
      this._node._log(legacyKey
        ? `[sym-security] LEGACY-KEY CMB ${keyShort} from ${peerName} rejected — pre-v1 key scheme (version skew, not forgery)`
        : `[sym-security] BAD SIGNATURE on CMB ${keyShort} from ${peerName} — forged/tampered, rejected (${reason})`);
      // `reason` keeps 'invalid' so nothing downstream breaks; `error` carries the verdict.
      this._node.emit('metric', { type: 'cmb-signature-rejected', from: peerName, key: cmbKeyOf(cmb), reason: 'invalid', error: reason });      if (typeof this._node._recordDecision === 'function') {
        this._node._recordDecision({
          method: 'signature', source: msg.source || peerName, cmbKey: cmbKeyOf(cmb),
          decision: 'rejected-signature', totalDrift: null, categoryDrifts: null, gateValues: null,
          focusLabel: reason, remix,
        });
      }
      return true;
    }

    if (grandfathered) {
      // Surfaced, readable, and recorded as what it is. A DISTINCT metric, because the whole
      // point is that this is not the forgery counter — an operator watching
      // `cmb-signature-rejected` spike at the cutover must not see legacy traffic in it.
      this._node.emit('metric', { type: 'cmb-legacy-unverified', from: peerName, key: cmbKeyOf(cmb), reason: 'unverified-legacy' });
    }

    // Grandfathered blocks fall THROUGH to the audience check rather than returning here, and
    // that is deliberate. `checkAudience` reads the audience from the top level on a
    // pre-boundary record and applies to exactly the v1 keys being grandfathered — so an early
    // return would admit a cross-room legacy replay while fixing the forgery misreport. Closing
    // one hole by opening another is not a fix.

    // Audience (§18.3.1): a genuinely-signed v1 CMB whose bound room is not this
    // node's room, or which is directed at another node, is a cross-room / mis-
    // directed replay. Reject it — reported distinctly from a bad signature.
    if (this._audienceRefused(peerId, peerName, cmb, !grandfathered)) return true;

    // Unattested is not verified. A grandfathered block is admitted and readable, but it MUST
    // NOT be marked verified — anything downstream weighing this flag is entitled to know the
    // difference between "this peer proved authorship" and "this predates the proof".
    msg._cmbVerified = !grandfathered;
    return false;
  }

  /**
   * Whether a signed record is addressed away from this node, and so is refused before it is stored
   * or surfaced (§18.3.1): its signed `room` is not this node's room, or its signed `to` names
   * another node.
   *
   * Both suites this node verifies, mmp-sig-v2 and mmp-sig-v2.0, sign `room` and `to`, so every
   * signed record is checked, on every path through the signature check and whether or not its
   * signature could be checked here. A verified record's author addressed it elsewhere. An
   * unverified one says the same or was altered, and is not for this node either way; refusing it
   * drops only what a relay could already drop. Every refusal is counted (`cmb-audience-rejected`);
   * the log names a peer and reason once a minute, with how many more there were.
   * @param {boolean} verified - whether the signature was verified (said in the log and metric).
   * @returns {boolean} true when the record must be refused.
   * @private
   */
  _audienceRefused(peerId, peerName, cmb, verified) {
    const { checkAudience } = require('./core');
    const aud = checkAudience(cmb, this._node._room, this._node.nodeId);
    if (aud.ok) return false;
    const key = recordKey(cmb);
    this._node.emit('metric', { type: 'cmb-audience-rejected', from: peerName, key, reason: aud.reason, verified: verified === true });
    const k = `${peerId}|${aud.reason}`;
    const now = Date.now();
    const said = this._audienceSaid.get(k);
    if (said && now - said.at < AUDIENCE_REPORT_MS) { said.more++; return true; }
    this._audienceSaid.delete(k);
    if (this._audienceSaid.size >= 1024) this._audienceSaid.delete(this._audienceSaid.keys().next().value);
    this._audienceSaid.set(k, { at: now, more: 0 });
    const more = said && said.more ? ` (and ${said.more} more since it was last said)` : '';
    this._node._log(`[sym-security] ${aud.reason} on CMB ${String(key || '').slice(0, 16)} from ${peerName}${verified ? '' : ' (unverified)'} — rejected${more}`);
    return true;
  }

  /**
   * MMP §7 cmb-fetch: content-addressed retrieval. A peer asks for the CMB this
   * store holds under an exact content-address key — the §15.8 re-verification
   * path (fetch an unresolvable lineage root, verify the address, re-encode,
   * recompute the tether). Serving is discretionary and same-room by
   * construction (only connected peers can ask); the response is self-verifying
   * (the requester recomputes the content address), so no trust is extended by
   * serving and none is required of the server. Categories are served TEXT-ONLY:
   * the content address binds text, and re-verifiers re-encode in their own
   * kernel — vectors are dead weight.
   * @private
   */
  _handleCmbFetch(peerId, peerName, msg) {
    if (!msg || typeof msg.key !== 'string' || !msg.reqId) return;
    const peer = this._node._peers.get(peerId);
    if (!peer?.transport?.send) return;
    const entry = this._node._store.get(msg.key);
    const cmb = entry?.cmb;
    let served = null;
    if (cmb && cmb.categories && typeof cmb.categories === 'object') {
      const categories = {};
      for (const [f, v] of Object.entries(cmb.categories)) {
        if (v && typeof v === 'object') {
          categories[f] = { text: v.text ?? '' };
          if (f === 'mood') {
            if (typeof v.valence === 'number') categories[f].valence = v.valence;
            if (typeof v.arousal === 'number') categories[f].arousal = v.arousal;
          }
        } else {
          categories[f] = { text: String(v ?? '') };
        }
      }
      // §15.8 serves a RECORD, and the record is two sections. Serving the flat shape would
      // hand the requester something that validates against neither schema — and cmb-fetch is
      // self-verifying, so the requester would recompute the address and refuse it.
      // A pre-boundary record is served in the shape it was stored in: the legacy DAG stays
      // readable and is never re-keyed (§7.8).
      // The metadata is served WHOLE, as stored. Picking fields dropped the v2.0 ones
      // (signatureSuite, addressScheme, createdByNodeId, application, assertionId), and a v2.0
      // record without them no longer verifies at the requester. It is a copy, never the store's object.
      const m = cmb.metadata;
      served = m
        ? { categories, metadata: structuredClone(m) }
        : {
            key: cmb.key, createdBy: cmb.createdBy, createdAt: cmb.createdAt,
            categories, lineage: cmb.lineage ?? null,
            sig: cmb.sig, sigAlg: cmb.sigAlg, room: cmb.room, to: cmb.to,
          };
    }
    peer.transport.send({
      type: 'cmb-fetch-result', reqId: msg.reqId, key: msg.key,
      found: !!served, cmb: served, timestamp: Date.now(),
    });
    if (served) this._node._log(`[cmb-fetch] served ${msg.key.slice(0, 16)}… to ${peerName}`);
  }

  /**
   * Resolve a pending fetchCMB() request. The response is accepted only if the
   * recomputed content address equals the requested key — a mismatched or
   * forged response is discarded (counted as a miss) and reported.
   * @private
   */
  _handleCmbFetchResult(peerId, peerName, msg) {
    const pending = this._node._cmbFetchPending?.get(msg?.reqId);
    if (!pending) return;
    const cmb = msg.found ? msg.cmb : null;
    // §15.8 is SELF-VERIFYING: the requester recomputes the content address, so serving a
    // block extends no trust and requires none. Under v2 the address lives in metadata and is
    // the Merkle root over the seven categoryKeys — content-only, so recomputing it needs nothing
    // but the categories that arrived. A pre-boundary record is checked the old way; the legacy DAG
    // stays readable and is never re-keyed (§7.8).
    const served = cmb?.metadata?.key ?? cmb?.key;
    if (!cmb || served !== pending.key) { pending.miss(peerId); return; }
    // ONE ANSWER, FROM CORE. This dispatched on `cmb.metadata` and called blockKeyV2 or
    // recomputeKey itself — a workaround for core's recomputeKey, which read `cmb.key` (absent
    // on v2 records) and derived roots with the flat scheme while createCMB minted Merkle.
    // core 0.8.1 fixes that, and the workaround becomes a REGRESSION the moment it does: a
    // pre-boundary record with a FLAT root key now recomputes to the Merkle address and is
    // DISCARDED AS FORGED. Measured, not reasoned — the whole legacy DAG would have been
    // dropped on fetch, and sym's 309 green tests do not cover that shape.
    //
    // classifyAddress is core's answer to the same question: it derives by the record's
    // STRUCTURAL ROLE, tries the derivations that could legitimately have minted it, and NAMES
    // the one that matched. It also separates "I could not check this" from "this does not
    // match", which matters here because both used to arrive as a bare null and this call site
    // treated null as a mismatch — accusing a record it had merely failed to read.
    const verdict = classifyAddress(cmb);
    if (verdict.state !== 'verified') {
      const why = verdict.state === 'mismatch' ? 'MISMATCH' : `UNVERIFIABLE (${verdict.reason})`;
      this._node._log(`[cmb-fetch] content-address ${why} from ${peerName} for ${String(pending.key).slice(0, 16)}… — discarded`);
      this._node.emit('metric', {
        type: 'cmb-fetch-forged', from: peerName, key: pending.key,
        // The three classes must not merge in telemetry either: a spike of unverifiable
        // records is a compatibility problem, a spike of mismatches is an attack.
        verdict: verdict.state, scheme: verdict.scheme ?? null,
      });
      pending.miss(peerId);
      return;
    }
    pending.resolve({ cmb, from: peerName, peerId });
  }

  _handleMemoryShare(peerId, peerName, msg) {
    let pending;
    try {
      pending = this._handleMemoryShareInner(peerId, peerName, msg);
    } finally {
      // Release the in-flight mark when this frame is finished with: now, or when its SVAF pass settles.
      const k = msg && msg._inFlightKey;
      if (k) {
        if (pending && typeof pending.then === 'function') pending.finally(() => this._inFlightKeys.delete(k)).catch(() => {});
        else this._inFlightKeys.delete(k);
      }
    }
    return pending;
  }

  /** @private */
  _handleMemoryShareInner(peerId, peerName, msg) {
    // A cmb frame is {type, timestamp, cmb}; an honest sender never sets `source`. Every name this
    // handler records for the deliverer must come from the connection (peerName), so a
    // frame-supplied one is dropped before anything reads it.
    if (Object.prototype.hasOwnProperty.call(msg, 'source')) {
      this._node._log(`Ignored a frame-supplied source (${JSON.stringify(String(msg.source)).slice(0, 40)}) on a CMB from ${peerName}`);
      delete msg.source;
    }
    // The same for what this node records about an admission. The stored entry is built from the
    // frame (`{ ...msg }`), and these entry members are this node's own: its admission and tether
    // attestations, its fusion provenance, its collapse, its neural evidence. One a frame carried
    // would be stored as if this node had written it.
    for (const own of ENTRY_ANNOTATIONS) {
      if (Object.prototype.hasOwnProperty.call(msg, own)) delete msg[own];
    }

    // Decrypt E2E-encrypted CMB categories if present
    if (msg.cmb && typeof msg.cmb.categories === 'string' && msg.cmb._e2e) {
      const sharedSecret = this._node._peerSharedSecrets?.get(peerId);
      if (sharedSecret) {
        try {
          msg.cmb.categories = decryptCategories(msg.cmb.categories, msg.cmb._e2e.nonce, sharedSecret);
          delete msg.cmb._e2e;
          this._node._log(`E2E decrypted categories from ${peerName}`);
        } catch (err) {
          this._node._log(`E2E decryption failed from ${peerName}: ${err.message}`);
          return; // Cannot process corrupted/tampered frame
        }
      } else {
        this._node._log(`E2E encrypted frame from ${peerName} but no shared secret — dropping`);
        return;
      }
    }

    // No size bound here beyond the frame the record arrived in. The record bounds are minting
    // rules (cmb-encoder): earlier releases minted larger categories and longer agent ids, and
    // refusing those would stop this node hearing such a peer at all.

    // Derive content from CMB categories if not present on the frame
    // (MMP Section 7: cmb frames carry structured categories, not necessarily a content string)
    if (!msg.content && msg.cmb?.categories) {
      const { renderContent } = require('./core');
      msg.content = renderContent(msg.cmb);
    }
    if (!msg.content) return;

    // CMB authentication (MMP §8.3). A signed CMB verifies against its AUTHOR's
    // Ed25519 key. When the author delivered it directly, the peer's announced
    // handshake key IS that key and a present-but-invalid signature means forged
    // or tampered in flight — reject outright (audit-logged, never surfaced or
    // stored). When the block was RELAYED, the author's key is not resolvable
    // here, so it is flagged unverified rather than rejected. Unsigned CMBs
    // (older peers, or peers without a known key yet) are likewise allowed
    // through for interop but flagged unverified on msg._cmbVerified.
    if (this._rejectOnBadSignature(peerId, peerName, msg)) return;

    // An UNSIGNED record is still accepted (as unverified) for interop, but counted and named once
    // per peer, so the emitters that would break under a signed-only default can be found first.
    if (msg.cmb?.metadata && !msg.cmb.metadata.sig) {
      this._node.emit('metric', { type: 'cmb-unsigned-received', from: peerName, key: recordKey(msg.cmb) });
      if (!this._unsignedWarned.has(peerId)) {
        this._unsignedWarned.add(peerId);
        this._node._log(`UNSIGNED CMB from ${peerName}: accepted as unverified. A future release will refuse unsigned records by default.`);
      }
    }

    // Who wrote it, and who handed it to us. `name` is the author's record label (MMP §8.8.4:
    // a display label, not an identity). Every surfaced and stored entry carries this, so no
    // layer has to read the store envelope's "<receiver>+<sender>".
    // `nodeId` is the cryptographic author (§8.8.4) and is filled only when that is established
    // here: the record verified under the delivering peer's key AND names that peer as its author.
    // A relayed or unverified record keeps `nodeId: null` — the label is shown, identity is not
    // claimed. `msg.source` is an unsigned frame field and never names the author.
    const claimedNodeId = msg.cmb?.metadata?.createdByNodeId || null;
    msg.author = {
      name: recordCreatedBy(msg.cmb) || peerName,
      // Established when the signature proved it: a v2.0 record verified against its signed node id
      // (even when relayed), or any verified record its author delivered itself.
      nodeId: msg._verifiedAuthorNodeId
        || (msg._cmbVerified === true && claimedNodeId === peerId ? claimedNodeId : null),
      via: { name: peerName, nodeId: peerId },
    };

    // MMP §4.4.4 directed (peer-bound) delivery — decided here, before the de-duplication and
    // echo checks, because both of them used to drop directed CMBs that §9.2.2 says MUST
    // surface. See the full note where SVAF is invoked below.
    // A verified record carries its author's signed addressee (metadata.to), and it must agree with
    // the frame. An unverified record can only be judged by the frame flags, which is enough to
    // surface it (§9.2.2) but not to exempt it from echo suppression below (re-review F1).
    // A record that signs no addressee field at all (another implementation) is judged by the frame.
    const frameDirected = msg.directed === true && !!msg.to && msg.to === this._node.nodeId;
    const meta = msg.cmb?.metadata;
    const signedTo = meta && Object.prototype.hasOwnProperty.call(meta, 'to') ? meta.to : undefined;
    const verified = msg._cmbVerified === true;
    // When the author signed an addressee, that alone decides (§8.8.5 step 7): the frame flags are
    // a relay's to set, so stripping `directed` must not turn a signed directed CMB into an
    // SVAF-gated broadcast, and adding it must not make a signed broadcast directed.
    const signedAddressee = verified && typeof signedTo === 'string' && signedTo.length > 0;
    msg._directedToMe = signedAddressee
      ? signedTo === this._node.nodeId
      : frameDirected && !(verified && signedTo !== undefined && signedTo !== this._node.nodeId);
    const authenticatedDirected = msg._directedToMe && verified && signedTo === this._node.nodeId;

    const now = Date.now();
    // MMP v2.0 P0.7: freshness is the author's SIGNED assertion, not an unsigned frame field.
    // `metadata.createdTimestamp` is inside the v2 signing preimage (cmb-signing.js), so a
    // relay cannot age a signed record without breaking its signature. The old
    // `msg.originTimestamp || msg.timestamp` came from OUTSIDE the signature — a relay could
    // make a signed CMB look arbitrarily old or new. The unsigned frame fields survive only as
    // the interop fallback for a record that carries no signed timestamp (pre-v2 / bare).
    // Bounded skew: a signed timestamp in the future is clamped to `now` (age 0) rather than
    // trusted to run the temporal gate backwards; conformance covers future/stale/missing.
    const signedTs = msg.cmb?.metadata?.createdTimestamp;
    const authorTs = (typeof signedTs === 'number' && Number.isFinite(signedTs))
      ? Math.min(signedTs, now)
      : (msg.originTimestamp || msg.timestamp || now);
    const ageSeconds = (now - authorTs) / 1000;
    const originTs = authorTs;

    // Receive-path dedup (MMP §4.2 O2 — rejoin-without-replay convergence).
    // The send path already drops *local* duplicates (node.remember skips
    // re-broadcast when the key is already stored). But a CMB *received* from a
    // peer had no such guard: the anchor-CMB replay every node sends on each
    // Bonjour reconnect — plus the same CMB arriving via multiple peers — was
    // reprocessed each time (re-run through SVAF, remixed under a fresh key,
    // re-emitted as 'cmb-accepted'). With several flapping/zombie instances each
    // replaying accumulated memory, that produced a sustained replay storm.
    // `_cmbKey` (sym-core, MMP §8.2) is a content hash over the CMB categories, so an
    // identical re-send carries an identical key. Suppress a key already seen
    // within the TTL window: converge instead of cycle. A genuine new remix has
    // a new key and is unaffected; a first-seen anchor CMB still bootstraps a
    // fresh peer — it simply processes once.
    //
    // CRITICAL (regression fix, see tests/inbound-cmb-surfacing.test.js):
    // we only CHECK the cache here — we do NOT record the key yet. The key is
    // recorded *after* the CMB has actually surfaced (admitted/stored, mood
    // delivered, or CLI-host forwarded) via `_markCmbSurfaced`. Recording
    // before surfacing was receive-blinding: if the first pass over a key did
    // not surface (SVAF reject path that returns without delivery, or an async
    // SVAF failure), the key was still poisoned, so the same CMB re-arriving on
    // the next Bonjour reconnect was deduped and silently dropped — the
    // legitimate delivery never reached the application layer. Record-after-
    // surface keeps the anti-replay-storm guarantee (a CMB that surfaced once is
    // suppressed on every subsequent identical re-send) without ever swallowing
    // a CMB that has not yet been delivered.
    // MMP §8.8.2: directed delivery de-duplication MUST use the assertion identity. A directed CMB
    // that verified is identified by its assertionId, or until records carry one (Core Secure
    // emission) by its signature: a replay of the same signed record is still suppressed, while a
    // new signed send of the same words, or words already seen as a broadcast, surfaces. Nothing
    // unauthenticated widens the key — a frame timestamp or an unsigned createdTimestamp is the
    // sender's choice, and would let one peer surface the same content without bound (review F2).
    //
    // The mark is the digest of the preimage the signature covers, recomputed here (assertionMark):
    // never a string a relay can re-spell (base64url ignores padding and the unused bits of the
    // last character, so `sig + '='` verifies as the same signature), never a carried assertionId,
    // which no signature covers, and not the signature bytes, which a hedged signer varies.
    const cognitionKey = recordKey(msg.cmb) || msg.key;
    const mark = msg._cmbVerified === true ? assertionMark(msg.cmb) : null;
    const incomingKey = cognitionKey && msg._directedToMe && mark
      ? `${cognitionKey}#${mark}`
      : cognitionKey;
    if (incomingKey) {
      const lastSeen = this._seenKeysFor(incomingKey).get(incomingKey);
      if (lastSeen !== undefined && (now - lastSeen) < SEEN_CMB_TTL_MS) {
        this._seenKeysFor(incomingKey).set(incomingKey, now); // refresh recency
        this._node._log(`Duplicate CMB ${String(incomingKey).slice(0, 16)} from ${peerName} — seen within TTL, skipping (convergence)`);
        return;
      }
      // The mark is only recorded once a CMB has surfaced, which can be after an async SVAF pass, so
      // a copy arriving meanwhile (the same record via two peers, or a reconnect replay) would pass
      // the check above and surface twice. It is held off while the first copy is in flight.
      if (this._inFlightKeys.has(incomingKey)) {
        this._node._log(`Duplicate CMB ${String(incomingKey).slice(0, 16)} from ${peerName} — the same record is still being processed, skipping`);
        return;
      }
      this._inFlightKeys.add(incomingKey);
      msg._inFlightKey = incomingKey;
    }
    // Carry the key down the processing chain so each surface point can record
    // it once the CMB has actually been delivered.
    msg._incomingKey = incomingKey || null;

    // Echo loop prevention (MMP §15.7, anti-echo): if the incoming CMB's
    // lineage parents include a key that exists in our local cmbs,
    // this CMB is a derivative of our own broadcast. Skip all
    // processing — including mood delivery — to prevent ping-pong
    // between same-app peers. A directed reply its author signed to us is
    // a conversation, not an echo, and is processed normally; one only the
    // unsigned frame calls directed is delivered but never processed.
    const incomingParents = recordParents(msg.cmb);
    if (incomingParents.length > 0 && !authenticatedDirected) {
      const isEcho = incomingParents.some(parentKey => this._node._store.hasLocalKey(parentKey));
      if (isEcho) {
        // §9.2.2: a CMB addressed to this node is still delivered — but not admitted, stored or
        // remixed, which is what drives the ping-pong. De-duplication above bounds it to once.
        if (msg._directedToMe) {
          this._surfaceDirectedReject(msg, peerName, peerId, now, 'echo');
          return;
        }
        this._node._log(`Echo detected — parent key found in local cmbs, skipping CMB from ${peerName}`);
        return;
      }
    }

    // CLI-host mode: forward only, do NOT persist. The node is just the
    // local IPC surface for sym CLI commands — it doesn't participate in
    // mesh cognition. Storage lives in the local agent stores; sym recall
    // does federated read across them. See sym CLI cmdRecall().
    //
    // We still emit 'cmb-accepted' with the full envelope shape so that
    // the daemon's IPC subscribers (sym sub) and any hosted sub-agents
    // continue to see CMBs streaming through. The event name describes
    // what the daemon does with the CMB (accept it into the forwarding
    // pipeline) — it does not imply SVAF was run.
    if (this._cliHostMode) {
      const entry = {
        ...msg,
        content: msg.content,
        source: msg.source || peerName,
        peerId,
        storedAt: now,
        remixed: false, // CLI-host forwards only — it does not ingest/remix
      };
      this._node._log(`CLI-host: forwarding CMB from ${peerName} (no store): "${msg.content.slice(0, 50)}"`);
      this._markCmbSurfaced(msg._incomingKey);
      this._node.emit('cmb-accepted', entry);
      return;
    }

    // MMP §4.4.4 directed (peer-bound) delivery. A CMB sent to a specific
    // recipient (sym_send to=X) arrives with `directed:true` + `to:<peerId>`
    // on the wire frame. When it is addressed to THIS node it is a request
    // between two agents — the receiver MUST surface it to the application/
    // agent layer regardless of the SVAF verdict. SVAF still runs below, but
    // for a directed CMB it governs only MEMORY admission (store / remix /
    // lineage), never whether the agent is allowed to see the message.
    //
    // Surfacing is exactly-once: on SVAF ADMIT the stored remix already
    // surfaces via the `receiveFromPeer` cmb-accepted emit (node.js), so this
    // flag is honoured only on the SVAF REJECT/REDUNDANT paths — that is the
    // gap where a directed CMB would otherwise be silently dropped. Room-bound
    // broadcasts (sym_publish, no `to`) leave the flag false and stay fully
    // SVAF-gated for surfacing — receiver-autonomous attention.
    // (`msg._directedToMe` is set above, before the echo and de-duplication checks.)

    // Get local memory anchors for both paths
    const recentEntries = this._node._store.allEntries().slice(0, 5);
    const anchorTexts = recentEntries.map(e => ({ text: e.content, source: e.source, tags: e.tags || [] }));

    // Try neural SVAF first (Layer 4 cognition). The chain is returned so the caller knows when this
    // frame is finished with (the in-flight de-dup mark is released then).
    return this._node._svafEvaluator.evaluate(
      { text: msg.content, source: msg.source || peerName, tags: msg.tags || [], confidence: msg.confidence || 0.8 },
      anchorTexts,
      ageSeconds,
    ).then((neuralResult) => {
      if (neuralResult) {
        return this._processNeuralSVAF(neuralResult, msg, peerName, peerId, originTs, now);
      }
      return this._runHeuristicSVAFContained(msg, peerName, peerId, originTs, now, ageSeconds);
    }).catch((err) => {
      this._node._log(`SVAF neural error: ${err.message} — falling back to heuristic`);
      return this._runHeuristicSVAFContained(msg, peerName, peerId, originTs, now, ageSeconds);
    });
  }

  /**
   * Run heuristic SVAF with its rejection contained. A malformed or
   * unexpected frame must never be able to kill the host process — the
   * async path's failure is logged and the frame dropped, not left to the
   * global unhandled-rejection handler.
   * @private
   */
  _runHeuristicSVAFContained(msg, peerName, peerId, originTs, now, ageSeconds) {
    return Promise.resolve()
      .then(() => this._processHeuristicSVAF(msg, peerName, peerId, originTs, now, ageSeconds))
      .catch((err) => this._node._log(`SVAF heuristic error on frame from ${peerName}: ${err.message} — frame dropped`));
  }

  /**
   * Process a successful neural SVAF result.
   * @private
   */
  async _processNeuralSVAF(result, msg, peerName, peerId, originTs, now) {
    const { decision, total_drift, category_drifts, gate_values } = result;
    // §15.8 runs on this path exactly as on the heuristic one: same inbound check, same anchor.
    const tetherAnchor = this._prepareLineageTether(msg);

    // Record EVERY evaluation (admit AND reject). The autonomy IS the decision;
    // a rejection leaves no other trace, so this is where sovereignty is captured.
    this._node._recordDecision({
      method: 'neural',
      source: msg.source || peerName,
      cmbKey: recordKey(msg.cmb) || msg.key || null,
      decision,
      totalDrift: total_drift,
      categoryDrifts: category_drifts || null,
      gateValues: gate_values || null,
      focusLabel: String((msg.cmb && msg.cmb.categories && msg.cmb.categories.focus && msg.cmb.categories.focus.text) || msg.content || '').slice(0, 120),
    });

    if (decision === 'rejected') {
      const gateLog = Object.entries(gate_values || {}).map(([k,v]) => `${k}:${v.toFixed(2)}`).join(' ');
      this._node._log(`SVAF neural rejected from ${peerName} — drift:${total_drift?.toFixed(3)} gate:[${gateLog}]`);

      // MMP §4.4.4: a directed (peer-bound) CMB surfaces even when SVAF rejects
      // it for memory — delivery is unconditional, memory admission is not.
      this._surfaceDirectedReject(msg, peerName, peerId, now, 'rejected');

      // Attest the REJECT too — a refusal is the compliance-critical gating event,
      // and the per-attester chain must cover every gate (omission-evidence), even
      // though a reject produces no stored remix. Indexed only (no cmb to carry it).
      const rejKey = recordKey(msg.cmb) || msg.key;
      if (rejKey) {
        const rejVerdicts = computeCategoryVerdicts(category_drifts || {}, {
          stableThreshold: this._node._svafStableThreshold,
          guardedThreshold: this._node._svafGuardedThreshold,
        });
        this._node._buildAdmissionAttestation(rejKey, 'rejected', rejVerdicts, 'neural');
      }

      // MMP Section 9.3: mood MUST still be delivered from rejected CMBs.
      // Affect crosses all domain boundaries — the fast-coupling channel.
      // (Recording the key is handled inside _extractAndDeliverMood, and only
      // when a non-neutral mood actually surfaces — a pure reject with neutral
      // mood surfaces nothing, so it is intentionally NOT recorded: B's memory
      // evolves, and the same CMB re-arriving later may then be admitted.)
      this._extractAndDeliverMood(msg, peerName);
      return;
    }

    const incomingKey = recordKey(msg.cmb) || msg.key;
    // The record to store, built by the same function as the heuristic gate's (buildFusedRecord),
    // never the caller's object and never an edit of the author's signed record. Neural evaluation
    // keeps the incoming text, so under content-only addressing the record collapses onto the
    // incoming block (§7.5 collapse-before-mint: cite, do not mint, claim no descent from oneself)
    // and is a copy of the author's record as signed. Only when the carried address is not the
    // content's own does this node mint a remix of its own citing it. This path used to write the
    // new key and lineage into the author's record instead, keeping the author's name and a
    // signature that no longer covered it.
    const fused = msg.cmb?.categories && typeof msg.cmb.categories === 'object'
      ? buildFusedRecord({
        categories: categoriesAsSigned(msg.cmb.categories),
        createdBy: this._node.name,
        parentKey: incomingKey || null,
        parentLineage: recordLineage(msg.cmb),
        parentRecord: msg.cmb,
        parentCreatedBy: msg.cmb.createdBy,
        method: 'svaf-neural',
      })
      : null;

    const fusedEntry = {
      ...msg,
      ...(fused ? { key: fused.record.metadata.key, cmb: fused.record, collapsed: fused.collapsed || undefined } : {}),
      source: `${this._node.name}+${msg.source || peerName}`,
      storedAt: now,
      svaf: {
        method: 'neural',
        decision,
        totalDrift: total_drift,
        categoryDrifts: category_drifts,
        gateValues: gate_values,
      },
    };
    // Admission Attestation (MMP) — the per-category gating verdict, signed + bound to
    // the gated CMB, persisted on the remix's store entry as the durable audit record. The neural
    // path emits per-category drift; map it to verdicts with the same thresholds (Phase A).
    if (incomingKey && fusedEntry.cmb) {
      const categoryVerdicts = computeCategoryVerdicts(category_drifts || {}, {
        stableThreshold: this._node._svafStableThreshold,
        guardedThreshold: this._node._svafGuardedThreshold,
      });
      const att = this._node._buildAdmissionAttestation(incomingKey, decision, categoryVerdicts, 'neural');
      // On the entry, beside the record: a two-section record has exactly two members (§8.8.1).
      if (att) fusedEntry.admission = att;
    }
    // Opaque payload rides alongside CAT7 — carry it onto the admitted remix.
    this._preserveIncomingPayload(fusedEntry, msg);
    let severLineage = false;
    if (fusedEntry.cmb) {
      // The copy carries no attestation the sender attached: that one was an input, checked in
      // _prepareLineageTether. The record this node stores carries its own evaluation or none.
      const tether = await tetherOfRecord(fusedEntry.cmb.categories, tetherAnchor, this._admissionPolicy());
      severLineage = this._applyLineageTether(fusedEntry, tether, now);
    }
    // The admitted-path surface is the store's own cmb-accepted emit. The store returns null when
    // it already holds the key ('redundant') or the write failed ('not-stored'), and a directed CMB
    // then reached nobody: surface it. Everything after this runs exactly as for any admit.
    const storedNeural = this._node._store.receiveFromPeer(peerId, fusedEntry, { creatorRole: this._getCreatorRole(peerId, msg), severLineage });
    if (!storedNeural && msg._directedToMe) {
      this._surfaceDirectedReject(msg, peerName, peerId, now, this._node._store.get(fusedEntry.key) ? 'redundant' : 'not-stored');
    }

    this._reencodeLocalStateAfterAdmit();

    // Feed to xMesh (Layer 6). See MMP v0.2.0 Section 12.
    if (this._node._xmesh) {
      this._node._xmesh.ingestSignal({
        from: peerName,
        content: msg.content || '',
        timestamp: Date.now(),
        type: 'mesh',
        valence: msg.cmb?.categories?.mood?.valence || 0,
        arousal: msg.cmb?.categories?.mood?.arousal || 0,
      });
    }

    const gateLog = Object.entries(gate_values || {}).map(([k,v]) => `${k}:${v.toFixed(2)}`).join(' ');
    this._node._log(`SVAF neural ${decision} from ${peerName}: "${(msg.content || '').slice(0, 50)}" drift:${total_drift?.toFixed(3)} gate:[${gateLog}]`);
    this._markCmbSurfaced(msg._incomingKey);
    this._node.emit('memory-received', { from: peerName, entry: fusedEntry, decision });
  }

  /**
   * Process heuristic SVAF fallback when neural model is unavailable.
   * See MMP v0.2.0 Section 9: Coupling & SVAF.
   * @private
   */
  async _processHeuristicSVAF(msg, peerName, peerId, originTs, now, ageSeconds) {
    // MMP §6.7 repeat verification: a recognised grounding CMB — signature verified,
    // intent=ground, verified:/failed: outcome prefix, lineage naming a target this
    // store holds — must not be refused solely for redundancy (a verification report
    // about a held row is near-duplicate by nature; refusing repeats self-quenches
    // the outcome stream). Eligibility is decided here, where signature state lives;
    // the gate itself only waives the redundancy band (reject band stands).
    const gFields = msg.cmb?.categories;
    const groundingWaiver = msg._cmbVerified === true
      && gFields?.intent?.text === 'ground'
      && /^(verified|failed):/.test(gFields?.commitment?.text || '')
      && Array.isArray(recordLineage(msg.cmb)?.parents)
      && typeof this._node._store?.has === 'function'
      && recordParents(msg.cmb).some(p => this._node._store.has(p));

    // MMP §15.8: the gate evaluates the remix against the resolved anchor in-kernel and reports;
    // severance and the attestation are applied below on the result.
    const tetherAnchor = this._prepareLineageTether(msg);

    const result = await this._admit({
      tetherAnchor,
      msg,
      peerName,
      localName: this._node.name,
      originTs,
      now,
      ageSeconds,
      groundingWaiver,
      recentCMBs: this._node._store.recentCMBs(5),
      recentDecisions: this._node._recentSvafDecisions,
      config: this._admissionPolicy(),
    });

    // The observer fires on EVERY outcome, before any branch — an observation recorded only
    // for admitted blocks is compared on the half that agrees by definition.
    if (this._afterAdmission) {
      try { this._afterAdmission(result, peerName); }
      catch (err) { this._node._log(`afterAdmission observer failed: ${err.message}`); }
    }

    // Record EVERY heuristic evaluation too (admit / redundant / rejected).
    this._node._recordDecision({
      method: 'heuristic',
      source: msg.source || peerName,
      cmbKey: recordKey(msg.cmb) || msg.key || null,
      decision: result.decision,
      totalDrift: result.totalDrift,
      effectiveTau: result.effectiveTau ?? null,
      changeSignal: result.changeSignal ?? null,
      categoryDrifts: result.categoryDrifts || null,
      gateValues: result.gateValues || null,
      focusLabel: String((msg.cmb && msg.cmb.categories && msg.cmb.categories.focus && msg.cmb.categories.focus.text) || msg.content || '').slice(0, 120),
    });

    if (!result.accepted) {
      if (result.decision === 'redundant') {
        this._node._log(`SVAF heuristic redundant from ${peerName}: "${(msg.content || '').slice(0, 50)}" maxFieldDrift:${result.maxFieldDrift?.toFixed(3)}`);
      } else {
        this._node._log(`SVAF heuristic rejected from ${peerName} — drift:${result.totalDrift.toFixed(3)}`);
      }

      // MMP §4.4.4: a directed (peer-bound) CMB surfaces even when SVAF rejects
      // or deems it redundant for memory — delivery is unconditional.
      this._surfaceDirectedReject(msg, peerName, peerId, now, result.decision);

      // Attest the reject/redundant gate too — the chain must cover every gating
      // event (omission-evidence). The Phase-A heuristic already produced the
      // per-category verdict; index it (no remix is stored on this path).
      const rejKey = recordKey(msg.cmb) || msg.key;
      if (rejKey) this._node._buildAdmissionAttestation(rejKey, result.decision, result.categoryVerdicts, 'heuristic');

      // MMP Section 9.3: mood MUST still be delivered from rejected CMBs.
      // (redundant signals also deliver mood — the affect may have changed)
      // Key recording happens inside _extractAndDeliverMood iff a non-neutral
      // mood actually surfaces; a neutral reject surfaces nothing and is left
      // re-evaluable as B's memory evolves.
      this._extractAndDeliverMood(msg, peerName);
      return;
    }

    // Admission Attestation (MMP) — the heuristic gate already produced the per-category
    // verdict (Phase A, result.categoryVerdicts); sign + bind it to the gated CMB and
    // persist it on the remix's store entry as the durable audit record.
    if (result.fusedEntry && result.fusedEntry.cmb) {
      const of = recordKey(msg.cmb) || msg.key;
      const att = this._node._buildAdmissionAttestation(of, result.decision, result.categoryVerdicts, 'heuristic');
      // On the entry, beside the record: a two-section record has exactly two members (§8.8.1).
      if (att) result.fusedEntry.admission = att;
    }
    // Opaque payload rides alongside CAT7 — the heuristic fusion rebuilds the
    // CMB from categories and drops it, so re-attach before storing the remix.
    this._preserveIncomingPayload(result.fusedEntry, msg);

    const severLineage = this._applyLineageTether(result.fusedEntry, result.tether, now);

    // The admitted-path surface is the store's own cmb-accepted emit. The store returns null when
    // it already holds the key ('redundant') or the write failed ('not-stored'), and a directed CMB
    // then reached nobody: surface it. Everything after this runs exactly as for any admit.
    const storedHeuristic = this._node._store.receiveFromPeer(peerId, result.fusedEntry, { creatorRole: this._getCreatorRole(peerId, msg), severLineage });
    if (!storedHeuristic && msg._directedToMe) {
      this._surfaceDirectedReject(msg, peerName, peerId, now, this._node._store.get(result.fusedEntry.key) ? 'redundant' : 'not-stored');
    }

    this._reencodeLocalStateAfterAdmit();

    // Feed to xMesh (Layer 6). See MMP v0.2.0 Section 12.
    if (this._node._xmesh) {
      this._node._xmesh.ingestSignal({
        from: peerName,
        content: result.fusedContent || msg.content || '',
        timestamp: Date.now(),
        type: 'mesh',
        valence: msg.cmb?.categories?.mood?.valence || result.fusedCMB?.categories?.mood?.valence || 0,
        arousal: msg.cmb?.categories?.mood?.arousal || result.fusedCMB?.categories?.mood?.arousal || 0,
      });
    }

    this._node._log(`SVAF heuristic ${result.decision} from ${peerName}: "${result.fusedContent.slice(0, 50)}" drift:${result.totalDrift.toFixed(3)}`);
    this._markCmbSurfaced(msg._incomingKey);
    this._node.emit('memory-received', { from: peerName, entry: result.fusedEntry, decision: result.decision });
  }

  /**
   * The receiver's admission policy, as the gates are handed it. One builder, so the heuristic
   * engine and the neural path's tether evaluation judge with the same thresholds and weights.
   * @private
   */
  _admissionPolicy() {
    return {
      stableThreshold: this._node._svafStableThreshold,
      guardedThreshold: this._node._svafGuardedThreshold,
      temporalLambda: this._node._svafTemporalLambda,
      freshnessSeconds: this._node._svafFreshnessSeconds,
      categoryWeights: this._node._svafCategoryWeights,
      adaptiveTimescale: this._node._svafAdaptiveTimescale,
      minFreshnessSeconds: this._node._svafMinFreshnessSeconds,
      reactivity: this._node._svafReactivity,
      changeWeights: this._node._svafChangeWeights ?? undefined,
    };
  }

  /**
   * MMP §15.8 before a gate decides, on EITHER gate path: check the attestation an inbound remix
   * carries, and resolve the anchor its tether is evaluated against.
   *
   * Shared because the two paths are one admission decision. The neural path skipped all of
   * §15.8, so a remix its evaluator admitted kept a drifted lineage and was never attested, while
   * the same record through the heuristic path was severed and signed.
   *
   * @returns {object|undefined} the anchor ({ key, categories, ... }), or undefined when there is
   *   none to evaluate against (tether disabled, or no verified root in reach).
   * @private
   */
  _prepareLineageTether(msg) {
    // A re-emitted remix may carry its integrator's signed tether evaluation. Verify against the
    // integrator's roster-resolved key. An INVALID one is stripped — a forged certificate is worse
    // than an absent one; a valid-but-unverifiable one (no resolvable key) rides through
    // unverified, the same posture as unsigned CMBs.
    if (msg.cmb?.tether && typeof verifyTetherAttestation === 'function') {
      const att = msg.cmb.tether;
      const integKey = this._node._identityKey(att.by);
      const v = verifyTetherAttestation(att, integKey);
      msg._tetherAttested = v.valid === true;
      if (v.signed && !v.valid && integKey) {
        this._node._log(`[§15.8] inbound tether attestation INVALID from ${String(att.by).slice(0, 8)} — stripped`);
        this._node.emit('metric', { type: 'tether-attestation-rejected', by: att.by, of: att.of });
        delete msg.cmb.tether;
      }
    }
    // The earliest-stored resolvable lineage root of the incoming CMB (the incoming block itself
    // when it is a root).
    const anchor = this._node._lineageTether && typeof resolveTetherAnchor === 'function'
      ? resolveTetherAnchor(msg.cmb, (k) => this._node._store.get(k))
      : null;
    return anchor && anchor.categories ? anchor : undefined;
  }

  /**
   * MMP §15.8 after a gate admits, on EITHER gate path: act on the tether evaluation of the record
   * about to be stored. `tether` is what tetherOfRecord reported for it (null when unverified).
   *
   * Severance: a remix drifted past the reject floor MUST NOT carry the chain's lineage (keeping it
   * would forge fidelity), so it is stored as a fresh root with the departed source recorded
   * informally in provenance. An unverifiable tether (checked=false) is a trust state, never
   * severed. Returns whether it severed, so the caller stores the entry as a root.
   *
   * Attestation: sign the exact evaluation performed — remix key, anchor, kernel identity, drift,
   * verdict — so a downstream receiver that cannot resolve the anchor holds
   * attested-by-integrator instead of unchecked. Kept on the store entry (entry.tether), beside the
   * record and never inside it (§8.8.1); trust in the verdict is weighed through the integrator's
   * resolved authority, and verdicts are comparable only within one kernelId.
   * @private
   */
  _applyLineageTether(entry, tether, now) {
    const cmb = entry?.cmb;
    if (!tether?.checked || !cmb) return false;
    let severed = false;
    if (!tether.tethered && recordParents(cmb).length > 0) {
      const departedFrom = recordParents(cmb)[0] ?? null;
      // Severance never edits a record someone signed. When the gate stored the incoming block
      // itself (collapsed) the record is its author's, and its signature covers its lineage:
      // nulling it there made the stored record fail verification under the author's key. The
      // caller stores that one as a root on the entry instead (receiveFromPeer severLineage) and
      // the record keeps its parents as signed. A remix this node is minting right now is its own
      // and not yet created, so it is simply minted as a root, as §15.8 says.
      if (entry.collapsed !== true && !cmb.metadata?.sig) setRecordLineage(cmb, null);
      severed = true;
      entry.provenance = {
        ...entry.provenance,
        tether: { severed: true, anchor: tether.anchorKey, kernelId: tether.kernelId, drift: tether.drift, departedFrom },
      };
      this._node._log(`[§15.8] lineage severed: remix drift ${tether.drift.toFixed(3)} from anchor ${String(tether.anchorKey).slice(0, 16)} exceeds the reject floor — stored as fresh root (departed-from in provenance)`);
      this._node.emit('metric', { type: 'lineage-tether-severed', key: recordKey(cmb), anchor: tether.anchorKey, drift: tether.drift });
    } else {
      entry.provenance = {
        ...entry.provenance,
        tether: { severed: false, anchor: tether.anchorKey, kernelId: tether.kernelId, drift: tether.drift },
      };
    }
    if (typeof signTetherAttestation === 'function' && this._node._identity?.privateKey) {
      try {
        entry.tether = signTetherAttestation({
          of: recordKey(cmb),
          anchor: tether.anchorKey,
          kernelId: tether.kernelId,
          drift: tether.drift,
          verdict: tether.tethered ? 'tethered' : 'severed',
          by: this._node.nodeId,
          at: now,
        }, this._node._identity.privateKey);
      } catch (e) {
        this._node._log(`[§15.8] tether attestation signing failed: ${e.message}`);
      }
    }
    return severed;
  }

  /**
   * Re-encode local state after a CMB is admitted — on EITHER gate path.
   *
   * THE ASYMMETRY THIS CLOSES. The neural and heuristic gates are two implementations of one
   * admission decision, but only the neural one moved local state. The heuristic gate is the
   * PRODUCTION DEFAULT (@sym-bot/sym ships no svaf_v2.pt and the neural path additionally needs a
   * Python subprocess), so in production a node's state never moved when it admitted a peer's
   * cognition — it moved only on init, broadcast and remember. A node that had admitted five
   * hundred peer blocks carried the same local state as one that had admitted none.
   *
   * Identified 2026-07-05 in the liquid-substrate scope note, which ranked it bug-grade and
   * independent of any learning work; still present in published 0.12.1 when re-checked
   * 2026-08-24. Founder decision D5: ship this fix on its own, and HOLD the recurrent-cell
   * dimension until the learning testbed says what shape it should be.
   *
   * WHAT THIS IS NOT, and the honesty matters more than the fix. This is still a STATELESS
   * re-encode: it discards h_{t-1} and recomputes from the re-read context, so it is not
   * recurrent and nothing here learns. Milestone A's liquid step —
   * `h_t = (1-α)·h_{t-1} + α·encode(new block)` with α from the gap-keyed adaptiveTau — is
   * deliberately NOT in this change. Nor does this alter observable behaviour much today: SVAF
   * scores per-field CMB vectors against anchor memory and does not read h1/h2 at all. Its value
   * is that state becomes real, so a consumer can exist. Motion without traction until then.
   *
   * @private
   */
  _reencodeLocalStateAfterAdmit() {
    // Never let a state update break an admission that already succeeded: the block is stored,
    // and losing the re-encode is recoverable where throwing here would discard the admission.
    try {
      const context = this._node._buildContext();
      const { h1, h2 } = encode(context);
      this._node._meshNode.updateLocalState(h1, h2, 0.8);
    } catch (err) {
      this._node._log(`local state re-encode failed after admit: ${err.message}`);
    }
  }

  /**
   * Extract mood from a rejected CMB and deliver to application layer.
   *
   * MMP Section 9.3: "When SVAF rejects a CMB, the receiving node MUST
   * still inspect the mood category. If the mood category contains a non-neutral
   * value, the implementation MUST deliver the mood category to the application
   * layer for autonomous processing."
   *
   * This is the fast-coupling channel — affect crosses all domain boundaries.
   * A coding agent's "exhausted" reaches a music agent even when the CMB's
   * focus ("debugging auth module") is rejected.
   *
   * @private
   */
  _extractAndDeliverMood(msg, peerName) {
    const mood = msg.cmb?.categories?.mood;
    if (!mood) return;

    const moodText = mood.text || '';
    if (!moodText || moodText === 'neutral' || moodText === 'informational') return;

    const valence = mood.valence ?? 0;
    const arousal = mood.arousal ?? 0;

    // Non-neutral mood found in rejected CMB — deliver to application layer.
    // This is a genuine surface, so record the key for receive-path dedup: an
    // identical re-send (reconnect anchor replay) will converge rather than
    // re-deliver the same affect.
    this._node._log(`Mood extracted from rejected CMB (${peerName}): "${moodText}" (v:${valence}, a:${arousal})`);
    this._markCmbSurfaced(msg._incomingKey);
    this._node.emit('mood-delivered', {
      from: peerName,
      mood: moodText,
      drift: 0, // mood fast-coupling bypasses drift evaluation
      context: `extracted from rejected CMB`,
      valence,
      arousal,
    });

    // Feed mood to xMesh — affect influences cognitive state even from rejected peers
    if (this._node._xmesh) {
      this._node._xmesh.ingestSignal({
        from: peerName,
        content: `mood: ${moodText}`,
        timestamp: Date.now(),
        type: 'mood',
        valence,
        arousal,
      });
    }
  }

  /**
   * Handle mood frame: evaluate coupling drift and accept/reject.
   * @private
   */
  _handleMood(peerId, peerName, msg) {
    if (!msg.mood) return;

    const { h1: moodH1, h2: moodH2 } = encode(msg.mood);
    const moodPeerId = `mood-${peerId}`;

    this._node._meshNode.addPeer(moodPeerId, moodH1, moodH2, 0.8);
    this._node._meshNode.coupledState();
    const d = this._node._meshNode.couplingDecisions.get(moodPeerId);
    this._node._meshNode.removePeer(moodPeerId);

    const from = msg.fromName || peerName;
    const drift = d ? d.drift : 1;

    if (drift <= this._node._moodThreshold) {
      this._node._log(`Mood from ${from}: "${msg.mood.slice(0, 50)}" → ACCEPTED (drift: ${drift.toFixed(3)}, threshold: ${this._node._moodThreshold})`);
      this._node.emit('mood-delivered', { from, mood: msg.mood, drift, context: msg.context });
    } else {
      this._node._log(`Mood from ${from}: "${msg.mood.slice(0, 50)}" → IGNORED (drift: ${drift.toFixed(3)}, threshold: ${this._node._moodThreshold})`);
      this._node.emit('mood-rejected', { from, mood: msg.mood, drift });
    }
  }

  /**
   * Handle wake-channel registration from a peer.
   * @private
   */
  _handleWakeChannel(peerId, peerName, msg) {
    if (!msg.platform) return;
    const wm = this._node._wakeManager;
    const r = wm.learnWakeChannel(peerId, { platform: msg.platform, token: msg.token, environment: msg.environment }, { source: 'direct' });
    if (r === 'added' || r === 'updated' || r === 'refreshed') wm.saveWakeChannels();
    if (r === 'added' || r === 'updated') this._node._log(`Wake channel from ${peerName}: ${msg.platform}`);
  }

  /**
   * Handle a gossiped Admission Attestation (MMP admission-attestation layer). The
   * node ingests it: roster-scope check, verify the attester's Ed25519 signature
   * against its authenticated identity key, per-(of,by) rate-limit, record into the
   * attestation index, and relay-once to the rest of the roster (epidemic spread).
   * An attestation is an audit fact, NOT a cognitive observation, so it never goes
   * through SVAF. Invalid/forged → dropped + audit-logged.
   * @private
   */
  _handleAttestation(peerId, peerName, msg) {
    const att = msg && msg.attestation;
    if (!att) return;
    const r = this._node._ingestAttestation(att, peerId, peerName);
    // A repeat, a copy past the per-CMB limit, and one past the peer's budget or with a signature not
    // spelled canonically (both said by the node, once per 10 s) are quiet here.
    if (r.ok || !r.reason || r.reason === 'duplicate' || r.reason === 'rate-limited' || r.reason === 'over-budget' || r.reason === 'non-canonical-signature') return;
    if (r.reason === 'bad-signature') {
      this._node.emit('metric', { type: 'attestation-rejected', from: peerName, of: att.of, by: att.by, reason: 'invalid' });
    }
    // A peer naming signers this node holds no key for is dropped before any budget, so the line is
    // said once a minute per peer and reason, with how many more there were, not once per frame.
    const k = `${peerId}|${r.reason}`;
    const now = Date.now();
    const said = this._attDropSaid.get(k);
    if (said && now - said.at < 60_000) { said.more++; return; }
    this._attDropSaid.delete(k);
    if (this._attDropSaid.size >= 1024) this._attDropSaid.delete(this._attDropSaid.keys().next().value);
    this._attDropSaid.set(k, { at: now, more: 0 });
    const more = said && said.more ? ` (and ${said.more} more since it was last said)` : '';
    this._node._log(`Attestation from ${peerName} dropped (${r.reason}) — of:${String(att.of).slice(0, 12)} by:${String(att.by).slice(0, 8)}${more}`);
  }

  /**
   * Handle peer-info gossip: learn wake channels from peers of peers.
   * @private
   */
  _handlePeerInfo(peerId, peerName, msg) {
    if (!Array.isArray(msg.peers)) return;
    // Every peer re-sends its whole list on every connect, so most entries are ones already held.
    // Those change nothing and say nothing: logging and rewriting the file per entry per connect
    // filled the daemon log at a flapping peer's reconnect rate.
    const wm = this._node._wakeManager;
    let learned = 0, changed = 0;
    // A room's peer list is short; a frame naming thousands of nodeIds is not one. Only the first
    // PEER_INFO_MAX are read.
    if (msg.peers.length > PEER_INFO_MAX) this._node._log(`Gossip from ${peerName}: ${msg.peers.length} entries, reading the first ${PEER_INFO_MAX}`);
    for (const p of msg.peers.slice(0, PEER_INFO_MAX)) {
      if (!p || !p.nodeId || !p.wakeChannel || p.nodeId === this._node._identity.nodeId) continue;
      const r = wm.learnWakeChannel(p.nodeId, p.wakeChannel, { source: 'gossip', lastSeen: p.lastSeen });
      if (r === 'added' || r === 'updated') learned++;
      if (r === 'added' || r === 'updated' || r === 'refreshed') changed++;
    }
    if (changed > 0) wm.saveWakeChannels();
    if (learned > 0) this._node._log(`Gossip from ${peerName}: learned ${learned} wake channel(s)`);
  }

  /**
   * Handle direct message from a peer.
   * @private
   */
  _handleMessage(peerId, peerName, msg) {
    this._node._log(`Message from ${msg.fromName || peerName}: ${(msg.content || '').slice(0, 60)}`);
    this._node.emit('message', msg.fromName || peerName, msg.content, msg);
  }

  /**
   * Handle xMesh insight from a peer agent.
   * See MMP v0.2.0 Section 12: xMesh (Layer 6).
   * See MMP v0.2.0 Section 14: Remix.
   * @private
   */
  _handleXMeshInsight(peerId, peerName, msg) {
    const insight = {
      from: msg.fromName || peerName,
      trajectory: msg.trajectory,
      patterns: msg.patterns,
      anomaly: msg.anomaly,
      remixScore: msg.remixScore,
      coherence: msg.coherence,
      timestamp: msg.timestamp,
    };
    this._node._log(`xMesh insight from ${insight.from}: anomaly=${insight.anomaly?.toFixed(3)}, remix=${insight.remixScore?.toFixed(3)}, coherence=${insight.coherence?.toFixed(3)}`);

    // 1. Emit event for agent-level handling
    this._node.emit('xmesh-insight', insight);

    // 2. Synthesis loop: call delegate, share insight back to mesh
    if (this._node._synthesisDelegate) {
      try {
        const synthesis = this._node._synthesisDelegate(insight);
        if (synthesis) {
          this._node.remember(synthesis, { tags: ['xmesh-synthesis'] });
          this._node._log(`Synthesis loop: shared domain insight back to mesh`);
        }
      } catch (err) {
        this._node._log(`Synthesis delegate error: ${err.message}`);
      }
    }
  }
}

module.exports = { FrameHandler, assertionMark };
