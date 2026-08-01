'use strict';

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
 * See MMP v0.2.0 Section 14: Echo loop prevention.
 *
 * Copyright (c) 2026 SYM.BOT. Apache 2.0 License.
 */

const fs = require('fs');
const path = require('path');
const { encode, DIM, processHeuristicSVAF, computeFieldVerdicts, decryptFields, blockKeyV2, resolveTetherAnchor, signTetherAttestation, verifyTetherAttestation, recomputeKey } = require('@sym-bot/core');

// Receive-path dedup window (MMP §4.2 O2 — rejoin-without-replay convergence).
// A CMB whose content-hash key we have already processed within this window is
// suppressed rather than re-evaluated/re-remixed/re-emitted. Bounds the dedup
// cache so a long-lived node does not grow it without limit.
const SEEN_CMB_TTL_MS = 60 * 60 * 1000; // 1 hour
const SEEN_CMB_MAX = 10000;

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
    // Receive-path dedup cache: CMB content-hash key -> last-seen timestamp.
    // Distinct from the local store (which holds *remix* keys); this tracks the
    // raw *incoming* keys so the same CMB re-sent on reconnect/resync converges
    // instead of cycling. See _handleMemoryShare and MMP §4.2 O2.
    this._seenCmbKeys = new Map();
    // Persist the dedup cache across plugin reloads / process restarts. Without this,
    // a reload wipes the cache and every already-processed CMB re-surfaces as new — a
    // primary trigger of the cross-node echo storm (MMP §14). Best-effort: any FS error
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
        if (typeof ts === 'number' && (now - ts) < SEEN_CMB_TTL_MS) this._seenCmbKeys.set(k, ts);
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
    this._seenCmbKeys.set(key, now);
    if (this._seenCmbKeys.size > SEEN_CMB_MAX) {
      for (const [k, ts] of this._seenCmbKeys) {
        if (this._seenCmbKeys.size <= SEEN_CMB_MAX) break;
        if (now - ts >= SEEN_CMB_TTL_MS) this._seenCmbKeys.delete(k);
      }
      while (this._seenCmbKeys.size > SEEN_CMB_MAX) {
        const oldest = this._seenCmbKeys.keys().next().value;
        this._seenCmbKeys.delete(oldest);
      }
    }
    this._persistSeenCmbKeys(now);
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
   * @param {object} msg - The frame payload with a .type field.
   * @returns {void}
   */
  handle(peerId, peerName, msg) {
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
   * is stored and surfaced. SVAF fusion rebuilds the CMB from its CAT7 fields —
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
   * surfaced (so the caller can skip the broadcast-only mood fast-path).
   *
   * The surfaced entry carries `remixed: false` — the receiver delivered the
   * CMB to the agent but did NOT ingest it into memory (no remix, no lineage).
   * Consumers check this flag to distinguish a delivered-only directed CMB from
   * one that was ingested (see node.js receiveFromPeer, which sets remixed:true).
   * `decision` carries the SVAF verdict (redundant/rejected) so the agent knows
   * why it was not stored.
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
   * Verify the Ed25519 signature on an inbound CMB against the sending peer's
   * announced identity key (MMP §8.3). Returns true if the CMB must be REJECTED
   * (a present-but-invalid signature — forged/tampered; or unsigned when the
   * node is configured to require signatures). Sets msg._cmbVerified. Unsigned
   * CMBs, or signed CMBs from a peer whose key we haven't seen yet, are allowed
   * through (flagged unverified) for interop unless strict mode is on.
   * @private
   */
  _rejectOnBadSignature(peerId, peerName, msg) {
    const cmb = msg.cmb;
    // v2 carries the address in metadata; a pre-boundary record at the top level. Logs and
    // metrics must name the block either way — an undefined key in a security log is worse
    // than no log, because it reads as a record with no address.
    const cmbKeyOf = (c) => c?.metadata?.key ?? c?.key ?? null;
    if (!cmb) { msg._cmbVerified = false; return false; }
    const { verifyCMB } = require('@sym-bot/core');
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
      // (handshake not processed). Cannot verify — do not reject; treat unverified.
      msg._cmbVerified = false;
      return false;
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
      this._node._log(`[sym-security] BAD SIGNATURE on CMB ${keyShort} from ${peerName} — forged/tampered, rejected${v.error ? ' (' + v.error + ')' : ''}`);
      this._node.emit('metric', { type: 'cmb-signature-rejected', from: peerName, key: cmbKeyOf(cmb), reason: 'invalid' });
      if (typeof this._node._recordDecision === 'function') {
        this._node._recordDecision({
          method: 'signature', source: msg.source || peerName, cmbKey: cmbKeyOf(cmb),
          decision: 'rejected-signature', totalDrift: null, fieldDrifts: null, gateValues: null,
          focusLabel: 'bad-signature',
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
    // return would admit a cross-group legacy replay while fixing the forgery misreport. Closing
    // one hole by opening another is not a fix.

    // Audience (§18.3.1): a genuinely-signed v1 CMB whose bound group is not this
    // node's group, or which is directed at another node, is a cross-group / mis-
    // directed replay. Reject it — reported distinctly from a bad signature.
    const { checkAudience } = require('@sym-bot/core');
    const aud = checkAudience(cmb, this._node._group, this._node.nodeId);
    if (!aud.ok) {
      this._node._log(`[sym-security] ${aud.reason} on CMB ${String(cmbKeyOf(cmb) || '').slice(0, 16)} from ${peerName} — rejected`);
      this._node.emit('metric', { type: 'cmb-audience-rejected', from: peerName, key: cmbKeyOf(cmb), reason: aud.reason });
      return true;
    }

    // Unattested is not verified. A grandfathered block is admitted and readable, but it MUST
    // NOT be marked verified — anything downstream weighing this flag is entitled to know the
    // difference between "this peer proved authorship" and "this predates the proof".
    msg._cmbVerified = !grandfathered;
    return false;
  }

  /**
   * MMP §7 cmb-fetch: content-addressed retrieval. A peer asks for the CMB this
   * store holds under an exact content-address key — the §15.8 re-verification
   * path (fetch an unresolvable lineage root, verify the address, re-encode,
   * recompute the tether). Serving is discretionary and same-group by
   * construction (only connected peers can ask); the response is self-verifying
   * (the requester recomputes the content address), so no trust is extended by
   * serving and none is required of the server. Fields are served TEXT-ONLY:
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
    if (cmb && cmb.fields && typeof cmb.fields === 'object') {
      const fields = {};
      for (const [f, v] of Object.entries(cmb.fields)) {
        if (v && typeof v === 'object') {
          fields[f] = { text: v.text ?? '' };
          if (f === 'mood') {
            if (typeof v.valence === 'number') fields[f].valence = v.valence;
            if (typeof v.arousal === 'number') fields[f].arousal = v.arousal;
          }
        } else {
          fields[f] = { text: String(v ?? '') };
        }
      }
      // §15.8 serves a RECORD, and the record is two sections. Serving the flat shape would
      // hand the requester something that validates against neither schema — and cmb-fetch is
      // self-verifying, so the requester would recompute the address and refuse it.
      // A pre-boundary record is served in the shape it was stored in: the legacy DAG stays
      // readable and is never re-keyed (§7.8).
      const m = cmb.metadata;
      served = m
        ? {
            fields,
            metadata: {
              key: m.key, createdBy: m.createdBy, createdTimestamp: m.createdTimestamp,
              lineage: m.lineage ?? null, room: m.room ?? null, to: m.to ?? null,
              sig: m.sig, sigAlg: m.sigAlg,
            },
          }
        : {
            key: cmb.key, createdBy: cmb.createdBy, createdAt: cmb.createdAt,
            fields, lineage: cmb.lineage ?? null,
            sig: cmb.sig, sigAlg: cmb.sigAlg, group: cmb.group, to: cmb.to,
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
    // the Merkle root over the seven fieldKeys — content-only, so recomputing it needs nothing
    // but the fields that arrived. A pre-boundary record is checked the old way; the legacy DAG
    // stays readable and is never re-keyed (§7.8).
    const served = cmb?.metadata?.key ?? cmb?.key;
    if (!cmb || served !== pending.key) { pending.miss(peerId); return; }
    const recomputed = cmb.metadata
      ? blockKeyV2(cmb.fields)
      : (typeof recomputeKey === 'function' ? recomputeKey(cmb) : null);
    if (recomputed !== pending.key) {
      this._node._log(`[cmb-fetch] content-address MISMATCH from ${peerName} for ${String(pending.key).slice(0, 16)}… — discarded`);
      this._node.emit('metric', { type: 'cmb-fetch-forged', from: peerName, key: pending.key });
      pending.miss(peerId);
      return;
    }
    pending.resolve({ cmb, from: peerName, peerId });
  }

  _handleMemoryShare(peerId, peerName, msg) {
    // Decrypt E2E-encrypted CMB fields if present
    if (msg.cmb && typeof msg.cmb.fields === 'string' && msg.cmb._e2e) {
      const sharedSecret = this._node._peerSharedSecrets?.get(peerId);
      if (sharedSecret) {
        try {
          msg.cmb.fields = decryptFields(msg.cmb.fields, msg.cmb._e2e.nonce, sharedSecret);
          delete msg.cmb._e2e;
          this._node._log(`E2E decrypted fields from ${peerName}`);
        } catch (err) {
          this._node._log(`E2E decryption failed from ${peerName}: ${err.message}`);
          return; // Cannot process corrupted/tampered frame
        }
      } else {
        this._node._log(`E2E encrypted frame from ${peerName} but no shared secret — dropping`);
        return;
      }
    }

    // Derive content from CMB fields if not present on the frame
    // (MMP Section 7: cmb frames carry structured fields, not necessarily a content string)
    if (!msg.content && msg.cmb?.fields) {
      const { renderContent } = require('@sym-bot/core');
      msg.content = renderContent(msg.cmb);
    }
    if (!msg.content) return;

    // CMB authentication (MMP §8.3). A signed CMB MUST verify against the
    // sending peer's Ed25519 identity key (announced in its handshake). A
    // present-but-invalid signature means the CMB was forged or tampered in
    // flight — reject it outright (audit-logged, never surfaced or stored).
    // Unsigned CMBs (older peers, or peers without a known key yet) are allowed
    // through for interop but flagged unverified on msg._cmbVerified.
    if (this._rejectOnBadSignature(peerId, peerName, msg)) return;

    // Echo loop prevention (MMP Section 14): if the incoming CMB's
    // lineage parents include a key that exists in our local cmbs,
    // this CMB is a derivative of our own broadcast. Skip all
    // processing — including mood delivery — to prevent ping-pong
    // between same-app peers.
    const incomingParents = msg.cmb?.lineage?.parents || [];
    if (incomingParents.length > 0) {
      const isEcho = incomingParents.some(parentKey => this._node._store.hasLocalKey(parentKey));
      if (isEcho) {
        this._node._log(`Echo detected — parent key found in local cmbs, skipping CMB from ${peerName}`);
        return;
      }
    }

    const now = Date.now();
    const originTs = msg.originTimestamp || msg.timestamp || now;
    const ageSeconds = (now - originTs) / 1000;

    // Receive-path dedup (MMP §4.2 O2 — rejoin-without-replay convergence).
    // The send path already drops *local* duplicates (node.remember skips
    // re-broadcast when the key is already stored). But a CMB *received* from a
    // peer had no such guard: the anchor-CMB replay every node sends on each
    // Bonjour reconnect — plus the same CMB arriving via multiple peers — was
    // reprocessed each time (re-run through SVAF, remixed under a fresh key,
    // re-emitted as 'cmb-accepted'). With several flapping/zombie instances each
    // replaying accumulated memory, that produced a sustained replay storm.
    // `_cmbKey` (sym-core, MMP §8.2) is a content hash over the CMB fields, so an
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
    const incomingKey = msg.cmb?.key || msg.key;
    if (incomingKey) {
      const lastSeen = this._seenCmbKeys.get(incomingKey);
      if (lastSeen !== undefined && (now - lastSeen) < SEEN_CMB_TTL_MS) {
        this._seenCmbKeys.set(incomingKey, now); // refresh recency
        this._node._log(`Duplicate CMB ${String(incomingKey).slice(0, 16)} from ${peerName} — seen within TTL, skipping (convergence)`);
        return;
      }
    }
    // Carry the key down the processing chain so each surface point can record
    // it once the CMB has actually been delivered.
    msg._incomingKey = incomingKey || null;

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
    // gap where a directed CMB would otherwise be silently dropped. Group-bound
    // broadcasts (sym_publish, no `to`) leave the flag false and stay fully
    // SVAF-gated for surfacing — receiver-autonomous attention.
    msg._directedToMe = msg.directed === true && !!msg.to && msg.to === this._node.nodeId;

    // Get local memory anchors for both paths
    const recentEntries = this._node._store.allEntries().slice(0, 5);
    const anchorTexts = recentEntries.map(e => ({ text: e.content, source: e.source, tags: e.tags || [] }));

    // Try neural SVAF first (Layer 4 cognition)
    this._node._svafEvaluator.evaluate(
      { text: msg.content, source: msg.source || peerName, tags: msg.tags || [], confidence: msg.confidence || 0.8 },
      anchorTexts,
      ageSeconds,
    ).then((neuralResult) => {
      if (neuralResult) {
        this._processNeuralSVAF(neuralResult, msg, peerName, peerId, originTs, now);
      } else {
        this._runHeuristicSVAFContained(msg, peerName, peerId, originTs, now, ageSeconds);
      }
    }).catch((err) => {
      this._node._log(`SVAF neural error: ${err.message} — falling back to heuristic`);
      this._runHeuristicSVAFContained(msg, peerName, peerId, originTs, now, ageSeconds);
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
    Promise.resolve()
      .then(() => this._processHeuristicSVAF(msg, peerName, peerId, originTs, now, ageSeconds))
      .catch((err) => this._node._log(`SVAF heuristic error on frame from ${peerName}: ${err.message} — frame dropped`));
  }

  /**
   * Process a successful neural SVAF result.
   * @private
   */
  _processNeuralSVAF(result, msg, peerName, peerId, originTs, now) {
    const { decision, total_drift, field_drifts, gate_values } = result;

    // Record EVERY evaluation (admit AND reject). The autonomy IS the decision;
    // a rejection leaves no other trace, so this is where sovereignty is captured.
    this._node._recordDecision({
      method: 'neural',
      source: msg.source || peerName,
      cmbKey: (msg.cmb && msg.cmb.key) || msg.key || null,
      decision,
      totalDrift: total_drift,
      fieldDrifts: field_drifts || null,
      gateValues: gate_values || null,
      focusLabel: String((msg.cmb && msg.cmb.fields && msg.cmb.fields.focus && msg.cmb.fields.focus.text) || msg.content || '').slice(0, 120),
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
      const rejKey = msg.cmb?.key || msg.key;
      if (rejKey) {
        const rejVerdicts = computeFieldVerdicts(field_drifts || {}, {
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

    // Propagate lineage: fused CMB is a child of the incoming CMB
    const incomingKey = msg.cmb?.key || msg.key;
    const incomingAncestors = msg.cmb?.lineage?.ancestors || [];

    const fusedEntry = {
      ...msg,
      source: `${this._node.name}+${msg.source || peerName}`,
      storedAt: now,
      svaf: {
        method: 'neural',
        decision,
        totalDrift: total_drift,
        fieldDrifts: field_drifts,
        gateValues: gate_values,
      },
    };
    // §7.5 COLLAPSE-BEFORE-MINT [MUST] — the Rule A self-loop.
    //
    // This used to mint a remix key over fields + parents + the RECEIVER'S NAME, which
    // guaranteed remix key != parent key by construction. Under content-only addressing that
    // guarantee is gone and must be replaced by a check rather than assumed: a fusion that
    // leaves the content unchanged (first-observation forwarding, a redundant re-assertion)
    // now addresses to exactly the parent's key, so writing lineage.parents = [incomingKey]
    // would produce the edge K -> K. A reachability walk never leaves it.
    //
    // The collapse property is what prevents it: the re-assertion MINTS NOTHING and cites the
    // address that already exists. Rule A is sound under content-only addressing IFF collapse
    // holds, so this is the place that has to hold it.
    if (incomingKey && fusedEntry.cmb) {
      const fusedKey = blockKeyV2(fusedEntry.cmb.fields);
      if (fusedKey === incomingKey) {
        // Nothing new was said. Cite, do not mint, and do not claim descent from oneself.
        fusedEntry.cmb.metadata.key = incomingKey;
        fusedEntry.key = incomingKey;
        fusedEntry.cmb.metadata.lineage = null;
        fusedEntry.collapsed = true;
      } else {
        fusedEntry.cmb.metadata.key = fusedKey;
        fusedEntry.key = fusedKey;
        fusedEntry.cmb.metadata.lineage = {
          parents: [incomingKey],
          method: 'svaf-neural',
        };
      }
    }
    // Admission Attestation (MMP) — the per-field gating verdict, signed + bound to
    // the gated CMB, persisted on the remix as the durable audit record. The neural
    // path emits per-field drift; map it to verdicts with the same thresholds (Phase A).
    if (incomingKey && fusedEntry.cmb) {
      const fieldVerdicts = computeFieldVerdicts(field_drifts || {}, {
        stableThreshold: this._node._svafStableThreshold,
        guardedThreshold: this._node._svafGuardedThreshold,
      });
      const att = this._node._buildAdmissionAttestation(incomingKey, decision, fieldVerdicts, 'neural');
      if (att) fusedEntry.cmb.admission = att;
    }
    // Opaque payload rides alongside CAT7 — carry it onto the admitted remix.
    this._preserveIncomingPayload(fusedEntry, msg);
    this._node._store.receiveFromPeer(peerId, fusedEntry, { creatorRole: this._getCreatorRole(peerId, msg) });

    // Re-encode context with new memory
    const context = this._node._buildContext();
    const { h1, h2 } = encode(context);
    this._node._meshNode.updateLocalState(h1, h2, 0.8);

    // Feed to xMesh (Layer 6). See MMP v0.2.0 Section 12.
    if (this._node._xmesh) {
      this._node._xmesh.ingestSignal({
        from: peerName,
        content: msg.content || '',
        timestamp: Date.now(),
        type: 'mesh',
        valence: msg.cmb?.fields?.mood?.valence || 0,
        arousal: msg.cmb?.fields?.mood?.arousal || 0,
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
    const gFields = msg.cmb?.fields;
    const groundingWaiver = msg._cmbVerified === true
      && gFields?.intent?.text === 'ground'
      && /^(verified|failed):/.test(gFields?.commitment?.text || '')
      && Array.isArray(msg.cmb?.lineage?.parents)
      && typeof this._node._store?.has === 'function'
      && msg.cmb.lineage.parents.some(p => this._node._store.has(p));

    // Inbound §15.8 tether attestation: a re-emitted remix may carry its
    // integrator's signed tether evaluation. Verify against the integrator's
    // roster-resolved key. An INVALID one is stripped — a forged certificate
    // is worse than an absent one; a valid-but-unverifiable one (no resolvable
    // key) rides through unverified, the same posture as unsigned CMBs.
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

    // MMP §15.8 lineage tether: resolve the earliest-stored resolvable lineage
    // root of the incoming CMB (the incoming block itself when it is a root).
    // The gate evaluates the remix against it in-kernel and reports; severance
    // is applied below on the result.
    const tetherAnchor = this._node._lineageTether && typeof resolveTetherAnchor === 'function'
      ? resolveTetherAnchor(msg.cmb, (k) => this._node._store.get(k))
      : null;

    const result = await processHeuristicSVAF({
      tetherAnchor: tetherAnchor && tetherAnchor.fields ? tetherAnchor : undefined,
      msg,
      peerName,
      localName: this._node.name,
      originTs,
      now,
      ageSeconds,
      groundingWaiver,
      recentCMBs: this._node._store.recentCMBs(5),
      recentDecisions: this._node._recentSvafDecisions,
      config: {
        stableThreshold: this._node._svafStableThreshold,
        guardedThreshold: this._node._svafGuardedThreshold,
        temporalLambda: this._node._svafTemporalLambda,
        freshnessSeconds: this._node._svafFreshnessSeconds,
        fieldWeights: this._node._svafFieldWeights,
        adaptiveTimescale: this._node._svafAdaptiveTimescale,
        minFreshnessSeconds: this._node._svafMinFreshnessSeconds,
        reactivity: this._node._svafReactivity,
        changeWeights: this._node._svafChangeWeights ?? undefined,
      },
    });

    // Record EVERY heuristic evaluation too (admit / redundant / rejected).
    this._node._recordDecision({
      method: 'heuristic',
      source: msg.source || peerName,
      cmbKey: (msg.cmb && msg.cmb.key) || msg.key || null,
      decision: result.decision,
      totalDrift: result.totalDrift,
      effectiveTau: result.effectiveTau ?? null,
      changeSignal: result.changeSignal ?? null,
      fieldDrifts: result.fieldDrifts || null,
      gateValues: result.gateValues || null,
      focusLabel: String((msg.cmb && msg.cmb.fields && msg.cmb.fields.focus && msg.cmb.fields.focus.text) || msg.content || '').slice(0, 120),
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
      // per-field verdict; index it (no remix is stored on this path).
      const rejKey = msg.cmb?.key || msg.key;
      if (rejKey) this._node._buildAdmissionAttestation(rejKey, result.decision, result.fieldVerdicts, 'heuristic');

      // MMP Section 9.3: mood MUST still be delivered from rejected CMBs.
      // (redundant signals also deliver mood — the affect may have changed)
      // Key recording happens inside _extractAndDeliverMood iff a non-neutral
      // mood actually surfaces; a neutral reject surfaces nothing and is left
      // re-evaluable as B's memory evolves.
      this._extractAndDeliverMood(msg, peerName);
      return;
    }

    // Admission Attestation (MMP) — the heuristic gate already produced the per-field
    // verdict (Phase A, result.fieldVerdicts); sign + bind it to the gated CMB and
    // persist it on the remix as the durable audit record.
    if (result.fusedEntry && result.fusedEntry.cmb) {
      const of = msg.cmb?.key || msg.key;
      const att = this._node._buildAdmissionAttestation(of, result.decision, result.fieldVerdicts, 'heuristic');
      if (att) result.fusedEntry.cmb.admission = att;
    }
    // Opaque payload rides alongside CAT7 — the heuristic fusion rebuilds the
    // CMB from fields and drops it, so re-attach before storing the remix.
    this._preserveIncomingPayload(result.fusedEntry, msg);

    // MMP §15.8 lineage tether — severance. The gate evaluated the remix
    // against the resolved anchor content-only, in one kernel; a remix
    // drifted past the reject floor MUST NOT carry the chain's lineage
    // (keeping it would forge fidelity), so it is stored as a fresh root
    // with the departed source recorded informally in provenance. An
    // unverifiable tether (checked=false) is a trust state, never severed.
    if (result.tether?.checked && !result.tether.tethered && result.fusedEntry?.cmb?.lineage) {
      const departedFrom = result.fusedEntry.cmb.lineage.parents?.[0] ?? null;
      result.fusedEntry.cmb.lineage = null; // fresh root (§15.8 severance)
      result.fusedEntry.cmb.provenance = {
        ...result.fusedEntry.cmb.provenance,
        tether: { severed: true, anchor: result.tether.anchorKey, kernelId: result.tether.kernelId, drift: result.tether.drift, departedFrom },
      };
      this._node._log(`[§15.8] lineage severed: remix drift ${result.tether.drift.toFixed(3)} from anchor ${String(result.tether.anchorKey).slice(0, 16)} exceeds the reject floor — stored as fresh root (departed-from in provenance)`);
      this._node.emit('metric', { type: 'lineage-tether-severed', key: result.fusedEntry.cmb.key, anchor: result.tether.anchorKey, drift: result.tether.drift });
    } else if (result.tether?.checked && result.fusedEntry?.cmb) {
      result.fusedEntry.cmb.provenance = {
        ...result.fusedEntry.cmb.provenance,
        tether: { severed: false, anchor: result.tether.anchorKey, kernelId: result.tether.kernelId, drift: result.tether.drift },
      };
    }

    // MMP §15.8 tether attestation: sign the exact evaluation performed —
    // remix key, anchor, kernel identity, drift, verdict — so a downstream
    // receiver that cannot resolve the anchor holds attested-by-integrator
    // instead of unchecked. Carried on the remix (cmb.tether); trust in the
    // verdict is weighed through the integrator's resolved authority, and
    // verdicts are comparable only within one kernelId.
    if (result.tether?.checked && result.fusedEntry?.cmb
        && typeof signTetherAttestation === 'function' && this._node._identity?.privateKey) {
      try {
        result.fusedEntry.cmb.tether = signTetherAttestation({
          of: result.fusedEntry.cmb.key,
          anchor: result.tether.anchorKey,
          kernelId: result.tether.kernelId,
          drift: result.tether.drift,
          verdict: result.tether.tethered ? 'tethered' : 'severed',
          by: this._node.nodeId,
          at: now,
        }, this._node._identity.privateKey);
      } catch (e) {
        this._node._log(`[§15.8] tether attestation signing failed: ${e.message}`);
      }
    }

    this._node._store.receiveFromPeer(peerId, result.fusedEntry, { creatorRole: this._getCreatorRole(peerId, msg) });

    // Feed to xMesh (Layer 6). See MMP v0.2.0 Section 12.
    if (this._node._xmesh) {
      this._node._xmesh.ingestSignal({
        from: peerName,
        content: result.fusedContent || msg.content || '',
        timestamp: Date.now(),
        type: 'mesh',
        valence: msg.cmb?.fields?.mood?.valence || result.fusedCMB?.fields?.mood?.valence || 0,
        arousal: msg.cmb?.fields?.mood?.arousal || result.fusedCMB?.fields?.mood?.arousal || 0,
      });
    }

    this._node._log(`SVAF heuristic ${result.decision} from ${peerName}: "${result.fusedContent.slice(0, 50)}" drift:${result.totalDrift.toFixed(3)}`);
    this._markCmbSurfaced(msg._incomingKey);
    this._node.emit('memory-received', { from: peerName, entry: result.fusedEntry, decision: result.decision });
  }

  /**
   * Extract mood from a rejected CMB and deliver to application layer.
   *
   * MMP Section 9.3: "When SVAF rejects a CMB, the receiving node MUST
   * still inspect the mood field. If the mood field contains a non-neutral
   * value, the implementation MUST deliver the mood field to the application
   * layer for autonomous processing."
   *
   * This is the fast-coupling channel — affect crosses all domain boundaries.
   * A coding agent's "exhausted" reaches a music agent even when the CMB's
   * focus ("debugging auth module") is rejected.
   *
   * @private
   */
  _extractAndDeliverMood(msg, peerName) {
    const mood = msg.cmb?.fields?.mood;
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
    this._node._peerWakeChannels.set(peerId, {
      platform: msg.platform,
      token: msg.token,
      environment: msg.environment,
    });
    this._node._wakeManager.saveWakeChannels();
    this._node._log(`Wake channel from ${peerName}: ${msg.platform}`);
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
    if (!r.ok && r.reason && r.reason !== 'duplicate' && r.reason !== 'rate-limited') {
      this._node._log(`Attestation from ${peerName} dropped (${r.reason}) — of:${String(att.of).slice(0, 12)} by:${String(att.by).slice(0, 8)}`);
      if (r.reason === 'bad-signature') {
        this._node.emit('metric', { type: 'attestation-rejected', from: peerName, of: att.of, by: att.by, reason: 'invalid' });
      }
    }
  }

  /**
   * Handle peer-info gossip: learn wake channels from peers of peers.
   * @private
   */
  _handlePeerInfo(peerId, peerName, msg) {
    if (!Array.isArray(msg.peers)) return;
    for (const p of msg.peers) {
      if (p.nodeId && p.wakeChannel && p.nodeId !== this._node._identity.nodeId) {
        this._node._peerWakeChannels.set(p.nodeId, p.wakeChannel);
        this._node._log(`Gossip from ${peerName}: learned wake channel for ${p.name}`);
      }
    }
    this._node._wakeManager.saveWakeChannels();
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

module.exports = { FrameHandler };
