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

const { encode, DIM, processHeuristicSVAF, decryptFields, remixKey } = require('@sym-bot/core');

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
      this._node._peerIdentityKeys.set(peerId, msg.publicKey);
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
    // Direct peer role from handshake
    const peerRole = this._node._peerLifecycleRoles?.get(peerId);
    if (peerRole) return peerRole;
    // CMB may have been relayed — check createdBy against all known peer roles
    const createdBy = msg.cmb?.createdBy;
    if (createdBy && this._node._peerLifecycleRoles) {
      for (const [id, role] of this._node._peerLifecycleRoles) {
        const peer = this._node._peers?.get(id);
        if (peer?.name === createdBy) return role;
      }
    }
    return 'observer';
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
    if (!cmb) { msg._cmbVerified = false; return false; }
    const { verifyCMB } = require('@sym-bot/core');
    const senderKey = this._node._peerIdentityKeys?.get(peerId);
    const v = verifyCMB(cmb, senderKey);

    if (!v.signed) {
      msg._cmbVerified = false;
      if (this._node._requireSignedCmb && senderKey) {
        this._node._log(`[sym-security] UNSIGNED CMB from ${peerName} rejected (SYM_REQUIRE_SIGNED_CMB)`);
        this._node.emit('metric', { type: 'cmb-signature-rejected', from: peerName, key: cmb.key, reason: 'unsigned' });
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

    if (!v.valid) {
      const keyShort = String(cmb.key || '').slice(0, 16);
      this._node._log(`[sym-security] BAD SIGNATURE on CMB ${keyShort} from ${peerName} — forged/tampered, rejected${v.error ? ' (' + v.error + ')' : ''}`);
      this._node.emit('metric', { type: 'cmb-signature-rejected', from: peerName, key: cmb.key, reason: 'invalid' });
      if (typeof this._node._recordDecision === 'function') {
        this._node._recordDecision({
          method: 'signature', source: msg.source || peerName, cmbKey: cmb.key || null,
          decision: 'rejected-signature', totalDrift: null, fieldDrifts: null, gateValues: null,
          focusLabel: 'bad-signature',
        });
      }
      return true;
    }

    msg._cmbVerified = true;
    return false;
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
    // lineage parents include a key that exists in our local meshmem,
    // this CMB is a derivative of our own broadcast. Skip all
    // processing — including mood delivery — to prevent ping-pong
    // between same-app peers.
    const incomingParents = msg.cmb?.lineage?.parents || [];
    if (incomingParents.length > 0) {
      const isEcho = incomingParents.some(parentKey => this._node._store.hasLocalKey(parentKey));
      if (isEcho) {
        this._node._log(`Echo detected — parent key found in local meshmem, skipping CMB from ${peerName}`);
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
    // broadcasts (sym_observe, no `to`) leave the flag false and stay fully
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
        this._processHeuristicSVAF(msg, peerName, peerId, originTs, now, ageSeconds);
      }
    }).catch((err) => {
      this._node._log(`SVAF neural error: ${err.message} — falling back to heuristic`);
      this._processHeuristicSVAF(msg, peerName, peerId, originTs, now, ageSeconds);
    });
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
    // MMP §14 lineage DAG: mint a remix key distinct from the parent's
    // key so lineage.parents carries a real edge, not a self-reference.
    // `remixKey` hashes over fields + parentKey + receiverName, giving
    // (i) idempotent dedup for retries, (ii) distinct remix keys across
    // different receivers fusing the same input, (iii) remix key ≠
    // parent key by construction.
    if (incomingKey && fusedEntry.cmb) {
      const newKey = remixKey(fusedEntry.cmb.fields, incomingKey, this._node.name);
      fusedEntry.cmb.key = newKey;
      fusedEntry.key = newKey;
      fusedEntry.cmb.lineage = {
        parents: [incomingKey],
        ancestors: [...new Set([incomingKey, ...incomingAncestors])],
        method: 'svaf-neural',
      };
    }
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
    const result = await processHeuristicSVAF({
      msg,
      peerName,
      localName: this._node.name,
      originTs,
      now,
      ageSeconds,
      recentCMBs: this._node._store.recentCMBs(5),
      config: {
        stableThreshold: this._node._svafStableThreshold,
        guardedThreshold: this._node._svafGuardedThreshold,
        temporalLambda: this._node._svafTemporalLambda,
        freshnessSeconds: this._node._svafFreshnessSeconds,
        fieldWeights: this._node._svafFieldWeights,
      },
    });

    // Record EVERY heuristic evaluation too (admit / redundant / rejected).
    this._node._recordDecision({
      method: 'heuristic',
      source: msg.source || peerName,
      cmbKey: (msg.cmb && msg.cmb.key) || msg.key || null,
      decision: result.decision,
      totalDrift: result.totalDrift,
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

      // MMP Section 9.3: mood MUST still be delivered from rejected CMBs.
      // (redundant signals also deliver mood — the affect may have changed)
      // Key recording happens inside _extractAndDeliverMood iff a non-neutral
      // mood actually surfaces; a neutral reject surfaces nothing and is left
      // re-evaluable as B's memory evolves.
      this._extractAndDeliverMood(msg, peerName);
      return;
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
