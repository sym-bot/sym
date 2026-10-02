'use strict';

const crypto = require('crypto');

const { recordKey, recordLineage, recordParents, recordCreatedBy, setRecordLineage } = require('./record');
const { wireNodeId, wireName } = require('./wire-identity');
const { ATTEST_FRAME, fromWireAttestation, fromWireCheckpoint, fromWireWitness, fromWireNodeStats } = require('./core/attestation');

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
 * See MMP v0.2.0 Section 12: XMesh (Layer 6).
 * Echo loop prevention: the anti-echo rule of MMP v2.0 §15.7 (it was Section 14 in v0.2.0).
 *
 * Copyright (c) 2026 SYM.BOT. Apache 2.0 License.
 */

const fs = require('fs');
const path = require('path');
const { encode, cosineSimilarity, processHeuristicSVAF, buildFusedRecord, computeCategoryVerdicts, resolveTetherAnchor, tetherOfRecord, signTetherAttestation, verifyTetherAttestation, classifyAddress, categoriesAsSigned, recordAsSigned } = require('./core');

/** The schema of the signed application section that marks a directed record as a message (design D1). */
const MESSAGE_SCHEMA = 'https://sym.bot/schema/message-v1.json';

/** The schema of the signed application section remember({ payload }) carries (§8.8.3). */
const PAYLOAD_SCHEMA = 'https://sym.bot/schema/payload-v1.json';

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
/** The most `peer-info` entries read from one frame, and the most a frame this node sends carries. */
const { PEER_INFO_MAX } = require('./core/wake');

/** A record refused for its audience is said at most once per this many ms per peer and reason. */
/** Freeze an object graph (plain data: a structured clone of a record). */
function deepFreeze(o) {
  if (o && typeof o === 'object' && !Object.isFrozen(o)) {
    Object.freeze(o);
    for (const v of Object.values(o)) deepFreeze(v);
  }
  return o;
}

/** The most keys one cmb-fetch may name (design D1). */
const MAX_FETCH_KEYS = 32;
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
    this._sessionOf = new WeakMap(); // frame -> the session that authenticated it
    this._unsignedWarned = new Set();
    this._attDropSaid = new Map(); // `${connection}|${reason}` -> { at, more }: a dropped attestation is said once a minute
    this._doorSaid = new Map();    // `${connection}|${reason}` -> { at, more }: a frame the door refused, the same way
    this._longPeerInfoSaid = new Map(); // peerId -> when an over-long peer-info from it was last said
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
   * Handle one AUTHENTICATED frame from a confirmed session (design D1). The session is the unit of
   * trust: `session.nodeId` and `session.identityKey` are what the §5.2 exchange proved, and every
   * per-peer structure is keyed by that nodeId; `session.name` is a label. Frames reach here only
   * through SymNode._receiveSessionFrame (the one guarded dispatch) from a session the room door
   * admitted. The wire frame table (design D1) is applied by the session (lib/session.js): records
   * arrive here as {type:'cmb', cmb} only after cmb-encrypted opened; every other frame was sealed.
   * @param {object} session - a confirmed session (lib/session.js PeerSession)
   * @param {object} msg - the inner frame
   */
  handle(session, msg) {
    if (!session || session.confirmed !== true || typeof session.nodeId !== 'string' || !session.nodeId) {
      throw new Error('frame-handler: frames are handled only from a confirmed session');
    }
    if (!msg || typeof msg !== 'object' || typeof msg.type !== 'string') throw new Error('frame-handler: not a frame');
    const peerId = session.nodeId;
    const peerName = typeof session.name === 'string' ? session.name : 'unknown';
    // THE DOOR (MMP §5.8.1), consulted per frame. The session layer admits only sessions the door
    // admitted; this is the second check, so no future path can dispatch around it.
    if (typeof this._node._roomDoor === 'function') {
      const door = this._node._roomDoor(peerId);
      if (!door.pass) {
        this._sayOnceAMinute(this._doorSaid, `${peerId}|${door.reason}`,
          (more) => `Door refused '${msg.type}' from ${peerName}: ${door.reason}${more}`);
        return;
      }
    }
    // One frame must never end the node. That is the node's one guarded dispatch (SymNode
    // _receiveSessionFrame, 0.13.17): a throw from here is refused and counted there.
    this._dispatch(session, peerId, peerName, msg);
  }

  /** A frame type that rides only on sessions that selected an extension (§16.3). */
  /** @private A sym-attest frame whose fields are not what the extension defines: refused, counted. */
  _attestMalformed(session, type) {
    if (typeof this._node._noteSessionRefusal === 'function') this._node._noteSessionRefusal(session, type, 'malformed');
    return undefined;
  }

  _extensionRefused(session, type, ext) {
    if (typeof session.has === 'function' && session.has(ext)) return false;
    if (typeof this._node._noteSessionRefusal === 'function') this._node._noteSessionRefusal(session, type, `${ext} not selected`);
    return true;
  }

  _dispatch(session, peerId, peerName, msg) {
    switch (msg.type) {
      case 'cmb':
        return this._handleMemoryShare(peerId, peerName, msg, session);

      case 'cmb-anchors':
        // The records that follow on this session are the sender's replayed context, not new signals
        // (they cannot carry a flag of their own: the record frame is fixed by §18.2.1).
        if (Array.isArray(msg.keys)) session._anchorKeys = new Set(msg.keys.filter((k) => typeof k === 'string').slice(0, 50));
        return undefined;

      case 'mood':
        return this._handleMood(peerId, peerName, msg);

      case 'wake-channel':
        return this._handleWakeChannel(peerId, peerName, msg);

      case 'peer-info':
        return this._handlePeerInfo(peerId, peerName, msg);

      // sym-attest-v1 (draft spec PR #27): the extension's frames, only where it was selected, each
      // checked field by field and translated to the store's form before anything else.
      case ATTEST_FRAME.attestation: {
        if (this._extensionRefused(session, msg.type, 'sym-attest-v1')) return undefined;
        const att = fromWireAttestation(msg.attestation);
        if (!att) return this._attestMalformed(session, msg.type);
        return this._handleAttestation(peerId, peerName, { attestation: att });
      }

      case ATTEST_FRAME.checkpoint: {
        if (this._extensionRefused(session, msg.type, 'sym-attest-v1')) return undefined;
        const cp = fromWireCheckpoint(msg.checkpoint);
        if (!cp) return this._attestMalformed(session, msg.type);
        this._node._ingestCheckpoint(cp, peerId);
        return undefined;
      }

      case ATTEST_FRAME.witness: {
        if (this._extensionRefused(session, msg.type, 'sym-attest-v1')) return undefined;
        const w = fromWireWitness(msg.witness);
        if (!w) return this._attestMalformed(session, msg.type);
        this._node._ingestWitness(w, peerId);
        return undefined;
      }

      case ATTEST_FRAME.nodeStats: {
        if (this._extensionRefused(session, msg.type, 'sym-attest-v1')) return undefined;
        const stats = fromWireNodeStats(msg.stats);
        if (!stats) return this._attestMalformed(session, msg.type);
        this._node._ingestNodeStats(stats, peerId, peerName);
        return undefined;
      }

      case 'attestation':
      case 'checkpoint':
      case 'witness':
      case 'node-stats':
        // sym 0.13's bare-name frames (and their 0.13 signed constructions): legacy, never accepted
        // on a Core Secure session (sym-attest-v1 §9).
        if (typeof this._node._noteSessionRefusal === 'function') this._node._noteSessionRefusal(session, msg.type, 'legacy-attest-frame');
        return undefined;

      case 'cmb-fetch':
        return this._handleCmbFetch(peerId, peerName, msg, session);

      case 'cmb-fetch-result':
        return this._handleCmbFetchResult(peerId, peerName, msg, session);

      case 'role-grant':
      case 'role-revoke':
        // Signed by the grantor and verified against the chain's vouched keys (design D3), never
        // against the session that delivered it. One that arrives before its root makes the node ask
        // this session for the chain (role-chain-fetch).
        if (msg.grant) this._node._ingestRoleGrant(msg.grant, peerId, session);
        return undefined;

      case 'role-chain-fetch':
        // A peer asks for the grants that root a grantor this node may hold (design D3).
        return this._node._serveRoleChain(session, msg);

      case 'role-chain':
        // The answer to this node's role-chain-fetch: ordinary signed grants, verified top-down.
        return this._node._onRoleChain(session, msg);

      case 'xmesh-insight':
        if (this._extensionRefused(session, msg.type, 'xmesh-insight-v1')) return undefined;
        return this._handleXMeshInsight(peerId, peerName, msg);

      case 'message':
        // Retired in Core Secure (design D1): a message is a directed CMB, and the local 'message'
        // event is raised from it (see _handleMemoryShareInner).
        if (typeof this._node._noteSessionRefusal === 'function') this._node._noteSessionRefusal(session, 'message', 'retired: a message is a directed CMB');
        return undefined;

      default:
        // §7.3: an unknown type is ignored.
        return undefined;
    }
  }

  // ── Sub-handlers ──────────────────────────────────────────

  /**
   * Get the lifecycle role of the CMB's creator.
   * Checks: 1) peer role from handshake, 2) CMB createdBy matching a known peer.
   * @private
   */
  _getCreatorRole(peerId, msg) {
    // Anchored mode: authority is EARNED and resolved through the signed grant chain to the pinned
    // anchor — NEVER a self-declared role. Elevation requires a verified record, and goes to its
    // AUTHOR (the signed createdByNodeId) holding the key that verified it: authority follows the key
    // (design D3), so a record relayed by another node gets its author's earned role, and an
    // unverified one none.
    if (this._node._anchor) {
      if (msg._cmbVerified && msg._verifiedAuthorNodeId && typeof this._node.resolveRole === 'function') {
        return this._node.resolveRole(msg._verifiedAuthorNodeId, Date.now(), { key: msg._authorKey });
      }
      return 'participant';
    }
    // Unanchored (dev — no root of trust): there is no authority to resolve. A Core Secure session
    // carries no self-declared role, so every author is a participant.
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
    if (fusedEntry) this._markProvenance(fusedEntry, msg);
  }

  /**
   * What this node knows of an entry's provenance, on the entry: `verified` (the record passed §8.8.5
   * under a resolved author key on a Core Secure session) and `profile`. A Legacy Import record is
   * QUARANTINED (design D7): `verified: false`, `profile: 'legacy-import'`, whatever its signature —
   * never given authority, never shown as verified, flagged on the channel surface.
   * @private
   */
  _markProvenance(entry, msg) {
    if (msg && msg._legacyImport) { entry.verified = false; entry.profile = 'legacy-import'; return entry; }
    entry.verified = !!(msg && msg._cmbVerified === true);
    entry.profile = 'core-secure';
    return entry;
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
    const entry = this._markProvenance({
      ...msg,
      content: msg.content,
      source: msg.source || peerName,
      peerId,
      storedAt: now,
      directed: true,
      remixed: false,
      decision: decision || 'rejected',
    }, msg);
    this._node._log(`Directed CMB from ${peerName} (peer-bound, MMP §4.4.4) — SVAF ${decision || 'rejected'} for memory; surfacing to agent anyway (remixed:false)`);
    this._markCmbSurfaced(msg._incomingKey);
    this._node.emit('cmb-accepted', entry);
    return true;
  }

  /**
   * §8.8.5 for an inbound record, Core Secure (design D4, §18.3.1): returns true when the record must
   * be REFUSED, and on success sets msg._cmbVerified, msg._verifiedAuthorNodeId and msg._authorKey.
   *
   *   - the record must be a signed `mmp-sig-v2.0` record: an unsigned or legacy-suite record does
   *     not enter Core Secure (it may only arrive on a Legacy Import session, below);
   *   - the author key is resolved by `createdByNodeId` through the key registry (design D3) — never
   *     by `createdBy`, never from the delivering session: a record from an author this node has
   *     never proven and no grant vouches is unresolvable, and refused (release note M12: such "X via
   *     Y" deliveries no longer surface);
   *   - the signature, the application commitment and the assertion identity must verify;
   *   - the signed audience (room, recipient) must be this node's.
   *
   * Failure at any step is a refusal, never an "unverified success" (§8.8.5).
   *
   * A legacy-suite record is refused WITHOUT being counted as a forgery: it is ordinary pre-v2.0
   * history (a 0.13 node's whole store), not an attack, so it goes on its own metric
   * (`cmb-legacy-suite-refused`) and never on `cmb-signature-rejected` or a rejected-signature
   * decision (P-6: refusing a record is not accusing it).
   * @private
   */
  _rejectOnBadSignature(peerId, peerName, msg) {
    const cmb = msg.cmb;
    if (!cmb || typeof cmb !== 'object') { msg._cmbVerified = false; return true; }
    if (msg._legacyImport) return this._rejectLegacyImport(peerId, peerName, msg);
    const { verifyCMB, assertionIdV2_0 } = require('./core');
    const md = cmb.metadata;
    const k = recordKey(cmb);
    const refuse = (reason, error) => {
      msg._cmbVerified = false;
      this._node._log(`[sym-security] CMB ${String(k || '').slice(0, 16)} from ${peerName} refused — ${reason}${error ? ` (${String(error).slice(0, 120)})` : ''}`);
      this._node.emit('metric', { type: 'cmb-signature-rejected', from: peerName, key: k, reason, error: error || reason });
      if (typeof this._node._recordDecision === 'function') {
        // The recorded label is the ACTUAL verdict (content-mismatch, bad-signature, …), not a constant.
        this._node._recordDecision({ method: 'signature', source: peerName, cmbKey: k, decision: 'rejected-signature', totalDrift: null, categoryDrifts: null, gateValues: null, focusLabel: error || reason, remix: recordParents(cmb).length > 0 });
      }
      return true;
    };
    if (!md || typeof md !== 'object' || md.signatureSuite !== 'mmp-sig-v2.0') {
      msg._cmbVerified = false;
      this._node.emit('metric', { type: 'cmb-legacy-suite-refused', from: peerName, key: k, suite: md && typeof md.signatureSuite === 'string' ? md.signatureSuite.slice(0, 32) : null });
      this._sayLegacySuite(peerId, peerName);
      return true;
    }
    if (!md.sig) return refuse('unsigned');
    if (typeof md.createdByNodeId !== 'string' || !md.createdByNodeId) return refuse('no-author-node-id');
    const authorKey = this._node._identityKey(md.createdByNodeId);
    if (!authorKey) {
      this._node.emit('metric', { type: 'cmb-author-unresolvable', from: peerName, author: md.createdByNodeId, key: k });
      return refuse('unresolvable-author', `no proven, pinned or vouched key for ${String(md.createdByNodeId).slice(0, 8)}`);
    }
    const v = verifyCMB(cmb, authorKey);
    if (!v.valid) return refuse('invalid', v.error || 'invalid');
    // A record that declares the v2.0 suite but is malformed for it has no preimage: assertionIdV2_0
    // throws. That is a mismatch to refuse, never an exception.
    let derivedId = null;
    try { derivedId = assertionIdV2_0(cmb); } catch { /* not a well-formed v2.0 record */ }
    if (!derivedId || md.assertionId !== derivedId) return refuse('assertion-id-mismatch');
    msg._cmbVerified = true;
    msg._verifiedAuthorNodeId = md.createdByNodeId;
    msg._authorKey = authorKey;
    // A record verified under the author's binding: that binding protects history now, and never
    // expires (design D3 binding lifetime).
    if (this._node._roster && typeof this._node._roster.noteVerified === 'function') this._node._roster.noteVerified(md.createdByNodeId);
    // Verified is not addressed here: the audience the author signed is checked next (§8.8.5 step 7).
    return this._audienceRefused(peerId, peerName, cmb, true);
  }

  /**
   * Say, at most once a minute per peer, that pre-v2.0 records from it are refused (they are counted
   * on every refusal by the `cmb-legacy-suite-refused` metric).
   * @private
   */
  _sayLegacySuite(peerId, peerName) {
    const now = Date.now();
    const k = `legacy-suite|${peerId}`;
    const said = this._audienceSaid.get(k);
    if (said && now - said.at < 60000) { said.more++; return; }
    this._audienceSaid.delete(k);
    if (this._audienceSaid.size >= 1024) this._audienceSaid.delete(this._audienceSaid.keys().next().value);
    this._audienceSaid.set(k, { at: now, more: 0 });
    const more = said && said.more ? ` (and ${said.more} more since it was last said)` : '';
    this._node._log(`CMB from ${peerName} refused — a pre-v2.0 (legacy-suite) record does not enter Core Secure${more}`);
  }

  /**
   * A record on a Legacy Import session (design D7): accepted only when its signature — any suite
   * the internal verifier knows — verifies against the route's PINNED key, and only for records the
   * routed node itself authored. It is quarantined downstream (verified: false, profile
   * legacy-import): never given authority, never shown as verified.
   * @private
   */
  _rejectLegacyImport(peerId, peerName, msg) {
    const { verifyCMB } = require('./core');
    const cmb = msg.cmb;
    const pinned = msg._legacyPinnedKey;
    const k = recordKey(cmb);
    const v = pinned ? verifyCMB(cmb, pinned) : { valid: false, error: 'no-pinned-key' };
    if (!v.valid) {
      this._node._log(`[legacy-import] CMB ${String(k || '').slice(0, 16)} from ${peerName} refused — it does not verify against the route's pinned key (${v.error || 'invalid'})`);
      this._node.emit('metric', { type: 'legacy-import-refused', from: peerName, key: k, reason: v.error || 'invalid' });
      return true;
    }
    msg._cmbVerified = false;          // quarantined: never verified, whatever its signature
    if (cmb.metadata && Object.prototype.hasOwnProperty.call(cmb.metadata, 'assertionId') && cmb.metadata.signatureSuite !== 'mmp-sig-v2.0') delete cmb.metadata.assertionId;
    return this._audienceRefused(peerId, peerName, cmb, false);
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
   * Serve a cmb-fetch (MMP §7, §15.8) over Core Secure (design D1): every record found goes out as
   * its OWN `cmb` frame — sealed as `cmb-encrypted` like any record, as signed (recordAsSigned), never
   * plaintext (§18.2.1) — and then one `cmb-fetch-result` that carries only the correlation id and
   * the key lists:
   *
   *   { type: 'cmb-fetch-result', reqId, returned: [key…], missing: [key…], timestamp }
   *
   * sealed as a control frame (`control-encrypted`), field names per draft spec PR #26. Each key
   * requested appears in exactly one list, once; the records go first and the result last, on the
   * session's one sequence, so they arrive before the result that lists them. A request names one
   * `key` (the §7 schema) or up to MAX_FETCH_KEYS `keys`. Only a signed v2.0 record is served;
   * anything else (a key this node does not hold, one not well-formed) is `missing`.
   * @private
   */
  _handleCmbFetch(peerId, peerName, msg, session) {
    if (!msg || typeof msg.reqId !== 'string' || !msg.reqId || msg.reqId.length > 128) return;
    if (!session || typeof session.send !== 'function') return;
    const asked = Array.isArray(msg.keys) ? msg.keys.slice(0, MAX_FETCH_KEYS) : [msg.key];
    const returned = [];
    const missing = [];
    const seen = new Set();
    for (const key of asked) {
      // A key is text; anything else names nothing and is not listed.
      if (typeof key !== 'string' || !key || key.length > 256 || seen.has(key)) continue;
      seen.add(key);
      const cmb = key.length <= 128 ? this._node._store.get(key)?.cmb : null;
      const servable = !!(cmb && cmb.metadata && cmb.metadata.signatureSuite === 'mmp-sig-v2.0' && cmb.metadata.sig);
      if (servable && session.send({ type: 'cmb', cmb: recordAsSigned(cmb) }) !== false) returned.push(key);
      else missing.push(key);
    }
    if (returned.length + missing.length === 0) return;
    session.send({ type: 'cmb-fetch-result', reqId: msg.reqId, returned, missing, timestamp: Date.now() });
    if (returned.length) this._node._log(`[cmb-fetch] served ${returned.length} record(s) (${returned[0].slice(0, 16)}…) to ${peerName}`);
  }

  /**
   * The answer a peer sent this node's cmb-fetch: the correlation id and the key lists, after the
   * records themselves (see _handleCmbFetch). A record that verified has already resolved the
   * request; a request still open here got no verifying record from this peer — listed `missing`,
   * listed `returned` but discarded on its content address, or never sent — so this peer counts as a
   * miss. Only a peer the request was sent to can close it (fetchCMB).
   * @private
   */
  _handleCmbFetchResult(peerId, peerName, msg, session) {
    const reqId = msg && typeof msg.reqId === 'string' ? msg.reqId : null;
    if (!reqId) return;
    if (session && session._fetchExpect) {
      for (const [k, r] of [...session._fetchExpect]) if (r === reqId) session._fetchExpect.delete(k);
    }
    const pending = this._node._cmbFetchPending?.get(reqId);
    if (!pending) return;
    pending.miss(peerId);
  }

  /**
   * Note on `session` that a record with `key` answers this node's fetch `reqId`: it is routed to
   * the fetch (a self-verifying content-address check) rather than admitted (see _handleMemoryShare).
   * At most 64 are kept per session.
   */
  expectFetched(session, key, reqId) {
    if (!session || typeof session !== 'object' || typeof key !== 'string') return;
    if (!session._fetchExpect) session._fetchExpect = new Map();
    if (session._fetchExpect.size >= 64) session._fetchExpect.delete(session._fetchExpect.keys().next().value);
    session._fetchExpect.set(key, reqId);
  }

  /**
   * A record that answers this node's cmb-fetch on `session`. §15.8 is SELF-VERIFYING: the requester
   * recomputes the content address, so serving extends no trust and requires none. classifyAddress
   * derives by the record's structural role and separates "could not check" from "does not match".
   * @private
   */
  _resolveFetched(peerId, peerName, msg, reqId) {
    const pending = this._node._cmbFetchPending?.get(reqId);
    if (!pending) return;
    const cmb = msg.cmb;
    const served = cmb?.metadata?.key ?? cmb?.key;
    if (!cmb || served !== pending.key) { pending.miss(peerId); return; }
    const verdict = classifyAddress(cmb);
    if (verdict.state !== 'verified') {
      const why = verdict.state === 'mismatch' ? 'MISMATCH' : `UNVERIFIABLE (${verdict.reason})`;
      this._node._log(`[cmb-fetch] content-address ${why} from ${peerName} for ${String(pending.key).slice(0, 16)}… — discarded`);
      this._node.emit('metric', { type: 'cmb-fetch-forged', from: peerName, key: pending.key, verdict: verdict.state, scheme: verdict.scheme ?? null });
      pending.miss(peerId);
      return;
    }
    pending.resolve({ cmb, from: peerName, peerId });
  }

  _handleMemoryShare(peerId, peerName, msg, session) {
    // A record answering this node's cmb-fetch on this session is the fetch's, not an admission.
    const fk = msg && msg.cmb ? recordKey(msg.cmb) : null;
    if (session && session._fetchExpect && fk && session._fetchExpect.has(fk)) {
      const reqId = session._fetchExpect.get(fk);
      session._fetchExpect.delete(fk);
      return this._resolveFetched(peerId, peerName, msg, reqId);
    }
    if (session && session._anchorKeys && fk && session._anchorKeys.has(fk)) {
      session._anchorKeys.delete(fk);
      msg._anchor = true;
    }
    // The session rides beside the frame, never on it: entries are built from the frame and kept.
    if (session) this._sessionOf.set(msg, session);
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

    // §8.8.5 verification (design D4): a signed v2.0 record whose author key resolves by
    // createdByNodeId, signature, application, assertion identity and audience all valid — or it is
    // refused. On a Legacy Import session: verified against the route's pinned key, then quarantined.
    if (this._rejectOnBadSignature(peerId, peerName, msg)) return;

    // THE HOST HOOK (design D1, review H9): a record that passed every check, with the proven facts
    // of the session that delivered it. Hosts read this instead of reaching into the frame handler.
    const session = this._sessionOf.get(msg);
    if (msg._cmbVerified === true && !msg._legacyImport && this._node.listenerCount('verified-record') > 0) {
      const md = msg.cmb.metadata;
      const verification = Object.freeze({
        suite: md.signatureSuite,
        assertionId: md.assertionId,
        authorNodeId: md.createdByNodeId,
        authorName: md.createdBy,
        authorKey: msg._authorKey,
        authorKeySource: this._node._roster ? (this._node._roster.source(md.createdByNodeId) || 'session') : null,
        audience: typeof md.to === 'string' && md.to ? 'directed' : 'room',
        room: md.room,
        to: md.to ?? null,
        relayed: md.createdByNodeId !== peerId,
        anchor: msg._anchor === true,
      });
      // The record is the host's own frozen copy: a listener can neither change what this node stores
      // and evaluates next, nor what the next listener sees.
      const event = Object.freeze({ record: deepFreeze(structuredClone(msg.cmb)), session: this._node._sessionFacts(session), verification });
      if (typeof this._node._emitIsolated === 'function') {
        const why = (e) => { try { return (e && e.message) || String(e); } catch { return 'unprintable error'; } };
        this._node._emitIsolated('verified-record', event, String(recordKey(msg.cmb)).slice(0, 16), why, (m) => { try { this._node._log(m); } catch { /* */ } });
      } else {
        this._node.emit('verified-record', event);
      }
    }

    // Who wrote it, and who handed it to us. `name` is the author's record label (MMP §8.8.4:
    // a display label, not an identity). Every surfaced and stored entry carries this, so no
    // layer has to read the store envelope's "<receiver>+<sender>".
    // `nodeId` is the cryptographic author (§8.8.4) and is filled only when that is established
    // here: the record verified under the delivering peer's key AND names that peer as its author.
    // A relayed or unverified record keeps `nodeId: null` — the label is shown, identity is not
    // claimed. `msg.source` is an unsigned frame field and never names the author.
    msg.author = {
      name: recordCreatedBy(msg.cmb) || peerName,
      // The cryptographic author (§8.8.4): the signed createdByNodeId the signature verified against,
      // even when relayed. A quarantined Legacy Import record names no verified author.
      nodeId: msg._cmbVerified === true ? (msg._verifiedAuthorNodeId || null) : null,
      via: { name: peerName, nodeId: peerId },
    };

    // MMP §9.2.2 binding (design D4): taken from the authenticated `metadata.to` — signed (§8.8.4)
    // and AAD-bound to the sealed frame — never from a relay envelope or a frame flag, which no
    // longer distinguish anything: a sealed broadcast is one frame per session, each addressed to
    // its recipient. `to` absent or null is room-bound and SVAF-gated. Only a Legacy Import record
    // (0.13 wire, design D7) is judged by its frame's flags, and it is quarantined.
    const meta = msg.cmb?.metadata;
    const signedTo = meta && typeof meta.to === 'string' && meta.to ? meta.to : null;
    const verified = msg._cmbVerified === true;
    if (msg._legacyImport) {
      const frameDirected = msg.directed === true && !!msg.to && msg.to === this._node.nodeId;
      msg._directedToMe = signedTo ? signedTo === this._node.nodeId : frameDirected;
    } else {
      msg._directedToMe = verified && signedTo === this._node.nodeId;
    }
    const authenticatedDirected = msg._directedToMe && verified && signedTo === this._node.nodeId;
    // What every entry built from this frame says about its addressing is the binding just decided,
    // never what a frame carried: `directed` / `to` on a stored or surfaced entry (an admitted
    // directed record surfaces through the store's own cmb-accepted) are the signed metadata.to.
    msg.directed = msg._directedToMe === true;
    if (msg.directed) msg.to = this._node.nodeId; else delete msg.to;

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

    const app = meta && meta.application;
    // A payload (remember({ payload })) rides as the record's signed application section; it is given
    // back beside the record as `cmb.payload`, as earlier releases carried it.
    if (verified && app && app.schema === PAYLOAD_SCHEMA && app.mediaType === 'application/json' && typeof app.data === 'string') {
      try { msg.cmb.payload = JSON.parse(Buffer.from(app.data, 'base64url').toString('utf8')); } catch { /* not JSON: left in the section */ }
    }

    // A MESSAGE (design D1): Core Secure retires the `message` frame; a message is a directed record
    // whose signed application section is the sym message schema. It raises the local 'message'
    // event (§14.9.1) exactly once (the de-duplication above covers replays) and is not admitted to
    // memory, as a message frame never was.
    if (msg._directedToMe && verified && app && app.schema === MESSAGE_SCHEMA && app.mediaType === 'text/plain' && typeof app.data === 'string') {
      const text = Buffer.from(app.data, 'base64url').toString('utf8');
      this._markCmbSurfaced(msg._incomingKey);
      this._node._log(`Message from ${msg.author.name}: ${text.slice(0, 60)}`);
      this._node.emit('message', msg.author.name, text, Object.freeze({ from: msg.author.nodeId, fromName: msg.author.name, content: text, timestamp: meta.createdTimestamp, key: cognitionKey, assertionId: meta.assertionId, via: peerId }));
      return undefined;
    }

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
    // frame is finished with (the in-flight de-dup mark is released then). Only the evaluator's own
    // failure falls back to the heuristic gate. Once the neural gate has decided, recorded and attested,
    // a later failure is contained in that path: running the heuristic gate as well signed and gossiped
    // a second attestation for one frame.
    return Promise.resolve()
      .then(() => this._node._svafEvaluator.evaluate(
        { text: msg.content, source: msg.source || peerName, tags: msg.tags || [], confidence: msg.confidence || 0.8 },
        anchorTexts,
        ageSeconds,
      ))
      .then(
        (neuralResult) => (neuralResult
          ? this._runNeuralSVAFContained(neuralResult, msg, peerName, peerId, originTs, now)
          : this._runHeuristicSVAFContained(msg, peerName, peerId, originTs, now, ageSeconds)),
        (err) => {
          try { this._node._log(`SVAF neural error: ${err && err.message} — falling back to heuristic`); } catch { /* never rethrow */ }
          return this._runHeuristicSVAFContained(msg, peerName, peerId, originTs, now, ageSeconds);
        },
      );
  }

  /**
   * Run the neural path with its own failure contained: by then the frame has been decided (and
   * attested), so a failure is logged and the frame is not gated again.
   * @private
   */
  _runNeuralSVAFContained(result, msg, peerName, peerId, originTs, now) {
    return Promise.resolve()
      .then(() => this._processNeuralSVAF(result, msg, peerName, peerId, originTs, now))
      .catch((err) => {
        // The asynchronous half of the frame's dispatch: refused and counted by the node's guard
        // (_refuseFrame, which cannot throw), not left to the global unhandled-rejection handler.
        const why = err && typeof err.message === 'string' ? err.message : 'an error';
        const said = new Error(`failed after its decision: ${why} — not gated again`);
        if (typeof this._node._refuseFrame === 'function') this._node._refuseFrame(peerId, peerName, msg, 'svaf', said);
        else try { this._node._log(`SVAF neural: a frame ${said.message}`); } catch { /* never rethrow */ }
      });
  }

  /**
   * Run heuristic SVAF with its rejection contained. A malformed or
   * unexpected frame must never be able to kill the host process — the
   * async path's failure is the asynchronous half of the frame's dispatch, so
   * it is refused and counted by the same guard as a synchronous one
   * (node._refuseFrame, which cannot itself throw), not left to the global
   * unhandled-rejection handler. (In 0.13.16 this catch built a log line from
   * the peer's name, and a name that could not be printed made the catch throw.)
   * @private
   */
  _runHeuristicSVAFContained(msg, peerName, peerId, originTs, now, ageSeconds) {
    return Promise.resolve()
      .then(() => this._processHeuristicSVAF(msg, peerName, peerId, originTs, now, ageSeconds))
      .catch((err) => {
        if (typeof this._node._refuseFrame === 'function') this._node._refuseFrame(peerId, peerName, msg, 'svaf', err);
        else try { this._node._log(`SVAF heuristic error: ${err && err.message} — frame dropped`); } catch { /* never rethrow */ }
      });
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
        this._node._buildAdmissionAttestation(rejKey, 'rejected', rejVerdicts, 'neural', msg.cmb?.metadata?.assertionId);
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
      // `of` is the record's cognition key (never the directed mark this node dedups by).
      const att = this._node._buildAdmissionAttestation(recordKey(msg.cmb) || incomingKey, decision, categoryVerdicts, 'neural', msg.cmb?.metadata?.assertionId);
      // On the entry, beside the record: a two-section record has exactly two members (§8.8.1).
      if (att) fusedEntry.admission = att;
    }
    // Opaque payload rides alongside CAT7 — carry it onto the admitted remix.
    this._preserveIncomingPayload(fusedEntry, msg);
    let severLineage = false;
    if (fusedEntry.cmb) {
      // The copy carries no attestation the sender attached: that one was an input, checked in
      // _prepareLineageTether. The record this node stores carries its own evaluation or none.
      // A tether that cannot be evaluated (the encoder failed) leaves the record unverified: stored,
      // as it was admitted, with no tether verdict.
      let tether = null;
      try {
        tether = await tetherOfRecord(fusedEntry.cmb.categories, tetherAnchor, this._admissionPolicy());
      } catch (err) {
        this._node._log(`§15.8 tether of a record from ${peerName} not evaluated: ${err.message} — stored unverified`);
      }
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

    // Feed to XMesh (Layer 6). See MMP v0.2.0 Section 12.
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
      if (rejKey) this._node._buildAdmissionAttestation(rejKey, result.decision, result.categoryVerdicts, 'heuristic', msg.cmb?.metadata?.assertionId);

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
      const att = this._node._buildAdmissionAttestation(of, result.decision, result.categoryVerdicts, 'heuristic', msg.cmb?.metadata?.assertionId);
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

    // Feed to XMesh (Layer 6). See MMP v0.2.0 Section 12.
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

    // Feed mood to XMesh — affect influences cognitive state even from rejected peers
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
   * Handle mood frame: evaluate the mood's drift from this node's state and accept/reject.
   *
   * The drift is MEASURED here, directly: ((1 − cos h1) + (1 − cos h2)) / 2 between this
   * node's local state and the mood's encoding — the measure the drift-bounded couplers
   * use. Until 0.13.17 it was read off the coupling engine by registering the mood as a
   * temporary PEER in the coupling set and running a coupling step. That assumed the engine's
   * decisions carry a `drift` (the stock coupler's do not) and that the step cannot throw (it
   * did, in the metrics logger, on every mood frame); and when it threw, the phantom peer was
   * never removed, so for its two-minute lifetime every coupling step threw with it —
   * remember() included. A measurement does not belong in shared state: nothing here touches
   * the coupling set. A mood that is not text is not a mood.
   * @private
   */
  _handleMood(peerId, peerName, msg) {
    if (typeof msg.mood !== 'string' || !msg.mood) return;

    const { h1: moodH1, h2: moodH2 } = encode(msg.mood);
    const mesh = this._node._meshNode;
    const drift = ((1 - cosineSimilarity(mesh.localH1, moodH1)) + (1 - cosineSimilarity(mesh.localH2, moodH2))) / 2;

    const from = wireName(msg.fromName, peerName);

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
    // A Core Secure session proved peerId's key, and the frame arrived sealed on it: the channel is
    // the peer's own (design D1).
    const r = wm.learnWakeChannel(peerId, { platform: msg.platform, token: msg.token, environment: msg.environment }, { source: 'direct' });
    if (r === 'added' || r === 'updated' || r === 'refreshed' || r === 'removed') wm.saveWakeChannels();
    if (r === 'added' || r === 'updated') this._node._log(`Wake channel from ${peerName}: ${msg.platform}`);
    if (r === 'removed') this._node._log(`Wake channel from ${peerName}: turned off`);
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
    // said once a minute per connection and reason, with how many more there were, not once per frame.
    // Per connection, not per peer id: over the relay the id is the sender's to choose, and a fresh one
    // per frame bought a line per frame.
    this._sayOnceAMinute(this._attDropSaid, `${peerId}|${r.reason}`,
      (more) => `Attestation from ${peerName} dropped (${r.reason}) — of:${String(att.of).slice(0, 12)} by:${String(att.by).slice(0, 8)}${more}`);
  }

  /**
   * Say a line at most once a minute per key, with how many more there were since it was last said.
   * `said` holds at most 1,024 keys, the least recently said let go first. O(1).
   * @param {Map} said
   * @param {string} key
   * @param {(more: string) => string} line
   * @private
   */
  _sayOnceAMinute(said, key, line) {
    const now = Date.now();
    const last = said.get(key);
    if (last && now - last.at < 60_000) { last.more++; return; }
    said.delete(key);
    if (said.size >= 1024) said.delete(said.keys().next().value);
    said.set(key, { at: now, more: 0 });
    this._node._log(line(last && last.more ? ` (and ${last.more} more since it was last said)` : ''));
  }

  /**
   * Handle peer-info gossip: learn wake channels from peers of peers.
   * @private
   */
  _handlePeerInfo(peerId, peerName, msg) {
    if (!Array.isArray(msg.peers)) return;
    // Learned only for the session's OWN nodeId (design D1): an entry naming another node is what
    // this peer says about someone else — a hint, never stored. Every peer re-sends its list on
    // every connect, so most entries change nothing and say nothing.
    const wm = this._node._wakeManager;
    if (msg.peers.length > PEER_INFO_MAX) {
      // An over-long frame is read for its first PEER_INFO_MAX entries, and said once a minute per peer.
      const now = Date.now();
      if (now - (this._longPeerInfoSaid.get(peerId) ?? -Infinity) >= 60_000) {
        this._longPeerInfoSaid.delete(peerId);
        if (this._longPeerInfoSaid.size >= 1024) this._longPeerInfoSaid.delete(this._longPeerInfoSaid.keys().next().value);
        this._longPeerInfoSaid.set(peerId, now);
        this._node._log(`Gossip from ${peerName}: ${msg.peers.length} entries, reading the first ${PEER_INFO_MAX}`);
      }
    }
    let changed = 0;
    for (const p of msg.peers.slice(0, PEER_INFO_MAX)) {
      const id = p && typeof p === 'object' ? wireNodeId(p.nodeId) : null;
      if (id !== peerId || !p.wakeChannel) continue;
      const r = wm.learnWakeChannel(id, p.wakeChannel, { source: 'direct' });
      if (r === 'added' || r === 'updated' || r === 'refreshed' || r === 'removed') changed++;
      if (r === 'added' || r === 'updated') this._node._log(`Wake channel from ${peerName}: ${p.wakeChannel.platform}`);
    }
    if (changed > 0) wm.saveWakeChannels();
  }

  /**
   * Handle direct message from a peer.
   * @private
   */
  _handleMessage(peerId, peerName, msg) {
    // The frame's own name for its sender is taken as text, as the transport's was (wire-identity.js).
    const from = wireName(msg.fromName, peerName);
    this._node._log(`Message from ${from}: ${(msg.content || '').slice(0, 60)}`);
    this._node.emit('message', from, msg.content, msg);
  }

  /**
   * Handle XMesh insight from a peer agent.
   * See MMP v0.2.0 Section 12: XMesh (Layer 6).
   * See MMP v0.2.0 Section 14: Remix.
   * @private
   */
  _handleXMeshInsight(peerId, peerName, msg) {
    const insight = {
      from: wireName(msg.fromName, peerName),
      trajectory: msg.trajectory,
      patterns: msg.patterns,
      anomaly: msg.anomaly,
      remixScore: msg.remixScore,
      coherence: msg.coherence,
      timestamp: msg.timestamp,
    };
    this._node._log(`XMesh insight from ${insight.from}: anomaly=${insight.anomaly?.toFixed(3)}, remix=${insight.remixScore?.toFixed(3)}, coherence=${insight.coherence?.toFixed(3)}`);

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
        // A record this node cannot sign is its key's failure, said by remember() already; naming the
        // delegate would send the operator to the wrong place.
        if (err && err.code === 'ESIGN') this._node._log('Synthesis not shared: this node cannot sign its records');
        else this._node._log(`Synthesis delegate error: ${err && err.message}`);
      }
    }
  }
}

module.exports = { FrameHandler, assertionMark, MESSAGE_SCHEMA };
