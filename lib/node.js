'use strict';

const { recordKey, recordCreatedBy, recordParents } = require('./record');

/**
 * SymNode — sovereign mesh node with cognitive coupling.
 *
 * Each node encodes its memories into a hidden state vector.
 * When peers connect, the coupling engine evaluates drift between
 * their cognitive states and autonomously decides whether to couple.
 *
 * Aligned peers share memories. Divergent peers stay independent.
 * The intelligence is in the decision to share, not in the sharing itself.
 *
 * See MMP v0.2.0 Section 3 (Identity), Section 4 (Transport),
 * Section 5 (Connection), Section 6 (Memory), Section 9 (Coupling & SVAF).
 *
 * Copyright (c) 2026 SYM.BOT. Apache 2.0 License.
 */

const fs = require('fs');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const { EventEmitter } = require('events');
const { MeshNode } = require('./core');
const { nodeDirById, loadIdentity, acquireIdentityLock, log: logMsg } = require('./config');
const { assertTestSandbox } = require('./core/state-root');
const { MemoryStore } = require('./memory-store');
const { AttestationStore, chainHash, isPosition, isCanonicalSig } = require('./attestation-store');
const { RoleGrantStore } = require('./role-grant-store');
const { RosterKeyRegistry } = require('./roster-keys');
const { wireNodeId, wireName, wireKey } = require('./wire-identity');
const { keepPeerState } = require('./peer-state');
const { RoomOwnershipRegistry } = require('./room-ownership');
const { verifyRoomGrant } = require('./core/room-grant');
const { DecisionLog } = require('./decision-log');
const {
  encode, DIM, createCMB, renderContent, FIELD_WEIGHT_PROFILES,
  WakeManager,
  signCMB, assertionIdV2_0, mintRemixKey, signAttestation, verifyAttestation, verifyAttestationRole,
  merkleRoot, signCheckpoint, verifyCheckpoint, signWitness, verifyWitness,
  signGrant, roleRank, CAT7_CATEGORIES, assertRecordSendable,
} = require('./core');
const { MMP_EMIT_V2 } = require('./emit-policy'); // the single reader-first flip switch
/** How far this node's record timestamps may run ahead of its clock before they follow it again. */
const MAX_CLOCK_LEAD_MS = 60 * 1000;
const { FrameHandler, MESSAGE_SCHEMA } = require('./frame-handler');
const { TcpTransport } = require('./transport');
const { PeerSession } = require('./session');
const { LegacyImport } = require('./legacy-import');
const { EXT_CMB_ENCRYPTED_V2 } = require('./core/mmp-extensions');
const ENGINE_VERSION = require('../package.json').version;
/**
 * Extensions this node offers in every hello (§16). An extension is active on a session only when
 * both offered it and it was selected (§16.3), and its frames are sent only on such sessions:
 *   cmb-encrypted-v2  — records travel sealed; required: a session without it is not Core Secure.
 *   sym-attest-v1     — admission attestations, checkpoints, witnesses, node-stats (design D1;
 *                       unregistered, so the registry entry is drafted for §16.4).
 *   xmesh-insight-v1  — the Layer-6 insight frame.
 */
const EXT_ATTEST = 'sym-attest-v1';
const EXT_XMESH_INSIGHT = 'xmesh-insight-v1';
const OFFERED_EXTENSIONS = Object.freeze([EXT_CMB_ENCRYPTED_V2, EXT_ATTEST, EXT_XMESH_INSIGHT]);
/** Frames that ride only on sessions that selected sym-attest-v1. */
const ATTEST_FRAMES = new Set(['attestation', 'checkpoint', 'witness', 'node-stats']);
/** Legacy hellos refused on the Core Secure listener are said at most once a minute per address. */
const LEGACY_REFUSAL_REPORT_MS = 60_000;
const { SEND_FAILURE, MAX_FRAME_SIZE } = require('./frame-parser');
const { RelayConnection } = require('./relay');
const { BonjourDiscovery, NullDiscovery } = require('./discovery');

/** Parse the earned-authority anchor from an object or a "nodeId:publicKey" string. */
function parseAnchor(a) {
  if (!a) return null;
  if (typeof a === 'object' && a.nodeId && a.publicKey) return { nodeId: a.nodeId, publicKey: a.publicKey };
  if (typeof a === 'string') {
    const i = a.indexOf(':');
    if (i > 0) return { nodeId: a.slice(0, i), publicKey: a.slice(i + 1) };
  }
  return null;
}

/**
 * Reduce a weighted verdict tally `{verdict -> weight}` to its dominant verdict and the
 * dominant's share of total weight (confidence in [0,1]). Ties break by descending weight
 * then lexical verdict, so the result is deterministic across nodes aggregating the same
 * attestations. Returns the raw tally too for consumers that want the full distribution.
 */
function summarizeTally(tally, totalWeight) {
  const entries = Object.entries(tally).sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1));
  const [dominant, domWeight] = entries[0] || [null, 0];
  return {
    dominant,
    confidence: totalWeight > 0 ? domWeight / totalWeight : 0,
    tally: { ...tally },
  };
}

/**
 * One lane's budget of NEW gossiped statements (attestations, checkpoints, witnesses, role grants): a
 * burst, then a rate a second, spent before the signature is checked, so no lane can buy more
 * signature checks than this (lanes and the ceiling over all of them: see GOSSIP_NEW_LANE). A repeat,
 * a malformed frame, one for a signer whose key is not held, a stale checkpoint or a further root for a
 * position already in conflict is dropped before it, for nothing.
 *
 * Sizing. A room of R nodes, each gating G CMBs a second, makes R·G attestations, R·G/8 checkpoints
 * (one per 8 attestations) and R·G/8·(R−1) witnesses a second. A busy room, R = 32 and G = 4, makes
 * 128 + 16 + 496 = 640 new statements a second in all. Relaying repeats every one to every node, but
 * only the first copy of a statement is new, so a peer spends this node's budget only for what it
 * delivers first: about what it signs itself, G·(1 + R/8) = 20 a second, and at most all 640 when it
 * is this node's only path to the room. 2,000 a second is 3× that worst case and 100× the usual; a
 * flood buys at most 2,000 checks a second per lane (one costs ~40 µs: under a tenth of a core).
 */
const GOSSIP_PER_SECOND = 2000;
const GOSSIP_BURST = 10000;
/**
 * The budget is kept per PROVEN peer (sym 0.14, design D1): the nodeId a Core Secure session proved.
 * Until 0.14 it was kept per connection lane, because the id a sender declared was free to claim;
 * a proven id costs a completed handshake, and the per-connection lanes — an identity workaround —
 * are gone. A peer seen for the first time starts with GOSSIP_NEW_LANE tokens and earns the rest at
 * the rate, so minting identities buys a hundred checks each, not a burst each. And every peer draws
 * on one ceiling as well, GOSSIP_GLOBAL_PER_SECOND after a burst of GOSSIP_GLOBAL_BURST, so many ids
 * together buy no more than that: 4,000 a second is six times the busy room's 640 new statements a
 * second in all. Under a flood from many ids at once the ceiling can drop honest frames too (a copy
 * may still come by another peer later); what it cannot do is spend more than the ceiling's checks.
 */
const GOSSIP_NEW_LANE = 100;
/** A signature longer than this is not one (an Ed25519 signature is 86 characters of base64url): it is
 *  refused as malformed before anything decodes or hashes it. */
const SIG_MAX_CHARS = 128;
const sigOk = (sig) => typeof sig === 'string' && sig.length > 0 && sig.length <= SIG_MAX_CHARS;
const GOSSIP_GLOBAL_PER_SECOND = 4000;
const GOSSIP_GLOBAL_BURST = 20000;
/**
 * One attester's new checkpoints this node takes (stores, witnesses and relays): a burst, then a rate a
 * second, spent after the signature is checked (so only the attester itself spends it) and whichever
 * peer brings them. Each checkpoint taken costs every node in the room a witness signed, gossiped and
 * verified (R−1 of them), so this bounds what one attester's checkpoint flood makes the room sign: at
 * most 4 witnesses a second per node, where the per-lane budget alone allowed 2,000.
 *
 * Sizing. An attester commits a checkpoint every 8 attestations, so one gating G CMBs a second makes
 * G/8 a second: 0.5 in the busy room above. 4 a second is 8× that (an attester gating 32 CMBs a second
 * without pause), and the burst of 128 holds 1,024 attestations gated back to back. A conflicting copy
 * for a position already held does not spend it: it is recorded once and never witnessed or relayed.
 */
const CHECKPOINTS_PER_SECOND = 4;
const CHECKPOINT_BURST = 128;
/** A peer's dropped statements are said at most once per this many ms (one log line, one metric). */
const GOSSIP_REPORT_MS = 10000;
/** Peers with a budget held at once; the least recently active goes first, in O(1). */
const GOSSIP_MAX_PEERS = 4096;
/** role-chain-fetch (design D3): records held per session while their chain is fetched, and for how long. */
const CHAIN_HOLD_MAX = 64;
const CHAIN_FETCH_TIMEOUT_MS = 10_000;
/** Grantees one fetch may name, and grants one answer carries, at most. */
const CHAIN_FETCH_MAX_GRANTEES = 16;
const CHAIN_ANSWER_MAX = 64;
/** Answers served per session: a token bucket. */
const CHAIN_SERVE_PER_SECOND = 4;
const CHAIN_SERVE_BURST = 16;
/**
 * The relay `error` code for "this node holds no session with you" (sym's; drafted for MMP spec PR
 * meshcognition-website#23, where an error only prompts a new handshake). 4400 is a session closing.
 */
const UNKNOWN_SESSION_CODE = 4404;
/** Relay handshakes in flight at once, at most (each holds a 10 s deadline and costs a key agreement). */
const RELAY_HANDSHAKES_MAX = 256;

/**
 * Take a token from `key`'s bucket in `buckets`: a Map ordered least recently used first and held to
 * `max` by evicting its head (O(1), no scan), each bucket refilled at `rate` a second up to `burst`.
 * A clock stepped back refills nothing and stalls nothing. @returns {boolean} whether a token was taken
 */
function takeToken(buckets, key, rate, burst, now, max) {
  const b = bucketOf(buckets, key, rate, burst, burst, now, max);
  if (b.tokens >= 1) { b.tokens -= 1; return true; }
  return false;
}

/** `key`'s bucket, refilled to `now`; a new one starts with `initial` tokens. Most recently used last. */
function bucketOf(buckets, key, rate, burst, initial, now, max) {
  let b = buckets.get(key);
  if (b) buckets.delete(key);
  else {
    b = { tokens: Math.min(initial, burst), at: now };
    if (buckets.size >= max) buckets.delete(buckets.keys().next().value);
  }
  buckets.set(key, b);
  return refill(b, rate, burst, now);
}

/** Refill a bucket to `now`. A clock stepped back refills nothing and stalls nothing. */
function refill(b, rate, burst, now) {
  const elapsed = now - b.at;
  if (elapsed > 0) b.tokens = Math.min(burst, b.tokens + (elapsed * rate) / 1000);
  b.at = now;
  return b;
}

/** Why a CMB was not handed to a peer, beyond the transport's own SEND_FAILURE reasons. */
const NOT_SENT = Object.freeze({
  SEND_FAILED: 'send-failed',           // a transport that says only whether, not why
  UNSEALABLE: 'unsealable',             // not a signed v2.0 record: nothing else travels in Core Secure
  QUEUE_FULL: 'queue-full',             // the relay pacer's queue is full
});

/** How each reason reads in the log. */
const NOT_SENT_SAID = Object.freeze({
  [SEND_FAILURE.TOO_LARGE]: 'frame too large',
  [SEND_FAILURE.NOT_CONNECTED]: 'not connected',
  [SEND_FAILURE.WRITE_FAILED]: 'write failed',
  [NOT_SENT.SEND_FAILED]: 'send failed',
  [NOT_SENT.UNSEALABLE]: 'not a signed v2.0 record (only those travel in Core Secure)',
  [NOT_SENT.QUEUE_FULL]: 'the relay send queue is full',
});

/**
 * Hand `frame` to a peer's transport and say why it was not taken: { ok, reason, bytes }. A transport
 * without trySend (an embedder's, or a test's) reports only whether, as NOT_SENT.SEND_FAILED.
 */
function trySend(transport, frame) {
  if (transport && typeof transport.trySend === 'function') return transport.trySend(frame);
  return transport && transport.send(frame) !== false ? { ok: true } : { ok: false, reason: NOT_SENT.SEND_FAILED };
}

/** The schema of the signed application section remember({ payload }) carries (§8.8.3). */
const PAYLOAD_SCHEMA = 'https://sym.bot/schema/payload-v1.json';

/** A remember() payload as a signed application section: its JSON bytes. */
function payloadApplication(payload) {
  const bytes = Buffer.from(JSON.stringify(payload), 'utf8');
  if (bytes.length > 524288) {
    const e = new Error(`payload is ${bytes.length} bytes; an application section carries at most 524288 (§8.8.3)`);
    e.code = 'ECMBSIZE';
    throw e;
  }
  return {
    mediaType: 'application/json',
    schema: PAYLOAD_SCHEMA,
    encoding: 'base64url',
    byteLength: bytes.length,
    digest: `sha256-${crypto.createHash('sha256').update(bytes).digest('hex')}`,
    data: bytes.toString('base64url'),
  };
}

class SymNode extends EventEmitter {

  /**
   * Create a new SymNode.
   *
   * @param {object} opts
   * @param {string} opts.name — required node name (See MMP v0.2.0 Section 3)
   * @param {string} [opts.cognitiveProfile] — free-text cognitive profile for encoding
   * @param {number} [opts.moodThreshold=0.8] — threshold for mood acceptance
   * @param {number} [opts.svafStableThreshold=0.25] — SVAF stable coupling threshold
   * @param {number} [opts.svafGuardedThreshold=0.5] — SVAF guarded coupling threshold
   * @param {number} [opts.svafTemporalLambda=0.3] — SVAF temporal decay lambda
   * @param {number} [opts.svafFreshnessSeconds=1800] — SVAF freshness window
   * @param {object} [opts.svafFieldWeights] — per-category weight profile (See MMP v0.2.0 Section 9)
   * @param {number} [opts.retentionSeconds=86400] — uniform CMB retention period (single-value knob, applies to both self-authored and peer-received entries)
   * @param {number} [opts.localRetentionSeconds] — origin-aware retention for self-authored CMBs (peerId == null). Falls back to `retentionSeconds` when omitted.
   * @param {number} [opts.peerRetentionSeconds] — origin-aware retention for peer-received CMBs. Falls back to `retentionSeconds` when omitted. Apps that value depth on their own lineage chains but tolerate faster forgetting of peer chatter set local > peer.
   * @param {object} [opts.wakeChannel] — wake channel configuration
   * @param {string} [opts.relay] — WebSocket relay URL (See MMP v0.2.0 Section 4)
   * @param {string} [opts.relayToken] — relay authentication token
   * @param {boolean} [opts.relayOnly=false] — skip LAN discovery, relay only
   * @param {boolean} [opts.silent=false] — suppress log output
   * @param {function} [opts.onSynthesis] — synthesis delegate for XMesh insights
   * @param {number} [opts.heartbeatInterval=5000] — heartbeat check interval in ms
   * @param {number} [opts.heartbeatTimeout=15000] — heartbeat timeout in ms
   * @param {number} [opts.encodeInterval=30000] — re-encode and broadcast interval in ms
   */
  constructor(opts = {}) {
    super();
    // Before anything is read or written: under the test runner, a node whose state root is the
    // real home is refused (ETESTHOME) rather than allowed to mint identities into ~/.sym.
    assertTestSandbox();
    if (!opts.name) throw new Error('SymNode requires a name');
    this._silent = opts.silent || false;

    // The agent id is CONFIGURED, never derived. Name-suffixing is gone: it used to
    // resolve a same-host collision to `<name>-2`, which quietly minted a SECOND
    // IDENTITY for what is one agent. Two live processes of one agent are the same
    // agent, so they contend for one identity and the single-writer lease decides —
    // acquireIdentityLock refuses the second rather than inventing a name for it.
    //
    // The suffix was never collision handling. It was the bookkeeping layer creating
    // identities to keep its own keys unique, and it is the reason resumed sessions
    // went invisible to peers still pushing to the original name.
    this.requestedName = opts.name;
    this.name = opts.name;
    this.nodeId = null; // set after identity loaded (see below)
    this._cognitiveProfile = opts.cognitiveProfile || null;
    this._moodThreshold = opts.moodThreshold ?? 0.8;

    // Section 3.5: Node lifecycle role — participant (default), validator, or anchor.
    // Validator/anchor nodes produce feedback CMBs with elevated anchor weight (Section 11.1).
    this._lifecycleRole = opts.lifecycleRole || 'participant';

    // Admission-attestation per-attester hash-chain (omission-evidence backbone).
    // Every attestation this node signs links to the previous via `prev` and a
    // monotonic `seq`, so a dropped attestation leaves a detectable gap. In-memory
    // for now; durable persistence + anchored checkpoints land in the gossip phase.
    this._attestSeq = 0;
    this._attestHead = 'genesis';
    // Commit a signed Merkle checkpoint over this node's attestation chain every
    // `checkpointInterval` gating events; roster peers countersign it (witness), so
    // suppressing an attestation ≤ the committed seq later contradicts the witnessed
    // root. Interval + witness quorum are tunable (research pairing); default 8.
    this._checkpointInterval = opts.checkpointInterval ?? 8;
    // The attestation index is created after the node dir is known (below), so it can
    // persist + reload the durable audit trail.


    // SVAF parameters (paper Section 3.2-3.3)
    this._svafStableThreshold = opts.svafStableThreshold ?? 0.25;
    this._svafGuardedThreshold = opts.svafGuardedThreshold ?? 0.5;
    this._svafTemporalLambda = opts.svafTemporalLambda ?? 0.3;
    this._svafFreshnessSeconds = opts.svafFreshnessSeconds ?? 1800;
    this._svafCategoryWeights = opts.svafFieldWeights ?? FIELD_WEIGHT_PROFILES.uniform;
    // The redundancy floor — δ_f^near below which a category is already in memory. Every other
    // SVAF threshold above has been settable for a long time; this one was not settable at
    // all, and it is the single number the binary redundancy cut consists of.
    //
    // NO `??` DEFAULT HERE, deliberately. Left undefined, core's SVAF evaluator (lib/core/svaf-baseline.js) applies its
    // own DEFAULT_REDUNDANCY_THRESHOLD, so the value has exactly one home. Writing 0.10 here
    // would create a second copy in a different package, free to drift from the first the day
    // either moves — and a threshold that means two things is worse than one nobody can set.
    //
    // ⚠ THIS KEY MOVES THE ACTING GATE. It is the floor of the redundancy cut the node
    // actually admits on, so setting it is a production gating change, not an experiment
    // knob — tune it only as a deliberate change to this node's admission policy.
    this._svafRedundancyThreshold = opts.svafRedundancyThreshold;

    // Adaptive integration timescale. These keys are forwarded to the admission engine;
    // the open baseline runs a fixed timescale (tau = freshnessSeconds) and ignores them,
    // so on a stock node they change nothing. An injected engine may honour them.
    this._svafAdaptiveTimescale = opts.svafAdaptiveTimescale ?? false;
    this._svafMinFreshnessSeconds = opts.svafMinFreshnessSeconds ?? Math.min(this._svafFreshnessSeconds, 60);
    this._svafReactivity = opts.svafReactivity ?? 0.9;
    this._svafChangeWeights = opts.svafChangeWeights ?? null;
    this._recentSvafDecisions = [];                            // change-signal ring (newest pushed last)
    this._recentSvafDecisionsMax = opts.svafRecentWindow ?? 8;

    // Retention — how long to keep CMBs in local storage.
    //
    // DEFAULT: UNLIMITED (founder ruling 2026-07-20). Accumulated cognition is the
    // most valuable asset a node holds; deleting it on a timer destroys the very
    // thing the system exists to build. The previous 86400s (24h) default was
    // silently pruning authority-bearing history — observed live: a deputy store
    // fell 130 -> 116 -> 98 CMBs in a few hours, taking its gate record with it,
    // and a migration lost its tail mid-flight to the same sweep.
    //
    // When storage becomes a real constraint the answer is OPERATOR-DRIVEN: search
    // the store and delete deliberately. A human choosing what to forget is a
    // different act from a timer forgetting on their behalf.
    //
    // Set an explicit finite value to opt IN to time-based retention. Regulated
    // domains MUST set per compliance: legal (jurisdiction), health (HIPAA 6yr),
    // finance (MiFID II 5yr, SEC 7yr).
    // `null`, `undefined`, `Infinity` or <= 0 all mean unlimited.
    this._retentionSeconds = Number.isFinite(opts.retentionSeconds) && opts.retentionSeconds > 0
      ? opts.retentionSeconds
      : Infinity;
    // Origin-aware retention (optional override of the uniform value
    // above). When set, self-authored CMBs (peerId == null) and peer-
    // received CMBs use independent freshness thresholds during
    // compaction. Useful when the app's own lineage chains are higher
    // value for retrospective analysis than peer chatter. Defaults
    // preserve back-compat: both fall through to `retentionSeconds`
    // when not explicitly set.
    this._localRetentionSeconds = opts.localRetentionSeconds ?? this._retentionSeconds;
    this._peerRetentionSeconds  = opts.peerRetentionSeconds  ?? this._retentionSeconds;

    // Layer-4 evaluator seam — INJECTED. The receive path offers every inbound
    // block to this evaluator first and runs the open §9.2 baseline whenever it
    // returns null. The stock evaluator ALWAYS returns null: a stock node's
    // admission is the baseline, and a consumer with its own Layer-4 engine
    // injects an evaluator that sometimes answers.
    this._svafEvaluator = opts.svafEvaluator ?? { evaluate: async () => null };
    // Identity by nodeId (design D9): `opts.nodeId` loads that identity; `opts.create === false`
    // refuses to mint when it is absent (a host restoring a known agent never mints a replacement);
    // a tombstoned identity (moved to another host) refuses to start. The name is the index.
    this._identity = loadIdentity({ name: this.name, nodeId: opts.nodeId, create: opts.create !== false });
    this.nodeId = this._identity.nodeId;
    this._dir = nodeDirById(this.nodeId);

    // Per-node attestation index — every gating attestation this node produces
    // (admit/guard/redundant/reject) + those received from roster peers, indexed by
    // gated-CMB-key (the audit trail) and by attester chain (omission-evidence).
    // Persisted append-only under the node dir, so the cross-mesh audit trail
    // survives a restart instead of evaporating from memory.
    // The logs are rotated (archive/ bounded per log); a rotation that fails is said here once.
    this._attestations = new AttestationStore({
      dir: path.join(this._dir, 'attestations'),
      selfId: this._identity.nodeId,
      log: (m) => this._log(`[attestations] ${m}`),
      // archive/ retention per log (bytes; 0 keeps every archive). Unset: SYM_ATTESTATION_ARCHIVE_MAX_BYTES,
      // else 128 MiB.
      archiveMaxBytes: opts.attestationArchiveMaxBytes,
    });
    // The budget of new gossiped statements, per proven peer and in all (see GOSSIP_PER_SECOND and
    // GOSSIP_NEW_LANE); `opts.gossipBudget` ({ perSecond, burst, newLane, globalPerSecond,
    // globalBurst }) changes it.
    const gb = opts.gossipBudget || {};
    this._gossipRate = gb.perSecond || GOSSIP_PER_SECOND;
    this._gossipBurst = gb.burst || GOSSIP_BURST;
    this._gossipNewLane = gb.newLane || GOSSIP_NEW_LANE;
    this._gossipGlobalRate = gb.globalPerSecond || GOSSIP_GLOBAL_PER_SECOND;
    this._gossipGlobalBurst = gb.globalBurst || GOSSIP_GLOBAL_BURST;
    this._gossipBuckets = new Map(); // proven peer nodeId -> { tokens, at }, least recently active first
    this._gossipGlobal = { tokens: this._gossipGlobalBurst, at: Date.now() };
    // Each attester's rate of new checkpoints taken (see CHECKPOINTS_PER_SECOND); `opts.checkpointRate`
    // ({ perSecond, burst }) changes it.
    this._checkpointRate = (opts.checkpointRate && opts.checkpointRate.perSecond) || CHECKPOINTS_PER_SECOND;
    this._checkpointBurst = (opts.checkpointRate && opts.checkpointRate.burst) || CHECKPOINT_BURST;
    this._checkpointBuckets = new Map(); // attester -> { tokens, at }, least recently active first
    this._gossipClock = Date.now;
    // What gossip this node dropped unverified, said at most once per 10 s per metric and key.
    this._dropReports = new Map();   // `${metric}|${key}` -> report, least recently dropped first
    // Restore the per-attester chain cursor from the reloaded own-chain so `seq`
    // stays monotonic and `prev` keeps linking across restarts — otherwise a restart
    // would reset the chain to genesis and read as a gap (false omission). Genesis
    // when there is no prior chain on disk.
    const ownChain = this._attestations.chainOf(this.nodeId);
    if (ownChain.length) {
      const lastOwn = ownChain[ownChain.length - 1];
      this._attestSeq = lastOwn.seq;
      this._attestHead = chainHash(lastOwn.sig);
    }

    // Acquire exclusive lock on this identity. Prevents two SymNode
    // processes on the same host from claiming the same nodeId, which
    // caused duplicate-identity races on the relay (close 4004 / 4006
    // loops, peer-flap floods, broken push paths). The lock is held
    // for the lifetime of this process; stop() releases it. Hosts MUST
    // wire SIGTERM/SIGINT to call stop() so the lockfile is cleaned
    // up on graceful exit — otherwise the lock becomes stale and the
    // next start() reclaims it via dead-PID detection.
    //
    // Throws with code 'EIDENTITYLOCK' if another process already holds
    // the lock. Hosts should catch and exit cleanly (or pick a
    // different SYM_NODE_NAME).
    this._releaseIdentityLock = acquireIdentityLock(this.name, { dir: this._dir });

    // Core Secure (design D1/D2): a peer is the set of confirmed sessions that proved one nodeId with
    // one identity key. Session keys are ephemeral, derived per handshake (§5.2.1): there is no
    // persistent X25519 key and no per-peer secret map. `_sessions` holds every live session,
    // authenticating or confirmed; `_peers` only admitted ones, keyed by the PROVEN nodeId.
    this._sessions = new Set();
    this._offeredExtensions = [...(opts.extensions || OFFERED_EXTENSIONS)];
    this._implementation = { name: 'sym', version: ENGINE_VERSION };
    this._handshakeTimeoutMs = opts.handshakeTimeoutMs || 10_000;
    this._legacyRefusals = new Map(); // address -> { at, more }: legacy hellos refused on the listener
    this._sessionStats = { confirmed: 0, failed: 0, failedByReason: {}, refusedFrames: 0, refusedByReason: {}, desync: 0, superseded: 0, legacyHellosRefused: 0 };
    this._chainStats = { fetched: 0, resolved: 0, timedOut: 0, served: 0 };
    this._chainFetchTimeoutMs = opts.chainFetchTimeoutMs || CHAIN_FETCH_TIMEOUT_MS;
    // Legacy Import (design D7) is created after the node dir and the key registry exist (below).
    this._legacyRoutes = opts.legacyRoutes || null;
    this._legacy = null;

    // Earned-authority root (MMP §6.5). The pinned, non-earnable anchor identity
    // (typically the founder) that all role authority must chain back to. Configured
    // via opts.anchor { nodeId, publicKey } or SYM_FOUNDER_ANCHOR="nodeId:publicKey".
    // Without an anchor the node falls back to its static `lifecycleRole` (legacy).
    this._anchor = parseAnchor(opts.anchor || process.env.SYM_FOUNDER_ANCHOR);
    // Roster key registry — authenticated nodeId→key bindings, so signatures from peers
    // we never directly handshook still verify. Pins by source precedence (anchor >
    // handshake > grant-vouched); the relayer never vouches. Persisted under the node dir.
    this._roster = new RosterKeyRegistry({
      anchor: this._anchor,
      dir: path.join(this._dir, 'roster-keys'),
      log: (m) => this._log(m),
      // A node with a live session never has its binding expired (design D3 binding lifetime).
      isLive: (nodeId) => !!(this._peers && this._peers.has(nodeId)),
      bindingTtlMs: opts.bindingTtlMs,
      maxBindings: opts.maxKeyBindings,
    });
    {
      const mig = this._roster.migration();
      if (mig && mig.read > 0) this._log(`Key registry migrated from 0.13: ${mig.bindings} binding(s), ${mig.legacyClaim} relabelled legacy-claim (unproven hellos: expected keys, never verifying), ${mig.grant} grant-vouched`);
    }
    // Legacy Import (design D7): off unless routes are configured (opts.legacyRoutes, or the node
    // dir's legacy-routes.json). Each route is outbound-only, pins its mandatory key fingerprint, and
    // is refused by the sticky floor once its nodeId has proven itself over Core Secure.
    this._legacy = new LegacyImport(this, { routes: this._legacyRoutes || [] });
    // Room ownership — which key owns which room, for THIS receiver. Config pins are
    // supplied per boot and outrank the persisted cache; there is no wire source (see
    // room-ownership.js). A room with no owner is OPEN and behaves exactly as before.
    this._roomOwners = new RoomOwnershipRegistry({
      dir: path.join(this._dir, 'room-owners'),
      owners: opts.roomOwners,
    });
    // The room-join grant THIS node presents when joining a gated room, if it holds one
    // (carried by an invite). Absent for the room's owner, which needs none.
    this._roomGrant = opts.roomGrant || null;
    // Role-grant chain — signed grants/revokes; resolves the role a node held at a
    // given time, with authority flowing only along anchor-rooted chains. Keeps only
    // records rooted at the anchor, verifies their sigs through the roster registry's own
    // lookup (which a rooted grant can populate with the grantee's vouched key); persisted
    // under the node dir. Reading it never stops the node from starting: what it could not
    // verify is skipped and said here, once.
    this._roleGrants = new RoleGrantStore({
      anchor: this._anchor,
      keys: this._roster,
      dir: path.join(this._dir, 'role-grants'),
    });
    {
      const r = this._roleGrants.loadReport();
      const skipped = Object.entries(r.skipped);
      if (r.unreadable) this._log(`Role grants: ${r.unreadable}; starting with no grants`);
      else if (skipped.length) {
        const n = skipped.reduce((sum, [, c]) => sum + c, 0);
        this._log(`Role grants: loaded ${r.loaded}, skipped ${n} that could not be verified (${skipped.map(([k, c]) => `${k} ${c}`).join(', ')})`);
      }
    }
    // Strict mode: when set, reject UNSIGNED CMBs from peers whose identity key
    // is known (default off — unsigned peers are allowed for interop).
    this._requireSignedCmb = process.env.SYM_REQUIRE_SIGNED_CMB === '1'
      || process.env.SYM_REQUIRE_SIGNED_CMB === 'true' || opts.requireSignedCmb === true;

    // MMP §15.8 lineage tether (on by default): a remix asserts lineage only
    // where the descent claim survives content-only evaluation against the
    // nearest resolvable lineage root; a remix drifted past the reject floor
    // is stored as a fresh root with the departed source in provenance.
    // Disable with opts.lineageTether=false or SYM_LINEAGE_TETHER=0.
    this._lineageTether = process.env.SYM_LINEAGE_TETHER === '0'
      ? false : opts.lineageTether !== false;

    // Delivery inbox — the receive counterpart to remember() (send). The node
    // buffers every CMB it delivers (each 'cmb-accepted') so any consumer can
    // PULL received CMBs via node.inbox() instead of subscribing to the event.
    // This makes the SDK sufficient for send + pull on its own (the MCP wrapper,
    // sym-swift, or a headless script all use the same primitive). Capped ring.
    this._inbox = [];
    this._inboxSeq = 0;
    this._inboxCursor = 0;
    this._inboxMax = opts.inboxMax || 500;
    // DURABLE (founder ruling 2026-08-04): communication is addressed to the
    // NODE, and a new session RELINKS to it — including what was delivered
    // while no session was attached. The inbox was process memory only, so a
    // restart wiped the delivery feed while every sender believed it had
    // delivered (four gate requests vanished into a restarted peer that
    // showed live on bonjour throughout). Ring + seq + CURSOR persist
    // together: messages without the cursor would replay what was already
    // drained; the cursor without messages would silently skip the backlog.
    this._inboxFile = path.join(this._dir, 'inbox.json');
    this._loadInbox();
    this.on('cmb-accepted', (entry) => this._pushInbox(entry));
    // The CMB store dir is `cmbs/`. The immediately-prior name was `meshmem/`
    // (identical format) — migrate by a plain directory rename, no transform.
    this._cmbsDir = path.join(this._dir, 'cmbs');
    const meshmemDir = path.join(this._dir, 'meshmem');
    if (!fs.existsSync(this._cmbsDir) && fs.existsSync(meshmemDir)) {
      try { fs.renameSync(meshmemDir, this._cmbsDir); } catch { /* keep meshmem; store still reads cmbs */ }
    }
    // Very old nodes used `memories/` (different category layout) — that still goes
    // through MemoryStore's category-mapped one-time migration.
    const legacyDir = path.join(this._dir, 'memories');
    this._store = new MemoryStore(this._cmbsDir, this.name, {
      legacyDir: fs.existsSync(legacyDir) ? legacyDir : undefined,
    });

    // SVAF decision log — every evaluation (admit AND reject), so the node's
    // autonomous per-category admission is observable, not just its admitted
    // memory. Local-first, capped, label-only (never the rejected payload).
    this._decisionLog = new DecisionLog(path.join(this._dir, 'decisions'), {
      cap: Number(process.env.SYM_DECISION_LOG_CAP) || 2000,
      enabled: process.env.SYM_DECISION_LOG !== '0',
    });

    // Wrap receiveFromPeer to emit 'cmb-accepted' event.
    // frame-handler.js (sym-core) calls _store.receiveFromPeer() after SVAF
    // accepts an incoming CMB. This proxy lets application-layer agents react
    // to accepted signals in real-time for remix (MMP v0.2.0 Section 14).
    const originalReceiveFromPeer = this._store.receiveFromPeer.bind(this._store);
    this._store.receiveFromPeer = (peerId, entry, opts) => {
      const stored = originalReceiveFromPeer(peerId, entry, opts);
      if (stored) {
        this._metrics.cmbAccepted++;
        // Preserve _anchor flag from reconnect anchor CMBs so mesh-agent
        // can skip remix for historical context replays.
        if (entry._anchor) stored._anchor = true;
        // Ingestion indicator (MMP §9.2.2): a CMB that reached the store was
        // admitted to local memory as a remix (lineage intact). Consumers use
        // `remixed` to tell an ingested CMB from a directed CMB that was
        // delivered to the agent but not stored (frame-handler sets remixed:false).
        stored.remixed = true;
        this.emit('cmb-accepted', stored);
        this.emit('metric', { type: 'cmb-accepted', from: entry.source || peerId, key: stored.key });
      }
      return stored;
    };

    // Protocol-level metrics — structured event tracking for observability.
    // Every significant protocol operation is counted and emitted.
    // Applications (sym.day, monitoring) subscribe via node.on('metric', ...)
    // See MMP v0.2.0 Section 13 (Application).
    this._metrics = {
      cmbProduced: 0,        // CMBs created by this agent via remember()
      cmbAccepted: 0,        // Peer CMBs accepted by SVAF
      cmbRejected: 0,        // Peer CMBs rejected by SVAF (logged by sym-core)
      remixProduced: 0,      // Remix CMBs (remember() with parents)
      remixRejected: 0,      // Remix attempts rejected (no new domain data)
      svafAligned: 0,        // SVAF aligned decisions
      svafGuarded: 0,        // SVAF guarded decisions
      svafRejected: 0,       // SVAF rejected decisions
      peersJoined: 0,        // Peers that connected
      peersLeft: 0,          // Peers that disconnected
      recalls: 0,            // recall() queries
      llmCalls: 0,           // LLM API calls reported by agent
      llmTokensIn: 0,        // Total input tokens
      llmTokensOut: 0,       // Total output tokens
      llmModel: null,        // Last model used
      startedAt: null,       // When the node started
      gossipOverBudget: 0,   // gossiped statements dropped unverified, past their peer's budget
      signaturesNotCanonical: 0, // gossiped statements refused for a signature not spelled canonically
      checkpointsOverRate: 0, // verified checkpoints not taken, past their attester's rate
      framesRefused: 0,      // Inbound frames whose handling failed — refused, never thrown (see _receiveFrame)
      framesRefusedByType: {}, // ...by frame type
    };
    this._refusalLines = new Map(); // peerId -> { at, quiet }: at most one log line per peer a minute

    // LLM cost pricing (USD per token). Updated by reportLLMUsage().
    // Default: gpt-4o-mini pricing as of 2026-03.
    this._llmPricing = {
      'gpt-4o-mini': { input: 0.15 / 1_000_000, output: 0.60 / 1_000_000 },
      'gpt-4o':      { input: 2.50 / 1_000_000, output: 10.00 / 1_000_000 },
    };

    // Remix guard — MMP v0.2.0 Section 14: agents MUST NOT remix without
    // new domain data. remember() sets this flag when the agent produces an
    // original observation from its domain. canRemix() checks it before
    // allowing remix of peer signals. Prevents remix storms.
    this._hasNewDomainData = false;

    // Rule A (§7.5): every block parents from its author's OWN HEAD, so the agent has one
    // continuous line rather than a scatter of unrooted blocks. HEAD is the last address this
    // node actually minted.
    //
    // `_ownKeys` is what makes the self/peer distinction resolvable AT ALL. Deciding it by
    // authorOf(parent) would need the parent block — which may not be local — and `createdBy`
    // is stripped on store write, so the lookup can fail in exactly the case it is needed. An
    // emitter always knows its own keys without resolving anything.
    this._head = null;
    this._ownKeys = new Set();
    this._OWN_KEYS_MAX = 4096;

    // Coupling engine — evaluates peer cognitive state
    this._meshNode = new MeshNode({ hiddenDim: DIM });
    this._cfcStatePath = path.join(this._dir, 'cfc-state.json');
    this._initLocalState();

    // Layer-6 insight engine — INJECTED, never named here. A consumer that wants
    // per-agent insight generation passes an object with ingestSignal(); a stock
    // node runs without one and the insight channel simply stays quiet. The
    // injected engine may call node.broadcastInsight()/emit('insight') itself.
    this._xmesh = opts.insightEngine ?? null;

    // Peer state
    this._peers = new Map();
    this._port = 0;
    this._running = false;

    // Mesh room membership per MMP §5.8. `default` is the reserved implicit
    // room for nodes that do not declare one; `room` is advertised in the
    // handshake frame (§5.2 optional category) so heterogeneous peers on the same
    // LAN can tell which room they belong to.
    this._room = opts.room || 'default';

    // Discovery — pluggable for testability. See MMP v0.2.0 Section 5.
    // `discoveryServiceType` enables LAN-level Bonjour isolation for mesh
    // rooms (MMP §5.8: "Bonjour isolation + relay token for WAN"). Default
    // `_sym._tcp` preserves backward compatibility; per-room service types
    // (e.g. `_melotune._tcp`, `_melotune-{roomId}._tcp`) isolate LAN peers
    // at the mDNS layer so nodes in different rooms never discover each
    // other. Matches the sym-swift SymNode(discoveryServiceType:) parameter.
    this._discoveryServiceType = opts.discoveryServiceType || '_sym._tcp';
    this._discovery = opts.discovery || (
      opts.relayOnly
        ? new NullDiscovery()
        : new BonjourDiscovery({ serviceType: this._discoveryServiceType, room: opts.room || 'default' })
    );

    // Wake
    this._wakeChannel = opts.wakeChannel || null;
    this._peerWakeChannels = new Map();
    this._peerLastWake = new Map();
    this._pendingFrames = new Map();

    this._wakeManager = new WakeManager({
      wakeChannelsFile: path.join(this._dir, 'wake-channels.json'),
      peerWakeChannels: this._peerWakeChannels,
      peerLastWake: this._peerLastWake,
      pendingFrames: this._pendingFrames,
      wakeCooldownMs: opts.wakeCooldownMs || 5 * 60 * 1000,
      wakeChannel: this._wakeChannel,
      log: (msg) => this._log(msg),
      getPeers: () => this._peers,
      getMeshNode: () => this._meshNode,
      getIdentity: () => this._identity,
      nodeName: this.name,
    });
    this._wakeManager.loadWakeChannels();

    // Relay
    this._relayUrl = opts.relay || null;
    this._relayToken = opts.relayToken || null;
    this._relayOnly = opts.relayOnly || false;

    this._relay = new RelayConnection({
      relayUrl: this._relayUrl,
      relayToken: this._relayToken,
      wakeChannel: this._wakeChannel,
      log: (msg) => this._log(msg),
      getIdentity: () => this._identity,
      getRoom: () => this._room,   // declared in relay-auth (wire note D4)
      isRunning: () => this._running,
      getMeshNode: () => this._meshNode,
      // The relay's roster names candidates and its envelopes carry bytes from an unproven `from`
      // (§4.4.1): the session manager below runs the handshake over each channel (design D2).
      onPeerPresent: (nodeId, name) => this._relayPeerPresent(nodeId, name),
      onPeerGone: (nodeId, name) => this._relayPeerGone(nodeId, name),
      onEnvelope: (from, fromName, payload) => this._relayEnvelope(from, fromName, payload),
      onDisconnected: () => this._relayDisconnected(),
      // Every message off the relay socket, the relay's own frames included, is taken under the
      // node's inbound guard: refused and counted, never thrown (0.13.17).
      guard: (frame, take) => this._guardInbound('relay', 'relay', frame, 'relay', take),
      isKnown: (nodeId) => !!(this._peers && this._peers.has(nodeId)),
      rate: opts.relayRate,
      onIdentityCollision: (info) => {
        // Surface the collision as an event so hosts can take action.
        // Default behavior (if no listener): the relay layer has already
        // logged loudly and stopped reconnecting; the node remains alive
        // but in a degraded state (no relay transport, only Bonjour LAN
        // peers reachable). Hosts that prefer to exit hard should listen
        // and call process.exit() themselves. `info.code` says which stop
        // (4004 replaced, 4006 duplicate rejected, 4007 key conflict) and
        // status().relayState.stopped keeps it.
        this.emit('identity-collision', info);
        this.emit('metric', { type: 'relay-hard-stop', code: info.code, kind: info.kind || null, nodeId: info.nodeId });
      },
      onAuthRefused: (info) => {
        // The relay's channel table does not hold our token. The relay layer has logged the
        // cause and the fix and dropped to a slow retry; hosts listen to put the line where
        // their operator reads (the plugin's stderr, the daemon's log).
        this.emit('relay-auth-refused', info);
      },
      nodeName: this.name,
    });

    // Frame handler — cliHostMode forwards frames without storing or SVAF.
    // Local CLI-host peer pattern: hosts the IPC surface for the sym CLI
    // on a single machine without participating in mesh cognition.
    this._cliHostMode = opts.cliHostMode || false;
    // The admission seam rides through: a consumer may inject its own admission
    // engine and/or a post-admission observer; stock nodes run the open baseline.
    this._frameHandler = new FrameHandler(this, {
      cliHostMode: this._cliHostMode,
      admit: opts.admit,
      afterAdmission: opts.afterAdmission,
    });

    // Synthesis delegate — agent processes XMesh insight and produces new outbound CMBs
    this._synthesisDelegate = opts.onSynthesis || null;

    // Timers
    this._heartbeatInterval = opts.heartbeatInterval || 10000;
    this._heartbeatTimeout = opts.heartbeatTimeout || 120000;
    this._heartbeatTimer = null;
    this._encodeInterval = opts.encodeInterval || 30000;
    this._encodeTimer = null;
    this._statsInterval = opts.statsInterval || 15000;
    this._statsTimer = null;
  }

  // ── Keys ───────────────────────────────────────────────────

  /**
   * This node's EARNED role right now — resolved from the role-grant chain when an
   * anchor is configured, else the static `lifecycleRole` (legacy / no root of trust).
   * The role this node stamps into its attestations + witnesses; consumers can
   * independently re-resolve it via the chain.
   * @returns {'participant'|'validator'|'anchor'}
   */
  _resolvedRole() {
    if (!this._anchor) return this._lifecycleRole;
    return this._roleGrants.resolveRole(this.nodeId, this._identity.publicKey, Date.now());
  }

  /**
   * Resolve any node's role at a time (default now) from this node's grant chain. Authority follows
   * the key (design D3): the role is the one conferred on the key `nodeId` is bound to here — its
   * proven or vouched binding — so an id held under another key resolves to participant. Pass
   * `opts.key` to ask about a specific key instead.
   */
  resolveRole(nodeId, at = Date.now(), opts = {}) {
    const key = opts.key || (nodeId === this.nodeId ? this._identity.publicKey : this._identityKey(nodeId));
    return this._roleGrants.resolveRole(nodeId, key, at);
  }

  /**
   * The key that verifies `nodeId`'s signatures: its binding in the key registry (design D3) —
   * the configured anchor, a proven session, an out-of-band pin, or an anchor-rooted grant's vouch.
   * Never a key a hello merely announced, and never a legacy claim.
   * @private
   */
  _identityKey(nodeId) {
    const k = this._roster.get(nodeId);
    if (k !== undefined) return k;
    // A full registry (every binding protecting history) holds no binding for a newcomer: the key
    // its live Core Secure session proved still verifies what it signs, for as long as that session
    // lasts. A degradation (nothing persisted), never a lockout. A legacy claim is not a binding,
    // so this never applies to an id the registry expects another key for.
    if (this._roster.expected(nodeId) !== undefined) return undefined;
    const peer = this._peers && this._peers.get(nodeId);
    const s = peer && peer.transport;
    return s && s.confirmed && !s.legacy && s.identityKey ? s.identityKey : undefined;
  }

  /**
   * MMP §7 cmb-fetch: retrieve a CMB by content address from connected peers —
   * the §15.8 re-verification path for lineage roots this store cannot resolve.
   * Self-verifying: a response is accepted only if its recomputed content
   * address equals the requested key (forged responses are discarded and
   * reported), so no trust in the serving peer is required.
   *
   * @param {string} key - Content-address key. The SCHEME is the digest length
   *   (64 hex = v1, 32 hex = legacy), not the prefix — v1 keys wear cmb1- or cmb-.
   * @param {object} [opts]
   * @param {number} [opts.timeoutMs=5000]
   * @returns {Promise<{cmb: object, from: string, peerId: string}|null>} first
   *   verified hit, or null when no connected peer serves a verifiable copy.
   */
  /**
   * MMP §15.8 retroactive lineage-tether audit: apply the tether to chains
   * stored BEFORE the invariant existed (or received from pre-tether peers).
   * Walks every stored remix carrying lineage, resolves its nearest anchor
   * (optionally fetching unresolvable roots by content address, cmb-fetch),
   * re-evaluates the tether with both sides re-encoded in the current kernel,
   * annotates provenance, signs a tether attestation, and — when `sever` is
   * set — strips lineage from chains that fail the floor (fresh root, ancestor
   * index updated, entry persisted).
   *
   * @param {object} [opts]
   * @param {boolean} [opts.fetch=false]  - fetch unresolvable anchors from peers.
   * @param {boolean} [opts.sever=false]  - apply severance (default: annotate + attest only).
   * @param {number}  [opts.timeoutMs=3000] - per-fetch timeout.
   * @returns {Promise<{audited:number, tethered:number, severed:number,
   *   failedFloor:number, unchecked:number, fetched:number}>}
   */
  async auditLineageTethers(opts = {}) {
    const { resolveTetherAnchor, evaluateLineageTetherFromText, signTetherAttestation, isLineageSevered } = require('./core');
    const report = { audited: 0, tethered: 0, severed: 0, failedFloor: 0, unchecked: 0, fetched: 0 };
    if (typeof evaluateLineageTetherFromText !== 'function') return report;
    const keys = [...this._store._index.byKey.keys()];
    for (const key of keys) {
      const entry = this._store.get(key);
      if (!entry) continue;
      const cmb = entry.cmb;
      // An entry this node already severed is a root to it, though its record still names parents.
      const parents = isLineageSevered(entry) ? [] : recordParents(cmb);
      if (!cmb || !cmb.categories || parents.length === 0) continue;
      report.audited++;

      let anchorCategories = null;
      let anchorKey = null;
      const anchor = resolveTetherAnchor(cmb, (k) => (k === entry.key ? undefined : this._store.get(k)));
      if (anchor.resolvedFromStore) { anchorCategories = anchor.categories; anchorKey = anchor.key; }
      if (!anchorCategories && opts.fetch === true) {
        // The store's own closure, from its index. The record carries direct parents only (§7.5);
        // an `ancestors` list on it is the sender's claim and must not choose what is fetched.
        const anc = this._store.ancestors(entry.key);
        for (const k of (anc.length ? anc : parents)) {
          // A key this store holds was already judged by the verified walk above, and fetchCMB
          // answers from the store first — it would hand back the record that walk refused.
          if (this._store.get(k)) continue;
          const hit = await this.fetchCMB(k, { timeoutMs: opts.timeoutMs ?? 3000 });
          if (hit?.cmb?.categories) { anchorCategories = hit.cmb.categories; anchorKey = k; report.fetched++; break; }
        }
      }
      if (!anchorCategories) { report.unchecked++; continue; }

      const ev = await evaluateLineageTetherFromText({
        remixCategories: cmb.categories, anchorCategories,
        categoryWeights: this._svafCategoryWeights, guardedThreshold: this._svafGuardedThreshold,
      });
      if (!ev.checked) { report.unchecked++; continue; }

      const applySever = !ev.tethered && opts.sever === true;
      // On the entry, beside the record: a two-section record has exactly two members (§8.8.1).
      entry.provenance = {
        ...entry.provenance,
        tether: {
          severed: applySever, anchor: anchorKey, kernelId: ev.kernelId,
          drift: ev.drift, audited: true,
          ...(applySever ? { departedFrom: parents[0] ?? null } : {}),
        },
      };
      try {
        entry.tether = signTetherAttestation({
          of: recordKey(cmb), anchor: anchorKey, kernelId: ev.kernelId, drift: ev.drift,
          verdict: ev.tethered ? 'tethered' : 'severed', by: this.nodeId, at: Date.now(),
        }, this._identity.privateKey);
      } catch { /* attestation is SHOULD — the audit annotation stands without it */ }

      if (ev.tethered) {
        report.tethered++;
      } else {
        report.failedFloor++;
        if (applySever) {
          // On the entry and in the index, never in the record: a stored record is immutable (§8),
          // and this one is usually its author's signed block, whose signature covers its lineage.
          this._store.severLineage(entry.key);
          report.severed++;
          this._log(`[§15.8 audit] lineage severed: ${String(entry.key).slice(0, 16)}… drift ${ev.drift.toFixed(3)} from anchor ${String(anchorKey).slice(0, 16)}…`);
          this.emit('metric', { type: 'lineage-tether-severed', key: entry.key, anchor: anchorKey, drift: ev.drift, audit: true });
        }
      }
      this._store._persist(entry);
    }
    this._log(`[§15.8 audit] audited:${report.audited} tethered:${report.tethered} failed-floor:${report.failedFloor} severed:${report.severed} unchecked:${report.unchecked} fetched:${report.fetched}`);
    return report;
  }

  async fetchCMB(key, opts = {}) {
    if (!key || typeof key !== 'string') return null;
    const local = this._store.get(key);
    if (local?.cmb) return { cmb: local.cmb, from: this.name, peerId: this.nodeId };
    if (this._peers.size === 0) return null;
    const timeoutMs = opts.timeoutMs ?? 5000;
    const reqId = `cf-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
    if (!this._cmbFetchPending) this._cmbFetchPending = new Map();
    return await new Promise((resolve) => {
      const asked = new Set();
      const misses = new Set();
      const done = (v) => {
        clearTimeout(timer);
        this._cmbFetchPending.delete(reqId);
        resolve(v);
      };
      const timer = setTimeout(() => done(null), timeoutMs);
      this._cmbFetchPending.set(reqId, {
        key,
        resolve: done,
        // Only peers the request was actually sent to can close it — an
        // unsolicited (or discarded-forged) response never terminates the
        // fetch early.
        miss: (peerId) => {
          if (!asked.has(peerId)) return;
          misses.add(peerId);
          if (misses.size >= asked.size) done(null);
        },
      });
      for (const [peerId, peer] of this._peers) {
        if (peer.transport?.send) {
          // The record answers before the result that lists it (design D1): the session is told now
          // that a record under `key` is this fetch's.
          this._frameHandler.expectFetched(peer.transport, key, reqId);
          if (peer.transport.send({ type: 'cmb-fetch', reqId, key, from: this.nodeId, timestamp: Date.now() }) !== false) asked.add(peerId);
        }
      }
      if (asked.size === 0) done(null);
    });
  }

  /**
   * Grant a lifecycle role to a peer (MMP §6.5). Signs a role-grant with this node's
   * identity key, records it, and gossips it to the roster. A grant is made only if THIS
   * node's own resolved role outranks-or-equals the conferred role along a chain rooted at
   * the anchor; a grant it is not entitled to make would have no effect anywhere, so it is
   * neither kept nor sent, and this returns null.
   * @param {string} granteeNodeId
   * @param {'validator'|'anchor'} role
   * @returns {object|null} the signed grant, or null
   */
  grantRole(granteeNodeId, role, opts = {}) {
    // Every grant names the key it confers authority on (design D3): a grant to a bare nodeId would
    // confer it on whoever holds that id later. The key is one this node has a PROVEN binding for (a
    // confirmed session, or an out-of-band pin), or one the operator names explicitly.
    const source = this._roster.source(granteeNodeId);
    const granteeKey = opts.granteeKey
      || ((source === 'proven' || source === 'pinned') ? this._roster.get(granteeNodeId) : undefined);
    if (!granteeKey) {
      this._log(`Role grant for ${String(granteeNodeId).slice(0, 8)} not made: no proven key is known for it (it has not completed a Core Secure session with this node, and no key was given)`);
      return null;
    }
    return this._emitGrant({ type: 'role-grant', grantee: granteeNodeId, role, granteeKey });
  }

  /** Revoke a peer's granted role (signed role-revoke, gossiped). */
  revokeRole(granteeNodeId) {
    return this._emitGrant({ type: 'role-revoke', grantee: granteeNodeId });
  }

  /**
   * Advance a CMB to `validated` under THIS node's earned authority (MMP §6.5). The
   * node's role is resolved from its grant chain (or the static lifecycle role when no
   * anchor is pinned) and the store rejects the move unless it resolves to validator or
   * above. Validation is identity-bound and un-spoofable — a participant cannot validate.
   * @param {string} key
   * @returns {{ ok: boolean, reason?: string }}
   */
  validateCMB(key) {
    return this._store.validateCMB(key, { byRole: this._resolvedRole() });
  }

  /**
   * Advance a CMB to `canonical` under THIS node's earned authority — reserved to anchor
   * rank (§6.5). Resolves this node's role and lets the store enforce the gate.
   * @param {string} key
   * @returns {{ ok: boolean, reason?: string }}
   */
  canonizeCMB(key) {
    return this._store.canonizeCMB(key, { byRole: this._resolvedRole() });
  }

  /** @private Sign + record + gossip a grant/revoke. */
  _emitGrant(partial) {
    // A grant vouches for the grantee's nodeId↔key binding (granteeKey, bound into the signed
    // payload): nodes that never met the grantee learn its key from this rooted grant. Revokes carry
    // no key.
    const g = { ...partial, grantedBy: this.nodeId, grantedAt: Date.now() };
    try {
      signGrant(g, this._identity.privateKey);
      const r = this._roleGrants.record(g);
      if (!r.stored) {
        this._log(`Role ${g.type === 'role-revoke' ? 'revoke' : 'grant'} for ${String(g.grantee).slice(0, 8)} not made: ${r.reason}`);
        return null;
      }
      this._gossipToRoster({ type: g.type, grant: g });
      return g;
    } catch (err) {
      this._log(`Role grant signing failed: ${err.message}`);
      return null;
    }
  }

  /**
   * Ingest a role-grant/revoke gossiped by a roster peer: the store keeps it only if it is
   * rooted at the anchor and its signature verifies against the grantor's authenticated
   * key (anchor pinned), and only a record kept is relayed (once). An unrooted record — a
   * peer's self-signed grant, say — has no effect, so it is dropped here and goes no further.
   * What is stored and relayed is the store's canonical copy: only the signed fields (A5).
   * @private
   */
  _ingestRoleGrant(g, fromPeerId, session = null) {
    // A role grant is gossip like any other signed statement: a repeat (its signature's bytes, however
    // it is spelled) or a frame that is malformed, spelled otherwise than its signer wrote it, or from a
    // grantor whose key this node does not hold is dropped before anything is spent; a new one spends
    // the delivering lane's budget before its signature is checked. The store bounds what it keeps,
    // and only what it keeps is relayed.
    if (!g || !g.grantee || !g.grantedBy || !g.type || !sigOk(g.sig)) return { ok: false, reason: 'malformed' };
    if (!isCanonicalSig(g.sig)) return this._refuseSpelling(fromPeerId, 'role-grant', g.grantedBy);
    if (this._roleGrants.has(g.sig)) return { ok: false, reason: 'duplicate' };
    if (!this._roleGrants.grantorKey(g.grantedBy)) {
      this._holdForChain(session, g);
      return { ok: false, reason: 'unknown-grantor-key' };
    }
    if (!this._gossipBudget(fromPeerId, 'role-grant', g.grantedBy)) return { ok: false, reason: 'over-budget' };
    const r = this._roleGrants.record(g);
    if (r.stored) this._gossipToRoster({ type: r.grant.type, grant: r.grant }, fromPeerId);
    else if (r.reason === 'unrooted') this._holdForChain(session, g);
    return { ok: r.stored, reason: r.reason };
  }

  /**
   * A grant or revoke arrived before the grant that roots its grantor (design D3; it replaces
   * 0.13.17's pending set, which anyone could flood). Instead of keeping it for whatever may come,
   * the node asks the session that delivered it for the chain — a directed `role-chain-fetch`
   * naming the grantor whose rooting grants are missing — and holds the record only for that fetch:
   * at most CHAIN_HOLD_MAX per session, until the answer or CHAIN_FETCH_TIMEOUT_MS. The answer is
   * ordinary signed grants, verified top-down by the store like any other; then the held record is
   * offered once more, and dropped either way. A record from a session that cannot be asked (none,
   * a Legacy Import session, or the answer itself) is not held.
   * @private
   */
  _holdForChain(session, g) {
    if (!session || session.legacy || !session.confirmed || session.closed || typeof session.send !== 'function') return;
    if (typeof g.grantedBy !== 'string' || !g.grantedBy || g.grantedBy.length > 256 || typeof g.sig !== 'string') return;
    const h = session._chainHold || (session._chainHold = { grants: new Map(), fetches: new Map() });
    // Keyed by every field the signature covers and the signature: a forged copy sent ahead of the
    // genuine record is a different entry, so it cannot keep the genuine one out.
    const holdKey = `${g.type}|${g.grantee}|${g.role || ''}|${g.grantedBy}|${g.grantedAt}|${g.granteeKey || ''}|${g.sig}`;
    if (h.grants.has(holdKey)) return;
    if (h.grants.size >= CHAIN_HOLD_MAX) {
      this._noteDrop('role-chain-hold-full', session.nodeId, { frame: g.type, author: g.grantedBy });
      return;
    }
    let reqId = null;
    for (const [id, f] of h.fetches) if (f.grantee === g.grantedBy) { reqId = id; break; }
    if (!reqId) {
      reqId = `rc-${crypto.randomBytes(8).toString('hex')}`;
      const timer = setTimeout(() => this._chainFetchDone(session, reqId, false), this._chainFetchTimeoutMs);
      if (timer.unref) timer.unref();
      h.fetches.set(reqId, { grantee: g.grantedBy, timer });
      this._chainStats.fetched++;
      session.send({ type: 'role-chain-fetch', reqId, grantees: [g.grantedBy] });
    }
    h.grants.set(holdKey, { grant: g, reqId });
  }

  /** @private A chain fetch ended (answered, timed out, or its session closed): let its held records go. */
  _chainFetchDone(session, reqId, answered) {
    const h = session && session._chainHold;
    const f = h && h.fetches.get(reqId);
    if (!f) return;
    clearTimeout(f.timer);
    h.fetches.delete(reqId);
    for (const [k, e] of [...h.grants]) {
      if (e.reqId !== reqId) continue;
      h.grants.delete(k);
      // Offered once more, with no session: whatever it still lacks, it is not held again.
      if (answered && !session.closed) {
        const r = this._ingestRoleGrant(e.grant, session.nodeId, null);
        if (r.ok) this._chainStats.resolved++;
      }
    }
    if (!answered) this._chainStats.timedOut++;
  }

  /**
   * The answer to this node's role-chain-fetch on `session`: `{ reqId, grants }`. Only an answer to a
   * fetch in flight on this session is read. Its grants are offered to the store top-down (until a
   * pass stores nothing, so their order does not matter), each through the ordinary ingest — the
   * gossip budget, the vouched-key verification, relay-once — and none of them is held for a further
   * fetch.
   * @private
   */
  _onRoleChain(session, msg) {
    const h = session && session._chainHold;
    const reqId = msg && typeof msg.reqId === 'string' ? msg.reqId : null;
    if (!h || !reqId || !h.fetches.has(reqId)) return;
    let left = Array.isArray(msg.grants) ? msg.grants.slice(0, CHAIN_ANSWER_MAX).filter((g) => g && typeof g === 'object') : [];
    let progress = true;
    while (progress && left.length) {
      progress = false;
      const next = [];
      for (const g of left) {
        const r = this._ingestRoleGrant(g, session.nodeId, null);
        if (r.ok) progress = true;
        else if (r.reason === 'unrooted' || r.reason === 'unknown-grantor-key') next.push(g);
      }
      left = next;
    }
    this._chainFetchDone(session, reqId, true);
  }

  /**
   * Answer a peer's role-chain-fetch: for each grantee named (at most CHAIN_FETCH_MAX_GRANTEES), the
   * grants and revokes this node holds for it, each preceded by the chain that roots its grantor, up
   * to the anchor (depth at most 8, at most CHAIN_ANSWER_MAX records): `{ type: 'role-chain', reqId,
   * grants }`, sealed on the session like every control frame. Paced per session (a token bucket of
   * CHAIN_SERVE_PER_SECOND), since an answer costs more than the request.
   * @private
   */
  _serveRoleChain(session, msg) {
    if (!session || typeof session.send !== 'function' || !msg) return;
    const reqId = typeof msg.reqId === 'string' && msg.reqId && msg.reqId.length <= 128 ? msg.reqId : null;
    if (!reqId || !Array.isArray(msg.grantees)) return;
    const now = Date.now();
    const b = session._chainServe || (session._chainServe = { tokens: CHAIN_SERVE_BURST, at: now });
    b.tokens = Math.min(CHAIN_SERVE_BURST, b.tokens + ((now - b.at) * CHAIN_SERVE_PER_SECOND) / 1000);
    b.at = now;
    if (b.tokens < 1) { this._noteDrop('role-chain-over-rate', session.nodeId, { frame: 'role-chain-fetch' }); return; }
    b.tokens -= 1;
    const anchorId = this._anchor && this._anchor.nodeId;
    const out = [];
    const seen = new Set();
    const visit = (nodeId, depth) => {
      if (depth > 8 || out.length >= CHAIN_ANSWER_MAX) return;
      for (const g of this._roleGrants.grantsFor(nodeId)) {
        if (out.length >= CHAIN_ANSWER_MAX) return;
        if (seen.has(g.sig)) continue;
        seen.add(g.sig);
        if (g.grantedBy !== anchorId) visit(g.grantedBy, depth + 1); // the grantor's own chain first: top-down
        if (out.length < CHAIN_ANSWER_MAX) out.push(g);
      }
    };
    for (const id of msg.grantees.slice(0, CHAIN_FETCH_MAX_GRANTEES)) if (typeof id === 'string' && id && id.length <= 256) visit(id, 0);
    this._chainStats.served++;
    session.send({ type: 'role-chain', reqId, grants: out });
  }

  /**
   * This node's own store tally: emitted = CMBs it authored (no peerId), admitted = CMBs
   * it accepted from peers (remixed in, has peerId), memory = total. The node is the only
   * authority on its own sovereign store, so this is what it self-reports to the mesh.
   * @returns {{ name: string, nodeId: string, emitted: number, admitted: number, memory: number, at: number }}
   * @private
   */
  _nodeStats() {
    const s = this._store.stats();
    return { name: this.name, nodeId: this.nodeId, emitted: s.local, admitted: s.peer, memory: s.total, at: Date.now() };
  }

  /**
   * Gossip this node's memory stats to the roster as a lightweight `node-stats` frame
   * (metadata, NOT a CAT7 CMB — so it never enters a cognition stream or SVAF). Lets any
   * observer show real emitted/admitted counts for this node even when its store lives on
   * another machine and is unreadable there. Best-effort; never throws into the timer.
   * @private
   */
  _emitNodeStats() {
    try { this._gossipToRoster({ type: 'node-stats', stats: this._nodeStats() }); }
    catch (err) { this._log(`node-stats emit failed: ${err.message}`); }
  }

  /**
   * Ingest a peer's gossiped node-stats: surface it as a `node-stats` event for hosts
   * (e.g. the Mesh Edge observer) to render. Self-reported and unsigned — it's a
   * convenience metric, not an authority claim, so it is taken at face value and not
   * stored. Ignores our own echo.
   * @private
   */
  _ingestNodeStats(stats, fromPeerId) {
    if (!stats || !stats.name || stats.nodeId === this.nodeId) return;
    this.emit('node-stats', stats);
  }

  /**
   * Build + sign an Admission Attestation for a CMB this node just gated — the
   * authoritative, durable per-category gating record (MMP admission-attestation
   * layer). Binds the gated CMB (`of`), this node's identity (`by`), the roster,
   * the overall + per-category verdict, this node's CLAIMED lifecycle role, and the
   * per-attester hash-chain position (`seq`/`prev`), all under an Ed25519 signature
   * (same key as CMB signing). `role` is claimed — consumers verify it against the
   * rooted role-grant chain (sym-core `verifyAttestationRole`), never the stamp.
   * Returns the signed attestation, or null if signing fails.
   * @param {string} of - the gated (incoming) CMB key
   * @param {string} verdict - overall decision (aligned|guarded|redundant|rejected)
   * @param {object} categoryVerdicts - per-CAT7-category verdict map (Phase A output)
   * @param {string} method - 'neural' | 'heuristic'
   * @private
   */
  _buildAdmissionAttestation(of, verdict, categoryVerdicts, method) {
    const att = {
      of,
      by: this.nodeId,
      at: Date.now(),
      roster: this._room,
      method,
      verdict,
      categories: categoryVerdicts,
      role: this._resolvedRole(),
      seq: ++this._attestSeq,
      prev: this._attestHead,
    };
    try {
      signAttestation(att, this._identity.privateKey);
      // Peers refuse a signature not spelled canonically; one of ours never is, and is never recorded.
      if (!isCanonicalSig(att.sig)) throw new Error('signature not in canonical form');
      // Advance the per-attester chain: the next attestation's `prev` is this one's
      // signature hash, so any dropped attestation breaks the link (omission-evidence).
      this._attestHead = crypto.createHash('sha256').update(att.sig).digest('hex');
      // Index it — every gating event this node makes enters its own chain + the
      // per-CMB audit trail, whether or not it produced a stored remix.
      this._attestations.record(att);
      // Gossip it to the roster so any member can reconstruct the cross-mesh audit
      // trail for this CMB. _peers are same-room (mDNS service-type isolation), so
      // the fan-out is roster-scoped by construction.
      this._gossipAttestation(att);
      // Periodically commit a witnessed checkpoint over the chain (omission-evidence).
      this._maybeCheckpoint();
      return att;
    } catch (err) {
      this._log(`Admission attestation signing failed: ${err.message}`);
      this._attestSeq--; // unspent seq — keep the chain contiguous
      return null;
    }
  }

  /**
   * Every recorded attestation about a gated CMB — this node's audit trail for it
   * (plus roster peers' attestations received via gossip).
   * @param {string} cmbKey — the gated CMB key (`of`)
   * @returns {object[]}
   */
  attestationsFor(cmbKey) {
    return this._attestations.byCmb(cmbKey);
  }

  /**
   * Aggregate every attestation about a CMB into a verdict WEIGHTED BY EARNED AUTHORITY
   * (MMP §6.4/§6.5). The per-attestation `verifyAttestationRole` check answers "is this
   * one attester's claimed role real"; this answers "what does the roster, weighted by
   * who actually holds rank, conclude about this CMB". An anchor's admit outweighs a
   * participant's; a node over-claiming a role it never earned is down-weighted to its
   * resolved rank and surfaced as evidence, not silently trusted.
   *
   * Each attestation is (1) signature-verified against the attester's key from the roster
   * registry — unverifiable ones are EXCLUDED, never weighted — and (2) role-resolved at
   * its own `at` (role-at-time) from the rooted grant chain. Weight = 2^rank
   * (participant 1, validator 2, anchor 4): everyone counts, earned rank counts more. The
   * overall and per-CAT7-category verdicts are weighted tallies; `confidence` is the dominant
   * verdict's share of total weight.
   * @param {string} cmbKey — the gated CMB key (`of`)
   * @returns {{ of: string, total: number, weight: number, byRole: object, overall: object,
   *   categories: object, mismatches: object[], excluded: object[] }}
   */
  aggregateAttestations(cmbKey) {
    const atts = this._attestations.byCmb(cmbKey);
    const overall = Object.create(null);   // verdict -> summed weight
    const categories = Object.create(null);    // cat7 category -> { verdict -> weight }
    const byRole = { participant: 0, validator: 0, anchor: 0 };
    const mismatches = [];
    const excluded = [];
    let total = 0;
    let weight = 0;

    for (const att of atts) {
      // (1) signature gate — an attestation we cannot verify is evidence, not a vote.
      const key = this._identityKey(att.by);
      if (!key) { excluded.push({ by: att.by, reason: 'unknown-key' }); continue; }
      if (!verifyAttestation(att, key).valid) { excluded.push({ by: att.by, reason: 'bad-signature' }); continue; }

      // (2) resolve the attester's EARNED role at the time it attested (role-at-time).
      const rr = verifyAttestationRole(att, (id, at) => this.resolveRole(id, at));
      if (!rr.matches) mismatches.push({ by: att.by, claimed: rr.claimed, resolved: rr.resolved });
      const w = 2 ** roleRank(rr.resolved); // participant 1, validator 2, anchor 4

      total += 1;
      weight += w;
      byRole[rr.resolved] = (byRole[rr.resolved] || 0) + 1;
      if (att.verdict) overall[att.verdict] = (overall[att.verdict] || 0) + w;
      for (const [f, v] of Object.entries(att.categories || {})) {
        if (!categories[f]) categories[f] = Object.create(null);
        categories[f][v] = (categories[f][v] || 0) + w;
      }
    }

    return {
      of: cmbKey,
      total,
      weight,
      byRole,
      overall: summarizeTally(overall, weight),
      categories: Object.fromEntries(Object.entries(categories).map(([f, t]) => [f, summarizeTally(t, weight)])),
      mismatches,
      excluded,
    };
  }

  /**
   * Gossip an attestation to roster peers on the dedicated `attestation` frame.
   * A dedicated frame (not remix re-broadcast) avoids the echo-storm guard, and the
   * peer set is same-room by mDNS isolation, so this is roster-scoped. `exceptPeerId`
   * skips the peer a relayed attestation came from (relay-once epidemic spread).
   * @private
   */
  _gossipAttestation(att, exceptPeerId = null) {
    this._gossipToRoster({ type: 'attestation', attestation: att }, exceptPeerId);
  }

  /** Send a frame to every roster peer (same-room by mDNS isolation), optionally
   *  skipping the one a relayed item came from (relay-once epidemic spread). */
  _gossipToRoster(frame, exceptPeerId = null) {
    if (!frame || !this._peers || this._peers.size === 0) return;
    for (const [peerId, peer] of this._peers) {
      if (peerId === exceptPeerId) continue;
      // The attestation family rides only on sessions that selected sym-attest-v1 (§16.3).
      if (!this._sessionTakes(peer.transport, frame.type)) continue;
      try { peer.transport.send(frame); } catch { /* transient peer — skip */ }
    }
  }

  /** Commit a checkpoint every `_checkpointInterval` gating events. @private */
  _maybeCheckpoint() {
    if (this._checkpointInterval > 0 && this._attestSeq > 0 && this._attestSeq % this._checkpointInterval === 0) {
      this._emitCheckpoint();
    }
  }

  /**
   * Build, sign, record, and gossip a checkpoint: a Merkle root over this node's
   * own attestation chain (the ordered signatures, seq 1..N). Roster peers witness
   * it; thereafter dropping any attestation ≤ N diverges from the committed root.
   * @returns {object|null} the checkpoint, or null on failure.
   * @private
   */
  _emitCheckpoint() {
    const chain = this._attestations.chainOf(this.nodeId);
    if (chain.length === 0) return null;
    const cp = {
      type: 'checkpoint',
      by: this.nodeId,
      roster: this._room,
      upto_seq: chain[chain.length - 1].seq,
      root: merkleRoot(chain.map(a => a.sig)),
      at: Date.now(),
    };
    try {
      signCheckpoint(cp, this._identity.privateKey);
      if (!isCanonicalSig(cp.sig)) throw new Error('signature not in canonical form');
      this._attestations.recordCheckpoint(cp);
      this._gossipToRoster({ type: 'checkpoint', checkpoint: cp });
      return cp;
    } catch (err) {
      this._log(`Checkpoint signing failed: ${err.message}`);
      return null;
    }
  }

  /**
   * Ingest a checkpoint gossiped by a roster peer: roster-scope check, verify the
   * attester's signature against its authenticated key, record, WITNESS it (this
   * node countersigns "I saw attester's chain to N with root R"), and relay-once.
   * @private
   */
  _ingestCheckpoint(cp, fromPeerId) {
    if (!cp || !cp.by || cp.upto_seq === undefined || !cp.root || !sigOk(cp.sig)) return { ok: false, reason: 'malformed' };
    if (cp.roster && this._room && cp.roster !== this._room) return { ok: false, reason: 'roster-mismatch' };
    // A position is an integer; the signature covers its text, so a re-spelled one is refused here,
    // before any signature check. A copy of a held checkpoint (same position, same root), of a
    // conflicting one already refused, or one older than every position held, is dropped unverified:
    // under the witness storm most of a node's thread went to verifying copies it already held.
    // Only a new statement spends the peer's budget, and it does so before its signature is checked.
    // Nothing unverified changes any state.
    if (!isPosition(cp.upto_seq)) return { ok: false, reason: 'malformed' };
    const held = this._attestations.checkpointAt(cp.by, cp.upto_seq);
    if (held && held.root === cp.root) return { ok: false, reason: 'duplicate' };
    if (this._attestations.conflictAt(cp.by, cp.upto_seq)?.root === cp.root) return { ok: false, reason: 'duplicate' };
    // A further root for a position already proven conflicted adds nothing: the evidence is held, and
    // a conflict is neither stored nor relayed. So it is dropped here, before the budget and the
    // signature, and one attester's equivocation costs at most one signature check per position it
    // holds (positions come at its rate, below), not one per root it signs.
    if (this._attestations.hasConflict(cp.by, cp.upto_seq)) return { ok: false, reason: 'conflict' };
    if (this._attestations.isStale(cp.by, cp.upto_seq)) return { ok: false, reason: 'stale' };
    if (!isCanonicalSig(cp.sig)) return this._refuseSpelling(fromPeerId, 'checkpoint', cp.by);
    const key = this._identityKey(cp.by);
    if (!key) return { ok: false, reason: 'unknown-attester-key' };
    if (!this._gossipBudget(fromPeerId, 'checkpoint', cp.by)) return { ok: false, reason: 'over-budget' };
    if (!verifyCheckpoint(cp, key).valid) return { ok: false, reason: 'bad-signature' };
    this._roster.noteVerified(cp.by); // something verified under its binding (design D3)
    // A new position is taken at most at its attester's rate, whichever peer brings it: past that it is
    // not stored, witnessed or relayed. Checked after the signature, so no one else can spend it. A
    // second root for a held position is the evidence of equivocation, kept once and free (a third is
    // dropped above).
    if (!held && !this._checkpointRateOk(cp.by, fromPeerId)) return { ok: false, reason: 'over-rate' };
    const r = this._attestations.recordCheckpoint(cp);
    if (r.reason === 'conflict' && r.first) {
      // Two signed roots for one position: equivocation, or a chain restarted after a lost log.
      this._log(`[sym-security] conflicting checkpoint from ${String(cp.by).slice(0, 8)} at ${cp.upto_seq}: kept root ${String(r.keptRoot).slice(0, 12)}, refused ${String(cp.root).slice(0, 12)}`);
      this.emit('metric', { type: 'attestation-conflict', kind: 'checkpoint', attester: cp.by, upto_seq: cp.upto_seq, keptRoot: r.keptRoot, otherRoot: cp.root });
    }
    if (r.stored) {
      this._gossipToRoster({ type: 'checkpoint', checkpoint: cp }, fromPeerId); // relay-once
      this._witnessCheckpoint(cp); // countersign as a roster witness
    }
    return { ok: r.stored, reason: r.reason };
  }

  /**
   * Spend one token of the PROVEN peer a NEW gossiped statement arrived from, and one of the shared
   * ceiling, before its signature is checked (see GOSSIP_PER_SECOND and GOSSIP_NEW_LANE). An honest
   * peer relays only what it has verified and stored, so its budget carries no forgeries. Both refill,
   * so a peer that stops flooding is heard again within burst/rate seconds. A dropped frame changes
   * nothing: it is not marked seen, so another peer's copy is taken. O(1).
   * @returns {boolean} whether the frame may be verified
   * @private
   */
  _gossipBudget(peerId, type, author) {
    const now = this._gossipClock();
    const b = bucketOf(this._gossipBuckets, peerId, this._gossipRate, this._gossipBurst, this._gossipNewLane, now, GOSSIP_MAX_PEERS);
    const all = refill(this._gossipGlobal, this._gossipGlobalRate, this._gossipGlobalBurst, now);
    if (b.tokens >= 1 && all.tokens >= 1) { b.tokens -= 1; all.tokens -= 1; return true; }
    // A drop by the ceiling is said in one report for all peers, not one per id: ids are free to mint,
    // so one report each would let a flood of them buy a log line a frame.
    if (b.tokens >= 1) this._noteDrop('gossip-over-ceiling', '*', { frame: type, author, peer: peerId });
    else this._noteDrop('gossip-over-budget', peerId, { frame: type, author });
    return false;
  }


  /**
   * Take one of an attester's checkpoint tokens (see CHECKPOINTS_PER_SECOND), keyed by the attester
   * whose signature was just checked, never by the peer that delivered it. Past the rate the checkpoint
   * is counted and said like a budget drop (`checkpoint-over-rate`, naming the attester and the peers
   * that brought it). O(1). @returns {boolean} whether the checkpoint may be taken
   * @private
   */
  _checkpointRateOk(attester, fromPeerId) {
    if (takeToken(this._checkpointBuckets, attester, this._checkpointRate, this._checkpointBurst, this._gossipClock(), GOSSIP_MAX_PEERS)) return true;
    this._noteDrop('checkpoint-over-rate', attester, { frame: 'checkpoint', peer: fromPeerId });
    return false;
  }

  /**
   * Refuse a gossiped statement whose signature is not spelled canonically (64 bytes, unpadded
   * base64url), before anything else is spent on it. Base64url decoding ignores padding, whitespace and
   * stray characters, so one signature can be spelled many ways that all verify; but the chain hash and
   * the Merkle root are computed over the signature as written, so only the spelling its signer wrote
   * may be stored. Every signer sym knows writes that one. Counted and said like a budget drop.
   * @private
   */
  _refuseSpelling(peerId, type, author) {
    this._noteDrop('signature-not-canonical', peerId, { frame: type, author });
    return { ok: false, reason: 'non-canonical-signature' };
  }

  /**
   * Count gossip dropped unverified, for `metric` under `key` (the delivering peer), and say it at most
   * once per GOSSIP_REPORT_MS per key: the first drop at once, the rest when that window closes, so
   * every drop is counted even when the flood stops. O(1); at most GOSSIP_MAX_PEERS reports are held,
   * the least recently dropped said and let go first.
   * @private
   */
  _noteDrop(metric, key, { frame, author, peer } = {}) {
    const now = this._gossipClock();
    const id = `${metric}|${key}`;
    const reports = this._dropReports;
    let r = reports.get(id);
    if (r) reports.delete(id);
    else {
      r = { metric, key, dropped: 0, frames: {}, authors: new Set(), peers: new Set(), reportedAt: -Infinity, timer: null };
      if (reports.size >= GOSSIP_MAX_PEERS) {
        const [oldId, old] = reports.entries().next().value;
        reports.delete(oldId);
        this._sayDrops(old, now);
      }
    }
    reports.set(id, r); // most recently dropped last
    if (metric === 'gossip-over-budget' || metric === 'gossip-over-ceiling') this._metrics.gossipOverBudget++;
    else if (metric === 'signature-not-canonical') this._metrics.signaturesNotCanonical++;
    else if (metric === 'checkpoint-over-rate') this._metrics.checkpointsOverRate++;
    r.dropped++;
    if (frame) r.frames[frame] = (r.frames[frame] || 0) + 1;
    if (author && r.authors.size < 16) r.authors.add(String(author));
    if (peer && r.peers.size < 16) r.peers.add(String(peer));
    if (now - r.reportedAt >= GOSSIP_REPORT_MS) this._sayDrops(r, now);
    else if (!r.timer) {
      r.timer = setTimeout(() => {
        r.timer = null;
        try { this._sayDrops(r); } catch (err) { this._log(`Gossip drop report failed: ${err && err.message}`); }
      }, Math.max(0, GOSSIP_REPORT_MS - (now - r.reportedAt)));
      if (typeof r.timer.unref === 'function') r.timer.unref();
    }
  }

  /**
   * Say what was dropped under one report since it was last said: one log line and one metric. For a
   * peer: `{ type, fromPeerId, from, dropped, frames: {attestation, checkpoint, witness}, authors (up
   * to 16 signers named by what was dropped) }`, plus `perSecond` for `gossip-over-budget`. For
   * `gossip-over-ceiling`, the drops of every peer by the shared ceiling: `{ type, dropped, frames,
   * authors, fromPeerIds (up to 16), perSecond }`. For `checkpoint-over-rate`: `{ type, attester,
   * dropped, fromPeerIds (up to 16), perSecond }`. @private
   */
  _sayDrops(r, now = this._gossipClock()) {
    if (r.timer) { clearTimeout(r.timer); r.timer = null; }
    if (!r.dropped) return;
    let ev;
    let line;
    if (r.metric === 'checkpoint-over-rate') {
      ev = { type: r.metric, attester: r.key, dropped: r.dropped, fromPeerIds: [...r.peers], perSecond: this._checkpointRate };
      line = `Checkpoints from ${String(r.key).slice(0, 8)} over their rate (${this._checkpointRate}/s): ${ev.dropped} not stored, witnessed or relayed, brought by ${ev.fromPeerIds.map((id) => String(id).slice(0, 8)).join(', ')}`;
    } else if (r.metric === 'gossip-over-ceiling') {
      ev = { type: r.metric, dropped: r.dropped, frames: { ...r.frames }, authors: [...r.authors], fromPeerIds: [...r.peers], perSecond: this._gossipGlobalRate };
      const what = Object.entries(ev.frames).map(([t, n]) => `${n} ${t}`).join(', ');
      line = `Gossip over the ceiling all peers share (${this._gossipGlobalRate}/s): ${ev.dropped} new statement(s) dropped unverified (${what}), from ${ev.fromPeerIds.map((id) => String(id).slice(0, 8)).join(', ')}`;
    } else {
      const name = this._peers?.get(r.key)?.name || null;
      ev = { type: r.metric, fromPeerId: r.key, from: name || r.key, dropped: r.dropped, frames: { ...r.frames }, authors: [...r.authors] };
      const what = Object.entries(ev.frames).map(([t, n]) => `${n} ${t}`).join(', ');
      if (r.metric === 'gossip-over-budget') {
        ev.perSecond = this._gossipRate;
        line = `Gossip from ${ev.from} over its budget (${this._gossipRate}/s): ${ev.dropped} new statement(s) dropped unverified (${what})`;
      } else {
        line = `Gossip from ${ev.from}: ${ev.dropped} statement(s) refused unverified, signature not in canonical form (${what})`;
      }
    }
    // Reset first, so a throwing sink cannot make the same drops be said twice; and the sink is
    // contained, so it cannot take a frame's handling or the node's shutdown with it. The totals
    // are kept in metrics() either way.
    this._resetDrops(r, now);
    try {
      this._log(line);
      this.emit('metric', ev);
    } catch { /* a log or metric sink must not break gossip or shutdown */ }
  }

  /** @private A report was said: start counting again. */
  _resetDrops(r, now) {
    r.dropped = 0;
    r.frames = {};
    r.authors = new Set();
    r.peers = new Set();
    r.reportedAt = now;
  }

  /** Countersign a checkpoint (witness) and gossip the witness. @private */
  _witnessCheckpoint(cp) {
    if (cp.by === this.nodeId) return; // don't witness your own
    // Once per checkpoint, across restarts: a second signing is a second copy of the same
    // statement, and two copies in circulation were relayed back and forth without end.
    if (this._attestations.hasWitnessed(cp.by, cp.upto_seq, this.nodeId)) return;
    const w = {
      type: 'witness',
      attester: cp.by,
      roster: cp.roster,
      upto_seq: cp.upto_seq,
      root: cp.root,
      by: this.nodeId,
      role: this._resolvedRole(),
      at: Date.now(),
    };
    try {
      signWitness(w, this._identity.privateKey);
      if (!isCanonicalSig(w.sig)) throw new Error('signature not in canonical form');
      this._attestations.recordWitness(w);
      this._gossipToRoster({ type: 'witness', witness: w });
    } catch (err) {
      this._log(`Witness signing failed: ${err.message}`);
    }
  }

  /**
   * Ingest a witness gossiped by a roster peer: roster check, verify the WITNESS's
   * signature against its authenticated key, record, relay-once.
   * @private
   */
  _ingestWitness(w, fromPeerId) {
    if (!w || !w.attester || w.upto_seq === undefined || !w.root || !w.by || !sigOk(w.sig)) return { ok: false, reason: 'malformed' };
    if (w.roster && this._room && w.roster !== this._room) return { ok: false, reason: 'roster-mismatch' };
    if (!isPosition(w.upto_seq)) return { ok: false, reason: 'malformed' };
    // A copy of a witness held or waiting, or of a conflicting one already refused: dropped unverified.
    const held = this._attestations.witnessSeen(w.attester, w.upto_seq, w.by);
    if (held && held.root === w.root) return { ok: false, reason: 'duplicate' };
    if (this._attestations.witnessConflictRoot(w.attester, w.upto_seq, w.by) === w.root) return { ok: false, reason: 'duplicate' };
    if (!isCanonicalSig(w.sig)) return this._refuseSpelling(fromPeerId, 'witness', w.by);
    const key = this._identityKey(w.by);
    if (!key) return { ok: false, reason: 'unknown-witness-key' };
    if (!this._gossipBudget(fromPeerId, 'witness', w.by)) return { ok: false, reason: 'over-budget' };
    if (!verifyWitness(w, key).valid) return { ok: false, reason: 'bad-signature' };
    this._roster.noteVerified(w.by);
    const r = this._attestations.recordWitness(w);
    if (r.stored) this._gossipToRoster({ type: 'witness', witness: w }, fromPeerId);
    if (r.reason === 'conflict' && r.first) {
      this._log(`[sym-security] conflicting witness from ${String(w.by).slice(0, 8)} for ${String(w.attester).slice(0, 8)} at ${w.upto_seq}: kept root ${String(r.keptRoot).slice(0, 12)}, refused ${String(w.root).slice(0, 12)}`);
      this.emit('metric', { type: 'attestation-conflict', kind: 'witness', attester: w.attester, upto_seq: w.upto_seq, witness: w.by, keptRoot: r.keptRoot, otherRoot: w.root });
    }
    return { ok: r.stored, reason: r.reason };
  }

  /**
   * Reconcile an attester's chain against its latest checkpoint — the omission test.
   * Recomputes the Merkle root over the chain this node holds up to the checkpoint's
   * `upto_seq` and compares it to the committed (and witnessed) root. A mismatch with
   * a complete local chain means tampering; a mismatch with a gap means an attestation
   * was suppressed. Returns the witnessed-status too (how many roster peers countersigned).
   * @param {string} by — attester nodeId
   * @returns {{ checkpoint: object|null, consistent: boolean, complete: boolean, gaps: number[], witnesses: number, witnessedRoot: string|null, recomputedRoot: string|null }}
   */
  reconcileChain(by) {
    const cp = this._attestations.latestCheckpoint(by);
    if (!cp) return { checkpoint: null, consistent: true, complete: true, gaps: [], witnesses: 0, witnessedRoot: null, recomputedRoot: null };
    const chain = this._attestations.chainOf(by).filter(a => a.seq <= cp.upto_seq);
    const present = new Set(chain.map(a => a.seq));
    const gaps = [];
    for (let s = 1; s <= cp.upto_seq; s++) if (!present.has(s)) gaps.push(s);
    const recomputedRoot = merkleRoot(chain.map(a => a.sig));
    const consistent = recomputedRoot === cp.root;
    return {
      checkpoint: cp,
      consistent,
      // The attester signed another root for this position too (equivocation, or a chain restarted
      // after a lost log): an inconsistency here is that, not tampering by a third party.
      conflicted: this._attestations.hasConflict(by, cp.upto_seq),
      complete: gaps.length === 0,
      gaps,
      witnesses: this._attestations.witnessesFor(by, cp.upto_seq, cp.root).length,
      witnessedRoot: cp.root,
      recomputedRoot,
    };
  }

  /**
   * Ingest an attestation received from a roster peer: roster-scope check, drop a repeat, spend the
   * delivering peer's gossip budget, verify the attester's Ed25519 signature against its
   * authenticated identity key, rate-limit per (of,by), record, and relay-once on first sight
   * (epidemic spread). Returns the
   * outcome so the frame-handler can log. Verification of a RELAYED attester (one that
   * is not a direct peer) needs the permissioned-roster key registry — pending; in the
   * current fully-connected roster every attester is a direct peer.
   *
   * On first sight of a verified attestation this emits 'attestation-received', so an
   * observer (an author watching its CMB's admission, a mesh visualiser) sees a peer's
   * verdict as it lands instead of polling attestationsFor(). A duplicate, a rate-limited
   * copy, a roster mismatch, an unknown attester or a bad signature emits nothing.
   * @private
   */
  _ingestAttestation(att, fromPeerId, fromPeerName) {
    if (!att || !sigOk(att.sig) || !att.of || !att.by) return { ok: false, reason: 'malformed' };
    // Roster scope (defense in depth — gossip already stays in-room).
    if (att.roster && this._room && att.roster !== this._room) {
      return { ok: false, reason: 'roster-mismatch' };
    }
    // Verify against the attester's authenticated identity key. Known for a direct
    // peer (handshake key map); a relayed attester awaits the roster key registry.
    // A signature already held was verified when it was stored: a repeat is dropped before the
    // signature check, which is most of what a flood of repeats costs.
    // A signature not spelled as its signer wrote it is refused first (the chain hashes the signature
    // as written), before the repeat check, which then only ever looks up a canonical spelling: no
    // re-spelling is decoded. Only a new statement spends the peer's budget, before its signature is
    // checked.
    if (!isCanonicalSig(att.sig)) return this._refuseSpelling(fromPeerId, 'attestation', att.by);
    if (this._attestations.has(att.sig)) return { ok: false, reason: 'duplicate' };
    const attesterKey = this._identityKey(att.by);
    if (!attesterKey) return { ok: false, reason: 'unknown-attester-key' };
    if (!this._gossipBudget(fromPeerId, 'attestation', att.by)) return { ok: false, reason: 'over-budget' };
    const v = verifyAttestation(att, attesterKey);
    if (!v.valid) return { ok: false, reason: v.error || 'bad-signature' };
    this._roster.noteVerified(att.by);
    // Record (rate-limited as ingested). Relay-once only on first sight.
    const r = this._attestations.record(att, { ingested: true });
    if (r.stored) {
      this._gossipAttestation(att, fromPeerId);
      this._emitAttestationReceived(att, fromPeerId, fromPeerName);
    }
    return { ok: r.stored, reason: r.reason };
  }

  /**
   * Emit 'attestation-received' for an attestation that was just verified and recorded.
   *
   * Signed fields pass through as signed: `of`, `by`, `at`, `roster`, `verdict`, `seq`, `prev`,
   * `role`, and the seven CAT7 `categories` as the strings the signature covers (any other key is
   * unsigned and dropped), with `sig`/`sigAlg`, so verifyAttestation(event, key) re-checks it.
   * `role` is the attester's own CLAIM: a node can stamp any role and still sign validly, so
   * `roleResolved`/`roleMatches` give the role this node's grant chain resolves. What the signature
   * does not cover is named so: `methodUnsigned` is outside the signed bytes, so a relay could have
   * changed it, and `byName` is the label the peer announced; `by` is the identity.
   *
   * `verified` means the signature checked out against the key this node holds for `by`, and
   * `keySource` says where that key came from (design D3): 'anchor' (configured), 'proven' (a
   * Core Secure session proved it — trust on first PROVEN use when nothing else pinned it), 'pinned'
   * (an invite or a Legacy Import route) or 'grant' (vouched by an anchor-rooted grant); a
   * 'legacy-claim' never verifies, so it never appears here. `from` is the peer that delivered the
   * frame; `relayed` is true when that peer is not the attester, null when the deliverer is
   * unknown. `receivedAt` is this node's clock, not the attester's `at`.
   *
   * The event holds only primitives, frozen: an object-valued field is given as the string its
   * signature covers, so a listener can neither reach the stored record nor change what the next
   * listener sees. `roleClaimed` is the claim `roleMatches` compares with `roleResolved`
   * ('participant' when the attester stamped none), both as the strings the signature would cover. Each listener is called on its own: one that throws, or returns
   * a promise that rejects, is logged and cannot starve later listeners or undo the ingest. Listeners
   * run synchronously on the frame-ingest path (gossip has already gone out), so heavy work belongs
   * in a queue. An event that cannot be built is reported on 'metric' as 'attestation-event-dropped',
   * dispatched the same isolated way rather than through emit().
   * @private
   */
  _emitAttestationReceived(att, fromPeerId, fromPeerName) {
    if (this.listenerCount('attestation-received') === 0) return;
    const why = (e) => { try { return (e && e.message) || String(e); } catch { return 'unprintable error'; } };
    // A log sink that fails must not become the failure it is reporting.
    const note = (m) => { try { this._log(m); } catch { /* nothing left to tell */ } };
    const subject = `${String(att.of).slice(0, 12)} by ${String(att.by).slice(0, 8)}`;
    // The canonicalizer joins these with ToString, so String() of an object keeps the signed bytes.
    const signed = (v) => (v === null || v === undefined ? null : (typeof v === 'object' || typeof v === 'function') ? String(v) : v);
    let event;
    try {
      const categories = {};
      for (const f of CAT7_CATEGORIES) {
        const v = att.categories && att.categories[f];
        categories[f] = v ? String(v) : null; // the form canonicalCategories signs
      }
      const role = verifyAttestationRole(att, (id, at) => this.resolveRole(id, at));
      // As strings, the form the canonicalizer signs: ['anchor'] and 'anchor' claim the same, as do 2 and
      // '2'. Neither field is signed, and both default to 'participant', so String() never yields 'null'.
      const roleClaimed = String(role.claimed);
      const roleResolved = String(role.resolved);
      event = Object.freeze({
        of: signed(att.of),
        by: signed(att.by),
        byName: signed(this._peers.get(att.by)?.name),
        verdict: signed(att.verdict),
        categories: Object.freeze(categories),
        role: signed(att.role),
        roleClaimed,
        roleResolved,
        roleMatches: roleClaimed === roleResolved,
        methodUnsigned: signed(att.method),
        roster: signed(att.roster),
        at: signed(att.at),
        seq: signed(att.seq),
        prev: signed(att.prev),
        sig: signed(att.sig),
        sigAlg: signed(att.sigAlg),
        verified: true,
        keySource: this._roster.source(att.by) ?? null,
        from: signed(fromPeerName),
        fromPeerId: signed(fromPeerId),
        relayed: fromPeerId ? fromPeerId !== att.by : null,
        receivedAt: Date.now(),
      });
    } catch (err) {
      note(`attestation-received not emitted for ${subject}: ${why(err)}`);
      this._emitIsolated('metric', { type: 'attestation-event-dropped', of: signed(att.of), by: signed(att.by), reason: why(err) }, subject, why, note);
      return;
    }
    this._emitIsolated('attestation-received', event, subject, why, note);
  }

  /**
   * Call each listener of `name` on its own, in order, from a snapshot. Not this.emit(): that stops
   * at the first listener that throws and leaves an async listener's rejection unhandled. A throw
   * or a rejection is noted with `subject` and the next listener still runs. rawListeners() keeps
   * once() wrappers, so a once-listener still removes itself.
   * @private
   */
  _emitIsolated(name, payload, subject, why, note) {
    for (const listener of this.rawListeners(name)) {
      try {
        const r = listener.call(this, payload);
        if (r && typeof r.then === 'function') {
          r.then(undefined, (err) => note(`${name} listener rejected for ${subject}: ${why(err)}`));
        }
      } catch (err) {
        note(`${name} listener failed for ${subject}: ${why(err)}`);
      }
    }
  }

  /**
   * Chain-integrity check for an attester (default: this node) — the local half of
   * omission-evidence. Reports `seq` gaps (suppressed attestations) and `prev`
   * breaks (re-linked chains).
   * @param {string} [by] — attester nodeId; defaults to this node.
   * @returns {{ ok: boolean, gaps: number[], breaks: number[] }}
   */
  verifyAttestationChain(by = this.nodeId) {
    return this._attestations.verifyChain(by);
  }

  // ── Context Encoding ───────────────────────────────────────

  _initLocalState() {
    // Restore persisted CfC state if available — preserves slow-τ adaptation
    // across restarts. Without this, feedback modulation (Section 11) resets
    // and the agent must re-learn from stored CMB anchors.
    if (fs.existsSync(this._cfcStatePath)) {
      try {
        const saved = JSON.parse(fs.readFileSync(this._cfcStatePath, 'utf8'));
        if (saved.h1?.length === DIM && saved.h2?.length === DIM) {
          this._meshNode.updateLocalState(saved.h1, saved.h2, 0.8);
          this._log('CfC state restored from disk');
          return;
        }
      } catch (e) {
        this._log(`CfC state restore failed: ${e.message}`);
      }
    }

    // No persisted state — encode from stored CMBs or random init
    const context = this._buildContext();
    if (context.length > 5) {
      const { h1, h2 } = encode(context);
      this._meshNode.updateLocalState(h1, h2, 0.8);
    } else {
      const h1 = Array.from({ length: DIM }, () => (Math.random() - 0.5) * 0.1);
      const h2 = Array.from({ length: DIM }, () => (Math.random() - 0.5) * 0.1);
      this._meshNode.updateLocalState(h1, h2, 0.3);
    }
  }

  /**
   * Persist current CfC hidden state to disk.
   * Called after state updates to preserve slow-τ adaptation across restarts.
   */
  _persistCfCState() {
    try {
      const [h1, h2] = this._meshNode.coupledState();
      fs.writeFileSync(this._cfcStatePath, JSON.stringify({ h1, h2, savedAt: Date.now() }));
    } catch (e) {
      // Non-fatal — state will be re-encoded from CMBs on next restart
    }
  }

  _buildContext() {
    const parts = [];
    if (this._cognitiveProfile) parts.push(this._cognitiveProfile);
    const entries = this._store.allEntries().slice(0, 20);
    parts.push(...entries.map(e => e.content || ''));
    return parts.join('\n');
  }

  _runRetentionPurge() {
    // Unlimited retention: do not compact and do not purge. Returning before
    // compactByOrigin matters — compaction is what demotes entries to `cold`,
    // and purge() deletes cold CMBs that have no descendants. Skipping only the
    // purge would still let history rot into a deletable tier.
    if (!Number.isFinite(this._localRetentionSeconds) || !Number.isFinite(this._peerRetentionSeconds)) return;
    const localMs = this._localRetentionSeconds * 1000;
    const peerMs = this._peerRetentionSeconds * 1000;
    const compacted = this._store.compactByOrigin(localMs, peerMs);
    const purged = this._store.purge();
    if (compacted > 0 || purged > 0) {
      // When local == peer (the back-compat path), log the single
      // value to keep existing log-grep tooling working. When they
      // differ, surface both so operators can confirm the origin
      // discrimination is in effect.
      const retentionDesc = (this._localRetentionSeconds === this._peerRetentionSeconds)
        ? `retention: ${this._retentionSeconds}s`
        : `local: ${this._localRetentionSeconds}s, peer: ${this._peerRetentionSeconds}s`;
      this._log(`Retention purge: ${compacted} compacted, ${purged} removed (${retentionDesc})`);
    }
  }

  _reencodeAndBroadcast() {
    const context = this._buildContext();
    if (context.length < 5) return;

    const { h1, h2 } = encode(context);
    this._meshNode.updateLocalState(h1, h2, 0.8);
    // MMP v0.2.2: do not broadcast hidden state. SVAF (Xu, 2026,
    // arXiv:2604.03955, §3.4) requires that hidden states stay private to
    // each agent. The local state update above is sufficient for the
    // local CfC to evaluate future incoming CMBs at SVAF Layer 4.
    // Cognitive signals propagate to peers as CMBs only.
    this._persistCfCState();
  }

  /**
   * Update cognitive state from external context (e.g. Claude Code's memories).
   * Updates the local CfC only — MMP v0.2.2: hidden states never cross the
   * wire under SVAF (Xu, 2026, arXiv:2604.03955, §3.4). Cognitive signals
   * propagate to peers as CMBs via `remember()`, not as raw state.
   *
   * @param {string} text — context text to encode (min 5 chars)
   */
  updateContext(text) {
    if (!text || text.length < 5) return;
    const { h1, h2 } = encode(text);
    this._meshNode.updateLocalState(h1, h2, 0.8);
    this._persistCfCState();
  }

  /**
   * Share content with cognitively aligned peers without storing locally.
   * Used by ClaudeMemoryBridge — Claude Code's memory dir is the source of truth.
   * See MMP v0.2.0 Section 7 (Frame Types).
   *
   * @param {string} content — raw content to share
   * @param {object} [opts]
   * @param {object} [opts.cmb] — pre-built CMB; auto-created from content if omitted
   * @param {string} [opts.source] — creator name override
   * @returns {{ key: string, content: string, cmb: object, timestamp: number }}
   */
  shareWithPeers(content, opts = {}) {
    // Core Secure (design D4): only a signed v2.0 record travels, sealed per session. A caller's own
    // record is sent as it is (the session refuses one that is not signed v2.0); otherwise the
    // content is minted here as this node's record, signed, and not stored.
    let cmb = opts.cmb;
    if (!cmb) {
      cmb = createCMB({ categories: { focus: String(content || '') }, createdBy: opts.source || this.name, room: this._room, emitV2: true, createdByNodeId: this.nodeId });
      cmb.metadata.assertionId = assertionIdV2_0(cmb);
      this._signOrThrow(cmb, 'CMB signing failed');
    }

    this._meshNode.coupledState();

    const ts = Date.now();
    let shared = 0;
    for (const [peerId, peer] of this._peers) {
      // Only a frame a transport took counts: this counted every peer, so a block no peer could take
      // (too large, a closed socket) was logged as shared with all of them.
      const sent = trySend(peer.transport, { type: 'cmb', timestamp: ts, cmb });
      if (sent.ok) shared++;
      else this._log(`Not shared with ${peer.name || peerId.slice(0, 8)}: ${NOT_SENT_SAID[sent.reason] || sent.reason}${sent.bytes ? ` (${sent.bytes} bytes)` : ''}`);
    }

    this._log(`Shared: "${String(content).slice(0, 50)}${String(content).length > 50 ? '...' : ''}" → ${shared}/${this._peers.size} peers`);
    return { key: recordKey(cmb), content, cmb, timestamp: ts };
  }

  // ── Lifecycle ──────────────────────────────────────────────

  /**
   * Start the node: TCP server, Bonjour discovery, relay, heartbeats, retention.
   * See MMP v0.2.0 Section 4 (Transport), Section 5 (Connection).
   * @returns {Promise<void>}
   */
  async start() {
    if (this._running) return;
    this._running = true;
    this._metrics.startedAt = Date.now();

    // Build the memory index WITHOUT blocking the event loop (see MemoryStore#load). Awaited
    // before anything below can recall or admit, so the node never serves an unbuilt store; a
    // caller that reached the store earlier has already built it synchronously, and this is a no-op.
    await this._store.load();

    // Track pending Bonjour connections to prevent duplicate connect attempts.
    // dns-sd may resolve the same peer multiple times.
    this._pendingBonjour = new Set();

    // Wire discovery events to sessions (design D2). A discovery record is a CANDIDATE: an endpoint
    // and the nodeId it claims. It decides only whom to dial; nothing about the peer exists until the
    // session the dial opens is confirmed.
    this._discovery.on('peer-found', (address, port, foundId, foundName, info = {}) => {
      // An advertisement's node-id/node-name are what the advertiser chose (wire-identity.js).
      const peerId = wireNodeId(foundId);
      if (!peerId || peerId === this.nodeId) return;
      const peerName = wireName(foundName);
      // A record without TXT mmp=2.0 is a legacy node: never dialled as Core Secure. Only a
      // configured Legacy Import route reaches it (design D7), by its own endpoint.
      if (!info || info.mmp !== '2.0') return;
      // §5.1: the lexicographically smaller nodeId initiates; the other MUST NOT.
      if (!(this.nodeId < peerId)) return;
      // Skip if already dialling (dns-sd resolves the same peer multiple times), or already holding a
      // live LAN session with it.
      if (this._pendingBonjour.has(peerId)) return;
      const existing = this._peers.get(peerId);
      const t = existing && existing.transports && existing.transports.get('bonjour');
      if (t && !t.closed) return;
      this._pendingBonjour.add(peerId);
      this._connectToPeer(address, port, peerId, peerName);
    });
    this._discovery.on('inbound-connection', (transport, firstFrame, remote) => {
      // Discovery has already required the first frame to be client-hello (the Core Secure listener
      // takes nothing else) and cleared its own deadline; the session's handshake timeout governs
      // from here. Through the guard: a hello this node cannot take closes the connection.
      const ok = this._guardInbound('?', 'inbound', firstFrame, 'lan', () => {
        const session = this._attachTransport(transport, { role: 'server', kind: 'bonjour', remote });
        session.receiveWire(firstFrame);
      });
      if (!ok) { try { transport.close(); } catch { /* already gone */ } }
    });
    // A legacy `handshake` on the Core Secure listener is refused at once (discovery closed the
    // socket); counted, and said at most once a minute per address.
    this._discovery.on('legacy-hello-refused', (remote) => this._noteLegacyRefusal(remote));

    this._port = await this._discovery.start(this._identity, (msg) => this._log(msg));

    if (this._relayUrl) {
      this._relay.connect();
    }
    this._legacy.start();

    this._heartbeatTimer = setInterval(() => this._checkHeartbeats(), this._heartbeatInterval);
    this._encodeTimer = setInterval(() => this._reencodeAndBroadcast(), this._encodeInterval);

    // Self-reported memory stats — a node is sovereign over its store, so it EMITS its
    // own {emitted, admitted, memory} counts to the roster (a tiny metadata frame, not a
    // CAT7 CMB) so any observer can show real counts for it even across machines, where
    // its store is unreadable. Once on start, then on an interval.
    this._emitNodeStats();
    this._statsTimer = setInterval(() => this._emitNodeStats(), this._statsInterval);

    // Retention purge — run on start + every hour; first-contact key bindings that verified nothing
    // and were not seen for 30 days expire on the same beat (design D3).
    this._runRetentionPurge();
    this._purgeTimer = setInterval(() => {
      this._runRetentionPurge();
      try { const n = this._roster.expire(); if (n) this._log(`Key registry: ${n} first-contact binding(s) that verified nothing expired (30 days unseen)`); } catch (err) { this._log(`Key registry expiry failed: ${err.message}`); }
    }, 3600_000);

    this._log(`Started (port: ${this._port}, id: ${this._identity.nodeId.slice(0, 8)}${this._relayUrl ? ', relay: ' + this._relayUrl : ''})`);
  }

  /**
   * Stop the node: close all peers, timers, relay, and discovery.
   * @returns {Promise<void>}
   */
  async stop() {
    // A coalesced wake-channel save still pending is written now (its timer is unref'd and would
    // not hold the process open), whether or not the node was started.
    this._wakeManager.flushWakeChannels();
    if (!this._running) {
      // An interior a host opened on a node it never started still ends with it.
      if (this._interior) this._interior.close();
      return;
    }
    this._running = false;

    if (this._heartbeatTimer) clearInterval(this._heartbeatTimer);
    if (this._encodeTimer) clearInterval(this._encodeTimer);
    if (this._statsTimer) clearInterval(this._statsTimer);
    if (this._purgeTimer) clearInterval(this._purgeTimer);
    for (const r of [...this._dropReports.values()]) { try { this._sayDrops(r); } catch { /* shutting down */ } }
    // A throttled inbox write still pending (a drain or an ack in the last second) is flushed,
    // or it is lost: the timer is unref'd and would not hold the process open.
    if (this._inboxPersistTimer) {
      clearTimeout(this._inboxPersistTimer);
      this._inboxPersistTimer = null;
      this._writeInbox();
    }

    this._relay.destroy();
    this._legacy.stop();
    if (this._interior) this._interior.close();

    // Every session, confirmed or not, ends with the node; a relay session tells its peer.
    for (const session of [...this._sessions]) {
      try { session.close('node-stopped'); } catch { /* shutting down */ }
    }
    this._sessions.clear();
    this._peers.clear();
    if (this._relaySessions) this._relaySessions.clear();
    for (const t of (this._relayRetry || new Map()).values()) clearTimeout(t.timer);
    if (this._relayRetry) this._relayRetry.clear();

    await this._discovery.stop();
    this._discovery.removeAllListeners();

    // Release the identity lock so a successor process (e.g. a fresh
    // restart) can claim this nodeId without waiting for stale-PID
    // detection. Best-effort: errors are swallowed because we're
    // shutting down anyway.
    if (this._releaseIdentityLock) {
      try { this._releaseIdentityLock(); } catch {}
      this._releaseIdentityLock = null;
    }

    this._log('Stopped');
  }

  // ── Memory (with cognitive coupling) ───────────────────────

  /**
   * Store a memory with structured CAT7 categories and broadcast to coupled peers.
   * See MMP v0.2.0 Section 6 (Memory), Section 7 (Frame Types), Section 14 (Remix).
   *
   * @param {object} categories — CAT7 categories: focus, issue, intent, motivation, commitment, perspective, mood
   * @param {object} [opts]
   * @param {object} [opts.cmb] — pre-built CMB; auto-created from categories if omitted
   * @param {Array<object>} [opts.parents] — parent CMBs for lineage (Section 14)
   * @param {Array<string>} [opts.tags] — optional tags for search
   * @param {string} [opts.to] — full peerId of a single target peer. When
   *   set, the CMB frame is emitted only to that peer (per MMP §4.4.4
   *   relay-routing envelope for targeted sends). When omitted (default),
   *   the frame is broadcast to all connected peers. The local store write
   *   happens in both cases — lineage stays intact even if the target peer
   *   is not currently connected, and remix-guard invariants (§15.7) are
   *   enforced identically for broadcast and targeted sends.
   * @param {*} [opts.payload] — optional opaque payload attached to the CMB
   *   alongside CAT7 categories. Rides the wire frame and the local store but is
   *   NOT part of cmbKey (CAT7 categories alone are the content-addressed
   *   identity, preserving cross-SDK CMB dedup with sym-core-swift). Used by
   *   substrate-level protocols that need to carry data beyond CAT7 — e.g.
   *   the LLM request/response substrate primitive (prompt + request_id in
   *   `llm-request` CMBs, response text + model in `llm-response` CMBs).
   *   Senders are responsible for ensuring CAT7 categories differ when payloads
   *   differ (e.g. unique request_id encoded in `focus`) to avoid store-side
   *   dedup collisions on the CAT7 hash.
   * @returns {object|null} stored entry, or null if duplicate or remix rejected
   */
  // ── Delivery inbox (pull-based receive) ────────────────────

  /** @private Buffer a delivered CMB into the inbox ring. */
  /** @private Load the persisted delivery feed — a restarted session drains
   *  what arrived before the restart instead of losing it. Best-effort: a
   *  missing or corrupt file starts empty, exactly like the old behavior. */
  _loadInbox() {
    try {
      const d = JSON.parse(fs.readFileSync(this._inboxFile, 'utf8'));
      if (Number.isSafeInteger(d.seq)) this._inboxSeq = d.seq;
      if (Number.isSafeInteger(d.cursor)) this._inboxCursor = d.cursor;
      if (Array.isArray(d.messages)) {
        // NEVER trust persisted entries to carry the fields this version relies on. seq and id
        // were introduced together (v0.10.0) and the durable feed crossed that boundary, so real
        // disks hold entries with seq-but-no-id — which surfaced as "[undefined]" and could never
        // be fetched (codex-mac, 2026-08-31) — and entries with neither, which `m.seq > cursor`
        // silently filtered out forever: loss wearing a working inbox. Normalize on restore:
        // known seqs advance the counter first, then missing seqs are minted ABOVE it (and above
        // the cursor), so a legacy entry surfaces once — redelivery is recoverable, silent loss
        // is not — and every entry gets the id its seq implies.
        const kept = d.messages.slice(-this._inboxMax);
        for (const m of kept) {
          if (Number.isSafeInteger(m.seq) && m.seq > this._inboxSeq) this._inboxSeq = m.seq;
        }
        for (const m of kept) {
          if (!Number.isSafeInteger(m.seq)) m.seq = ++this._inboxSeq;
          if (typeof m.id !== 'string' || !m.id) m.id = `in${String(m.seq).padStart(4, '0')}`;
        }
        this._inbox = kept;
      }
    } catch { /* fresh start */ }
  }

  /** @private Persist ring + seq + cursor. Throttled: at most one write per
   *  second, with a trailing write so the last message is never lost. */
  _persistInbox() {
    if (this._inboxPersistTimer) return;
    this._inboxPersistTimer = setTimeout(() => {
      this._inboxPersistTimer = null;
      this._writeInbox();
    }, 1000);
    if (this._inboxPersistTimer.unref) this._inboxPersistTimer.unref();
  }

  /** @private Write ring + seq + cursor now. */
  _writeInbox() {
    try {
      fs.writeFileSync(this._inboxFile, JSON.stringify({
        seq: this._inboxSeq, cursor: this._inboxCursor, messages: this._inbox,
      }));
    } catch { /* best-effort */ }
  }

  _pushInbox(entry) {
    if (!entry) return;
    const cmb = entry.cmb || {};
    const seq = ++this._inboxSeq;
    const id = `in${String(seq).padStart(4, '0')}`;
    // Later 'cmb-accepted' listeners (a channel's push path) read these to refer to the same
    // delivery by the same id instead of minting a second one.
    entry.inboxId = id;
    entry.inboxSeq = seq;
    this._inbox.push({
      seq,
      id,
      // A display label: the author's when its signature proved who wrote it, otherwise the peer that
      // delivered it. (It used to be the author's label whether or not anything proved it.) A label
      // is not unique — two node ids can each sign createdBy "alice" — so authorize on
      // author.nodeId, the proven identity, never on `from`.
      from: (entry.author?.nodeId && entry.author?.name)
        || entry.author?.via?.name
        || recordCreatedBy(cmb) || entry.source || 'unknown',
      author: entry.author || null,
      content: entry.content || '',
      categories: cmb.categories || null,
      // Preserve the opaque payload (sibling of categories, NOT inside it). Without
      // this it was dropped here, so any CMB pulled via node.inbox() lost its
      // payload — structured agent-to-agent data never survived the pull path,
      // only the channel-push path (which reads entry.cmb.payload directly).
      payload: cmb.payload ?? null,
      directed: !!entry.directed,
      remixed: entry.remixed,
      verified: entry._cmbVerified === true || entry.verified === true || undefined,
      key: recordKey(cmb) || entry.key || null,
      receivedAt: Date.now(),
    });
    // The ring evicts oldest-first. Eviction is free for a message that has
    // already been DRAINED — the session has it, the buffer is just recycling.
    // Evicting an UNDRAINED message is data loss: nobody has ever read it and
    // nothing will ever hand it over again. The two were indistinguishable
    // here, so a node that nothing pulls from silently shreds its own backlog
    // once it passes _inboxMax.
    //
    // Not hypothetical: sym-daemon-mac was measured at seq=96 with cursor=0 —
    // 96 messages, never drained once, still accumulating. At 500 it would
    // have begun discarding directed CMBs, oldest first, in silence.
    //
    // Because the cursor advances in seq order, the oldest entry is drained
    // whenever anything is, so this test needs no reordering: if the head is
    // undrained then the whole ring is, and that is exactly the loss case.
    while (this._inbox.length > this._inboxMax) {
      const oldest = this._inbox[0];
      if (oldest && oldest.seq > this._inboxCursor && oldest.acked) {
        // Read in full (inboxAck) but never drained: not lost, still counted.
        this._metrics.inboxAckedEvicted = (this._metrics.inboxAckedEvicted ?? 0) + 1;
      } else if (oldest && oldest.seq > this._inboxCursor) {
        this._metrics.inboxDropped = (this._metrics.inboxDropped ?? 0) + 1;
        this._log(
          `INBOX OVERFLOW — DISCARDING UNDRAINED ${oldest.id}${oldest.directed ? ' (DIRECTED)' : ''} ` +
          `from ${oldest.from}: ring full at ${this._inboxMax} and the cursor is at ${this._inboxCursor}. ` +
          `Nothing is draining this node.`,
        );
        this.emit('metric', {
          type: 'inbox-overflow-dropped',
          id: oldest.id, from: oldest.from, directed: !!oldest.directed, key: oldest.key,
        });
      }
      this._inbox.shift();
    }
    this._persistInbox();
  }

  /**
   * What this node is HOLDING for whoever pulls from it. A node is a terminus
   * the moment nothing drains it, and until now that state was invisible: the
   * inbox accumulated with no counter, no log and no way to ask.
   *
   * `undrainedDirected` is the number that matters — those are CMBs somebody
   * addressed to this node specifically and is entitled to believe arrived.
   *
   * @returns {{seq:number, cursor:number, undrained:number, undrainedDirected:number,
   *            oldestUndrainedAt:number|null, neverDrained:boolean, dropped:number, ackedEvicted:number}}
   */
  inboxStatus() {
    // An acked item was already read in full (inboxAck), so it is not owed to anyone.
    const undrained = this._inbox.filter((m) => m.seq > this._inboxCursor && !m.acked);
    return {
      seq: this._inboxSeq,
      cursor: this._inboxCursor,
      undrained: undrained.length,
      undrainedDirected: undrained.filter((m) => m.directed).length,
      oldestUndrainedAt: undrained.length ? (undrained[0].receivedAt ?? null) : null,
      // Distinct from "has a backlog": a node that has NEVER been drained is
      // not behind, it is unattended — the condition that hid five directed
      // CMBs, two of them founder words, for three days.
      neverDrained: this._inboxCursor === 0 && this._inboxSeq > 0
        && !(this._inbox.length > 0 && this._inbox.every((m) => m.acked)),
      dropped: this._metrics.inboxDropped ?? 0,
      ackedEvicted: this._metrics.inboxAckedEvicted ?? 0,
    };
  }

  /**
   * Pull received CMBs since the last drain — the receive counterpart to
   * remember() (send). Directed sym_send addressed to this node plus admitted
   * broadcasts land here regardless of whether a real-time push surface is
   * available. FIFO with a drain cursor so no message is skipped past `limit`.
   *
   * @param {object} [opts]
   * @param {boolean} [opts.peek=false] — return without advancing the cursor.
   * @param {number}  [opts.limit=50]   — max unread messages (oldest-first); acked ones are listed
   *   up to as many again, so a reply holds at most 2 × limit.
   * @param {number}  [opts.since]      — explicit cursor override (seq).
   * @returns {{ messages: object[], drained: number, remaining: number, cursor: number }}
   */
  inbox(opts = {}) {
    const limit = Math.max(1, Math.min(opts.limit || 50, this._inboxMax));
    const from = opts.since !== undefined ? opts.since : this._inboxCursor;
    const fresh = this._inbox.filter((m) => m.seq > from);
    // The limit counts what is still unread: an item already acked (read in full by id) comes back
    // marked, but does not use up a place a new delivery needed. Acked items are listed up to the
    // same limit; past it they are passed over (they were read), so a reply holds at most `limit`
    // unread and `limit` acked items: 2 × `limit` in all.
    const slice = [];
    let unread = 0, ackedListed = 0, passed = 0, lastSeq = null;
    for (const m of fresh) {
      if (!m.acked) { if (unread >= limit) break; unread++; }
      else if (ackedListed >= limit) { passed++; lastSeq = m.seq; continue; }
      else ackedListed++;
      slice.push(m);
      lastSeq = m.seq;
    }
    if (!opts.peek && lastSeq !== null) {
      this._inboxCursor = Math.max(this._inboxCursor, lastSeq);
      this._persistInbox(); // the drain moves the cursor — a restart must not replay it
    }
    return {
      messages: slice,
      drained: slice.length,
      remaining: fresh.length - slice.length - passed,
      cursor: this._inboxCursor,
    };
  }

  /**
   * Mark one inbox item as read in full, out of cursor order — a consumer that showed a
   * delivery by id (a channel's fetch of a pushed CMB) acks it so it stops counting as
   * undrained. The cursor is untouched: inbox() still returns the item, with `acked: true`,
   * so a drain can say "already read" instead of silently skipping it. Persisted with the ring.
   * @param {string} id — inbox id, e.g. "in0007"
   * @returns {boolean} true if the item exists and was newly acked; false if unknown or already acked
   */
  inboxAck(id) {
    const m = this._inbox.find((x) => x.id === id);
    if (!m || m.acked) return false;
    m.acked = true;
    this._persistInbox();
    return true;
  }

  /** Fetch one buffered inbox message by its id (e.g. "in0007"). */
  inboxGet(id) {
    return this._inbox.find((m) => m.id === id) || null;
  }

  remember(categories, opts = {}) {
    // Whether this call builds (and signs) the record, as opposed to forwarding a caller's opts.cmb.
    const builtHere = !opts.cmb;
    // Hoisted: the anti-paraphrase guard reads these before the record is built, and the flag
    // lifecycle reads them after it is stored. A caller supplying its own opts.cmb still needs
    // the same self/peer split.
    const parentKeys = (opts.parents || []).map((p) => p?.metadata?.key ?? p?.key).filter(Boolean);
    const peerParents = parentKeys.filter((k) => !this._ownKeys.has(k));

    if (!opts.cmb) {
      if (!categories || typeof categories !== 'object') {
        throw new Error('remember() requires CAT7 categories — the agent LLM extracts categories');
      }

      // §15.7 anti-paraphrase, split by WHOSE block is being parented (B-2).
      //
      // The guard is right about what it was written for — remixing a PEER without new domain
      // data is how agents paraphrase each other into noise. But it conflated that with
      // PARENTING TO YOUR OWN HEAD, which is not a remix at all: it is having a history. A node
      // continuing its own line is paraphrasing nobody.
      //
      // Conflated, the flag enforced a strict alternation — root, parented, root, parented —
      // because a parented emission CONSUMED the flag and only a root SET it. Two parented
      // blocks in a row were impossible, so Rule A was not merely unimplemented, it was
      // unimplementable: it requires every block to be parented and the guard forbade every
      // second one. The flag also initialises false, so even a node's FIRST parented emission
      // was dropped.
      if (peerParents.length > 0 && !this._hasNewDomainData) {
        this._metrics.remixRejected++;
        this._log('Remix rejected: no new domain data (MMP Section 15.7)');
        this.emit('metric', { type: 'remix-rejected', reason: 'no-new-domain-data' });
        return null;
      }

      // Lineage from parents (§7.5). `ancestors` is RETIRED: reachability is walked from refs,
      // never carried — a transitive closure stapled to every block had to be recomputed at
      // every hop, and a wrong one was indistinguishable from a right one.
      let lineage = null;
      if (opts.parents && opts.parents.length > 0) {
        lineage = {
          parents: opts.parents.map(p => p.metadata?.key ?? p.key),
          method: 'SVAF-v2',
        };
      }
      // A payload rides as the record's signed application section (§8.8.3): "an application action
      // MUST NOT ride as an unsigned top-level payload". It is sealed with the record (§18.2.1) and the
      // receiver gives it back as `cmb.payload`.
      const application = (opts.payload !== undefined && opts.payload !== null) ? payloadApplication(opts.payload) : null;
      // Audience is part of the record now, so it is constructed rather than stapled on.
      opts.cmb = createCMB({
        categories,
        createdBy: this.name,
        lineage,
        room: this._room ?? null,
        to: opts.to ?? null,
        // The v2.0 preimage fields (lib/emit-policy: on since 0.14): signs under mmp-sig-v2.0, with the
        // signed author node id.
        emitV2: MMP_EMIT_V2,
        createdByNodeId: MMP_EMIT_V2 ? this._identity.nodeId : undefined,
        application: MMP_EMIT_V2 ? application : undefined,
      });
      // Two of this node's records never share a createdTimestamp: the timestamp is the one preimage
      // term that tells two assertions of the same words apart, so two sends in one millisecond
      // would otherwise carry identical signatures and the second would read as a replay.
      // The ratchet starts from this node's newest stored record, so it holds across restarts. It
      // follows the clock again after a backward step of more than MAX_CLOCK_LEAD_MS instead of
      // running ahead of it indefinitely.
      const clock = opts.cmb.metadata.createdTimestamp;
      let last = this._timestampRatchetBase();
      if (last - clock > MAX_CLOCK_LEAD_MS) {
        this._log(`The clock is ${Math.round((last - clock) / 1000)} s behind this node's newest record; timestamps follow the clock again`);
        this.emit('metric', { type: 'clock-stepped-back', byMs: last - clock });
        last = clock - 1;
      }
      const ts = Math.max(clock, last + 1);
      opts.cmb.metadata.createdTimestamp = ts;
      this._lastCreatedTimestamp = ts;
      // assertionId is a hash OF the v2.0 preimage, set after construction and before signing.
      if (MMP_EMIT_V2) {
        opts.cmb.metadata.assertionId = assertionIdV2_0(opts.cmb);
      }
      // No remix re-key. The v2 address is the Merkle root over the seven categoryKeys and is
      // CONTENT-ONLY, so a lineage-bearing block is addressed exactly like any other block with
      // the same content. The old re-key existed because the remix derivation bound parents and
      // the author's NAME into the address; that derivation is gone, and its absence is the
      // collapse property Rule A depends on.
      if (opts.payload !== undefined && opts.payload !== null) {
        // The decoded payload beside the record, as before; the signed source is metadata.application.
        opts.cmb.payload = opts.payload;
      }
      // Authenticate the CMB with this node's Ed25519 identity key. Receivers
      // verify the signature against the public key we announce in the
      // handshake and reject any CMB that is forged or tampered (MMP §8.3).
      // A record that cannot be signed is not sent or stored unsigned (§18.3.1): a node whose key is
      // broken must say so, not quietly emit records every verifying peer will refuse.
      this._signOrThrow(opts.cmb, 'CMB signing failed');
    }
    // A record no transport can carry is refused here, before it is stored as sent (ECMBSIZE).
    // createCMB bounds what it builds; a payload, or a caller's own record, is bounded only here.
    assertRecordSendable(opts.cmb);
    // §7.5 COLLAPSE-BEFORE-MINT [MUST] — AC-2.4, the emit-side half of the Rule A self-loop.
    //
    // Under content-only addressing, re-asserting content identical to your own HEAD produces
    // the SAME ADDRESS as your HEAD. Parenting that on [own HEAD] writes the edge K -> K, and a
    // reachability walk never leaves it. Rule A is sound under content-only addressing IFF the
    // collapse property holds, so this is where it holds.
    //
    // It must be a MINT-LEVEL REFUSAL, not a store-level dedup, and the two come apart exactly
    // here: a dedup writes nothing while HEAD has already moved — the block was minted and then
    // discarded, so the store looks right and the timeline is wrong. Nothing is minted, HEAD
    // does not advance, and the caller is handed the address that already says this.
    const mintKey = opts.cmb?.metadata?.key;
    if (mintKey && this._head && mintKey === this._head) {
      // Clear the lineage before handing the record back. It was populated during construction
      // with [own HEAD] per Rule A — and since this address IS the HEAD, that lineage is exactly
      // the K -> K self-edge. Nothing is stored either way, but a caller may forward or persist
      // what it is handed, so the record must not leave here claiming descent from itself.
      // The signature was computed over that lineage, so only a record this node built is changed —
      // and then re-signed. A caller's record is returned exactly as given.
      if (builtHere && opts.cmb.metadata) {
        opts.cmb.metadata.lineage = null;
        if (MMP_EMIT_V2) opts.cmb.metadata.assertionId = assertionIdV2_0(opts.cmb);
        this._signOrThrow(opts.cmb, 'CMB re-signing after collapse failed');
      }
      this._metrics.collapsed = (this._metrics.collapsed ?? 0) + 1;
      this.emit('metric', { type: 'cmb-collapsed', key: mintKey, reason: 'identical-to-own-head' });
      this._log(`Collapsed: re-assertion of own HEAD ${String(mintKey).slice(0, 16)}… — cited, not minted`);
      const collapsed = { key: mintKey, cmb: opts.cmb, collapsed: true };
      // Collapse refuses a MINT, not a delivery: a directed send of the same words to a peer is
      // still an addressed request. The freshly signed record goes, not the stored HEAD: it is a
      // new assertion of the same cognition, so the receiver surfaces it instead of discarding it
      // as a replay of the first send.
      if (opts.to && builtHere) {
        this._dispatchExisting(collapsed, mintKey, opts.to);
      } else if (opts.to) {
        // A caller's record cannot be re-signed here, and its lineage was just cleared, so sending it
        // would read as forged at the peer (re-review F2). Not sent, and the result says so.
        this._markUndelivered(collapsed, mintKey, opts.to, 'caller-supplied record collapsed onto HEAD');
      }
      return collapsed;
    }

    const content = renderContent(opts.cmb);
    const entry = this._store.write(content, opts);

    // Duplicate — already stored, skip broadcast. A directed send is an addressed request,
    // not a broadcast, so the stored record still goes to that peer and the caller gets the
    // delivery result instead of null.
    if (!entry) {
      if (!opts.to) return null;
      const existingKey = opts.cmb?.metadata?.key || opts.cmb?.key || null;
      // Entry-shaped, like any other return, but built from the caller's own record: the stored entry
      // under this key may be a peer's admission, and its provenance is not this send's (re-review F5).
      const stored = existingKey ? this._store.get(existingKey) : null;
      // The store returns null both for a key it already holds and for a write that failed; only
      // the first is a duplicate (r3 F3).
      const existing = {
        key: existingKey,
        content: stored?.content ?? renderContent(opts.cmb),
        source: this.name,
        cmb: opts.cmb,
        storedAt: stored?.storedAt ?? null,
        tags: opts.tags || [],
        duplicate: !!stored,
        persisted: !!stored,
      };
      if (!stored) this._log(`STORE WRITE FAILED for ${String(existingKey).slice(0, 16)} — sending, but not stored locally`);
      this._dispatchExisting(existing, existingKey, opts.to);
      return existing;
    }

    // Only a PEER remix consumes the flag. If self-parents consumed it, a node that parented to
    // its own HEAD would burn its ability to remix a peer next — the alternation returning in a
    // subtler form, one hop further away from where anyone would look for it.
    if (peerParents.length > 0) {
      this._hasNewDomainData = false;
    } else if (parentKeys.length === 0) {
      this._hasNewDomainData = true;
    }

    // HEAD advances only when something was actually minted, and the key is remembered as ours
    // so a later self-parent is recognisable without resolving anything.
    if (entry?.key) {
      this._head = entry.key;
      this._ownKeys.add(entry.key);
      if (this._ownKeys.size > this._OWN_KEYS_MAX) {
        this._ownKeys.delete(this._ownKeys.values().next().value);
      }
    }

    // Protocol metrics
    this._metrics.cmbProduced++;
    if (opts.parents && opts.parents.length > 0) {
      this._metrics.remixProduced++;
    }
    this.emit('metric', { type: 'cmb-produced', key: entry.key, hasLineage: !!(opts.parents?.length) });

    const context = this._buildContext();
    const { h1, h2 } = encode(context);
    this._meshNode.updateLocalState(h1, h2, 0.8);

    this._meshNode.coupledState();

    // Build cmb frame per MMP spec Section 7: timestamp + cmb only
    // Encrypt categories per-peer if shared secret is available (E2E encryption)
    const baseCmb = entry.cmb || null;

    const { dispatched: shared, reason: notSent } = this._dispatchCmb(baseCmb, entry.storedAt, opts.to);

    // Feed signal to the Layer-6 insight engine, when one is injected
    if (this._xmesh) this._xmesh.ingestSignal({
      from: this.name,
      content,
      timestamp: entry.storedAt,
      type: 'own',
      valence: opts.cmb?.categories?.mood?.valence || 0,
      arousal: opts.cmb?.categories?.mood?.arousal || 0,
    });

    const fanoutDesc = opts.to
      ? `target=${opts.to.slice(0, 8)} (${shared ? 'sent' : NOT_SENT_SAID[notSent] || notSent})`
      : `${shared}/${this._peers.size} peers`;
    this._log(`Remembered: "${content.slice(0, 50)}${content.length > 50 ? '...' : ''}" → ${fanoutDesc}`);

    // MMP §4.4.4 — the addressed send is the one promise this layer makes, so it is
    // the one that has to be answerable. Until now a directed send to a peer that
    // was not connected wrote the CMB locally, logged a single line, and returned
    // an entry INDISTINGUISHABLE from a delivered one; every layer above reported
    // success for sends that reached nobody. Measured cost (bl-a6e63608c8c): five
    // directed CMBs to one seat — including a founder authorization and a founder
    // question — undelivered for three days while both senders believed otherwise,
    // each building a prose relay workaround around a channel reporting success.
    //
    // `undelivered` is true ONLY for a directed send. A broadcast that reached no
    // peers made no addressed promise — receiver-autonomous attention means nobody
    // was obliged to be listening — and flagging it would bury the signal that
    // matters under noise operators learn to wave through.
    //
    // Non-enumerable on purpose: the store persists entries with JSON.stringify,
    // and this is a fact about ONE send at ONE moment, not part of the durable
    // record. A stored record must never carry a claim it cannot re-check at read
    // time — that is the same class of defect this property exists to expose.
    // `dispatched`, NOT `delivered` — and the distinction is the point of the
    // whole property. `shared` increments immediately after peer.transport.send(),
    // so it counts frames handed to a transport, not frames any peer received.
    // Naming that "delivered" would be this exact class of overclaim one layer
    // up: a count bound to something other than what its name asserts. The word
    // `delivered` stays reserved until an ack earns it (CTO gate on a371021).
    //
    // `undelivered` is still sound as written, and is the load-bearing category:
    // never-dispatched does entail never-delivered, even though the converse
    // does not hold.
    Object.defineProperty(entry, 'delivery', {
      value: Object.freeze({
        directed: !!opts.to,
        to: opts.to || null,
        targets: opts.to ? (this._peers.has(opts.to) ? 1 : 0) : this._peers.size,
        dispatched: shared,
        undelivered: !!opts.to && shared === 0,
        // Why a directed send was not dispatched (NOT_SENT_SAID's keys): not connected is one
        // reason of several, and the one this used to report for all of them.
        ...(opts.to && shared === 0 ? { reason: notSent } : {}),
      }),
      enumerable: false,
      configurable: true,
    });

    if (entry.delivery.undelivered) {
      // Loud, and distinct from the fan-out line above: a broken addressed promise
      // is not routine telemetry. This is the signal a caller acts on.
      this._log(`UNDELIVERED (directed): ${opts.to.slice(0, 8)} ${NOT_SENT_SAID[notSent] || notSent} — stored locally, NOT sent`);
      this.emit('metric', { type: 'cmb-undelivered', to: opts.to, key: entry.key, reason: notSent });
    }

    return entry;
  }

  /**
   * The newest createdTimestamp this node has minted, read once from its own stored records.
   * @private
   */
  _timestampRatchetBase() {
    if (this._lastCreatedTimestamp === undefined) {
      // Every stored record of this node's own, not a recent window: on a node that has admitted 20
      // peer records since its last own one, the 20 newest held none of its own and the ratchet
      // restarted from zero.
      let max = 0;
      try { max = this._store.newestOwnCreatedAt(); } catch { /* an unreadable store starts the ratchet at zero */ }
      this._lastCreatedTimestamp = max;
    }
    return this._lastCreatedTimestamp;
  }

  /**
   * Sign a record with this node's identity key, or throw ESIGN. Nothing is stored or dispatched
   * before this runs, so a failure leaves no unsigned copy anywhere.
   * @private
   */
  _signOrThrow(cmb, what) {
    try {
      signCMB(cmb, this._identity.privateKey);
    } catch (err) {
      this._log(`${what}: ${err.message} — nothing stored or sent`);
      this.emit('metric', { type: 'cmb-signing-failed', reason: err.message });
      const e = new Error(`${what}: ${err.message}`);
      e.code = 'ESIGN';
      e.cause = err;
      throw e;
    }
  }

  /**
   * Search local mesh memory by keyword.
   * See MMP v0.2.0 Section 6 (Memory).
   *
   * @param {string} query — search keyword
   * @returns {Array<object>} matching entries sorted by recency
   */
  recall(query) {
    this._metrics.recalls++;
    return this._store.search(query);
  }

  // ── Startup Primer ─────────────────────────────────────────

  /**
   * Reconstitute the agent's remix-memory as a human-readable primer
   * suitable for injection into LLM context at session start. The
   * operationalisation of MMP §4.2 O2: rejoin-without-replay — a fresh
   * agent session picks up its prior state automatically, with zero
   * first-turn overhead.
   *
   * Plugin startup integration pattern:
   *
   *   const node = new SymNode({ name, ... });
   *   await node.start();
   *   // ... register tool surface, transport, etc ...
   *   const primer = node.buildStartupPrimer();   // final init step
   *   mcpServer.instructions += '\n\n' + primer.text;
   *
   * The primer is bounded in both time and count so a long-running
   * store does not flood LLM context. Callers may tune the caps per
   * deployment.
   *
   * @param {object} [opts]
   * @param {number} [opts.maxCount=20]  — cap on entries returned.
   * @param {number} [opts.maxAgeMs=86400000] — recency window (default 24h).
   * @returns {{ text: string, count: number, dropped: number, totalInStore: number }}
   *   `text`         — formatted primer, empty string if store is empty
   *   `count`        — entries included in the primer
   *   `dropped`      — entries elided by the caps (0 if none)
   *   `totalInStore` — total entries in the agent's remix store
   */
  buildStartupPrimer(opts = {}) {
    const maxCount = Number.isInteger(opts.maxCount) && opts.maxCount > 0 ? opts.maxCount : 20;
    const maxAgeMs = Number.isInteger(opts.maxAgeMs) && opts.maxAgeMs > 0 ? opts.maxAgeMs : 86_400_000; // 24h
    const cutoff = Date.now() - maxAgeMs;

    // recall('') returns every entry sorted newest-first — the remix store
    // is the agent's memory, not a curated view. No tag-filter gating.
    const all = this._store.search('');
    const totalInStore = all.length;
    if (!totalInStore) {
      return { text: '', count: 0, dropped: 0, totalInStore: 0 };
    }

    // Apply recency window first, then count cap.
    const withinWindow = all.filter((e) => (e.storedAt || e.timestamp || 0) >= cutoff);
    const kept = withinWindow.slice(0, maxCount);
    const dropped = totalInStore - kept.length;

    const lines = [];
    lines.push(`## Mesh memory primer — ${this.name} (${kept.length}/${totalInStore} CMBs)`);
    lines.push('');
    lines.push(
      `The following are the most recent ${kept.length} Cognitive Memory Blocks ` +
      `in this agent's remix store — its own observations plus peer observations ` +
      `admitted by SVAF. Treat this as prior cognitive state; act accordingly.`,
    );
    if (dropped > 0) {
      lines.push('');
      lines.push(
        `(${dropped} older entries elided by the startup primer caps ` +
        `(maxCount=${maxCount}, maxAgeMs=${maxAgeMs}). ` +
        `Use sym_recall to retrieve them if needed.)`,
      );
    }
    lines.push('');
    for (const e of kept) {
      const when = e.storedAt ? new Date(e.storedAt).toISOString() : '—';
      const keyShort = (e.key || '').slice(0, 16);
      const src = e.source || e.createdBy || 'unknown';
      const focus = e.cmb?.categories?.focus?.text || e.content || '';
      lines.push(`- [${when}] ${src} · ${keyShort} — ${focus}`);
    }

    return {
      text: lines.join('\n'),
      count: kept.length,
      dropped,
      totalInStore,
    };
  }

  // ── Remix Guard (MMP v0.2.0 Section 14) ────────────────────

  /**
   * Check whether this agent has new domain data available for remix.
   * Per MMP Section 14: agents MUST NOT remix peer signals unless they
   * have new observations from their own domain to intersect with.
   * Silence is correct when the agent has nothing new to contribute.
   *
   * Set to true automatically when remember() stores a new CMB.
   * Reset to false by markRemixed() after a remix cycle completes.
   *
   * @returns {boolean} true if agent has new domain data since last remix
   */
  canRemix() {
    return this._hasNewDomainData;
  }

  /**
   * Mark that the agent has completed a remix cycle. Resets the
   * new-domain-data flag so the agent stays silent until it has
   * fresh observations from its domain.
   */
  markRemixed() {
    this._hasNewDomainData = false;
  }

  // ── Metrics (MMP protocol-level observability) ─────────────

  /**
   * Report an LLM API call for protocol-level cost tracking.
   * Called by the agent after each LLM invocation (e.g. from role-reason.js).
   *
   * @param {number} tokensIn — input/prompt tokens
   * @param {number} tokensOut — output/completion tokens
   * @param {string} [model] — model name (default: 'gpt-4o-mini')
   */
  reportLLMUsage(tokensIn, tokensOut, model = 'gpt-4o-mini') {
    this._metrics.llmCalls++;
    this._metrics.llmTokensIn += tokensIn;
    this._metrics.llmTokensOut += tokensOut;
    this._metrics.llmModel = model;
    this.emit('metric', { type: 'llm-call', tokensIn, tokensOut, model });
  }

  /**
   * Get protocol-level metrics for this node.
   * Tracks: CMBs produced/accepted, remixes, SVAF decisions,
   * peer events, recall queries, LLM usage with cost, uptime.
   *
   * Applications (sym.day, monitoring) use this for observability.
   * Subscribe to node.on('metric', ...) for real-time events.
   *
   * @returns {object} cumulative metrics since node start
   */
  metrics() {
    const m = this._metrics;
    const uptimeMs = m.startedAt ? Date.now() - m.startedAt : 0;

    // Compute LLM cost based on model pricing
    const pricing = this._llmPricing[m.llmModel] || this._llmPricing['gpt-4o-mini'];
    const llmCostUSD = (m.llmTokensIn * pricing.input) + (m.llmTokensOut * pricing.output);

    return {
      ...m,
      framesRefusedByType: { ...m.framesRefusedByType },
      uptimeMs,
      llmCostUSD: Math.round(llmCostUSD * 1_000_000) / 1_000_000,
    };
  }

  // ── Mood (with cognitive evaluation) ───────────────────────

  /**
   * Broadcast a mood frame to all connected peers.
   * See MMP v0.2.0 Section 7 (Frame Types).
   *
   * @param {string} mood — mood text
   * @param {object} [opts]
   * @param {string} [opts.context] — optional context for the mood
   */
  broadcastMood(mood, opts = {}) {
    const frame = {
      type: 'mood',
      from: this._identity.nodeId,
      fromName: this.name,
      mood,
      context: opts.context || null,
      timestamp: Date.now(),
    };
    this._broadcastToPeers(frame);
    this._wakeManager.wakeSleepingPeers('mood', frame);
    this._log(`Mood broadcast: "${mood.slice(0, 50)}"`);
  }

  // ── XMesh Insight (per-agent LNN cognitive state) ──────────

  /**
   * Broadcast an XMesh insight to all connected peers.
   * See MMP v0.2.0 Section 12 (XMesh).
   *
   * @param {object} insight — XMesh insight with trajectory, patterns, anomaly, etc.
   */
  broadcastInsight(insight) {
    const frame = {
      type: 'xmesh-insight',
      from: this._identity.nodeId,
      fromName: this.name,
      trajectory: insight.trajectory,
      patterns: insight.patterns,
      anomaly: insight.anomaly,
      remixScore: insight.remixScore,
      coherence: insight.coherence,
      timestamp: Date.now(),
    };
    this._broadcastToPeers(frame);
    this._wakeManager.wakeSleepingPeers('xmesh-insight', frame);
    this._log(`XMesh insight broadcast`);
  }

  /**
   * Set the synthesis delegate for XMesh insights.
   * See MMP v0.2.0 Section 12 (XMesh).
   *
   * @param {function|null} fn — synthesis callback or null to clear
   */
  set onSynthesis(fn) {
    this._synthesisDelegate = typeof fn === 'function' ? fn : null;
  }

  // ── Communication ──────────────────────────────────────────

  /**
   * Send a message to a specific peer or broadcast to all peers.
   * See MMP v0.2.0 Section 7 (Frame Types).
   *
   * @param {string} message — message content
   * @param {object} [opts]
   * @param {string} [opts.to] — target peer ID; broadcasts to all if omitted
   */
  send(message, opts = {}) {
    // Core Secure retires the `message` frame (design D1): a message is a directed CMB (`to` = the
    // recipient), signed and sealed like any record, and the receiver raises its local 'message'
    // event (§14.9.1) from it. The text rides in the record's focus and, whole, in a signed
    // application section that marks the record as a message. Sent, not stored.
    const content = String(message ?? '');
    const targets = opts.to ? [opts.to] : [...this._peers.keys()];
    let delivered = 0;
    for (const to of targets) {
      let cmb;
      try { cmb = this._mintMessage(content, to); } catch (err) { this._log(`Message to ${String(to).slice(0, 8)} not sent: ${err.message}`); continue; }
      const peer = this._peers.get(to);
      if (!peer) continue;
      if (trySend(peer.transport, { type: 'cmb', timestamp: Date.now(), cmb }).ok) delivered++;
    }
    if (!opts.to) this._wakeManager.wakeSleepingPeers('message', { type: 'message', fromName: this.name, content, timestamp: Date.now() });
    // If no peers received the message, trigger an immediate reconnect
    // attempt for any cached bonjour peers. The next send will find
    // them connected instead of waiting for the 15s background timer.
    if (delivered === 0) this._discovery.reconnect();
    return delivered;
  }

  /** @private A signed v2.0 directed record carrying a message to `to`. */
  _mintMessage(content, to) {
    const bytes = Buffer.from(content, 'utf8');
    const application = {
      mediaType: 'text/plain',
      schema: MESSAGE_SCHEMA,
      encoding: 'base64url',
      byteLength: bytes.length,
      digest: `sha256-${crypto.createHash('sha256').update(bytes).digest('hex')}`,
      data: bytes.toString('base64url'),
    };
    const preview = content.length > 4096 ? `${content.slice(0, 4096)}…` : content;
    const cmb = createCMB({ categories: { focus: preview || '(empty message)', intent: 'message' }, createdBy: this.name, room: this._room, to, emitV2: true, createdByNodeId: this.nodeId, application });
    const clock = cmb.metadata.createdTimestamp;
    const ts = Math.max(clock, this._timestampRatchetBase() + 1);
    cmb.metadata.createdTimestamp = ts;
    this._lastCreatedTimestamp = ts;
    cmb.metadata.assertionId = assertionIdV2_0(cmb);
    this._signOrThrow(cmb, 'Message signing failed');
    return cmb;
  }

  /**
   * Send an error frame to a peer. Per MMP Section 7.2, error frames are
   * informational — the receiver MUST NOT treat them as commands.
   * Codes 1xxx are connection-level (close after sending).
   * Codes 2xxx are evaluation-level (informational only).
   *
   * @param {string} peerId — target peer
   * @param {number} code — error code (1001-1005, 2001-2002)
   * @param {string} message — human-readable error description
   * @param {string} [detail] — optional debug detail (MUST NOT contain sensitive info)
   */
  sendError(peerId, code, message, detail) {
    const peer = this._peers.get(peerId);
    if (!peer) return;
    peer.transport.send({ type: 'error', code, message, detail: detail || undefined });
    this._log(`Error sent to ${peer.name}: ${code} ${message}`);
  }

  // ── Wake (delegated) ──────────────────────────────────────

  /**
   * Wake a sleeping peer if needed (e.g. iOS background).
   *
   * @param {string} peerId — peer to wake
   * @param {string} [reason='message'] — wake reason
   * @returns {Promise<boolean>}
   */
  async wakeIfNeeded(peerId, reason = 'message') {
    return this._wakeManager.wakeIfNeeded(peerId, reason);
  }

  /**
   * Wake all known sleeping peers.
   *
   * @param {string} [reason='message'] — wake reason
   * @returns {Promise<void>}
   */
  async wakeAllPeers(reason = 'message') {
    return this._wakeManager.wakeAllPeers(reason);
  }

  // ── Monitoring ─────────────────────────────────────────────

  /**
   * List connected peers with coupling state.
   * See MMP v0.2.0 Section 5 (Connection), Section 9 (Coupling & SVAF).
   *
   * @returns {Array<{ id: string, peerId: string, name: string, connected: boolean, lastSeen: number, coupling: string, drift: number|null, source: string }>}
   *   `id` is the truncated 8-char display form; `peerId` is the full nodeId
   *   suitable for passing to `remember({to})` (MMP §4.4.4 targeted send).
   */
  /**
   * Record one SVAF evaluation (any outcome) to the decision log and emit it
   * live as 'svaf-decision'. This is the observable proof of autonomous
   * per-category admission — INCLUDING rejections, which the memory store drops.
   * @private
   */
  _recordDecision(rec) {
    if (!rec) return;
    try {
      const entry = { ts: Date.now(), ...rec };
      this._decisionLog.record(entry);
      this.emit('svaf-decision', entry);
      // Feed the adaptive-timescale change signal (newest last; bounded ring).
      if (rec.decision) {
        this._recentSvafDecisions.push(rec.decision);
        if (this._recentSvafDecisions.length > this._recentSvafDecisionsMax) this._recentSvafDecisions.shift();
      }
    } catch { /* never block intake */ }
  }

  /**
   * Recent SVAF decisions — the observable record of this node's autonomous,
   * per-category admission (admit AND reject). Newest-first.
   * @param {object} [opts] { limit=200, since=0, decision, source }
   * @returns {Array<object>}
   */
  decisions(opts = {}) {
    return this._decisionLog ? this._decisionLog.list(opts) : [];
  }

  peers() {
    const result = [];
    const decisions = this._meshNode.couplingDecisions;
    for (const [id, peer] of this._peers) {
      const d = decisions.get(id);
      result.push({
        id: id.slice(0, 8),
        peerId: id,
        name: peer.name || 'unknown',
        connected: true,
        lastSeen: peer.lastSeen,
        coupling: d ? d.decision : 'pending',
        drift: d && typeof d.drift === 'number' ? parseFloat(d.drift.toFixed(3)) : null,
        source: peer.transport ? peer.transport.kind : (peer.source || 'bonjour'),
        // Every session is sealed (Core Secure); a Legacy Import session says so (design D7).
        e2e: true,
        profile: peer.transport && peer.transport.legacy ? 'legacy-import' : 'core-secure',
        keySource: this._roster.source(id) || null,
        sessions: [...peer.transports.values()].map((t) => ({ transport: t.kind, sessionId: t.sessionId || null, confirmedAt: t.confirmedAt || null, extensions: [...(t.selected || [])], legacy: !!t.legacy })),
      });
    }
    return result;
  }

  /**
   * Count of stored memories.
   * @returns {number}
   */
  memories() {
    return this._store.count();
  }

  /**
   * Current mesh coherence score.
   * @returns {number}
   */
  coherence() {
    return this._meshNode.coherence;
  }

  /**
   * Full node status snapshot.
   * See MMP v0.2.0 Section 13 (Application).
   *
   * @returns {{ name: string, nodeId: string, running: boolean, port: number, relay: string|null, relayConnected: boolean, peers: Array, peerCount: number, memoryCount: number, coherence: number }}
   */
  status() {
    return {
      name: this.name,
      nodeId: this._identity.nodeId,
      running: this._running,
      port: this._port,
      relay: this._relayUrl || null,
      relayConnected: this._relay.ws?.readyState === 1 || false,
      // The phase, last close, next retry and refusal (if any) — what a host needs to say
      // WHY the relay is not connected, and the one-line description that says the fix.
      relayState: this._relay.state(),
      relayStatus: this._relay.describe(),
      peers: this.peers(),
      peerCount: this._peers.size,
      memoryCount: this.memories(),
      coherence: this.coherence(),
      // Core Secure (design D1–D3): what the session layer did, and the key conflicts an operator
      // has to resolve (`sym keys resolve <nodeId> <key>`).
      coreSecure: {
        sessions: { confirmed: [...this._sessions].filter((x) => x.confirmed).length, authenticating: [...this._sessions].filter((x) => !x.confirmed && !x.closed).length },
        stats: JSON.parse(JSON.stringify(this._sessionStats)),
        keyConflicts: this._roster.conflicts(),
        keyBindings: this._roster.size(),
        keyBindingsExpired: this._roster.expiredCount(),
        roleChain: { ...this._chainStats },
      },
      legacyImport: this._legacy ? this._legacy.status() : { routes: 0, sessions: [] },
    };
  }

  /**
   * Resolve with the relay state the first time the relay answers — connected, refused or
   * identity collision — or after `timeoutMs`. For hosts that join a relay at runtime and
   * want to report the relay's actual answer.
   */
  awaitRelayOutcome(timeoutMs = 10000) {
    return this._relay.awaitOutcome(timeoutMs);
  }

  /**
   * THE ONE INBOUND DISPATCH (0.13.17). Every frame reaches the frame handler through here, now from
   * the session that authenticated it (design D1): a LAN or loopback TCP session, inbound or
   * outbound, or a relay session. A frame this node cannot handle — its handler, or a host's listener
   * on the event it raises, throws — is REFUSED and COUNTED (metrics().framesRefused, by type), and
   * said in the log at most once a minute per peer. It is never thrown out of the transport.
   * @returns {boolean} true if the frame was handled, false if it was refused
   * @private
   */
  _receiveSessionFrame(session, frame) {
    return this._guardInbound(session.nodeId, session.name, frame, session.kind === 'relay' ? 'relay' : 'lan', () => {
      this._frameHandler.handle(session, frame);
    });
  }

  /**
   * The guard itself: run `take` for one inbound frame; if it throws, the frame is refused and
   * counted (_refuseFrame) and false is returned. Nothing it runs escapes into the transport.
   * @private
   */
  _guardInbound(peerId, peerName, msg, via, take) {
    try {
      take();
      return true;
    } catch (err) {
      this._refuseFrame(peerId, peerName, msg, via, err);
      return false;
    }
  }

  /**
   * Count and (rate-limited) say a refused inbound frame. Must not throw itself: it runs where
   * a throw would leave the transport.
   * @private
   */
  _refuseFrame(peerId, peerName, msg, via, err) {
    try {
      const type = msg && typeof msg.type === 'string' ? msg.type.slice(0, 40) : '?';
      this._metrics.framesRefused++;
      const byType = this._metrics.framesRefusedByType;
      byType[type] = (byType[type] || 0) + 1;
      const why = err && typeof err.message === 'string' ? err.message : String(err);
      // Every refusal is a metric (counted); only the log line is rate-limited.
      try { this.emit('metric', { type: 'frame-handler-error', from: String(peerName).slice(0, 64), frameType: type, error: why.slice(0, 200) }); } catch { /* a metric sink must not become the failure */ }
      const key = String(peerId);
      const now = Date.now();
      const last = this._refusalLines.get(key);
      if (last && now - last.at < 60_000) { last.quiet++; return; }
      if (this._refusalLines.size >= 1024) this._refusalLines.clear();
      this._refusalLines.set(key, { at: now, quiet: 0 });
      const more = last && last.quiet ? ` (${last.quiet} more from this peer since the last line)` : '';
      this._log(`Refused a '${type}' frame from ${String(peerName).slice(0, 64)} (${via}): ${why.slice(0, 200)}${more}`);
    } catch { /* counting a refusal must never become the failure */ }
  }


  // ── Sessions (design D1/D2) ────────────────────────────────

  /**
   * The facts of a confirmed session a host may read: what the §5.2 exchange proved. The shape the
   * `verified-record` hook carries; frozen, primitives only.
   */
  _sessionFacts(session) {
    if (!session) return null;
    return Object.freeze({
      nodeId: session.nodeId,
      name: session.name,
      identityKey: session.identityKey,
      sessionId: session.sessionId,
      transport: session.kind === 'relay' ? 'relay' : 'lan',
      role: session.role,
      room: session.room,
      extensions: Object.freeze([...(session.selected || [])]),
      confirmedAt: session.confirmedAt,
      implementation: session.peerImplementation ? Object.freeze({ ...session.peerImplementation }) : null,
      profile: session.legacy ? 'legacy-import' : 'core-secure',
    });
  }

  // ── Interior (design D9.3) ─────────────────────────────────

  /**
   * This node's interior: the local submission path for its mind (lib/interior.js). The mind gets a
   * per-mission capability (`startMind`), submits through `submit` or the interior socket (`listen`),
   * and the node checks, signs and sends. One mind per node at a time.
   * @returns {import('./interior').Interior}
   */
  interior() {
    if (!this._interior) {
      const { Interior } = require('./interior');
      this._interior = new Interior(this);
    }
    return this._interior;
  }

  // ── Invites (design D5) ────────────────────────────────────

  /**
   * An invite URL naming this node as issuer (`node`, `key`): an acceptor pins this node's key out of
   * band. A team invite also carries the relay and its token, so the URL is a SECRET.
   * @param {{ relay?: string, token?: string, room?: string, scheme?: string }} [opts]
   * @returns {string}
   */
  inviteURL(opts = {}) {
    const { buildInvite } = require('./invite');
    return buildInvite({ room: opts.room || this._room, relay: opts.relay, token: opts.token, scheme: opts.scheme, issuer: { nodeId: this.nodeId, publicKey: this._identity.publicKey } });
  }

  /**
   * Accept an invite: pin its issuer's key at `pinned` ONLY when that nodeId is unbound here. A
   * nodeId already bound to the same key keeps its (stronger) binding; one bound to a different key
   * is a conflict, recorded for the operator — an invite never repoints a key (design D3/D5).
   * @param {string|object} invite - the URL, or what parseInvite returned
   * @returns {{ pinned: boolean, reason?: string, issuer?: object, invite?: object }}
   */
  acceptInvite(invite) {
    const { parseInvite } = require('./invite');
    const parsed = typeof invite === 'string' ? parseInvite(invite) : invite;
    if (!parsed || parsed.error) return { pinned: false, reason: (parsed && parsed.error) || 'not an invite' };
    if (!parsed.issuer) return { pinned: false, reason: 'the invite names no issuer key', invite: parsed };
    const { nodeId, publicKey } = parsed.issuer;
    if (nodeId === this.nodeId) return { pinned: false, reason: 'the invite is this node\'s own', invite: parsed };
    const before = this._roster.source(nodeId);
    const b = this._roster.bind(nodeId, publicKey, 'pinned');
    if (!b.bound) {
      this._log(`Invite from ${nodeId.slice(0, 8)} not pinned: ${b.reason === 'conflict' ? `that nodeId is bound to another key (${before}); resolve with sym keys resolve` : b.reason}`);
      return { pinned: false, reason: b.reason, issuer: parsed.issuer, invite: parsed };
    }
    return { pinned: before === undefined, reason: before === undefined ? undefined : `already bound (${b.source})`, issuer: parsed.issuer, invite: parsed };
  }

  /**
   * Connect this node over a transport the host provides (an in-process pipe, a custom socket): the
   * §5.2 handshake runs over it like any other, and the other end becomes a peer only once both
   * proofs validate. The dialler is the `client`; the other end must attach as the `server`.
   * @param {{ on: function, send?: function, trySend?: function, close: function }} transport - emits
   *   'message' (frame objects) and 'close'
   * @param {{ role: 'client'|'server', expectNodeId?: string }} opts
   * @returns {{ sessionId: function(): (string|null), confirmed: function(): boolean, close: function }}
   */
  connectTransport(transport, { role, expectNodeId } = {}) {
    if (role !== 'client' && role !== 'server') throw new Error('connectTransport: role must be client or server');
    const session = this._attachTransport(transport, { role, kind: 'bonjour', expectNodeId: expectNodeId || null });
    return Object.freeze({
      sessionId: () => session.sessionId,
      confirmed: () => session.confirmed,
      close: () => session.close('closed-by-host'),
    });
  }

  /**
   * Open a session over a transport. The dialler is the client (it sends client-hello); the
   * listener is the server. A TCP transport's frames are fed to the session here; a relay session's
   * are routed to it by `from` (_relayEnvelope).
   * @returns {PeerSession}
   * @private
   */
  _attachTransport(transport, { role, kind = 'bonjour', expectNodeId = null, relayFrom = null, remote = null } = {}) {
    const session = new PeerSession({
      role, transport, kind, relayFrom, expectNodeId,
      local: { nodeId: this.nodeId, name: this.name, publicKey: this._identity.publicKey, privateKey: this._identity.privateKey },
      room: this._room, extensions: this._offeredExtensions, implementation: this._implementation,
      timeoutMs: this._handshakeTimeoutMs,
    });
    session.remote = remote;
    this._sessions.add(session);
    if (kind !== 'relay' && transport && typeof transport.on === 'function') {
      transport.on('message', (f) => session.receiveWire(f));
      transport.on('close', () => session.close('transport-closed', { notify: false }));
      transport.on('error', () => {});
    }
    session.on('confirmed', () => {
      if (!this._guardInbound(session.nodeId, session.name, { type: 'session-confirmed' }, kind, () => this._onSessionConfirmed(session))) {
        session.close('confirm-failed');
      }
    });
    session.on('frame', (frame) => this._onSessionFrame(session, frame));
    session.on('refused', (type, reason) => this._noteSessionRefusal(session, type, reason));
    session.on('closed', (info) => {
      this._guardInbound(session.nodeId || '?', session.name || '?', { type: 'session-closed' }, kind, () => this._onSessionClosed(session, info));
    });
    if (role === 'client') session.start();
    return session;
  }

  /**
   * Both proofs validated. Before anything per-peer exists: the proven (nodeId, key) is checked
   * against the key registry (design D3) — a bound nodeId presenting a different key is a conflict,
   * refused and recorded — and the room door decides admission (design D6).
   * @private
   */
  _onSessionConfirmed(session) {
    this._sessionStats.confirmed++;
    const expected = this._roster.expected(session.nodeId);
    if (expected && expected !== session.identityKey) {
      this._roster.bind(session.nodeId, session.identityKey, 'proven'); // records the conflict
      this._log(`Refused ${session.name} (${session.nodeId.slice(0, 8)}): it proved a key that is not the one bound to its nodeId (${this._roster.source(session.nodeId)}) — a key conflict for the operator (sym keys resolve)`);
      session.close('key-conflict');
      return;
    }
    // A room-join grant this node holds goes first, so a gated peer can admit it.
    if (this._roomGrant) session.send({ type: 'mesh-room-join', grant: this._roomGrant });
    session.admission = { state: 'pending', since: Date.now() };
    this._decideAdmission(session);
  }

  /** @private Run the room door for a confirmed session; admit, refuse, or wait for its grant. */
  _decideAdmission(session) {
    if (session.closed || session.admission?.state !== 'pending') return;
    const v = this._roomAdmissionDecide(session);
    if (v.pending) {
      if (!session._admissionTimer) {
        session._admissionTimer = setTimeout(() => {
          if (session.admission?.state !== 'pending') return;
          this._refuseAdmission(session, 'no room-join grant presented for a gated room');
        }, this._handshakeTimeoutMs);
        if (session._admissionTimer.unref) session._admissionTimer.unref();
      }
      return;
    }
    if (session._admissionTimer) { clearTimeout(session._admissionTimer); session._admissionTimer = null; }
    if (!v.admit) { this._refuseAdmission(session, v.reason); return; }
    this._admitSession(session);
  }

  _refuseAdmission(session, reason) {
    session.admission = { state: 'refused', reason, at: Date.now() };
    if (!this._roomVerdicts) this._roomVerdicts = new Map();
    // Kept, so a refused peer that keeps speaking stays refused, and bounded (peer-state.js): a peer
    // mints identities for free.
    keepPeerState(this._roomVerdicts, session.nodeId, { admit: false, reason, at: Date.now() }, this._peers);
    this._log(`Refused ${session.name} into '${this._room}': ${reason}`);
    session.close('admission-refused');
  }

  /**
   * Admit a confirmed session: bind its key `proven`, join it to its peer (creating the peer on its
   * first session), and greet it. A second confirmed session for the same (nodeId, key) on the same
   * transport kind SUPERSEDES the first (a peer restart, 4004 included); one on another kind is a
   * secondary path (§4.6).
   * @private
   */
  _admitSession(session) {
    const nodeId = session.nodeId;
    const b = this._roster.bind(nodeId, session.identityKey, 'proven');
    if (!b.bound && b.reason === 'conflict') { session.close('key-conflict'); return; }
    if (!b.bound && b.reason === 'full') this._log(`Key registry full: ${nodeId.slice(0, 8)} is held for this session only`);
    // First contact starts the binding's clock; a later session re-proving the same key is something
    // verified under it, so the binding never expires (design D3 binding lifetime).
    if (b.bound) { if (b.created) this._roster.noteSeen(nodeId); else this._roster.noteVerified(nodeId); }
    session.admission = { state: 'admitted', at: Date.now() };
    if (!this._roomVerdicts) this._roomVerdicts = new Map();
    keepPeerState(this._roomVerdicts, nodeId, { admit: true, reason: null, at: Date.now() }, this._peers);
    if (session.kind === 'relay') {
      // The in-flight slots hold a handshake being made; a confirmed session leaves them, so the next
      // hello (a peer restart, a re-handshake) can be made while this one keeps carrying frames.
      const st = this._relayState(session.relayFrom);
      st.confirmed.add(session);
      if (st.client === session) st.client = null;
      if (st.server === session) st.server = null;
    }
    let peer = this._peers.get(nodeId);
    const isNew = !peer;
    if (!peer) {
      peer = { peerId: nodeId, name: session.name, identityKey: session.identityKey, transports: new Map(), transport: null, isOutbound: session.role === 'client', source: session.kind, lastSeen: Date.now(), joinedAt: Date.now() };
      this._peers.set(nodeId, peer);
    } else if (peer.identityKey !== session.identityKey) {
      session.close('key-conflict');
      return;
    }
    // The sticky floor arms now (a proven binding): a Legacy Import session for this nodeId ends.
    for (const t of [...peer.transports.values()]) if (t.legacy && !t.closed) t.close('floor');
    const prev = peer.transports.get(session.kind);
    peer.transports.set(session.kind, session);
    peer.transport = this._bestTransport(peer);
    peer.name = session.name;
    peer.lastSeen = Date.now();
    if (prev && prev !== session && !prev.closed) {
      this._sessionStats.superseded++;
      prev._superseded = true;
      prev.close('superseded');
    }
    if (session.kind === 'bonjour') this._pendingBonjour?.delete(nodeId);
    if (session.kind === 'relay') this._relayRetry?.delete(nodeId);
    this._greetSession(peer, session, isNew);
    if (isNew) {
      this._log(`Peer connected: ${peer.name} (${session.role === 'client' ? 'outbound' : 'inbound'}, ${session.kind}, Core Secure session ${session.sessionId.slice(0, 8)})`);
      this._metrics.peersJoined++;
      this.emit('peer-joined', { id: nodeId, name: peer.name, source: session.kind });
      this.emit('metric', { type: 'peer-joined', name: peer.name, source: session.kind });
    } else {
      this._log(`Session ${prev ? 'replaced' : 'added'} for ${peer.name}: ${session.kind} (${peer.transports.size} transport(s))`);
    }
  }

  /**
   * What a freshly admitted session is sent: this node's recent own records (the "Ask the Mesh"
   * context, debounced per peer), its own wake channel, and frames queued while the peer slept.
   * Everything goes sealed. Anchors are announced first in a sealed `cmb-anchors` frame, so the
   * receiver knows which records are replayed context (a flag the record frame cannot carry).
   * @private
   */
  _greetSession(peer, session, isNew) {
    if (!this._lastAnchorSent) this._lastAnchorSent = new Map();
    const lastSent = this._lastAnchorSent.get(peer.peerId) || 0;
    const now = Date.now();
    if (now - lastSent >= 60000) {
      keepPeerState(this._lastAnchorSent, peer.peerId, now, this._peers);
      // Own emissions only (anti-echo, §15.7), and only records that can travel in Core Secure.
      const anchors = this._store.recent(50)
        .filter((a) => a.cmb && a.peerId == null && a.cmb.metadata && a.cmb.metadata.signatureSuite === 'mmp-sig-v2.0' && a.cmb.metadata.sig)
        .slice(0, 5);
      if (anchors.length > 0) {
        session.send({ type: 'cmb-anchors', keys: anchors.map((a) => a.cmb.metadata.key) });
        let sent = 0;
        for (const a of anchors) if (session.send({ type: 'cmb', cmb: a.cmb })) sent++;
        this._log(`Sent ${sent} anchor CMB(s) to ${peer.name}`);
      }
    } else if (isNew) {
      this._log(`Skipping anchor CMBs for ${peer.name} (reconnected within 60s)`);
    }
    // This node's own wake channel. (peer-info about OTHER nodes is not sent: a receiver learns a
    // wake channel only from its node's own session, so gossip about others would be dropped.)
    if (this._wakeChannel) session.send({ type: 'wake-channel', ...this._wakeChannel });
    const pending = this._pendingFrames.get(peer.peerId);
    if (pending && pending.length > 0) {
      this._log(`Delivering ${pending.length} pending frame(s) to ${peer.name}`);
      for (const frame of pending) session.send(frame);
      this._pendingFrames.delete(peer.peerId);
    }
  }

  /** @private A frame from a session: the door first (design D6), then the one guarded dispatch. */
  _onSessionFrame(session, frame) {
    const state = session.admission && session.admission.state;
    if (state !== 'admitted') {
      if (state === 'pending' && frame && frame.type === 'mesh-room-join') {
        session.roomGrant = frame.grant;
        this._decideAdmission(session);
        return;
      }
      this._noteSessionRefusal(session, frame && frame.type, 'not-admitted');
      return;
    }
    if (frame && frame.type === 'mesh-room-join') return; // admitted already: nothing to decide
    const peer = this._peers.get(session.nodeId);
    if (peer) peer.lastSeen = Date.now();
    this._receiveSessionFrame(session, frame);
  }

  /** @private A session ended: detach it, and the peer when it was the peer's last. */
  _onSessionClosed(session, info) {
    this._sessions.delete(session);
    if (session._chainHold) {
      for (const reqId of [...session._chainHold.fetches.keys()]) this._chainFetchDone(session, reqId, false);
      session._chainHold = null;
    }
    if (session._admissionTimer) { clearTimeout(session._admissionTimer); session._admissionTimer = null; }
    const reason = info && info.reason;
    if (info && info.desync) this._sessionStats.desync++;
    if (!(info && info.wasConfirmed)) {
      this._sessionStats.failed++;
      const by = this._sessionStats.failedByReason;
      by[reason] = (by[reason] || 0) + 1;
      if (reason !== 'node-stopped' && reason !== 'transport-closed') {
        this._sayOncePerMinute(`hs|${reason}|${session.remote || session.relayFrom || ''}`, `Handshake ${session.kind === 'relay' ? `with relay peer ${String(session.relayFrom).slice(0, 8)}` : `on ${session.role === 'client' ? 'an outbound' : 'an inbound'} LAN connection`} failed: ${reason}${info.detail ? ` (${String(info.detail).slice(0, 160)})` : ''}`);
      }
    }
    if (session.kind === 'bonjour' && session.expectNodeId) this._pendingBonjour?.delete(session.expectNodeId);
    if (session.kind === 'relay') {
      const st = this._relaySessions && this._relaySessions.get(session.relayFrom);
      if (st) {
        st.confirmed.delete(session);
        if (st.client === session) st.client = null;
        if (st.server === session) st.server = null;
        // An entry lives only while a session for that relay `from` does: a flood of hellos from
        // ids that never confirm leaves nothing behind.
        if (!st.client && !st.server && st.confirmed.size === 0) this._relaySessions.delete(session.relayFrom);
      }
    }
    const peer = session.nodeId ? this._peers.get(session.nodeId) : null;
    if (peer && peer.transports.get(session.kind) === session) {
      peer.transports.delete(session.kind);
      peer.transport = this._bestTransport(peer);
      if (peer.transports.size === 0) {
        this._peers.delete(session.nodeId);
        this._forgetPeer(session.nodeId);
        this._meshNode.removePeer(session.nodeId);
        this._metrics.peersLeft++;
        this._log(`Peer disconnected: ${peer.name} (all sessions closed; last: ${reason})`);
        this.emit('peer-left', { id: session.nodeId, name: peer.name });
        this.emit('metric', { type: 'peer-left', name: peer.name });
      } else {
        this._log(`Session closed for ${peer.name}: ${session.kind} (${reason}; ${peer.transports.size} remaining)`);
      }
    }
    // A relay client re-handshakes while the peer is present (frame loss, a desync, a timeout, the
    // server's error frame); a superseded or deliberately closed session does not.
    if (session.kind === 'relay' && session.role === 'client' && this._running && !session._superseded
        && reason !== 'node-stopped' && reason !== 'relay-peer-left' && reason !== 'relay-disconnected' && reason !== 'key-conflict' && reason !== 'admission-refused'
        && this._relay.present.has(session.relayFrom)) {
      this._scheduleRelayRetry(session.relayFrom);
    }
  }

  /**
   * A peer left the peer table (its last session closed): what was learned for its sessions and is
   * learned again on the next one goes — an ADMIT verdict, the anchor-replay debounce. A refusal
   * verdict is kept (bounded), so a refused peer that keeps speaking stays refused (0.13.17).
   * @private
   */
  _forgetPeer(nodeId) {
    const v = this._roomVerdicts && this._roomVerdicts.get(nodeId);
    if (v && v.admit) this._roomVerdicts.delete(nodeId);
    if (this._lastAnchorSent) this._lastAnchorSent.delete(nodeId);
  }

  /** @private Count and (once a minute per reason) say a frame a session did not take. */
  _noteSessionRefusal(session, type, reason) {
    // Taken as text before anything prints it: a frame's type is whatever its sender wrote.
    type = typeof type === 'string' ? type.slice(0, 40) : '?';
    reason = typeof reason === 'string' ? reason.slice(0, 80) : '?';
    this._sessionStats.refusedFrames++;
    const by = this._sessionStats.refusedByReason;
    const k = `${reason}`;
    by[k] = (by[k] || 0) + 1;
    this.emit('metric', { type: 'session-frame-refused', frameType: type, reason, from: session && session.nodeId });
    this._sayOncePerMinute(`sr|${session && (session.nodeId || session.relayFrom || session.remote)}|${reason}`, `Refused a '${String(type).slice(0, 40)}' frame from ${session && (session.name || session.relayFrom || 'an unconfirmed session')}: ${reason}`);
  }

  /** @private One log line per key a minute, with how many more since. */
  _sayOncePerMinute(key, line) {
    if (!this._saidOnce) this._saidOnce = new Map();
    const now = Date.now();
    const said = this._saidOnce.get(key);
    if (said && now - said.at < 60_000) { said.more++; return; }
    if (this._saidOnce.size >= 1024) this._saidOnce.delete(this._saidOnce.keys().next().value);
    this._saidOnce.set(key, { at: now, more: 0 });
    try { this._log(`${line}${said && said.more ? ` (${said.more} more since)` : ''}`); } catch { /* a log sink must not fail a frame */ }
  }

  /** @private A legacy hello on the Core Secure listener (design D2): refused, counted, said once a minute per address. */
  _noteLegacyRefusal(remote) {
    this._sessionStats.legacyHellosRefused++;
    this.emit('metric', { type: 'legacy-hello-refused', remote: remote || null });
    this._sayOncePerMinute(`legacy|${remote || ''}`, `Refused a legacy handshake from ${remote || 'a LAN peer'}: this node speaks Core Secure only (a 0.13 peer is reached by a Legacy Import route, never by its hello)`);
  }

  _connectToPeer(address, port, peerId, peerName) {
    // Connect timeout: 10s to establish the TCP connection, cleared once connected so the socket
    // doesn't die from idle. The session's own 10 s handshake deadline takes over from there.
    const socket = net.createConnection({ host: address, port }, () => {
      socket.setTimeout(0);
      const transport = new TcpTransport(socket);
      this._attachTransport(transport, { role: 'client', kind: 'bonjour', expectNodeId: peerId, remote: `${address}:${port}` });
    });
    socket.on('error', (err) => {
      this._pendingBonjour.delete(peerId);
      this._sayOncePerMinute(`dial|${peerId}`, `Connect failed to ${peerName}: ${err.message}`);
    });
    socket.setTimeout(10000, () => { this._pendingBonjour.delete(peerId); socket.destroy(); });
  }

  // ── Relay sessions (design D2) ─────────────────────────────

  /** @private Tell relay `from` that `sessionId` (or, null, any session) is not held here (rate-limited per from). */
  _sayUnknownSession(from, sessionId) {
    if (!this._unknownSessionSaid) this._unknownSessionSaid = new Map();
    const now = Date.now();
    if (now - (this._unknownSessionSaid.get(from) ?? -Infinity) < 1000) return;
    this._unknownSessionSaid.delete(from);
    if (this._unknownSessionSaid.size >= 1024) this._unknownSessionSaid.delete(this._unknownSessionSaid.keys().next().value);
    this._unknownSessionSaid.set(from, now);
    try { this._relay.sendTo(from, { type: 'error', code: UNKNOWN_SESSION_CODE, message: 'unknown session', ...(sessionId ? { detail: `session:${sessionId}` } : {}) }); } catch { /* best effort */ }
  }

  /** @private How many relay handshakes (client or server) are in flight. */
  _relayHandshakesInFlight() {
    let n = 0;
    if (this._relaySessions) for (const st of this._relaySessions.values()) n += (st.client ? 1 : 0) + (st.server ? 1 : 0);
    return n;
  }

  /** @private The sessions bound to one relay `from`. */
  _relayState(nodeId) {
    if (!this._relaySessions) this._relaySessions = new Map();
    let st = this._relaySessions.get(nodeId);
    if (!st) { st = { client: null, server: null, confirmed: new Set() }; this._relaySessions.set(nodeId, st); }
    return st;
  }

  /**
   * The relay names a peer present (relay-peers, relay-peer-joined). A candidate: the node with the
   * smaller nodeId sends client-hello to it; the other waits for one. A confirmed session already
   * held stays until a new one confirms (supersession covers a peer restart under 4004).
   * @private
   */
  _relayPeerPresent(nodeId) {
    if (!wireNodeId(nodeId) || nodeId === this.nodeId) return;
    if (this._legacy && this._legacy.size) this._legacy.relayPresent(nodeId);
    if (!(this.nodeId < nodeId)) return;
    // A peer that already has a live, confirmed relay session reuses it (0.13.17 re-review A2): the
    // relay re-announces every peer on every reconnect and may repeat a join notice, and a fresh
    // handshake for each would only supersede a working session.
    // A repeated announcement can also mean the peer restarted behind the relay (4004 replaces its
    // connection without a peer-left): the live session is probed with a ping, which the peer's new
    // process answers with an `error` (it holds no session) — the session then closes and the node
    // re-handshakes — while the same process answers pong and nothing changes.
    const st = this._relaySessions && this._relaySessions.get(nodeId);
    const live = st && [...st.confirmed].find((x) => x.confirmed && !x.closed);
    if (live) {
      const now = Date.now();
      if (now - (live._probedAt || 0) >= 1000) { live._probedAt = now; try { live.send({ type: 'ping' }); } catch { /* it closes itself */ } }
      return;
    }
    this._startRelayClient(nodeId);
  }

  /** @private Send a client-hello to `nodeId` over the relay (one handshake in flight at a time). */
  _startRelayClient(nodeId) {
    if (!this._running) return;
    const cur = this._relaySessions && this._relaySessions.get(nodeId);
    if (cur && cur.client && !cur.client.closed) return;
    // At most RELAY_HANDSHAKES_MAX in flight: the rest wait their turn on the retry backoff.
    if (this._relayHandshakesInFlight() >= RELAY_HANDSHAKES_MAX) { this._scheduleRelayRetry(nodeId); return; }
    const st = this._relayState(nodeId);
    st.client = this._attachTransport(this._relay.transportFor(nodeId), { role: 'client', kind: 'relay', relayFrom: nodeId, expectNodeId: nodeId });
  }

  /** @private Re-handshake with a present relay peer, backing off 1 s, 2 s, … 30 s. */
  _scheduleRelayRetry(nodeId) {
    if (!this._relayRetry) this._relayRetry = new Map();
    const r = this._relayRetry.get(nodeId) || { attempt: 0, timer: null };
    if (r.timer) return;
    const delay = Math.min(1000 * 2 ** r.attempt, 30_000);
    r.attempt++;
    r.timer = setTimeout(() => {
      r.timer = null;
      if (this._running && this._relay.present.has(nodeId)) this._startRelayClient(nodeId);
    }, delay);
    if (r.timer.unref) r.timer.unref();
    this._relayRetry.set(nodeId, r);
  }

  /** @private The relay says a peer left: every session bound to that `from` ends (design D2). */
  _relayPeerGone(nodeId) {
    if (this._legacy) this._legacy.relayGone(nodeId);
    const st = this._relaySessions && this._relaySessions.get(nodeId);
    const r = this._relayRetry && this._relayRetry.get(nodeId);
    if (r && r.timer) clearTimeout(r.timer);
    if (this._relayRetry) this._relayRetry.delete(nodeId);
    if (!st) return;
    for (const s of [st.client, st.server, ...st.confirmed]) if (s && !s.closed) s.close('relay-peer-left', { notify: false });
    this._relaySessions.delete(nodeId);
  }

  /** @private The relay connection closed: every relay session ends with it. */
  _relayDisconnected() {
    if (!this._relaySessions) return;
    for (const [nodeId] of [...this._relaySessions]) {
      const st = this._relaySessions.get(nodeId);
      for (const s of [st.client, st.server, ...st.confirmed]) if (s && !s.closed) s.close('relay-disconnected', { notify: false });
    }
    this._relaySessions.clear();
    if (this._relayRetry) { for (const r of this._relayRetry.values()) if (r.timer) clearTimeout(r.timer); this._relayRetry.clear(); }
  }

  /**
   * An envelope from relay `from`. The relay's `from` is unproven (§4.4.1), so it only selects the
   * session the payload is offered to; the session authenticates it. A hello opens a new candidate
   * session (an unconfirmed hello never tears down a confirmed one); a sealed frame goes to the
   * confirmed session whose sessionId it carries; anything else is a Legacy Import route's or refused.
   * @private
   */
  _relayEnvelope(from, fromName, payload) {
    if (from === this.nodeId) return;
    const st = this._relaySessions && this._relaySessions.get(from);
    const refuse = (reason) => this._noteSessionRefusal({ relayFrom: from, name: fromName }, payload.type, reason);
    switch (payload.type) {
      case 'client-hello': {
        // The smaller nodeId is the client (design D2): a hello from a larger one is not taken.
        if (!(from < this.nodeId)) { refuse('client-hello-from-larger-id'); return; }
        // A hello costs a key agreement and a signature: at most RELAY_HANDSHAKES_MAX are in flight
        // over the relay at once (relay `from`s are free to mint); past it a new hello is refused.
        if (!(st && st.server) && this._relayHandshakesInFlight() >= RELAY_HANDSHAKES_MAX) { refuse('too-many-handshakes'); return; }
        const s = this._relayState(from);
        if (s.server && !s.server.closed && !s.server.confirmed) s.server.close('superseded-hello', { notify: false });
        s.server = this._attachTransport(this._relay.transportFor(from), { role: 'server', kind: 'relay', relayFrom: from, expectNodeId: from });
        s.server.receiveWire(payload);
        return;
      }
      case 'server-hello':
        if (st && st.client && !st.client.closed && !st.client.confirmed) st.client.receiveWire(payload);
        else refuse('no-handshake-in-flight');
        return;
      case 'client-finish':
        if (st && st.server && !st.server.closed && !st.server.confirmed) st.server.receiveWire(payload);
        else refuse('no-handshake-in-flight');
        return;
      case 'cmb-encrypted':
      case 'control-encrypted': {
        const s = st && [...st.confirmed].find((x) => x.sessionId === payload.sessionId && !x.closed);
        if (s) { s.receiveWire(payload); return; }
        refuse('other-session');
        // A sealed frame for a session this node does not hold — its peer still holds one from before
        // this process started (a restart the relay reports as a repeated join, or nothing at all) —
        // is answered with an `error` naming that session, at most once a second per relay `from`:
        // the peer closes it and re-handshakes (an error only prompts a new handshake, design D2), so a
        // live session is reused on a repeated announcement (A2) without leaving a restart stranded.
        if (typeof payload.sessionId === 'string' && /^[0-9a-f]{32}$/.test(payload.sessionId)) this._sayUnknownSession(from, payload.sessionId);
        return;
      }
      case 'ping':
      case 'pong': {
        const peer = this._peers.get(from);
        const s = peer && peer.transports.get('relay');
        if (s && s.relayFrom === from) s.receiveWire(payload);
        // A ping from a relay `from` this node holds no session with: its peer holds one from before
        // this process started. Answered with an `error`, so it closes that session and re-handshakes.
        else if (payload.type === 'ping') this._sayUnknownSession(from, null);
        return;
      }
      case 'error': {
        if (!st) return;
        if (payload.code === UNKNOWN_SESSION_CODE) {
          // The peer holds no session with this node (its process restarted). The client re-handshakes
          // and keeps the session it has until the new one confirms and supersedes it — no peer-left
          // for a restart; the server waits for the client's hello. Never a teardown on its own.
          if (this.nodeId < from && this._relay.present.has(from)) this._startRelayClient(from);
          return;
        }
        const m = typeof payload.detail === 'string' && /^session:([0-9a-f]{32})$/.exec(payload.detail);
        for (const s of [st.client, st.server, ...st.confirmed]) {
          if (!s || s.closed) continue;
          if (m && s.sessionId && s.sessionId !== m[1]) continue;
          s.close('peer-closed', { notify: false });
        }
        return;
      }
      default:
        if (this._legacy && this._legacy.relayFrame(from, fromName, payload)) return;
        refuse(payload.type === 'handshake' ? 'legacy-hello' : 'not-core-secure');
    }
  }

  /**
   * Select the highest-priority live session for a peer: LAN over relay (§4.6).
   * @private
   */
  _bestTransport(peer) {
    for (const src of ['bonjour', 'relay']) {
      const t = peer.transports.get(src);
      if (t && !t.closed) return t;
    }
    for (const t of peer.transports.values()) if (!t.closed) return t;
    return null;
  }

  /**
   * IS THIS NODE'S ROOM GATED, AND BY WHOM — a public answer, because callers were guessing.
   *
   * A gated room admits its owner (recognised by its pinned key) and grant-holders (a grant whose
   * bound key equals the key the session PROVED). Before 0.14 no handshake proved a key, so a gated
   * room admitted nobody; Core Secure sessions prove it, so this now reports `grant-holders`.
   * @returns {{room: string, gated: boolean, owner: {nodeId: string, publicKey: string, source: string}|null}}
   */
  roomGate() {
    const owner = this._roomOwners && this._roomOwners.ownerOf(this._room);
    if (!owner) return { room: this._room, gated: false, owner: null, admits: 'anyone', why: null };
    return {
      room: this._room,
      gated: true,
      owner: { nodeId: owner.nodeId, publicKey: owner.publicKey, source: owner.source || 'unknown' },
      admits: 'grant-holders',
      why: null,
    };
  }

  /**
   * Whether the session speaking for `peerId` proved the key bound to it. Every admitted session
   * did (Core Secure): a peer is the set of sessions that proved one (nodeId, key).
   * @returns {boolean}
   */
  _peerKeyProven(peerId) {
    const peer = this._peers.get(peerId);
    return !!(peer && peer.transport && peer.transport.confirmed && !peer.transport.legacy);
  }

  /**
   * THE DOOR, CONSULTED PER FRAME (§5.8.1). A frame reaches the handler only from a session the
   * door admitted (_onSessionFrame); this answers for a peer by its admitted sessions.
   * @returns {{pass: boolean, reason?: string}}
   * @private
   */
  _roomDoor(peerId) {
    const v = this._roomVerdicts && this._roomVerdicts.get(peerId);
    if (v && !v.admit) return { pass: false, reason: v.reason || 'refused at admission' };
    if (this._peers.has(peerId)) return { pass: true };
    if (v) return { pass: true };
    const owner = this._roomOwners && this._roomOwners.ownerOf(this._room);
    if (owner) return { pass: false, reason: `spoke into gated room '${this._room}' without joining it` };
    return { pass: true };
  }

  /**
   * MAY THIS SESSION BE IN THIS ROOM (design D6)? The room is explicit and inside the transcript, so
   * a session that confirmed is in this node's room (a mismatch closed it before confirmation). An
   * ungated room admits it. A gated room admits its owner when the session proved the owner's
   * pinned key, and a grantee when its room-join grant's bound key equals the session's PROVEN key;
   * a session that has presented no grant yet is pending (it has one handshake timeout to send one).
   * @returns {{ admit?: boolean, pending?: boolean, reason?: string }}
   */
  _roomAdmissionDecide(session) {
    const owner = this._roomOwners.ownerOf(this._room);
    if (!owner) return { admit: true };
    if (session.nodeId === owner.nodeId) {
      return session.identityKey === owner.publicKey
        ? { admit: true }
        : { admit: false, reason: 'claims the owner\'s nodeId under another key' };
    }
    const grant = session.roomGrant;
    if (!grant) return { pending: true };
    const v = verifyRoomGrant(grant, owner.publicKey, { room: this._room, grantee: session.nodeId, provenKey: session.identityKey, ownerNodeId: owner.nodeId });
    return v.ok ? { admit: true } : { admit: false, reason: `room-join grant refused: ${v.reason}` };
  }

  /**
   * Fan a CMB out to every peer, or to one peer when `to` is set (MMP §4.4.4).
   * @returns {{ dispatched: number, reason: string|null }} `dispatched` counts frames a transport
   *   accepted (not frames a peer received); `reason` is why the last peer that did not get one did
   *   not (NOT_SENT_SAID's keys), or null when every target got one.
   * @private
   */
  _dispatchCmb(baseCmb, timestamp, to) {
    // The caller has already stored the CMB, so it persists regardless of how
    // many peers receive this frame.
    let targets;
    let reason = null;
    if (to) {
      const targeted = this._peers.get(to);
      if (targeted) {
        targets = [[to, targeted]];
      } else {
        targets = [];
        reason = SEND_FAILURE.NOT_CONNECTED;
        this._log(`Targeted send: peer ${to.slice(0, 8)} not connected; CMB stored locally only`);
      }
    } else {
      targets = this._peers;
    }

    let shared = 0;
    for (const [peerId, peer] of targets) {
      // One sealed frame per peer session (design D4): each session has its own keys. The record's
      // binding — directed or room-bound — is its signed, AAD-bound `metadata.to` (§8.8.4), never a
      // frame flag; the session refuses a record that is not a signed v2.0 record.
      const sent = trySend(peer.transport, { type: 'cmb', timestamp, cmb: baseCmb });
      // A transport refuses a frame when the socket is closed, the relay is not open, the write
      // failed or the frame is over MAX_FRAME_SIZE. Counting those as dispatched made a stale peer
      // read as reached, and reporting them all as "not connected" hid a frame no peer could take.
      if (sent.ok) { shared++; continue; }
      reason = sent.reason;
      if (sent.reason === SEND_FAILURE.TOO_LARGE) {
        this._log(`CMB ${String(recordKey(baseCmb) || '').slice(0, 16)} not sent to ${peer.name || peerId.slice(0, 8)}: its frame is ${sent.bytes} bytes, over the ${MAX_FRAME_SIZE}-byte bound`);
        this.emit('metric', { type: 'cmb-frame-too-large', to: peerId, key: recordKey(baseCmb), bytes: sent.bytes, limit: MAX_FRAME_SIZE });
      }
    }

    return { dispatched: shared, reason };
  }

  /**
   * Deliver the record of a send that minted nothing (collapsed onto HEAD, or already stored) to
   * its one addressed peer, and attach the same `delivery` result a fresh send carries, so the
   * send is answerable instead of looking delivered. The record is the caller's freshly signed
   * one: a new assertion of the same cognition (MMP §8.8.2), not a replay of an earlier send.
   * @private
   */
  _dispatchExisting(result, key, to) {
    const cmb = result.cmb || null;
    const { dispatched: shared, reason } = cmb ? this._dispatchCmb(cmb, Date.now(), to) : { dispatched: 0, reason: NOT_SENT.SEND_FAILED };
    Object.defineProperty(result, 'delivery', {
      value: Object.freeze({ directed: true, to, targets: this._peers.has(to) ? 1 : 0, dispatched: shared, undelivered: shared === 0, ...(shared === 0 ? { reason } : {}) }),
      enumerable: false,
      configurable: true,
    });
    if (shared === 0) {
      this._log(`UNDELIVERED (directed): ${to.slice(0, 8)} ${NOT_SENT_SAID[reason] || reason} — record ${String(key).slice(0, 16)} NOT sent`);
      this.emit('metric', { type: 'cmb-undelivered', to, key, reason });
    }
  }

  /**
   * Attach an undelivered `delivery` result for a directed send that was deliberately not sent.
   * @private
   */
  _markUndelivered(result, key, to, reason) {
    Object.defineProperty(result, 'delivery', {
      value: Object.freeze({ directed: true, to, targets: this._peers.has(to) ? 1 : 0, dispatched: 0, undelivered: true, reason }),
      enumerable: false,
      configurable: true,
    });
    this._log(`UNDELIVERED (directed): ${to.slice(0, 8)} — ${reason}; record ${String(key).slice(0, 16)} NOT sent`);
    this.emit('metric', { type: 'cmb-undelivered', to, key, reason });
  }

  /**
   * Whether a frame of `type` may be sent on `session` (§16.3: an extension's frames only where it was
   * selected). Core frames always may.
   * @private
   */
  _sessionTakes(session, type) {
    if (!session || typeof session.has !== 'function') return true;
    if (ATTEST_FRAMES.has(type)) return session.has(EXT_ATTEST);
    if (type === 'xmesh-insight') return session.has(EXT_XMESH_INSIGHT);
    return true;
  }

  _broadcastToPeers(frame) {
    let delivered = 0;
    for (const [, peer] of this._peers) {
      if (!this._sessionTakes(peer.transport, frame && frame.type)) continue;
      try {
        if (peer.transport && peer.transport.send(frame) !== false) delivered++;
      } catch {
        // A session that failed counts as undelivered; its close handler cleans up the peer.
      }
    }
    return delivered;
  }

  _checkHeartbeats() {
    const now = Date.now();
    // Per session (§5.4): every live path is checked, so a degraded secondary is found and closed.
    for (const session of [...this._sessions]) {
      if (!session.confirmed) continue;
      if (now - session.lastSeen > this._heartbeatTimeout) {
        this._log(`Heartbeat timeout: ${session.name} (${session.kind})`);
        session.close('heartbeat-timeout');
      } else if (now - session.lastSeen > this._heartbeatInterval) {
        try { session.send({ type: 'ping' }); } catch { /* the session closes itself */ }
      }
    }
  }

  _log(msg) {
    if (!this._silent) logMsg(this.name, msg);
  }
}

// ── meshmem → cmbs store migration ─────────────────────────────────────
// The per-node CMB store dir was renamed `meshmem/` → `cmbs/`. A fresh SymNode
// self-migrates its own dir on construct (above); this bulk pass migrates every
// node at sym / mesh-channel install so readers use the `cmbs/` name with no
// fallback. A LIVE node is skipped — it is running the prior code on `meshmem/`
// and self-migrates on its next restart; renaming under it would break it.
//
// Only a node that still needs the rename has its lock checked, and all of those
// checks share one start-time lookup: on Windows each lookup is a PowerShell
// process, and the daemon runs this pass at every start over every node dir.
function migrateStores(nodesRoot = path.join(require('./core/state-root').SYM_STATE_DIR, 'nodes')) {
  const { readLockFile, locksHeldByLiveProcess } = require('./config');
  let dirs;
  try { dirs = fs.readdirSync(nodesRoot, { withFileTypes: true }); } catch { return 0; }
  // Node dirs live under by-id/ since 0.14 (design D9); a 0.13 dir not yet moved is a real dir.
  let byId = [];
  try { byId = fs.readdirSync(path.join(nodesRoot, 'by-id'), { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => path.join(nodesRoot, 'by-id', d.name)); } catch { /* none yet */ }
  const pending = [
    ...dirs.filter((d) => d.isDirectory() && d.name !== 'by-id' && d.name !== 'by-name').map((d) => path.join(nodesRoot, d.name)),
    ...byId,
  ].filter((nodeDir) => fs.existsSync(path.join(nodeDir, 'meshmem')) && !fs.existsSync(path.join(nodeDir, 'cmbs')));
  const live = locksHeldByLiveProcess(pending.map((nodeDir) => readLockFile(path.join(nodeDir, 'lock.pid'))));
  let migrated = 0;
  pending.forEach((nodeDir, i) => {
    if (live[i]) return; // live node self-migrates on restart
    try { fs.renameSync(path.join(nodeDir, 'meshmem'), path.join(nodeDir, 'cmbs')); migrated++; } catch { /* leave it */ }
  });
  return migrated;
}

module.exports = { SymNode, migrateStores };

// The room grammar is a CROSS-IMPLEMENTATION CONTRACT, not an internal detail: a room name
// IS the Bonjour service type (§5.8), so every implementation that validates one must agree
// exactly or two nodes disagree about whether a room exists. It is exported here because
// consumers were otherwise obliged to keep their own copy — and copies drift. The plugin's
// fourth and fifth copies both did, one of them silently gating the room-persistence path
// while the runtime path accepted the same name.
Object.defineProperty(module.exports, 'rooms', {
  enumerable: true,
  get() { return require('./rooms'); },
});

// Lazy-load MeshAgent to avoid circular dependency (mesh-agent requires node)
// Lazy-load the Class 1 emitter (§17.1) — no node machinery required.
Object.defineProperty(module.exports, 'emit', {
  enumerable: true,
  get() { return require('./emit'); },
});

Object.defineProperty(module.exports, 'MeshAgent', {
  get() { return require('./mesh-agent').MeshAgent; },
  enumerable: true,
});

Object.defineProperty(module.exports, 'llm', {
  get() { return require('./llm-reason'); },
  enumerable: true,
});

// Backward compat — agents using { claude } still work
Object.defineProperty(module.exports, 'claude', {
  get() { return require('./llm-reason'); },
  enumerable: true,
});

// Core Secure host API (0.14): identities by nodeId, relocation, invites — so a host (XMesh,
// mesh-channel) never reaches into lib/ paths or underscore fields.
Object.defineProperty(module.exports, 'identity', {
  enumerable: true,
  get() {
    const c = require('./config');
    return {
      loadIdentity: c.loadIdentity, renameIdentity: c.renameIdentity, migrateIdentities: c.migrateIdentities,
      nodeDirById: c.nodeDirById, nodeIdForName: c.nodeIdForName, readTombstone: c.readTombstone,
      IdentityAbsentError: c.IdentityAbsentError, IdentityTombstonedError: c.IdentityTombstonedError, IdentityHaltError: c.IdentityHaltError,
    };
  },
});
Object.defineProperty(module.exports, 'relocation', {
  enumerable: true,
  get() { return require('./relocation'); },
});
Object.defineProperty(module.exports, 'invite', {
  enumerable: true,
  get() { return require('./invite'); },
});

Object.defineProperty(module.exports, 'platform', {
  get() { return require('./platform'); },
  enumerable: true,
});
