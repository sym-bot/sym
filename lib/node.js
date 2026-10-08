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
const authorityMixin = require('./node-authority');
const { parsePin } = require('./core/authority');
const { RosterKeyRegistry, keyFingerprint } = require('./roster-keys');
const { signedProjection, isLowerUuid } = require('./core/record-canonical');
const { buildMoodFrame } = require('./core/mood-frame');
const { isRoomId } = require('./core/room-id');
/** A stored record's signed projection, or null for one that is not a v2.0 record. */
const projectionOrNull = (cmb) => {
  if (!cmb || !cmb.metadata || cmb.metadata.signatureSuite !== 'mmp-sig-v2.0') return null;
  try { return signedProjection(cmb); } catch { return null; }
};
const { wireNodeId, wireName, wireKey } = require('./wire-identity');
const { keepPeerState } = require('./peer-state');
const { RoomOwnershipRegistry } = require('./room-ownership');
const { verifyRoomGrant, grantForWire } = require('./core/room-grant');
const { DecisionLog } = require('./decision-log');
const {
  encode, DIM, createCMB, renderContent, FIELD_WEIGHT_PROFILES,
  WakeManager,
  signCMB, assertionIdV2_0, mintRemixKey, signAttestation, verifyAttestation, verifyAttestationRole,
  merkleRoot, signCheckpoint, verifyCheckpoint, signWitness, verifyWitness,
  CAT7_CATEGORIES, assertRecordSendable,
  attestMerkleRoot, attestCheckpointRoot, toWireAttestation, toWireCheckpoint, toWireWitness, ATTEST_FRAME,
} = require('./core');
/** What a checkpoint made since 0.14 commits (the sym-attest-v1 root); one without it is 0.13's. */
const ATTEST_SCHEME = 'sym-attest-v1';
/** How long the witnesses of a node that contradicted a held, attester-signed checkpoint are dropped. */
const WITNESS_MUTE_MS = 10 * 60 * 1000;
const { MMP_EMIT_V2 } = require('./emit-policy'); // the single reader-first flip switch
/** How far this node's record timestamps may run ahead of its clock before they follow it again. */
const MAX_CLOCK_LEAD_MS = 60 * 1000;
const { FrameHandler, MESSAGE_SCHEMA } = require('./frame-handler');
const { TcpTransport } = require('./transport');
const { PeerSession, IDENTITY_CONFLICT, UNKNOWN_SESSION } = require('./session');
const { LegacyImport } = require('./legacy-import');
const { EXT_CMB_ENCRYPTED_V2 } = require('./core/mmp-extensions');
const ENGINE_VERSION = require('../package.json').version;
/**
 * Extensions this node offers in every hello by default (§16). An extension is active on a session
 * only when both offered it and it was selected (§16.3), and its frames are sent only on such
 * sessions:
 *   cmb-encrypted-v2  — records travel sealed; required: a session without it is not Core Secure.
 *   sym-attest-v1     — admission attestations, checkpoints, witnesses, node-stats (registered as a
 *                       Draft Candidate in MMP 2.0 update 1, §16.4).
 *
 * xmesh-insight-v1 (the Layer-6 insight frame) is not offered by default: it is registered nowhere
 * (the frame registry lists `xmesh-insight` as a legacy type), so a host that wants it adds it with
 * opts.extraExtensions. (opts.extensions replaces the whole list.)
 */
const EXT_ATTEST = 'sym-attest-v1';
const EXT_XMESH_INSIGHT = 'xmesh-insight-v1';
const OFFERED_EXTENSIONS = Object.freeze([EXT_CMB_ENCRYPTED_V2, EXT_ATTEST]);
/** An extension token as §16.3 offers it: lowercase, versioned. */
const EXTENSION_TOKEN = /^[a-z][a-z0-9-]{0,62}-v[0-9]+$/;
/** Frames that ride only on sessions that selected sym-attest-v1. */
// The extension's frames (MMP §16.2 names, draft spec PR meshcognition-website#27); sym 0.13's bare
// `attestation` / `checkpoint` / `witness` / `node-stats` are never sent on a Core Secure session.
const ATTEST_FRAMES = new Set(Object.values(ATTEST_FRAME));
/** Legacy hellos refused on the Core Secure listener are said at most once a minute per address. */
const LEGACY_REFUSAL_REPORT_MS = 60_000;
const { SEND_FAILURE, MAX_FRAME_SIZE } = require('./frame-parser');
const { RelayConnection } = require('./relay');
const { BonjourDiscovery, NullDiscovery, mmpLists20 } = require('./discovery');

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
 * One lane's budget of NEW gossiped statements (attestations, checkpoints, witnesses, authority statements): a
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
/** A room as signed statements compare it: NFC (this node's room is NFC; sym-attest-v1 signs nfc(room)). */
const nfcRoom = (r) => (typeof r === 'string' ? r.normalize('NFC') : r);
/**
 * Statements one peer relays for one signer that may fail under this node's binding for that signer
 * in a window before that peer's statements for that signer are dropped unverified for the rest of it
 * (final re-review, Finding 3).
 */
const RELAY_FAILURES_MAX = 8;
const RELAY_FAILURE_WINDOW_MS = 60_000;
/**
 * Unread inbox items the node holds at most, as a multiple of the ring size: an unread item is never
 * evicted, and past this a new delivery gets no inbox id (it is counted and said).
 */
const INBOX_UNREAD_FACTOR = 4;
/** inbox file -> the SymNode in this process that owns it (see the constructor). */
const INBOX_OWNERS = new Map();
/** A peer that delivered a forged signature is not admitted again for this long (security review D). */
const FORGERY_PENALTY_MS = 60_000;
/**
 * MMP §7.2 error codes (lib/session.js): 1011 UNKNOWN_SESSION ("this node holds no session with you",
 * draft spec PRs #23 and #31: it only prompts a new handshake), 1010 SESSION_CLOSED (sealed, a
 * session closing), 1009 IDENTITY_CONFLICT (draft spec PR #21: a bound nodeId proving another key).
 */
const UNKNOWN_SESSION_CODE = UNKNOWN_SESSION;
/** The frame types this node knows, for counting (anything else counts as 'other'). */
const KNOWN_FRAME_TYPES = new Set(['cmb', 'cmb-encrypted', 'control-encrypted', 'client-hello', 'server-hello', 'client-finish',
  'ping', 'pong', 'error', 'cmb-anchors', 'mood', 'wake-channel', 'peer-info', 'sym-attest-attestation', 'sym-attest-checkpoint',
  'sym-attest-witness', 'sym-attest-node-stats', 'attestation', 'checkpoint', 'witness', 'node-stats', 'cmb-fetch', 'cmb-fetch-result',
  'role-grant', 'role-revoke', 'role-chain-fetch', 'role-chain', 'role-digest', 'authority-statement', 'authority-digest',
  'authority-fetch', 'authority-set', 'xmesh-insight', 'room-join', 'handshake',
  'state-sync', 'message', 'session-confirmed', 'relay-auth', 'relay-peers', 'relay-peer-joined', 'relay-peer-left',
  'relay-ping', 'relay-pong', 'relay-reauth', 'relay-error']);
/** 1011 replies to relay froms this node holds no session with: a token bucket over all of them. */
const UNKNOWN_SESSION_PER_SECOND = 2;
const UNKNOWN_SESSION_BURST = 8;
/** Peers that refused this node with 1009, not dialled again automatically (LAN or relay). */
const IDENTITY_REFUSED_MAX = 1024;
/**
 * Relay handshakes in flight at once, at most (each holds a deadline and costs a key agreement), of
 * which UNKNOWN candidates — a nodeId with no binding, no peer and no route, which anyone can mint
 * and a relay can announce by the thousand — hold at most RELAY_UNKNOWN_MAX: the rest are reserved
 * for configured, pinned and previously bound peers (security review D, announce-starve). An unknown
 * candidate past its share waits in turn (fewest failures first, then the newest), and one that
 * failed waits longer each time, up to RELAY_UNKNOWN_BACKOFF_MAX_MS.
 */
const RELAY_HANDSHAKES_MAX = 256;
const RELAY_UNKNOWN_MAX = 32;
const RELAY_UNKNOWN_BACKOFF_MAX_MS = 10 * 60_000;
/** One relay `from`'s client-hellos: a token bucket (security review D, relay-orphan). */
const RELAY_HELLO_PER_SECOND = 1;
const RELAY_HELLO_BURST = 4;
/**
 * Inbound LAN handshakes in flight (authenticating sessions) at most, in all and per remote host;
 * past either the oldest is closed (security review D, hello-cost).
 */
const LAN_HANDSHAKES_MAX = 128;
const LAN_HANDSHAKES_PER_HOST = 8;
/** A LAN peer whose dial or handshake failed is dialled again after 15 s, doubling to this at most. */
const LAN_BACKOFF_MAX_MS = 10 * 60_000;

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

/** Throw EBADTO unless `to` is absent (null/undefined: room-bound) or a lowercase UUID (§3.1.1). */
function assertAddressee(to) {
  if (to === undefined || to === null || isLowerUuid(to)) return;
  const e = new TypeError(`to must be a nodeId, a lowercase UUID (got ${JSON.stringify(String(to).slice(0, 40))})`);
  e.code = 'EBADTO';
  throw e;
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
    // A host adds tokens through config (opts.extraExtensions), after the defaults; each is offered once.
    const extra = Array.isArray(opts.extraExtensions) ? opts.extraExtensions.filter((t) => typeof t === 'string' && EXTENSION_TOKEN.test(t)) : [];
    this._offeredExtensions = [...new Set([...(opts.extensions || OFFERED_EXTENSIONS), ...extra])];
    this._implementation = { name: 'sym', version: ENGINE_VERSION };
    // A stalled handshake ends in a few seconds (security review D): a hello costs this node a key
    // agreement and a signature, and an authenticating session holds a slot.
    this._handshakeTimeoutMs = opts.handshakeTimeoutMs || 5_000;
    this._legacyRefusals = new Map(); // address -> { at, more }: legacy hellos refused on the listener
    this._sessionStats = { confirmed: 0, failed: 0, failedByReason: {}, refusedFrames: 0, refusedByReason: {}, desync: 0, superseded: 0, legacyHellosRefused: 0 };
    // Legacy Import (design D7) is created after the node dir and the key registry exist (below).
    this._legacyRoutes = opts.legacyRoutes || null;
    this._legacy = null;

    // The anchor (MMP §6.6.1): a pinned key set with a threshold, configured out of band —
    // opts.anchor { threshold, keys: [{ key, nodeId? }] }, the 1-of-1 { nodeId, publicKey }, or
    // SYM_FOUNDER_ANCHOR ("nodeId:publicKey", or the pin as JSON). Never learned from the wire.
    // Without one nothing is in force, and the node falls back to its static `lifecycleRole` (§6.5).
    this._pin = parsePin(opts.anchor !== undefined ? opts.anchor : (process.env.SYM_FOUNDER_ANCHOR || null));
    // Roster key registry — authenticated nodeId→key bindings, so signatures from peers
    // we never directly handshook still verify. Sources: the anchor pin, a proven session, an
    // out-of-band pin, an in-force grant (a view, never stored); the relayer never vouches.
    // Persisted under the node dir.
    // nodeId -> { key, sessions }: the key each live confirmed session proved (see _admitSession).
    this._sessionKeys = new Map();
    this._roster = new RosterKeyRegistry({
      // Each pinned anchor member configured with its nodeId binds that nodeId (configuration).
      anchors: this._pin ? this._pin.members.filter((m) => m.nodeId).map((m) => ({ nodeId: m.nodeId, publicKey: m.key })) : [],
      // This node's own nodeId is its own key: no session, pin or grant binds it to another (review C).
      self: { nodeId: this.nodeId, publicKey: this._identity.publicKey },
      dir: path.join(this._dir, 'roster-keys'),
      log: (m) => this._log(m),
      // A node with a live session never has its binding expired (design D3 binding lifetime).
      isLive: (nodeId) => !!(this._peers && this._peers.has(nodeId)),
      // The sticky floor arms only for a nodeId that has a Legacy Import route (finite, configured).
      isRouted: (nodeId) => !!(this._legacy && this._legacy.routeFor && this._legacy.routeFor(nodeId)),
      bindingTtlMs: opts.bindingTtlMs,
      maxBindings: opts.maxKeyBindings,
    });
    {
      const mig = this._roster.migration();
      if (mig && mig.read > 0) this._log(`Key registry migrated from 0.13: ${mig.bindings} binding(s), ${mig.legacyClaim} relabelled legacy-claim (expected keys, never verifying), ${mig.grant} of them from 0.13 grants (no 0.13 grant confers authority or binds a key now)`);
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
    // Authority (MMP §6.6): the verified grant, revoke and endorse statements this node holds, and
    // the in-force set they resolve to — a function of the set, never of arrival order or any clock.
    // Persisted under the node dir and verified again at every load.
    authorityMixin.initAuthority(this, opts);
    // A grant binding is a view over the in-force grants (§6.6.9): it binds an unbound nodeId only,
    // never this node's own.
    this._roster.setGrantView((nodeId) => (nodeId === this.nodeId ? undefined : this._authority.grantKey(nodeId)));
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
    // THE INBOX JOURNAL (inbox-id bug, 2026-10): every inbox change is appended here before it takes
    // effect — a delivery before its id is announced, a drain, an ack — and `inbox.json` is a
    // snapshot the journal is folded into. The snapshot alone was written at most once a second, so a
    // process that ended between a delivery and its write lost the delivery while its id had been
    // announced, and the next instance announced the same id for another record.
    this._inboxJournal = path.join(this._dir, 'inbox.log');
    // One owner per inbox in this process: the newest node built for the identity (a hot-swap builds
    // the next before the last may have stopped). A node that is no longer the owner assigns no id and
    // writes nothing, so two instances never number deliveries apart, and a fetch reads the inbox the
    // announcement came from.
    INBOX_OWNERS.set(this._inboxFile, this);
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
        this._emitAccepted(stored);
        this.emit('metric', { type: stored.profile === 'legacy-import' ? 'legacy-record' : 'cmb-accepted', from: entry.source || peerId, key: stored.key });
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
      remixProduced: 0,      // Remixes minted through the gated remix path (remix()); a record that cites parents is not thereby one (§15.7)
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
      framesRefusedByType: Object.create(null), // ...by frame type (known types; the rest as 'other')
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
    // §5.8: a room identifier is [a-z0-9._-], 1 to 64 characters (MMP 2.0 update 1, one grammar
    // everywhere); a node in any other room could mint no record a peer takes. ASCII, so it is NFC.
    this._room = opts.room === undefined || opts.room === null || opts.room === '' ? 'default' : opts.room;
    if (!isRoomId(this._room)) {
      const e = new RangeError(`SymNode: room ${JSON.stringify(String(this._room).slice(0, 80))} is not a §5.8 room identifier ([a-z0-9._-], 1 to 64 characters)`);
      e.code = 'EBADROOM';
      throw e;
    }

    // Discovery — pluggable for testability. See MMP v0.2.0 Section 5.
    // `discoveryServiceType` enables LAN-level Bonjour isolation for mesh
    // rooms (MMP §5.8: "Bonjour isolation + relay token for WAN"). Default
    // `_sym._tcp` preserves backward compatibility; per-room service types
    // (e.g. `_melotune._tcp`, `_melotune-{roomId}._tcp`) isolate LAN peers
    // at the mDNS layer so nodes in different rooms never discover each
    // other. Matches the sym-swift SymNode(discoveryServiceType:) parameter.
    this._discoveryServiceType = opts.discoveryServiceType || '_sym._tcp';
    // §5.1 migration (MMP 2.0 update 1): every room is advertised on _sym._tcp with TXT room; the
    // per-room types earlier releases advertised are browsed too (opts.discoveryBrowseTypes), never
    // advertised.
    this._discoveryBrowseTypes = Array.isArray(opts.discoveryBrowseTypes) ? opts.discoveryBrowseTypes : [];
    this._discovery = opts.discovery || (
      opts.relayOnly
        ? new NullDiscovery()
        : new BonjourDiscovery({ serviceType: this._discoveryServiceType, browseTypes: this._discoveryBrowseTypes, room: this._room })
    );
    // The room a discovery advertises in TXT is this node's (§5.1), whoever built the discovery: the
    // dial filter compares TXT room with it, so an advertisement in another room is never this node's.
    if (typeof this._discovery.setRoom === 'function') this._discovery.setRoom(this._room);

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
      // A queued frame goes only to a session proving the key bound when it was queued.
      keyOf: (nodeId) => this._identityKey(nodeId),
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
   * The key that verifies `nodeId`'s signatures: its binding in the key registry (design D3) —
   * the configured anchor, a proven session, an out-of-band pin, or an in-force grant (§6.6.9).
   * Never a key a hello merely announced, and never a legacy claim.
   * @private
   */
  _identityKey(nodeId) {
    const k = this._roster.get(nodeId);
    if (k !== undefined) return k;
    // A nodeId with no durable binding verifies under the key its live Core Secure session proved,
    // for as long as that session lasts (the session-scoped binding). A legacy claim is not a
    // binding, so this never applies to an id the registry expects another key for.
    if (this._roster.expected(nodeId) !== undefined) return undefined;
    const held = this._sessionKeys && this._sessionKeys.get(nodeId);
    return held && [...held.sessions].some((s) => s.confirmed && !s.closed && !s.legacy) ? held.key : undefined;
  }

  /** Where the key that verifies `nodeId` comes from: a registry source, 'session', or undefined. */
  _keySource(nodeId) {
    const src = this._roster.source(nodeId);
    if (src !== undefined && src !== 'legacy-claim') return src;
    if (src === undefined && this._identityKey(nodeId) !== undefined) return 'session';
    return src;
  }

  /**
   * An admitted verified record by `nodeId` under `key` (frame-handler): the binding is EARNED. One
   * the registry holds for that key is marked verified (it never expires); a nodeId it holds nothing
   * for, proven by a live session under that very key, is bound `proven` now (security review D).
   * @private
   */
  _earnBinding(nodeId, key) {
    if (!nodeId || !key) return;
    const k = this._roster.get(nodeId);
    if (k === key) { this._roster.noteVerified(nodeId); return; }
    if (k !== undefined || this._roster.expected(nodeId) !== undefined) return;
    const held = this._sessionKeys.get(nodeId);
    if (!held || held.key !== key || ![...held.sessions].some((s) => s.confirmed && !s.closed)) return;
    const b = this._roster.bind(nodeId, key, 'proven');
    if (b.bound) this._roster.noteVerified(nodeId);
  }

  /**
   * MMP §15.8 retroactive lineage-tether audit: apply the tether to the chains of records this node
   * minted itself. A peer's record this node holds is a collapsed integration, kept exactly as its
   * author signed it: the tether is the remixing node's to apply, and does not apply to it (§15.5,
   * MMP 2.0 update 1, #17), so the audit leaves it alone.
   * Walks every stored record of this node's carrying lineage, resolves its nearest anchor
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
      // A peer's record (a collapsed integration, its author's as signed): no tether (§15.5).
      if (entry.peerId != null || entry.collapsed === true) continue;
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
          // The categories, whether or not the record verified: the key binds them (§15.8 MAY use them).
          if (hit?.categories) { anchorCategories = hit.categories; anchorKey = k; report.fetched++; break; }
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

  /**
   * MMP §7 cmb-fetch: retrieve a record by its cognition key from connected peers — the §15.8 path
   * for lineage roots this store cannot resolve. A copy whose recomputed key differs is discarded and
   * reported, so no trust in the serving peer is needed for the categories. The key binds nothing
   * else (§8.8.2), so the record is then verified by the whole of §8.8.5 (MMP 2.0 update 1, #26):
   *
   *   { key, verified: true,  cmb, categories, authorNodeId, from, peerId }  — it passed: a record
   *   { key, verified: false, categories, reason, from, peerId }             — the categories only
   *
   * An unverified answer never carries the record's metadata, so nothing reads it as attributed. A
   * record this node holds answers first: its own, or one it admitted verified, as a record; one held
   * under Legacy Import as its categories only.
   *
   * @param {string} key - cognition key, cmb-<64 hex>
   * @param {object} [opts]
   * @param {number} [opts.timeoutMs=5000]
   * @returns {Promise<object|null>} the first answer whose key matches, or null when none does.
   */
  async fetchCMB(key, opts = {}) {
    if (!key || typeof key !== 'string') return null;
    const local = this._store.get(key);
    if (local?.cmb) {
      const categories = local.cmb.categories;
      const own = local.peerId == null;
      if (own || local.verified === true) {
        return { key, verified: true, cmb: local.cmb, categories, authorNodeId: own ? this.nodeId : (local.cmb.metadata?.createdByNodeId ?? null), from: this.name, peerId: this.nodeId };
      }
      return { key, verified: false, reason: local.profile === 'legacy-import' ? 'legacy-import' : 'unverified', categories, from: this.name, peerId: this.nodeId };
    }
    // Only a cognition key is asked for (cmb-fetch.schema.json): a peer refuses a request for anything else.
    if (this._peers.size === 0 || !/^cmb-[0-9a-f]{64}$/.test(key)) return null;
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
          if (peer.transport.send({ type: 'cmb-fetch', reqId, key, timestamp: Date.now() }) !== false) asked.add(peerId);
        }
      }
      if (asked.size === 0) done(null);
    });
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
    // §6.5: this node's lifecycle authority over THAT CMB, judged on its own signed fields (a scoped
    // grant counts only inside its scope), against the in-force set now.
    const e = this._store.get(key);
    return this._store.validateCMB(key, { lifecycle: this._authority.anchored ? this.lifecycleAuthority(this.nodeId, this._identity.publicKey, e && e.cmb) : lifecycleOfRole(this._lifecycleRole) });
  }

  /**
   * Advance a CMB to `canonical` under THIS node's earned authority — reserved to anchor
   * rank (§6.5). Resolves this node's role and lets the store enforce the gate.
   * @param {string} key
   * @returns {{ ok: boolean, reason?: string }}
   */
  canonizeCMB(key) {
    const e = this._store.get(key);
    return this._store.canonizeCMB(key, { lifecycle: this._authority.anchored ? this.lifecycleAuthority(this.nodeId, this._identity.publicKey, e && e.cmb) : lifecycleOfRole(this._lifecycleRole) });
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
    try {
      // sym-attest-v1 §5.4: the counts and the time only; the receiver attributes them to this
      // node's proven session (a self-asserted name and nodeId are not carried).
      const s = this._nodeStats();
      this._gossipToRoster({ type: ATTEST_FRAME.nodeStats, stats: { emitted: s.emitted, admitted: s.admitted, memory: s.memory, at: s.at } });
    } catch (err) { this._log(`node-stats emit failed: ${err.message}`); }
  }

  /**
   * Ingest a peer's gossiped node-stats: surface it as a `node-stats` event for hosts
   * (e.g. the Mesh Edge observer) to render. Self-reported and unsigned — it's a
   * convenience metric, not an authority claim, so it is taken at face value and not
   * stored. Ignores our own echo.
   * @private
   */
  _ingestNodeStats(stats, fromPeerId, fromPeerName) {
    if (!stats || !fromPeerId || fromPeerId === this.nodeId) return;
    // Attributed to the session's proven peer, never stored, never evidence (sym-attest-v1 §5.4).
    this.emit('node-stats', Object.freeze({ nodeId: fromPeerId, name: fromPeerName || null, emitted: stats.emitted, admitted: stats.admitted, memory: stats.memory, at: stats.at }));
  }

  /**
   * Build + sign an Admission Attestation for a CMB this node just gated — the
   * authoritative, durable per-category gating record (MMP admission-attestation
   * layer). Binds the gated CMB (`of`), this node's identity (`by`), the roster,
   * the overall + per-category verdict, this node's CLAIMED lifecycle role, and the
   * per-attester hash-chain position (`seq`/`prev`), all under an Ed25519 signature
   * (same key as CMB signing). `role` is claimed — consumers verify it against their
   * own in-force authority set (MMP §6.6.10, sym-core `verifyAttestationRole`), never the stamp.
   * Returns the signed attestation, or null if signing fails.
   * @param {string} of - the gated (incoming) CMB key
   * @param {string} verdict - overall decision (aligned|guarded|redundant|rejected)
   * @param {object} categoryVerdicts - per-CAT7-category verdict map (Phase A output)
   * @param {string} method - 'neural' | 'heuristic'
   * @private
   */
  _buildAdmissionAttestation(of, verdict, categoryVerdicts, method, assertionId, { quarantined = false, directed = false } = {}) {
    // No attestation is signed about a Legacy Import record (#27: only records verified under Core
    // Secure are attested; every receiver refuses one without an assertion id) or about a directed
    // record (#27: the room would learn a sealed one-to-one record's key, assertion and verdict, a
    // confirmation oracle on private content). Neither enters this node's chain, so the chain the room
    // sees has no gap where one was left out.
    if (quarantined || directed) return null;
    const att = {
      of,
      assertionId,
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
      this._attestHead = chainHash(att.sig); // sha256 of the signature's bytes (sym-attest-v1 §5.1)
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
   * registry — unverifiable ones are EXCLUDED, never weighted — and (2) role-resolved against
   * the in-force set NOW (MMP §6.6.10), a scoped role only for a CMB inside its scope; the
   * attestation's own time plays no part. Weight = 2^rank (participant and issuer 1,
   * validator 2, admin and anchor 4): everyone counts, earned rank counts more. The
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
    const byRole = { participant: 0, issuer: 0, validator: 0, admin: 0, anchor: 0 };
    const mismatches = [];
    const excluded = [];
    let total = 0;
    let weight = 0;

    for (const att of atts) {
      // (1) signature gate — an attestation we cannot verify is evidence, not a vote.
      const key = this._identityKey(att.by);
      if (!key) { excluded.push({ by: att.by, reason: 'unknown-key' }); continue; }
      if (!verifyAttestation(att, key).valid) { excluded.push({ by: att.by, reason: 'bad-signature' }); continue; }
      // (2) the attester's role in force NOW over the attested CMB (§6.6.10: a weight is judged against
      // the in-force set at the moment it is applied; the attestation's own time plays no part).
      const rr = verifyAttestationRole(att, () => this._attesterRole(att));
      if (!rr.matches) mismatches.push({ by: att.by, claimed: rr.claimed, resolved: rr.resolved });
      const w = 2 ** authorityMixin.lifecycleRank(rr.resolved); // participant and issuer 1, validator 2, admin and anchor 4

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
    this._gossipToRoster({ type: ATTEST_FRAME.attestation, attestation: toWireAttestation(att) }, exceptPeerId);
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
   * Build, sign, record, and gossip a checkpoint (sym-attest-v1 §5.2, MMP 2.0 update 1): the chained
   * root over this node's attestations since its last checkpoint, seq fromSeq..uptoSeq, chained to that
   * checkpoint's root (`genesis` for the first). So it commits to the whole history from seq 1 while
   * this node holds only the segment since its last checkpoint. Roster peers witness it.
   *
   * The segment and the previous checkpoint are persisted before anything that depends on them is sent
   * (the store appends each attestation and checkpoint to its log before it is gossiped). A node that
   * has lost them (a lost log, a store that evicted its own segment) signs no checkpoint over fewer: its
   * checkpoint chain ends there, visibly (said once, `checkpoint-chain-ended`), and no further one is
   * signed under it. No root is ever signed over the attestations it happens to still hold.
   * @returns {object|null} the checkpoint, or null when none is signed.
   * @private
   */
  _emitCheckpoint() {
    const chain = this._attestations.chainOf(this.nodeId);
    if (chain.length === 0) return null;
    const head = chain[chain.length - 1].seq;
    const last = this._attestations.latestChainedCheckpoint(this.nodeId);
    const fromSeq = last ? last.upto_seq + 1 : 1;
    const prev = last ? last.root : 'genesis';
    if (head < fromSeq) return null; // nothing new since the last checkpoint
    const bySeq = new Map(chain.map((a) => [a.seq, a]));
    const segment = [];
    for (let s = fromSeq; s <= head; s++) {
      const a = bySeq.get(s);
      if (!a) { segment.length = 0; break; }
      segment.push(a);
    }
    // The previous checkpoint is the chain's own; with none held, the chain starts at seq 1 or not at all.
    if (segment.length === 0 || (!last && chain[0].seq !== 1)) {
      if (!this._checkpointChainEnded) {
        this._checkpointChainEnded = true;
        this._log(`Checkpoint chain ended: this node no longer holds its attestations ${fromSeq}..${head}${last ? ` after its checkpoint at ${last.upto_seq}` : ' from seq 1'} (sym-attest-v1 §5.2: no root is signed over fewer)`);
        this.emit('metric', { type: 'checkpoint-chain-ended', fromSeq, uptoSeq: head });
      }
      return null;
    }
    if (this._checkpointChainEnded) return null;
    const segmentRoot = attestMerkleRoot(segment.map((a) => a.sig)); // promote-odd, leaf/node tags
    const cp = {
      type: 'checkpoint',
      scheme: ATTEST_SCHEME,
      by: this.nodeId,
      roster: this._room,
      from_seq: fromSeq,
      upto_seq: head,
      prev,
      root: attestCheckpointRoot({ prev, fromSeq, uptoSeq: head, segmentRoot }),
      at: Date.now(),
    };
    try {
      signCheckpoint(cp, this._identity.privateKey);
      if (!isCanonicalSig(cp.sig)) throw new Error('signature not in canonical form');
      this._attestations.recordCheckpoint(cp);
      this._gossipToRoster({ type: ATTEST_FRAME.checkpoint, checkpoint: toWireCheckpoint(cp) });
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
  _ingestCheckpoint(cp, fromPeerId, session = null) {
    if (!cp || !cp.by || cp.upto_seq === undefined || cp.from_seq === undefined || !cp.prev || !cp.root || !sigOk(cp.sig)) return { ok: false, reason: 'malformed' };
    if (cp.roster && this._room && nfcRoom(cp.roster) !== this._room) return { ok: false, reason: 'roster-mismatch' };
    // A position is an integer; the signature covers its text, so a re-spelled one is refused here,
    // before any signature check. A copy of a held checkpoint (same position, same root), of a
    // conflicting one already refused, or one older than every position held, is dropped unverified:
    // under the witness storm most of a node's thread went to verifying copies it already held.
    // Only a new statement spends the peer's budget, and it does so before its signature is checked.
    // Nothing unverified changes any state.
    if (!isPosition(cp.upto_seq) || !isPosition(cp.from_seq)) return { ok: false, reason: 'malformed' };
    const held = this._attestations.checkpointAt(cp.by, cp.upto_seq);
    const same = (c) => !!c && c.from_seq === cp.from_seq && c.prev === cp.prev && c.root === cp.root;
    if (same(held)) return { ok: false, reason: 'duplicate' };
    if (same(this._attestations.conflictAt(cp.by, cp.upto_seq))) return { ok: false, reason: 'duplicate' };
    // The link checks (§5.2) need no signature: a checkpoint that does not start right after the one
    // its prev names is malformed, never evidence.
    if (!this._attestations.linkValid(cp)) return { ok: false, reason: 'malformed-link' };
    // An attester this node holds equivocation evidence against: its further checkpoints add nothing
    // and are dropped unverified (§6 step 6), which bounds the evidence to one copy per attester.
    if (this._attestations.attesterEquivocated(cp.by)) return { ok: false, reason: 'attester-equivocated' };
    if (this._attestations.isStale(cp.by, cp.upto_seq)) return { ok: false, reason: 'stale' };
    if (!isCanonicalSig(cp.sig)) return this._refuseSpelling(fromPeerId, 'checkpoint', cp.by);
    const key = this._identityKey(cp.by);
    if (!key) return { ok: false, reason: 'unknown-attester-key' };
    if (this._relayMuted(fromPeerId, cp.by)) return { ok: false, reason: 'relayed-signer-muted' };
    if (!this._gossipBudget(fromPeerId, 'checkpoint', cp.by)) return { ok: false, reason: 'over-budget' };
    if (!verifyCheckpoint(cp, key).valid) { this._penaliseForgery(session, 'checkpoint', { author: cp.by, key }); return { ok: false, reason: 'bad-signature' }; }
    if (!this._gossipCeiling(fromPeerId, 'checkpoint', cp.by)) return { ok: false, reason: 'over-ceiling' };
    // A verified gossip statement does not make its signer's binding durable (security review D:
    // only an admitted record, a grant in effect or a pin does; a fresh identity signs statements free).
    // A new position is taken at most at its attester's rate, whichever peer brings it: past that it is
    // not stored, witnessed or relayed. Checked after the signature, so no one else can spend it. A
    // second root for a held position is the evidence of equivocation, kept once and free (a third is
    // dropped above).
    if (!held && !this._checkpointRateOk(cp.by, fromPeerId)) return { ok: false, reason: 'over-rate' };
    const r = this._attestations.recordCheckpoint(cp);
    if (r.reason === 'conflict' && r.first) {
      // Two checkpoints that cannot lie on one chain (overlapping ranges, or one prev with two children):
      // equivocation, or a chain restarted after a lost log.
      const kept = r.kept || held;
      this._log(`[sym-security] conflicting checkpoint from ${String(cp.by).slice(0, 8)}: ${cp.from_seq}..${cp.upto_seq} against the held ${kept ? `${kept.from_seq}..${kept.upto_seq}` : '?'} (${(r.because || ['same position']).join(', ')}); kept root ${String(r.keptRoot).slice(0, 12)}, refused ${String(cp.root).slice(0, 12)}; this attester is no longer witnessed`);
      this.emit('metric', { type: 'attestation-conflict', kind: 'checkpoint', attester: cp.by, upto_seq: cp.upto_seq, from_seq: cp.from_seq, because: r.because || null, keptRoot: r.keptRoot, otherRoot: cp.root });
      // The conflicting copy is relayed once, as evidence, so the room learns of the equivocation (#27);
      // a witness this node already signed for the first root stands.
      this._gossipToRoster({ type: ATTEST_FRAME.checkpoint, checkpoint: toWireCheckpoint(cp) }, fromPeerId);
    }
    if (r.stored) {
      this._gossipToRoster({ type: ATTEST_FRAME.checkpoint, checkpoint: toWireCheckpoint(cp) }, fromPeerId); // relay-once
      this._witnessCheckpoint(cp); // countersign as a roster witness
    }
    return { ok: r.stored, reason: r.reason };
  }

  /**
   * Spend one token of the PROVEN peer a NEW gossiped statement arrived from, before its signature is
   * checked (see GOSSIP_PER_SECOND and GOSSIP_NEW_LANE). Only the peer's own lane is spent before the
   * check (security review D: no shared budget is spent before verification), so a peer flooding
   * forgeries spends its own budget and nobody else's. A forgery in its own name ends its session
   * (`_penaliseForgery`); a statement it relays for another signer that fails here is dropped without
   * blaming it (its binding for that signer may differ), and past RELAY_FAILURES_MAX in a minute its
   * statements for that signer are dropped unverified (`_relayMuted`). The lane refills, so a peer that stops flooding is heard again within
   * burst/rate seconds. A dropped frame changes nothing: it is not marked seen, so another peer's copy
   * is taken. O(1). `cost` is the checks the statement will cost (an authority statement naming a key
   * not seen before costs more: see FRESH_KEY_COST and the asking rule in node-authority.js).
   * @returns {boolean} whether the frame may be verified
   * @private
   */
  _gossipBudget(peerId, type, author, cost = 1) {
    const now = this._gossipClock();
    const b = bucketOf(this._gossipBuckets, peerId, this._gossipRate, this._gossipBurst, this._gossipNewLane, now, GOSSIP_MAX_PEERS);
    if (b.tokens >= cost) { b.tokens -= cost; return true; }
    this._noteDrop('gossip-over-budget', peerId, { frame: type, author });
    return false;
  }

  /**
   * Reserve `amount` checks of `peerId`'s lane for an ask this node makes (MMP §6.6.8, the asking
   * rule in node-authority.js): taken now if the lane holds it (at most the burst is ever needed),
   * and given back, less what the answer cost, by `_gossipRefund`.
   * @returns {number} 0 when reserved; otherwise ms until the lane will hold it
   * @private
   */
  _gossipReserve(peerId, amount) {
    const now = this._gossipClock();
    const b = bucketOf(this._gossipBuckets, peerId, this._gossipRate, this._gossipBurst, this._gossipNewLane, now, GOSSIP_MAX_PEERS);
    const need = Math.min(amount, this._gossipBurst);
    if (b.tokens >= need) { b.tokens -= need; return 0; }
    return Math.max(1, Math.ceil(((need - b.tokens) * 1000) / this._gossipRate));
  }

  /** @private Give back what a reservation did not spend (never past the burst). */
  _gossipRefund(peerId, amount) {
    if (!(amount > 0)) return;
    const b = this._gossipBuckets.get(peerId);
    if (!b) return;
    refill(b, this._gossipRate, this._gossipBurst, this._gossipClock());
    b.tokens = Math.min(this._gossipBurst, b.tokens + amount);
  }

  /**
   * @private Spend `amount` of `peerId`'s lane with no floor: work already done for that peer (a
   * pending statement verified again once its chain arrived). A lane in debt pays it back before it
   * buys anything else, and this node asks that peer for nothing until it does.
   */
  _gossipSpend(peerId, amount) {
    const now = this._gossipClock();
    const b = bucketOf(this._gossipBuckets, peerId, this._gossipRate, this._gossipBurst, this._gossipNewLane, now, GOSSIP_MAX_PEERS);
    b.tokens -= amount;
  }

  /**
   * The shared ceiling over every peer, spent only AFTER a statement's signature verified (security
   * review D): what it bounds is the work verified statements cause (storing, relaying, witnessing),
   * which only signers whose keys this node holds can buy, never the signature checks forgeries cost.
   * Past it the verified statement is dropped unstored and unmarked, so a later copy is taken.
   * @returns {boolean} whether the verified statement may be taken
   * @private
   */
  _gossipCeiling(peerId, type, author) {
    const all = refill(this._gossipGlobal, this._gossipGlobalRate, this._gossipGlobalBurst, this._gossipClock());
    if (all.tokens >= 1) { all.tokens -= 1; return true; }
    // Said in one report for all peers, not one per id: ids are free to mint.
    this._noteDrop('gossip-over-ceiling', '*', { frame: type, author, peer: peerId });
    return false;
  }

  /**
   * A frame on a proven session carried a signature that does not verify (security review D). Whose
   * fault that is depends on who the statement names as its signer, because verification uses THIS
   * node's binding for the signer, and bindings are local views: another honest node may hold a
   * different one (this node's may be a squatter's session-scoped binding, or a vouch it lacks).
   *
   *   - The signer is the session's own proven peer, and the key that failed is the one the session
   *     proved: the peer signed or sent a statement in its own name that its own key did not sign.
   *     That is attributable (its frames are sealed under keys only that peer holds), so the session
   *     ends ('forged-signature') and its nodeId is not admitted again for FORGERY_PENALTY_MS.
   *   - Anyone else (a relayed statement): the delivering peer verified it under ITS binding for the
   *     signer, which may differ from this node's. The statement is dropped and counted
   *     (`relayed-signature-unverified`), said once a minute per peer and kind, and never charged to
   *     the delivering session (0.14.0 re-review N1: the penalty used to close honest relayers whenever
   *     a squatter held the signer's nodeId here).
   *
   * A Legacy Import session is not attributable this way: its frames are only dropped.
   * @param {object} session
   * @param {string} kind - what failed: record | attestation | checkpoint | witness
   * @param {{ author: string, key?: string|null }} signer - the nodeId the statement names as its
   *   signer, and (when the key tried is not simply this node's binding for it) the key that failed;
   *   null when the session's proven key was not among those tried.
   * @returns {boolean} whether the session was penalised
   * @private
   */
  _penaliseForgery(session, kind, { author, key } = {}) {
    if (!session || session.legacy || !session.confirmed || session.closed || typeof session.close !== 'function') return false;
    const nodeId = session.nodeId;
    const own = typeof author === 'string' && author === nodeId && (key === undefined || (!!key && key === session.identityKey));
    if (!own) {
      this._relayedUnverified = (this._relayedUnverified || 0) + 1;
      this._noteRelayFailure(nodeId, author);
      this.emit('metric', { type: 'relayed-signature-unverified', kind, peer: nodeId, author: typeof author === 'string' ? author.slice(0, 128) : null });
      this._sayOncePerMinute(`relayed-unverified|${nodeId}|${kind}`, `[sym-security] a ${kind} signed as ${String(author).slice(0, 8)}, relayed by ${session.name || String(nodeId).slice(0, 8)}, does not verify under this node's key for its signer: dropped (the relaying peer is not charged; its binding for the signer may differ from this node's)`);
      return false;
    }
    this._forgeryCount = (this._forgeryCount || 0) + 1;
    if (!this._forgeryPenalty) this._forgeryPenalty = new Map();
    this._forgeryPenalty.delete(nodeId);
    if (this._forgeryPenalty.size >= GOSSIP_MAX_PEERS) this._forgeryPenalty.delete(this._forgeryPenalty.keys().next().value);
    this._forgeryPenalty.set(nodeId, Date.now() + FORGERY_PENALTY_MS);
    this.emit('metric', { type: 'forged-signature', kind, peer: nodeId });
    this._sayOncePerMinute(`forged|${nodeId}`, `[sym-security] ${session.name || String(nodeId).slice(0, 8)} delivered a ${kind} in its own name whose signature does not verify under the key its session proved: session closed, not admitted again for ${FORGERY_PENALTY_MS / 1000} s`);
    session.close('forged-signature');
    return true;
  }

  /**
   * @private A statement `peer` relayed for `author` failed under this node's binding for the author
   * (final re-review, Finding 3). Past RELAY_FAILURES_MAX in RELAY_FAILURE_WINDOW_MS, that peer's
   * statements for that author are dropped unverified until the window ends: the cost of forgeries
   * relayed in another's name is bounded without blaming the relayer, whose other statements are taken.
   */
  _noteRelayFailure(peer, author) {
    if (typeof peer !== 'string' || typeof author !== 'string') return;
    if (!this._relayFailures) this._relayFailures = new Map();
    const k = `${peer}\u0000${author.slice(0, 128)}`;
    const now = Date.now();
    let f = this._relayFailures.get(k);
    if (!f || now - f.since >= RELAY_FAILURE_WINDOW_MS) f = { since: now, count: 0 };
    f.count++;
    this._relayFailures.delete(k);
    if (this._relayFailures.size >= GOSSIP_MAX_PEERS) this._relayFailures.delete(this._relayFailures.keys().next().value);
    this._relayFailures.set(k, f);
  }

  /** Whether `peer`'s statements for `author` are being dropped unverified (see _noteRelayFailure). */
  _relayMuted(peer, author) {
    if (!this._relayFailures || typeof author !== 'string') return false;
    const f = this._relayFailures.get(`${peer}\u0000${author.slice(0, 128)}`);
    if (!f) return false;
    if (Date.now() - f.since >= RELAY_FAILURE_WINDOW_MS) { this._relayFailures.delete(`${peer}\u0000${author.slice(0, 128)}`); return false; }
    if (f.count < RELAY_FAILURES_MAX) return false;
    this._noteDrop('relayed-signer-muted', peer, { author });
    return true;
  }

  /** @private Whether `nodeId` is inside a forgery penalty (and drop it when it has run out). */
  _penalised(nodeId) {
    const until = this._forgeryPenalty && this._forgeryPenalty.get(nodeId);
    if (!until) return false;
    if (Date.now() < until) return true;
    this._forgeryPenalty.delete(nodeId);
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

  /** @private Whether witnesses signed by `by` are muted (it contradicted a held checkpoint). */
  _witnessMuted(by) {
    const until = this._mutedWitnesses && this._mutedWitnesses.get(by);
    if (!until) return false;
    if (Date.now() < until) return true;
    this._mutedWitnesses.delete(by);
    return false;
  }

  /** @private Mute the witnesses `by` signs for WITNESS_MUTE_MS; at most 1,024 witnesses, oldest first out. */
  _muteWitness(by) {
    if (!this._mutedWitnesses) this._mutedWitnesses = new Map();
    this._mutedWitnesses.delete(by);
    if (this._mutedWitnesses.size >= 1024) this._mutedWitnesses.delete(this._mutedWitnesses.keys().next().value);
    this._mutedWitnesses.set(by, Date.now() + WITNESS_MUTE_MS);
  }

  /** Countersign a checkpoint (witness) and gossip the witness. @private */
  _witnessCheckpoint(cp) {
    if (cp.by === this.nodeId) return; // don't witness your own
    // Never an attester this node holds equivocation evidence against (sym-attest-v1 §5.2): this runs
    // only for a checkpoint the store took, and the store takes none of such an attester's (neither
    // the conflicting copy nor any later one). A witness signed before the conflict was known stands.
    // Once per checkpoint, across restarts: a second signing is a second copy of the same
    // statement, and two copies in circulation were relayed back and forth without end.
    if (this._attestations.hasWitnessed(cp.by, cp.upto_seq, this.nodeId)) return;
    const w = {
      type: 'witness',
      attester: cp.by,
      roster: cp.roster,
      from_seq: cp.from_seq,
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
      this._gossipToRoster({ type: ATTEST_FRAME.witness, witness: toWireWitness(w) });
    } catch (err) {
      this._log(`Witness signing failed: ${err.message}`);
    }
  }

  /**
   * Ingest a witness gossiped by a roster peer: roster check, verify the WITNESS's
   * signature against its authenticated key, record, relay-once.
   * @private
   */
  _ingestWitness(w, fromPeerId, session = null) {
    if (!w || !w.attester || w.upto_seq === undefined || w.from_seq === undefined || !w.root || !w.by || !sigOk(w.sig)) return { ok: false, reason: 'malformed' };
    if (w.roster && this._room && nfcRoom(w.roster) !== this._room) return { ok: false, reason: 'roster-mismatch' };
    if (!isPosition(w.upto_seq) || !isPosition(w.from_seq)) return { ok: false, reason: 'malformed' };
    // A copy of a witness held or waiting, or of a conflicting one already refused: dropped unverified.
    // Duplicates by content: the same (attester, fromSeq, uptoSeq, by) with the same root.
    const held = this._attestations.witnessSeen(w.attester, w.upto_seq, w.by);
    if (held && held.root === w.root && held.from_seq === w.from_seq) return { ok: false, reason: 'duplicate' };
    // A witness that contradicted an attester-signed checkpoint this node holds is muted for a while:
    // its further witnesses are dropped unverified (sym-attest-v1 §5.3, update 1: it MAY be muted).
    if (this._witnessMuted(w.by)) return { ok: false, reason: 'witness-muted' };
    if (this._attestations.witnessConflictRoot(w.attester, w.upto_seq, w.by) === w.root) return { ok: false, reason: 'duplicate' };
    if (!isCanonicalSig(w.sig)) return this._refuseSpelling(fromPeerId, 'witness', w.by);
    const key = this._identityKey(w.by);
    if (!key) return { ok: false, reason: 'unknown-witness-key' };
    if (this._relayMuted(fromPeerId, w.by)) return { ok: false, reason: 'relayed-signer-muted' };
    if (!this._gossipBudget(fromPeerId, 'witness', w.by)) return { ok: false, reason: 'over-budget' };
    if (!verifyWitness(w, key).valid) { this._penaliseForgery(session, 'witness', { author: w.by, key }); return { ok: false, reason: 'bad-signature' }; }
    if (!this._gossipCeiling(fromPeerId, 'witness', w.by)) return { ok: false, reason: 'over-ceiling' };
    // A verified gossip statement does not make its signer's binding durable (security review D:
    // only an admitted record, a grant in effect or a pin does; a fresh identity signs statements free).
    const r = this._attestations.recordWitness(w);
    if (r.stored) this._gossipToRoster({ type: ATTEST_FRAME.witness, witness: toWireWitness(w) }, fromPeerId);
    if (r.reason === 'lead' && r.first) {
      // Overlapping an attester-signed checkpoint held without matching it: either the attester signed
      // two histories or the witness signed a range the attester never did. A lead, not proof (§5.3).
      this._log(`[sym-security] witness ${String(w.by).slice(0, 8)} for ${String(w.attester).slice(0, 8)} names ${w.from_seq}..${w.upto_seq}, a range that overlaps a checkpoint held without matching it: a lead, not evidence`);
      this.emit('metric', { type: 'witness-lead', attester: w.attester, from_seq: w.from_seq, upto_seq: w.upto_seq, witness: w.by, root: w.root });
    }
    if (r.reason === 'disagrees') {
      // A verified witness for another range or root than the attester-signed checkpoint held at that
      // position counts against the witness, never the attester (sym-attest-v1 §5.3, update 1): it is
      // said once, counted, and the witness is muted for WITNESS_MUTE_MS.
      this._muteWitness(w.by);
      if (r.first) {
        this._log(`[sym-security] witness ${String(w.by).slice(0, 8)} for ${String(w.attester).slice(0, 8)} names ${w.from_seq}..${w.upto_seq} root ${String(w.root).slice(0, 12)}, not the attester's checkpoint held there (root ${String(r.keptRoot).slice(0, 12)}): its witnesses are dropped for ${WITNESS_MUTE_MS / 60000} minutes`);
        this.emit('metric', { type: 'witness-contradicts-checkpoint', attester: w.attester, upto_seq: w.upto_seq, witness: w.by, keptRoot: r.keptRoot, otherRoot: w.root });
      }
    }
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
    // A chained checkpoint (MMP 2.0 update 1) commits to its segment fromSeq..uptoSeq and the root it
    // follows, so it is checked against that segment alone; an unchained one (a log from before the
    // update, or 0.13's) against seq 1..uptoSeq.
    const chained = cp.from_seq !== undefined;
    const lo = chained ? cp.from_seq : 1;
    const chain = this._attestations.chainOf(by).filter(a => a.seq >= lo && a.seq <= cp.upto_seq);
    const present = new Set(chain.map(a => a.seq));
    const gaps = [];
    for (let s = lo; s <= cp.upto_seq; s++) if (!present.has(s)) gaps.push(s);
    let recomputedRoot = null;
    try {
      recomputedRoot = chained
        ? attestCheckpointRoot({ prev: cp.prev, fromSeq: cp.from_seq, uptoSeq: cp.upto_seq, segmentRoot: attestMerkleRoot(chain.map(a => a.sig)) })
        : (cp.scheme === ATTEST_SCHEME ? attestMerkleRoot : merkleRoot)(chain.map(a => a.sig));
    } catch { /* no attestation of the segment held */ }
    const consistent = recomputedRoot === cp.root;
    return {
      checkpoint: cp,
      consistent,
      // The attester signed another root for this position too (equivocation, or a chain restarted
      // after a lost log): an inconsistency here is that, not tampering by a third party.
      conflicted: this._attestations.hasConflict(by, cp.upto_seq) || this._attestations.attesterEquivocated(by),
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
  _ingestAttestation(att, fromPeerId, fromPeerName, session = null) {
    if (!att || !sigOk(att.sig) || !att.of || !att.by) return { ok: false, reason: 'malformed' };
    // Roster scope (defense in depth — gossip already stays in-room).
    // Compared as NFC, the form the attestation signs its room in (sym-attest-v1) and this node's room.
    if (att.roster && this._room && nfcRoom(att.roster) !== this._room) {
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
    if (this._relayMuted(fromPeerId, att.by)) return { ok: false, reason: 'relayed-signer-muted' };
    if (!this._gossipBudget(fromPeerId, 'attestation', att.by)) return { ok: false, reason: 'over-budget' };
    const v = verifyAttestation(att, attesterKey);
    if (!v.valid) {
      if (!v.error || v.error === 'bad-signature') this._penaliseForgery(session, 'attestation', { author: att.by, key: attesterKey });
      return { ok: false, reason: v.error || 'bad-signature' };
    }
    if (!this._gossipCeiling(fromPeerId, 'attestation', att.by)) return { ok: false, reason: 'over-ceiling' };
    // A verified gossip statement does not make its signer's binding durable (security review D:
    // only an admitted record, a grant in effect or a pin does; a fresh identity signs statements free).
    // Record (rate-limited as ingested). Relay-once only on first sight.
    const r = this._attestations.record(att, { ingested: true });
    if (r.stored) {
      // Never relayed when the record it attests is a directed one this node holds (#27): a peer that
      // signed it should not have; this node does not spread it.
      if (!this._attestsDirected(att)) this._gossipAttestation(att, fromPeerId);
      this._emitAttestationReceived(att, fromPeerId, fromPeerName);
    }
    return { ok: r.stored, reason: r.reason };
  }

  /** @private Whether `att` attests a record this node holds with a signed `to` (the assertion matching). */
  _attestsDirected(att) {
    try {
      const e = att && this._store.get(att.of);
      const m = e && e.cmb && e.cmb.metadata;
      return !!(m && m.assertionId === att.assertionId && m.to !== null && m.to !== undefined);
    } catch { return false; }
  }

  /**
   * Emit 'attestation-received' for an attestation that was just verified and recorded.
   *
   * Signed fields pass through as signed: `of`, `assertionId`, `by`, `at`, `roster`, `method`,
   * `verdict`, `seq`, `prev`, `role`, and the seven CAT7 `categories` as the strings the signature
   * covers (sym-attest-v1 signs every field), with `sig`/`sigAlg`, so verifyAttestation(event, key)
   * re-checks it. `role` is the attester's own CLAIM: a node can stamp any role and still sign
   * validly, so `roleResolved`/`roleMatches` give the role this node resolves from its in-force
   * authority set. `byName` is the label the peer announced, never signed; `by` is the identity.
   *
   * `verified` means the signature checked out against the key this node holds for `by`, and
   * `keySource` says where that key came from (design D3): 'anchor' (configured), 'proven' (a
   * Core Secure session proved it — trust on first PROVEN use when nothing else pinned it), 'pinned'
   * (an invite or a Legacy Import route) or 'grant' (named by an in-force grant, §6.6.9); a
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
    // sym-attest-v1 signs a text field as its text and anything else as empty, and a number as its
    // decimal: the event shows a text or a finite number as is and anything else as null, which signs
    // the same, so verifyAttestation(event, key) re-checks it.
    const signed = (v) => (typeof v === 'string' ? v : null);
    const signedInt = (v) => (Number.isSafeInteger(v) ? v : null);
    let event;
    try {
      const categories = {};
      for (const f of CAT7_CATEGORIES) {
        const v = att.categories && att.categories[f];
        categories[f] = typeof v === 'string' ? v : null; // the form the signature covers
      }
      // The claim as signed: a text role, or none (an absent or non-text role signs as empty and claims
      // 'participant').
      const role = verifyAttestationRole({ ...att, role: typeof att.role === 'string' && att.role ? att.role : undefined }, () => this._attesterRole(att));
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
        method: signed(att.method),
        assertionId: signed(att.assertionId),
        room: signed(att.roster),
        roster: signed(att.roster),
        at: signedInt(att.at),
        seq: signedInt(att.seq),
        prev: signed(att.prev),
        sig: signed(att.sig),
        sigAlg: signed(att.sigAlg),
        verified: true,
        keySource: this._keySource(att.by) ?? null,
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
    // MMP §3.1.1: a nodeId is a lowercase UUID, and every Core Secure receiver refuses a record whose
    // createdByNodeId is not one. Every identity minted since 0.3.7 is a UUIDv7; an older identity
    // file can hold another id, and such a node would be refused by every peer without being told.
    if (!isLowerUuid(this.nodeId)) {
      this._log(`[sym-security] this node's nodeId ${String(this.nodeId).slice(0, 40)} is not a lowercase UUID (MMP §3.1.1): every Core Secure peer refuses the records it signs. Create a new identity for this agent.`);
      this.emit('metric', { type: 'node-id-not-canonical', nodeId: String(this.nodeId).slice(0, 128) });
    }

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
      // A record whose TXT mmp does not list 2.0 (a comma-separated version list, MMP §5.1) is not
      // dialled as Core Secure; one without mmp is a legacy node, reached only by a configured
      // Legacy Import route (design D7), by its own endpoint.
      if (!info || !mmpLists20(info.mmp)) return;
      // §5.1: connect only to advertisements whose TXT room equals this node's (absent reads as
      // `default`). A hint, never an admission: the handshake decides membership.
      if ((info.room === null || info.room === undefined ? 'default' : info.room) !== this._room) return;
      // §5.1: the lexicographically smaller nodeId initiates; the other MUST NOT.
      if (!(this.nodeId < peerId)) return;
      // A peer that refused this node with 1009 IDENTITY_CONFLICT is not dialled again (review F).
      if (this._identityRefused && this._identityRefused.has(peerId)) return;
      // A peer whose last dial or handshake failed waits its backoff (security review D).
      const lb = this._lanBackoff && this._lanBackoff.get(peerId);
      if (lb && Date.now() < lb.nextAt) return;
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
        this._makeRoomForLanHandshake(remote);
        const session = this._attachTransport(transport, { role: 'server', kind: 'bonjour', remote });
        if (!this._lanInFlight) this._lanInFlight = new Set();
        this._lanInFlight.add(session);
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
      // An interior a host opened on a node it never started still ends with it, and so does the
      // identity lock its constructor took (final re-review, Finding 7a: a stopped node must not keep
      // its nodeId held in this process).
      if (this._interior) this._interior.close();
      if (this._releaseIdentityLock) { try { this._releaseIdentityLock(); } catch { /* */ } this._releaseIdentityLock = null; }
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
    if (INBOX_OWNERS.get(this._inboxFile) === this) { this._writeInbox(); INBOX_OWNERS.delete(this._inboxFile); }

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
    if (this._pumpTimer) { clearTimeout(this._pumpTimer); this._pumpTimer = null; }
    if (this._relayWanted) this._relayWanted.clear();

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
    this._loadInboxSnapshot();
    // Fold the journal in: what was appended after the last snapshot (deliveries, drains, acks).
    let lines = [];
    try { lines = fs.readFileSync(this._inboxJournal, 'utf8').split('\n'); } catch { /* none */ }
    let folded = 0;
    const bySeq = new Map(this._inbox.map((m) => [m.seq, m]));
    for (const line of lines) {
      if (!line) continue;
      let o;
      try { o = JSON.parse(line); } catch { continue; } // a torn last line: its change never took effect
      folded++;
      if (o && o.e && Number.isSafeInteger(o.e.seq) && typeof o.e.id === 'string') {
        if (o.e.seq > this._inboxSeq) this._inboxSeq = o.e.seq;
        if (!bySeq.has(o.e.seq)) { bySeq.set(o.e.seq, o.e); this._inbox.push(o.e); }
      } else if (o && typeof o.ack === 'string') {
        const m = this._inbox.find((x) => x.id === o.ack);
        if (m) m.acked = true;
      } else if (o && Number.isSafeInteger(o.cursor)) {
        if (o.cursor > this._inboxCursor) this._inboxCursor = o.cursor;
      } else if (o && Number.isSafeInteger(o.seq)) {
        if (o.seq > this._inboxSeq) this._inboxSeq = o.seq; // a seq taken whose entry was refused
      }
    }
    this._inbox.sort((a, b) => a.seq - b.seq);
    if (folded) this._writeInbox(); // folded into a new snapshot; the journal starts empty
  }

  /** @private Read the snapshot (inbox.json). */
  _loadInboxSnapshot() {
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

  /**
   * @private Write ring + seq + cursor now, as a snapshot (written whole, then renamed into place),
   * and empty the journal it now holds. Nothing runs between the two, so no journalled change is lost.
   */
  _writeInbox() {
    if (INBOX_OWNERS.get(this._inboxFile) !== this) return; // a newer node owns it (see the constructor)
    try {
      const tmp = `${this._inboxFile}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify({
        seq: this._inboxSeq, cursor: this._inboxCursor, messages: this._inbox,
      }), { mode: 0o600 });
      fs.renameSync(tmp, this._inboxFile);
      try { fs.truncateSync(this._inboxJournal, 0); } catch { /* none yet */ }
    } catch { /* best-effort: the journal still holds every change */ }
  }

  /**
   * Surface a delivery (mesh-channel 0.11.0): a Core Secure one as `cmb-accepted` (and so into the
   * inbox); a quarantined Legacy Import record as `legacy-record` only, never into the path a host
   * reads as Core Secure deliveries.
   * @private
   */
  _emitAccepted(entry) {
    if (entry && entry.profile === 'legacy-import') { this.emit('legacy-record', entry); return; }
    this.emit('cmb-accepted', entry);
  }

  _pushInbox(entry) {
    if (!entry) return;
    const cmb = entry.cmb || {};
    if (INBOX_OWNERS.get(this._inboxFile) !== this) {
      this._sayOncePerMinute('inbox-not-owner', 'A newer node for this identity owns its inbox in this process: a delivery to this one is not put in the inbox');
      return;
    }
    // An unread item is never evicted (inbox-id bug, 2026-10): an id announced and not yet read always
    // fetches its record. Past INBOX_UNREAD_MAX unread items a delivery gets no id at all (it is not
    // announced), and that is counted and said, instead of discarding an announced one.
    this._evictRead();
    const unread = this._inbox.reduce((n, m) => n + (m.seq > this._inboxCursor && !m.acked ? 1 : 0), 0);
    if (unread >= this._inboxMax * INBOX_UNREAD_FACTOR) {
      this._metrics.inboxDropped = (this._metrics.inboxDropped ?? 0) + 1;
      this._sayOncePerMinute('inbox-full', `INBOX FULL — ${unread} unread deliveries and nothing draining this node: a new delivery is not put in the inbox (its record is still in memory if it was admitted)`);
      this.emit('metric', { type: 'inbox-full-refused', key: recordKey(cmb) || entry.key || null, directed: !!entry.directed });
      return;
    }
    const seq = this._inboxSeq + 1;
    const id = `in${String(seq).padStart(4, '0')}`;
    const item = {
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
      // Provenance travels with the delivery, persisted with the inbox (mesh-channel 0.11.0): the
      // verdict, the profile, the assertion identity, and the frozen verification and session facts.
      verified: entry.verified === true,
      profile: entry.profile || null,
      assertionId: entry.verified === true ? (entry.assertionId || entry.verification?.assertionId || null) : null,
      verification: entry.verified === true ? (entry.verification || null) : null,
      session: entry.verified === true ? (entry.session || null) : null,
      // The verified record itself, as signed (its signed projection), for a reader that checks it.
      record: entry.verified === true ? projectionOrNull(cmb) : null,
      key: recordKey(cmb) || entry.key || null,
      receivedAt: Date.now(),
    };
    // The id is assigned only once the item is durably in the inbox: journalled first. A write that
    // fails assigns nothing, so nothing is announced that a fetch could not find.
    if (!this._journalInbox({ e: item })) {
      this._log(`Inbox write failed: a delivery from ${item.from} was not put in the inbox`);
      this.emit('metric', { type: 'inbox-write-failed', key: item.key });
      return;
    }
    this._inboxSeq = seq;
    this._inbox.push(item);
    // Later 'cmb-accepted' listeners (a channel's push path) read these to refer to the same
    // delivery by the same id instead of minting a second one.
    entry.inboxId = id;
    entry.inboxSeq = seq;
    this._persistInbox();
  }

  /** @private Append one inbox change to the journal, synchronously. @returns {boolean} written */
  _journalInbox(change) {
    if (INBOX_OWNERS.get(this._inboxFile) !== this) return false;
    try { fs.appendFileSync(this._inboxJournal, JSON.stringify(change) + '\n', { mode: 0o600 }); return true; }
    catch { return false; }
  }

  /**
   * @private Evict read items (drained or acked) past the ring's size, oldest first; never an unread
   * one. (Until the inbox-id fix the ring evicted the oldest item whatever it was, so an announced,
   * unread delivery could vanish: "not found" for an id the host had just been shown.)
   */
  _evictRead() {
    if (this._inbox.length < this._inboxMax) return;
    const keep = [];
    let excess = this._inbox.length - this._inboxMax + 1;
    for (const m of this._inbox) {
      const read = m.seq <= this._inboxCursor || m.acked;
      if (excess > 0 && read) { excess--; if (m.acked && m.seq > this._inboxCursor) this._metrics.inboxAckedEvicted = (this._metrics.inboxAckedEvicted ?? 0) + 1; continue; }
      keep.push(m);
    }
    this._inbox = keep;
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
    if (!opts.peek && lastSeq !== null && lastSeq > this._inboxCursor) {
      this._inboxCursor = lastSeq;
      // Journalled now: a restart, or a node built for the same identity, must not replay what was read.
      this._journalInbox({ cursor: lastSeq });
      this._persistInbox();
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
    this._journalInbox({ ack: m.id });
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
    // A record's addressee is a nodeId, a lowercase UUID (MMP §3.1.1; the record schema's `to`): one
    // spelled otherwise would be minted, stored and reported undelivered, and no session could ever
    // carry it (the seal point refuses it). Refused here instead, before anything is minted.
    assertAddressee(opts.to);

    if (!opts.cmb) {
      if (!categories || typeof categories !== 'object') {
        throw new Error('remember() requires CAT7 categories — the agent LLM extracts categories');
      }

      // §15.7 is NOT checked here (draft spec PR meshcognition-website#35): a remix is defined by
      // how it was produced — the node's integration of an admitted peer record, `remix()` — never
      // by the parents a record cites. A record the agent authors through remember() is its own
      // domain observation (a reply, a trail decision, an outcome), however many parents it cites,
      // and is never refused as a remix. Nothing here gates on parents, an intent value or the
      // lineage method.

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
      // A broadcast that collapses onto HEAD minted nothing: it is a duplicate, and says so.
      const collapsed = { key: mintKey, cmb: opts.cmb, collapsed: true, ...(opts.to ? {} : { duplicate: true }) };
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
    // delivery result. A broadcast duplicate is said so: `{ key, duplicate: true }` (mesh-channel
    // 0.11.0), never the null a refusal or a failure returns.
    if (!entry) {
      const existingKey = opts.cmb?.metadata?.key || opts.cmb?.key || null;
      if (!opts.to) {
        if (existingKey && this._store.get(existingKey)) return { key: existingKey, duplicate: true };
        return null; // the store write failed: nothing was stored
      }
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

    // A record the agent authored is new domain data by construction (§15.7.2, draft spec PR #35),
    // with or without parents. Only the remix path (`remix()`) consumes the flag.
    this._hasNewDomainData = true;

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
   * THE REMIX PATH (MMP §15.5, §15.7; draft spec PR meshcognition-website#35): the record this node
   * mints by integrating an admitted peer record (`parents`) through its own domain lens. Only this
   * path is gated: with no new domain data since the last remix it is refused, and the result says
   * so — `{ refused: 'remix-without-new-domain-data' }` — where remember() would have minted. A
   * remix that mints consumes the flag. Everything else is remember()'s.
   * @param {object} categories
   * @param {object} [opts] - remember()'s options; `parents` names the integrated records
   * @returns {object|null} the stored entry, `{ refused }`, `{ key, duplicate: true }`, or null
   */
  remix(categories, opts = {}) {
    if (!this._hasNewDomainData) {
      this._metrics.remixRejected++;
      this._log('Remix not minted: no new domain data since the last remix (MMP §15.7)');
      this.emit('metric', { type: 'remix-rejected', reason: 'no-new-domain-data' });
      return { refused: 'remix-without-new-domain-data' };
    }
    const entry = this.remember(categories, opts);
    if (entry && !entry.refused && !entry.duplicate && !entry.collapsed) {
      this._hasNewDomainData = false;
      // Counted here, on the gated path only (MMP §15.7, update 1, #35): a record remember() mints with
      // parents (a reply, an outcome, a trail decision) is not a remix.
      this._metrics.remixProduced++;
    }
    return entry;
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
   * Broadcast a mood frame to all connected peers (MMP §9.3): `{ type, mood, context, timestamp }`,
   * sealed on each confirmed session. It names no sender; each receiver attributes it to the session
   * it arrived on (lib/core/mood-frame).
   *
   * @param {string} mood — mood text, 1 to 1,024 characters
   * @param {object} [opts]
   * @param {string} [opts.context] — optional context for the mood, at most 4,096 characters
   * @throws {RangeError} EMOODFRAME when either is out of bounds: nothing is sent
   */
  broadcastMood(mood, opts = {}) {
    const frame = buildMoodFrame(mood, opts.context);
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
    // An addressee that is not a nodeId is refused before anything is minted (EBADTO), as remember()
    // refuses it.
    if (opts.to !== undefined && opts.to !== null) assertAddressee(opts.to);
    const targets = opts.to ? [opts.to] : [...this._peers.keys()];
    let delivered = 0;
    for (const to of targets) {
      let cmb;
      try { cmb = this._mintMessage(content, to); } catch (err) { this._log(`Message to ${String(to).slice(0, 8)} not sent: ${err.message}`); continue; }
      const peer = this._peers.get(to);
      if (!peer) continue;
      if (trySend(peer.transport, { type: 'cmb', timestamp: Date.now(), cmb }).ok) delivered++;
    }
    // A sleeping peer is woken, and the message waits for it as a record signed to it (the retired
    // `message` frame is never queued).
    if (!opts.to) {
      this._wakeManager.wakeSleepingPeers('message', (peerId) => {
        try { return { type: 'cmb', timestamp: Date.now(), cmb: this._mintMessage(content, peerId) }; } catch { return null; }
      });
    }
    // If no peers received the message, trigger an immediate reconnect
    // attempt for any cached bonjour peers. The next send will find
    // them connected instead of waiting for the 15s background timer.
    if (delivered === 0) this._discovery.reconnect();
    return delivered;
  }

  /** @private A signed v2.0 directed record carrying a message to `to`. */
  _mintMessage(content, to) {
    assertAddressee(to);
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
   * Send an error frame to a peer (sealed on its session). Per MMP §7.2 a host's error is
   * information: 1002 (frame rejected) or an evaluation-level 2xxx code (2001 SVAF rejected).
   * Any other code throws EBADERRORCODE.
   *
   * @param {string} peerId — target peer
   * @param {number} code — 1002, or 2000-2999
   * @param {string} message — human-readable error description
   * @param {string} [detail] — optional debug detail (MUST NOT contain sensitive info)
   */
  sendError(peerId, code, message, detail) {
    // MMP §7.2: a host sends information, never the protocol's own decisions. 1009, 1010 and 1011 are
    // the session's (identity conflict, close, unknown session), the other Close codes end a session
    // a host does not own, and 4xxx are relay close codes, never peer errors (draft PR #23). What a
    // host may send: 1002 (frame rejected) and the informational 2xxx codes.
    if (!(code === 1002 || (Number.isInteger(code) && code >= 2000 && code <= 2999))) {
      throw Object.assign(new Error(`sendError: ${code} is not a code a host may send (1002, or 2000-2999)`), { code: 'EBADERRORCODE' });
    }
    const peer = this._peers.get(peerId);
    if (!peer) return;
    peer.transport.send({ type: 'error', code, message: String(message ?? '').slice(0, 200), ...(detail ? { detail: String(detail).slice(0, 200) } : {}) });
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
        keySource: this._keySource(id) || null,
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
  /**
   * The @sym-bot/sym version this node runs: the `version` of the package.json loaded with it (what a
   * host such as mesh-channel's sym_status reports). The same string the node announces as its
   * `implementation` in the §5.2 hello. Also `status().version` and `require('@sym-bot/sym').version`.
   * @returns {string}
   */
  get version() { return ENGINE_VERSION; }

  status() {
    return {
      name: this.name,
      nodeId: this._identity.nodeId,
      version: ENGINE_VERSION,
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
        authority: this.authorityStatus(),
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
      // Counted by frame type only for a type this node knows (security review): a peer's own type
      // names would grow the table without bound (or name `__proto__`).
      const byType = this._metrics.framesRefusedByType;
      const k = KNOWN_FRAME_TYPES.has(type) ? type : 'other';
      byType[k] = (byType[k] || 0) + 1;
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

  // ── Identity, public (mesh-channel 0.11.0 host API) ────────

  /** This node's own Ed25519 identity public key (unpadded base64url). Public; never a private key. */
  get publicKey() { return this._identity.publicKey; }

  /** This node's identity key fingerprint, `sha256:<hex>` over the raw key bytes. */
  get fingerprint() { return keyFingerprint(this._identity.publicKey); }

  /**
   * The key bindings this node holds, public keys only: the durable registry's (anchor, pinned,
   * proven, legacy-claim) and the live sessions' (`session`). A key an in-force grant names is shown
   * where it binds an unbound nodeId (§6.6.9). A host reads these; it never writes them.
   * @returns {{ nodeId: string, key: string, source: string }[]}
   */
  keyBindings() {
    const out = [];
    const seen = new Set();
    for (const e of this._roster.entries()) {
      seen.add(e.nodeId);
      const source = this._roster.source(e.nodeId) || e.source;
      out.push({ nodeId: e.nodeId, key: e.key, source });
    }
    for (const [nodeId, held] of this._sessionKeys) {
      if (seen.has(nodeId) || ![...held.sessions].some((s) => s.confirmed && !s.closed)) continue;
      out.push({ nodeId, key: held.key, source: 'session' });
    }
    return out.map((e) => Object.freeze(e));
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
    // A clear 1011 on a confirmed relay session: the peer restarted and holds no session with this
    // node. The client re-handshakes; the session stays until the new one supersedes it.
    session.on('unknown-session', (s, f) => {
      if (session.kind === 'relay') this._onUnknownSession(session.relayFrom, f);
    });
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
      this._refuseIdentityConflict(session);
      return;
    }
    // A live session-scoped binding is a binding (security review D, binding-squat): a second key for
    // a nodeId some live session proved is an identity conflict, whether or not the registry keeps it.
    const live = this._sessionKeys.get(session.nodeId);
    if (live && live.key !== session.identityKey && [...live.sessions].some((x) => !x.closed)) {
      this._roster.noteConflict(session.nodeId, live.key, 'session', session.identityKey, 'proven');
      this._log(`Refused ${session.name} (${session.nodeId.slice(0, 8)}): it proved a key other than the one a live session proved for its nodeId — a key conflict`);
      this._refuseIdentityConflict(session);
      return;
    }
    // A room-join grant this node holds goes first, so a gated peer can admit it.
    if (this._roomGrant) session.send({ type: 'room-join', grant: grantForWire(this._roomGrant) }); // the schema's members only (§5.8.1)
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
    if (this._penalised(nodeId)) { this._refuseAdmission(session, 'delivered a forged signature; not admitted again yet'); return; }
    // EVERY CONFIRMED SESSION RUNS WITH A BINDING (security review D, binding-squat): its proven key is
    // held for nodeId while the session lives (the session-scoped table, bounded by the session caps),
    // and a second key for that nodeId is a conflict. The durable registry takes only EARNED
    // bindings — a pin, a grant in effect, or an admitted verified record (_earnBinding) — and the
    // key it already expects for nodeId (a legacy claim becomes `proven`; a pin stays pinned).
    const expected = this._roster.expected(nodeId);
    if (expected !== undefined && expected !== session.identityKey) { this._refuseIdentityConflict(session); return; }
    if (expected === session.identityKey) {
      const b = this._roster.bind(nodeId, session.identityKey, 'proven');
      if (!b.bound && b.reason === 'conflict') { this._refuseIdentityConflict(session); return; }
      // A session seen renews the binding's clock. A re-handshake proves only that the key is held,
      // which anyone minting identities can do twice, so it is never "verified" (security review D).
      this._roster.noteSeen(nodeId);
    }
    // The sticky floor of a routed nodeId arms on a proof, whatever the registry keeps.
    this._roster.armFloor(nodeId);
    let held = this._sessionKeys.get(nodeId);
    if (!held || held.key !== session.identityKey) { held = { key: session.identityKey, sessions: new Set() }; this._sessionKeys.set(nodeId, held); }
    held.sessions.add(session);
    // A room-join grant admits until it expires, not for as long as the session lasts (security
    // review): the session closes when its grant does.
    const g = session.roomGrant;
    if (g && Number.isFinite(g.expiresAt) && this._roomOwners.ownerOf(this._room)) {
      const left = g.expiresAt - Date.now();
      const close = () => { if (!session.closed) { this._log(`Room-join grant of ${session.name} expired: session closed`); session.close('room-grant-expired'); } };
      if (left <= 0) { close(); return; }
      session._grantTimer = setTimeout(close, Math.min(left, 2 ** 31 - 1));
      if (session._grantTimer.unref) session._grantTimer.unref();
    }
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
      this._refuseIdentityConflict(session);
      return;
    }
    // The sticky floor arms now (a proven binding): a Legacy Import session for this nodeId ends.
    for (const t of [...peer.transports.values()]) if (t.legacy && !t.closed) t.close('floor');
    const prev = peer.transports.get(session.kind);
    peer.name = session.name;
    peer.lastSeen = Date.now();
    if (session.kind === 'relay' && session.role === 'client' && prev && prev !== session && !prev.closed && prev.confirmed) {
      // A relay client confirms when it sends client-finish, and cannot know the server took it: a
      // re-handshake whose finish was lost must leave the confirmed session exactly as it was (draft
      // spec PR #23). So the new session supersedes the old only once it carries an authenticated
      // frame from the server (every admitted session is sent at least a sealed cmb-anchors); until
      // then the old one stays the peer's, and a new one that hears nothing ends.
      session._supersedes = prev;
      session._supersedeTimer = setTimeout(() => {
        if (session._supersedes && !session.closed) session.close('unconfirmed-by-peer', { notify: false });
      }, this._handshakeTimeoutMs);
      if (session._supersedeTimer.unref) session._supersedeTimer.unref();
    } else {
      peer.transports.set(session.kind, session);
      peer.transport = this._bestTransport(peer);
      this._supersede(prev, session);
    }
    if (session.kind === 'bonjour') { this._pendingBonjour?.delete(nodeId); this._lanBackoff?.delete(nodeId); }
    if (session.kind === 'relay') { this._relayRetry?.delete(nodeId); this._relayFailures?.delete(nodeId); this._schedulePumpRelay(); }
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

  /** @private `prev` is superseded by `session` (the same peer and transport kind): closed quietly. */
  _supersede(prev, session) {
    if (!prev || prev === session || prev.closed) return;
    this._sessionStats.superseded++;
    prev._superseded = true;
    // Supersession sends nothing (draft spec PR #23): the peer's own new session supersedes its old.
    prev.close('superseded', { notify: false });
  }

  /** @private A relay client session held back from superseding heard from its server: now it does. */
  _completeSupersede(session) {
    const prev = session._supersedes;
    session._supersedes = null;
    if (session._supersedeTimer) { clearTimeout(session._supersedeTimer); session._supersedeTimer = null; }
    const peer = this._peers.get(session.nodeId);
    if (!peer || session.closed) return;
    peer.transports.set(session.kind, session);
    peer.transport = this._bestTransport(peer);
    this._supersede(prev, session);
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
    let announced = false;
    // MMP §9.4 (update 1, #30): a NON-EMPTY cmb-anchors at most once a minute per peer; the empty
    // list goes on every admission. Only a list that was sent starts the minute: an admission with
    // nothing to replay does not hold back the next one's context.
    if (now - lastSent >= 60000) {
      // Records this node authored itself under mmp-sig-v2.0 (§15.7: replay is not forwarding), and
      // only ones it may seal into this session (§18.2.1): this session's room, and no recipient (a
      // record signed to one node is never replayed as context to another, whoever's session this is).
      const room = String(session.room ?? this._room).normalize('NFC');
      const anchors = this._store.recent(50)
        .filter((a) => a.cmb && a.peerId == null && a.cmb.metadata && a.cmb.metadata.signatureSuite === 'mmp-sig-v2.0' && a.cmb.metadata.sig
          && a.cmb.metadata.createdByNodeId === this.nodeId
          && typeof a.cmb.metadata.room === 'string' && a.cmb.metadata.room.normalize('NFC') === room
          && (a.cmb.metadata.to === null || a.cmb.metadata.to === undefined))
        .slice(0, 5);
      if (anchors.length > 0) {
        keepPeerState(this._lastAnchorSent, peer.peerId, now, this._peers);
        announced = true;
        session.send({ type: 'cmb-anchors', keys: anchors.map((a) => a.cmb.metadata.key) });
        let sent = 0;
        for (const a of anchors) if (session.send({ type: 'cmb', cmb: a.cmb })) sent++;
        this._log(`Sent ${sent} anchor CMB(s) to ${peer.name}`);
      }
    } else if (isNew) {
      this._log(`Skipping anchor CMBs for ${peer.name} (reconnected within 60s)`);
    }
    // Every admitted session hears at least one sealed frame from this node first: a relay client
    // waits for one before its new session supersedes the old (see _admitSession). `cmb-anchors` with
    // no keys says "no replayed context follows" (docs/WIRE-0.14.0.md §1).
    if (!announced) session.send({ type: 'cmb-anchors', keys: [] });
    // MMP §6.6.8: this node's authority root and in-force count, when a session is confirmed (only
    // with an anchor pinned: without one there is no root).
    this._sendAuthorityDigest(session, { now: true });
    // This node's own wake channel. (peer-info about OTHER nodes is not sent: a receiver learns a
    // wake channel only from its node's own session, so gossip about others would be dropped.)
    if (this._wakeChannel) session.send({ type: 'wake-channel', ...this._wakeChannel });
    const pending = this._pendingFrames.get(peer.peerId);
    if (pending && pending.length > 0) {
      // Only to the key the frames were queued for, and only frames this session takes (an
      // extension's frames where it was selected): security review.
      let sent = 0;
      for (const e of pending) {
        if (!e || !e.frame || e.key !== session.identityKey || !this._sessionTakes(session, e.frame.type)) continue;
        if (session.send(e.frame)) sent++;
      }
      this._log(`Delivered ${sent} of ${pending.length} pending frame(s) to ${peer.name}`);
      this._pendingFrames.delete(peer.peerId);
    }
  }

  /** @private A frame from a session: the door first (design D6), then the one guarded dispatch. */
  _onSessionFrame(session, frame) {
    const state = session.admission && session.admission.state;
    if (state !== 'admitted') {
      if (state === 'pending' && frame && frame.type === 'room-join') {
        session.roomGrant = frame.grant;
        this._decideAdmission(session);
        return;
      }
      this._noteSessionRefusal(session, frame && frame.type, 'not-admitted');
      return;
    }
    if (session._supersedes) this._completeSupersede(session); // the server took the new session
    if (frame && frame.type === 'room-join') return; // admitted already: nothing to decide
    const peer = this._peers.get(session.nodeId);
    if (peer) peer.lastSeen = Date.now();
    this._receiveSessionFrame(session, frame);
  }

  /** @private A session ended: detach it, and the peer when it was the peer's last. */
  _onSessionClosed(session, info) {
    this._sessions.delete(session);
    const held = session.nodeId && this._sessionKeys.get(session.nodeId);
    if (held && held.sessions.delete(session) && held.sessions.size === 0) this._sessionKeys.delete(session.nodeId);
    this._authorityReleaseSession(session);
    if (session._admissionTimer) { clearTimeout(session._admissionTimer); session._admissionTimer = null; }
    if (session._grantTimer) { clearTimeout(session._grantTimer); session._grantTimer = null; }
    if (session._supersedeTimer) { clearTimeout(session._supersedeTimer); session._supersedeTimer = null; }
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
    if (reason === 'identity-conflict') {
      // 1009 means no automatic retry (security review F): neither the relay's re-handshake nor the
      // LAN re-dial discovery offers every 15 s. Until this node restarts.
      const who = session.nodeId || session.expectNodeId || session.relayFrom;
      if (who) {
        if (!this._identityRefused) this._identityRefused = new Map();
        this._identityRefused.delete(who);
        if (this._identityRefused.size >= IDENTITY_REFUSED_MAX) this._identityRefused.delete(this._identityRefused.keys().next().value);
        this._identityRefused.set(who, Date.now());
      }
      this._sayOncePerMinute(`idc|${session.nodeId || session.relayFrom || session.remote || ''}`, `[sym-security] ${session.name || session.relayFrom || 'a peer'} refused this node with IDENTITY_CONFLICT (1009): it binds this nodeId to a different key. Not retrying; check which key is genuine.`);
      this.emit('metric', { type: 'identity-conflict-refused-by-peer', peer: session.nodeId || session.relayFrom || null });
    }
    if (session.kind === 'bonjour' && session.expectNodeId) {
      this._pendingBonjour?.delete(session.expectNodeId);
      if (!(info && info.wasConfirmed) && reason !== 'node-stopped') this._lanFailed(session.expectNodeId);
    }
    if (this._lanInFlight) this._lanInFlight.delete(session);
    if (session.kind === 'relay' && session.role === 'client' && !(info && info.wasConfirmed) && reason !== 'node-stopped' && reason !== 'relay-disconnected') {
      this._relayClientFailed(session.relayFrom);
    }
    // A relay handshake slot came free: the wait list goes next.
    if (session.kind === 'relay' && this._running) this._schedulePumpRelay();
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
        && reason !== 'node-stopped' && reason !== 'relay-peer-left' && reason !== 'relay-disconnected' && reason !== 'key-conflict' && reason !== 'identity-conflict' && reason !== 'admission-refused'
        && reason !== 'unconfirmed-by-peer' && !(session._supersedes && !session._supersedes.closed)
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

  /**
   * A confirmed session proved a key other than the one bound to its nodeId (design D3): refused
   * with the error MMP draft spec PR meshcognition-website#21 defines, 1009 IDENTITY_CONFLICT, then
   * closed. Nothing per-peer was created; the conflict is recorded by the registry.
   * @private
   */
  _refuseIdentityConflict(session) {
    try {
      session.trySend({ type: 'error', code: IDENTITY_CONFLICT, message: 'IDENTITY_CONFLICT', ...(session.sessionId ? { detail: `session:${session.sessionId}` } : {}) });
    } catch { /* the session closes below either way */ }
    const t = session.transport;
    if (t && typeof t.end === 'function' && session.kind !== 'relay') {
      // TCP: the error frame goes out before the connection closes.
      session.close('key-conflict', { notify: false, closeTransport: false });
      t.end();
    } else {
      session.close('key-conflict', { notify: false });
    }
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
      this._lanFailed(peerId);
      this._sayOncePerMinute(`dial|${peerId}`, `Connect failed to ${peerName}: ${err.message}`);
    });
    socket.setTimeout(10000, () => { this._pendingBonjour.delete(peerId); this._lanFailed(peerId); socket.destroy(); });
  }

  /** @private A LAN dial or handshake to `peerId` failed: it waits longer before the next (review D). */
  _lanFailed(peerId) {
    if (!peerId) return;
    if (!this._lanBackoff) this._lanBackoff = new Map();
    const b = this._lanBackoff.get(peerId) || { failures: 0, nextAt: 0 };
    b.failures++;
    b.nextAt = Date.now() + Math.min(15_000 * 2 ** (b.failures - 1), LAN_BACKOFF_MAX_MS);
    this._lanBackoff.delete(peerId);
    if (this._lanBackoff.size >= 4096) this._lanBackoff.delete(this._lanBackoff.keys().next().value);
    this._lanBackoff.set(peerId, b);
  }

  /**
   * @private Before an inbound LAN handshake starts: past LAN_HANDSHAKES_PER_HOST authenticating from
   * this remote host, or LAN_HANDSHAKES_MAX in all, the oldest goes (security review D, hello-cost).
   */
  _makeRoomForLanHandshake(remote) {
    if (!this._lanInFlight) this._lanInFlight = new Set();
    for (const s of [...this._lanInFlight]) if (s.closed || s.confirmed) this._lanInFlight.delete(s);
    const host = String(remote || '?').replace(/:\d+$/, '');
    const same = [...this._lanInFlight].filter((s) => String(s.remote || '?').replace(/:\d+$/, '') === host);
    if (same.length >= LAN_HANDSHAKES_PER_HOST) same[0].close('handshake-evicted', { notify: false });
    if (this._lanInFlight.size >= LAN_HANDSHAKES_MAX) {
      const oldest = [...this._lanInFlight].find((s) => !s.closed);
      if (oldest) oldest.close('handshake-evicted', { notify: false });
    }
  }

  // ── Relay sessions (design D2) ─────────────────────────────

  /** @private Whether `nodeId` is a peer this node knows: bound, pinned, routed, or a live peer. */
  _isKnownPeer(nodeId) {
    if (this._peers.has(nodeId)) return true;
    if (this._roster.expected(nodeId) !== undefined) return true;
    return !!(this._legacy && this._legacy.routeFor && this._legacy.routeFor(nodeId));
  }

  /** @private Relay handshakes in flight for unknown candidates. */
  _relayUnknownInFlight() {
    let n = 0;
    if (this._relaySessions) for (const st of this._relaySessions.values()) {
      if (st.client && st.client._unknownCandidate) n++;
      if (st.server && st.server._unknownCandidate) n++;
    }
    return n;
  }

  /** @private `nodeId` waits for a relay handshake slot (see RELAY_UNKNOWN_MAX). */
  _wantRelay(nodeId) {
    if (!this._relayWanted) this._relayWanted = new Map();
    if (!this._relayWanted.has(nodeId)) {
      if (this._relayWanted.size >= 4096) this._relayWanted.delete(this._relayWanted.keys().next().value);
      this._relayWanted.set(nodeId, { since: Date.now() });
    }
    this._schedulePumpRelay();
  }

  /** @private A relay client handshake with `nodeId` failed: an unknown one waits longer next time. */
  _relayClientFailed(nodeId) {
    if (!this._relayFailures) this._relayFailures = new Map();
    const f = this._relayFailures.get(nodeId) || { failures: 0, nextAt: 0 };
    f.failures++;
    f.nextAt = Date.now() + Math.min(1000 * 2 ** f.failures, RELAY_UNKNOWN_BACKOFF_MAX_MS);
    this._relayFailures.delete(nodeId);
    if (this._relayFailures.size >= 4096) this._relayFailures.delete(this._relayFailures.keys().next().value);
    this._relayFailures.set(nodeId, f);
  }

  /** @private Run the relay handshake wait list soon (one timer). */
  _schedulePumpRelay(delay = 0) {
    if (this._pumpTimer) return;
    this._pumpTimer = setTimeout(() => { this._pumpTimer = null; this._pumpRelay(); }, delay);
    if (this._pumpTimer.unref) this._pumpTimer.unref();
  }

  /**
   * @private Start what the wait list's slots allow: known candidates first, then unknown ones by
   * fewest failures, then the newest; one still backing off waits for its time.
   */
  _pumpRelay() {
    if (!this._running || !this._relayWanted || !this._relayWanted.size) return;
    const now = Date.now();
    let soonest = Infinity;
    const ready = [];
    for (const [id, w] of [...this._relayWanted]) {
      if (!this._relay.present.has(id) || (this._identityRefused && this._identityRefused.has(id))) { this._relayWanted.delete(id); continue; }
      const st = this._relaySessions && this._relaySessions.get(id);
      if (st && ((st.client && !st.client.closed) || [...st.confirmed].some((x) => !x.closed))) { this._relayWanted.delete(id); continue; }
      const f = this._relayFailures && this._relayFailures.get(id);
      if (f && f.nextAt > now) { soonest = Math.min(soonest, f.nextAt); continue; }
      ready.push({ id, known: this._isKnownPeer(id), failures: f ? f.failures : 0, since: w.since });
    }
    ready.sort((a, b) => (a.known === b.known ? 0 : a.known ? -1 : 1) || a.failures - b.failures || b.since - a.since);
    for (const c of ready) {
      if (this._relayHandshakesInFlight() >= RELAY_HANDSHAKES_MAX) break;
      if (!c.known && this._relayUnknownInFlight() >= RELAY_UNKNOWN_MAX) continue;
      this._relayWanted.delete(c.id);
      this._startRelayClient(c.id);
    }
    if (soonest !== Infinity) this._schedulePumpRelay(Math.max(50, soonest - now));
  }

  /**
   * A clear 1011 UNKNOWN_SESSION from relay `from` (MMP §5.2.2, update 1 #23). Anyone on the relay
   * path can write one, so it prompts a new handshake only on the client side, only while the peer
   * is present, only when its `detail` names a session this node holds with that peer or a probe
   * ping to it is outstanding, while no newer session with it is waiting to supersede, and no faster
   * than the handshake retry backoff (1 s, doubling, at most 30 s; it starts over after a quiet
   * minute). The existing session stays until the new one supersedes it. Nothing else follows.
   * @returns {string|null} why it prompted nothing, or null when it did
   * @private
   */
  _onUnknownSession(from, frame) {
    const st = this._relaySessions && this._relaySessions.get(from);
    if (!(this.nodeId < from)) return 'unknown-session-server-role';
    if (!st || !this._relay || !this._relay.present.has(from)) return 'unknown-session-no-peer';
    const now = Date.now();
    const m = frame && typeof frame.detail === 'string' ? /^session:([0-9a-f]{32})$/.exec(frame.detail) : null;
    const held = [...st.confirmed].filter((x) => x.confirmed && !x.closed);
    const names = !!m && held.some((x) => x.sessionId === m[1]);
    const probed = held.find((x) => x.probeSince && now - x.probeSince <= this._handshakeTimeoutMs);
    if (!names && !probed) return 'unknown-session-not-ours';
    // A newer session with that peer is already waiting to supersede (or a handshake is in flight):
    // another would only chain re-handshakes through the supersession window.
    if ((st.client && !st.client.closed) || [...st.confirmed].some((x) => x._supersedes && !x.closed)) return 'unknown-session-superseding';
    if (!this._unknownSessionPrompts) this._unknownSessionPrompts = new Map();
    const g = this._unknownSessionPrompts.get(from) || { attempt: 0, at: -Infinity };
    if (now - g.at > 60_000) g.attempt = 0;
    if (now - g.at < Math.min(1000 * 2 ** Math.max(0, g.attempt - 1), 30_000)) return 'unknown-session-backoff';
    g.attempt++;
    g.at = now;
    this._unknownSessionPrompts.delete(from);
    if (this._unknownSessionPrompts.size >= 1024) this._unknownSessionPrompts.delete(this._unknownSessionPrompts.keys().next().value);
    this._unknownSessionPrompts.set(from, g);
    if (probed) probed.probeSince = 0;
    this._startRelayClient(from);
    return null;
  }

  /** @private Tell relay `from` that `sessionId` (or, null, any session) is not held here (rate-limited per from). */
  _sayUnknownSession(from, sessionId) {
    if (!this._unknownSessionSaid) this._unknownSessionSaid = new Map();
    const now = Date.now();
    if (now - (this._unknownSessionSaid.get(from) ?? -Infinity) < 1000) return;
    // One small budget for every such reply (security review D, pacer-starve): a flood of strangers
    // buys at most UNKNOWN_SESSION_PER_SECOND replies in all; past it they are dropped, not queued.
    const b = this._unknownSessionBudget || (this._unknownSessionBudget = { tokens: UNKNOWN_SESSION_BURST, at: now });
    b.tokens = Math.min(UNKNOWN_SESSION_BURST, b.tokens + ((now - b.at) * UNKNOWN_SESSION_PER_SECOND) / 1000);
    b.at = now;
    if (b.tokens < 1) { this._unknownSessionDropped = (this._unknownSessionDropped || 0) + 1; return; }
    b.tokens -= 1;
    // Least recently said first out: at most 1,024 froms remembered.
    this._unknownSessionSaid.delete(from);
    if (this._unknownSessionSaid.size >= 1024) this._unknownSessionSaid.delete(this._unknownSessionSaid.keys().next().value);
    this._unknownSessionSaid.set(from, now);
    try { this._relay.sendTo(from, { type: 'error', code: UNKNOWN_SESSION_CODE, message: 'unknown session', ...(sessionId ? { detail: `session:${sessionId}` } : {}) }); } catch { /* best effort */ }
  }

  /** @private Close the oldest unknown relay handshake in flight (client or server). @returns {boolean} */
  _evictOldestUnknownRelayHandshake() {
    let oldest = null;
    if (this._relaySessions) for (const st of this._relaySessions.values()) {
      for (const x of [st.server, st.client]) {
        if (x && !x.closed && !x.confirmed && x._unknownCandidate && (!oldest || x.startedAt < oldest.startedAt)) oldest = x;
      }
    }
    if (!oldest) return false;
    oldest.close('handshake-evicted', { notify: false });
    return true;
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
      if (now - (live._probedAt || 0) >= 1000) {
        live._probedAt = now;
        // Outstanding until a pong comes back (lib/session.js): a 1011 while it is may prompt a
        // re-handshake though it names no session (§5.2.2).
        if (!live.probeSince) live.probeSince = now;
        try { live.send({ type: 'ping' }); } catch { /* it closes itself */ }
      }
      return;
    }
    this._startRelayClient(nodeId);
  }

  /** @private Send a client-hello to `nodeId` over the relay (one handshake in flight at a time). */
  _startRelayClient(nodeId) {
    if (!this._running) return;
    if (this._identityRefused && this._identityRefused.has(nodeId)) return; // 1009: not retried (review F)
    const cur = this._relaySessions && this._relaySessions.get(nodeId);
    if (cur && cur.client && !cur.client.closed) return;
    // At most RELAY_HANDSHAKES_MAX in flight, and at most RELAY_UNKNOWN_MAX of them for unknown
    // candidates: the rest wait in turn (_pumpRelay). An unknown one still backing off waits too.
    const unknown = !this._isKnownPeer(nodeId);
    const f = unknown && this._relayFailures && this._relayFailures.get(nodeId);
    if (this._relayHandshakesInFlight() >= RELAY_HANDSHAKES_MAX || (unknown && this._relayUnknownInFlight() >= RELAY_UNKNOWN_MAX) || (f && f.nextAt > Date.now())) {
      this._wantRelay(nodeId);
      return;
    }
    const st = this._relayState(nodeId);
    st.client = this._attachTransport(this._relay.transportFor(nodeId), { role: 'client', kind: 'relay', relayFrom: nodeId, expectNodeId: nodeId });
    st.client._unknownCandidate = unknown;
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
        // A relay `from`'s hellos are rate-limited (a hello costs a key agreement and a signature).
        if (!takeToken(this._relayHelloBuckets || (this._relayHelloBuckets = new Map()), from, RELAY_HELLO_PER_SECOND, RELAY_HELLO_BURST, Date.now(), 4096)) { refuse('hello-rate'); return; }
        // One authenticating slot per (relay, from): a new hello retires the one in flight. At most
        // RELAY_HANDSHAKES_MAX in flight in all, at most RELAY_UNKNOWN_MAX for unknown froms; past
        // a share, the oldest unknown handshake in flight goes, so a flood of hellos that never
        // finish holds slots only until newer hellos arrive (security review D, relay-slots).
        const unknown = !this._isKnownPeer(from);
        const prev = st && st.server && !st.server.closed && !st.server.confirmed ? st.server : null;
        if (!prev) {
          const full = this._relayHandshakesInFlight() >= RELAY_HANDSHAKES_MAX;
          const unknownFull = unknown && this._relayUnknownInFlight() >= RELAY_UNKNOWN_MAX;
          if (full || unknownFull) {
            if (!this._evictOldestUnknownRelayHandshake()) { refuse('too-many-handshakes'); return; }
          }
        }
        const s = this._relayState(from);
        // The new session is attached before the old one closes, so the relay state entry (which lives
        // only while a session for this `from` does) is never dropped from under it (review item 11).
        const next = this._attachTransport(this._relay.transportFor(from), { role: 'server', kind: 'relay', relayFrom: from, expectNodeId: from });
        next._unknownCandidate = unknown;
        s.server = next;
        if (prev) prev.close('superseded-hello', { notify: false });
        next.receiveWire(payload);
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
        // A CLEAR error over the relay is anyone's to write (security review F): it never closes a
        // session. Only 1011 UNKNOWN_SESSION means something: the peer holds no session with this node
        // (its process restarted). The client re-handshakes and keeps the session it has until the new
        // one confirms and supersedes it; the server waits for the client's hello. A session's own
        // errors (1010 closing, 1009 identity conflict) arrive sealed, on the session.
        if (payload.code === UNKNOWN_SESSION_CODE) {
          const why = this._onUnknownSession(from, payload);
          if (why) refuse(why);
          return;
        }
        refuse('clear-error-ignored');
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
    const owner = this._roomOwners && this._roomOwners.ownerOf(this._room);
    const peer = this._peers.get(peerId);
    if (peer) {
      // A Legacy Import peer never passes a gated room's door (security review E): it proved no key.
      const ts = peer.transports ? [...peer.transports.values()] : [];
      if (owner && ts.length > 0 && ts.every((t) => t.legacy)) return { pass: false, reason: `a Legacy Import peer cannot join gated room '${this._room}'` };
      return { pass: true };
    }
    if (v) return { pass: true };
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

// MMP §6.6 authority: pin, statements, frames and roles (lib/node-authority.js).
Object.assign(SymNode.prototype, authorityMixin.methods);

/** The lifecycle authority a static role gives where no anchor is pinned (a closed development mode, §6.5). */
function lifecycleOfRole(role) {
  return role === 'anchor' || role === 'admin' ? 'canonical' : role === 'validator' ? 'validated' : 'none';
}

module.exports = { SymNode, migrateStores, version: ENGINE_VERSION };

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
