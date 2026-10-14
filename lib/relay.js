'use strict';

/**
 * RelayConnection — manages the WebSocket relay connection and relay peers.
 *
 * Handles: connect, reconnect, relay-peer-joined/left, relay message routing.
 * See MMP v0.2.0 Section 4 (Transport), Section 5 (Connection).
 *
 * Copyright (c) 2026 SYM.BOT. Apache 2.0 License.
 */

const { MAX_FRAME_SIZE, SEND_FAILURE } = require('./frame-parser');
const { PEER_INFO_MAX } = require('./core/wake');
const { wireNodeId, wireName } = require('./wire-identity');
const RELAY_ENVELOPE_ALLOWANCE = 4096;
const { nestedTooDeep } = require('./core/json-depth');
const keyProof = require('./core/relay-auth-proof');
const { CANONICAL_KEY_B64URL } = require('./core/ed25519');
/**
 * THE CONNECTION CEILING IS NOT THE MESSAGE BOUND (R3-1, R3-2). A delivered envelope is at most
 * MAX_FRAME_SIZE + RELAY_ENVELOPE_ALLOWANCE (MMP §4.4.4), and this client used that as the ws
 * `maxPayload` of the whole connection: one larger message — a relay that re-serialised a payload
 * longer than it arrived (sym-relay before 0.6.1), or a roster padded with long names — made ws close
 * the shared connection (1009/1006), and the sender could do it again on every reconnect. The ws
 * ceiling is now this, large and still bounded; a message over the per-message bound is dropped on
 * its own (counted in state().oversizeDropped) and the connection stays up. The relay's roster
 * (`relay-peers`) is the one message read past the per-message bound, up to this ceiling: dropping it
 * would leave the node not knowing its room.
 */
const RELAY_CONNECTION_MAX = 8 * 1024 * 1024;
const MESSAGE_MAX = MAX_FRAME_SIZE + RELAY_ENVELOPE_ALLOWANCE;
const ROSTER_PREFIX = /^\s*\{\s*"type"\s*:\s*"relay-peers"/;

/**
 * A RELAY URL, as this client dials it: an absolute ws:// or wss:// URL with a host. http:// and
 * https:// are the same relay (ws maps them, and sym 0.14.2 dialled them), so they are taken and
 * spelled ws:// and wss:// here, where every relay URL comes in (SymNode, RelayConnection, an
 * invite): the URL the node dials, shows and signs its key proof's origin over is that one.
 * @param {*} url
 * @returns {string|null} the URL to dial, or null when it is not a relay URL (relayUrlProblem says why)
 */
function normalizeRelayUrl(url) {
  if (typeof url !== 'string') return null;
  const s = url.trim();
  if (!s || s.length > 2048) return null;
  const spelled = s.replace(/^https?(?=:)/i, (m) => (m.length === 5 ? 'wss' : 'ws'));
  let u;
  try { u = new URL(spelled); } catch { return null; }
  if ((u.protocol !== 'ws:' && u.protocol !== 'wss:') || !u.hostname) return null;
  return spelled;
}

/** Whether `url` is a relay URL this client can dial (normalizeRelayUrl). */
function isRelayUrl(url) {
  return normalizeRelayUrl(url) !== null;
}

/**
 * Why `url` is not a relay URL, in words that never repeat it (it may carry a secret): what it is,
 * and how long. Null when it is one.
 */
function relayUrlProblem(url) {
  if (normalizeRelayUrl(url) !== null) return null;
  if (typeof url !== 'string') return `the relay setting is a ${url === null ? 'null' : typeof url}, not a URL`;
  const s = url.trim();
  if (!s) return 'the relay setting is empty';
  if (s.length > 2048) return `the relay setting is ${s.length} characters long (at most 2048)`;
  let u = null;
  try { u = new URL(s); } catch { /* not a URL at all */ }
  if (!u) return `the relay setting (${s.length} characters) is not a URL`;
  if (!/^(wss?|https?):$/.test(u.protocol)) return `the relay setting is a ${u.protocol.replace(/:$/, '')}: URL, not ws://, wss://, http:// or https://`;
  return 'the relay setting names no host';
}
/**
 * Peers the relay's announcements (join notices, peer-list entries) may add to the peer table:
 * peers this node did not know when they were announced. Past this many, an announcement for a
 * nodeId this node does not know is ignored (said once, counted in state().announcementsIgnored).
 * A peer this node already knows (announced before, or with a live transport of its own) is
 * unaffected, and one that leaves (relay-peer-left, or the relay link closing) frees its place.
 */
const MAX_ANNOUNCED_PEERS = 4096;
const ENGINE_VERSION = require('../package.json').version;

/**
 * The relay closes a connection that sends more than 25 frames a second sustained (burst 300) with
 * 4008 (sym-relay 0.5: a token bucket per connection, every frame counted; MMP 2.0 update 1 makes
 * 25/300 the floors a relay MUST allow, §19.1). Core Secure seals one frame per peer session, so a
 * room broadcast is N frames: this client paces everything it sends at 20 a second (burst 200),
 * relay-auth and relay-pong inside the same bucket, so the headroom holds whatever it sends, and
 * queues what does not fit.
 */
const RELAY_RATE_PER_SECOND = 20;
const RELAY_BURST = 200;
/** Frames waiting for the pacer at most; past it a send is refused (`queue-full`), never dropped silently. */
const RELAY_QUEUE_MAX = 10_000;
/**
 * THE PACER IS FAIR (security review D, pacer-starve): one FIFO carried everything at the relay's
 * rate, so replies to a flood of strangers queued ahead of an honest session's records. Now each
 * frame waits in its CLASS — 0: confirmed-session traffic (sealed frames, ping/pong, Legacy Import
 * records), 1: handshakes, 2: everything else (a 1011 reply, an error) — and within a class in its
 * destination's own queue, the destinations served in turn. A higher class always goes first.
 * Class 2 holds at most CLASS2_MAX frames (past it a send is refused), and one destination at most
 * PER_DESTINATION_MAX.
 */
const CLASS2_MAX = 64;
const PER_DESTINATION_MAX = 2048;
/** Bytes waiting for one destination, at most (a 1 MiB frame each could otherwise pile up). */
const PER_DESTINATION_BYTES = 8 * 1024 * 1024;
const CLASS0 = new Set(['cmb-encrypted', 'control-encrypted', 'ping', 'pong', 'cmb']);
const CLASS1 = new Set(['client-hello', 'server-hello', 'client-finish', 'handshake']);
const classOf = (payload) => {
  const t = payload && payload.type;
  return CLASS0.has(t) ? 0 : CLASS1.has(t) ? 1 : 2;
};

/**
 * One FIFO per destination, so a destination's frames leave in the order they were sent (a
 * client-finish before the sealed frames that follow it); the destinations wait in the CLASS of the
 * frame at their head, a higher class served first and destinations within a class in turn.
 */
class FairQueue {
  constructor() { this.clear(); }
  clear() { this.byTo = new Map(); this.bytesTo = new Map(); this.ready = [new Map(), new Map(), new Map()]; this.class2 = 0; this.length = 0; }
  /**
   * Take out of `to`'s queue the frames `pred` picks, keeping the rest in their order. @returns {object[]}
   */
  removeWhere(to, pred) {
    const q = this.byTo.get(to);
    if (!q || !q.length) return [];
    const keep = [];
    const out = [];
    for (const it of q) (pred(it) ? out : keep).push(it);
    if (!out.length) return [];
    this.ready[q[0].cls].delete(to);
    for (const it of out) { this.length--; if (it.cls === 2) this.class2--; }
    if (keep.length) {
      this.byTo.set(to, keep);
      this.bytesTo.set(to, keep.reduce((n, it) => n + it.bytes, 0));
      this.ready[keep[0].cls].set(to, true);
    } else {
      this.byTo.delete(to);
      this.bytesTo.delete(to);
    }
    return out;
  }
  /** Every frame still waiting, each destination's in its order, and the queue emptied. @returns {object[]} */
  drain() {
    const all = [];
    for (const q of this.byTo.values()) for (const item of q) all.push(item);
    this.clear();
    return all;
  }
  /** Bytes waiting for `to`. */
  bytesFor(to) { return this.bytesTo.get(to) || 0; }
  /**
   * Whether `bytes` more for `to` fit with HALF of every bound to spare (the queue's length, the
   * destination's frames and bytes): what a sender that can wait (a re-offer) checks, so it never
   * takes the room a refused sealed frame would end a session for.
   */
  hasRoom(to, bytes) {
    const q = this.byTo.get(to);
    return this.length < RELAY_QUEUE_MAX / 2 && (!q || q.length < PER_DESTINATION_MAX / 2)
      && this.bytesFor(to) + bytes <= PER_DESTINATION_BYTES / 2;
  }
  /** @returns {string|null} why it was not queued, or null */
  push(cls, item) {
    if (this.length >= RELAY_QUEUE_MAX) return 'queue-full';
    if (cls === 2 && this.class2 >= CLASS2_MAX) return 'queue-full';
    let q = this.byTo.get(item.to);
    if (!q) { q = []; this.byTo.set(item.to, q); }
    if (q.length >= PER_DESTINATION_MAX || this.bytesFor(item.to) + item.bytes > PER_DESTINATION_BYTES) return 'queue-full';
    item.cls = cls;
    q.push(item);
    this.bytesTo.set(item.to, this.bytesFor(item.to) + item.bytes);
    if (cls === 2) this.class2++;
    this.length++;
    if (q.length === 1) this.ready[cls].set(item.to, true);
    return null;
  }
  /**
   * Take the next frame: the destination first in turn in the highest class holding one, skipping
   * destinations in `exclude` and a head frame that does not fit in `room` bytes. @returns {object|null}
   */
  take(exclude = null, room = Infinity) {
    for (let cls = 0; cls < 3; cls++) {
      for (const to of this.ready[cls].keys()) {
        if (exclude && exclude.has(to)) continue;
        const q = this.byTo.get(to);
        if (q[0].bytes > room) continue;
        const item = q.shift();
        const left = this.bytesFor(to) - item.bytes;
        if (left > 0) this.bytesTo.set(to, left); else this.bytesTo.delete(to);
        this.ready[cls].delete(to);
        if (item.cls === 2) this.class2--;
        this.length--;
        if (q.length) this.ready[q[0].cls].set(to, true); // to the back of its head's class
        else this.byTo.delete(to);
        return item;
      }
    }
    return null;
  }
}
/**
 * The fan-out envelope (design D4; MMP spec draft PR meshcognition-website#25, for sym-relay 0.6.0):
 * `{ fanout: [{ to, payload }, …] }` is one client message, counted once toward the relay's rate,
 * delivered to each recipient as the unicast it would have been. Used only when the relay lists the
 * `fanout` token in `relay-peers.features` on this connection; an older relay is paced instead. The
 * draft has a relay that lists it accept at least FANOUT_MAX entries, with no recipient twice in one
 * envelope (a malformed fan-out is refused whole).
 */
const FANOUT_FEATURE = 'fanout';

/**
 * Close codes after which the client never reconnects on its own (MMP §4.4.7, §4.4.9): each says
 * another connection holds this node's relay slot, and reconnecting would only fight it.
 *   4004 replaced — another connection authenticated as this nodeId and the relay took the slot. On a
 *        relay that verifies keys (sym-relay ≥ 0.8.0; this connection proved its key, see
 *        core/relay-auth-proof.js) only a holder of this node's private key can do that: another
 *        process proved this identity's key on the relay, it is the newest holder, and this one stops.
 *        On a relay that does not verify keys any holder of the channel token can, by claiming the
 *        nodeId; the client says so (upgrade the relay) and still stops.
 *   4006 duplicate rejected — a relay that does not verify keys found another live connection
 *        claiming this nodeId (first writer wins inside 5 s). A relay that verifies keys never sends
 *        it to a proven connection.
 * A 0.14.3 candidate retried both on a long backoff with a ping-pong detector: a patch over an
 * identity the relay did not verify, and it let two processes holding one key flap forever. It is
 * gone; the key proof is the fix, and on a proven connection the newest proof of a key wins, once.
 *
 * Every other close is reconnected with backoff (MMP 2.0 update 1, §4.4.9): 4005, 4008, and the
 * RFC 6455 closes 1001, 1009, 1011 and 1013 by the table, and 4002 and 4007 too. 4007 belonged to
 * the key-proof draft of meshcognition-website#20, whose review found a lockout in "MUST NOT
 * reconnect after 4007"; a relay that refuses a proof here closes with 4002 (fix the auth frame).
 */
const HARD_STOPS = {
  4004: { phase: 'collision', kind: 'replaced' },
  4006: { phase: 'duplicate-rejected', kind: 'duplicate-rejected' },
};
const STOP_PHASES = Object.values(HARD_STOPS).map((h) => h.phase);
const TERMINAL_PHASES = ['connected', 'refused', ...STOP_PHASES, 'disabled', 'off'];
/** The relay's feature token for key proof: keyed slots, `key`/`proven` entries, and `toKey`. */
const KEY_PROOF_FEATURE = 'key-proof';
/**
 * Slots one nodeId may hold in this client's view of the relay at once (a relay that verifies keys
 * lists one entry per key that proved it, and one for a legacy claim). Past it, an announcement of
 * another key for that nodeId is ignored and counted (state().slotsIgnored).
 */
const MAX_SLOTS_PER_NODE = 16;
const FANOUT_MAX = 64;

/** Whether `identity` holds what a key proof needs: its Ed25519 key pair (base64url, raw). */
function canProve(identity) {
  return !!identity && typeof identity.privateKey === 'string' && identity.privateKey.length > 0
    && typeof identity.publicKey === 'string' && CANONICAL_KEY_B64URL.test(identity.publicKey);
}

/**
 * The slot a roster or presence entry names: its key when the relay says it is proven (a canonical
 * base64url key and `proven: true`, sym-relay 0.8.0), '' for a legacy claim or an older relay.
 */
function slotKeyOf(entry) {
  return entry && entry.proven === true && typeof entry.key === 'string' && CANONICAL_KEY_B64URL.test(entry.key) ? entry.key : '';
}

/** The cause of a hard stop, in the words the log, describe() and the docs use. */
function hardStopCause(relayVerifiesKeys) {
  return relayVerifiesKeys
    ? 'another process proved this identity\'s key on this relay; this one stopped'
    : 'this relay does not verify keys, so any holder of the token can cause this; upgrade the relay';
}
/** The relay's own frames (auth, pong) waiting for a token at most; see _sendControl. */
const CONTROL_QUEUE_MAX = 8;
class RelayConnection {

  /**
   * @param {object} opts
   * @param {string}   opts.relayUrl           — relay WebSocket URL
   * @param {string}   opts.relayToken         — optional auth token
   * @param {object}   opts.wakeChannel        — this node's wake channel config
   * @param {function} opts.log                — logging function
   * @param {function} opts.getIdentity        — () => identity
   * @param {function} opts.isRunning          — () => boolean
   * @param {function} opts.getPeers           — () => peers Map
   * @param {function} opts.getMeshNode        — () => meshNode
   * @param {function} opts.createPeer         — (transport, peerId, peerName, isOutbound, source) => peer
   * @param {function} opts.addPeer            — (peer) => void
   * @param {function} opts.handlePeerMessage  — (peerId, peerName, msg, lane) => void; `lane` is this
   *   relay connection and the sender id it names, the key the node's gossip budget is kept by
   * @param {function} opts.onPeerLeft         — (peerId, peerName) => void — emit peer-left event
   * @param {string}   opts.nodeName           — this node's name
   * @param {Map}      opts.peerWakeChannels   — shared peer wake channels Map
   * @param {function} opts.saveWakeChannels   — () => void
   * @param {function} opts.learnWakeChannel   — (nodeId, channel, {source, lastSeen}) => outcome (WakeManager)
   * @param {function} [opts.onIdentityCollision] — ({nodeId, name, code, kind, reason,
   *                   relayVerifiesKeys}) => void — called once when the relay closes with 4004 or
   *                   4006 (HARD_STOPS). The relay layer has logged it loudly and stopped
   *                   reconnecting; LAN peers are unaffected. `relayVerifiesKeys` true: this
   *                   connection had proved its key, so another process proved the same key (stop
   *                   one of them); false: the relay does not verify keys, so any token holder could
   *                   have caused it (upgrade the relay).
   * @param {function} [opts.keyOf] — (nodeId) => key | undefined — the identity key this node binds to
   *                   `nodeId` (base64url), if any. A relay that verifies keys lists every key that
   *                   proved a nodeId; the one bound here is preferred, and directed frames name it
   *                   (`toKey`) so the relay hands them to that slot only.
   * @param {function} [opts.onIdentityAmbiguous] — (nodeId, keys[]) => void — the relay presents
   *                   `nodeId` under more than one proven key and none is bound here; no session is
   *                   started for it until it resolves (a pin, a certification, or the rivals leaving).
   * @param {function} [opts.onIdentityResolved] — (nodeId) => void — an ambiguity above is gone.
   * @param {function} [opts.onUnflushed] — (items) => void — frames the pacer still held when the
   *                   connection closed, each `{ to, bytes, meta }`, for those sent with a `meta`
   *                   (sendTo's third argument); the node re-offers them to the next session.
   * @param {function} [opts.onFlushed] — (meta) => void — a frame sent with a `meta` was written to
   *                   the socket.
   * @param {function} [opts.onAuthRefused] — ({relayUrl, name, code, reason}) => void —
   *                   called ONCE per refusal episode when the relay closes with 4003
   *                   (token not in its channel table). The relay layer has already
   *                   logged the cause and the fix and dropped to the slow retry.
   * @param {number}   [opts.authRefusedRetryMs] — cadence of the slow retry after a
   *                   4003 (default 10 minutes).
   */
  constructor(opts) {
    // A relay setting that is not a relay URL disables the relay, said in state() and describe(),
    // and never throws: the relay is an optional transport, and the node runs on the LAN without it.
    const given = opts.relayUrl;
    const hasSetting = !(given === null || given === undefined || given === '');
    this._relayUrl = hasSetting ? normalizeRelayUrl(given) : null;
    this._disabled = hasSetting && !this._relayUrl ? { reason: relayUrlProblem(given), at: Date.now() } : null;
    this._relayToken = opts.relayToken;
    this._wakeChannel = opts.wakeChannel;
    this._log = opts.log;
    this._getIdentity = opts.getIdentity;
    this._getRoom = opts.getRoom || (() => null);   // the room this node declares to the relay (wire note D4)
    this._isRunning = opts.isRunning;
    // The node's session manager (design D1/D2): a relay roster entry is a CANDIDATE — a nodeId the
    // relay says is present — and an envelope is bytes from a relay `from`. Neither creates a peer:
    // the node runs the §5.2 handshake over the channel and a peer exists only once it confirms.
    this._onPeerPresent = opts.onPeerPresent || (() => {});
    this._onPeerGone = opts.onPeerGone || (() => {});
    // A nodeId the relay presents under several proven keys, none bound here: reported, never guessed.
    this._onIdentityAmbiguous = opts.onIdentityAmbiguous || (() => {});
    this._onIdentityResolved = opts.onIdentityResolved || (() => {});
    this._ambiguous = new Map();
    this._onEnvelope = opts.onEnvelope || (() => {});
    this._onDisconnected = opts.onDisconnected || (() => {});
    // (frame, take) => boolean: runs `take` for one message off the relay socket so that nothing it
    // does can throw out of the socket's callback (the node passes its inbound guard, which refuses
    // and counts); without one, a throw is caught and logged here.
    this._guard = typeof opts.guard === 'function' ? opts.guard : (frame, take) => {
      try { take(); return true; } catch (err) {
        try { this._log(`Relay message refused: ${err && typeof err.message === 'string' ? err.message.slice(0, 200) : 'unknown error'}`); } catch { /* never the failure */ }
        return false;
      }
    };
    // The relay's announcements name candidates; at most this many are held (0.13.17's bound).
    this._maxAnnounced = Number.isInteger(opts.maxAnnouncedPeers) && opts.maxAnnouncedPeers > 0 ? opts.maxAnnouncedPeers : MAX_ANNOUNCED_PEERS;
    this._announcementsIgnored = 0;
    // A peer the node already knows (a live session of its own) is never ignored at the bound.
    this._isKnown = typeof opts.isKnown === 'function' ? opts.isKnown : () => false;
    // The pacer and the fan-out feature the relay advertises.
    this._rate = (opts.rate && opts.rate.perSecond) || RELAY_RATE_PER_SECOND;
    this._burst = (opts.rate && opts.rate.burst) || RELAY_BURST;
    this._bucket = { tokens: this._burst, at: Date.now() };
    this._control = [];               // the relay's own frames (auth, pong), sent first, inside the bucket
    this._queue = new FairQueue();    // per class, per destination (see FairQueue)
    this._flushTimer = null;
    this._flushScheduled = false;
    this._fanout = null;              // { max } when the relay advertises fan-out
    this._present = new Map();        // nodeId -> name, as the relay last reported
    this._sentFrames = 0;
    this._sentFanout = 0;
    this._onIdentityCollision = opts.onIdentityCollision || null;
    this._onAuthRefused = opts.onAuthRefused || null;
    this._authRefusedRetryMs = opts.authRefusedRetryMs || 10 * 60 * 1000;
    this._authRefused = false;
    this._nodeName = opts.nodeName;
    this._identityCollision = false;   // a hard stop (4004 / 4006): never reconnect on its own
    this._stopped = null;              // { code, kind, reason, at, relayVerifiesKeys } — why, for state() and describe()
    // Key proof (core/relay-auth-proof.js). Per connection: whether this node asked for a challenge,
    // the challenge's nonce once it came, and whether the relay took the proof (relay-peers after it).
    this._keyOf = typeof opts.keyOf === 'function' ? opts.keyOf : () => undefined;
    this._proof = { requested: false, nonce: null, proven: false };
    this._relayVerifiesKeys = null;    // what the last relay answer said: true, false, or null before one
    this._unverifiedSaid = false;      // "this relay does not verify keys" is said once
    this._keyProofFeature = false;     // the relay lists `key-proof` on this connection
    this._authFrameSent = null;        // the relay-auth this connection last sent (relay-reauth re-sends it)
    // The relay's slots: nodeId -> Map(key, or '' for a legacy claim -> { name, key, proven }).
    this._slots = new Map();
    this._slotsIgnored = 0;
    this._onUnflushed = typeof opts.onUnflushed === 'function' ? opts.onUnflushed : null;
    this._onFlushed = typeof opts.onFlushed === 'function' ? opts.onFlushed : null;
    this._oversizeDropped = 0;         // relay messages over the per-message bound, dropped on their own

    this._relayWs = null;
    this._relayReconnectTimer = null;
    this._relayReconnectDelay = 1000;
    this._lastRelayMessage = 0;  // timestamp of last message from relay

    // Observable state. A host used to see one bit — `ws.readyState === 1` — so a refused
    // token, an unreachable host and a relay mid-restart all read "disconnected", and the
    // agent driving the session could not tell which it was, let alone what to do. Every
    // transition below is recorded so state() can say the phase, the last close, and the
    // next retry, and describe() can put the fix in one line.
    this._phase = this._disabled ? 'disabled' : this._relayUrl ? 'idle' : 'off';
    this._phaseSince = Date.now();
    this._attempts = 0;          // consecutive connects since the last successful auth
    this._nextRetryAt = null;
    this._lastClose = null;      // { code, reason, at }
    this._lastError = null;      // { message, at }
    this._refused = null;        // { code, reason, at } while a refusal episode lasts
    this._outcomeWaiters = [];
  }

  /** The underlying WebSocket (for readyState checks). */
  get ws() { return this._relayWs; }

  /**
   * Snapshot of the relay connection as the host should reason about it.
   * phase: off | disabled | idle | connecting | authenticating | connected | reconnecting | refused
   *        | collision (4004) | duplicate-rejected (4006) — the last two are hard stops (HARD_STOPS),
   *        `stopped` says which ({ code, kind, reason, at, relayVerifiesKeys }); `disabled` is a relay
   *        setting that is not a relay URL (`disabled.reason`), and the node runs on the LAN only.
   * relayVerifiesKeys: true when the relay took this node's key proof on its last answer, false when it
   *        authenticated it without one (a relay that does not verify keys), null before an answer.
   */
  state() {
    return {
      url: this._relayUrl || null,
      phase: this._phase,
      disabled: this._disabled,
      relayVerifiesKeys: this._relayVerifiesKeys,
      slotsIgnored: this._slotsIgnored,
      identityAmbiguous: this._ambiguous ? this._ambiguous.size : 0,
      since: this._phaseSince,
      attempts: this._attempts,
      nextRetryAt: this._nextRetryAt,
      lastClose: this._lastClose,
      lastError: this._lastError,
      refused: this._refused,
      stopped: this._stopped,
      peers: this._present.size,
      announcementsIgnored: this._announcementsIgnored,
      queued: this._queue.length,
      fanout: this._fanout ? { max: this._fanout.max } : null,
      sentFrames: this._sentFrames,
      sentFanout: this._sentFanout,
      oversizeDropped: this._oversizeDropped,
    };
  }

  /** One line a person or an agent can act on. Same words everywhere the state is shown. */
  describe() {
    const s = this.state();
    const ago = (t) => `${Math.max(0, Math.round((Date.now() - t) / 1000))}s`;
    const inS = (t) => `${Math.max(0, Math.round((t - Date.now()) / 1000))}s`;
    switch (s.phase) {
      case 'off': return 'not configured (LAN only)';
      case 'disabled':
        return `DISABLED: ${s.disabled.reason}, so the relay is off and this node runs on the LAN only. ` +
          `Fix: set SYM_RELAY_URL (or the invite's relay) to a ws://, wss://, http:// or https:// URL and restart.`;
      case 'idle': return `configured: ${s.url} (not started)`;
      case 'connecting': return `connecting to ${s.url} (attempt ${s.attempts})`;
      case 'authenticating': return `authenticating with ${s.url} (attempt ${s.attempts})`;
      case 'connected':
        return `connected to ${s.url} for ${ago(s.since)}, ${s.peers} relay peer(s); ` +
          (s.relayVerifiesKeys ? 'the relay verified this node\'s key' : 'this relay does not verify keys (any holder of its token can claim this node\'s nodeId there; upgrade the relay)');
      case 'refused':
        if (s.refused.kind === 'key-proof') {
          return `REFUSED by ${s.url}: its key proof was not accepted (${s.refused.reason}). This node signed for ${s.refused.origin}; ` +
            `if the relay answers to another origin, dial that URL or have its operator add this one (SYM_RELAY_ORIGINS). ` +
            `Not falling back to unproven auth. Retrying every ${Math.round(this._authRefusedRetryMs / 60000)} min meanwhile.`;
        }
        return `REFUSED by ${s.url} (${s.refused.code}: ${s.refused.reason}) since ${ago(s.refused.at)} ago — ` +
          `the token this session presents is not accepted by that relay. Fix: mint a token with sym_invite_create ` +
          `or get the team's invite, then sym_join_room with it (or fix SYM_RELAY_TOKEN and restart). ` +
          `Retrying every ${Math.round(this._authRefusedRetryMs / 60000)} min meanwhile.`;
      case 'collision':
      case 'duplicate-rejected': {
        const st = s.stopped || {};
        const what = s.phase === 'collision'
          ? `${s.url} replaced this connection (4004)`
          : `${s.url} refused this connection as a duplicate of another live one (4006)`;
        return `STOPPED: ${what}: ${hardStopCause(st.relayVerifiesKeys)}. Not reconnecting — ` +
          (st.relayVerifiesKeys ? 'stop the other process holding this identity, then restart this one.' : 'restart this node to rejoin, and upgrade the relay.');
      }
      case 'reconnecting': {
        const last = s.lastClose ? `last close ${s.lastClose.code}${s.lastClose.reason ? `: ${s.lastClose.reason}` : ''}` :
          (s.lastError ? `last error: ${s.lastError.message}` : 'no answer');
        return `unreachable: ${s.url} (${last}) — retry in ${s.nextRetryAt ? inS(s.nextRetryAt) : '?'}, attempt ${s.attempts}. ` +
          `LAN peers are unaffected.`;
      }
      default: return `${s.phase}: ${s.url}`;
    }
  }

  /**
   * Resolve with state() the first time the connection reaches an outcome — connected,
   * refused or collision — or after `timeoutMs` with whatever the state is then. Lets a
   * join report the relay's actual answer instead of "discovering peers".
   */
  awaitOutcome(timeoutMs = 10000) {
    const terminal = () => TERMINAL_PHASES.includes(this._phase);
    if (terminal()) return Promise.resolve(this.state());
    return new Promise((resolve) => {
      const timer = setTimeout(() => { done(); }, timeoutMs);
      const done = () => {
        clearTimeout(timer);
        this._outcomeWaiters = this._outcomeWaiters.filter((w) => w !== done);
        resolve(this.state());
      };
      this._outcomeWaiters.push(done);
    });
  }

  _setPhase(phase) {
    if (phase === this._phase) return;
    this._phase = phase;
    this._phaseSince = Date.now();
    if (TERMINAL_PHASES.includes(phase)) {
      for (const w of this._outcomeWaiters.slice()) w();
    }
  }

  /** The nodeIds the relay reports present (candidates: nothing about them is proven). */
  get present() { return new Map(this._present); }

  /**
   * Open WebSocket connection to the relay and authenticate.
   * Auto-reconnects on disconnect with exponential backoff.
   */
  /**
   * The relay's peer list, sent after a successful relay-auth (a refusal episode ends here). The
   * relay re-sends the whole list on every (re)connect, so wake channels are learned quietly and
   * what changed is said once.
   * @private
   */
  _handleRelayPeers(msg) {
    this._authRefused = false;
    this._refused = null;
    this._attempts = 0;
    // The backoff starts over HERE, when the relay has taken the auth (R3-10). It started over when
    // the WebSocket opened, so a relay that accepted the socket and then closed it (1013 Try Again
    // Later, 4008, 1009) was dialled every second for as long as it did so.
    this._relayReconnectDelay = 1000;
    // The relay took this connection's auth: with this node's key proof when it had asked for one
    // and this node answered it, without one otherwise (core/relay-auth-proof.js).
    this._proof.proven = !!this._proof.nonce;
    this._relayVerifiesKeys = this._proof.proven;
    if (!this._proof.proven && !this._unverifiedSaid) {
      this._unverifiedSaid = true;
      this._log(`Relay ${this._relayUrl} does not verify keys (it took relay-auth without a key proof${this._proof.requested ? '' : '; this node has no key to prove'}): any holder of its token can claim this node's nodeId there and close this connection. Upgrade the relay (sym-relay ≥ 0.8.0) to have it verify keys.`);
    }
    this._setPhase('connected');
    // The relay's features (sym-relay 0.6.0 advertises fan-out here). Absent means an older relay:
    // every frame goes on its own, paced.
    // Unknown tokens are ignored; an absent list lists nothing.
    const features = Array.isArray(msg.features) ? msg.features.filter((f) => typeof f === 'string') : [];
    this._fanout = features.includes(FANOUT_FEATURE) ? { max: FANOUT_MAX } : null;
    // `key-proof` (sym-relay 0.8.0): `toKey` is understood. A relay before it refuses a fan-out entry
    // carrying one, so it is named only to a relay that lists this.
    this._keyProofFeature = features.includes(KEY_PROOF_FEATURE);
    // A room's peer list is short. Like a peer's peer-info, the relay's is read for its first
    // PEER_INFO_MAX entries: a longer one (a faulty or compromised relay) cannot keep the event loop.
    // Its wake channels name OTHER nodes and come from the relay, so they are hints, never stored
    // (design D1): a wake channel is learned only from its node's own session.
    const peers = Array.isArray(msg.peers) ? msg.peers : [];
    if (peers.length > PEER_INFO_MAX) this._log(`Relay peer list of ${peers.length} entries: reading the first ${PEER_INFO_MAX}`);
    for (const p of peers.slice(0, PEER_INFO_MAX)) {
      // Taken at the door (wire-identity.js): an entry that cannot be named by a string is skipped.
      const id = p && typeof p === 'object' ? wireNodeId(p.nodeId) : null;
      if (!id || p.offline) continue;
      this._handleRelayPeerJoined(id, wireName(p.name), slotKeyOf(p));
    }
  }

  /**
   * The auth frame names the ENGINE VERSION beside the identity. One field, no payload, no
   * confidentiality cost — and it turns "which engines ever reached path X through the relay"
   * from a question nobody can answer after the fact (2026-09-05: whether a pre-0.3.6 engine
   * ever received categories in the clear could not be checked, because auth carried no
   * version) into a query on the relay's log.
   */
  _authFrame(nonce = null) {
    const identity = this._getIdentity();
    const auth = {
      type: 'relay-auth',
      // The lowercase form (MMP §3.1.1; relay-frame.schema.json): a relay refuses any other with 4002.
      nodeId: String(identity.nodeId).toLowerCase(),
      name: this._nodeName,
      engine: ENGINE_VERSION,
      wakeChannel: this._wakeChannel || undefined,
    };
    // The room is DECLARED to the relay (wire note D4, 2026-09-06): the relay partitions delivery
    // and roster by it, sym-swift and sym-py declare theirs, and a Node that stayed silent landed
    // in the unnamed partition where its roommates could not see it. Absent means "default".
    const room = this._getRoom();
    if (typeof room === 'string' && room && room !== 'default') auth.room = room;
    if (this._relayToken) auth.token = this._relayToken;
    // Key proof (core/relay-auth-proof.js): a node holding its identity key asks for a challenge, and
    // answers one with the proof. A relay that does not know `keyProof` authenticates the first frame.
    if (canProve(identity)) {
      auth.keyProof = keyProof.KEY_PROOF;
      if (nonce) {
        auth.publicKey = identity.publicKey;
        auth.proof = keyProof.signProof({ nonce, room: auth.room || 'default', nodeId: auth.nodeId, origin: keyProof.originOf(this._relayUrl) }, identity.privateKey);
      }
    }
    return auth;
  }

  /** @private Send the relay-auth, remembered for relay-reauth. */
  _sendAuth(ws, nonce = null) {
    const frame = this._authFrame(nonce);
    if (frame.keyProof && !nonce) this._proof.requested = true;
    this._authFrameSent = frame;
    this._sendControl(ws, frame);
  }

  /**
   * The relay's challenge (core/relay-auth-proof.js): taken once per connection, only when this node
   * asked for it and before the relay has taken an auth; answered with the proof.
   * @private
   */
  _onChallenge(ws, msg) {
    if (!this._proof.requested || this._proof.nonce || this._phase === 'connected') return;
    const nonce = keyProof.challengeNonce(msg.nonce);
    if (msg.keyProof !== keyProof.KEY_PROOF || !nonce) {
      this._log('Relay challenge refused: not a mmp-relay-auth-v1 challenge with a 32-byte nonce');
      return;
    }
    this._proof.nonce = nonce;
    try { this._sendAuth(ws, nonce); } catch (err) {
      this._log(`Relay key proof could not be made: ${err && err.message}`);
    }
  }

  connect() {
    if (!this._isRunning() || !this._relayUrl) return;
    if (this._identityCollision) return;  // a hard stop (4004 / 4006): never reconnected on its own
    // One socket at a time: a dial while one is open or opening is not a second connection.
    if (this._relayWs && (this._relayWs.readyState === 0 || this._relayWs.readyState === 1)) return;
    if (this._relayReconnectTimer) { clearTimeout(this._relayReconnectTimer); this._relayReconnectTimer = null; }

    let WebSocket;
    try {
      WebSocket = require('ws');
    } catch {
      this._log('Relay requires the "ws" package — npm install ws');
      return;
    }

    // The connection's ceiling (RELAY_CONNECTION_MAX), not the per-message bound: ws closes the whole
    // connection for a message over its maxPayload, so the bound is applied per message below.
    let ws;
    try {
      ws = new WebSocket(this._relayUrl, { maxPayload: RELAY_CONNECTION_MAX });
    } catch (err) {
      // The URL was checked in the constructor; anything ws still refuses is an error of this dial.
      this._log(`Relay error: ${err && err.message}`);
      this._lastError = { message: String(err && err.message).slice(0, 200), at: Date.now() };
      this._scheduleReconnect();
      return;
    }
    this._relayWs = ws;
    this._proof = { requested: false, nonce: null, proven: false };   // per connection
    this._authFrameSent = null;
    this._proofRefusal = null;
    const connection = this._connections = (this._connections || 0) + 1;   // this connection, for lanes
    this._attempts++;
    this._nextRetryAt = null;
    // A retry inside a refusal episode is part of the episode (see _scheduleReconnect): the phase
    // stays `refused` until the relay admits us (relay-peers ends the episode). Relabelling it for
    // the length of each dial made state() and describe() report a refused node as connecting.
    if (!this._refused) this._setPhase('connecting');

    ws.on('open', () => {
      if (this._relayWs !== ws) return;
      this._log(`Relay connected: ${this._relayUrl}`);
      if (!this._refused) this._setPhase('authenticating');

      // Keepalive + liveness detection.
      // Send pong every 20s to keep Render from dropping idle connections.
      // If no message received from relay in 60s, the connection is zombie
      // (relay restarted behind TLS proxy) — force reconnect.
      this._lastRelayMessage = Date.now();
      if (this._relayPingTimer) clearInterval(this._relayPingTimer);
      this._relayPingTimer = setInterval(() => {
        if (ws.readyState !== 1) return;
        if (Date.now() - this._lastRelayMessage > 60000) {
          // terminate(), not close() (R3-15): a connection that has gone quiet will not answer a
          // closing handshake either, and close() waits for one (30 s in ws) before 'close' fires.
          this._log('Relay liveness timeout — forcing reconnect');
          try { ws.terminate(); } catch { /* already gone */ }
          return;
        }
        this._sendControl(ws, { type: 'relay-pong' });
      }, 20000);

      this._sendAuth(ws);
    });

    ws.on('message', (data) => {
      if (this._relayWs !== ws) return;
      // Any message is the relay alive, whether or not it is taken.
      this._lastRelayMessage = Date.now();
      // MMP §4.1's frame bound applies on the relay path too, where frames come from parties
      // that are not the socket peer. The envelope (from, fromName) gets a small allowance. A message
      // over it is dropped ON ITS OWN and the connection stays up (R3-1, R3-2); only the relay's
      // roster is read past it, up to the connection's ceiling (see RELAY_CONNECTION_MAX).
      let text;
      if (data.length > MESSAGE_MAX) {
        text = data.toString('utf8', 0, 64);
        if (!ROSTER_PREFIX.test(text)) {
          this._oversizeDropped++;
          const now = Date.now();
          if (now - (this._oversizeSaidAt || 0) >= 60_000) {
            this._oversizeSaidAt = now;
            this._log(`Relay message dropped: ${data.length} bytes exceeds the ${MESSAGE_MAX}-byte frame bound (${this._oversizeDropped} dropped so far; the connection stays up)`);
          }
          return;
        }
      }
      // Nesting is bounded before parsing (core/json-depth.js): a message nested deeper is not a
      // frame and is dropped unparsed, as malformed JSON is. Until 0.13.17 a payload some 10,000
      // levels deep (24 KB on the wire) parsed, and serialising it to measure it, below, recursed
      // once per level and threw a RangeError out of this callback, which is uncaught.
      let msg;
      try {
        text = data.toString();
        if (nestedTooDeep(text)) return;
        msg = JSON.parse(text);
      } catch { return; }
      // MMP §4.1: a frame without a string `type` is silently discarded. Relay
      // envelopes carry `from` + `payload` instead, so accept those as well.
      if (!msg || typeof msg !== 'object') return;
      // The roster is the one message taken past the bound; anything else that long is not.
      if (data.length > MESSAGE_MAX && msg.type !== 'relay-peers') { this._oversizeDropped++; return; }

      // Everything a message leads to runs inside the guard (0.13.17): nothing off this socket can
      // throw out of the socket's callback, which is uncaught.
      this._guard(msg, () => this._takeRelayMessage(ws, msg, connection));
    });

    ws.on('close', (code, reason) => {
      const reasonStr = reason && reason.toString ? reason.toString() : '';
      // A socket this connection no longer holds (destroy() let it go, or a newer dial replaced it)
      // ends with nothing scheduled: destroy() already cleaned up, and only the current socket's
      // close may reconnect.
      if (this._relayWs !== ws) return;
      this._log(`Relay disconnected (code ${code}${reasonStr ? `: ${reasonStr}` : ''})`);
      this._relayWs = null;
      this._lastClose = { code, reason: reasonStr, at: Date.now() };
      if (this._relayPingTimer) { clearInterval(this._relayPingTimer); this._relayPingTimer = null; }

      // Section 4.6 + 5.5: every relay session ends with the connection it was bound to; a peer
      // reachable over the LAN keeps that session. So does what this relay advertised
      // (relay-peers.features): the next relay says its own. What the pacer still held was never
      // written to the socket: a frame sent with a `meta` (a record the node dispatched) goes back to
      // the node, which holds it for the peer's next session (R3-4); the rest is dropped.
      this._present.clear();
      this._slots.clear();
      if (this._ambiguous) this._ambiguous.clear();
      this._fanout = null;
      this._keyProofFeature = false;
      const unflushed = this._takeUnflushed();
      this._control.length = 0;
      if (this._flushTimer) { clearTimeout(this._flushTimer); this._flushTimer = null; }
      try { this._onDisconnected(); } catch (err) { this._log(`Relay disconnect handling failed: ${err && err.message}`); }
      this._giveBackUnflushed(unflushed);

      // MMP identity invariant: nodeId is bound to a keypair. A 4004 or 4006 says another connection
      // holds this node's slot. On a connection that proved its key only another holder of the key can
      // have done it (the newest proof wins, once); on one that did not, anyone with the token could.
      // Either way the client stops (MMP §4.4.7) and says which it was (HARD_STOPS).
      const hard = HARD_STOPS[code];
      if (hard) {
        this._hardStop(code, hard, reasonStr);
        return;
      }

      // 4003 is deterministic: the token this process holds is not in the relay's channel
      // table, and nothing this process does changes either side — the token comes from
      // its environment, the table from the operator's. Retried at the normal cadence, a
      // refused node wrote one rejection every ~23 s into the relay's log for as long as it
      // lived and NOTHING into its host's, so nobody could tell which machine was knocking
      // or why. It is not a hard stop like 4004 (a retry harms no other node, and the one
      // production open-mode incident began with a channel table being edited live), so:
      // say it once, loudly, with the fix; tell the host; keep knocking at a cadence a log
      // can bear.
      // A key proof the relay refused for a reason a retry cannot fix (origin-mismatch, invalid,
      // no-challenge): a non-retryable auth refusal, like 4003 — said once, loudly, with the ORIGIN
      // this node signed for, and retried only at the slow cadence. Never answered by authenticating
      // without a proof: a relay that challenged is a relay that verifies, and dropping the proof
      // there would be a downgrade.
      const proofRefusal = this._proofRefusal;
      this._proofRefusal = null;
      if (code === 4002 && proofRefusal) {
        const origin = keyProof.originOf(this._relayUrl);
        const why = `key proof refused (${proofRefusal.reason}): ${proofRefusal.message}`;
        if (!this._refused) this._refused = { code, kind: 'key-proof', reason: why, origin, at: Date.now() };
        this._setPhase('refused');
        if (!this._authRefused) {
          this._authRefused = true;
          this._log(`FATAL: relay ${this._relayUrl} refused ${this._nodeName}'s key proof (${proofRefusal.reason}). ` +
            `This node signed for the origin ${origin}` +
            (proofRefusal.reason === 'origin-mismatch' ? ', which the relay does not answer to: dial the relay at a URL its operator lists (SYM_RELAY_ORIGINS), or have the operator add this one' : '') +
            `. Not falling back to authenticating without a proof. Retrying every ${Math.round(this._authRefusedRetryMs / 60000)} min, not sooner.`);
          if (this._onAuthRefused) {
            try { this._onAuthRefused({ relayUrl: this._relayUrl, name: this._nodeName, code, reason: why, kind: 'key-proof', proofReason: proofRefusal.reason, origin }); } catch (err) {
              this._log(`onAuthRefused callback threw: ${err.message}`);
            }
          }
        }
        this._scheduleReconnect(this._authRefusedRetryMs);
        return;
      }

      if (code === 4003) {
        const why = reasonStr || 'Invalid token';
        if (!this._refused) this._refused = { code, reason: why, at: Date.now() };
        this._setPhase('refused');
        if (!this._authRefused) {
          this._authRefused = true;
          this._log(`FATAL: relay ${this._relayUrl} refused ${this._nodeName} (${code}: ${why}). ` +
            `The token this process presents is not one the relay's operator configured — fix SYM_RELAY_TOKEN ` +
            `(or the invite) and restart. Retrying every ${Math.round(this._authRefusedRetryMs / 60000)} min, not sooner.`);
          if (this._onAuthRefused) {
            try { this._onAuthRefused({ relayUrl: this._relayUrl, name: this._nodeName, code, reason: why }); } catch (err) {
              this._log(`onAuthRefused callback threw: ${err.message}`);
            }
          }
        }
        this._scheduleReconnect(this._authRefusedRetryMs);
        return;
      }

      this._scheduleReconnect();
    });

    ws.on('error', (err) => {
      this._log(`Relay error: ${err.message}`);
      this._lastError = { message: err.message, at: Date.now() };
    });
  }

  /**
   * A hard stop (4004 / 4006): recorded, said once loudly with its cause, told to the host once, and
   * never reconnected on its own (HARD_STOPS).
   * @private
   */
  _hardStop(code, hard, reasonStr) {
    const id = this._getIdentity();
    const first = !this._identityCollision;
    // Whether THIS connection had proved its key (the relay took the proof): only then is the cause known.
    const relayVerifiesKeys = !!this._proof.proven;
    const reason = reasonStr.slice(0, 200);
    this._identityCollision = true;
    this._stopped = { code, kind: hard.kind, reason, at: Date.now(), relayVerifiesKeys };
    this._nextRetryAt = null;
    this._setPhase(hard.phase);
    if (!first) return;
    const what = code === 4004 ? 'replaced this connection' : 'refused this connection as a duplicate of another live one';
    this._log(`FATAL: relay ${this._relayUrl} ${what} (${code}${reason ? `: ${reason}` : ''}; nodeId=${id.nodeId}, name=${this._nodeName}): ` +
      `${hardStopCause(relayVerifiesKeys)}. Not reconnecting.`);
    if (this._onIdentityCollision) {
      try { this._onIdentityCollision({ nodeId: id.nodeId, name: this._nodeName, code, kind: hard.kind, reason, relayVerifiesKeys }); } catch (err) {
        this._log(`onIdentityCollision callback threw: ${err.message}`);
      }
    }
  }

  /**
   * Everything the pacer still holds, taken out of it: the frames sent with a `meta`, for the node.
   * @private
   */
  _takeUnflushed() {
    const items = this._queue.drain();
    const out = [];
    for (const it of items) if (it.meta) out.push({ to: it.to, bytes: it.bytes, meta: it.meta });
    return out;
  }

  /** @private The frames _takeUnflushed took, handed to the node (never thrown out of a callback). */
  _giveBackUnflushed(items) {
    if (!items.length || !this._onUnflushed) return;
    try { this._onUnflushed(items); } catch (err) { this._log(`Relay: handing back ${items.length} unsent frame(s) failed: ${err && err.message}`); }
  }

  /**
   * One parsed message off the relay socket (always called through the guard). The relay's own
   * frames are taken field by field as what they must be; an envelope's payload is handed to the
   * node only as bytes for the session bound to its `from`.
   * @private
   */
  _takeRelayMessage(ws, msg, connection) {
    // A peer's nodeId and name reach us here as the JOINER put them in its relay-auth (the relay
    // forwards them as given), so they are taken as what they must be before anything keeps or
    // prints them (see wire-identity.js): a peer that cannot be named by a string is not added.
    if (msg.type === 'relay-peer-joined') {
      const id = wireNodeId(msg.nodeId);
      if (id) this._handleRelayPeerJoined(id, wireName(msg.name), slotKeyOf(msg));
    } else if (msg.type === 'relay-peer-left') {
      const id = wireNodeId(msg.nodeId);
      if (id) this._handleRelayPeerLeft(id, wireName(msg.name), slotKeyOf(msg));
    } else if (msg.type === 'relay-peers') {
      this._handleRelayPeers(msg);
    } else if (msg.type === 'relay-challenge') {
      this._onChallenge(ws, msg);
    } else if (msg.type === 'relay-ping') {
      this._sendControl(ws, { type: 'relay-pong' });
    } else if (msg.type === 'relay-reauth') {
      // Server lost our registration (e.g. relay restarted while TCP survived).
      // Re-send auth to re-register without dropping the connection: the frame this connection last
      // sent, its proof (over this connection's challenge) included.
      this._log('Relay requested re-auth — re-sending identity');
      this._sendControl(ws, this._authFrameSent || this._authFrame());
    } else if (msg.type === 'relay-error') {
      // { kind, code, message } as sym-relay sends them; each is printed only when it is what it
      // should be, and nothing else in the frame is turned into text (0.13.17).
      const kind = typeof msg.kind === 'string' ? ` ${msg.kind.slice(0, 40)}` : '';
      const code = Number.isInteger(msg.code) ? ` ${msg.code}` : '';
      const text = typeof msg.message === 'string' ? msg.message.slice(0, 500) : '(no message)';
      this._log(`Relay error${kind}${code}: ${text}`);
      // A refused key proof (sym-relay 0.8.0, kind `key-proof`) is held for the close that follows, so
      // a refusal retrying cannot fix (an origin the relay does not answer to, a proof that does not
      // verify) is not looped on. `rate` is the one a retry can fix: it comes as 4008, an ordinary close.
      if (msg.kind === 'key-proof' && typeof msg.reason === 'string' && msg.reason !== 'rate') {
        this._proofRefusal = { reason: msg.reason.slice(0, 40), message: text };
      }
    } else if (wireNodeId(msg.from) && msg.payload && typeof msg.payload === 'object'
               && typeof msg.payload.type === 'string') {
      // The whole message was bounded above (MAX_FRAME_SIZE + the envelope allowance, and its
      // nesting); the payload is a part of it. A relay `from` is unproven (§4.4.1): the node takes
      // the payload only as bytes for the session bound to that `from`. `fromKey`, when the relay
      // stamped one (0.8.0), is the key the sender's slot proved: the node lanes by (from, fromKey)
      // and drops a frame whose key is not the one it binds for that nodeId.
      const fromKey = typeof msg.fromKey === 'string' && CANONICAL_KEY_B64URL.test(msg.fromKey) ? msg.fromKey : null;
      this._onEnvelope(msg.from, wireName(msg.fromName), msg.payload, fromKey, connection);
    }
  }

  /**
   * The slot of `nodeId` this node takes as that peer (a relay that verifies keys lists one per key
   * that proved the nodeId, and one for a legacy claim): the slot proven for the key this node binds
   * to the nodeId; else the legacy claim's (it may be the bound peer on an older engine); else, with
   * no binding, the newest proven one. A slot proven for ANOTHER key than the bound one is never the
   * peer: it is ignored, so an impostor that proved its own key under a member's nodeId is no
   * candidate and its departure ends nothing. Null when no slot is the peer.
   * @private
   */
  _preferredSlot(nodeId) {
    const slots = this._slots.get(nodeId);
    if (!slots || !slots.size) return null;
    let bound;
    try { bound = this._keyOf(nodeId); } catch { bound = undefined; }
    if (typeof bound === 'string' && bound) return slots.get(bound) || slots.get('') || null;
    // No binding. The node never picks one proven key over another by who announced first (that would
    // be TOFU on the relay's say-so): one proven key is first proven use, several is an identity
    // ambiguity (_noteAmbiguity) that only a pin, an anchor certification, or every rival leaving
    // resolves. A lone legacy claim (no proven key at all) is still a candidate, as before 0.8.0.
    const provenKeys = [];
    let proven = null, legacy = null;
    for (const [k, slot] of slots) { if (slot.proven) { provenKeys.push(k); proven = slot; } else legacy = slot; }
    if (provenKeys.length >= 2) { this._noteAmbiguity(nodeId, provenKeys); return null; }
    this._clearAmbiguity(nodeId);
    return proven || legacy || null;
  }

  /** A nodeId with no binding is proven under more than one key: reported once, until it resolves. @private */
  _noteAmbiguity(nodeId, keys) {
    if (!this._ambiguous) this._ambiguous = new Map();
    const sorted = [...keys].sort();
    const prev = this._ambiguous.get(nodeId);
    if (prev && prev.length === sorted.length && prev.every((k, i) => k === sorted[i])) return;
    this._ambiguous.set(nodeId, sorted);
    try { this._onIdentityAmbiguous(nodeId, sorted); } catch (err) { this._log(`Relay identity-ambiguity handling failed: ${err && err.message}`); }
  }

  /** @private The ambiguity on `nodeId` is gone (it resolved, or the nodeId left). */
  _clearAmbiguity(nodeId) {
    if (this._ambiguous && this._ambiguous.delete(nodeId)) {
      try { this._onIdentityResolved(nodeId); } catch (err) { this._log(`Relay identity-ambiguity handling failed: ${err && err.message}`); }
    }
  }

  /** The nodeIds the relay presents under more than one proven key, none of them bound here. */
  get ambiguous() { return this._ambiguous ? new Map([...this._ambiguous].map(([k, v]) => [k, [...v]])) : new Map(); }

  /**
   * The key to name in `toKey` for a directed frame to `nodeId`, or null: the key this node binds to
   * it, when the relay understands `toKey` and lists a slot proven for exactly that key. Otherwise the
   * frame goes to every slot of the nodeId (sealed end to end, so a slot that cannot open it gains
   * nothing), which is also how it reaches a bound peer on an engine that proves no key.
   * @private
   */
  _toKeyFor(nodeId) {
    if (!this._keyProofFeature) return null;
    const slots = this._slots.get(nodeId);
    if (!slots) return null;
    let bound;
    try { bound = this._keyOf(nodeId); } catch { bound = undefined; }
    return typeof bound === 'string' && bound && slots.has(bound) ? bound : null;
  }

  _handleRelayPeerJoined(peerId, peerName, slotKey = '') {
    const identity = this._getIdentity();
    if (!peerId || peerId === identity.nodeId) return;
    if (!this._present.has(peerId) && !this._slots.has(peerId) && this._slots.size >= this._maxAnnounced && !this._isKnown(peerId)) {
      // A candidate costs a handshake attempt: past the bound, an announcement for a nodeId not
      // already held is ignored (said once, counted in state().announcementsIgnored). One that
      // leaves (relay-peer-left, or the relay link closing) frees its place.
      this._announcementsIgnored++;
      if (this._announcementsIgnored === 1) this._log(`Relay: ${this._maxAnnounced} announced peers held; announcements for more are ignored (counted in relay state)`);
      return;
    }
    let slots = this._slots.get(peerId);
    if (!slots) { slots = new Map(); this._slots.set(peerId, slots); }
    if (!slots.has(slotKey) && slots.size >= MAX_SLOTS_PER_NODE) {
      this._slotsIgnored++;
      if (this._slotsIgnored === 1) this._log(`Relay: ${MAX_SLOTS_PER_NODE} keys already listed for one nodeId; announcements of more are ignored (counted in relay state)`);
      return;
    }
    // Re-inserted, so the newest announcement of a slot is last (_preferredSlot's "newest proven").
    slots.delete(slotKey);
    const slot = { name: peerName, key: slotKey || null, proven: !!slotKey };
    slots.set(slotKey, slot);
    const preferred = this._preferredSlot(peerId);
    if (preferred !== slot) {
      // Another slot is this nodeId's peer (or none is: a key other than the bound one). Nothing
      // changes for the peer; a slot proven for a key this node does not bind is never a candidate.
      if (!preferred) this._present.delete(peerId);
      return;
    }
    this._present.set(peerId, peerName);
    try { this._onPeerPresent(peerId, peerName); } catch (err) { this._log(`Relay peer-joined handling failed: ${err && err.message}`); }
  }

  _handleRelayPeerLeft(peerId, peerName, slotKey = '') {
    const slots = this._slots.get(peerId);
    const before = slots ? this._preferredSlot(peerId) : null;
    if (slots) {
      slots.delete(slotKey);
      if (!slots.size) { this._slots.delete(peerId); this._clearAmbiguity(peerId); }
    }
    const after = this._slots.has(peerId) ? this._preferredSlot(peerId) : null;
    // The peer this node took for the nodeId is still there: another slot left (an impostor's key, a
    // legacy claim beside a proven peer), and nothing ends.
    if (before && after === before) return;
    this._present.delete(peerId);
    try { this._onPeerGone(peerId, peerName); } catch (err) { this._log(`Relay peer-left error for ${peerName || peerId}: ${err && err.message}`); }
    if (after) {
      // The slot taken for the peer left and another remains (a legacy claim behind a proven peer):
      // that one is the candidate now, as a fresh announcement.
      this._present.set(peerId, after.name);
      try { this._onPeerPresent(peerId, after.name); } catch (err) { this._log(`Relay peer-joined handling failed: ${err && err.message}`); }
    }
  }

  /**
   * A transport for one session bound to the relay `from`/`to` = `nodeId` (design D2): it sends
   * envelopes addressed to that node through the pacer, and is closed by its session. It never
   * receives: the relay connection hands envelopes to the node, which routes them by `from`.
   */
  transportFor(nodeId) {
    const relay = this;
    return {
      _closed: false,
      /** `meta` (optional) rides with the frame through the pacer: see sendTo. */
      trySend(frame, meta) {
        if (this._closed) return { ok: false, reason: SEND_FAILURE.NOT_CONNECTED };
        return relay.sendTo(nodeId, frame, meta);
      },
      send(frame) { return this.trySend(frame).ok; },
      /** Bytes waiting in the pacer for this peer (an outbound byte budget). */
      pendingBytes() { return relay._queue.bytesFor(nodeId); },
      /** Whether `bytes` more for this peer fit in the pacer with half its bounds to spare. */
      hasRoom(bytes) { return relay._queue.hasRoom(nodeId, bytes); },
      close() { this._closed = true; },
      destroy() { this._closed = true; },
    };
  }

  /**
   * The frames waiting for `to` that were sent with a `meta` `pred` picks, taken out of the pacer (a
   * session that ended: what was sealed for it can only be offered again, sealed for the next one).
   * @returns {Array<{ to: string, bytes: number, meta: object }>}
   */
  takeQueued(to, pred) {
    return this._queue.removeWhere(to, (it) => !!it.meta && pred(it.meta)).map((it) => ({ to: it.to, bytes: it.bytes, meta: it.meta }));
  }

  /**
   * Send one payload to `to` through the pacer. Sends made in the same turn of the event loop are
   * flushed together, so a broadcast's per-session frames go out as fan-out envelopes when the relay
   * supports them, and paced under its rate when it does not.
   * @param {string} to
   * @param {object} payload
   * @param {object} [meta] - opaque to the relay: handed to onFlushed once the frame is written to the
   *   socket, or back through onUnflushed if the connection closes first (R3-4)
   * @returns {{ ok: boolean, reason?: string, bytes?: number }}
   */
  sendTo(to, payload, meta) {
    const ws = this._relayWs;
    if (!ws || ws.readyState !== 1) return { ok: false, reason: SEND_FAILURE.NOT_CONNECTED };
    // `toKey` (sym-relay 0.8.0): the frame goes only to the slot proven for the key this node binds to
    // `to` (_toKeyFor). Decided now, for this connection: a frame never outlives its connection.
    const toKey = this._toKeyFor(to);
    let data;
    try { data = JSON.stringify(toKey ? { to, toKey, payload } : { to, payload }); } catch { return { ok: false, reason: SEND_FAILURE.WRITE_FAILED }; }
    const bytes = Buffer.byteLength(data, 'utf8');
    // MMP §4.1: senders MUST NOT produce frames over MAX_FRAME_SIZE; the relay would close the whole
    // shared connection (1009) rather than drop one frame.
    if (bytes > MAX_FRAME_SIZE) return { ok: false, reason: SEND_FAILURE.TOO_LARGE, bytes };
    const refused = this._queue.push(classOf(payload), { to, toKey, payload, data, bytes, meta: meta || null });
    if (refused) return { ok: false, reason: refused, bytes };
    this._scheduleFlush();
    return { ok: true, bytes };
  }

  _scheduleFlush() {
    if (this._flushScheduled || this._flushTimer) return;
    this._flushScheduled = true;
    setImmediate(() => { this._flushScheduled = false; this._flush(); });
  }

  _refill(now = Date.now()) {
    const b = this._bucket;
    const elapsed = now - b.at;
    if (elapsed > 0) b.tokens = Math.min(this._burst, b.tokens + (elapsed * this._rate) / 1000);
    b.at = now;
    return b;
  }

  /** Send what the bucket allows: the relay's own frames first, then fan-out envelopes when
   *  advertised, else one frame per payload. */
  _flush() {
    const ws = this._relayWs;
    if (!ws || ws.readyState !== 1) return;
    while (this._control.length) {
      const b = this._refill();
      if (b.tokens < 1) { this._waitForToken(b); return; }
      b.tokens -= 1;
      try { ws.send(this._control.shift().data); } catch (err) { this._log(`Relay send failed: ${err && err.message}`); }
    }
    while (this._queue.length) {
      const b = this._refill();
      if (b.tokens < 1) { this._waitForToken(b); return; }
      let data;
      let taken;
      if (this._fanout && this._queue.length > 1) {
        // Frames in the queue's own order (class, then destinations in turn), up to FANOUT_MAX and the
        // frame bound, and never a recipient twice in one envelope, so per-recipient order holds.
        const batch = [];
        const to = new Set();
        let size = 16;
        while (batch.length < this._fanout.max) {
          const q = this._queue.take(to, MAX_FRAME_SIZE - size - 1);
          if (!q) break;
          batch.push(q);
          to.add(q.to);
          size += q.bytes + 1;
        }
        if (!batch.length) batch.push(this._queue.take());
        data = batch.length === 1 ? batch[0].data : JSON.stringify({ fanout: batch.map((q) => (q.toKey ? { to: q.to, toKey: q.toKey, payload: q.payload } : { to: q.to, payload: q.payload })) });
        if (batch.length > 1) this._sentFanout++;
        taken = batch;
      } else {
        taken = [this._queue.take()];
        data = taken[0].data;
      }
      b.tokens -= 1;
      // A frame sent with a `meta` is FLUSHED when the socket has written it (the send's callback),
      // not when ws took it: until then it sits in a buffer this process drops with the socket. One
      // whose write fails (the connection closed first) goes back to the node like one the pacer
      // still held. What the kernel took and the network lost is the residual (see node.js).
      const metas = taken.filter((it) => it.meta);
      const done = metas.length ? (err) => {
        if (err) { this._giveBackUnflushed(metas.map((it) => ({ to: it.to, bytes: it.bytes, meta: it.meta }))); return; }
        if (!this._onFlushed) return;
        for (const it of metas) {
          try { this._onFlushed(it.meta); } catch { /* the frame went; the node's bookkeeping never stops the pacer */ }
        }
      } : undefined;
      try { ws.send(data, done); this._sentFrames++; } catch (err) {
        this._log(`Relay send failed: ${err && err.message}`);
        if (done) done(err);
        continue;
      }
    }
  }

  /** @private Flush again once the bucket holds a token. */
  _waitForToken(b) {
    if (this._flushTimer) return;
    const wait = Math.ceil(((1 - b.tokens) * 1000) / this._rate);
    this._flushTimer = setTimeout(() => { this._flushTimer = null; this._flush(); }, Math.max(wait, 5));
    if (this._flushTimer.unref) this._flushTimer.unref();
  }

  /**
   * A frame of the relay protocol itself (auth, pong): ahead of every other frame, but inside the
   * bucket (MMP 2.0 update 1, §19.1's headroom sentence): sent at once while the bucket holds a token,
   * and otherwise as soon as it does. It went out at once whatever the bucket held, so a full flush and
   * a pong were 201 frames in a second against a floor of 200.
   */
  _sendControl(ws, frame) {
    if (ws !== this._relayWs) return;
    // Bounded: a pong already waiting answers the relay's liveness check as well as a second would, and
    // the queue holds at most CONTROL_QUEUE_MAX frames (the oldest pong goes first), however long the
    // bucket stays empty.
    if (frame.type === 'relay-pong' && this._control.some((c) => c.pong)) return;
    this._control.push({ data: JSON.stringify(frame), pong: frame.type === 'relay-pong' });
    while (this._control.length > CONTROL_QUEUE_MAX) {
      const i = this._control.findIndex((c) => c.pong);
      this._control.splice(i === -1 ? 0 : i, 1);
    }
    this._flush();
  }

  /**
   * @param {number} [fixedDelayMs] — use this delay instead of the exponential backoff and
   *   leave the backoff state untouched (the slow retry after an auth refusal).
   */
  _scheduleReconnect(fixedDelayMs) {
    if (!this._isRunning() || !this._relayUrl) return;

    const base = fixedDelayMs || this._relayReconnectDelay;
    const jitter = base * 0.1 * Math.random();
    const delay = base + jitter;

    this._log(`Relay reconnecting in ${Math.round(delay / 1000)}s`);
    this._nextRetryAt = Date.now() + delay;
    // A refusal keeps its phase (the slow retry is part of the episode); everything else
    // is "reconnecting" until the next outcome.
    if (this._phase !== 'refused') this._setPhase('reconnecting');
    if (this._relayReconnectTimer) clearTimeout(this._relayReconnectTimer);
    this._relayReconnectTimer = setTimeout(() => { this._relayReconnectTimer = null; this.connect(); }, delay);

    if (!fixedDelayMs) this._relayReconnectDelay = Math.min(this._relayReconnectDelay * 2, 30000);
  }

  /**
   * Clean up relay resources on stop. What the pacer may still send goes first (R3-13: the node closes
   * its sessions before this, and each confirmed relay session's sealed 1010 notice waits in the
   * pacer): one last flush, inside the bucket, then the socket closes. What is still queued after it,
   * and was sent with a `meta`, goes back to the node (onUnflushed), which says it was not sent.
   */
  destroy() {
    if (this._relayReconnectTimer) { clearTimeout(this._relayReconnectTimer); this._relayReconnectTimer = null; }
    if (this._relayPingTimer) { clearInterval(this._relayPingTimer); this._relayPingTimer = null; }
    if (this._flushTimer) { clearTimeout(this._flushTimer); this._flushTimer = null; }
    try { this._flush(); } catch { /* stopping either way */ }
    if (this._flushTimer) { clearTimeout(this._flushTimer); this._flushTimer = null; }

    this._present.clear();
    this._slots.clear();
    if (this._ambiguous) this._ambiguous.clear();
    const unflushed = this._takeUnflushed();
    this._control.length = 0;

    const ws = this._relayWs;
    this._relayWs = null;
    if (ws) {
      // A socket still opening has nothing to close politely; one that is open closes after what was sent.
      try { if (ws.readyState === 0) ws.terminate(); else ws.close(1000, 'node stopped'); } catch { /* already gone */ }
    }
    this._nextRetryAt = null;
    // A hard stop outlives destroy(): the identity fact behind it does not change with a restart of
    // this node object (state().stopped keeps the reason). So does a disabled relay setting.
    this._setPhase(this._stopped ? HARD_STOPS[this._stopped.code].phase : this._disabled ? 'disabled' : (this._relayUrl ? 'idle' : 'off'));
    this._giveBackUnflushed(unflushed);
  }
}

module.exports = {
  RelayConnection, RELAY_RATE_PER_SECOND, RELAY_BURST, FANOUT_FEATURE, FANOUT_MAX, HARD_STOPS, FairQueue, CLASS2_MAX,
  RELAY_CONNECTION_MAX, MESSAGE_MAX, KEY_PROOF_FEATURE, MAX_SLOTS_PER_NODE, isRelayUrl, normalizeRelayUrl, relayUrlProblem, hardStopCause,
};
