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
 * Whether `url` is a relay URL this client can dial: an absolute ws:// or wss:// URL with a host.
 * Checked where a relay URL comes in (the node's options, an invite), so a URL `ws` cannot parse
 * never reaches start() (R3-11: it threw there, after the node had half started).
 * @param {*} url
 * @returns {boolean}
 */
function isRelayUrl(url) {
  if (typeof url !== 'string' || !url || url.length > 2048) return false;
  let u;
  try { u = new URL(url); } catch { return false; }
  return (u.protocol === 'ws:' || u.protocol === 'wss:') && !!u.hostname;
}

/** Throw EBADRELAY unless `url` is absent or a relay URL (isRelayUrl). */
function assertRelayUrl(url, where = 'relay') {
  if (url === null || url === undefined || url === '') return;
  if (isRelayUrl(url)) return;
  const e = new TypeError(`${where}: ${JSON.stringify(String(url).slice(0, 120))} is not a ws:// or wss:// URL`);
  e.code = 'EBADRELAY';
  throw e;
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
 * The IDENTITY CLOSES: the relay says another connection holds this nodeId.
 *   4004 replaced — another connection authenticated as this nodeId and the relay took it;
 *   4006 duplicate rejected — this node is the newcomer and the existing holder is younger than 5 s.
 *
 * UNTIL 0.14.3 BOTH WERE PERMANENT STOPS (MMP §4.4.7: "MUST NOT automatically reconnect" after 4004,
 * "SHOULD NOT" after 4006), and that let anyone holding the channel token switch a member off for
 * good (R3-3): relay-auth carries no key proof, so a token holder that read a member's nodeId from
 * the roster could claim it once, leave, and the member never came back. Now an identity close is
 * retried on a LONG backoff (identityRetryMs, 1 min, doubling to 30 min), said loudly every time, with
 * a PING-PONG DETECTOR: PINGPONG_CLOSES identity closes inside PINGPONG_WINDOW_MS mean two live
 * processes hold this identity and replace each other, which is said as that, told to the host
 * (onIdentityCollision with pingPong: true) and retried only at the longest backoff. A relay-side key
 * proof would end the impostor case properly; it needs a spec ruling and is not implemented here.
 * `identityRetry: false` keeps the §4.4.7 behaviour (no reconnect after an identity close).
 *
 * Every other close is reconnected with backoff (MMP 2.0 update 1, §4.4.9): 4005, 4008, and the
 * RFC 6455 closes 1001, 1009, 1011 and 1013 by the table, and 4007 too. 4007 belongs to relay-auth
 * key proof (draft PR meshcognition-website#20), which is deferred past 0.14.0 and not in MMP: its
 * review found a lockout in "MUST NOT reconnect after 4007", so it is an ordinary close here.
 */
const IDENTITY_CLOSES = {
  4004: { phase: 'collision', kind: 'replaced' },
  4006: { phase: 'duplicate-rejected', kind: 'duplicate-rejected' },
};
/** @deprecated the name before 0.14.3, when these closes stopped the client for good. */
const HARD_STOPS = IDENTITY_CLOSES;
const IDENTITY_RETRY_MS = 60_000;
const IDENTITY_RETRY_MAX_MS = 30 * 60_000;
const PINGPONG_WINDOW_MS = 30 * 60_000;
const PINGPONG_CLOSES = 3;
const STOP_PHASES = Object.values(IDENTITY_CLOSES).map((h) => h.phase);
const TERMINAL_PHASES = ['connected', 'refused', ...STOP_PHASES, 'off'];
const FANOUT_MAX = 64;
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
   * @param {function} [opts.onIdentityCollision] — ({nodeId, name, code, kind, reason, pingPong,
   *                   retryInMs}) => void — called at the first identity close (4004 / 4006) of an
   *                   episode, and again when the ping-pong detector finds two processes replacing
   *                   each other (pingPong: true). The relay layer has logged it and retries on the
   *                   long backoff (IDENTITY_CLOSES); a single close is no proof of a second process
   *                   (relay-auth carries no key proof), so a host that exits on it lets any token
   *                   holder stop it: exit on `pingPong` if at all.
   * @param {boolean}  [opts.identityRetry=true] — false: no reconnect after an identity close
   *                   (MMP §4.4.7 as written).
   * @param {number}   [opts.identityRetryMs] — the first retry after an identity close (1 min).
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
    assertRelayUrl(opts.relayUrl, 'RelayConnection');
    this._relayUrl = opts.relayUrl;
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
    this._identityCollision = false;   // inside an identity-close episode (4004 / 4006), until an auth succeeds
    this._stopped = null;              // the last identity close { code, kind, reason, at, closes, pingPong }
    this._identityRetry = opts.identityRetry !== false;
    this._identityRetryMs = Number.isFinite(opts.identityRetryMs) && opts.identityRetryMs > 0 ? opts.identityRetryMs : IDENTITY_RETRY_MS;
    this._identityCloses = [];         // when each identity close came, inside PINGPONG_WINDOW_MS
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
    this._phase = this._relayUrl ? 'idle' : 'off';
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
   * phase: off | idle | connecting | authenticating | connected | reconnecting | refused | collision (4004)
   *        | duplicate-rejected (4006) — the last two are identity closes, retried on the long backoff
   *        (IDENTITY_CLOSES); `stopped` is the last one ({ code, kind, reason, at, closes, pingPong }),
   *        kept under its pre-0.14.3 name.
   */
  state() {
    return {
      url: this._relayUrl || null,
      phase: this._phase,
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
      case 'idle': return `configured: ${s.url} (not started)`;
      case 'connecting': return `connecting to ${s.url} (attempt ${s.attempts})`;
      case 'authenticating': return `authenticating with ${s.url} (attempt ${s.attempts})`;
      case 'connected': return `connected to ${s.url} for ${ago(s.since)}, ${s.peers} relay peer(s)`;
      case 'refused':
        return `REFUSED by ${s.url} (${s.refused.code}: ${s.refused.reason}) since ${ago(s.refused.at)} ago — ` +
          `the token this session presents is not accepted by that relay. Fix: mint a token with sym_invite_create ` +
          `or get the team's invite, then sym_join_room with it (or fix SYM_RELAY_TOKEN and restart). ` +
          `Retrying every ${Math.round(this._authRefusedRetryMs / 60000)} min meanwhile.`;
      case 'collision':
      case 'duplicate-rejected': {
        const st = s.stopped || {};
        const what = s.phase === 'collision'
          ? `${s.url} replaced this connection with another that claims this identity (4004)`
          : `${s.url} refused this connection because another live connection claims this identity (4006)`;
        const retry = s.nextRetryAt ? `Retrying in ${inS(s.nextRetryAt)}` : 'Not reconnecting (identityRetry is off)';
        if (st.pingPong) {
          return `PING-PONG: ${what}, ${st.closes} times in ${Math.round(PINGPONG_WINDOW_MS / 60000)} min: two live processes ` +
            `hold this identity and replace each other. Stop one of them. ${retry}.`;
        }
        return `IDENTITY CLOSE: ${what}. Another process may hold this keypair, or a holder of the relay token ` +
          `claimed this nodeId (relay-auth carries no key proof). ${retry}.`;
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
    // An identity-close episode ends with an auth the relay took; its history stays for the
    // ping-pong detector (PINGPONG_WINDOW_MS), and state().lastClose still names the close.
    this._identityCollision = false;
    this._stopped = null;
    this._setPhase('connected');
    // The relay's features (sym-relay 0.6.0 advertises fan-out here). Absent means an older relay:
    // every frame goes on its own, paced.
    // Unknown tokens are ignored; an absent list lists nothing.
    const features = Array.isArray(msg.features) ? msg.features.filter((f) => typeof f === 'string') : [];
    this._fanout = features.includes(FANOUT_FEATURE) ? { max: FANOUT_MAX } : null;
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
      this._handleRelayPeerJoined(id, wireName(p.name));
    }
  }

  /**
   * The auth frame names the ENGINE VERSION beside the identity. One field, no payload, no
   * confidentiality cost — and it turns "which engines ever reached path X through the relay"
   * from a question nobody can answer after the fact (2026-09-05: whether a pre-0.3.6 engine
   * ever received categories in the clear could not be checked, because auth carried no
   * version) into a query on the relay's log.
   */
  _authFrame() {
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
    return auth;
  }

  connect() {
    if (!this._isRunning() || !this._relayUrl) return;
    // With identityRetry off, an identity close stops this client (MMP §4.4.7 as written).
    if (this._identityCollision && !this._identityRetry) return;
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

      this._sendControl(ws, this._authFrame());
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
      this._fanout = null;
      const unflushed = this._takeUnflushed();
      this._control.length = 0;
      if (this._flushTimer) { clearTimeout(this._flushTimer); this._flushTimer = null; }
      try { this._onDisconnected(); } catch (err) { this._log(`Relay disconnect handling failed: ${err && err.message}`); }
      this._giveBackUnflushed(unflushed);

      // MMP identity invariant: nodeId is bound to a keypair. A 4004 ("Replaced by new connection")
      // or 4006 says another connection CLAIMS this nodeId — another process holding the same key
      // (a restart race, an orphan), or anyone with the channel token who read the nodeId from the
      // roster, since relay-auth proves no key. Reconnecting at once would fight a real second
      // process every second; never reconnecting let a token holder switch this node off for good
      // (R3-3). So: say it loudly, retry on the long backoff, and detect a ping-pong (IDENTITY_CLOSES).
      const identityClose = IDENTITY_CLOSES[code];
      if (identityClose) {
        this._identityClosed(code, identityClose, reasonStr);
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
   * An identity close (4004 / 4006): recorded, said, told to the host at the first of an episode and
   * at a ping-pong, and retried on the long backoff (see IDENTITY_CLOSES).
   * @private
   */
  _identityClosed(code, close, reasonStr) {
    const id = this._getIdentity();
    const now = Date.now();
    const first = !this._identityCollision;
    this._identityCollision = true;
    this._identityCloses = this._identityCloses.filter((t) => now - t < PINGPONG_WINDOW_MS);
    this._identityCloses.push(now);
    const closes = this._identityCloses.length;
    const pingPong = closes >= PINGPONG_CLOSES;
    const wasPingPong = !!(this._stopped && this._stopped.pingPong);
    const delay = !this._identityRetry ? null
      : pingPong ? IDENTITY_RETRY_MAX_MS
        : Math.min(this._identityRetryMs * 2 ** (closes - 1), IDENTITY_RETRY_MAX_MS);
    const reason = reasonStr.slice(0, 200);
    this._stopped = { code, kind: close.kind, reason, at: now, closes, pingPong };
    this._nextRetryAt = null;
    this._setPhase(close.phase);
    const what = code === 4004
      ? 'replaced this connection with another that claims this nodeId'
      : 'refused this connection: another live connection claims this nodeId';
    const then = delay === null ? 'Not reconnecting (identityRetry is off).' : `Retrying in ${Math.round(delay / 1000)}s.`;
    if (pingPong) {
      this._log(`FATAL: relay ${this._relayUrl} ${what} (${code}${reason ? `: ${reason}` : ''}; nodeId=${id.nodeId}, name=${this._nodeName}), ` +
        `${closes} times in ${Math.round(PINGPONG_WINDOW_MS / 60000)} min: PING-PONG — two live processes hold this identity and replace each other. Stop one of them. ${then}`);
    } else {
      this._log(`IDENTITY CLOSE: relay ${this._relayUrl} ${what} (${code}${reason ? `: ${reason}` : ''}; nodeId=${id.nodeId}, name=${this._nodeName}). ` +
        `Another process may hold this keypair, or a holder of the relay token claimed this nodeId. ${then}`);
    }
    if ((first || (pingPong && !wasPingPong)) && this._onIdentityCollision) {
      try { this._onIdentityCollision({ nodeId: id.nodeId, name: this._nodeName, code, kind: close.kind, reason, pingPong, retryInMs: delay }); } catch (err) {
        this._log(`onIdentityCollision callback threw: ${err.message}`);
      }
    }
    if (delay !== null) this._scheduleReconnect(delay, { keepPhase: true });
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
      if (id) this._handleRelayPeerJoined(id, wireName(msg.name));
    } else if (msg.type === 'relay-peer-left') {
      const id = wireNodeId(msg.nodeId);
      if (id) this._handleRelayPeerLeft(id, wireName(msg.name));
    } else if (msg.type === 'relay-peers') {
      this._handleRelayPeers(msg);
    } else if (msg.type === 'relay-ping') {
      this._sendControl(ws, { type: 'relay-pong' });
    } else if (msg.type === 'relay-reauth') {
      // Server lost our registration (e.g. relay restarted while TCP survived).
      // Re-send auth to re-register without dropping the connection.
      this._log('Relay requested re-auth — re-sending identity');
      this._sendControl(ws, this._authFrame());
    } else if (msg.type === 'relay-error') {
      // { kind, code, message } as sym-relay sends them; each is printed only when it is what it
      // should be, and nothing else in the frame is turned into text (0.13.17).
      const kind = typeof msg.kind === 'string' ? ` ${msg.kind.slice(0, 40)}` : '';
      const code = Number.isInteger(msg.code) ? ` ${msg.code}` : '';
      const text = typeof msg.message === 'string' ? msg.message.slice(0, 500) : '(no message)';
      this._log(`Relay error${kind}${code}: ${text}`);
    } else if (wireNodeId(msg.from) && msg.payload && typeof msg.payload === 'object'
               && typeof msg.payload.type === 'string') {
      // The whole message was bounded above (MAX_FRAME_SIZE + the envelope allowance, and its
      // nesting); the payload is a part of it. A relay `from` is unproven (§4.4.1): the node takes
      // the payload only as bytes for the session bound to that `from`.
      this._onEnvelope(msg.from, wireName(msg.fromName), msg.payload, connection);
    }
  }

  _handleRelayPeerJoined(peerId, peerName) {
    const identity = this._getIdentity();
    if (!peerId || peerId === identity.nodeId) return;
    if (!this._present.has(peerId) && this._present.size >= this._maxAnnounced && !this._isKnown(peerId)) {
      // A candidate costs a handshake attempt: past the bound, an announcement for a nodeId not
      // already held is ignored (said once, counted in state().announcementsIgnored). One that
      // leaves (relay-peer-left, or the relay link closing) frees its place.
      this._announcementsIgnored++;
      if (this._announcementsIgnored === 1) this._log(`Relay: ${this._maxAnnounced} announced peers held; announcements for more are ignored (counted in relay state)`);
      return;
    }
    this._present.set(peerId, peerName);
    try { this._onPeerPresent(peerId, peerName); } catch (err) { this._log(`Relay peer-joined handling failed: ${err && err.message}`); }
  }

  _handleRelayPeerLeft(peerId, peerName) {
    this._present.delete(peerId);
    try { this._onPeerGone(peerId, peerName); } catch (err) { this._log(`Relay peer-left error for ${peerName || peerId}: ${err && err.message}`); }
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
    let data;
    try { data = JSON.stringify({ to, payload }); } catch { return { ok: false, reason: SEND_FAILURE.WRITE_FAILED }; }
    const bytes = Buffer.byteLength(data, 'utf8');
    // MMP §4.1: senders MUST NOT produce frames over MAX_FRAME_SIZE; the relay would close the whole
    // shared connection (1009) rather than drop one frame.
    if (bytes > MAX_FRAME_SIZE) return { ok: false, reason: SEND_FAILURE.TOO_LARGE, bytes };
    const refused = this._queue.push(classOf(payload), { to, payload, data, bytes, meta: meta || null });
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
        data = batch.length === 1 ? batch[0].data : JSON.stringify({ fanout: batch.map((q) => ({ to: q.to, payload: q.payload })) });
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
  _scheduleReconnect(fixedDelayMs, { keepPhase = false } = {}) {
    if (!this._isRunning() || !this._relayUrl) return;

    const base = fixedDelayMs || this._relayReconnectDelay;
    const jitter = base * 0.1 * Math.random();
    const delay = base + jitter;

    this._log(`Relay reconnecting in ${Math.round(delay / 1000)}s`);
    this._nextRetryAt = Date.now() + delay;
    // A refusal keeps its phase (the slow retry is part of the episode), and so does an identity
    // close; everything else is "reconnecting" until the next outcome.
    if (this._phase !== 'refused' && !keepPhase) this._setPhase('reconnecting');
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
    const unflushed = this._takeUnflushed();
    this._control.length = 0;

    const ws = this._relayWs;
    this._relayWs = null;
    if (ws) {
      // A socket still opening has nothing to close politely; one that is open closes after what was sent.
      try { if (ws.readyState === 0) ws.terminate(); else ws.close(1000, 'node stopped'); } catch { /* already gone */ }
    }
    this._nextRetryAt = null;
    // The last identity close stays in state().stopped; the phase is idle, since nothing is pending.
    // With identityRetry off, the stop outlives destroy() as it did before 0.14.3: the identity fact
    // behind it does not change with a restart of this node object.
    if (this._identityRetry || !this._stopped) {
      this._identityCollision = false;
      this._setPhase(this._relayUrl ? 'idle' : 'off');
    } else {
      this._setPhase(IDENTITY_CLOSES[this._stopped.code].phase);
    }
    this._giveBackUnflushed(unflushed);
  }
}

module.exports = {
  RelayConnection, RELAY_RATE_PER_SECOND, RELAY_BURST, FANOUT_FEATURE, FANOUT_MAX, HARD_STOPS, IDENTITY_CLOSES, FairQueue, CLASS2_MAX,
  RELAY_CONNECTION_MAX, MESSAGE_MAX, PINGPONG_CLOSES, PINGPONG_WINDOW_MS, IDENTITY_RETRY_MS, IDENTITY_RETRY_MAX_MS, isRelayUrl, assertRelayUrl,
};
