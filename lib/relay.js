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
 * 4008 (sym-relay 0.5: a token bucket per connection, every frame counted). Core Secure seals one
 * frame per peer session, so a room broadcast is N frames: this client paces everything it sends
 * under that limit, with headroom, and queues what does not fit.
 */
const RELAY_RATE_PER_SECOND = 20;
const RELAY_BURST = 200;
/** Frames waiting for the pacer at most; past it a send is refused (`queue-full`), never dropped silently. */
const RELAY_QUEUE_MAX = 10_000;
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
 * Close codes after which the client never reconnects on its own (MMP §4.4.7, §4.4.9): each is a
 * statement about this node's identity that a retry cannot change, and retrying would only fight the
 * holder the relay chose.
 *   4004 replaced — another process re-authenticated as this nodeId and the relay took it;
 *   4006 duplicate rejected — this node is the newcomer and the existing holder is the legitimate one;
 *   4007 key conflict — the relay binds this nodeId to a different key (draft, MMP spec PR
 *        meshcognition-website#20: handled when a relay sends it; relay-auth v2 is not implemented).
 */
const HARD_STOPS = {
  4004: { phase: 'collision', kind: 'replaced' },
  4006: { phase: 'duplicate-rejected', kind: 'duplicate-rejected' },
  4007: { phase: 'key-conflict', kind: 'key-conflict' },
};
const STOP_PHASES = Object.values(HARD_STOPS).map((h) => h.phase);
const TERMINAL_PHASES = ['connected', 'refused', ...STOP_PHASES, 'off'];
const FANOUT_MAX = 64;
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
   * @param {function} [opts.onIdentityCollision] — ({nodeId, name, code}) => void —
   *                   called when the relay reports our nodeId is already held
   *                   by another connection. If not provided, the default
   *                   behavior is to log loudly and stop reconnecting (but
   *                   not exit the host process). Hosts that want stronger
   *                   action (e.g. process.exit) should wire this callback.
   * @param {function} [opts.onAuthRefused] — ({relayUrl, name, code, reason}) => void —
   *                   called ONCE per refusal episode when the relay closes with 4003
   *                   (token not in its channel table). The relay layer has already
   *                   logged the cause and the fix and dropped to the slow retry.
   * @param {number}   [opts.authRefusedRetryMs] — cadence of the slow retry after a
   *                   4003 (default 10 minutes).
   */
  constructor(opts) {
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
    this._queue = [];                 // [{ to, payload }] in send order
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
    this._identityCollision = false;   // a hard stop (4004 / 4006 / 4007): never reconnect on its own
    this._stopped = null;              // { code, kind, reason, at } — why, for state() and describe()

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
   *        | duplicate-rejected (4006) | key-conflict (4007) — the last three are hard stops (HARD_STOPS)
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
        return `STOPPED: ${s.url} reports another process holding this identity (4004). Not reconnecting — ` +
          `stop the other process or use a different node identity.`;
      case 'duplicate-rejected':
        return `STOPPED: ${s.url} refused this connection because another live connection already holds this ` +
          `identity (4006); that holder is the legitimate one. Not reconnecting — stop the other process, or ` +
          `restart this one after it has gone.`;
      case 'key-conflict':
        return `STOPPED: ${s.url} binds this nodeId to a DIFFERENT key (4007): another party holds this nodeId at ` +
          `the relay, or this identity was re-keyed. Not reconnecting — check which key is genuine before anything else.`;
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
      nodeId: identity.nodeId,
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
    if (this._identityCollision) return;  // hard-stop after duplicate-identity refusal

    let WebSocket;
    try {
      WebSocket = require('ws');
    } catch {
      this._log('Relay requires the "ws" package — npm install ws');
      return;
    }

    // §4.1's frame bound, applied by ws before it buffers a message (it closes with 1009 instead).
    const ws = new WebSocket(this._relayUrl, { maxPayload: MAX_FRAME_SIZE + RELAY_ENVELOPE_ALLOWANCE });
    this._relayWs = ws;
    const connection = this._connections = (this._connections || 0) + 1;   // this connection, for lanes
    this._attempts++;
    this._nextRetryAt = null;
    // A retry inside a refusal episode is part of the episode (see _scheduleReconnect): the phase
    // stays `refused` until the relay admits us (relay-peers ends the episode). Relabelling it for
    // the length of each dial made state() and describe() report a refused node as connecting.
    if (!this._refused) this._setPhase('connecting');

    ws.on('open', () => {
      this._relayReconnectDelay = 1000;
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
          this._log('Relay liveness timeout — forcing reconnect');
          ws.close();
          return;
        }
        this._sendControl(ws, { type: 'relay-pong' });
      }, 20000);

      this._sendControl(ws, this._authFrame());
    });

    ws.on('message', (data) => {
      // MMP §4.1's frame bound applies on the relay path too, where frames come from parties
      // that are not the socket peer. The envelope (from, fromName) gets a small allowance.
      if (data.length > MAX_FRAME_SIZE + RELAY_ENVELOPE_ALLOWANCE) {
        this._log(`Relay message dropped: ${data.length} bytes exceeds the frame bound`);
        return;
      }
      // Nesting is bounded before parsing (core/json-depth.js): a message nested deeper is not a
      // frame and is dropped unparsed, as malformed JSON is. Until 0.13.17 a payload some 10,000
      // levels deep (24 KB on the wire) parsed, and serialising it to measure it, below, recursed
      // once per level and threw a RangeError out of this callback, which is uncaught.
      let msg;
      try {
        const text = data.toString();
        if (nestedTooDeep(text)) return;
        msg = JSON.parse(text);
      } catch { return; }
      // MMP §4.1: a frame without a string `type` is silently discarded. Relay
      // envelopes carry `from` + `payload` instead, so accept those as well.
      if (!msg || typeof msg !== 'object') return;
      this._lastRelayMessage = Date.now();

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
      // reachable over the LAN keeps that session. What was queued for the pacer is dropped with it.
      this._present.clear();
      this._queue = [];
      if (this._flushTimer) { clearTimeout(this._flushTimer); this._flushTimer = null; }
      try { this._onDisconnected(); } catch (err) { this._log(`Relay disconnect handling failed: ${err && err.message}`); }

      // MMP identity invariant: nodeId is bound to a keypair. If the relay
      // closes us with code 4004 ("Replaced by new connection"), another
      // process is holding the same private key (legitimate restart race,
      // orphan process, or impersonation). Silently reconnecting kicks the
      // other instance, which kicks us back, producing a 1-second ping-pong
      // loop. Loudly refuse instead — wrong winner is worse than loud
      // failure. The host can listen via onIdentityCollision and decide
      // whether to exit, wait, or alert.
      // 4006 (the existing holder is legitimate) and 4007 (the relay binds this nodeId to another key)
      // stop the same way: said once, kept in state().stopped, never retried (see HARD_STOPS).
      const hard = HARD_STOPS[code];
      if (hard) {
        const id = this._getIdentity();
        const first = !this._identityCollision;
        this._identityCollision = true;
        this._stopped = { code, kind: hard.kind, reason: reasonStr.slice(0, 200), at: Date.now() };
        this._nextRetryAt = null;
        this._setPhase(hard.phase);
        if (first) {
          const what = code === 4004
            ? 'reports duplicate identity: another process is holding this keypair'
            : code === 4006
              ? 'rejected this connection as a duplicate: another live connection holds this identity and is the legitimate holder'
              : 'binds this nodeId to a DIFFERENT key: another party holds this nodeId at the relay, or this identity was re-keyed';
          this._log(`FATAL: relay ${this._relayUrl} ${what} (${code}${reasonStr ? `: ${reasonStr.slice(0, 200)}` : ''}; nodeId=${id.nodeId}, name=${this._nodeName}). Not reconnecting.`);
          if (this._onIdentityCollision) {
            try { this._onIdentityCollision({ nodeId: id.nodeId, name: this._nodeName, code, kind: hard.kind, reason: reasonStr.slice(0, 200) }); } catch (err) {
              this._log(`onIdentityCollision callback threw: ${err.message}`);
            }
          }
        }
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
      trySend(frame) {
        if (this._closed) return { ok: false, reason: SEND_FAILURE.NOT_CONNECTED };
        return relay.sendTo(nodeId, frame);
      },
      send(frame) { return this.trySend(frame).ok; },
      close() { this._closed = true; },
      destroy() { this._closed = true; },
    };
  }

  /**
   * Send one payload to `to` through the pacer. Sends made in the same turn of the event loop are
   * flushed together, so a broadcast's per-session frames go out as fan-out envelopes when the relay
   * supports them, and paced under its rate when it does not.
   * @returns {{ ok: boolean, reason?: string, bytes?: number }}
   */
  sendTo(to, payload) {
    const ws = this._relayWs;
    if (!ws || ws.readyState !== 1) return { ok: false, reason: SEND_FAILURE.NOT_CONNECTED };
    let data;
    try { data = JSON.stringify({ to, payload }); } catch { return { ok: false, reason: SEND_FAILURE.WRITE_FAILED }; }
    const bytes = Buffer.byteLength(data, 'utf8');
    // MMP §4.1: senders MUST NOT produce frames over MAX_FRAME_SIZE; the relay would close the whole
    // shared connection (1009) rather than drop one frame.
    if (bytes > MAX_FRAME_SIZE) return { ok: false, reason: SEND_FAILURE.TOO_LARGE, bytes };
    if (this._queue.length >= RELAY_QUEUE_MAX) return { ok: false, reason: 'queue-full', bytes };
    this._queue.push({ to, payload, data, bytes });
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

  /** Send what the bucket allows: fan-out envelopes when advertised, else one frame per payload. */
  _flush() {
    const ws = this._relayWs;
    if (!ws || ws.readyState !== 1) return;
    while (this._queue.length) {
      const b = this._refill();
      if (b.tokens < 1) {
        const wait = Math.ceil(((1 - b.tokens) * 1000) / this._rate);
        this._flushTimer = setTimeout(() => { this._flushTimer = null; this._flush(); }, Math.max(wait, 5));
        if (this._flushTimer.unref) this._flushTimer.unref();
        return;
      }
      let data;
      if (this._fanout && this._queue.length > 1) {
        // Consecutive payloads, in order, up to FANOUT_MAX and the frame bound, and never a recipient
        // twice in one envelope (the batch ends at the first repeat, so per-recipient order holds).
        const batch = [];
        const to = new Set();
        let size = 16;
        while (this._queue.length && batch.length < this._fanout.max && !to.has(this._queue[0].to) && size + this._queue[0].bytes + 1 <= MAX_FRAME_SIZE) {
          const q = this._queue.shift();
          batch.push(q);
          to.add(q.to);
          size += q.bytes + 1;
        }
        data = batch.length === 1 ? batch[0].data : JSON.stringify({ fanout: batch.map((q) => ({ to: q.to, payload: q.payload })) });
        if (batch.length > 1) this._sentFanout++;
      } else {
        data = this._queue.shift().data;
      }
      b.tokens -= 1;
      try { ws.send(data); this._sentFrames++; } catch (err) { this._log(`Relay send failed: ${err && err.message}`); }
    }
  }

  /** A frame of the relay protocol itself (auth, pong): sent at once, counted against the bucket. */
  _sendControl(ws, frame) {
    this._refill().tokens -= 1;
    ws.send(JSON.stringify(frame));
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
    this._relayReconnectTimer = setTimeout(() => this.connect(), delay);

    if (!fixedDelayMs) this._relayReconnectDelay = Math.min(this._relayReconnectDelay * 2, 30000);
  }

  /** Clean up relay resources on stop. */
  destroy() {
    if (this._relayReconnectTimer) { clearTimeout(this._relayReconnectTimer); this._relayReconnectTimer = null; }
    if (this._relayPingTimer) { clearInterval(this._relayPingTimer); this._relayPingTimer = null; }

    this._present.clear();
    this._queue = [];
    if (this._flushTimer) { clearTimeout(this._flushTimer); this._flushTimer = null; }

    if (this._relayWs) {
      try { this._relayWs.close(); } catch {}
      this._relayWs = null;
    }
    this._nextRetryAt = null;
    // A hard stop outlives destroy(): the identity fact behind it does not change with a restart of
    // this node object (state().stopped keeps the reason).
    this._setPhase(this._stopped ? HARD_STOPS[this._stopped.code].phase : (this._relayUrl ? 'idle' : 'off'));
  }
}

module.exports = { RelayConnection, RELAY_RATE_PER_SECOND, RELAY_BURST, FANOUT_FEATURE, FANOUT_MAX, HARD_STOPS };
