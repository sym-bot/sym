'use strict';

/**
 * RelayConnection — manages the WebSocket relay connection and relay peers.
 *
 * Handles: connect, reconnect, relay-peer-joined/left, relay message routing.
 * See MMP v0.2.0 Section 4 (Transport), Section 5 (Connection).
 *
 * Copyright (c) 2026 SYM.BOT. Apache 2.0 License.
 */

const { RelayPeerTransport } = require('./transport');
const ENGINE_VERSION = require('../package.json').version;
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
   * @param {function} opts.handlePeerMessage  — (peerId, peerName, msg) => void
   * @param {function} opts.onPeerLeft         — (peerId, peerName) => void — emit peer-left event
   * @param {string}   opts.nodeName           — this node's name
   * @param {Map}      opts.peerWakeChannels   — shared peer wake channels Map
   * @param {function} opts.saveWakeChannels   — () => void
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
    this._isRunning = opts.isRunning;
    this._getPeers = opts.getPeers;
    this._getMeshNode = opts.getMeshNode;
    this._createPeer = opts.createPeer;
    this._addPeer = opts.addPeer;
    this._handlePeerMessage = opts.handlePeerMessage;
    this._onPeerLeft = opts.onPeerLeft;
    this._onIdentityCollision = opts.onIdentityCollision || null;
    this._onAuthRefused = opts.onAuthRefused || null;
    this._authRefusedRetryMs = opts.authRefusedRetryMs || 10 * 60 * 1000;
    this._authRefused = false;
    this._nodeName = opts.nodeName;
    this._peerWakeChannels = opts.peerWakeChannels;
    this._saveWakeChannels = opts.saveWakeChannels;
    this._identityCollision = false;

    this._relayWs = null;
    this._relayReconnectTimer = null;
    this._relayReconnectDelay = 1000;
    this._relayPeerTransports = new Map();
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
   * phase: off | idle | connecting | authenticating | connected | reconnecting | refused | collision
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
      peers: this._relayPeerTransports.size,
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
    const terminal = () => ['connected', 'refused', 'collision', 'off'].includes(this._phase);
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
    if (['connected', 'refused', 'collision', 'off'].includes(phase)) {
      for (const w of this._outcomeWaiters.slice()) w();
    }
  }

  /** Relay peer transports map. */
  get peerTransports() { return this._relayPeerTransports; }

  /**
   * Open WebSocket connection to the relay and authenticate.
   * Auto-reconnects on disconnect with exponential backoff.
   */
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

    const ws = new WebSocket(this._relayUrl);
    this._relayWs = ws;
    this._attempts++;
    this._nextRetryAt = null;
    this._setPhase('connecting');

    ws.on('open', () => {
      this._relayReconnectDelay = 1000;
      this._log(`Relay connected: ${this._relayUrl}`);
      this._setPhase('authenticating');

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
        ws.send(JSON.stringify({ type: 'relay-pong' }));
      }, 20000);

      ws.send(JSON.stringify(this._authFrame()));
    });

    ws.on('message', (data) => {
      let msg;
      try { msg = JSON.parse(data.toString()); } catch { return; }
      this._lastRelayMessage = Date.now();

      if (msg.type === 'relay-peer-joined') {
        this._handleRelayPeerJoined(msg.nodeId, msg.name);
      } else if (msg.type === 'relay-peer-left') {
        this._handleRelayPeerLeft(msg.nodeId, msg.name);
      } else if (msg.type === 'relay-peers') {
        // The peer list is sent only after a successful relay-auth: a refusal episode ends here.
        this._authRefused = false;
        this._refused = null;
        this._attempts = 0;
        this._setPhase('connected');
        for (const p of (msg.peers || [])) {
          if (p.wakeChannel && p.wakeChannel.platform !== 'none') {
            this._peerWakeChannels.set(p.nodeId, p.wakeChannel);
            this._log(`Gossip: learned wake channel for ${p.name} (${p.wakeChannel.platform})`);
          }
          if (!p.offline) {
            this._handleRelayPeerJoined(p.nodeId, p.name);
          }
        }
        this._saveWakeChannels();
      } else if (msg.type === 'relay-ping') {
        ws.send(JSON.stringify({ type: 'relay-pong' }));
      } else if (msg.type === 'relay-reauth') {
        // Server lost our registration (e.g. relay restarted while TCP survived).
        // Re-send auth to re-register without dropping the connection.
        this._log('Relay requested re-auth — re-sending identity');
        ws.send(JSON.stringify(this._authFrame()));
      } else if (msg.type === 'relay-error') {
        this._log(`Relay error: ${msg.message}`);
      } else if (msg.from && msg.payload) {
        const peers = this._getPeers();
        const peer = peers.get(msg.from);
        if (peer) peer.lastSeen = Date.now();
        this._handlePeerMessage(msg.from, msg.fromName || 'unknown', msg.payload);
      }
    });

    ws.on('close', (code, reason) => {
      const reasonStr = reason && reason.toString ? reason.toString() : '';
      this._log(`Relay disconnected (code ${code}${reasonStr ? `: ${reasonStr}` : ''})`);
      this._relayWs = null;
      this._lastClose = { code, reason: reasonStr, at: Date.now() };
      if (this._relayPingTimer) { clearInterval(this._relayPingTimer); this._relayPingTimer = null; }

      // Section 4.6 + 5.5: close relay transports only.
      // _createPeer's close handlers will failover to Bonjour
      // or remove the peer if no transports remain.
      for (const [, transport] of this._relayPeerTransports) {
        transport.destroy();
      }
      this._relayPeerTransports.clear();

      // MMP identity invariant: nodeId is bound to a keypair. If the relay
      // closes us with code 4004 ("Replaced by new connection"), another
      // process is holding the same private key (legitimate restart race,
      // orphan process, or impersonation). Silently reconnecting kicks the
      // other instance, which kicks us back, producing a 1-second ping-pong
      // loop. Loudly refuse instead — wrong winner is worse than loud
      // failure. The host can listen via onIdentityCollision and decide
      // whether to exit, wait, or alert.
      if (code === 4004) {
        const id = this._getIdentity();
        this._identityCollision = true;
        this._setPhase('collision');
        this._log(`FATAL: relay reports duplicate identity (nodeId=${id.nodeId}, name=${this._nodeName}). Another process is holding this keypair. Not reconnecting.`);
        if (this._onIdentityCollision) {
          try { this._onIdentityCollision({ nodeId: id.nodeId, name: this._nodeName, code }); } catch (err) {
            this._log(`onIdentityCollision callback threw: ${err.message}`);
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

  _handleRelayPeerJoined(peerId, peerName) {
    const identity = this._getIdentity();
    if (!peerId || peerId === identity.nodeId) return;
    const peers = this._getPeers();
    const transport = new RelayPeerTransport(this._relayWs, peerId);
    this._relayPeerTransports.set(peerId, transport);

    transport.on('close', () => {
      this._relayPeerTransports.delete(peerId);
    });

    // Section 4.6: if peer already connected (e.g. via Bonjour),
    // _createPeer adds relay as secondary transport, not a duplicate.
    const peer = this._createPeer(transport, peerId, peerName, true, 'relay');
    if (!peers.has(peerId)) {
      this._addPeer(peer);
    }
  }

  _handleRelayPeerLeft(peerId, peerName) {
    // Section 4.6 + 5.5: close the relay transport only.
    // _createPeer's close handler will failover to Bonjour
    // or remove the peer if no transports remain.
    try {
      const transport = this._relayPeerTransports.get(peerId);
      if (transport) transport.destroy();
      this._relayPeerTransports.delete(peerId);
      this._log(`Relay transport closed for ${peerName || peerId}`);
    } catch (err) {
      this._log(`Relay peer-left error for ${peerName || peerId}: ${err.message}`);
    }
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
    if (this._relayReconnectTimer) clearTimeout(this._relayReconnectTimer);

    for (const [, transport] of this._relayPeerTransports) {
      transport.destroy();
    }
    this._relayPeerTransports.clear();

    if (this._relayWs) {
      try { this._relayWs.close(); } catch {}
      this._relayWs = null;
    }
    this._nextRetryAt = null;
    this._setPhase(this._relayUrl ? 'idle' : 'off');
  }
}

module.exports = { RelayConnection };
