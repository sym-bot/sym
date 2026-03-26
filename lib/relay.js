'use strict';

const { RelayPeerTransport } = require('./transport');

/**
 * RelayConnection — manages the WebSocket relay connection and relay peers.
 *
 * Handles: connect, reconnect, relay-peer-joined/left, relay message routing.
 */
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
    this._nodeName = opts.nodeName;
    this._peerWakeChannels = opts.peerWakeChannels;
    this._saveWakeChannels = opts.saveWakeChannels;

    this._relayWs = null;
    this._relayReconnectTimer = null;
    this._relayReconnectDelay = 1000;
    this._relayPeerTransports = new Map();
  }

  /** The underlying WebSocket (for readyState checks). */
  get ws() { return this._relayWs; }

  /** Relay peer transports map. */
  get peerTransports() { return this._relayPeerTransports; }

  connect() {
    if (!this._isRunning() || !this._relayUrl) return;

    let WebSocket;
    try {
      WebSocket = require('ws');
    } catch {
      this._log('Relay requires the "ws" package — npm install ws');
      return;
    }

    const ws = new WebSocket(this._relayUrl);
    this._relayWs = ws;

    ws.on('open', () => {
      this._relayReconnectDelay = 1000;
      this._log(`Relay connected: ${this._relayUrl}`);

      const identity = this._getIdentity();
      const auth = {
        type: 'relay-auth',
        nodeId: identity.nodeId,
        name: this._nodeName,
        wakeChannel: this._wakeChannel || undefined,
      };
      if (this._relayToken) auth.token = this._relayToken;
      ws.send(JSON.stringify(auth));
    });

    ws.on('message', (data) => {
      let msg;
      try { msg = JSON.parse(data.toString()); } catch { return; }

      if (msg.type === 'relay-peer-joined') {
        this._handleRelayPeerJoined(msg.nodeId, msg.name);
      } else if (msg.type === 'relay-peer-left') {
        this._handleRelayPeerLeft(msg.nodeId, msg.name);
      } else if (msg.type === 'relay-peers') {
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
      } else if (msg.type === 'relay-error') {
        this._log(`Relay error: ${msg.message}`);
      } else if (msg.from && msg.payload) {
        const peers = this._getPeers();
        const peer = peers.get(msg.from);
        if (peer) peer.lastSeen = Date.now();
        this._handlePeerMessage(msg.from, msg.fromName || 'unknown', msg.payload);
      }
    });

    ws.on('close', () => {
      this._log('Relay disconnected');
      this._relayWs = null;

      const peers = this._getPeers();
      for (const [peerId, peer] of peers) {
        if (peer.source === 'relay') {
          peers.delete(peerId);
          this._getMeshNode().removePeer(peerId);
          this._onPeerLeft(peerId, peer.name);
        }
      }
      for (const [, transport] of this._relayPeerTransports) {
        transport.destroy();
      }
      this._relayPeerTransports.clear();

      this._scheduleReconnect();
    });

    ws.on('error', (err) => {
      this._log(`Relay error: ${err.message}`);
    });
  }

  _handleRelayPeerJoined(peerId, peerName) {
    const identity = this._getIdentity();
    if (!peerId || peerId === identity.nodeId) return;
    const peers = this._getPeers();
    if (peers.has(peerId)) return;

    const transport = new RelayPeerTransport(this._relayWs, peerId);
    this._relayPeerTransports.set(peerId, transport);

    transport.on('close', () => {
      this._relayPeerTransports.delete(peerId);
    });

    const peer = this._createPeer(transport, peerId, peerName, true, 'relay');
    this._addPeer(peer);
  }

  _handleRelayPeerLeft(peerId, peerName) {
    const peers = this._getPeers();
    const peer = peers.get(peerId);
    if (!peer || peer.source !== 'relay') return;

    const transport = this._relayPeerTransports.get(peerId);
    if (transport) transport.destroy();
    this._relayPeerTransports.delete(peerId);

    peers.delete(peerId);
    this._getMeshNode().removePeer(peerId);
    this._log(`Relay peer left: ${peerName || peerId}`);
    this._onPeerLeft(peerId, peerName || peer.name);
  }

  _scheduleReconnect() {
    if (!this._isRunning() || !this._relayUrl) return;

    const jitter = this._relayReconnectDelay * 0.1 * Math.random();
    const delay = this._relayReconnectDelay + jitter;

    this._log(`Relay reconnecting in ${Math.round(delay / 1000)}s`);
    this._relayReconnectTimer = setTimeout(() => this.connect(), delay);

    this._relayReconnectDelay = Math.min(this._relayReconnectDelay * 2, 30000);
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
  }
}

module.exports = { RelayConnection };
