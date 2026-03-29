'use strict';

/**
 * Transport layer for SYM peer connections.
 *
 * Provides two transport implementations:
 * - TcpTransport: wraps a raw TCP socket with length-prefixed framing (LAN)
 * - RelayPeerTransport: virtual transport over a shared WebSocket relay (WAN)
 *
 * All transports emit: 'message', 'close', 'error'.
 * All transports implement: send(frame), close().
 *
 * See MMP v0.2.0 Section 4 (Transport).
 *
 * Copyright (c) 2026 SYM.BOT Ltd. Apache 2.0 License.
 */

const { EventEmitter } = require('events');
const { FrameParser, sendFrame } = require('./frame-parser');
/**
 * TcpTransport — wraps a raw TCP socket with length-prefixed framing.
 * See MMP v0.2.0 Section 4 (Transport).
 */
class TcpTransport extends EventEmitter {

  /**
   * @param {net.Socket} socket — connected TCP socket
   */
  constructor(socket) {
    super();
    this._socket = socket;
    this._parser = new FrameParser();
    this._closed = false;

    socket.on('data', (chunk) => this._parser.feed(chunk));
    this._parser.on('message', (msg) => this.emit('message', msg));
    this._parser.on('error', (err) => this.emit('error', err));
    socket.on('close', () => { this._closed = true; this.emit('close'); });
    socket.on('error', (err) => this.emit('error', err));
  }

  /**
   * Send a JSON frame to the peer.
   * @param {object} frame — JSON-serializable frame
   */
  send(frame) {
    if (this._closed) return;
    sendFrame(this._socket, frame);
  }

  /**
   * Close the transport and destroy the underlying socket.
   */
  close() {
    if (this._closed) return;
    this._closed = true;
    try { this._socket.destroy(); } catch {}
  }

  /** Drain any buffered bytes into a new transport (for handshake hand-off). */
  get pendingBuffer() {
    return this._parser.buffer || Buffer.alloc(0);
  }
}

/**
 * RelayPeerTransport — a virtual transport for a specific peer over a shared
 * WebSocket relay connection.
 *
 * Multiple peers share one WebSocket to the relay. Each RelayPeerTransport
 * targets a specific peer nodeId via the envelope's `to` field.
 */
class RelayPeerTransport extends EventEmitter {

  /**
   * @param {WebSocket} relayWs — shared WebSocket to the relay server
   * @param {string} targetNodeId — peer node ID to route frames to
   */
  constructor(relayWs, targetNodeId) {
    super();
    this._ws = relayWs;
    this._targetNodeId = targetNodeId;
    this._closed = false;
  }

  /**
   * Send a JSON frame to the target peer via the relay.
   * @param {object} frame — JSON-serializable frame
   */
  send(frame) {
    if (this._closed || !this._ws || this._ws.readyState !== 1) return;
    this._ws.send(JSON.stringify({ to: this._targetNodeId, payload: frame }));
  }

  /**
   * Close this virtual transport.
   */
  close() {
    if (this._closed) return;
    this._closed = true;
    this.emit('close');
  }

  /**
   * Called by the relay client when the shared WebSocket closes.
   */
  destroy() {
    this._closed = true;
    this.emit('close');
  }
}

module.exports = { TcpTransport, RelayPeerTransport };
