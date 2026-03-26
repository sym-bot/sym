'use strict';

const { EventEmitter } = require('events');
const { FrameParser, sendFrame } = require('./frame-parser');

/**
 * Transport abstraction for SYM peer connections.
 *
 * All transports emit:
 *   'message' (msg)  — parsed JSON frame from peer
 *   'close'  ()      — connection closed
 *   'error'  (err)   — connection error
 *
 * All transports implement:
 *   send(frame)       — send a JSON frame to the peer
 *   close()           — close the connection
 */

/**
 * TcpTransport — wraps a raw TCP socket with length-prefixed framing.
 */
class TcpTransport extends EventEmitter {

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

  send(frame) {
    if (this._closed) return;
    sendFrame(this._socket, frame);
  }

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

  constructor(relayWs, targetNodeId) {
    super();
    this._ws = relayWs;
    this._targetNodeId = targetNodeId;
    this._closed = false;
  }

  send(frame) {
    if (this._closed || !this._ws || this._ws.readyState !== 1) return;
    this._ws.send(JSON.stringify({ to: this._targetNodeId, payload: frame }));
  }

  close() {
    if (this._closed) return;
    this._closed = true;
    this.emit('close');
  }

  /** Called by the relay client when the shared WebSocket closes. */
  destroy() {
    this._closed = true;
    this.emit('close');
  }
}

module.exports = { TcpTransport, RelayPeerTransport };
