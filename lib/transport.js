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
 * Copyright (c) 2026 SYM.BOT. Apache 2.0 License.
 */

const { EventEmitter } = require('events');
const { FrameParser, writeFrame, SEND_FAILURE, MAX_FRAME_SIZE } = require('./frame-parser');
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

    // TCP keepalive: detect half-open connections (peer process killed
    // without graceful FIN) faster than the OS default (~2h on macOS).
    // Without this, a peer that crashes leaves us with an ESTABLISHED
    // socket that survives long enough to block legitimate redials —
    // dedup logic against the stale entry rejects the live new connection.
    // 1s initial delay then OS-default probe cadence (typically detects
    // dead remote within ~10s on macOS, faster than waiting for the
    // application heartbeat timeout).
    try { socket.setKeepAlive(true, 1000); } catch {}

    socket.on('data', (chunk) => this._parser.feed(chunk));
    this._parser.on('message', (msg) => this.emit('message', msg));
    this._parser.on('error', (err) => {
      this.emit('error', err);
      if (err.fatal) this.close();
    });
    socket.on('close', () => { this._closed = true; this.emit('close'); });
    socket.on('error', (err) => this.emit('error', err));
  }

  /**
   * Send a JSON frame to the peer.
   * @param {object} frame — JSON-serializable frame
   * @returns {boolean} false if the transport is closed, the frame is too large or the write failed
   *   (trySend says which)
   */
  send(frame) {
    return this.trySend(frame).ok;
  }

  /**
   * Send a JSON frame to the peer, and say why when it is not sent.
   * @param {object} frame — JSON-serializable frame
   * @returns {{ ok: boolean, reason?: string, bytes?: number }} `reason` is one of SEND_FAILURE
   */
  trySend(frame) {
    if (this._closed) return { ok: false, reason: SEND_FAILURE.NOT_CONNECTED };
    return writeFrame(this._socket, frame);
  }

  /**
   * Close the transport and destroy the underlying socket.
   */
  close() {
    if (this._closed) return;
    this._closed = true;
    try { this._socket.destroy(); } catch {}
  }

  /** Bytes written to this connection and not yet taken by the kernel (an outbound byte budget). */
  pendingBytes() {
    try { return this._socket.writableLength || 0; } catch { return 0; }
  }

  /** Close after what was written has gone out (an error frame before a refusal), at most 1 s later. */
  end() {
    if (this._closed) return;
    this._closed = true;
    try {
      this._socket.end();
      const t = setTimeout(() => { try { this._socket.destroy(); } catch {} }, 1000);
      if (t.unref) t.unref();
    } catch { try { this._socket.destroy(); } catch {} }
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
 * targets a specific peer nodeId via the envelope's `to` category.
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
   * @returns {boolean} false if the relay is not open, the frame is too large or the send failed
   *   (trySend says which)
   */
  send(frame) {
    return this.trySend(frame).ok;
  }

  /**
   * Send a JSON frame to the target peer via the relay, and say why when it is not sent.
   * @param {object} frame — JSON-serializable frame
   * @returns {{ ok: boolean, reason?: string, bytes?: number }} `reason` is one of SEND_FAILURE
   */
  trySend(frame) {
    if (this._closed || !this._ws || this._ws.readyState !== 1) return { ok: false, reason: SEND_FAILURE.NOT_CONNECTED };
    const data = JSON.stringify({ to: this._targetNodeId, payload: frame });
    const bytes = Buffer.byteLength(data, 'utf8');
    // MMP §4.1: senders MUST NOT produce frames over MAX_FRAME_SIZE; the relay
    // would close the whole shared connection (1009) rather than drop one frame.
    if (bytes > MAX_FRAME_SIZE) return { ok: false, reason: SEND_FAILURE.TOO_LARGE, bytes };
    try {
      this._ws.send(data);
      return { ok: true, bytes };
    } catch { return { ok: false, reason: SEND_FAILURE.WRITE_FAILED, bytes }; }
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
