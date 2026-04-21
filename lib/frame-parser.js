'use strict';

/**
 * Wire frame parser for SYM TCP transport.
 *
 * Implements length-prefixed framing: 4-byte big-endian length header
 * followed by a UTF-8 JSON payload. Max frame size: 1 MiB.
 *
 * See MMP v0.2.0 Section 4 (Transport), Section 7 (Frame Types).
 *
 * Copyright (c) 2026 SYM.BOT. Apache 2.0 License.
 */

const { EventEmitter } = require('events');

/** Maximum frame payload size (1 MiB). */
const MAX_FRAME_SIZE = 1024 * 1024;

/**
 * Streaming parser for length-prefixed JSON frames.
 * Emits 'message' for each parsed frame, 'error' on parse failures.
 */
class FrameParser extends EventEmitter {
  /** Create a new parser with empty buffer. */
  constructor() {
    super();
    this.buffer = Buffer.alloc(0);
    this.state = 'length';
    this.frameLength = 0;
  }

  /**
   * Feed raw TCP data into the parser.
   * @param {Buffer} chunk — raw bytes from socket
   */
  feed(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    this._parse();
  }

  _parse() {
    while (true) {
      if (this.state === 'length') {
        if (this.buffer.length < 4) return;
        this.frameLength = this.buffer.readUInt32BE(0);
        this.buffer = this.buffer.subarray(4);
        if (this.frameLength === 0 || this.frameLength > MAX_FRAME_SIZE) {
          this.emit('error', new Error(`Invalid frame length: ${this.frameLength}`));
          return;
        }
        this.state = 'payload';
      }
      if (this.state === 'payload') {
        if (this.buffer.length < this.frameLength) return;
        const payload = this.buffer.subarray(0, this.frameLength);
        this.buffer = this.buffer.subarray(this.frameLength);
        this.state = 'length';
        this.frameLength = 0;
        try {
          this.emit('message', JSON.parse(payload.toString('utf8')));
        } catch (e) {
          this.emit('error', new Error(`Invalid JSON: ${e.message}`));
        }
      }
    }
  }
}

/**
 * Send a length-prefixed JSON frame over a TCP socket.
 *
 * @param {net.Socket} socket — TCP socket to write to
 * @param {object} msg — JSON-serializable message
 * @returns {boolean} true if sent, false if too large or write failed
 */
function sendFrame(socket, msg) {
  const payload = Buffer.from(JSON.stringify(msg), 'utf8');
  if (payload.length > MAX_FRAME_SIZE) return false;
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length, 0);
  try {
    socket.write(Buffer.concat([header, payload]));
    return true;
  } catch { return false; }
}

module.exports = { FrameParser, sendFrame };
