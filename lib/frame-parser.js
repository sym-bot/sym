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

const utf8 = new TextDecoder('utf-8', { fatal: true });

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
    if (this.state === 'failed') return;
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
          // MMP §4.1: rejection MUST close the transport. The stream cannot be
          // resynchronised past a bad length, so the parser stops here for good.
          this.state = 'failed';
          this.buffer = Buffer.alloc(0);
          const err = new Error(`Invalid frame length: ${this.frameLength}`);
          err.fatal = true;
          this.emit('error', err);
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
        let msg;
        try {
          msg = JSON.parse(utf8.decode(payload));
        } catch (e) {
          this.emit('error', new Error(`Invalid JSON: ${e.message}`));
          continue;
        }
        // MMP §4.1: a frame without a string `type` is silently discarded.
        if (!msg || typeof msg !== 'object' || typeof msg.type !== 'string') continue;
        try {
          this.emit('message', msg);
        } catch (e) {
          this.emit('error', new Error(`Frame handler failed for '${msg.type}': ${e.message}`));
        }
      }
    }
  }
}

/**
 * Why a frame was not sent. Callers that only need whether keep using sendFrame()/send(); the ones
 * that tell a person what happened read the reason, so "too large" is never reported as "not
 * connected".
 */
const SEND_FAILURE = Object.freeze({
  TOO_LARGE: 'too-large',         // the serialized frame is over MAX_FRAME_SIZE: no transport carries it
  NOT_CONNECTED: 'not-connected', // no socket, or it is destroyed, closed or no longer writable
  WRITE_FAILED: 'write-failed',   // the socket refused the write
});

/**
 * Send a length-prefixed JSON frame over a TCP socket, and say why when it is not sent.
 *
 * @param {net.Socket} socket — TCP socket to write to
 * @param {object} msg — JSON-serializable message
 * @returns {{ ok: boolean, reason?: string, bytes: number }} `bytes` is the serialized frame's
 *   length; `reason` is one of SEND_FAILURE when `ok` is false.
 */
function writeFrame(socket, msg) {
  const payload = Buffer.from(JSON.stringify(msg), 'utf8');
  const bytes = payload.length;
  if (bytes > MAX_FRAME_SIZE) return { ok: false, reason: SEND_FAILURE.TOO_LARGE, bytes };
  // A socket that is destroyed or no longer writable has not taken the frame, even though write()
  // on it may not throw: 'close' can arrive after the destroy, and until then this counted as sent.
  if (!socket || socket.destroyed || socket.writable === false) return { ok: false, reason: SEND_FAILURE.NOT_CONNECTED, bytes };
  const header = Buffer.alloc(4);
  header.writeUInt32BE(bytes, 0);
  try {
    socket.write(Buffer.concat([header, payload]));
    return { ok: true, bytes };
  } catch { return { ok: false, reason: SEND_FAILURE.WRITE_FAILED, bytes }; }
}

/**
 * Send a length-prefixed JSON frame over a TCP socket.
 *
 * @param {net.Socket} socket — TCP socket to write to
 * @param {object} msg — JSON-serializable message
 * @returns {boolean} true if sent, false if too large, not connected or the write failed
 *   (writeFrame says which)
 */
function sendFrame(socket, msg) {
  return writeFrame(socket, msg).ok;
}

module.exports = { FrameParser, sendFrame, writeFrame, SEND_FAILURE, MAX_FRAME_SIZE };
