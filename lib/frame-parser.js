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
const { MAX_FRAME_DEPTH, nestedTooDeep } = require('./core/json-depth');

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
    // The bytes not yet parsed, as the chunks they came in (R3-12): feed() concatenated the whole
    // buffer with every chunk, so one frame near MAX_FRAME_SIZE fed in 1 KiB reads cost O(n²) copying
    // on the event loop — 67 ms for one 1 MiB frame, before the peer had authenticated anything. A
    // frame's bytes are now copied once, when the whole frame is there.
    this._chunks = [];
    this._length = 0;
    this.state = 'length';
    this.frameLength = 0;
  }

  /** The bytes held and not yet parsed (copied on demand: a transport hand-off reads it once). */
  get buffer() {
    if (this._chunks.length === 0) return Buffer.alloc(0);
    return this._chunks.length === 1 ? this._chunks[0] : Buffer.concat(this._chunks, this._length);
  }

  /**
   * Feed raw TCP data into the parser.
   * @param {Buffer} chunk — raw bytes from socket
   */
  feed(chunk) {
    if (this.state === 'failed' || !chunk || !chunk.length) return;
    this._chunks.push(chunk);
    this._length += chunk.length;
    this._parse();
  }

  /** @private Take exactly `n` bytes (held) from the front. */
  _take(n) {
    const first = this._chunks[0];
    let out;
    if (first.length >= n) {
      out = first.subarray(0, n);
      if (first.length === n) this._chunks.shift(); else this._chunks[0] = first.subarray(n);
    } else {
      out = Buffer.allocUnsafe(n);
      let off = 0;
      while (off < n) {
        const c = this._chunks[0];
        const k = Math.min(c.length, n - off);
        c.copy(out, off, 0, k);
        off += k;
        if (k === c.length) this._chunks.shift(); else this._chunks[0] = c.subarray(k);
      }
    }
    this._length -= n;
    return out;
  }

  _parse() {
    while (true) {
      if (this.state === 'length') {
        if (this._length < 4) return;
        this.frameLength = this._take(4).readUInt32BE(0);
        if (this.frameLength === 0 || this.frameLength > MAX_FRAME_SIZE) {
          // MMP §4.1: rejection MUST close the transport. The stream cannot be
          // resynchronised past a bad length, so the parser stops here for good.
          this.state = 'failed';
          this._chunks = [];
          this._length = 0;
          const err = new Error(`Invalid frame length: ${this.frameLength}`);
          err.fatal = true;
          this.emit('error', err);
          return;
        }
        this.state = 'payload';
      }
      if (this.state === 'payload') {
        if (this._length < this.frameLength) return;
        const payload = this._take(this.frameLength);
        this.state = 'length';
        this.frameLength = 0;
        let msg;
        try {
          const text = utf8.decode(payload);
          if (nestedTooDeep(text)) {
            this.emit('error', new Error(`Frame dropped: nested deeper than ${MAX_FRAME_DEPTH} levels`));
            continue;
          }
          msg = JSON.parse(text);
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

module.exports = { FrameParser, sendFrame, writeFrame, SEND_FAILURE, MAX_FRAME_SIZE, MAX_FRAME_DEPTH, nestedTooDeep };
