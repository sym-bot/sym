'use strict';

/**
 * Newline-delimited text off a byte stream, split on BYTES and decoded whole (R3-7, 0.14.3).
 *
 * Every line reader here did `buf += chunk.toString()`: each chunk was decoded on its own, so a
 * multi-byte character split across two reads became two U+FFFD replacement characters — and the
 * interior then SIGNED the damaged text and published it (a submitted focus "决定：周五发布" was
 * signed as "决定：��五发布"), and the daemon stored a task title the same way. A newline (0x0a) is
 * never part of a multi-byte UTF-8 sequence, so a line is cut on the byte and decoded only when it is
 * whole. The bound is in BYTES (it was in UTF-16 code units, a third of the bytes for CJK text).
 *
 * @copyright 2026 SYM.BOT. Apache 2.0 License.
 */

const strict = new TextDecoder('utf-8', { fatal: true });

class LineReader {
  /**
   * @param {object} [o]
   * @param {number} [o.maxLineBytes=Infinity] - a line (or the unfinished tail) longer than this is
   *   refused: onOverflow is called and the reader takes nothing more
   * @param {boolean} [o.strict=false] - a line that is not valid UTF-8 goes to onInvalid instead of
   *   being decoded with replacement characters (for text that will be signed or stored)
   * @param {(line: string) => void} o.onLine
   * @param {(bytes: Buffer) => void} [o.onInvalid]
   * @param {(bytes: number) => void} [o.onOverflow]
   */
  constructor({ maxLineBytes = Infinity, strict: isStrict = false, onLine, onInvalid, onOverflow } = {}) {
    this._max = maxLineBytes;
    this._strict = isStrict;
    this._onLine = onLine || (() => {});
    this._onInvalid = onInvalid || (() => {});
    this._onOverflow = onOverflow || (() => {});
    this._parts = [];
    this._bytes = 0;
    this._dead = false;
  }

  /** Bytes held for an unfinished line. */
  get pendingBytes() { return this._bytes; }

  /** Feed a chunk (a Buffer; a string is taken as UTF-8). */
  push(chunk) {
    if (this._dead) return;
    const buf = typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk;
    let start = 0;
    for (;;) {
      const i = buf.indexOf(0x0a, start);
      if (i === -1) break;
      const piece = buf.subarray(start, i);
      start = i + 1;
      let line = piece;
      if (this._parts.length) {
        this._parts.push(piece);
        line = Buffer.concat(this._parts, this._bytes + piece.length);
        this._parts = [];
        this._bytes = 0;
      }
      if (line.length > this._max) { this._overflow(line.length); return; }
      this._emit(line);
      if (this._dead) return;
    }
    if (start < buf.length) {
      const rest = buf.subarray(start);
      this._bytes += rest.length;
      if (this._bytes > this._max) { this._overflow(this._bytes); return; }
      this._parts.push(rest);
    }
  }

  /** Stop taking input (what is held is dropped). */
  close() { this._dead = true; this._parts = []; this._bytes = 0; }

  _emit(bytes) {
    let text;
    if (this._strict) {
      try { text = strict.decode(bytes); } catch { this._onInvalid(bytes); return; }
    } else {
      text = bytes.toString('utf8');
    }
    this._onLine(text);
  }

  _overflow(n) {
    this.close();
    this._onOverflow(n);
  }
}

module.exports = { LineReader };
