'use strict';

/**
 * @module sym/core/json-depth
 * @description The nesting bound on JSON a peer wrote, checked before it is parsed.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

/**
 * Maximum nesting of objects and arrays in JSON a peer wrote: a frame, or the plaintext of an
 * encrypted one. A frame is parsed once at the door and then kept, relayed, persisted and handed
 * to hosts, each of which serialises it again, and serialising recurses once per level: a frame
 * some 10,000 levels deep (24 KB on the wire) parses but cannot be serialised, and threw a
 * RangeError wherever that happened, outside any guard. No MMP frame nests anywhere near this
 * deep, so a deeper one is not a frame and is dropped unparsed, as malformed JSON is.
 */
const MAX_FRAME_DEPTH = 128;

/**
 * Whether JSON text nests objects/arrays deeper than `max`. Scans the text (brackets inside
 * strings do not count) without parsing it, so a frame too deep is never built.
 * @param {string} text
 * @param {number} [max=MAX_FRAME_DEPTH]
 * @returns {boolean}
 */
function nestedTooDeep(text, max = MAX_FRAME_DEPTH) {
  let depth = 0;
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (inString) {
      if (c === 0x5c) i++;                 // backslash: skip the escaped character
      else if (c === 0x22) inString = false;
    } else if (c === 0x22) inString = true;
    else if (c === 0x7b || c === 0x5b) { if (++depth > max) return true; }
    else if (c === 0x7d || c === 0x5d) depth--;
  }
  return false;
}

module.exports = { MAX_FRAME_DEPTH, nestedTooDeep };
