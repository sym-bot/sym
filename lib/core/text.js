'use strict';

/**
 * @module sym/core/text
 * @description Well-formed text (sym 0.14.3, review M2). A record is signed as UTF-8 bytes (§8.8.4), and
 * UTF-8 has no spelling for a lone surrogate: an encoder writes U+FFFD in its place. These are the one
 * definition of "the string its bytes say" and of a cut that never makes a lone surrogate, used by the
 * record boundary (cmb-encoder's wellFormedRecord) and by every place sym truncates a text it passes on.
 * It requires nothing, so any core module can use it without a cycle.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

/**
 * Whether `s` is well-formed Unicode: no lone surrogate.
 * @param {string} s
 * @returns {boolean}
 */
const isWellFormedText = typeof String.prototype.isWellFormed === 'function'
  ? (s) => typeof s === 'string' && s.isWellFormed()
  : (s) => typeof s === 'string' && !/\p{Cs}/u.test(s);

/**
 * `s` with each lone surrogate replaced by U+FFFD: the string its UTF-8 bytes decode to, and so the one
 * spelling of what a signature over them covers (String.prototype.toWellFormed, Node 20+).
 * @param {string} s
 * @returns {string}
 */
const toWellFormedText = typeof String.prototype.toWellFormed === 'function'
  ? (s) => s.toWellFormed()
  : (s) => s.replace(/\p{Cs}/gu, '�');

/**
 * At most the first `max` UTF-16 units of `s`, cut on a code point boundary: a surrogate pair is never
 * split, so a cut never makes a lone surrogate. One unit shorter when `max` falls inside a pair.
 * @param {string} s
 * @param {number} max
 * @returns {string}
 */
function cutText(s, max) {
  if (typeof s !== 'string' || s.length <= max) return s;
  if (!(max > 0)) return '';
  const last = s.charCodeAt(max - 1);
  const next = s.charCodeAt(max);
  return s.slice(0, last >= 0xd800 && last <= 0xdbff && next >= 0xdc00 && next <= 0xdfff ? max - 1 : max);
}

module.exports = { isWellFormedText, toWellFormedText, cutText };
