'use strict';

/**
 * @module @sym-bot/core/ref
 * @description Descent refs — the one place a ref string is constructed or read.
 *
 * A descent ref names WHICH ASSERTION a category descends from:
 *
 *     blockKey # category ~ sigDigest
 *     cmb-<64hex>#focus~<64hex>
 *
 * Why all three parts are needed. The store is MANY-TO-ONE: an address maps to a
 * list of signed assertion records, one per (author, time, audience, parents). So a
 * block key alone does not identify what a category descended from — several agents may
 * have asserted the same content. `category` selects the CAT7 category; `sigDigest` selects
 * WHICH assertion over that address.
 *
 * ── THE ONE HARD RULE ─────────────────────────────────────────────────────────
 * `sigDigest` is a digest over the canonical signature PAYLOAD. NEVER over the
 * signature bytes.
 *
 * Node's Ed25519 (RFC 8032) is deterministic, so signature bytes are stable there and
 * a bytes-based digest would pass every JS test. Apple CryptoKit's Curve25519.Signing
 * is RANDOMIZED: the same (key, message) yields different bytes on each call. A ref
 * built from signature bytes would therefore be reproducible on Node, unreproducible
 * on iOS, and would break the mirror silently — green on the side that authored the
 * contract, broken on the side that proves it.
 *
 * The payload is what both SDKs agree on byte-for-byte, so the payload is what we
 * digest. `refDigest` takes the payload bytes and is the ONLY digest entry point.
 *
 * ── OPAQUE OUTSIDE THIS MODULE ────────────────────────────────────────────────
 * Refs are opaque strings everywhere else: stored, shipped, compared, never parsed or
 * assembled by hand. Two open items land here as one-file changes when they settle —
 * the exact ref FORMAT (three candidates under derivation) and the exact canonical
 * PAYLOAD FRAMING. Anything that string-splits a ref elsewhere defeats both.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const crypto = require('crypto');
const { CAT7_CATEGORIES } = require('./cmb');

/** Structural form of a v1 block key: bare `cmb-` + exactly 64 lowercase hex. */
const BLOCK_KEY_RE = /^cmb-[0-9a-f]{64}$/;
/** A digest as it appears in a ref: 64 lowercase hex (SHA-256, untruncated). */
const DIGEST_RE = /^[0-9a-f]{64}$/;

/** Separators. Neither can occur inside any component — a block key is
 *  prefix+hex, a category name is drawn from a fixed set, a digest is hex — so a ref
 *  needs no escaping and parsing can be strictly positional. */
const FIELD_SEP = '#';
const SIG_SEP = '~';

const FIELD_SET = new Set(CAT7_CATEGORIES);

/**
 * Digest the canonical signature payload. THE ONLY digest entry point for refs.
 *
 * Takes the payload BYTES (what the signer signs), never a signature. Keeping the
 * input behind this function is what lets the payload framing change in one place.
 *
 * @param {Buffer|Uint8Array} payload - canonical signature payload bytes.
 * @returns {string} 64 lowercase hex.
 */
function refDigest(payload) {
  if (!Buffer.isBuffer(payload) && !(payload instanceof Uint8Array)) {
    throw new TypeError('refDigest requires the canonical signature payload as bytes');
  }
  return crypto.createHash('sha256').update(Buffer.from(payload)).digest('hex');
}

/**
 * Mint a descent ref. Fail-closed: every component is validated, because a malformed
 * ref that is merely stored becomes an unresolvable descent edge later, far from here.
 *
 * @param {object} parts
 * @param {string} parts.blockKey  - `cmb-<64hex>`.
 * @param {string} parts.category     - a CAT7 category name.
 * @param {string} parts.sigDigest - 64 hex from `refDigest`.
 * @returns {string} the ref.
 */
function mintRef({ blockKey, category, sigDigest } = {}) {
  if (typeof blockKey !== 'string' || !BLOCK_KEY_RE.test(blockKey)) {
    throw new TypeError(`mintRef: blockKey must be cmb-<64hex>, got ${JSON.stringify(blockKey)}`);
  }
  if (typeof category !== 'string' || !FIELD_SET.has(category)) {
    throw new TypeError(`mintRef: category must be one of CAT7, got ${JSON.stringify(category)}`);
  }
  if (typeof sigDigest !== 'string' || !DIGEST_RE.test(sigDigest)) {
    throw new TypeError('mintRef: sigDigest must be 64 lowercase hex from refDigest(payload)');
  }
  return `${blockKey}${FIELD_SEP}${category}${SIG_SEP}${sigDigest}`;
}

/**
 * Parse a descent ref. Returns null for anything malformed — never throws, never
 * guesses. A caller that cannot resolve a ref should treat it as unresolved, which is
 * recoverable; a caller handed a half-parsed ref is not.
 *
 * @param {string} ref
 * @returns {{blockKey: string, category: string, sigDigest: string}|null}
 */
function parseRef(ref) {
  if (typeof ref !== 'string') return null;
  const hash = ref.indexOf(FIELD_SEP);
  if (hash < 0) return null;
  const tilde = ref.indexOf(SIG_SEP, hash + 1);
  if (tilde < 0) return null;
  // Exactly one of each separator: a second occurrence means this is not our format.
  if (ref.indexOf(FIELD_SEP, hash + 1) !== -1) return null;
  if (ref.indexOf(SIG_SEP, tilde + 1) !== -1) return null;

  const blockKey = ref.slice(0, hash);
  const category = ref.slice(hash + 1, tilde);
  const sigDigest = ref.slice(tilde + 1);

  if (!BLOCK_KEY_RE.test(blockKey)) return null;
  if (!FIELD_SET.has(category)) return null;
  if (!DIGEST_RE.test(sigDigest)) return null;
  return { blockKey, category, sigDigest };
}

/** Is this a well-formed descent ref? Cheap guard for callers that only need a yes/no. */
function isRef(ref) {
  return parseRef(ref) !== null;
}

module.exports = { mintRef, parseRef, isRef, refDigest };
