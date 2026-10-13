'use strict';

/**
 * @module sym/core/ed25519
 * @description THE ONE Ed25519 VERIFICATION RULE (MMP §18.3.2). RFC 8032 lets verifiers differ, in
 * the equation they check and in which encodings and small-order points they accept, and two nodes
 * that verify differently hold different valid sets from the same bytes. So every signature sym
 * checks — authority statements, records, handshake proofs, attestations, room-join grants, tether
 * attestations, relocation bundles — goes through `verifyStrict` and nothing else.
 *
 * A signature R ‖ S (64 bytes) by a key A (32 bytes) over M is valid iff:
 *   1. A is a canonical encoding of a curve point (y < p; x = 0 never with the sign bit set);
 *   2. A has prime order: [L]A is the identity and A is not;
 *   3. R is a canonical encoding of a point of prime order;
 *   4. S, little-endian, is less than L;
 *   5. [S]B = R + [k]A, k = SHA-512(R ‖ A ‖ M) mod L.
 *
 * On Node, crypto.verify (OpenSSL) checks the cofactorless equation by comparing R's bytes with the
 * encoding of [S]B − [k]A. With rules 1, 2 and 4 checked first, and R not the identity's encoding
 * (01 followed by 31 zero bytes), its acceptance means R's bytes are the canonical encoding of a point
 * of the prime-order subgroup other than the identity, which is rule 3 (§18.3.2, informative). Rules
 * 1 and 2 cost one scalar multiplication per key; the result is cached per key.
 *
 * Implemented here from the curve's definition (extended twisted Edwards coordinates, BigInt): the
 * spec's reference construction is an oracle for the tests only.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const crypto = require('crypto');

const P = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const mod = (a, m = P) => { const r = a % m; return r >= 0n ? r : r + m; };
function pow(b, e, m = P) {
  let r = 1n; b = mod(b, m);
  while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; }
  return r;
}
const inv = (a) => pow(a, P - 2n);
const D = mod(-121665n * inv(121666n));
const D2 = mod(2n * D);
const SQRT_M1 = pow(2n, (P - 1n) / 4n);

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const IDENTITY_ENCODING = Buffer.concat([Buffer.from([1]), Buffer.alloc(31)]);

/** Little-endian bytes to BigInt. */
function leToBig(buf) {
  let n = 0n;
  for (let i = buf.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(buf[i]);
  return n;
}

/**
 * Decode a 32-byte encoding to an extended point [X, Y, Z, T], or null when it is not a canonical
 * encoding of a curve point (rule 1): y ≥ p, no square root for x, or x = 0 with the sign bit set.
 */
function decodePoint(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length !== 32) return null;
  const last = bytes[31];
  const sign = (last & 0x80) !== 0;
  const yBytes = Buffer.from(bytes); yBytes[31] = last & 0x7f;
  const y = leToBig(yBytes);
  if (y >= P) return null;
  const y2 = (y * y) % P;
  const u = mod(y2 - 1n);
  const v = mod(D * y2 + 1n);
  // x = u v^3 (u v^7)^((p-5)/8)
  const v3 = (v * v % P) * v % P;
  const v7 = (v3 * v3 % P) * v % P;
  let x = (u * v3 % P) * pow(u * v7 % P, (P - 5n) / 8n) % P;
  const vx2 = v * (x * x % P) % P;
  if (vx2 === u) { /* x is a root */ }
  else if (vx2 === mod(-u)) x = (x * SQRT_M1) % P;
  else return null;
  if (x === 0n && sign) return null;
  if (((x & 1n) === 1n) !== sign) x = mod(-x);
  return [x, y, 1n, (x * y) % P];
}

const IDENTITY = [0n, 1n, 1n, 0n];
function add(p1, p2) {
  const [X1, Y1, Z1, T1] = p1; const [X2, Y2, Z2, T2] = p2;
  const A = mod((Y1 - X1) * (Y2 - X2));
  const B = mod((Y1 + X1) * (Y2 + X2));
  const C = mod(T1 * D2 % P * T2);
  const Dd = mod(2n * Z1 * Z2);
  const E = mod(B - A); const F = mod(Dd - C); const G = mod(Dd + C); const H = mod(B + A);
  return [mod(E * F), mod(G * H), mod(F * G), mod(E * H)];
}
function isIdentity([X, Y, Z]) { return mod(X) === 0n && mod(Y - Z) === 0n; }
function mul(pt, k) {
  let r = IDENTITY; let q = pt;
  while (k > 0n) { if (k & 1n) r = add(r, q); q = add(q, q); k >>= 1n; }
  return r;
}

/**
 * Rules 1 and 2 for a 32-byte key, cached per key: a canonical encoding of a point of prime order.
 * The cache is least recently used, so keys that keep being used stay and a flood of fresh keys
 * evicts only keys nobody used since; `keep` (the pinned anchor keys) are never evicted.
 */
const KEY_CACHE = new Map();
let KEY_CACHE_MAX = 8192;
const KEPT = new Map();
function isPrimeOrderKey(key, { keep = false } = {}) {
  const bytes = toBytes(key, 32);
  if (!bytes) return false;
  const k = bytes.toString('hex');
  const kept = KEPT.get(k);
  if (kept !== undefined) return kept;
  let ok = KEY_CACHE.get(k);
  if (ok !== undefined) {
    KEY_CACHE.delete(k); // most recently used last
  } else {
    const pt = decodePoint(bytes);
    ok = !!pt && !isIdentity(pt) && isIdentity(mul(pt, L));
  }
  if (keep) { KEPT.set(k, ok); KEY_CACHE.delete(k); return ok; }
  if (KEY_CACHE.size >= KEY_CACHE_MAX) KEY_CACHE.delete(KEY_CACHE.keys().next().value);
  KEY_CACHE.set(k, ok);
  return ok;
}

/**
 * Whether rules 1 and 2 are already known for `key` (cached): a check of a key not yet known costs one
 * scalar multiplication, far more than a signature check, so a caller that budgets work can charge
 * for it before it is spent.
 */
function isKeyKnown(key) {
  const bytes = toBytes(key, 32);
  if (!bytes) return false;
  const k = bytes.toString('hex');
  return KEPT.has(k) || KEY_CACHE.has(k);
}

/** Bytes of a Buffer or a base64url string, of exactly `n` bytes, or null. */
function toBytes(v, n) {
  let b = null;
  if (Buffer.isBuffer(v)) b = v;
  else if (v instanceof Uint8Array) b = Buffer.from(v);
  else if (typeof v === 'string') { try { b = Buffer.from(v, 'base64url'); } catch { b = null; } }
  return b && b.length === n ? b : null;
}

/**
 * MMP §18.3.2: whether `signature` (64 bytes) by `publicKey` (32 bytes) over `message` is valid.
 * Keys and signatures are Buffers or base64url strings. Never throws.
 * @param {Buffer|Uint8Array} message
 * @param {Buffer|string} publicKey
 * @param {Buffer|string} signature
 * @returns {boolean}
 */
function verifyStrict(message, publicKey, signature) {
  try {
    const A = toBytes(publicKey, 32);
    const sig = toBytes(signature, 64);
    if (!A || !sig) return false;
    if (!isPrimeOrderKey(A)) return false;                 // rules 1 and 2
    const R = sig.subarray(0, 32);
    if (R.equals(IDENTITY_ENCODING)) return false;         // R is not the identity
    if (leToBig(sig.subarray(32)) >= L) return false;      // rule 4
    const keyObject = crypto.createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, A]), format: 'der', type: 'spki' });
    return crypto.verify(null, Buffer.isBuffer(message) ? message : Buffer.from(message), keyObject, sig); // rule 5, and so rule 3
  } catch {
    return false;
  }
}

/**
 * Rules 1 to 4 as named reasons, in the order §18.3.2's vector names them (for tests and reports):
 * the first pre-check that fails, or null.
 */
function precheckFailure(publicKey, signature) {
  const A = toBytes(publicKey, 32);
  const sig = toBytes(signature, 64);
  if (!A || !sig) return 'malformed';
  const a = decodePoint(A);
  if (!a) return 'A is not a canonical encoding of a curve point';
  if (isIdentity(a) || !isIdentity(mul(a, L))) return 'A is not of prime order';
  const r = decodePoint(Buffer.from(sig.subarray(0, 32)));
  if (!r) return 'R is not a canonical encoding of a curve point';
  if (isIdentity(r) || !isIdentity(mul(r, L))) return 'R is not of prime order';
  if (leToBig(sig.subarray(32)) >= L) return 'S is not less than L';
  return null;
}

/** @private Tests only: a smaller cache, to show what it keeps. Returns the previous size. */
function _setKeyCacheMax(n) { const was = KEY_CACHE_MAX; KEY_CACHE_MAX = n; while (KEY_CACHE.size > KEY_CACHE_MAX) KEY_CACHE.delete(KEY_CACHE.keys().next().value); return was; }

module.exports = { verifyStrict, isPrimeOrderKey, isKeyKnown, precheckFailure, L, _setKeyCacheMax };
