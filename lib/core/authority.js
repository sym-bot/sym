'use strict';

/**
 * @module sym/core/authority
 * @description MMP §6.6 authority statements: grant, revoke and endorse. Their shapes (the schema
 * authority-frame.schema.json, written out as code so that the schema and this check accept exactly
 * the same statements), their canonical signed bytes (`mmp-authority-v1`) and their ids, the anchor
 * pin and its digest, and the authority root. Signatures verify by the one rule of §18.3.2
 * (./ed25519.js). Resolution lives in lib/authority-store.js.
 *
 * Nothing here reads a clock: `issuedAt` is signed information, never an input to anything.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const crypto = require('crypto');
const { verifyStrict, isPrimeOrderKey } = require('./ed25519');

/** §19.1 constants for §6.6. */
const MAX_DELEGATION_DEPTH = 4;
const ANCHOR_MAX_KEYS = 16;
const AUTHORITY_QUOTA = 256;
const AUTHORITY_ANCHOR_QUOTA = 4096;
const AUTHORITY_DELEGATE_QUOTA = 16;
const AUTHORITY_SCOPE_MAX = 256;
const AUTHORITY_MAX_TARGETS = 64;
const AUTHORITY_PAGE = 64;
const AUTHORITY_PENDING_MAX = 64;
const AUTHORITY_PENDING_TIMEOUT = 10_000;

const DOMAIN = Buffer.from('mmp-authority-v1\n', 'utf8');
const PIN_DOMAIN = Buffer.from('mmp-anchor-pin-v1\n', 'utf8');
const ROOT_DOMAIN = Buffer.from('mmp-authority-root-v1\n', 'utf8');

const STATEMENT_ID = /^auth-[0-9a-f]{64}$/;
const PUBLIC_KEY = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;
const SIGNATURE = /^[A-Za-z0-9_-]{85}[AQgw]$/;
const NONCE = /^[A-Za-z0-9_-]{21}[AQgw]$/;
const NODE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const EXTENSION_ROLE = /^[a-z][a-z0-9]*(-[a-z0-9]+)+$/;
const SCOPE = /^[a-z][a-z0-9]*(-[a-z0-9]+)*:(?!\.+(\/|$))[A-Za-z0-9._~-]+(\/(?!\.+(\/|$))[A-Za-z0-9._~-]+)*$/;

const CORE_ROLES = new Set(['admin', 'validator', 'issuer', 'participant']);
/** Delegating roles: their holders sign statements, and a bucket counts their grants (§6.6.2, §6.6.6). */
const DELEGATING = new Set(['admin', 'validator', 'issuer']);

const isPlain = (v) => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
const onlyKeys = (o, allowed) => Object.keys(o).every((k) => allowed.has(k));

/** Whether `role` is a role a grant may confer (the schema's role): a core role or an extension role. */
function isRole(role) {
  return typeof role === 'string' && (CORE_ROLES.has(role) || (role.length <= 64 && EXTENSION_ROLE.test(role)));
}
/** A non-authority role: participant, or an extension role. */
const isNonAuthority = (role) => role === 'participant' || (isRole(role) && !CORE_ROLES.has(role));
const isDelegating = (role) => DELEGATING.has(role);

/** Whether `scope` is a scope (§6.6.2): an extension namespace and a path of segments, none only dots. */
function isScope(scope) {
  return typeof scope === 'string' && scope.length <= AUTHORITY_SCOPE_MAX && SCOPE.test(scope);
}

/**
 * Whether `child` equals or narrows `parent` (§6.6.2): the same string, or that string followed by
 * `/` and more segments. Byte for byte, never normalised. `parent` null is the whole mesh, which every
 * scope (and none) narrows; a null `child` under a scoped parent would widen it.
 */
function scopeNarrows(parent, child) {
  if (parent === null || parent === undefined) return true;
  if (child === null || child === undefined) return false;
  return child === parent || child.startsWith(`${parent}/`);
}

const GRANT_KEYS = new Set(['kind', 'authorisedBy', 'subject', 'role', 'scope', 'nonce', 'issuedAt', 'sigs']);
const TARGET_KEYS = new Set(['kind', 'authorisedBy', 'targets', 'nonce', 'issuedAt', 'sigs']);
const SUBJECT_KEYS = new Set(['nodeId', 'key']);
const SIG_KEYS = new Set(['key', 'sig']);

/**
 * §6.6.3 rule 1, the shape alone (cheap: no curve arithmetic): the schema's shape, canonical base64url
 * fields, a canonical subject nodeId, issuedAt at most 2^53 − 1, a scope that follows the grammar, and
 * unique targets numbering 1 to 64. The reason is returned when it is not. `malformedReason` adds the
 * subject key's order.
 * @returns {string|null} null when the shape is right
 */
function shapeReason(s) {
  if (!isPlain(s)) return 'not an object';
  if (s.kind !== 'grant' && s.kind !== 'revoke' && s.kind !== 'endorse') return 'kind';
  if (!onlyKeys(s, s.kind === 'grant' ? GRANT_KEYS : TARGET_KEYS)) return 'a member the schema does not define';
  if (!(s.authorisedBy === 'anchor' || (typeof s.authorisedBy === 'string' && STATEMENT_ID.test(s.authorisedBy)))) return 'authorisedBy';
  if (typeof s.nonce !== 'string' || !NONCE.test(s.nonce)) return 'nonce';
  if (s.issuedAt !== undefined && !(Number.isSafeInteger(s.issuedAt) && s.issuedAt >= 0)) return 'issuedAt';
  if (!Array.isArray(s.sigs) || s.sigs.length < 1 || s.sigs.length > ANCHOR_MAX_KEYS) return 'sigs';
  if (s.authorisedBy !== 'anchor' && s.sigs.length !== 1) return 'a non-anchor statement carries one signature';
  for (const e of s.sigs) {
    if (!isPlain(e) || !onlyKeys(e, SIG_KEYS)) return 'a signature entry';
    if (typeof e.key !== 'string' || !PUBLIC_KEY.test(e.key)) return 'a signature entry key';
    if (typeof e.sig !== 'string' || !SIGNATURE.test(e.sig)) return 'a signature';
  }
  if (s.kind === 'grant') {
    const sub = s.subject;
    if (!isPlain(sub) || !onlyKeys(sub, SUBJECT_KEYS)) return 'subject';
    if (typeof sub.nodeId !== 'string' || !NODE_ID.test(sub.nodeId)) return 'subject nodeId';
    if (typeof sub.key !== 'string' || !PUBLIC_KEY.test(sub.key)) return 'subject key';
    if (!isRole(s.role)) return 'role';
    if (s.scope !== undefined && !isScope(s.scope)) return 'scope';
  } else {
    if (!Array.isArray(s.targets) || s.targets.length < 1 || s.targets.length > AUTHORITY_MAX_TARGETS) return 'targets';
    const seen = new Set();
    for (const t of s.targets) {
      if (typeof t !== 'string' || !STATEMENT_ID.test(t)) return 'a target';
      if (seen.has(t)) return 'targets repeat';
      seen.add(t);
    }
  }
  return null;
}

/**
 * §6.6.3 rule 1, whole: well formed, and a grant's subject key the encoding of a point of prime order
 * (§18.3.2; the one check no JSON Schema can express: a key under which nobody can sign everything).
 * @returns {string|null} why not, or null
 */
function malformedReason(s) {
  const bad = shapeReason(s);
  if (bad) return bad;
  if (s.kind === 'grant' && !isPrimeOrderKey(s.subject.key)) return 'subject key is not of prime order';
  return null;
}

/** `<utf8 byte length>:<utf8 bytes>` (§8.8.4). */
function lp(str) {
  const b = Buffer.from(String(str), 'utf8');
  return Buffer.concat([Buffer.from(`${b.length}:`, 'utf8'), b]);
}
const bytewise = (a, b) => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));

/** The canonical signed bytes of a statement (§6.6.3). Signatures are not part of them. */
function payload(s) {
  const parts = [DOMAIN, lp(s.kind), lp(s.authorisedBy)];
  if (s.kind === 'grant') {
    parts.push(lp(s.subject.nodeId), lp(s.subject.key), lp(s.role), lp(s.scope === undefined ? '' : s.scope));
  } else {
    const targets = [...s.targets].sort(bytewise);
    parts.push(lp(String(targets.length)), ...targets.map(lp));
  }
  parts.push(lp(s.nonce), lp(s.issuedAt === undefined ? '' : String(s.issuedAt)));
  return Buffer.concat(parts);
}

/** A statement's id: `auth-` and the lowercase hex SHA-256 of its payload. Computed, never carried. */
function statementId(s) {
  return `auth-${crypto.createHash('sha256').update(payload(s)).digest('hex')}`;
}

/** The statement as the schema defines it, its signature entries as given (`sigs` replaced if passed). */
function canonicalStatement(s, sigs = s.sigs) {
  const c = { kind: s.kind, authorisedBy: s.authorisedBy };
  if (s.kind === 'grant') {
    c.subject = { nodeId: s.subject.nodeId, key: s.subject.key };
    c.role = s.role;
    if (s.scope !== undefined) c.scope = s.scope;
  } else {
    c.targets = [...s.targets];
  }
  c.nonce = s.nonce;
  if (s.issuedAt !== undefined) c.issuedAt = s.issuedAt;
  c.sigs = sigs.map((e) => ({ key: e.key, sig: e.sig }));
  return c;
}

/** A fresh 16-byte nonce, unpadded base64url. */
const freshNonce = () => crypto.randomBytes(16).toString('base64url');

/**
 * Sign the statement's payload with a raw Ed25519 private key (base64url) whose public key is
 * `publicKey`, adding the entry to `sigs` (pure Ed25519, no prehash). Returns the statement.
 */
function signStatement(s, privateKeyB64url, publicKeyB64url) {
  const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
  const priv = crypto.createPrivateKey({ key: Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(privateKeyB64url, 'base64url')]), format: 'der', type: 'pkcs8' });
  const sig = crypto.sign(null, payload(s), priv).toString('base64url');
  s.sigs = [...(Array.isArray(s.sigs) ? s.sigs : []), { key: publicKeyB64url, sig }];
  return s;
}

/** Whether a signature entry verifies over the statement's payload (§18.3.2). */
function entryVerifies(s, entry, bytes = payload(s)) {
  return !!entry && verifyStrict(bytes, entry.key, entry.sig);
}

/**
 * Parse an anchor pin (§6.6.1) from configuration: { threshold, keys: [{ key, nodeId? }] }, a single
 * { nodeId, publicKey } (the 1-of-1 pin of earlier revisions), or a "nodeId:publicKey" string.
 * Returns null when nothing is configured; throws when what is configured is not a pin.
 * @returns {{ threshold: number, members: { key: string, nodeId: string|null }[] }|null}
 */
function parsePin(cfg) {
  if (cfg === undefined || cfg === null || cfg === '') return null;
  let threshold;
  let keys;
  if (typeof cfg === 'string') {
    const trimmed = cfg.trim();
    if (trimmed.startsWith('{')) return parsePin(JSON.parse(trimmed));
    const i = trimmed.indexOf(':');
    if (i <= 0) throw new Error('anchor pin: expected "nodeId:publicKey" or a JSON pin');
    threshold = 1; keys = [{ nodeId: trimmed.slice(0, i), key: trimmed.slice(i + 1) }];
  } else if (isPlain(cfg) && typeof cfg.publicKey === 'string') {
    threshold = 1; keys = [{ nodeId: cfg.nodeId, key: cfg.publicKey }];
  } else if (isPlain(cfg) && Array.isArray(cfg.keys)) {
    threshold = cfg.threshold; keys = cfg.keys;
  } else {
    throw new Error('anchor pin: expected { threshold, keys: [{ key, nodeId? }] }');
  }
  if (!Array.isArray(keys) || keys.length < 1 || keys.length > ANCHOR_MAX_KEYS) throw new Error(`anchor pin: 1 to ${ANCHOR_MAX_KEYS} keys`);
  if (!Number.isSafeInteger(threshold) || threshold < 1 || threshold > keys.length) throw new Error('anchor pin: a threshold from 1 to the number of keys');
  const seen = new Set();
  const members = keys.map((k) => {
    const key = typeof k === 'string' ? k : k && k.key;
    const nodeId = (k && typeof k === 'object' && k.nodeId !== undefined && k.nodeId !== null) ? k.nodeId : null;
    // Kept in the key cache for good: a pinned key is checked on every anchor-level statement.
    if (typeof key !== 'string' || !PUBLIC_KEY.test(key) || !isPrimeOrderKey(key, { keep: true })) throw new Error('anchor pin: a key that is not an Ed25519 key of prime order');
    if (nodeId !== null && (typeof nodeId !== 'string' || !NODE_ID.test(nodeId))) throw new Error('anchor pin: a nodeId that is not a canonical lowercase UUID');
    if (seen.has(key)) throw new Error('anchor pin: keys must be distinct');
    seen.add(key);
    return { key, nodeId };
  });
  return { threshold, members };
}

/** The pin digest (§6.6.7): threshold, member count and the members (key, or key:nodeId under 1). */
function pinDigest(pin) {
  const members = pin.members.map((m) => (pin.threshold === 1 && m.nodeId ? `${m.key}:${m.nodeId}` : m.key)).sort(bytewise);
  return crypto.createHash('sha256')
    .update(Buffer.concat([PIN_DOMAIN, lp(String(pin.threshold)), lp(String(members.length)), ...members.map(lp)]))
    .digest('hex');
}

/** The authority root (§6.6.7) over a pin digest and the in-force ids. */
function authorityRoot(digest, inForceIds) {
  const ids = [...inForceIds].sort(bytewise);
  return crypto.createHash('sha256')
    .update(Buffer.concat([ROOT_DOMAIN, lp(digest), lp(String(ids.length)), ...ids.map(lp)]))
    .digest('hex');
}

module.exports = {
  MAX_DELEGATION_DEPTH, ANCHOR_MAX_KEYS, AUTHORITY_QUOTA, AUTHORITY_ANCHOR_QUOTA, AUTHORITY_DELEGATE_QUOTA,
  AUTHORITY_SCOPE_MAX, AUTHORITY_MAX_TARGETS, AUTHORITY_PAGE, AUTHORITY_PENDING_MAX, AUTHORITY_PENDING_TIMEOUT,
  STATEMENT_ID, PUBLIC_KEY, SIGNATURE, NODE_ID,
  isRole, isNonAuthority, isDelegating, isScope, scopeNarrows,
  shapeReason, malformedReason, payload, statementId, canonicalStatement, freshNonce, signStatement, entryVerifies,
  parsePin, pinDigest, authorityRoot, bytewise,
};
