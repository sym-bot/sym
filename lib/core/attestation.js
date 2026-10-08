'use strict';

/**
 * @module sym/core/attestation
 * @description Admission Attestations — signed, attributable per-category SVAF gating
 * records (MMP admission-attestation layer).
 *
 * When a receiver gates a CMB it produces an Admission Attestation: the per-category
 * verdict (Phase A) bound to the gated CMB (`of`), the attester's authenticated
 * identity (`by`), the permissioned roster it is scoped to, a per-attester
 * hash-chain position (`seq`,`prev`), and an Ed25519 signature. The attestation is
 * the durable record the audit trail is built from — tamper-evident against
 * MODIFICATION (any signed element mutated after signing breaks the signature).
 *
 * Trust rules NOT enforced here — the receiving node enforces them above this layer
 * (see docs: admission-attestation-design v2):
 *   (a) `role` is CLAIMED. The signature proves the key `by` authored the bytes,
 *       NOT that `by` holds that role. Resolve it against the receiver's in-force
 *       authority set when the weight is applied (MMP §6.6.10; `verifyAttestationRole`
 *       with a resolver) and weight by the RESOLVED role, never the stamped category.
 *   (b) OMISSION-evidence comes from the `seq`/`prev` chain + anchored checkpoints,
 *       reconciled by the node — signatures alone cannot prove absence.
 *   (c) The mechanism is scoped to a permissioned roster (roots authority, bounds
 *       gossip, sets the privacy boundary).
 * This module provides only the canonical payload + sign/verify + the role-claim
 * check; chain/roster/rate-limit/checkpointing live in `@sym-bot/sym`.
 *
 * sym 0.14 (design D1; MMP extension `sym-attest-v1`, draft spec PR meshcognition-website#27):
 * the signed constructions are the extension's 1.0.0 ones — each `lp`-encoded under its own
 * domain tag (`mmp-attest-v1`, `mmp-attest-checkpoint-v1`, `mmp-attest-witness-v1`), every field
 * signed (`method` and `assertionId` included), the chain link `prev` the SHA-256 of the previous
 * signature's BYTES, the checkpoint root a promote-odd Merkle tree with leaf and node tags. On the
 * wire the frames are `sym-attest-attestation`, `-checkpoint`, `-witness`, `-node-stats`, with the
 * extension's field names (`room`, `uptoSeq`); `toWire*` / `fromWire*` translate to and from the
 * store's own (`roster`, `upto_seq`), and `fromWire*` checks every field's shape and vocabulary. The
 * 0.13 constructions (a `|`-joined string, literal prefixes, a pair-with-itself Merkle tree) are not
 * produced or accepted on a Core Secure session.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const crypto = require('crypto');
const { privateKeyObject } = require('./cmb-signing');
const { CAT7_CATEGORIES, lp } = require('./cmb-encoder');
const { verifyStrict } = require('./ed25519');
/** Rank for weights (§6.6.10): anchor and admin 2, validator 1, every other role 0. */
const roleRank = (role) => (role === 'anchor' || role === 'admin' ? 2 : role === 'validator' ? 1 : 0);

/** Per-category verdict vocabulary (MMP §9.2.1; matches CATEGORY_VERDICT in svaf-baseline.js). */
const VERDICTS = Object.freeze(['admit', 'guard', 'redundant', 'reject', 'silent']);
/** Whole-record verdicts (MMP §9.2). */
const RECORD_VERDICTS = Object.freeze(['aligned', 'guarded', 'redundant', 'rejected']);

/** The extension's frame types (MMP §16.2 `<extension>-<name>`). */
const ATTEST_FRAME = Object.freeze({
  attestation: 'sym-attest-attestation',
  checkpoint: 'sym-attest-checkpoint',
  witness: 'sym-attest-witness',
  nodeStats: 'sym-attest-node-stats',
});
/** sym 0.13's bare frame types: legacy, never sent or accepted on a Core Secure session. */
const LEGACY_ATTEST_FRAMES = Object.freeze(['attestation', 'checkpoint', 'witness', 'node-stats']);

const DOMAIN = Object.freeze({
  attestation: 'mmp-attest-v1\n',
  checkpoint: 'mmp-attest-checkpoint-v1\n',
  witness: 'mmp-attest-witness-v1\n',
  leaf: 'mmp-attest-leaf-v1\n',
  node: 'mmp-attest-node-v1\n',
});

/** Canonical decimal ASCII for a non-negative safe integer (MMP §8.8.4); anything else throws. */
function decimal(n) {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error(`sym-attest: expected a non-negative safe integer, got ${JSON.stringify(n)}`);
  return String(n);
}
const text = (v) => (typeof v === 'string' ? v : '');
const nfc = (v) => text(v).normalize('NFC');
const roomOf = (o) => (typeof o.room === 'string' ? o.room : o.roster);
const positionOf = (o) => (o.uptoSeq !== undefined ? o.uptoSeq : o.upto_seq);

/**
 * The per-category verdicts as signed: the seven values in CAT7 order (kept for callers that show
 * them; the signature lp-encodes each, below).
 */
function canonicalCategories(categories) {
  return CAT7_CATEGORIES.map((f) => `${f}:${(categories && categories[f]) || ''}`).join(',');
}

/**
 * The signed bytes of an attestation (sym-attest-v1 §5.1):
 *   UTF8("mmp-attest-v1\n") || lp(of) || lp(assertionId) || lp(by) || lp(decimal(at)) ||
 *   lp(NFC(room)) || lp(method) || lp(verdict) || lp(each of the seven category verdicts, CAT7
 *   order) || lp(role) || lp(decimal(seq)) || lp(prev)
 * @param {object} a - attestation (the store's `roster` is read as `room`)
 * @returns {Buffer}
 */
function attestationPayload(a) {
  const cats = (a && a.categories) || {};
  return Buffer.concat([
    Buffer.from(DOMAIN.attestation, 'utf8'),
    lp(text(a.of)), lp(text(a.assertionId)), lp(text(a.by)), lp(decimal(a.at)), lp(nfc(roomOf(a))),
    lp(text(a.method)), lp(text(a.verdict)),
    ...CAT7_CATEGORIES.map((f) => lp(text(cats[f]))),
    lp(text(a.role)), lp(decimal(a.seq)), lp(text(a.prev)),
  ]);
}

function sign(payload, privateKeyB64url) {
  return crypto.sign(null, payload, privateKeyObject(privateKeyB64url)).toString('base64url');
}
function verify(payloadOf, obj, publicKeyB64url) {
  if (!obj || !obj.sig || obj.sigAlg !== 'ed25519') return { signed: false, valid: false };
  if (!publicKeyB64url) return { signed: true, valid: false, error: 'no-public-key' };
  try {
    // MMP §18.3.2: the one Ed25519 rule.
    const ok = verifyStrict(payloadOf(obj), publicKeyB64url, obj.sig);
    return ok ? { signed: true, valid: true } : { signed: true, valid: false, error: 'bad-signature' };
  } catch (e) {
    return { signed: true, valid: false, error: e.message };
  }
}

/**
 * Sign an attestation in place with the attester's raw Ed25519 private key (base64url). Sets `sig`
 * and `sigAlg`. Returns the attestation.
 */
function signAttestation(att, privateKeyB64url) {
  if (!att || !att.of || !att.by) throw new Error('signAttestation requires of + by');
  att.sig = sign(attestationPayload(att), privateKeyB64url);
  att.sigAlg = 'ed25519';
  return att;
}

/**
 * Verify an attestation signature against the attester's raw Ed25519 public key. Proves the key
 * `by` authored these exact bytes — NOT that `by` holds the claimed `role` (verifyAttestationRole).
 * @returns {{ signed: boolean, valid: boolean, error?: string }}
 */
function verifyAttestation(att, attesterPublicKeyB64url) {
  return verify(attestationPayload, att, attesterPublicKeyB64url);
}

/**
 * Check the CLAIMED role against the role resolved for `by` from the receiver's in-force authority
 * set now (§6.6.10). `resolveRole(by) → role | null` is injected by the node.
 * @returns {{ claimed: string, resolved: string, matches: boolean, rank: number }}
 */
function verifyAttestationRole(att, resolveRole) {
  const claimed = (att && att.role) || 'participant';
  // Resolved against the receiver's in-force set when the weight is applied (§6.6.10): the
  // attestation's own time is not passed, since authority carries none.
  const resolved = ((typeof resolveRole === 'function' && att) ? resolveRole(att.by) : null) || 'participant';
  return { claimed, resolved, matches: resolved === claimed, rank: roleRank(resolved) };
}

/**
 * The chain link (sym-attest-v1 §5.1): `prev` of the next attestation is the lowercase hex SHA-256
 * of this one's signature BYTES; `genesis` before the first.
 */
function chainLink(sigB64url) {
  return crypto.createHash('sha256').update(Buffer.from(String(sigB64url), 'base64url')).digest('hex');
}

/**
 * The checkpoint root (sym-attest-v1 §5.2): a promote-odd Merkle root over the attestations'
 * signature bytes, with separate leaf and node domain tags; an unpaired last node is carried up
 * unchanged, never paired with itself.
 *   leaf(i) = SHA-256("mmp-attest-leaf-v1\n" || sigBytes(i)),  node(l, r) = SHA-256("mmp-attest-node-v1\n" || l || r)
 * @param {string[]} sigs - base64url signatures, seq 1..uptoSeq in order
 * @returns {string} lowercase hex
 */
function attestMerkleRoot(sigs) {
  const H = (...parts) => crypto.createHash('sha256').update(Buffer.concat(parts)).digest();
  const leafTag = Buffer.from(DOMAIN.leaf, 'utf8');
  const nodeTag = Buffer.from(DOMAIN.node, 'utf8');
  let level = (sigs || []).map((s) => H(leafTag, Buffer.from(String(s), 'base64url')));
  if (level.length === 0) return H(leafTag).toString('hex');
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(i + 1 < level.length ? H(nodeTag, level[i], level[i + 1]) : level[i]);
    level = next;
  }
  return level[0].toString('hex');
}

// ── Checkpoints + witnesses (omission-evidence) ─────────────────────────────────────

/**
 * The signed bytes of a checkpoint (sym-attest-v1 §5.2):
 *   UTF8("mmp-attest-checkpoint-v1\n") || lp(by) || lp(NFC(room)) || lp(decimal(uptoSeq)) || lp(root) || lp(decimal(at))
 */
function checkpointPayload(cp) {
  return Buffer.concat([
    Buffer.from(DOMAIN.checkpoint, 'utf8'),
    lp(text(cp.by)), lp(nfc(roomOf(cp))), lp(decimal(positionOf(cp))), lp(text(cp.root)), lp(decimal(cp.at)),
  ]);
}

/** Sign a checkpoint in place with the attester's raw Ed25519 private key (base64url). */
function signCheckpoint(cp, privateKeyB64url) {
  if (!cp || !cp.by || positionOf(cp) === undefined || !cp.root) throw new Error('signCheckpoint requires by + uptoSeq + root');
  cp.sig = sign(checkpointPayload(cp), privateKeyB64url);
  cp.sigAlg = 'ed25519';
  return cp;
}

/** Verify a checkpoint's signature against the attester's raw Ed25519 public key. */
function verifyCheckpoint(cp, attesterPublicKeyB64url) {
  return verify(checkpointPayload, cp, attesterPublicKeyB64url);
}

/**
 * The signed bytes of a witness (sym-attest-v1 §5.3):
 *   UTF8("mmp-attest-witness-v1\n") || lp(attester) || lp(NFC(room)) || lp(decimal(uptoSeq)) ||
 *   lp(root) || lp(by) || lp(role) || lp(decimal(at))
 */
function witnessPayload(w) {
  return Buffer.concat([
    Buffer.from(DOMAIN.witness, 'utf8'),
    lp(text(w.attester)), lp(nfc(roomOf(w))), lp(decimal(positionOf(w))), lp(text(w.root)),
    lp(text(w.by)), lp(text(w.role)), lp(decimal(w.at)),
  ]);
}

/** Sign a witness countersignature in place with the witness's raw Ed25519 private key. */
function signWitness(w, privateKeyB64url) {
  if (!w || !w.attester || !w.by || positionOf(w) === undefined || !w.root) throw new Error('signWitness requires attester + by + uptoSeq + root');
  w.sig = sign(witnessPayload(w), privateKeyB64url);
  w.sigAlg = 'ed25519';
  return w;
}

/** Verify a witness countersignature against the WITNESS's raw Ed25519 public key. */
function verifyWitness(w, witnessPublicKeyB64url) {
  return verify(witnessPayload, w, witnessPublicKeyB64url);
}

// ── The wire form (sym-attest-v1 §5) ─────────────────────────────────────────────────

const ID_RE = /^[\x21-\x7e]{1,128}$/;
const TOKEN_RE = /^[a-z0-9][a-z0-9_-]{0,31}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const SIG_RE = /^[A-Za-z0-9_-]{86}$/;
const isId = (v) => typeof v === 'string' && ID_RE.test(v);
const isRoom = (v) => typeof v === 'string' && v.length > 0 && v.length <= 256;
const isTime = (v) => Number.isSafeInteger(v) && v >= 0;
const isPos = (v) => Number.isSafeInteger(v) && v >= 1;

/** An internal attestation as the `sym-attest-attestation` frame carries it. */
function toWireAttestation(a) {
  const categories = {};
  for (const f of CAT7_CATEGORIES) categories[f] = a.categories ? a.categories[f] : undefined;
  return { of: a.of, assertionId: a.assertionId, by: a.by, at: a.at, room: roomOf(a), method: a.method, verdict: a.verdict, categories, role: a.role, seq: a.seq, prev: a.prev, sigAlg: a.sigAlg, sig: a.sig };
}

/**
 * A `sym-attest-attestation` frame's attestation, checked field by field (§6 step 1), as the
 * store holds it — or null.
 */
function fromWireAttestation(w) {
  if (!w || typeof w !== 'object' || Array.isArray(w)) return null;
  if (typeof w.of !== 'string' || !/^cmb-[0-9a-f]{64}$/.test(w.of)) return null;
  if (typeof w.assertionId !== 'string' || !/^asrt-[0-9a-f]{64}$/.test(w.assertionId)) return null;
  if (!isId(w.by) || !isTime(w.at) || !isRoom(w.room)) return null;
  if (typeof w.method !== 'string' || !TOKEN_RE.test(w.method)) return null;
  if (!RECORD_VERDICTS.includes(w.verdict)) return null;
  const c = w.categories;
  if (!c || typeof c !== 'object' || Array.isArray(c)) return null;
  const categories = {};
  for (const f of CAT7_CATEGORIES) { if (!VERDICTS.includes(c[f])) return null; categories[f] = c[f]; }
  if (Object.keys(c).length !== CAT7_CATEGORIES.length) return null;
  if (typeof w.role !== 'string' || !TOKEN_RE.test(w.role)) return null;
  if (!isPos(w.seq)) return null;
  if (w.seq === 1 ? w.prev !== 'genesis' : !(typeof w.prev === 'string' && HEX64.test(w.prev))) return null;
  if (w.sigAlg !== 'ed25519' || typeof w.sig !== 'string' || !SIG_RE.test(w.sig)) return null;
  return { of: w.of, assertionId: w.assertionId, by: w.by, at: w.at, roster: w.room, method: w.method, verdict: w.verdict, categories, role: w.role, seq: w.seq, prev: w.prev, sigAlg: w.sigAlg, sig: w.sig };
}

function toWireCheckpoint(cp) {
  return { by: cp.by, room: roomOf(cp), uptoSeq: positionOf(cp), root: cp.root, at: cp.at, sigAlg: cp.sigAlg, sig: cp.sig };
}
function fromWireCheckpoint(w) {
  if (!w || typeof w !== 'object' || Array.isArray(w)) return null;
  if (!isId(w.by) || !isRoom(w.room) || !isPos(w.uptoSeq) || typeof w.root !== 'string' || !HEX64.test(w.root) || !isTime(w.at)) return null;
  if (w.sigAlg !== 'ed25519' || typeof w.sig !== 'string' || !SIG_RE.test(w.sig)) return null;
  return { type: 'checkpoint', by: w.by, roster: w.room, upto_seq: w.uptoSeq, root: w.root, at: w.at, sigAlg: w.sigAlg, sig: w.sig };
}

function toWireWitness(x) {
  return { attester: x.attester, room: roomOf(x), uptoSeq: positionOf(x), root: x.root, by: x.by, role: x.role, at: x.at, sigAlg: x.sigAlg, sig: x.sig };
}
function fromWireWitness(w) {
  if (!w || typeof w !== 'object' || Array.isArray(w)) return null;
  if (!isId(w.attester) || !isRoom(w.room) || !isPos(w.uptoSeq) || typeof w.root !== 'string' || !HEX64.test(w.root)) return null;
  if (!isId(w.by) || typeof w.role !== 'string' || !TOKEN_RE.test(w.role) || !isTime(w.at)) return null;
  if (w.sigAlg !== 'ed25519' || typeof w.sig !== 'string' || !SIG_RE.test(w.sig)) return null;
  return { type: 'witness', attester: w.attester, roster: w.room, upto_seq: w.uptoSeq, root: w.root, by: w.by, role: w.role, at: w.at, sigAlg: w.sigAlg, sig: w.sig };
}

/** `sym-attest-node-stats` (§5.4): unsigned, informational, attributed to the session's peer. */
function fromWireNodeStats(w) {
  if (!w || typeof w !== 'object' || Array.isArray(w)) return null;
  const n = (v) => Number.isSafeInteger(v) && v >= 0;
  if (!n(w.emitted) || !n(w.admitted) || !n(w.memory) || !isTime(w.at)) return null;
  return { emitted: w.emitted, admitted: w.admitted, memory: w.memory, at: w.at };
}

module.exports = {
  attestationPayload,
  canonicalCategories,
  signAttestation,
  verifyAttestation,
  verifyAttestationRole,
  checkpointPayload,
  signCheckpoint,
  verifyCheckpoint,
  witnessPayload,
  signWitness,
  verifyWitness,
  chainLink,
  attestMerkleRoot,
  toWireAttestation, fromWireAttestation,
  toWireCheckpoint, fromWireCheckpoint,
  toWireWitness, fromWireWitness,
  fromWireNodeStats,
  ATTEST_FRAME, LEGACY_ATTEST_FRAMES, ATTEST_DOMAIN: DOMAIN,
  VERDICTS, RECORD_VERDICTS,
};
