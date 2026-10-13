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
  chain: 'mmp-attest-chain-v1\n',
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
const fromOf = (o) => (o.fromSeq !== undefined ? o.fromSeq : o.from_seq);

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
 * The segment root (sym-attest-v1 §5.2): a promote-odd Merkle root over the signature bytes of the
 * attestations seq fromSeq..uptoSeq, in order, with separate leaf and node domain tags; an unpaired
 * last node is carried up unchanged, never paired with itself.
 *   leaf(i) = SHA-256("mmp-attest-leaf-v1\n" || sigBytes(i)),  node(l, r) = SHA-256("mmp-attest-node-v1\n" || l || r)
 * @param {string[]} sigs - base64url signatures, in seq order (at least one)
 * @returns {string} lowercase hex
 */
function attestMerkleRoot(sigs) {
  const H = (...parts) => crypto.createHash('sha256').update(Buffer.concat(parts)).digest();
  const leafTag = Buffer.from(DOMAIN.leaf, 'utf8');
  const nodeTag = Buffer.from(DOMAIN.node, 'utf8');
  let level = (sigs || []).map((s) => H(leafTag, Buffer.from(String(s), 'base64url')));
  if (level.length === 0) throw new Error('sym-attest: a segment holds at least one attestation');
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(i + 1 < level.length ? H(nodeTag, level[i], level[i + 1]) : level[i]);
    level = next;
  }
  return level[0].toString('hex');
}

/**
 * The chained checkpoint root (sym-attest-v1 §5.2, MMP 2.0 update 1): it commits to the previous
 * checkpoint's root and the segment since it, so it commits to the whole history from seq 1 while the
 * attester holds only its last segment.
 *   root = lowercaseHex(SHA-256(UTF8("mmp-attest-chain-v1\n") || lp(prev) || lp(decimal(fromSeq)) ||
 *                               lp(decimal(uptoSeq)) || lp(lowercaseHex(segment))))
 * `prev` is `genesis` for an attester's first checkpoint (fromSeq 1).
 */
function attestCheckpointRoot({ prev, fromSeq, uptoSeq, segmentRoot }) {
  return crypto.createHash('sha256').update(Buffer.concat([
    Buffer.from(DOMAIN.chain, 'utf8'),
    lp(text(prev)), lp(decimal(fromSeq)), lp(decimal(uptoSeq)), lp(text(segmentRoot)),
  ])).digest('hex');
}

/**
 * Whether two checkpoints from one attester prove that it signed two histories (sym-attest-v1 §5.2):
 * not the same checkpoint (fromSeq, uptoSeq, prev and root), and their ranges overlap or they name the
 * same prev. One chain does neither: its ranges are consecutive and each prev has one successor.
 * @returns {string[]} the reasons ('overlapping ranges', 'same prev'); empty when they can lie on one chain
 */
function checkpointConflict(a, b) {
  if (!a || !b || a.by !== b.by) return [];
  const [af, au, bf, bu] = [fromOf(a), positionOf(a), fromOf(b), positionOf(b)];
  if (af === bf && au === bu && a.prev === b.prev && a.root === b.root) return [];
  const reasons = [];
  if (af <= bu && bf <= au) reasons.push('overlapping ranges');
  if (a.prev === b.prev) reasons.push('same prev');
  return reasons;
}

/**
 * The link checks (sym-attest-v1 §5.2): the range is not reversed, prev is genesis exactly when
 * fromSeq is 1, and when the checkpoint named by prev is held the new one starts right after it. A
 * checkpoint that fails is malformed, never evidence.
 * @param {object} cp
 * @param {object|null} [prevCheckpoint] - the held checkpoint whose root is cp.prev, if any
 */
function checkpointLinkValid(cp, prevCheckpoint = null) {
  const f = fromOf(cp); const u = positionOf(cp);
  if (!Number.isSafeInteger(f) || !Number.isSafeInteger(u) || u < f || f < 1) return false;
  if ((f === 1) !== (cp.prev === 'genesis')) return false;
  if (prevCheckpoint && prevCheckpoint.root === cp.prev && f !== positionOf(prevCheckpoint) + 1) return false;
  return true;
}

// ── Checkpoints + witnesses (omission-evidence) ─────────────────────────────────────

/**
 * The signed bytes of a checkpoint (sym-attest-v1 §5.2):
 *   UTF8("mmp-attest-checkpoint-v1\n") || lp(by) || lp(NFC(room)) || lp(decimal(fromSeq)) ||
 *   lp(decimal(uptoSeq)) || lp(prev) || lp(root) || lp(decimal(at))
 */
function checkpointPayload(cp) {
  return Buffer.concat([
    Buffer.from(DOMAIN.checkpoint, 'utf8'),
    lp(text(cp.by)), lp(nfc(roomOf(cp))), lp(decimal(fromOf(cp))), lp(decimal(positionOf(cp))),
    lp(text(cp.prev)), lp(text(cp.root)), lp(decimal(cp.at)),
  ]);
}

/** Sign a checkpoint in place with the attester's raw Ed25519 private key (base64url). */
function signCheckpoint(cp, privateKeyB64url) {
  if (!cp || !cp.by || fromOf(cp) === undefined || positionOf(cp) === undefined || !cp.prev || !cp.root) throw new Error('signCheckpoint requires by + fromSeq + uptoSeq + prev + root');
  cp.sig = sign(checkpointPayload(cp), privateKeyB64url);
  cp.sigAlg = 'ed25519';
  return cp;
}

/** Verify a checkpoint's signature against the attester's raw Ed25519 public key. */
function verifyCheckpoint(cp, attesterPublicKeyB64url) {
  try { return verify(checkpointPayload, cp, attesterPublicKeyB64url); } catch (e) { return { signed: !!(cp && cp.sig), valid: false, error: e.message }; }
}

/**
 * The signed bytes of a witness (sym-attest-v1 §5.3): it carries the witnessed checkpoint's range,
 * so witnesses alone can show a fork:
 *   UTF8("mmp-attest-witness-v1\n") || lp(attester) || lp(NFC(room)) || lp(decimal(fromSeq)) ||
 *   lp(decimal(uptoSeq)) || lp(root) || lp(by) || lp(role) || lp(decimal(at))
 */
function witnessPayload(w) {
  return Buffer.concat([
    Buffer.from(DOMAIN.witness, 'utf8'),
    lp(text(w.attester)), lp(nfc(roomOf(w))), lp(decimal(fromOf(w))), lp(decimal(positionOf(w))), lp(text(w.root)),
    lp(text(w.by)), lp(text(w.role)), lp(decimal(w.at)),
  ]);
}

/** Sign a witness countersignature in place with the witness's raw Ed25519 private key. */
function signWitness(w, privateKeyB64url) {
  if (!w || !w.attester || !w.by || fromOf(w) === undefined || positionOf(w) === undefined || !w.root) throw new Error('signWitness requires attester + by + fromSeq + uptoSeq + root');
  w.sig = sign(witnessPayload(w), privateKeyB64url);
  w.sigAlg = 'ed25519';
  return w;
}

/** Verify a witness countersignature against the WITNESS's raw Ed25519 public key. */
function verifyWitness(w, witnessPublicKeyB64url) {
  try { return verify(witnessPayload, w, witnessPublicKeyB64url); } catch (e) { return { signed: !!(w && w.sig), valid: false, error: e.message }; }
}

// ── The wire form (sym-attest-v1 §5) ─────────────────────────────────────────────────

// sym-attest-v1 as MMP 2.0 update 1 registers it (#27): the attester and witness are nodes, so a
// lowercase UUID (§3.1.1); a role is any role a grant can confer (§6.6.2: up to 64 characters); a
// method a short token.
const ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const METHOD_RE = /^[a-z0-9][a-z0-9_-]{0,31}$/;
const ROLE_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
/** The members of an attestation, exactly: the object is closed. */
const ATTESTATION_MEMBERS = new Set(['of', 'assertionId', 'by', 'at', 'room', 'method', 'verdict', 'categories', 'role', 'seq', 'prev', 'sigAlg', 'sig']);
const HEX64 = /^[0-9a-f]{64}$/;
const SIG_RE = /^[A-Za-z0-9_-]{86}$/;
const isId = (v) => typeof v === 'string' && ID_RE.test(v);
// A room is a §5.8 identifier (sym-attest-frame.schema.json `room`, MMP 2.0 update 1).
const { isRoomId: isRoom } = require('./room-id');
// time and position at most 2^53 − 1 (sym-attest-frame.schema.json): every parser reads the signed integer.
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
  for (const k of Object.keys(w)) if (!ATTESTATION_MEMBERS.has(k)) return null; // closed (#27)
  if (typeof w.of !== 'string' || !/^cmb-[0-9a-f]{64}$/.test(w.of)) return null;
  if (typeof w.assertionId !== 'string' || !/^asrt-[0-9a-f]{64}$/.test(w.assertionId)) return null;
  if (!isId(w.by) || !isTime(w.at) || !isRoom(w.room)) return null;
  if (typeof w.method !== 'string' || !METHOD_RE.test(w.method)) return null;
  if (!RECORD_VERDICTS.includes(w.verdict)) return null;
  const c = w.categories;
  if (!c || typeof c !== 'object' || Array.isArray(c)) return null;
  const categories = {};
  for (const f of CAT7_CATEGORIES) { if (!VERDICTS.includes(c[f])) return null; categories[f] = c[f]; }
  if (Object.keys(c).length !== CAT7_CATEGORIES.length) return null;
  if (typeof w.role !== 'string' || !ROLE_RE.test(w.role)) return null;
  if (!isPos(w.seq)) return null;
  if (w.seq === 1 ? w.prev !== 'genesis' : !(typeof w.prev === 'string' && HEX64.test(w.prev))) return null;
  if (w.sigAlg !== 'ed25519' || typeof w.sig !== 'string' || !SIG_RE.test(w.sig)) return null;
  return { of: w.of, assertionId: w.assertionId, by: w.by, at: w.at, roster: w.room, method: w.method, verdict: w.verdict, categories, role: w.role, seq: w.seq, prev: w.prev, sigAlg: w.sigAlg, sig: w.sig };
}

const CHECKPOINT_MEMBERS = new Set(['by', 'room', 'fromSeq', 'uptoSeq', 'prev', 'root', 'at', 'sigAlg', 'sig']);
const WITNESS_MEMBERS = new Set(['attester', 'room', 'fromSeq', 'uptoSeq', 'root', 'by', 'role', 'at', 'sigAlg', 'sig']);
const isLink = (v) => v === 'genesis' || (typeof v === 'string' && HEX64.test(v));

function toWireCheckpoint(cp) {
  return { by: cp.by, room: roomOf(cp), fromSeq: fromOf(cp), uptoSeq: positionOf(cp), prev: cp.prev, root: cp.root, at: cp.at, sigAlg: cp.sigAlg, sig: cp.sig };
}
/** A `sym-attest-checkpoint` frame's checkpoint, checked against the schema (closed; prev genesis
 *  exactly when fromSeq is 1; uptoSeq not below fromSeq), as the store holds it — or null. */
function fromWireCheckpoint(w) {
  if (!w || typeof w !== 'object' || Array.isArray(w)) return null;
  for (const k of Object.keys(w)) if (!CHECKPOINT_MEMBERS.has(k)) return null;
  if (!isId(w.by) || !isRoom(w.room) || !isPos(w.fromSeq) || !isPos(w.uptoSeq) || !isLink(w.prev) || typeof w.root !== 'string' || !HEX64.test(w.root) || !isTime(w.at)) return null;
  // §6 step 1: the range is not reversed, and prev is genesis exactly when fromSeq is 1. (The prev link
  // to a held checkpoint is checked after step 4, against what is held.)
  if (w.uptoSeq < w.fromSeq || (w.fromSeq === 1) !== (w.prev === 'genesis')) return null;
  if (w.sigAlg !== 'ed25519' || typeof w.sig !== 'string' || !SIG_RE.test(w.sig)) return null;
  return { type: 'checkpoint', by: w.by, roster: w.room, from_seq: w.fromSeq, upto_seq: w.uptoSeq, prev: w.prev, root: w.root, at: w.at, sigAlg: w.sigAlg, sig: w.sig };
}

function toWireWitness(x) {
  return { attester: x.attester, room: roomOf(x), fromSeq: fromOf(x), uptoSeq: positionOf(x), root: x.root, by: x.by, role: x.role, at: x.at, sigAlg: x.sigAlg, sig: x.sig };
}
/** A `sym-attest-witness` frame's witness, checked against the schema (closed), as the store holds it — or null. */
function fromWireWitness(w) {
  if (!w || typeof w !== 'object' || Array.isArray(w)) return null;
  for (const k of Object.keys(w)) if (!WITNESS_MEMBERS.has(k)) return null;
  if (!isId(w.attester) || !isRoom(w.room) || !isPos(w.fromSeq) || !isPos(w.uptoSeq) || w.uptoSeq < w.fromSeq || typeof w.root !== 'string' || !HEX64.test(w.root)) return null;
  if (!isId(w.by) || typeof w.role !== 'string' || !ROLE_RE.test(w.role) || !isTime(w.at)) return null;
  if (w.sigAlg !== 'ed25519' || typeof w.sig !== 'string' || !SIG_RE.test(w.sig)) return null;
  return { type: 'witness', attester: w.attester, roster: w.room, from_seq: w.fromSeq, upto_seq: w.uptoSeq, root: w.root, by: w.by, role: w.role, at: w.at, sigAlg: w.sigAlg, sig: w.sig };
}

/** `sym-attest-node-stats` (§5.4): unsigned, informational, attributed to the session's peer. Closed. */
const NODE_STATS_MEMBERS = new Set(['emitted', 'admitted', 'memory', 'at']);
function fromWireNodeStats(w) {
  if (!w || typeof w !== 'object' || Array.isArray(w)) return null;
  for (const k of Object.keys(w)) if (!NODE_STATS_MEMBERS.has(k)) return null;
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
  attestCheckpointRoot,
  checkpointConflict,
  checkpointLinkValid,
  toWireAttestation, fromWireAttestation,
  toWireCheckpoint, fromWireCheckpoint,
  toWireWitness, fromWireWitness,
  fromWireNodeStats,
  ATTEST_FRAME, LEGACY_ATTEST_FRAMES, ATTEST_DOMAIN: DOMAIN,
  VERDICTS, RECORD_VERDICTS,
};
