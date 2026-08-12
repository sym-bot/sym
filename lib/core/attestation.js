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
 *       NOT that `by` holds that role. Verify role-at-`at` against the rooted
 *       role-grant chain (use `verifyAttestationRole` with a resolver) and weight
 *       by the RESOLVED role, never the stamped category.
 *   (b) OMISSION-evidence comes from the `seq`/`prev` chain + anchored checkpoints,
 *       reconciled by the node — signatures alone cannot prove absence.
 *   (c) The mechanism is scoped to a permissioned roster (roots authority, bounds
 *       gossip, sets the privacy boundary).
 * This module provides only the canonical payload + sign/verify + the role-claim
 * check; chain/roster/rate-limit/checkpointing live in `@sym-bot/sym`.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const crypto = require('crypto');
const { privateKeyObject, publicKeyObject } = require('./cmb-signing');
const { CAT7_CATEGORIES } = require('./cmb-encoder');
const { roleRank } = require('./role-grant');

/** Per-category verdict vocabulary (matches svaf-heuristic CATEGORY_VERDICT). */
const VERDICTS = Object.freeze(['admit', 'guard', 'redundant', 'reject', 'silent']);

/**
 * Deterministic canonicalization of the per-category verdict map. Fixed CAT7 order so
 * the signed bytes are independent of object key insertion order; every category is
 * included (a missing category signs as empty), so dropping a category breaks the sig.
 * @param {object} categories - per-CAT7-category verdict map
 * @returns {string}
 */
function canonicalCategories(categories) {
  return CAT7_CATEGORIES.map(f => `${f}:${(categories && categories[f]) || ''}`).join(',');
}

/**
 * Canonical bytes signed for an attestation. Binds the gated CMB, the attester, the
 * time, the roster, the overall verdict, EVERY per-category verdict, the claimed role,
 * and the hash-chain position (`seq`,`prev`) — so no element can be mutated after
 * signing (modify, repoint, re-category, re-role, re-chain) without breaking the sig.
 * @param {object} a - attestation
 * @returns {Buffer}
 */
function attestationPayload(a) {
  const parts = [
    a.of || '', a.by || '', a.at ?? '', a.roster || '',
    a.verdict || '', canonicalCategories(a.categories), a.role || '',
    a.seq ?? '', a.prev || '',
  ];
  return Buffer.from(parts.join('|'), 'utf8');
}

/**
 * Sign an attestation in place with the attester's raw Ed25519 private key
 * (base64url). Sets `sig` + `sigAlg`. Returns the attestation.
 */
function signAttestation(att, privateKeyB64url) {
  if (!att || !att.of || !att.by) throw new Error('signAttestation requires of + by');
  const sig = crypto.sign(null, attestationPayload(att), privateKeyObject(privateKeyB64url));
  att.sig = sig.toString('base64url');
  att.sigAlg = 'ed25519';
  return att;
}

/**
 * Verify an attestation signature against the attester's raw Ed25519 public key.
 * Proves the key `by` authored these exact bytes — NOT that `by` holds the claimed
 * `role` (use `verifyAttestationRole` for that).
 * @returns {{ signed: boolean, valid: boolean, error?: string }}
 */
function verifyAttestation(att, attesterPublicKeyB64url) {
  if (!att || !att.sig || att.sigAlg !== 'ed25519') return { signed: false, valid: false };
  if (!attesterPublicKeyB64url) return { signed: true, valid: false, error: 'no-public-key' };
  try {
    const ok = crypto.verify(
      null,
      attestationPayload(att),
      publicKeyObject(attesterPublicKeyB64url),
      Buffer.from(att.sig, 'base64url'),
    );
    return ok ? { signed: true, valid: true } : { signed: true, valid: false, error: 'bad-signature' };
  } catch (e) {
    return { signed: true, valid: false, error: e.message };
  }
}

/**
 * Check the CLAIMED role against the role authoritatively resolved for `by` at time
 * `at` from the rooted role-grant chain. The aggregate audit read MUST use the
 * RESOLVED role, never the stamped one — a node can stamp any role; the signature
 * does not vouch for it. `resolveRole(by, at) → role | null` is injected by the node
 * (chain-walking is the earned-authority layer); `null`/unknown → `participant`.
 * @returns {{ claimed: string, resolved: string, matches: boolean, rank: number }}
 */
function verifyAttestationRole(att, resolveRole) {
  const claimed = (att && att.role) || 'participant';
  const resolved = ((typeof resolveRole === 'function' && att) ? resolveRole(att.by, att.at) : null) || 'participant';
  return { claimed, resolved, matches: resolved === claimed, rank: roleRank(resolved) };
}

// ── Checkpoints + witnesses (omission-evidence, MMP) ─────────────────────────────
//
// A CHECKPOINT commits an attester to its chain up to `seq` via a Merkle root over
// its attestation signatures (built by the node; this layer signs/verifies it). A
// WITNESS is a roster peer's countersignature on that checkpoint ("I saw <attester>'s
// chain to <seq> with root <root>"). Once witnessed, the attester cannot later serve
// a chain that drops an attestation ≤ seq without diverging from the witnessed root —
// turning silent omission into a detectable contradiction. The honest guarantee is
// "omission-evident to the last witnessed checkpoint," NOT real-time completeness.

/** Canonical bytes for a checkpoint — binds attester, roster, the committed seq, the root, and time. */
function checkpointPayload(cp) {
  return Buffer.from(`checkpoint|${cp.by || ''}|${cp.roster || ''}|${cp.upto_seq ?? ''}|${cp.root || ''}|${cp.at ?? ''}`, 'utf8');
}

/** Sign a checkpoint in place with the attester's raw Ed25519 private key (base64url). */
function signCheckpoint(cp, privateKeyB64url) {
  if (!cp || !cp.by || cp.upto_seq === undefined || !cp.root) {
    throw new Error('signCheckpoint requires by + upto_seq + root');
  }
  cp.sig = crypto.sign(null, checkpointPayload(cp), privateKeyObject(privateKeyB64url)).toString('base64url');
  cp.sigAlg = 'ed25519';
  return cp;
}

/** Verify a checkpoint's signature against the attester's raw Ed25519 public key. */
function verifyCheckpoint(cp, attesterPublicKeyB64url) {
  if (!cp || !cp.sig || cp.sigAlg !== 'ed25519') return { signed: false, valid: false };
  if (!attesterPublicKeyB64url) return { signed: true, valid: false, error: 'no-public-key' };
  try {
    const ok = crypto.verify(null, checkpointPayload(cp), publicKeyObject(attesterPublicKeyB64url), Buffer.from(cp.sig, 'base64url'));
    return ok ? { signed: true, valid: true } : { signed: true, valid: false, error: 'bad-signature' };
  } catch (e) {
    return { signed: true, valid: false, error: e.message };
  }
}

/**
 * Canonical bytes for a witness countersignature. Binds the attester whose checkpoint
 * is witnessed (`attester`), the committed `upto_seq` + `root`, the witness (`by`),
 * its role, the roster, and time — so a witness cannot be replayed onto a different
 * checkpoint, attester, or root.
 */
function witnessPayload(w) {
  return Buffer.from(`witness|${w.attester || ''}|${w.roster || ''}|${w.upto_seq ?? ''}|${w.root || ''}|${w.by || ''}|${w.role || ''}|${w.at ?? ''}`, 'utf8');
}

/** Sign a witness countersignature in place with the witness's raw Ed25519 private key. */
function signWitness(w, privateKeyB64url) {
  if (!w || !w.attester || !w.by || w.upto_seq === undefined || !w.root) {
    throw new Error('signWitness requires attester + by + upto_seq + root');
  }
  w.sig = crypto.sign(null, witnessPayload(w), privateKeyObject(privateKeyB64url)).toString('base64url');
  w.sigAlg = 'ed25519';
  return w;
}

/** Verify a witness countersignature against the WITNESS's raw Ed25519 public key. */
function verifyWitness(w, witnessPublicKeyB64url) {
  if (!w || !w.sig || w.sigAlg !== 'ed25519') return { signed: false, valid: false };
  if (!witnessPublicKeyB64url) return { signed: true, valid: false, error: 'no-public-key' };
  try {
    const ok = crypto.verify(null, witnessPayload(w), publicKeyObject(witnessPublicKeyB64url), Buffer.from(w.sig, 'base64url'));
    return ok ? { signed: true, valid: true } : { signed: true, valid: false, error: 'bad-signature' };
  } catch (e) {
    return { signed: true, valid: false, error: e.message };
  }
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
  VERDICTS,
};
