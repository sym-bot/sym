'use strict';

/**
 * @module sym/core/tether-attestation
 * @description MMP §15.8 tether attestation — the integrator's signed record of
 * its lineage-tether evaluation, carried on the remix.
 *
 * The tether verdict is computed by the INTEGRATING node against the nearest
 * lineage root it could resolve, in its own kernel. A downstream receiver that
 * cannot resolve that root cannot recompute the verdict; without a record it
 * holds an UNCHECKED certificate. The attestation closes that hole the same way
 * admission attestations close the gating-audit hole: the integrator signs the
 * exact evaluation it performed — remix key, anchor key, kernel identity,
 * measured drift, verdict, integrator, time — so downstream receivers hold
 * attested-by-integrator instead of unchecked, with trust weighed through the
 * integrator's resolved authority (§6.5–§6.6), never assumed.
 *
 * KERNEL COMPARABILITY (§15.8): every φ-space judgement is kernel-relative.
 * Two tether verdicts are comparable iff their kernelId values are equal;
 * comparing drifts across kernels is meaningless (the same laundering scenario
 * measures 0.75 in the semantic kernel and 0.37 in the lexical fallback).
 * kernelId is a short stable token naming encoder + comparison dimensionality.
 *
 * Canonical payload (netstring length-prefixed, domain-separated — the §8.2.1
 * serialization discipline):
 *   "mmp-tether-v1\n" + LP(of) + LP(anchor) + LP(kernelId) + LP(driftStr)
 *                     + LP(verdict) + LP(by) + LP(decimal(at))
 * driftStr is the drift formatted with exactly 6 fractional digits, so the
 * signed bytes are identical across implementations regardless of float
 * printing conventions.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const crypto = require('crypto');
const { lp } = require('./cmb-encoder');

// RFC 8410 DER prefixes for raw 32-byte Ed25519 keys (same discipline as
// cmb-signing / attestation).
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function privateKeyObject(rawB64url) {
  const raw = Buffer.from(rawB64url, 'base64url');
  if (raw.length !== 32) throw new Error('Ed25519 private key must be 32 raw bytes');
  return crypto.createPrivateKey({ key: Buffer.concat([ED25519_PKCS8_PREFIX, raw]), format: 'der', type: 'pkcs8' });
}

function publicKeyObject(rawB64url) {
  const raw = Buffer.from(rawB64url, 'base64url');
  if (raw.length !== 32) throw new Error('Ed25519 public key must be 32 raw bytes');
  return crypto.createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
}

/** Canonical signed bytes for a tether attestation. */
function tetherPayload(t) {
  const drift = Number(t.drift);
  if (!Number.isFinite(drift)) throw new Error('tether attestation requires a finite drift');
  const driftStr = drift.toFixed(6);
  return Buffer.concat([
    Buffer.from('mmp-tether-v1\n', 'utf8'),
    lp(t.of || ''),
    lp(t.anchor || ''),
    lp(t.kernelId || ''),
    lp(driftStr),
    lp(t.verdict || ''),
    lp(t.by || ''),
    lp(String(t.at ?? '')),
  ]);
}

/**
 * Sign a tether attestation with the integrator's raw Ed25519 private key.
 * Mutates and returns the record with `sig` (base64url) + `sigAlg`.
 * @param {{of:string, anchor:string, kernelId:string, drift:number,
 *          verdict:'tethered'|'severed', by:string, at:number}} t
 */
function signTetherAttestation(t, privateKeyB64url) {
  if (!t || !t.of || !t.anchor || !t.by) throw new Error('signTetherAttestation requires of + anchor + by');
  if (t.verdict !== 'tethered' && t.verdict !== 'severed') throw new Error('verdict must be tethered|severed');
  const sig = crypto.sign(null, tetherPayload(t), privateKeyObject(privateKeyB64url));
  t.sig = sig.toString('base64url');
  t.sigAlg = 'ed25519';
  return t;
}

/**
 * Verify a tether attestation against the integrator's raw Ed25519 public key.
 * Proves `by` authored these exact bytes — not that `by` evaluated honestly
 * (weigh the integrator's resolved authority for that, §6.5–§6.6).
 * @returns {{ signed: boolean, valid: boolean, error?: string }}
 */
function verifyTetherAttestation(t, integratorPublicKeyB64url) {
  if (!t || !t.sig || t.sigAlg !== 'ed25519') return { signed: false, valid: false };
  if (!integratorPublicKeyB64url) return { signed: true, valid: false, error: 'no-public-key' };
  try {
    const ok = crypto.verify(null, tetherPayload(t), publicKeyObject(integratorPublicKeyB64url),
      Buffer.from(t.sig, 'base64url'));
    return ok ? { signed: true, valid: true } : { signed: true, valid: false, error: 'bad-signature' };
  } catch (e) {
    return { signed: true, valid: false, error: e.message };
  }
}

/**
 * §15.8 comparability rule: two tether records are comparable iff they carry
 * the SAME kernelId. Never compare drifts across kernels.
 */
function tetherComparable(a, b) {
  return !!(a && b && a.kernelId && a.kernelId === b.kernelId);
}

module.exports = { tetherPayload, signTetherAttestation, verifyTetherAttestation, tetherComparable };
