'use strict';

/**
 * @module sym/core/verified-receipt
 * @description The MMP v2.0 verification receipt SYM emits so a closed-core
 * consumer (xmesh-core) can admit a network record without re-verifying it.
 *
 * xmesh-core is a verified-record CONSUMER, not a transport verifier: it refuses
 * any network-origin record unless it is handed a typed receipt proving a Core
 * Secure substrate already verified the complete v2.0 assertion, bound to the
 * EXACT bytes it verified. SYM is that substrate. This module is the emitting
 * half of that boundary — its `recordDigest` is byte-identical to
 * `@sym-bot/xmesh-core/lib/verified-record.recordDigest`, so the digest SYM
 * signs into the receipt is the digest xmesh-core recomputes at admission. If a
 * relay or a caller mutates one byte of the record between verification and
 * admission, the two digests diverge and xmesh-core refuses.
 *
 * The receipt is a trusted in-process hand-off between two Core modules, not a
 * capability token against code already executing in the process. Its value is
 * detecting mutation/substitution across the verify→admit gap and forcing the
 * trust transition to be explicit.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const crypto = require('crypto');
const { verifyCMB, assertionIdV2_0 } = require('./cmb-signing');

const RECEIPT_PROTOCOL_VERSION = '2.0';

/**
 * Deterministic JSON with lexicographically sorted object keys — byte-identical
 * to xmesh-core `verified-record.canonicalJSON`. Do not "improve" this
 * independently: the two implementations are a wire contract, and any divergence
 * (key order, primitive stringification, array handling) makes every honest
 * record refuse at the digest check. It is duplicated rather than shared because
 * the packages must not take a runtime dependency on each other's internals.
 */
function canonicalJSON(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJSON(value[key])}`).join(',')}}`;
}

/** SHA-256 (hex) of the canonical form of the exact record — byte-identical to xmesh-core. */
function recordDigest(record) {
  return crypto.createHash('sha256').update(canonicalJSON(record), 'utf8').digest('hex');
}

/**
 * Build the receipt for a record already verified by the caller. Shape is the
 * exact contract xmesh-core `validateAdmissionSubject` checks: verified flag,
 * protocol version, the assertion id and signature suite (both re-checked
 * against the record's own metadata there), and the digest binding it to bytes.
 */
function verificationReceipt(cmb) {
  const m = cmb && cmb.metadata;
  if (!m || typeof m !== 'object') throw new Error('verification-receipt: record has no metadata');
  return {
    verified: true,
    protocolVersion: RECEIPT_PROTOCOL_VERSION,
    assertionId: m.assertionId,
    signatureSuite: m.signatureSuite,
    recordDigest: recordDigest(cmb),
  };
}

/**
 * Verify a v2.0 record and, only on a valid signature AND matching content
 * address, emit the receipt bound to those exact bytes. This is the single
 * function a receive path should call before handing a network record to
 * xmesh-core: a receipt is emitted if and only if SYM itself accepted the
 * record's cryptographic assertion.
 *
 * FAIL-CLOSED: any verification outcome other than {signed:true, valid:true}
 * yields no receipt. A caller that forwards the record to xmesh-core without a
 * receipt is refused there — the two halves compose to a closed boundary.
 *
 * The assertionId carried in metadata is additionally re-derived from the signed
 * preimage and must match: a receipt must never certify an assertionId the
 * signature does not actually cover, even though the signature already binds it.
 *
 * @returns {{ok:true, receipt:object}|{ok:false, error:string}}
 */
function verifyAndAttest(cmb, publicKeyB64url) {
  const v = verifyCMB(cmb, publicKeyB64url);
  if (!v || !v.valid) return { ok: false, error: (v && v.error) || 'unverified' };

  const m = cmb.metadata;
  if (m.signatureSuite !== 'mmp-sig-v2.0') return { ok: false, error: 'not-a-v2.0-record' };
  // Belt-and-braces: the assertionId is part of the signed preimage, so a valid
  // signature already fixes it. Re-derive and compare so a receipt can never
  // certify a metadata.assertionId that drifted from the signed value.
  let derived;
  try { derived = assertionIdV2_0(cmb); } catch (e) { return { ok: false, error: `assertion-id: ${e.message}` }; }
  if (derived !== m.assertionId) return { ok: false, error: 'assertion-id-mismatch' };

  return { ok: true, receipt: verificationReceipt(cmb) };
}

module.exports = {
  RECEIPT_PROTOCOL_VERSION,
  canonicalJSON,
  recordDigest,
  verificationReceipt,
  verifyAndAttest,
};
