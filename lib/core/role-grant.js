'use strict';

/**
 * @module @sym-bot/core/role-grant
 * @description Ed25519-signed lifecycle role grants (MMP §6.5 — earned authority).
 *
 * A node's authority to validate or canonize is an EARNED, SIGNED fact bound to
 * its Ed25519 identity — never inferred from a CMB's text. A role-grant frame
 * promotes a node's lifecycle role (participant → validator → anchor); a
 * role-revoke frame pulls it back down. Both are signed by the granting node and
 * verified against that node's announced public key, so authority cannot be
 * spoofed by content alone.
 *
 * Trust rule (enforced by the receiver, not here): a grant is honoured only when
 * the GRANTOR's own role outranks-or-equals the role it confers — validators
 * grant validator; only anchors grant anchor — and the chain roots at the pinned
 * founder anchor. This module provides only the canonical payload + sign/verify;
 * the rank check and root-of-trust pin live in the node that applies the grant.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const crypto = require('crypto');
const { privateKeyObject, publicKeyObject } = require('./cmb-signing');

/** Lifecycle role ranks. `observer` is the protocol's `participant` default. */
const ROLE_RANK = Object.freeze({ participant: 0, observer: 0, validator: 1, anchor: 2 });

/** Numeric rank of a role string (unknown → 0). */
function roleRank(role) {
  return ROLE_RANK[role] ?? 0;
}

/**
 * Canonical bytes signed for a grant/revoke. Binds the action, the grantee, the
 * conferred role, the grantor, the time, and (optionally) the grantee's announced
 * public key — so a signature can't be replayed to confer a different role, onto a
 * different node, or with a substituted key. Binding `granteeKey` lets the grantor
 * VOUCH for the grantee's nodeId↔key pairing along the authority chain: a node that
 * never directly handshook the grantee can still learn its key from a rooted grant,
 * tamper-evidently, because swapping the key breaks the grantor's signature (the
 * relayer never vouches). Empty when absent (revokes, key-less grants) — both signer
 * and verifier use this function, so the round-trip is stable either way.
 * @param {object} g - { type, grantee, role, grantedBy, grantedAt, granteeKey? }
 * @returns {Buffer}
 */
function grantPayload(g) {
  return Buffer.from(`${g.type}|${g.grantee}|${g.role || ''}|${g.grantedBy}|${g.grantedAt}|${g.granteeKey || ''}`, 'utf8');
}

/**
 * Sign a role-grant/revoke frame in place with the grantor's raw Ed25519 private
 * key (base64url). Sets `sig` + `sigAlg`. Returns the frame.
 */
function signGrant(grant, privateKeyB64url) {
  if (!grant || !grant.grantee || !grant.grantedBy) {
    throw new Error('signGrant requires grantee + grantedBy');
  }
  const sig = crypto.sign(null, grantPayload(grant), privateKeyObject(privateKeyB64url));
  grant.sig = sig.toString('base64url');
  grant.sigAlg = 'ed25519';
  return grant;
}

/**
 * Verify a grant/revoke signature against the grantor's raw Ed25519 public key.
 * @returns {{ signed: boolean, valid: boolean, error?: string }}
 */
function verifyGrant(grant, grantorPublicKeyB64url) {
  if (!grant || !grant.sig || grant.sigAlg !== 'ed25519') return { signed: false, valid: false };
  if (!grantorPublicKeyB64url) return { signed: true, valid: false, error: 'no-public-key' };
  try {
    const ok = crypto.verify(
      null,
      grantPayload(grant),
      publicKeyObject(grantorPublicKeyB64url),
      Buffer.from(grant.sig, 'base64url'),
    );
    return ok ? { signed: true, valid: true } : { signed: true, valid: false, error: 'bad-signature' };
  } catch (e) {
    return { signed: true, valid: false, error: e.message };
  }
}

module.exports = { signGrant, verifyGrant, grantPayload, roleRank, ROLE_RANK };
