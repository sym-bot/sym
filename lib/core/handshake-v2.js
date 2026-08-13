'use strict';

/**
 * @module sym/core/handshake-v2
 * @description MMP v2.0 handshake proof-of-possession (P0.3), byte-exact with
 * meshcognition.org/spec/mmp.
 *
 * The audit's P0.3: the old handshake trusted the first frame's nodeId and keys with no proof —
 * an active peer or relay could claim an unused nodeId with its own keys, or substitute the
 * X25519 key and become the endpoint for encrypted data. Here each side proves possession of its
 * identity key by signing a canonical transcript that binds both nonces, both nodeIds, both
 * identity and E2E public keys, the protocol version, implementation, room and extensions. A
 * handshake whose proof does not verify is rejected before any key is pinned.
 *
 * The session id and the traffic-key schedule chain from the same transcript hash (the traffic
 * keys via HKDF — wired with the published key schedule; the transcript, hash, session id and
 * proofs are here and need no KDF).
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const crypto = require('crypto');
const { lp } = require('./cmb-encoder');
const { privateKeyObject, publicKeyObject } = require('./cmb-signing');

const TRANSCRIPT_DOMAIN = 'mmp-handshake-transcript-v2\n';
const PROOF_DOMAIN = 'mmp-handshake-proof-v2\n';

/** SHA-256 of the canonical transcript bytes. Both sides hash the identical transcript. */
function transcriptHash(transcriptBytes) {
  return crypto.createHash('sha256').update(transcriptBytes).digest();
}

/** The session id is the first 16 bytes of the transcript hash, as lowercase hex — a stable,
 *  transcript-bound name shared by both sides with no extra derivation. */
function sessionIdFromTranscript(transcriptBytes) {
  return transcriptHash(transcriptBytes).subarray(0, 16).toString('hex');
}

/**
 * The proof preimage a party signs to prove possession of its identity key: the domain, the
 * party's role ('client' | 'server'), and the full transcript hash (lowercase hex). Signing over
 * the transcript hash binds the proof to every negotiated value, so a relay cannot splice a proof
 * from one handshake onto another.
 */
function proofPayload(role, transcriptBytes) {
  return Buffer.concat([
    Buffer.from(PROOF_DOMAIN, 'utf8'),
    lp(String(role)),
    lp(transcriptHash(transcriptBytes).toString('hex')),
  ]);
}

/** Sign the proof with the party's raw Ed25519 identity private key (base64url). */
function signProof(role, transcriptBytes, identityPrivateKeyB64url) {
  return crypto.sign(null, proofPayload(role, transcriptBytes), privateKeyObject(identityPrivateKeyB64url))
    .toString('base64url');
}

/**
 * Verify a party's proof against the identity public key IT PRESENTED IN THE TRANSCRIPT. Returns
 * true only if the signature is valid over the transcript this receiver actually saw — so an
 * unproven, replayed, or key-substituted handshake fails here, before any key is pinned.
 */
function verifyProof(role, transcriptBytes, proofB64url, identityPublicKeyB64url) {
  try {
    return crypto.verify(
      null, proofPayload(role, transcriptBytes),
      publicKeyObject(identityPublicKeyB64url),
      Buffer.from(proofB64url, 'base64url'),
    );
  } catch { return false; }
}

module.exports = { transcriptHash, sessionIdFromTranscript, proofPayload, signProof, verifyProof, TRANSCRIPT_DOMAIN, PROOF_DOMAIN };
