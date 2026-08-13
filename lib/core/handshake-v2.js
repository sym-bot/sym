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

/** Bytewise sort — the canonical order for extension lists inside the transcript. */
function sortedBytewise(items) {
  return [...(items || [])].map(String).sort((a, b) => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8')));
}

const dec = (n) => String(n >>> 0);

/**
 * Build the canonical §5.2 handshake transcript both sides hash. Byte-exact with the published
 * vector: domain, then protocolVersion and room, then both nonces, then the client block and the
 * server block (nodeId, identity key, E2E key, name, implementation name+version, and the
 * bytewise-sorted offered extensions with a length prefix), then the bytewise-sorted selected
 * extensions with a length prefix. Every negotiated value — including which extensions were offered
 * and selected — is bound here, so a relay that strips or reorders an extension breaks the
 * transcript and the proofs over it (the downgrade resistance the cmb-encrypted-v2 migration relies
 * on).
 *
 * Each party carries its own `nonce` (as it does on its hello frame); both nonces are emitted,
 * client then server, before the party blocks.
 *
 * @param {object} o
 * @param {string} o.protocolVersion
 * @param {string} o.room
 * @param {object} o.client - { nonce, nodeId, identityPublicKey, e2ePublicKey, name, implementation:{name,version}, extensions:[] }
 * @param {object} o.server - same shape as client
 * @param {string[]} o.selectedExtensions
 * @returns {Buffer}
 */
function buildTranscript({ protocolVersion, room, client, server, selectedExtensions }) {
  const clientNonce = client.nonce;
  const serverNonce = server.nonce;
  const party = (p) => {
    const exts = sortedBytewise(p.extensions);
    return [
      lp(String(p.nodeId)),
      lp(String(p.identityPublicKey)),
      lp(String(p.e2ePublicKey)),
      lp(String(p.name)),
      lp(String(p.implementation && p.implementation.name)),
      lp(String(p.implementation && p.implementation.version)),
      lp(dec(exts.length)),
      ...exts.map((e) => lp(e)),
    ];
  };
  const sel = sortedBytewise(selectedExtensions);
  return Buffer.concat([
    Buffer.from(TRANSCRIPT_DOMAIN, 'utf8'),
    lp(String(protocolVersion)),
    lp(String(room)),
    lp(String(clientNonce)),
    lp(String(serverNonce)),
    ...party(client),
    ...party(server),
    lp(dec(sel.length)),
    ...sel.map((e) => lp(e)),
  ]);
}

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

/**
 * The session key schedule (MMP v2.0 §5.2), byte-exact. From the X25519 shared secret and the
 * full transcript hash, HKDF-SHA256 derives the two directional AEAD traffic keys and the two
 * finished keys — salt is the full 32-byte transcript hash, IKM the shared secret, each key a
 * distinct exact-UTF-8 info label. Binding the salt to the transcript makes every key unique to
 * this exact negotiated handshake.
 */
function deriveSessionKeys(sharedSecret, transcriptHashBytes) {
  const hkdf = (info) => Buffer.from(crypto.hkdfSync('sha256', sharedSecret, transcriptHashBytes, Buffer.from(info, 'utf8'), 32));
  return {
    clientToServerKey: hkdf('mmp-aead-v2 client-to-server'),
    serverToClientKey: hkdf('mmp-aead-v2 server-to-client'),
    clientFinishedKey: hkdf('mmp-finished-v2 client'),
    serverFinishedKey: hkdf('mmp-finished-v2 server'),
  };
}

/**
 * Key confirmation (§5.2): HMAC-SHA256 under the role's finished key over the transcript hash.
 * Each side sends its confirmation; a mismatch means the peers did not derive the same secret
 * (a MITM or a divergent transcript) and the session must be torn down before data flows.
 */
function keyConfirmation(role, finishedKey, transcriptHashBytes) {
  return crypto.createHmac('sha256', finishedKey)
    .update(Buffer.concat([
      Buffer.from('mmp-key-confirm-v2\n', 'utf8'),
      lp(String(role)),
      lp(transcriptHashBytes.toString('hex')),
    ]))
    .digest();
}

module.exports = { buildTranscript, sortedBytewise, transcriptHash, sessionIdFromTranscript, proofPayload, signProof, verifyProof, deriveSessionKeys, keyConfirmation, TRANSCRIPT_DOMAIN, PROOF_DOMAIN };
