'use strict';

/**
 * @module sym/core/relay-auth-proof
 * @description RELAY-AUTH KEY PROOF, the client's half (sym 0.14.3; sym-relay 0.8.0 verifies it).
 *
 * A relay-auth's nodeId used to be a claim: the relay keyed a connection's slot by whatever nodeId the
 * client named, so any holder of the channel token could claim a member's nodeId and have the member
 * closed (4004) or refused (4006). The node now proves its identity key to a relay that asks:
 *
 *   node  → relay-auth { nodeId, name, token?, room?, engine?, keyProof: "mmp-relay-auth-v1" }
 *           A relay that does not know key proof (sym-relay before 0.8.0) ignores the field and
 *           authenticates this frame as it always did: relay-peers arrives with no challenge, and the
 *           node records that this relay does not verify keys.
 *   relay → relay-challenge { keyProof: "mmp-relay-auth-v1", nonce: <32 bytes, base64url> }
 *   node  → relay-auth { …the same fields…, keyProof, publicKey, proof }
 *   relay → relay-peers (the slot is the node's, under its key) | 4002 (the proof does not verify)
 *
 * The signed bytes are domain-separated and every field is length-prefixed (4 bytes, big-endian):
 *
 *   lp("mmp-relay-auth-v1") ‖ lp(nonce) ‖ lp(room) ‖ lp(nodeId) ‖ lp(origin)
 *
 * room is the room the relay keys the slot by (`default` when relay-auth names none); nodeId the
 * lowercase nodeId of the relay-auth; origin the WHATWG origin of the URL this node DIALED
 * (`wss://host`, `ws://127.0.0.1:8787`), never one the relay names: a proof made for one relay
 * does not verify at another, so a relay that forwards another's challenge gains nothing. The token
 * is never signed. tests/relay-auth-proof-v1.json is the vector sym-relay carries too.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const crypto = require('crypto');
const { privateKeyObject } = require('./cmb-signing');
const { verifyStrict, CANONICAL_KEY_B64URL } = require('./ed25519');

const KEY_PROOF = 'mmp-relay-auth-v1';
const NONCE_BYTES = 32;

function lp(buf) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(buf.length, 0);
  return Buffer.concat([len, buf]);
}

/**
 * The bytes the node signs.
 * @param {{ nonce: Buffer, room: string, nodeId: string, origin: string }} t
 * @returns {Buffer}
 */
function transcript({ nonce, room, nodeId, origin }) {
  if (!Buffer.isBuffer(nonce) || nonce.length !== NONCE_BYTES) throw new TypeError('relay-auth transcript: nonce must be 32 bytes');
  for (const [k, v] of Object.entries({ room, nodeId, origin })) {
    if (typeof v !== 'string' || !v) throw new TypeError(`relay-auth transcript: ${k} must be a non-empty string`);
  }
  return Buffer.concat([
    lp(Buffer.from(KEY_PROOF, 'utf8')),
    lp(nonce),
    lp(Buffer.from(room, 'utf8')),
    lp(Buffer.from(nodeId, 'utf8')),
    lp(Buffer.from(origin, 'utf8')),
  ]);
}

/**
 * The challenge's nonce, or null when it is not 32 bytes in canonical unpadded base64url.
 * @param {*} nonce
 * @returns {Buffer|null}
 */
function challengeNonce(nonce) {
  if (typeof nonce !== 'string' || !CANONICAL_KEY_B64URL.test(nonce)) return null;
  const b = Buffer.from(nonce, 'base64url');
  return b.length === NONCE_BYTES ? b : null;
}

/** The WHATWG origin of a ws:// or wss:// URL, or null. */
function originOf(url) {
  try {
    const u = new URL(url);
    return u.protocol === 'ws:' || u.protocol === 'wss:' ? u.origin : null;
  } catch { return null; }
}

/**
 * The proof: Ed25519 (pure) over the transcript with the identity's private key (raw, base64url),
 * in canonical unpadded base64url.
 */
function signProof(t, identityPrivateKeyB64url) {
  return crypto.sign(null, transcript(t), privateKeyObject(identityPrivateKeyB64url)).toString('base64url');
}

/** Whether `proof` by `publicKey` verifies over the transcript (MMP §18.3.2). For tests and relays. */
function verifyProof(t, publicKey, proof) {
  try { return verifyStrict(transcript(t), publicKey, proof); } catch { return false; }
}

module.exports = { KEY_PROOF, NONCE_BYTES, transcript, challengeNonce, originOf, signProof, verifyProof };
