'use strict';

/**
 * @module sym/core/e2e-v2
 * @description MMP v2.0 E2E AEAD — X25519-HKDF-SHA256-ChaCha20-Poly1305, byte-exact with the
 * published contract (meshcognition.org/spec/mmp, suite `X25519-HKDF-SHA256-ChaCha20-Poly1305`).
 *
 * Corrects the audit's P0.4: the old path used a raw X25519 shared secret DIRECTLY as an
 * AES-256-GCM key with no KDF and no AAD binding. Here a session traffic key comes from HKDF and
 * every sealed frame is bound, via AEAD AAD, to the record it protects — the record key, the
 * signed assertionId, the author nodeId, the direction and a per-direction sequence counter. The
 * nonce is the sequence counter, never random, so it can never repeat within a session and a
 * relay cannot replay a frame under a different record.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const crypto = require('crypto');
const { lp } = require('./cmb-encoder');

/**
 * The AEAD associated data (mmp-aead-aad-v2), byte-exact with the published contract. Binds the
 * ciphertext to exactly one signed record and one position in the session, so a valid ciphertext
 * cannot be moved to another record, direction, or sequence.
 */
function aeadAADv2({ protocolVersion, sessionId, direction, sequence, key, assertionId, createdByNodeId, room, to }) {
  return Buffer.concat([
    Buffer.from('mmp-aead-aad-v2\n', 'utf8'),
    lp(String(protocolVersion)),
    lp(String(sessionId)),
    lp(String(direction)),
    lp(String(sequence)),
    lp(String(key)),
    lp(String(assertionId)),
    lp(String(createdByNodeId)),
    lp(String(room ?? '')),
    lp(String(to ?? '')),
  ]);
}

/** Seal plaintext under the ChaCha20-Poly1305 traffic key. Returns ciphertext||tag (16-byte tag). */
function sealV2(trafficKey, nonce, aad, plaintext) {
  const c = crypto.createCipheriv('chacha20-poly1305', trafficKey, nonce, { authTagLength: 16 });
  c.setAAD(aad);
  const body = Buffer.concat([c.update(plaintext), c.final()]);
  return Buffer.concat([body, c.getAuthTag()]);
}

/** Open a ciphertext||tag frame. Throws on any authentication failure — never returns partial. */
function openV2(trafficKey, nonce, aad, sealed) {
  if (sealed.length < 16) throw new Error('mmp-aead-v2: sealed frame shorter than its auth tag');
  const body = sealed.subarray(0, sealed.length - 16);
  const tag = sealed.subarray(sealed.length - 16);
  const d = crypto.createDecipheriv('chacha20-poly1305', trafficKey, nonce, { authTagLength: 16 });
  d.setAAD(aad);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(body), d.final()]);
}

module.exports = { aeadAADv2, sealV2, openV2 };
