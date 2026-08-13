'use strict';

// MMP v2.0 E2E AEAD conformance: sym must produce the published
// X25519-HKDF-SHA256-ChaCha20-Poly1305 bytes exactly. The vector (website #12, digest-pinned in
// the artifact manifest) gives the traffic key, nonce, AAD and expected sealed ciphertext per
// case; sym must seal to the same bytes and open them back, or an independent implementer's
// encryption and sym's silently disagree.

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { aeadAADv2, sealV2, openV2 } = require('../lib/core/e2e-v2');
const vec = require('./mmp-v2-e2e.vector.json');

describe('MMP v2.0 E2E AEAD conformance (X25519-HKDF-SHA256-ChaCha20-Poly1305)', () => {
  const plaintext = Buffer.from(vec.protectedPlaintextUtf8, 'utf8');

  for (const c of vec.cases) {
    const key = Buffer.from(c.trafficKeyHex, 'hex');
    const nonce = Buffer.from(c.nonceHex, 'hex');
    const aad = Buffer.from(c.aadHex, 'hex');
    const label = `${c.direction} seq ${c.sequence}`;

    it(`seals byte-identically to the published vector — ${label}`, () => {
      const sealed = sealV2(key, nonce, aad, plaintext);
      assert.strictEqual(sealed.toString('base64url'), c.sealedBase64url);
    });

    it(`opens the published ciphertext back to the plaintext — ${label}`, () => {
      const opened = openV2(key, nonce, aad, Buffer.from(c.sealedBase64url, 'base64url'));
      assert.strictEqual(opened.toString('utf8'), vec.protectedPlaintextUtf8);
    });

    it(`AAD is reconstructed byte-exactly from the record binding — ${label}`, () => {
      const m = vec.metadata;
      const built = aeadAADv2({
        protocolVersion: vec.protocolVersion, sessionId: vec.sessionId,
        direction: c.direction, sequence: c.sequence,
        key: m.key, assertionId: m.assertionId, createdByNodeId: m.createdByNodeId, room: m.room, to: m.to,
      });
      assert.strictEqual(built.toString('hex'), c.aadHex);
    });

    it(`a tampered AAD (wrong sequence) fails to open — ${label}`, () => {
      const wrong = Buffer.from(c.aadHex, 'hex'); wrong[wrong.length - 1] ^= 0xff;
      assert.throws(() => openV2(key, nonce, wrong, Buffer.from(c.sealedBase64url, 'base64url')));
    });
  }
});
