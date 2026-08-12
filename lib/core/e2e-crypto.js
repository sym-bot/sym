'use strict';

/**
 * @module sym/core/e2e-crypto
 * @description End-to-end encryption for CMB categories.
 *
 * Uses X25519 Diffie-Hellman for key agreement and AES-256-GCM for
 * authenticated encryption. The relay never sees plaintext category data.
 *
 * Only CMB `categories` are encrypted — `key`, `createdBy`, `createdAt`,
 * and `lineage` remain in cleartext for routing and deduplication.
 *
 * See MMP v0.2.0 Section 6 (Memory), Section 7 (Frame Types).
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const crypto = require('crypto');

/**
 * Generate an X25519 key pair for Diffie-Hellman key agreement.
 *
 * @returns {{ publicKey: Buffer, privateKey: Buffer }}
 */
function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  return { publicKey, privateKey };
}

/**
 * Derive a shared secret from our private key and a peer's public key
 * using X25519 Diffie-Hellman.
 *
 * @param {Buffer} myPrivateKey — our X25519 private key (DER/PKCS8)
 * @param {Buffer} peerPublicKey — peer's X25519 public key (DER/SPKI)
 * @returns {Buffer} — 32-byte shared secret
 */
function deriveSharedSecret(myPrivateKey, peerPublicKey) {
  const privKeyObj = crypto.createPrivateKey({
    key: myPrivateKey,
    format: 'der',
    type: 'pkcs8',
  });
  const pubKeyObj = crypto.createPublicKey({
    key: peerPublicKey,
    format: 'der',
    type: 'spki',
  });
  return crypto.diffieHellman({
    privateKey: privKeyObj,
    publicKey: pubKeyObj,
  });
}

/**
 * Encrypt CMB categories using AES-256-GCM with a random 12-byte nonce.
 *
 * @param {object} categories — CAT7 categories object to encrypt
 * @param {Buffer} sharedSecret — 32-byte shared secret from DH
 * @returns {{ ciphertext: string, nonce: string }} — base64-encoded ciphertext (with appended auth tag) and nonce
 */
function encryptCategories(categories, sharedSecret) {
  const nonce = crypto.randomBytes(12);
  const plaintext = JSON.stringify(categories);

  const cipher = crypto.createCipheriv('aes-256-gcm', sharedSecret, nonce);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Append 16-byte auth tag to ciphertext for transport
  const ciphertextWithTag = Buffer.concat([encrypted, authTag]);

  return {
    ciphertext: ciphertextWithTag.toString('base64'),
    nonce: nonce.toString('base64'),
  };
}

/**
 * Decrypt CMB categories using AES-256-GCM.
 *
 * @param {string} ciphertext — base64-encoded ciphertext (with appended 16-byte auth tag)
 * @param {string} nonce — base64-encoded 12-byte nonce
 * @param {Buffer} sharedSecret — 32-byte shared secret from DH
 * @returns {object} — decrypted CAT7 categories object
 * @throws {Error} if decryption or authentication fails
 */
function decryptCategories(ciphertext, nonce, sharedSecret) {
  const ciphertextBuf = Buffer.from(ciphertext, 'base64');
  const nonceBuf = Buffer.from(nonce, 'base64');

  // Last 16 bytes are the auth tag
  const authTag = ciphertextBuf.subarray(ciphertextBuf.length - 16);
  const encryptedData = ciphertextBuf.subarray(0, ciphertextBuf.length - 16);

  const decipher = crypto.createDecipheriv('aes-256-gcm', sharedSecret, nonceBuf);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);
  return JSON.parse(decrypted.toString('utf8'));
}

module.exports = {
  generateKeyPair,
  deriveSharedSecret,
  encryptCategories,
  decryptCategories,
};
