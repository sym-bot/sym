'use strict';

/**
 * Configuration helpers for SYM mesh nodes.
 *
 * Manages identity persistence, node directories, and logging.
 * Node data lives under ~/.sym/nodes/<name>/.
 *
 * See MMP v0.2.0 Section 3 (Identity), Section 18 (Configuration).
 *
 * Copyright (c) 2026 SYM.BOT Ltd. Apache 2.0 License.
 */

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const os = require('os');

/** Root SYM configuration directory (~/.sym). */
const SYM_DIR = path.join(process.env.HOME || os.homedir(), '.sym');

/** Directory containing all node data (~/.sym/nodes). */
const NODES_DIR = path.join(SYM_DIR, 'nodes');

/**
 * Ensure a directory exists, creating it recursively if needed.
 * @param {string} dir — directory path
 */
function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

/**
 * Get the data directory for a named node.
 * @param {string} name — node name
 * @returns {string} path to ~/.sym/nodes/<name>
 */
function nodeDir(name) {
  return path.join(NODES_DIR, name);
}

/**
 * Generate a UUID v7 (RFC 9562).
 * 48-bit Unix timestamp (ms) + 4-bit version (0111) + 12-bit random +
 * 2-bit variant (10) + 62-bit random.
 * @returns {string} lowercase UUID v7 with hyphens
 */
function uuidv7() {
  const now = Date.now();
  const bytes = crypto.randomBytes(16);

  // Bytes 0-5: 48-bit timestamp (ms since epoch), big-endian
  bytes[0] = (now / 2 ** 40) & 0xff;
  bytes[1] = (now / 2 ** 32) & 0xff;
  bytes[2] = (now / 2 ** 24) & 0xff;
  bytes[3] = (now / 2 ** 16) & 0xff;
  bytes[4] = (now / 2 ** 8) & 0xff;
  bytes[5] = now & 0xff;

  // Byte 6: version 7 (0111 xxxx)
  bytes[6] = (bytes[6] & 0x0f) | 0x70;

  // Byte 8: variant 10xx xxxx
  bytes[8] = (bytes[8] & 0x3f) | 0x80;

  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Validate a node name per MMP Section 3.1.2.
 * Must be valid UTF-8, 1-64 bytes, printable characters only.
 * @param {string} name
 * @throws {Error} if name is invalid
 */
function validateName(name) {
  if (!name || typeof name !== 'string') {
    throw new Error('Node name must be a non-empty string');
  }
  const byteLength = Buffer.byteLength(name, 'utf8');
  if (byteLength < 1 || byteLength > 64) {
    throw new Error(`Node name must be 1-64 bytes (got ${byteLength})`);
  }
  // Reject control characters (U+0000-U+001F, U+007F-U+009F)
  if (/[\x00-\x1f\x7f-\x9f]/.test(name)) {
    throw new Error('Node name must not contain control characters');
  }
}

/**
 * Generate an Ed25519 keypair for node identity signing.
 * Returns raw 32-byte keys.
 * @returns {{ publicKey: Buffer, privateKey: Buffer }}
 */
function generateSigningKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  // DER/SPKI Ed25519 public key: 12-byte ASN.1 header + 32-byte raw key
  // DER/PKCS8 Ed25519 private key: 16-byte ASN.1 header + 32-byte raw key
  return {
    publicKey: publicKey.slice(-32),
    privateKey: privateKey.slice(-32),
  };
}

/**
 * Load or create a persistent identity for a node.
 * Identity is stored as ~/.sym/nodes/<name>/identity.json.
 * See MMP v0.2.0 Section 3 (Identity).
 *
 * New nodes get UUID v7 + Ed25519 keypair. Existing nodes with UUID v4
 * are accepted (backward compatible per spec Section 3.1.1).
 *
 * @param {string} name — node name
 * @returns {{ nodeId: string, name: string, hostname: string, createdAt: number, publicKey: string, privateKey: string }}
 */
function loadOrCreateIdentity(name) {
  validateName(name);
  const dir = nodeDir(name);
  ensureDir(dir);
  const idPath = path.join(dir, 'identity.json');
  if (fs.existsSync(idPath)) {
    try {
      const identity = JSON.parse(fs.readFileSync(idPath, 'utf8'));
      // Migrate: add Ed25519 keypair if missing (pre-v0.3.7 nodes)
      if (!identity.publicKey) {
        const kp = generateSigningKeyPair();
        identity.publicKey = kp.publicKey.toString('base64url');
        identity.privateKey = kp.privateKey.toString('base64url');
        fs.writeFileSync(idPath, JSON.stringify(identity, null, 2));
      }
      return identity;
    } catch (e) {
      console.error(`[SYM] WARNING: identity.json corrupt or unreadable — regenerating. Error: ${e.message}`);
    }
  }
  const kp = generateSigningKeyPair();
  const identity = {
    nodeId: uuidv7(),
    name,
    hostname: os.hostname(),
    createdAt: Date.now(),
    publicKey: kp.publicKey.toString('base64url'),
    privateKey: kp.privateKey.toString('base64url'),
  };
  fs.writeFileSync(idPath, JSON.stringify(identity, null, 2));
  return identity;
}

/**
 * Log a timestamped message with node name prefix.
 * @param {string} nodeName — node name for prefix
 * @param {string} msg — message to log
 */
function log(nodeName, msg) {
  const ts = new Date().toISOString().slice(11, 19);
  console.log(`[${ts}] [${nodeName}] ${msg}`);
}

module.exports = {
  SYM_DIR,
  NODES_DIR,
  ensureDir,
  nodeDir,
  uuidv7,
  validateName,
  generateSigningKeyPair,
  loadOrCreateIdentity,
  log,
};
