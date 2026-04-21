'use strict';

/**
 * Configuration helpers for SYM mesh nodes.
 *
 * Manages identity persistence, node directories, and logging.
 * Node data lives under ~/.sym/nodes/<name>/.
 *
 * See MMP v0.2.0 Section 3 (Identity), Section 18 (Configuration).
 *
 * Copyright (c) 2026 SYM.BOT. Apache 2.0 License.
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
 * Acquire an exclusive lock on a node identity. Prevents two processes
 * from claiming the same nodeId on the same host, which would cause
 * duplicate-identity races on the relay (close code 4004 / 4006 loops)
 * and ambiguous CMB delivery.
 *
 * Lockfile lives at ~/.sym/nodes/<name>/lock.pid and contains the PID
 * of the holder. On acquire:
 *   1. If no lockfile exists, write our PID and return a release fn.
 *   2. If lockfile exists and the PID is alive, throw IdentityLockError.
 *   3. If lockfile exists but the PID is dead (stale lock from a crashed
 *      process), reclaim it and return a release fn.
 *
 * The release function deletes the lockfile. SymNode calls it on stop()
 * and on SIGTERM/SIGINT (the host should wire signal handlers; this
 * function only manages the file).
 *
 * @param {string} name — node name
 * @returns {() => void} release function — call to delete the lockfile
 * @throws {Error} if another process already holds the lock
 */
function acquireIdentityLock(name) {
  validateName(name);
  const dir = nodeDir(name);
  ensureDir(dir);
  const lockPath = path.join(dir, 'lock.pid');

  if (fs.existsSync(lockPath)) {
    let holderPid;
    try {
      holderPid = parseInt(fs.readFileSync(lockPath, 'utf8').trim(), 10);
    } catch {
      // Corrupt lockfile — treat as stale
      holderPid = NaN;
    }
    if (Number.isFinite(holderPid)) {
      // Same-PID re-acquisition is allowed: this happens in tests that
      // create multiple SymNodes with the same name in sequence, in
      // hot-reload scenarios, and in recovery flows where a single
      // process re-initializes after a soft failure. The lock is meant
      // to catch CROSS-PROCESS duplicates (the actual bug), not
      // in-process re-init.
      if (holderPid === process.pid) {
        return function release() {
          try {
            const current = parseInt(fs.readFileSync(lockPath, 'utf8').trim(), 10);
            if (current === process.pid) fs.unlinkSync(lockPath);
          } catch {}
        };
      }
      // process.kill(pid, 0) sends no signal but throws ESRCH if the
      // process is dead. Works on POSIX and Windows in Node.
      let alive = false;
      try {
        process.kill(holderPid, 0);
        alive = true;
      } catch (e) {
        // ESRCH = no such process; EPERM = exists but we can't signal
        // (still alive, just not ours). Both indicate "exists" except ESRCH.
        if (e.code === 'EPERM') alive = true;
      }
      if (alive) {
        const err = new Error(
          `Identity '${name}' is already locked by PID ${holderPid}. ` +
          `Only one SymNode process can hold a given nodeId on a host. ` +
          `If this is unexpected, check for orphaned processes or set a ` +
          `different SYM_NODE_NAME for this process.`
        );
        err.code = 'EIDENTITYLOCK';
        err.holderPid = holderPid;
        throw err;
      }
      // Stale lock — delete the file so the openSync('wx') below succeeds.
      // Without this unlink, the recursive EEXIST handler loops forever.
      try { fs.unlinkSync(lockPath); } catch {}
    }
    // Lockfile existed but had unparseable content (NaN PID). Treat as
    // corrupt and reclaim by deleting before openSync('wx').
    if (!Number.isFinite(holderPid)) {
      try { fs.unlinkSync(lockPath); } catch {}
    }
  }

  // Atomic create: O_EXCL fails if another process creates the file
  // between our existsSync check above and our write. The fallback
  // re-reads and re-checks the holder.
  let fd;
  try {
    fd = fs.openSync(lockPath, 'wx');
  } catch (e) {
    if (e.code === 'EEXIST') {
      // Lost the race — re-acquire (recursive call handles the new state)
      return acquireIdentityLock(name);
    }
    throw e;
  }
  fs.writeSync(fd, String(process.pid));
  fs.closeSync(fd);

  return function release() {
    try {
      // Only delete if it's still ours (don't clobber a successor's lock)
      const current = parseInt(fs.readFileSync(lockPath, 'utf8').trim(), 10);
      if (current === process.pid) fs.unlinkSync(lockPath);
    } catch {
      // Lockfile already gone or unreadable — nothing to do
    }
  };
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
  acquireIdentityLock,
  log,
};
