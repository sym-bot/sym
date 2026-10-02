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
const { execFileSync } = require('child_process');

/**
 * Root SYM configuration directory. Honours SYM_STATE_DIR; ~/.sym when unset.
 *
 * This used to be computed here as `$HOME/.sym`, importing nothing but node builtins — while
 * `lib/core/state-root.js` in the SAME package already resolved SYM_STATE_DIR. So the module
 * that mints identities, keypairs, stores and the single-writer lock was tenancy-blind by
 * construction: two team roots on one host, each with its own SYM_STATE_DIR, still shared
 * one `~/.sym/nodes`, and the second daemon's observer was refused the identity lock the
 * first one held. Renaming the observer would have satisfied the lock and left the boundary
 * exactly as broken. Rooting the tree fixes every agent at once — observer, operators, any
 * future node — with no store migration for a deployment that sets nothing.
 * (xmesh mission-79aed0, F-B4/F-B7, 2026-08-18.)
 */
const { SYM_STATE_DIR: SYM_DIR } = require('./core/state-root');

/** DER/PKCS8 Ed25519 private-key header — the 16 bytes preceding the raw 32-byte key. */
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

/** The founder's ruling, carried verbatim into the error an operator actually sees. */
const IDENTITY_RULING =
  'An agent may lose its machine and recover its data, but if it loses its private key, it ' +
  'cannot prove that it is the same agent. Therefore the key must be preserved, and the ' +
  'system must refuse to start rather than silently create a replacement identity.';

/**
 * Raised instead of minting a replacement identity.
 *
 * The failure this exists to prevent is quiet: a node whose identity.json is unreadable used to
 * log a warning and generate a fresh keypair, overwriting the old one. The agent kept its name
 * and lost the only thing that made it itself — and the damage surfaced later, elsewhere, as
 * peers rejecting its blocks as forged against the public key they had pinned.
 *
 * Halting is the recoverable outcome: the key may still be on a backup or a durable volume, and
 * an operator who is told plainly can restore it. Regenerating is the unrecoverable one.
 */
class IdentityHaltError extends Error {
  constructor(name, idPath, reason) {
    super(
      `[SYM] REFUSING TO START — cannot establish the identity of agent "${name}".\n\n` +
      `  ${reason}\n` +
      `  identity: ${idPath}\n\n` +
      `${IDENTITY_RULING}\n\n` +
      `  Restore the keypair from your durable copy and start again. If this agent's key is ` +
      `genuinely gone, it cannot return as "${name}" — peers hold its public key and will read ` +
      `anything a new key signs as forged. Set SYM_IDENTITY_DIR to a durable volume so a ` +
      `rebuilt machine restores the key instead of replacing it.`
    );
    this.name = 'IdentityHaltError';
    this.agent = name;
    this.identityPath = idPath;
    this.reason = reason;
  }
}

/** Directory containing all node data (~/.sym/nodes). */
const NODES_DIR = path.join(SYM_DIR, 'nodes');

/**
 * Where an agent's KEYPAIR lives, when it must outlive the machine.
 *
 * The store is recoverable and the keypair is not: blocks are content-addressed and can be
 * re-fetched from any peer that holds them (§15.8, self-verifying), but no peer can return a
 * private key. Peers pin the PUBLIC key at handshake, so an agent that loses its private key
 * can present the right agent id and still fail verification against the key its peers already
 * hold — an impostor the mesh is correct to reject.
 *
 * So the keypair is the one thing that must sit on a durable volume rather than inside a
 * rebuildable sandbox. Point SYM_IDENTITY_DIR at that volume and the node dir stays disposable:
 * rebuild the sandbox, restore nothing but the key, rejoin as the same agent, let cmb-fetch
 * bring the blocks back.
 *
 * Unset, identity lives in the node dir as before.
 */
/**
 * Directory holding this agent's identity.json. Separate from the node dir precisely so the
 * two can have different lifetimes — durable key, disposable store.
 *
 * The environment is read HERE rather than captured at module load. Capturing it at load time
 * makes the setting silently depend on require order: an embedder that pulls in lib/config
 * before setting SYM_IDENTITY_DIR would get the default and never be told, which for a value
 * that decides whether a keypair survives a rebuild is the wrong failure mode entirely.
 *
 * @param {string} name
 */
function identityDir(name) {
  const root = process.env.SYM_IDENTITY_DIR;
  return root ? path.join(root, name) : nodeDir(name);
}

/**
 * Ensure a directory exists, creating it recursively if needed.
 * @param {string} dir — directory path
 */
function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

/**
 * Normalize a hostname for mDNS advertisement.
 *
 * Windows' os.hostname() returns a bare NetBIOS name (e.g. "xmesh-hp") with no
 * domain suffix. Advertising that as a Bonjour SRV target produces records that
 * macOS mDNSResponder refuses to resolve (macOS answers mDNS only for the
 * `.local.` TLD), which breaks Mac↔Windows peer connections entirely.
 *
 * Bare names get `.local` appended. FQDNs and already-`.local` names pass
 * through unchanged (trailing dot stripped).
 */
function normalizeMdnsHostname(h) {
  if (!h) return h;
  const trimmed = String(h).replace(/\.$/, '');
  if (trimmed.includes('.')) return trimmed;
  return `${trimmed}.local`;
}

/**
 * Get the data directory for a named node. A name is an index (design D9): when the name index holds
 * it, this is the node's by-id directory (`nodes/by-id/<nodeId>`); otherwise the 0.13 path
 * `nodes/<name>`, which `loadIdentity` moves to the by-id layout when it first loads it.
 * @param {string} name — node name
 * @returns {string} path to the node's directory
 */
function nodeDir(name) {
  const id = nodeIdForName(name);
  return id ? nodeDirById(id) : path.join(NODES_DIR, name);
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
  // A name is one path component (security review): it names `nodes/<name>`, a compat link and an
  // index file, so a separator or a dot-name would reach outside the state root.
  if (/[\/\\]/.test(name) || name === '.' || name === '..') {
    throw new Error('Node name must not contain a path separator or be "." or ".."');
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
 * Raised when an identity that must already exist does not (`loadIdentity({ create: false })`): a
 * host restoring a known agent can never mint a replacement silently (design D9).
 */
class IdentityAbsentError extends Error {
  constructor(what) {
    super(`[SYM] No identity for ${what} on this host, and none was minted (create: false). ` +
      `Restore it (sym node import) or start it where it lives; minting a new one would be a different agent.`);
    this.name = 'IdentityAbsentError';
    this.code = 'EIDENTITYABSENT';
  }
}

/**
 * Raised for an identity that was moved away (`sym node export` wrote a tombstone, design D9): the
 * source refuses to start it, so no second live copy can exist.
 */
class IdentityTombstonedError extends Error {
  constructor(nodeId, tomb) {
    super(`[SYM] REFUSING TO START ${nodeId}: this identity was exported to another host` +
      `${tomb && tomb.movedAt ? ` on ${new Date(tomb.movedAt).toISOString()}` : ''} and is tombstoned here. ` +
      `It runs where it was imported; two live copies would be two agents claiming one key.`);
    this.name = 'IdentityTombstonedError';
    this.code = 'EIDENTITYTOMBSTONED';
    this.tombstone = tomb || null;
  }
}

/** Where a node lives, by its nodeId (design D9): <state root>/nodes/by-id/<nodeId>. */
function nodeDirById(nodeId) {
  if (!isNodeIdText(nodeId)) throw new Error(`not a nodeId: ${String(nodeId).slice(0, 40)}`);
  return path.join(NODES_DIR, 'by-id', nodeId);
}

/** Where a node's identity.json lives by nodeId: SYM_IDENTITY_DIR/by-id/<nodeId> when set, else the node dir. */
function identityDirById(nodeId) {
  const root = process.env.SYM_IDENTITY_DIR;
  return root ? path.join(root, 'by-id', nodeId) : nodeDirById(nodeId);
}

const isNodeIdText = (id) => typeof id === 'string' && /^[0-9A-Za-z][0-9A-Za-z_.-]{0,127}$/.test(id) && id !== '.' && id !== '..';
const TOMBSTONE = 'TOMBSTONE.json';
const nameIndexPath = (name) => path.join(NODES_DIR, 'by-name', `${encodeURIComponent(name)}.json`);

/** The nodeId the name index holds for `name`, or null. */
function nodeIdForName(name) {
  try {
    const r = JSON.parse(fs.readFileSync(nameIndexPath(name), 'utf8'));
    return r && isNodeIdText(r.nodeId) ? r.nodeId : null;
  } catch { return null; }
}

/** Write the name index entry (atomic) and the 0.13-compatible `nodes/<name>` symlink (one release). */
function indexName(name, nodeId) {
  ensureDir(path.join(NODES_DIR, 'by-name'));
  const file = nameIndexPath(name);
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify({ name, nodeId, at: Date.now() }));
  fs.renameSync(tmp, file);
  linkCompat(path.join(NODES_DIR, name), path.join('by-id', nodeId));
  const idRoot = process.env.SYM_IDENTITY_DIR;
  if (idRoot && fs.existsSync(path.join(idRoot, 'by-id', nodeId))) linkCompat(path.join(idRoot, name), path.join('by-id', nodeId));
}

/** `link` → `target` (relative), unless a real directory is there (a legacy layout not yet moved). */
function linkCompat(link, target) {
  try {
    const st = fs.lstatSync(link);
    if (st.isSymbolicLink()) {
      if (fs.readlinkSync(link) === target) return;
      fs.unlinkSync(link);
    } else {
      return; // a real dir: migration moves it first
    }
  } catch { /* absent */ }
  try { fs.symlinkSync(target, link, process.platform === 'win32' ? 'junction' : 'dir'); } catch { /* best effort: the index is authoritative */ }
}

/** The tombstone a moved identity left, or null. */
function readTombstone(nodeId) {
  try { return JSON.parse(fs.readFileSync(path.join(nodeDirById(nodeId), TOMBSTONE), 'utf8')); } catch { return null; }
}

/**
 * Read and validate an identity.json. Never regenerates a key: a file that exists and cannot be read
 * halts (IdentityHaltError). A pre-v0.3.7 identity with no keypair gets its first key; a private key
 * with no public key gets the public key derived from it.
 * @private
 */
function readIdentityFile(idPath, name) {
  let raw;
  try {
    raw = fs.readFileSync(idPath, 'utf8');
  } catch (e) {
    // The file EXISTS and we cannot read it. Never regenerate here — a transient read failure
    // (permissions, a full disk, a partial write) would otherwise overwrite a live keypair.
    throw new IdentityHaltError(name, idPath, `identity.json exists but could not be read: ${e.message}`);
  }
  let identity;
  try {
    identity = JSON.parse(raw);
  } catch (e) {
    throw new IdentityHaltError(name, idPath, `identity.json is not valid JSON: ${e.message}`);
  }
  if (!identity || typeof identity !== 'object' || !identity.nodeId) {
    throw new IdentityHaltError(name, idPath, 'identity.json has no nodeId — the file is not an identity');
  }
  let mutated = false;
  // NO KEYPAIR AT ALL (pre-v0.3.7 nodes): nothing to replace, so minting one gives an agent its first
  // key; the nodeId is preserved. A PRIVATE KEY BUT NO PUBLIC KEY: derive it, never generate one.
  if (!identity.publicKey && !identity.privateKey) {
    const kp = generateSigningKeyPair();
    identity.publicKey = kp.publicKey.toString('base64url');
    identity.privateKey = kp.privateKey.toString('base64url');
    mutated = true;
  } else if (!identity.publicKey) {
    const priv = crypto.createPrivateKey({
      key: Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(identity.privateKey, 'base64url')]),
      format: 'der',
      type: 'pkcs8',
    });
    const spki = crypto.createPublicKey(priv).export({ type: 'spki', format: 'der' });
    identity.publicKey = spki.subarray(spki.length - 32).toString('base64url');
    mutated = true;
  }
  // Migrate: normalize bare hostnames (pre-v0.5.1 Windows nodes)
  const normalized = normalizeMdnsHostname(identity.hostname);
  if (normalized !== identity.hostname) {
    identity.hostname = normalized;
    mutated = true;
  }
  if (mutated) fs.writeFileSync(idPath, JSON.stringify(identity, null, 2));
  return identity;
}

/**
 * Move one 0.13 node (`nodes/<name>/`, and its identity at `SYM_IDENTITY_DIR/<name>/` when that is
 * set) to `nodes/by-id/<nodeId>/`, and leave `nodes/<name>` as a symlink to it for one release (a 0.13
 * rollback reads the old path). Idempotent: a name that is already a symlink, or indexed, is left as
 * it is. A directory whose lock a live process holds is skipped: that node moves itself when it
 * restarts.
 *
 * A 0.13 identity file is read with the same reader a load uses, so one that exists and cannot be
 * established (unreadable, not JSON, no nodeId) HALTS (IdentityHaltError) instead of reading as
 * "no node here" — which would let the caller mint a replacement under the agent's name.
 * @returns {'moved'|'indexed'|'skipped-live'|'skipped-duplicate'|'not-a-node'|'already'}
 */
function migrateNodeDir(name) {
  const legacy = path.join(NODES_DIR, name);
  const idRoot = process.env.SYM_IDENTITY_DIR;
  const legacyIdDir = idRoot ? path.join(idRoot, name) : legacy;
  const lst = (p) => { try { return fs.lstatSync(p); } catch { return null; } };
  const indexFromLink = (link) => {
    const m = /by-id[\\/]([^\\/]+)$/.exec(fs.readlinkSync(link));
    if (m && isNodeIdText(m[1])) { indexName(name, m[1]); return 'indexed'; }
    return 'already';
  };
  const st = lst(legacy);
  if (st && st.isSymbolicLink()) return nodeIdForName(name) ? 'already' : indexFromLink(legacy);
  if (st && !st.isDirectory()) return 'not-a-node';
  const idSt = idRoot ? lst(legacyIdDir) : st;
  if (idRoot && idSt && idSt.isSymbolicLink()) return nodeIdForName(name) ? 'already' : indexFromLink(legacyIdDir);
  const idFile = path.join(legacyIdDir, 'identity.json');
  if (!fs.existsSync(idFile)) return 'not-a-node';
  const identity = readIdentityFile(idFile, name); // halts on an identity it cannot establish
  const nodeId = identity.nodeId;
  if (!isNodeIdText(nodeId)) throw new IdentityHaltError(name, idFile, `the nodeId ${JSON.stringify(String(nodeId).slice(0, 40))} cannot name a directory under nodes/by-id`);
  if (st) {
    const lock = readLockFile(path.join(legacy, 'lock.pid'));
    if (lock && lock.pid !== process.pid && lockIsHeldByLiveProcess(lock)) return 'skipped-live';
  }
  const dest = nodeDirById(nodeId);
  const idDest = idRoot && idSt && idSt.isDirectory() ? path.join(idRoot, 'by-id', nodeId) : null;
  // Two dirs claim one nodeId: the first one moved stays, and nothing of this one is moved.
  if ((st && fs.existsSync(dest)) || (idDest && fs.existsSync(idDest))) return 'skipped-duplicate';
  ensureDir(path.dirname(dest));
  if (st) fs.renameSync(legacy, dest);
  else ensureDir(dest);
  if (idDest) {
    ensureDir(path.dirname(idDest));
    fs.renameSync(legacyIdDir, idDest);
  }
  indexName(name, nodeId);
  return 'moved';
}

/**
 * Move every 0.13 node directory under the state root to the by-id layout (design D9, §6 of the
 * design: a one-time, idempotent move). Safe to run at every start and from several processes.
 * @returns {{ moved: number, already: number, skippedLive: number, duplicates: number }}
 */
function migrateIdentities() {
  const out = { moved: 0, already: 0, skippedLive: 0, duplicates: 0 };
  let entries;
  try { entries = fs.readdirSync(NODES_DIR, { withFileTypes: true }); } catch { return out; }
  for (const d of entries) {
    if (d.name === 'by-id' || d.name === 'by-name' || d.name.startsWith('.')) continue;
    let r;
    try { r = migrateNodeDir(d.name); } catch { continue; }
    if (r === 'moved') out.moved++;
    else if (r === 'already' || r === 'indexed') out.already++;
    else if (r === 'skipped-live') out.skippedLive++;
    else if (r === 'skipped-duplicate') out.duplicates++;
  }
  return out;
}

/**
 * Load a node's identity by nodeId or by name (design D9).
 *
 *   - `{ nodeId }` loads `nodes/by-id/<nodeId>/identity.json`;
 *   - `{ name }` resolves the name index to a nodeId (moving a 0.13 `nodes/<name>/` dir first);
 *   - `create: false` throws IdentityAbsentError when the identity is absent: a host restoring a
 *     known agent can never mint a replacement silently;
 *   - `create: true` (the default, for a brand-new agent) is the ONLY path that mints, and it mints
 *     only when the name is unknown (a name is an index; renaming changes the index, never the
 *     identity);
 *   - a tombstoned identity (exported to another host) refuses to load: IdentityTombstonedError.
 *
 * @param {{ nodeId?: string, name?: string, create?: boolean }} o
 * @returns {{ nodeId: string, name: string, hostname: string, createdAt: number, publicKey: string, privateKey: string }}
 */
function loadIdentity({ nodeId, name, create = true } = {}) {
  if (name !== undefined) validateName(name);
  if (!nodeId && !name) throw new Error('loadIdentity needs a nodeId or a name');
  if (nodeId && !isNodeIdText(nodeId)) throw new Error(`not a nodeId: ${String(nodeId).slice(0, 40)}`);
  if (!nodeId && name) {
    nodeId = nodeIdForName(name);
    if (!nodeId) {
      const r = migrateNodeDir(name);
      if (r === 'moved' || r === 'already' || r === 'indexed') nodeId = nodeIdForName(name);
      if (r === 'skipped-live') {
        // A 0.13 process of this name holds its old directory: load it in place, unmoved.
        const idRoot = process.env.SYM_IDENTITY_DIR;
        const idPath = idRoot ? path.join(idRoot, name, 'identity.json') : path.join(NODES_DIR, name, 'identity.json');
        return readIdentityFile(idPath, name);
      }
    }
  }
  if (nodeId) {
    const tomb = readTombstone(nodeId);
    if (tomb) throw new IdentityTombstonedError(nodeId, tomb);
    const idPath = path.join(identityDirById(nodeId), 'identity.json');
    if (fs.existsSync(idPath)) {
      const identity = readIdentityFile(idPath, name || nodeId);
      if (identity.nodeId !== nodeId) throw new IdentityHaltError(name || nodeId, idPath, `identity.json names ${identity.nodeId}, not ${nodeId}`);
      if (name && nodeIdForName(name) !== nodeId) indexName(name, nodeId);
      return identity;
    }
    if (!create || !name) throw new IdentityAbsentError(name ? `"${name}" (${nodeId})` : nodeId);
  }
  if (!create) throw new IdentityAbsentError(`"${name}"`);
  // No identity under this name: a genuinely new agent. This is the ONLY path that mints one.
  const kp = generateSigningKeyPair();
  const identity = {
    nodeId: uuidv7(),
    name,
    hostname: normalizeMdnsHostname(os.hostname()),
    createdAt: Date.now(),
    publicKey: kp.publicKey.toString('base64url'),
    privateKey: kp.privateKey.toString('base64url'),
  };
  // A 0.13-style `nodes/<name>/` dir with no identity (made by hand, or by a test) is the new node's
  // dir: it moves with the identity rather than being left behind.
  const legacy = path.join(NODES_DIR, name);
  let legacyDir = false;
  try { legacyDir = fs.lstatSync(legacy).isDirectory(); } catch { /* absent */ }
  const dir = nodeDirById(identity.nodeId);
  ensureDir(path.dirname(dir));
  if (legacyDir) fs.renameSync(legacy, dir);
  ensureDir(dir);
  const idDir = identityDirById(identity.nodeId);
  ensureDir(idDir);
  fs.writeFileSync(path.join(idDir, 'identity.json'), JSON.stringify(identity, null, 2), { mode: 0o600 });
  indexName(name, identity.nodeId);
  return identity;
}

/**
 * Load or create a persistent identity for a node (0.13 API, kept): `loadIdentity({ name, create: true })`.
 * See MMP §3 (Identity).
 * @param {string} name — node name
 */
function loadOrCreateIdentity(name) {
  return loadIdentity({ name, create: true });
}

/**
 * Rename a node: the name index moves; the identity (nodeId, key) does not (design D9).
 * @returns {string} the nodeId
 */
function renameIdentity(oldName, newName) {
  validateName(oldName); validateName(newName);
  const nodeId = nodeIdForName(oldName);
  if (!nodeId) throw new IdentityAbsentError(`"${oldName}"`);
  if (nodeIdForName(newName)) throw new Error(`the name "${newName}" already indexes a node`);
  indexName(newName, nodeId);
  try { fs.unlinkSync(nameIndexPath(oldName)); } catch { /* */ }
  try { if (fs.lstatSync(path.join(NODES_DIR, oldName)).isSymbolicLink()) fs.unlinkSync(path.join(NODES_DIR, oldName)); } catch { /* */ }
  return nodeId;
}

/**
 * True if `pid` refers to a live process. `process.kill(pid, 0)` sends no
 * signal but throws ESRCH when the process is gone; EPERM means the
 * process exists but isn't ours to signal (still alive). Works on POSIX
 * and Windows in Node.
 * @param {number} pid
 * @returns {boolean}
 */
function pidIsAlive(pid) {
  if (!Number.isFinite(pid)) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return e.code === 'EPERM';
  }
}

/**
 * Grace period (ms) during which an unparseable lockfile is treated as
 * held rather than stale — it may be mid-write by a peer that just won the
 * O_EXCL create but hasn't written its PID yet. Beyond this age an
 * unparseable lockfile is corrupt and reclaimed.
 */
const LOCK_CORRUPT_GRACE_MS = 2000;

/**
 * Slack (ms) when comparing a lockfile's mtime against system boot time.
 * os.uptime() has 1-second resolution and filesystem timestamps can skew
 * slightly relative to it.
 */
const LOCK_BOOT_SLACK_MS = 5000;

/** Wall-clock time (ms epoch) at which the OS booted. */
function bootTimeMs() {
  return Date.now() - os.uptime() * 1000;
}

/**
 * The kernel start time of a process, as an opaque stable string
 * (`ps -o lstart=`, or ISO-8601 UTC from PowerShell on Windows), or null
 * when it cannot be determined (dead PID, ps/PowerShell unavailable, access denied). Two different processes that reuse the same
 * PID number have different start times — this is what lets the identity
 * lock distinguish "our previous holder is still running" from "an
 * unrelated process recycled the holder's PID".
 * @param {number} pid
 * @param {{fresh?: boolean}} [opts] — fresh: re-read even if a start time is remembered
 * @returns {string|null}
 */
function processStartTime(pid, { fresh = false } = {}) {
  const cache = startTimeCache();
  if (cache) return cachedProcessStartTime(cache, pid, fresh);
  try {
    const out = execFileSync('ps', ['-p', String(pid), '-o', 'lstart='], {
      encoding: 'utf8',
      env: { ...process.env, LC_ALL: 'C' }, // stable date format
      timeout: 3000,
    }).trim();
    return out || null;
  } catch {
    return null;
  }
}

/**
 * Read the start times of several processes at once, so a later processStartTime() for any of
 * them is answered from memory. A no-op where reads are cheap enough not to be remembered (`ps`).
 * @param {number[]} pids
 */
function primeProcessStartTimes(pids) {
  const cache = startTimeCache();
  if (cache) cache.prime(pids.filter(validStartTimePid));
}

/**
 * A memory of process start times in front of a slow lookup — on Windows every read is a
 * PowerShell process (~0.45 s, synchronous), and a daemon start checks the lock of every node
 * directory.
 *
 * A start time belongs to a PROCESS, and a live process's start time never changes, so a
 * successful read is kept for as long as the pid stays alive. Once the pid is seen dead the
 * entry is dropped, because the number is now free for an unrelated process. A failed read is
 * kept only briefly: it may be a transient timeout, but retrying it on every check would put a
 * multi-second call back on every lock check for a process we cannot read.
 *
 * What memory cannot see is a holder that dies and whose pid is reused BETWEEN two of our
 * checks: nothing observed it dead, so its remembered start outlives it. `fresh` re-reads and
 * replaces the entry, and the lock check re-reads before it acts on a mismatch (see
 * lockIsHeldByLiveProcess) — so a remembered value can only err toward "held", the direction a
 * failed lookup already takes, never toward handing a live holder's lock to someone else.
 *
 * @param {(pids: number[]) => Map<number, string>} lookup — reads many pids in ONE call; a pid
 *   it cannot read is absent from the result; throwing means it could read none
 * @param {object} [o]
 * @param {(pid: number) => boolean} [o.isAlive]
 * @param {number} [o.failureTtlMs] — how long a failed read is remembered
 * @param {() => number} [o.now]
 */
function createStartTimeCache(lookup, { isAlive = pidIsAlive, failureTtlMs = START_FAILURE_TTL_MS, now = Date.now } = {}) {
  const entries = new Map(); // pid → { value: string|null, at: ms }
  const remembered = (pid) => {
    const e = entries.get(pid);
    return Boolean(e) && (e.value !== null || now() - e.at < failureTtlMs);
  };
  const read = (pids) => {
    let got;
    try { got = lookup(pids); } catch { got = null; }
    for (const pid of pids) {
      const value = got instanceof Map && typeof got.get(pid) === 'string' ? got.get(pid) : null;
      entries.set(pid, { value, at: now() });
    }
  };
  return {
    /** The start time of `pid`, or null when it is dead or cannot be read. */
    get(pid, { fresh = false } = {}) {
      if (!isAlive(pid)) { entries.delete(pid); return null; }
      if (fresh || !remembered(pid)) read([pid]);
      return entries.get(pid).value;
    },
    /** Read every live pid not already remembered, in one lookup. */
    prime(pids) {
      const need = [];
      for (const pid of new Set(pids)) {
        if (!isAlive(pid)) entries.delete(pid);
        else if (!remembered(pid)) need.push(pid);
      }
      if (need.length) read(need);
    },
    clear() { entries.clear(); },
  };
}
const START_FAILURE_TTL_MS = 10000;

function validStartTimePid(pid) {
  return Number.isInteger(pid) && pid > 0 && pid <= 0xffffffff;
}

let _startTimeCache = null;
let _startTimeLookupOverride = null; // test hook: see _setProcessStartTimeLookup
let _startTimeWarned = false;

/** The remembered-start-time path, or null where start times are read directly (`ps`). */
function startTimeCache() {
  if (!_startTimeLookupOverride && process.platform !== 'win32') return null;
  if (!_startTimeCache) _startTimeCache = createStartTimeCache(_startTimeLookupOverride || windowsStartTimes);
  return _startTimeCache;
}

/**
 * Failure (no PowerShell, a timeout, access denied for another user's or a protected process)
 * returns null, which every reader treats as "held": the safe direction, and the pre-0.13.13
 * behaviour. A one-time warning says so.
 */
function cachedProcessStartTime(cache, pid, fresh) {
  if (!validStartTimePid(pid)) return null;
  const value = cache.get(pid, { fresh });
  if (value === null && !_startTimeWarned && pidIsAlive(pid)) {
    _startTimeWarned = true;
    process.emitWarning(`SYM identity lock: could not read the start time of process ${pid}; ` +
      'a lock held by that PID is treated as live (delete ~/.sym/nodes/<name>/lock.pid if its holder is gone).');
  }
  return value;
}

/**
 * Windows has no `ps`. PowerShell reports a process's start time; the UTC ISO-8601 form is stable
 * across calls and locales, so the lock writer (for itself) and a later reader (for the same PID)
 * produce the same string. Without it, a Windows lock recorded no start time and a crashed
 * holder's recycled PID kept the name locked until reboot.
 *
 * Every pid asked for is read in ONE PowerShell process: `Get-Process -Id a,b,c` skips the ones
 * that are gone, and a process whose start time cannot be read (access denied) prints nothing,
 * so it is simply absent from the result. `exit 0` because PowerShell exits 1 when any pid in
 * the list was missing, which would otherwise throw away the ones it did read. The
 * per-process expression is the one earlier versions used for a single pid, so the strings
 * match locks those versions wrote.
 * @param {number[]} pids
 * @returns {Map<number, string>}
 */
function windowsStartTimes(pids) {
  const out = execFileSync(windowsPowerShellPath(), [
    '-NoProfile', '-NonInteractive', '-Command',
    `Get-Process -Id ${pids.join(',')} -ErrorAction SilentlyContinue | ForEach-Object { ` +
      `try { '{0} {1}' -f $_.Id, $_.StartTime.ToUniversalTime().ToString('o') } catch { } }; exit 0`,
  ], { encoding: 'utf8', timeout: 5000 + 250 * pids.length, windowsHide: true });
  const times = new Map();
  for (const line of out.split(/\r?\n/)) {
    const m = /^(\d+) (\d{4}-\d{2}-\d{2}T[\d:.]+Z)$/.exec(line.trim());
    if (m) times.set(Number(m[1]), m[2]);
  }
  return times;
}

/** The system PowerShell by absolute path, never whatever `powershell.exe` the search path finds first. */
function windowsPowerShellPath() {
  const root = process.env.SystemRoot || process.env.windir || 'C:\\Windows';
  return path.join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
}

let _selfStartTime = null;
let _selfStartTimeResolved = false;
/** processStartTime(process.pid), computed once per process. */
function selfStartTime() {
  if (!_selfStartTimeResolved) {
    _selfStartTime = processStartTime(process.pid);
    // A failed lookup (a transient timeout) is not cached: the next acquire tries again.
    _selfStartTimeResolved = _selfStartTime !== null;
  }
  return _selfStartTime;
}

/**
 * Parse a node identity lockfile. Two formats exist:
 *   - v2 (current): line 1 is the bare holder PID, line 2 is a JSON
 *     metadata object `{"start": <ps lstart>, "createdAt": <ms>}`. Legacy
 *     readers that `parseInt()` the whole file still get the PID from the
 *     numeric prefix, so both directions interoperate.
 *   - legacy: the bare PID and nothing else.
 * @param {string} lockPath — absolute path to the lock.pid file
 * @returns {{pid: number|null, start: string|null, mtimeMs: number}|null}
 *   null when the file is absent/unreadable; pid null when content is
 *   unparseable (corrupt or mid-write).
 */
function readLockFile(lockPath) {
  let raw, mtimeMs;
  try {
    raw = fs.readFileSync(lockPath, 'utf8');
    mtimeMs = fs.statSync(lockPath).mtimeMs;
  } catch {
    return null;
  }
  const lines = raw.split('\n');
  const pid = parseInt(lines[0].trim(), 10);
  let start = null;
  if (lines.length > 1 && lines[1].trim()) {
    try {
      const meta = JSON.parse(lines[1]);
      if (meta && typeof meta.start === 'string') start = meta.start;
    } catch {
      // metadata line corrupt — fall back to PID-only semantics
    }
  }
  return {
    pid: Number.isFinite(pid) && pid > 0 ? pid : null,
    start,
    mtimeMs,
  };
}

/**
 * True when a parsed lockfile is held by a LIVE process — i.e. the process
 * that wrote it is still running. This is the single liveness authority
 * for identity locks, and it defends against every observed staleness
 * mode, not just a dead PID:
 *
 *   - dead PID (ESRCH)                          → stale
 *   - PID recycled by an unrelated process       → stale (start-time mismatch;
 *     `process.kill(pid, 0)` alone would say "alive" — this was the live
 *     failure where a leaked pre-reboot lock's PID was reoccupied after
 *     boot and blocked the daemon's primary node forever)
 *   - legacy PID-only lock written before the current boot → stale (its
 *     holder cannot have survived the reboot, whatever now owns that PID)
 *   - unparseable content                        → stale once older than a
 *     short grace window (mid-write by a racing acquirer), else held
 *
 * EPERM from kill(pid, 0) still means "exists but not ours to signal" =
 * alive; the start-time comparison works regardless of process ownership
 * because `ps` can read other users' processes.
 * @param {{pid: number|null, start: string|null, mtimeMs: number}} lock
 * @returns {boolean}
 */
function lockIsHeldByLiveProcess(lock) {
  if (!lock) return false;
  if (lock.pid === null) {
    // Corrupt/empty content: held only while young enough to be a racing
    // writer between its O_EXCL create and its PID write.
    return Date.now() - lock.mtimeMs < LOCK_CORRUPT_GRACE_MS;
  }
  if (!pidIsAlive(lock.pid)) return false;
  if (lock.start) {
    let current = processStartTime(lock.pid);
    // A remembered start time (Windows) may predate a death and reuse of this pid that no
    // check observed. A mismatch hands the lock to someone else, so it is never concluded
    // from memory: re-read first. A match errs only toward "held". (`ps` is never remembered.)
    if (current && current !== lock.start && startTimeCache()) current = processStartTime(lock.pid, { fresh: true });
    if (current && current !== lock.start) return false; // PID reused
  } else if (lock.mtimeMs < bootTimeMs() - LOCK_BOOT_SLACK_MS) {
    // Legacy lock with no start-time metadata, written before this boot:
    // the writer died at reboot; a live PID here is reuse by definition.
    return false;
  }
  return true;
}

/**
 * lockIsHeldByLiveProcess for several locks, with every holder's start time read in one
 * lookup rather than one per lock — on Windows that is one PowerShell process instead of one
 * per node directory.
 * @param {Array<{pid: number|null, start: string|null, mtimeMs: number}|null>} locks
 * @returns {boolean[]}
 */
function locksHeldByLiveProcess(locks) {
  primeProcessStartTimes(locks.filter((l) => l && l.pid !== null && l.start).map((l) => l.pid));
  return locks.map((l) => lockIsHeldByLiveProcess(l));
}

/**
 * Read the holder PID from a node's lockfile, or null if the lockfile is
 * absent, unreadable, or has non-numeric content. Understands both the
 * legacy bare-PID format and the current PID+metadata format.
 * @param {string} name — node name
 * @returns {number|null}
 */
function lockHolderPid(name) {
  const lock = readLockFile(path.join(nodeDir(name), 'lock.pid'));
  return lock ? lock.pid : null;
}

// ── Held-lock registry + exit hooks ─────────────────────────────────────
// Every lock this process holds is tracked here so a process-level exit
// hook can release them all. stop() remains the primary release path; the
// hooks cover hosts that exit without calling stop() (process.exit, an
// uncaught exception, a default-disposition SIGTERM/SIGINT). SIGKILL can
// never be caught — that case is healed at the next acquire by the
// stale-lock reclaim above.
const _heldLockPaths = new Set();
let _exitHooksInstalled = false;

/** Delete a lockfile iff this process is its recorded holder. */
function _releaseLockIfOurs(lockPath) {
  try {
    const lock = readLockFile(lockPath);
    // Only delete if it's still ours (don't clobber a successor's lock)
    if (lock && lock.pid === process.pid) fs.unlinkSync(lockPath);
  } catch {
    // Lockfile already gone or unreadable — nothing to do
  }
}

function _sweepHeldLocks() {
  for (const p of _heldLockPaths) _releaseLockIfOurs(p);
  _heldLockPaths.clear();
}

function _installExitHooks() {
  if (_exitHooksInstalled) return;
  _exitHooksInstalled = true;
  process.on('exit', _sweepHeldLocks);
  // Death by signal does NOT run 'exit' handlers. When the host has no
  // handler of its own for a fatal signal, convert the default death into
  // a clean exit so held locks are released. When the host DOES handle the
  // signal (listenerCount > 1 — ours plus theirs), defer entirely: its
  // shutdown path calls stop()/process.exit(), and the 'exit' sweep runs.
  const signums = { SIGHUP: 1, SIGINT: 2, SIGTERM: 15 };
  for (const [sig, num] of Object.entries(signums)) {
    process.on(sig, () => {
      if (process.listenerCount(sig) === 1) {
        _sweepHeldLocks();
        process.exit(128 + num);
      }
    });
  }
}

/**
 * NAME-SUFFIXING IS DELETED (founder ruling, agent id = node id).
 *
 * The name-suffixing resolver used to answer a same-host collision by returning
 * `<base>-2`, `-3`, … That was never collision handling. An agent id names an AGENT, and
 * two live processes of one agent are the same agent — so suffixing quietly minted a
 * SECOND IDENTITY for a single participant, with its own keypair, its own store, and no
 * relationship to the first that any peer could see.
 *
 * It is the direct cause of resumed sessions going invisible: peers kept pushing to the
 * original name while the returning process had silently become `<name>-2`. It is also a
 * forking mechanism for content addresses, for the same reason the uuid was.
 *
 * A collision is now decided by the single-writer lease in `acquireIdentityLock`, which
 * refuses the second process rather than inventing a name for it.
 */

/**
 * Acquire an exclusive lock on a node identity. Prevents two processes
 * from claiming the same nodeId on the same host, which would cause
 * duplicate-identity races on the relay (close code 4004 / 4006 loops)
 * and ambiguous CMB delivery.
 *
 * Lockfile lives at ~/.sym/nodes/<name>/lock.pid: line 1 is the holder's
 * PID (legacy parsers read exactly this), line 2 is JSON metadata with the
 * holder's process start time — the disambiguator that makes staleness
 * detection immune to PID reuse. On acquire:
 *   1. If no lockfile exists, write PID+metadata and return a release fn.
 *   2. If the lockfile's holder is LIVE (see lockIsHeldByLiveProcess:
 *      alive PID *and* matching start time), throw EIDENTITYLOCK.
 *   3. Otherwise the lock is stale (dead PID, recycled PID, pre-boot
 *      legacy lock, aged-out corrupt content) — reclaim it.
 *
 * The release function deletes the lockfile. SymNode calls it on stop();
 * a process-level 'exit' hook (plus default-disposition SIGHUP/SIGINT/
 * SIGTERM conversion) releases any still-held locks so ordinary
 * non-stop() exits don't leak. SIGKILL still leaks by nature — healed at
 * the next acquire by step 3.
 *
 * @param {string} name — node name
 * @param {number} [_attempt] — internal EEXIST-race retry counter
 * @returns {() => void} release function — call to delete the lockfile
 * @throws {Error} if another process already holds the lock
 */
function acquireIdentityLock(name, opts = {}, _attempt = 0) {
  validateName(name);
  // The lock lives in the node's own directory: by nodeId since 0.14 (opts.dir); `nodes/<name>` is a
  // link to it for one release, so a 0.13 process of the same agent contends for the same file.
  const dir = (opts && opts.dir) || nodeDir(name);
  ensureDir(dir);
  const lockPath = path.join(dir, 'lock.pid');

  const makeRelease = () => {
    _heldLockPaths.add(lockPath);
    _installExitHooks();
    return function release() {
      _heldLockPaths.delete(lockPath);
      _releaseLockIfOurs(lockPath);
    };
  };

  const lock = readLockFile(lockPath);
  if (lock) {
    // Same-PID re-acquisition is allowed: this happens in tests that
    // create multiple SymNodes with the same name in sequence, in
    // hot-reload scenarios, and in recovery flows where a single
    // process re-initializes after a soft failure. The lock is meant
    // to catch CROSS-PROCESS duplicates (the actual bug), not
    // in-process re-init.
    if (lock.pid === process.pid) return makeRelease();
    if (lockIsHeldByLiveProcess(lock)) {
      const err = new Error(
        `[SYM] Agent '${name}' is already live in PID ${lock.pid ?? 'unknown'} on this host.\n\n` +
        `  An agent id names an AGENT, not a process. Two processes of the same agent ARE ` +
        `the same agent, so they share one identity and one store, and only one may hold ` +
        `the write lease at a time. This process is refused; the running one keeps it.\n\n` +
        `  If that other process is orphaned, stop it and start again. Do NOT work around ` +
        `this by choosing a different name: a different agent id is a DIFFERENT AGENT, with ` +
        `its own keypair and its own history, and peers will treat it as a stranger.`
      );
      err.code = 'EIDENTITYLOCK';
      err.holderPid = lock.pid;
      throw err;
    }
    // Stale lock — delete the file so the openSync('wx') below succeeds.
    // Without this unlink, the EEXIST retry below could never make progress.
    try { fs.unlinkSync(lockPath); } catch {}
  }

  // Atomic create: O_EXCL fails if another process creates the file
  // between our read above and our write. The fallback re-reads and
  // re-checks the holder, bounded so pathological contention can't
  // recurse forever.
  let fd;
  try {
    fd = fs.openSync(lockPath, 'wx');
  } catch (e) {
    if (e.code === 'EEXIST' && _attempt < 5) {
      // Lost the race — re-acquire (retry handles the new state)
      return acquireIdentityLock(name, opts, _attempt + 1);
    }
    throw e;
  }
  fs.writeSync(
    fd,
    `${process.pid}\n${JSON.stringify({ start: selfStartTime(), createdAt: Date.now() })}\n`,
  );
  fs.closeSync(fd);

  return makeRelease();
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
  identityDir,
  identityDirById,
  nodeDirById,
  nodeIdForName,
  loadIdentity,
  migrateIdentities,
  migrateNodeDir,
  renameIdentity,
  readTombstone,
  TOMBSTONE,
  IdentityHaltError,
  IdentityAbsentError,
  IdentityTombstonedError,
  uuidv7,
  validateName,
  generateSigningKeyPair,
  loadOrCreateIdentity,
  normalizeMdnsHostname,
  pidIsAlive,
  processStartTime,
  primeProcessStartTimes,
  /** Test hook: forget remembered start times, so the next read reaches the lookup. */
  _clearProcessStartTimeCache: () => { if (_startTimeCache) _startTimeCache.clear(); },
  /**
   * Test hook: read start times through `lookup` (see createStartTimeCache) on every platform,
   * so the remembered-start-time path Windows takes can be exercised anywhere. null restores
   * the platform default.
   */
  _setProcessStartTimeLookup: (lookup) => {
    _startTimeLookupOverride = lookup || null;
    _startTimeCache = null;
    _startTimeWarned = false;
  },
  _createStartTimeCache: createStartTimeCache,
  /** Test hook (win32 only): the raw batched PowerShell lookup. */
  _windowsStartTimes: windowsStartTimes,
  readLockFile,
  lockIsHeldByLiveProcess,
  locksHeldByLiveProcess,
  lockHolderPid,
  acquireIdentityLock,
  log,
};
