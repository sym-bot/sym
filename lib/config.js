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
  const dir = identityDir(name);
  ensureDir(dir);
  const idPath = path.join(dir, 'identity.json');
  if (fs.existsSync(idPath)) {
    let raw;
    try {
      raw = fs.readFileSync(idPath, 'utf8');
    } catch (e) {
      // The file EXISTS and we cannot read it. Never regenerate here — a transient read
      // failure (permissions, a full disk, a partial write) would otherwise overwrite a
      // live keypair, and the old private key is gone the moment we do.
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
    {
      let mutated = false;
      // Two different situations wear the same shape here, and only one of them is the
      // forbidden one.
      //
      //   NO KEYPAIR AT ALL (pre-v0.3.7 nodes): there is nothing to replace, so minting one
      //   is not "creating a replacement identity" — it is giving an agent its first key.
      //   Allowed, and the nodeId is preserved so the agent stays itself.
      //
      //   A PRIVATE KEY PRESENT BUT NO PUBLIC KEY: the public key must be DERIVED from the
      //   private one, never generated. Minting a fresh pair would discard a live private
      //   key, and every peer holding the old public key would read this agent's blocks as
      //   forged. Ed25519 public keys are a function of the private key, so derivation is
      //   exact and lossless.
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
  }
  // No identity file: a genuinely new agent. This is the ONLY path that mints one.
  const kp = generateSigningKeyPair();
  const identity = {
    nodeId: uuidv7(),
    name,
    hostname: normalizeMdnsHostname(os.hostname()),
    createdAt: Date.now(),
    publicKey: kp.publicKey.toString('base64url'),
    privateKey: kp.privateKey.toString('base64url'),
  };
  fs.writeFileSync(idPath, JSON.stringify(identity, null, 2));
  return identity;
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
 * (`ps -o lstart=`), or null when it cannot be determined (dead PID,
 * Windows, ps unavailable). Two different processes that reuse the same
 * PID number have different start times — this is what lets the identity
 * lock distinguish "our previous holder is still running" from "an
 * unrelated process recycled the holder's PID".
 * @param {number} pid
 * @returns {string|null}
 */
function processStartTime(pid) {
  if (process.platform === 'win32') return null;
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

let _selfStartTime = null;
let _selfStartTimeResolved = false;
/** processStartTime(process.pid), computed once per process. */
function selfStartTime() {
  if (!_selfStartTimeResolved) {
    _selfStartTime = processStartTime(process.pid);
    _selfStartTimeResolved = true;
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
    const current = processStartTime(lock.pid);
    if (current && current !== lock.start) return false; // PID reused
  } else if (lock.mtimeMs < bootTimeMs() - LOCK_BOOT_SLACK_MS) {
    // Legacy lock with no start-time metadata, written before this boot:
    // the writer died at reboot; a live PID here is reuse by definition.
    return false;
  }
  return true;
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
function acquireIdentityLock(name, _attempt = 0) {
  validateName(name);
  const dir = nodeDir(name);
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
      return acquireIdentityLock(name, _attempt + 1);
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
  IdentityHaltError,
  uuidv7,
  validateName,
  generateSigningKeyPair,
  loadOrCreateIdentity,
  normalizeMdnsHostname,
  pidIsAlive,
  processStartTime,
  readLockFile,
  lockIsHeldByLiveProcess,
  lockHolderPid,
  acquireIdentityLock,
  log,
};
