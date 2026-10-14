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
  /**
   * @param {string} name
   * @param {string} idPath - the file the halt is about
   * @param {string} reason
   * @param {string} [advice] - what to do, when the general advice (restore the keypair) is not it: the key
   *   may be on this host, and then the advice says where, never "start over"
   */
  constructor(name, idPath, reason, advice) {
    super(
      `[SYM] REFUSING TO START — cannot establish the identity of agent "${name}".\n\n` +
      `  ${reason}\n` +
      `  identity: ${idPath}\n\n` +
      `${IDENTITY_RULING}\n\n` +
      (advice ? `  ${advice}` :
        `  Restore the keypair from your durable copy and start again. If this agent's key is ` +
        `genuinely gone, it cannot return as "${name}" — peers hold its public key and will read ` +
        `anything a new key signs as forged. Set SYM_IDENTITY_DIR to a durable volume so a ` +
        `rebuilt machine restores the key instead of replacing it.`)
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
 * `nodes/<name>`, which `loadIdentity` copies to the by-id layout when it first loads it.
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
 * Why `name` cannot be a node name at all (MMP §3.1.2, and one path component), or null.
 * @private
 */
function basicNameProblem(name) {
  if (!name || typeof name !== 'string') return 'Node name must be a non-empty string';
  const byteLength = Buffer.byteLength(name, 'utf8');
  if (byteLength < 1 || byteLength > 64) return `Node name must be 1-64 bytes (got ${byteLength})`;
  // Reject control characters (U+0000-U+001F, U+007F-U+009F)
  if (/[\x00-\x1f\x7f-\x9f]/.test(name)) return 'Node name must not contain control characters';
  // A name is one path component (security review): it names `nodes/<name>`, a compat link and an
  // index file, so a separator or a dot-name would reach outside the state root.
  if (/[\/\\]/.test(name) || name === '.' || name === '..') return 'Node name must not contain a path separator or be "." or ".."';
  return null;
}

/**
 * Why Windows could not hold `name` as a directory name, or null. The rule mesh-channel's
 * nodeNameProblem applies: the characters Windows refuses in a file name, the device names it reserves
 * whatever the extension (CON, NUL, COM1, ...), and a trailing dot or space, which Windows drops (so two
 * names would share one directory). A name is `nodes/<name>` on every platform, and a node moved to a
 * Windows host must still have one.
 * @private
 */
function windowsNameProblem(name) {
  if (/[:*?"<>|]/.test(name)) return 'Node name must not contain any of : * ? " < > | (not valid in a file name on every platform)';
  if (/^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$/i.test(name)) return 'Node name must not be a name Windows reserves (CON, PRN, AUX, NUL, COM0-9, LPT0-9, with or without an extension)';
  if (/[. ]$/.test(name)) return 'Node name must not end with a dot or a space (Windows drops it, so two names would share one directory)';
  return null;
}

/**
 * Validate a node name per MMP Section 3.1.2.
 * Must be valid UTF-8, 1-64 bytes, printable characters only, one path component, and a name every
 * platform can hold as a directory name.
 * @param {string} name
 * @throws {Error} if name is invalid
 */
function validateName(name) {
  const problem = basicNameProblem(name) || windowsNameProblem(name);
  if (problem) throw new Error(problem);
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
 * host restoring a known agent can never mint a replacement silently (design D9). It says what IS on
 * this host under the name when something is (a node's files without an identity, another agent's
 * identity), so "no identity" is never said of a host that holds one: that case is an IdentityHaltError.
 */
class IdentityAbsentError extends Error {
  constructor(what, seen = []) {
    super(`[SYM] No identity for ${what} on this host, and none was minted (create: false). ` +
      (seen.length ? `What is here instead: ${seen.join('; ')}. ` : '') +
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

/**
 * Raised for an identity whose export began and did not finish (relocation.js wrote EXPORTING.json beside
 * the key, and no tombstone yet): a bundle may exist, so the source does not start it until the export is
 * finished (run it again) or abandoned (`abortExport`, which removes the bundle it wrote).
 */
class IdentityExportPendingError extends Error {
  constructor(nodeId, intent) {
    super(`[SYM] REFUSING TO START ${nodeId}: an export of this identity` +
      `${intent && intent.out ? ` to ${intent.out}` : ''}${intent && intent.startedAt ? `, begun ${new Date(intent.startedAt).toISOString()},` : ''} did not finish. ` +
      'A bundle of it may exist; started here as well, there could be two live copies. Finish the export (run `sym node export` ' +
      'again) or abandon it (relocation.abortExport({ nodeId }), which removes the bundle it wrote; delete any copy made of that file).');
    this.name = 'IdentityExportPendingError';
    this.code = 'EIDENTITYEXPORTING';
    this.intent = intent || null;
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
  if (root && !isNodeIdText(nodeId)) throw new Error(`not a nodeId: ${String(nodeId).slice(0, 40)}`);
  return root ? path.join(root, 'by-id', nodeId) : nodeDirById(nodeId);
}

const isNodeIdText = (id) => typeof id === 'string' && /^[0-9A-Za-z][0-9A-Za-z_.-]{0,127}$/.test(id) && id !== '.' && id !== '..';
const TOMBSTONE = 'TOMBSTONE.json';
/** Beside the key while an export is under way (relocation.js): the bundle may exist, the tombstone does not yet. */
const EXPORTING = 'EXPORTING.json';
/**
 * The commit record of a directory this release installed: written into the staging directory before the
 * one rename that puts it in place, so a directory that carries it is complete. A by-id directory without
 * it was made by something else (a lock, an earlier release's interrupted move) and is never taken for
 * "the identity is in place" by a migration.
 */
const COMMIT_MARK = '.sym-commit';
/** Where a migrated 0.13 directory is set aside, under the root it was in. Nothing deletes it automatically. */
const LEGACY_ASIDE = '.legacy-0.13';
const nameIndexPath = (name) => path.join(NODES_DIR, 'by-name', `${encodeURIComponent(name)}.json`);
const lstatOrNull = (p) => { try { return fs.lstatSync(p); } catch { return null; } };
const statOrNull = (p) => { try { return fs.statSync(p); } catch { return null; } };
const randomTag = () => crypto.randomBytes(4).toString('hex');
/** The errors a rename gives when its target is taken (by a directory that is not empty, on Windows by any). */
const RENAME_TAKEN = new Set(['EEXIST', 'ENOTEMPTY', 'EPERM', 'EISDIR', 'ENOTDIR']);
/** A short synchronous pause, for the few places that let another start finish a step of a few system calls. */
const pause = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

// ── Durable files ────────────────────────────────────────────────────────

/** fsync a directory, so a rename or create in it survives a crash. Best effort where unsupported (Windows). */
function fsyncDir(dir) {
  let fd;
  try { fd = fs.openSync(dir, 'r'); fs.fsyncSync(fd); } catch { /* not supported here */ } finally { if (fd !== undefined) try { fs.closeSync(fd); } catch { /* */ } }
}

/** fsync a file by path. Best effort: a file this process may not open for writing is still read back by the verify. */
function fsyncFile(file) {
  let fd;
  try { fd = fs.openSync(file, 'r+'); fs.fsyncSync(fd); } catch { /* not ours to open for writing */ } finally { if (fd !== undefined) try { fs.closeSync(fd); } catch { /* */ } }
}

/** Write `text` to a new file `file` (it must not exist), synced. A failure removes what it made (it made it: O_EXCL). */
function writeNewFileSynced(file, text, mode) {
  const fd = fs.openSync(file, 'wx', mode);
  try {
    try { fs.writeSync(fd, text); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    fs.chmodSync(file, mode);
  } catch (e) {
    try { fs.unlinkSync(file); } catch { /* */ }
    throw e;
  }
}

/** A temp file beside `file`, written and synced: the first step of a durable replace or an exclusive create. */
function writeTempBeside(file, text, mode) {
  const tmp = path.join(path.dirname(file), `.${path.basename(file)}.${process.pid}-${randomTag()}.tmp`);
  writeNewFileSynced(tmp, text, mode);
  return tmp;
}

/** Replace `file` with `text` in one step: a synced temp file renamed over it, and the directory synced. */
function writeFileDurable(file, text, mode = 0o600) {
  const tmp = writeTempBeside(file, text, mode);
  try { fs.renameSync(tmp, file); } catch (e) { try { fs.unlinkSync(tmp); } catch { /* */ } throw e; }
  fsyncDir(path.dirname(file));
}

/**
 * Create `file` holding `text`, only if no file is there: true when this call made it, false when one already
 * was. The content is written and synced under a temp name and then hard-linked into place, so the file is never
 * seen empty or half written; `link` fails with EEXIST when the name is taken, and of several processes exactly
 * one wins. Where hard links are not supported, an O_EXCL create written in place.
 */
function createFileExclusive(file, text, mode = 0o644) {
  const tmp = writeTempBeside(file, text, mode);
  try {
    try {
      fs.linkSync(tmp, file);
      return true;
    } catch (e) {
      if (e.code === 'EEXIST') return false;
      if (!['EPERM', 'ENOTSUP', 'EOPNOTSUPP', 'ENOSYS', 'EXDEV', 'EMLINK'].includes(e.code)) throw e;
    }
    try { writeNewFileSynced(file, text, mode); return true; } catch (e) { if (e.code === 'EEXIST') return false; throw e; }
  } finally {
    try { fs.unlinkSync(tmp); } catch { /* */ }
    fsyncDir(path.dirname(file));
  }
}

// ── The name index (the record of which node a name is) ──────────────────

/**
 * The nodeId the name index holds for `name`; null ONLY when there is no entry (ENOENT). An entry that
 * exists and cannot be read, or does not hold a nodeId, is the record of an agent that cannot be read: it
 * halts (IdentityHaltError), and is never taken for "no such agent" (a start that took it so made a new
 * identity while the original was on disk).
 * @param {string} name
 * @returns {string|null}
 */
function nodeIdForName(name) {
  const file = nameIndexPath(name);
  let raw;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch (e) {
    if (e.code === 'ENOENT') return null;
    throw unreadableIndex(name, file, `it could not be read (${e.code || e.message})`);
  }
  let r = null;
  try { r = JSON.parse(raw); } catch { /* below */ }
  if (!r || typeof r !== 'object' || !isNodeIdText(r.nodeId) || (r.name !== undefined && r.name !== name)) {
    throw unreadableIndex(name, file, raw.length ? 'it does not hold {"name", "nodeId"} for this name' : 'it is empty');
  }
  return r.nodeId;
}

function unreadableIndex(name, file, why) {
  const onDisk = identitiesOnDisk().filter((i) => i.name === name).map((i) => `${i.nodeId} (${i.file})`);
  const link = compatLinkNodeId(path.join(NODES_DIR, name));
  return new IdentityHaltError(name, file,
    `the name index entry for "${name}" exists, but ${why}. It is the record of which node this name is, so it is not read as "no such agent". ` +
    (onDisk.length || link
      ? `The identity it named is still on this host: ${[...onDisk, link && `nodes/${name} leads to by-id/${link}`].filter(Boolean).join('; ')}. `
      : '') +
    'Nothing was changed.',
    `Restore the entry: ${file} holds {"name": ${JSON.stringify(name)}, "nodeId": "<the agent's nodeId>"}. Do not delete it to "start over": ` +
    'the key it leads to is this agent.');
}

/** Wait (briefly) for the entry another process is creating in place, where hard links are not supported. */
function nodeIdForNameSettled(name) {
  for (let i = 0; ; i++) {
    try { return nodeIdForName(name); } catch (e) {
      const st = statOrNull(nameIndexPath(name));
      if (i >= 40 || !st || st.size !== 0 || Date.now() - st.mtimeMs > 2000) throw e;
      pause(5);
    }
  }
}

/**
 * Claim `name` for `nodeId` by an exclusive create of its index entry. Of several first starts of one name,
 * exactly one makes the entry; the rest find it made. Returns the nodeId the entry holds afterwards: `nodeId`
 * when this call claimed the name (or it already named it), the winner's otherwise.
 */
function claimName(name, nodeId) {
  ensureDir(path.join(NODES_DIR, 'by-name'));
  for (let i = 0; i < 5; i++) {
    if (createFileExclusive(nameIndexPath(name), JSON.stringify({ name, nodeId, at: Date.now() }))) return nodeId;
    const held = nodeIdForNameSettled(name);
    if (held) return held;
  }
  throw new Error(`[SYM] the name index entry for "${name}" keeps appearing and disappearing; nothing was changed`);
}

/** Point `name` at `nodeId` whatever it named (a start pinned to a nodeId: known, kept), durably. */
function repointName(name, nodeId) {
  ensureDir(path.join(NODES_DIR, 'by-name'));
  writeFileDurable(nameIndexPath(name), JSON.stringify({ name, nodeId, at: Date.now() }), 0o644);
}

/** Every nodeId some index entry names, with the names. Entries that cannot be read are left out. */
function indexEntries() {
  const out = new Map();
  const dir = path.join(NODES_DIR, 'by-name');
  let files = [];
  try { files = fs.readdirSync(dir); } catch { return out; }
  for (const f of files) {
    if (f.startsWith('.') || !f.endsWith('.json')) continue;
    try {
      const r = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
      if (r && isNodeIdText(r.nodeId)) {
        if (!out.has(r.nodeId)) out.set(r.nodeId, []);
        out.get(r.nodeId).push(typeof r.name === 'string' ? r.name : decodeURIComponent(f.slice(0, -5)));
      }
    } catch { /* unreadable: its own name halts when started */ }
  }
  return out;
}

/** The by-id roots: nodes/by-id, and SYM_IDENTITY_DIR/by-id when set. */
function byIdRoots() {
  const roots = [path.join(NODES_DIR, 'by-id')];
  if (process.env.SYM_IDENTITY_DIR) roots.push(path.join(process.env.SYM_IDENTITY_DIR, 'by-id'));
  return roots;
}

/** Every identity.json filed by nodeId on this host: { nodeId, name, file, scrubbed }. Dot-entries (staging, husks) are not identities. */
function identitiesOnDisk() {
  const out = new Map();
  for (const root of byIdRoots()) {
    let dirs = [];
    try { dirs = fs.readdirSync(root); } catch { continue; }
    for (const d of dirs) {
      if (d.startsWith('.') || !isNodeIdText(d) || out.has(d)) continue;
      const file = path.join(root, d, 'identity.json');
      try {
        const j = JSON.parse(fs.readFileSync(file, 'utf8'));
        if (j && j.nodeId === d) out.set(d, { nodeId: d, name: j.name, file, scrubbed: !j.privateKey });
      } catch { /* none, or not readable: not an identity this scan can name */ }
    }
  }
  return [...out.values()];
}

/** True when the identity of `nodeId` is where a load reads it. */
function identityInPlace(nodeId) {
  return fs.existsSync(path.join(identityDirById(nodeId), 'identity.json'));
}

// ── The 0.13-compatible links (nodes/<name> -> by-id/<nodeId>, for one release) ──

/**
 * True when the link at `link` leads to `target` (relative to the link's directory). A Windows junction
 * reads back as an absolute path (sometimes with a \\?\ prefix) where a relative target was given, so the
 * two are compared as the paths they resolve to, not as text: comparing text re-made the link on every check.
 */
function linkLeadsTo(link, target) {
  let got;
  try { got = fs.readlinkSync(link); } catch { return false; }
  if (got === target) return true;
  const fold = (s) => (process.platform === 'win32' ? s.toLowerCase() : s);
  const norm = (p) => fold(path.resolve(path.dirname(link), String(p).replace(/^\\\\\?\\/, ''))).replace(/[\\/]+$/, '');
  return norm(got) === norm(target);
}

/** The nodeId a compat link at `p` (a link to `by-id/<nodeId>` beside it) leads to, or null when `p` is not one. */
function compatLinkNodeId(p) {
  let target;
  try { target = fs.readlinkSync(p); } catch { return null; }
  const m = /(?:^|[\\/])by-id[\\/]([^\\/]+)[\\/]?$/.exec(target);
  if (!m || !isNodeIdText(m[1])) return null;
  return linkLeadsTo(p, path.join('by-id', m[1])) ? m[1] : null;
}

/** Remove a link (a symlink, or a Windows junction, which unlink refuses). */
function removeLink(p) {
  try { fs.unlinkSync(p); } catch (e) { if (e.code === 'ENOENT') return; fs.rmdirSync(p); }
}

/**
 * Make `link` lead to `by-id/<nodeId>`. A real directory is not replaced (a 0.13 one is set aside by the
 * migration first), except an empty one (or one holding only a stale lock), which is nothing. The link is
 * made under a name of its own and renamed onto the path, so a stale link is replaced in one step. Best
 * effort: the index is authoritative.
 */
function linkCompat(link, nodeId) {
  const target = path.join('by-id', nodeId);
  const st = lstatOrNull(link);
  if (st && st.isSymbolicLink() && linkLeadsTo(link, target)) return true;
  if (st && !st.isSymbolicLink() && !(st.isDirectory() && removeEmptyDir(link))) return false;
  const tmp = path.join(path.dirname(link), `.${path.basename(link)}.link-${process.pid}-${randomTag()}`);
  try {
    fs.symlinkSync(target, tmp, process.platform === 'win32' ? 'junction' : 'dir');
  } catch { return false; }
  try {
    fs.renameSync(tmp, link);
    return true;
  } catch {
    try { removeLink(tmp); } catch { /* */ }
    try {
      if (lstatOrNull(link) && lstatOrNull(link).isSymbolicLink()) removeLink(link);
      fs.symlinkSync(target, link, process.platform === 'win32' ? 'junction' : 'dir');
      return true;
    } catch { return false; }
  }
}

/** The compat links of `name`: nodes/<name>, and SYM_IDENTITY_DIR/<name> when the identity is there. */
function ensureCompatLinks(name, nodeId) {
  linkCompat(path.join(NODES_DIR, name), nodeId);
  const idRoot = process.env.SYM_IDENTITY_DIR;
  if (idRoot && fs.existsSync(path.join(idRoot, 'by-id', nodeId))) linkCompat(path.join(idRoot, name), nodeId);
}

/**
 * Remove `dir` if it holds nothing but a lock nobody holds: rmdir removes only an empty directory, so this can
 * never remove one with anything in it. Returns true when it is gone.
 */
function removeEmptyDir(dir) {
  const lockPath = path.join(dir, 'lock.pid');
  const lock = readLockFile(lockPath);
  if (lock) {
    if (lock.pid === process.pid || lockIsHeldByLiveProcess(lock)) return false;
    removeStaleLock(lockPath, lock);
  }
  try { fs.rmdirSync(dir); return true; } catch (e) { return e.code === 'ENOENT'; }
}

/** The tombstone a moved identity left, or null: beside the key, or (written by 0.14.0 - 0.14.2) in the node dir. */
function readTombstone(nodeId) {
  for (const d of new Set([identityDirById(nodeId), nodeDirById(nodeId)])) {
    try { return JSON.parse(fs.readFileSync(path.join(d, TOMBSTONE), 'utf8')); } catch { /* none here */ }
  }
  return null;
}

/** The record of an export that has begun and not finished, or null (beside the key; see relocation.js). */
function readExportIntent(nodeId) {
  for (const d of new Set([identityDirById(nodeId), nodeDirById(nodeId)])) {
    try { return JSON.parse(fs.readFileSync(path.join(d, EXPORTING), 'utf8')); } catch { /* none here */ }
  }
  return null;
}

/** The files in a node's directory that hold a PRIVATE KEY: its signing identity and the 0.13 E2E keypair. */
const PRIVATE_KEY_FILES = ['identity.json', 'e2e-keypair.json'];

/**
 * Narrow a node's private key files to their owner (0600), and with `dirs` the directories that hold
 * them (0700). A key file a 0.13 node wrote at the umask default (0644 — world-readable) stays
 * world-readable in the 0.13 directory the migration sets aside; this is what ends that.
 *
 * Best effort on purpose: a file this process does not own, or a filesystem without modes (Windows),
 * must not stop a node from starting. Nothing here changes what a file holds.
 * @param {Array<string|null>} dirs
 */
function securePrivateFiles(dirs, { narrowDirs = false } = {}) {
  const narrow = (p, mode) => { try { if ((fs.statSync(p).mode & 0o077) !== 0) fs.chmodSync(p, mode); } catch { /* absent, or not ours */ } };
  for (const d of new Set(dirs.filter(Boolean))) {
    for (const f of PRIVATE_KEY_FILES) narrow(path.join(d, f), 0o600);
    if (narrowDirs) narrow(d, 0o700);
  }
}

/** Write a file the way a key file must be written: a private temp file, synced, renamed over the target. */
function writeFileAtomic0600(file, text) {
  const tmp = `${file}.${process.pid}.tmp`;
  let fd;
  try {
    fd = fs.openSync(tmp, 'w', 0o600);
    fs.writeSync(fd, text);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(tmp, file);
    fsyncDir(path.dirname(file));
  } catch (e) {
    if (fd !== undefined) try { fs.closeSync(fd); } catch { /* */ }
    try { fs.unlinkSync(tmp); } catch { /* */ }
    throw e;
  }
}

// ── Reading an identity ──────────────────────────────────────────────────

/**
 * Parse and validate the text of an identity.json, writing nothing. Never regenerates a key: text that is
 * not an identity halts (IdentityHaltError), and so does one with a public key and no private key. A
 * pre-v0.3.7 identity with no keypair at all gets its first key; a private key with no public key gets the
 * public key derived from it; a bare hostname gets `.local`. `source` is what the file says, `identity` what
 * it becomes, `mutated` whether they differ.
 * @private
 */
function parseIdentity(raw, name, idPath) {
  let source;
  try {
    source = JSON.parse(raw);
  } catch (e) {
    throw new IdentityHaltError(name, idPath, `identity.json is not valid JSON: ${e.message}`);
  }
  if (!source || typeof source !== 'object' || !source.nodeId) {
    throw new IdentityHaltError(name, idPath, 'identity.json has no nodeId — the file is not an identity');
  }
  // A PUBLIC KEY BUT NO PRIVATE KEY is not "no keypair": the key existed and is gone (a truncated write,
  // a scrubbed export). Neither mint one nor sign with `undefined`: a new key is a different agent.
  if (source.publicKey && !source.privateKey) {
    throw new IdentityHaltError(name, idPath, 'identity.json has a public key but no private key — the private key is gone, not missing, and a new one would be a different agent');
  }
  const identity = { ...source };
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
  return { source, identity, mutated };
}

/** Read an identity.json that EXISTS: one that cannot be read halts, never regenerates. @private */
function readIdentityText(idPath, name) {
  try {
    return fs.readFileSync(idPath, 'utf8');
  } catch (e) {
    // The file EXISTS and we cannot read it. Never regenerate here — a transient read failure
    // (permissions, a full disk, a partial write) would otherwise overwrite a live keypair.
    throw new IdentityHaltError(name, idPath, `identity.json exists but could not be read: ${e.message}`);
  }
}

/**
 * Read and validate an installed identity.json (see parseIdentity). A fix it needs (a first key, a derived
 * public key, `.local`) is written back atomically and privately; a key file left readable by others is
 * narrowed to its owner.
 * @private
 */
function readIdentityFile(idPath, name) {
  const { identity, mutated } = parseIdentity(readIdentityText(idPath, name), name, idPath);
  // Atomic and private: a truncate-in-place that is interrupted leaves a key file with no key in it, and a
  // mode passed to writeFileSync is ignored for a file that already exists.
  if (mutated) writeFileAtomic0600(idPath, JSON.stringify(identity, null, 2));
  securePrivateFiles([path.dirname(idPath)]);
  return identity;
}

/** True when `other` is the identity `source` says: the same nodeId, and every key `source` has, the same. */
function sameIdentity(source, other) {
  return Boolean(source && other) && source.nodeId === other.nodeId &&
    (!source.privateKey || source.privateKey === other.privateKey) &&
    (!source.publicKey || source.publicKey === other.publicKey);
}

// ── Staged copies, committed by one rename ───────────────────────────────

/** Top-level entries a copy of a node directory leaves out: runtime state, and what the copy writes itself. */
const COPY_SKIP_TOP = new Set(['lock.pid', 'interior.sock', TOMBSTONE, EXPORTING, COMMIT_MARK]);
const skipTop = (extra = []) => {
  const names = new Set([...COPY_SKIP_TOP, ...extra]);
  return (rel) => !rel.includes('/') && (names.has(rel) || rel.endsWith('.tmp') || rel.startsWith('lock.pid.') || /^\.[^/]*\.link-\d+-[0-9a-f]+$/.test(rel));
};

/** Two regular files hold the same bytes (read in pieces: a store file can be large). */
function sameBytes(a, b) {
  const sa = statOrNull(a); const sb = statOrNull(b);
  if (!sa || !sb || !sa.isFile() || !sb.isFile() || sa.size !== sb.size) return false;
  let fa; let fb;
  try {
    fa = fs.openSync(a, 'r'); fb = fs.openSync(b, 'r');
    const ba = Buffer.alloc(1 << 20); const bb = Buffer.alloc(1 << 20);
    for (let pos = 0; pos < sa.size;) {
      const na = fs.readSync(fa, ba, 0, ba.length, pos); const nb = fs.readSync(fb, bb, 0, bb.length, pos);
      if (na !== nb || na === 0 || ba.compare(bb, 0, nb, 0, na) !== 0) return false;
      pos += na;
    }
    return true;
  } catch { return false; } finally {
    if (fa !== undefined) fs.closeSync(fa);
    if (fb !== undefined) fs.closeSync(fb);
  }
}

/**
 * Copy the children of directory `src` into directory `dst` (which exists): directories are made 0700,
 * files keep their bytes and mode (a key file 0600) and are synced. Links are FOLLOWED, so what a 0.13 node
 * kept behind a link (its directory on another volume, an identity.json linked to a key file) is copied, not
 * a link that would lead somewhere else from the new place; a link that leads nowhere is copied as the link
 * it is. What is neither a file nor a directory (a socket) is not data and is left out, and so is what
 * `skip(rel)` names. A directory reached twice through links is copied as a link, not followed forever.
 */
function copyChildren(src, dst, skip, rel = '', within = new Set()) {
  within.add(fs.realpathSync(src));
  for (const e of fs.readdirSync(src).sort()) {
    const r = rel ? `${rel}/${e}` : e;
    if (skip(r)) continue;
    const from = path.join(src, e);
    const to = path.join(dst, e);
    const st = statOrNull(from);
    if (!st) { // a link that leads nowhere
      const l = lstatOrNull(from);
      if (l && l.isSymbolicLink()) fs.symlinkSync(fs.readlinkSync(from), to);
      continue;
    }
    if (st.isDirectory()) {
      if (within.has(fs.realpathSync(from))) { fs.symlinkSync(fs.readlinkSync(from), to); continue; }
      fs.mkdirSync(to, { mode: 0o700 });
      fs.chmodSync(to, 0o700);
      copyChildren(from, to, skip, r, new Set(within));
      fsyncDir(to);
    } else if (st.isFile()) {
      // From the file a link leads to: a clone (macOS) of a link would copy the link.
      fs.copyFileSync(fs.realpathSync(from), to, fs.constants.COPYFILE_EXCL | fs.constants.COPYFILE_FICLONE);
      fsyncFile(to);
      fs.chmodSync(to, PRIVATE_KEY_FILES.includes(e) ? 0o600 : st.mode & 0o777);
    }
  }
}

/** The first path (relative) under directory `src` whose copy under `dst` is missing or differs, or null. */
function firstDifference(src, dst, skip, rel = '', within = new Set()) {
  within.add(fs.realpathSync(src));
  for (const e of fs.readdirSync(src).sort()) {
    const r = rel ? `${rel}/${e}` : e;
    if (skip(r)) continue;
    const from = path.join(src, e);
    const to = path.join(dst, e);
    const st = statOrNull(from);
    if (!st) {
      const l = lstatOrNull(from); const d = lstatOrNull(to);
      if (l && l.isSymbolicLink() && !(d && d.isSymbolicLink() && fs.readlinkSync(to) === fs.readlinkSync(from))) return r;
      continue;
    }
    if (st.isDirectory()) {
      if (within.has(fs.realpathSync(from))) continue;
      const d = lstatOrNull(to);
      if (!d || !d.isDirectory()) return r;
      const inner = firstDifference(from, to, skip, r, new Set(within));
      if (inner) return inner;
    } else if (st.isFile() && !sameBytes(from, to)) {
      return r;
    }
  }
  return null;
}

/** Remove leftover staging directories (`.<id>.partial-<pid>-<rand>`) of processes that are gone. */
function clearPartials(parent) {
  let names = [];
  try { names = fs.readdirSync(parent); } catch { return; }
  for (const n of names) {
    const m = /^\.[^\\/]+\.(?:partial|import)-(\d+)-[0-9a-f]+$/.exec(n);
    if (!m || Number(m[1]) === process.pid || pidIsAlive(Number(m[1]))) continue;
    try { fs.rmSync(path.join(parent, n), { recursive: true, force: true }); } catch { /* the next attempt */ }
  }
}

/**
 * A new staging directory for `nodeId` beside where it will be installed (`parent`), so the commit is a rename
 * on one volume: `.<nodeId>.<kind>-<pid>-<rand>`, 0700. Leftovers of processes that are gone are cleared first.
 */
function makeStaging(parent, nodeId, kind = 'partial') {
  ensureDir(parent);
  clearPartials(parent);
  const staging = path.join(parent, `.${nodeId}.${kind}-${process.pid}-${randomTag()}`);
  fs.mkdirSync(staging, { mode: 0o700 });
  fs.chmodSync(staging, 0o700);
  return staging;
}

/** Write the commit record into a staging directory (last), and sync the directory. */
function markStaged(staging, nodeId, from) {
  writeNewFileSynced(path.join(staging, COMMIT_MARK), JSON.stringify({ nodeId, from, at: Date.now() }) + '\n', 0o600);
  fsyncDir(staging);
}

/** Why a staged commit was refused: a different identity, or files that differ, already under the nodeId. */
class CommitConflict extends Error {}

/**
 * What is at `target`, the by-id directory a commit for `nodeId` installs:
 *   - 'absent';
 *   - 'committed': it carries the commit record (and, when it holds the identity, `source`'s identity);
 *   - 'husk': a directory without the commit record that does not contradict `source` (empty, a stale lock,
 *     the files of an earlier release's interrupted move or of a node that ran there without its identity);
 *   - 'conflict': it holds a different identity, or is not a directory.
 * `holdsIdentity`: the identity lives in this directory (no SYM_IDENTITY_DIR, or the identity directory).
 */
function examineTarget(target, nodeId, source, holdsIdentity) {
  const st = lstatOrNull(target);
  if (!st) return { state: 'absent' };
  if (st.isSymbolicLink() || !st.isDirectory()) return { state: 'conflict', reason: `${target} is not a directory` };
  const marked = fs.existsSync(path.join(target, COMMIT_MARK));
  if (holdsIdentity) {
    const f = path.join(target, 'identity.json');
    if (fs.existsSync(f)) {
      let other = null;
      try { other = JSON.parse(fs.readFileSync(f, 'utf8')); } catch { /* below */ }
      if (!other) return { state: 'conflict', reason: `${f} is already there and cannot be read` };
      if (!sameIdentity(source, other)) return { state: 'conflict', reason: `a different identity.json is already filed under ${nodeId} (${f})` };
    } else if (marked) {
      return { state: 'conflict', reason: `${target} carries a commit record and no identity.json` };
    }
  }
  if (marked) {
    let mark = null;
    try { mark = JSON.parse(fs.readFileSync(path.join(target, COMMIT_MARK), 'utf8')); } catch { /* below */ }
    if (!mark || mark.nodeId !== nodeId) return { state: 'conflict', reason: `${target} carries the commit record of another node` };
    return { state: 'committed' };
  }
  return { state: 'husk' };
}

/**
 * Copy what `from` holds into `staging` where it is not there yet; a file on both sides that differs is a
 * conflict (CommitConflict), and nothing of `from` is changed. How a husk's files (a node that ran in the
 * by-id directory without its identity) come into the staged directory before the husk is set aside.
 */
function mergeIntoStaging(from, staging, skip, rel = '') {
  for (const e of fs.readdirSync(path.join(from, rel)).sort()) {
    const r = rel ? `${rel}/${e}` : e;
    if (skip(r)) continue;
    const src = path.join(from, r);
    const dst = path.join(staging, r);
    const st = statOrNull(src);
    if (!st) continue;
    const d = lstatOrNull(dst);
    if (st.isDirectory()) {
      if (d && !d.isDirectory()) throw new CommitConflict(`${src} is a directory where the 0.13 copy has a file`);
      if (!d) { fs.mkdirSync(dst, { mode: 0o700 }); fs.chmodSync(dst, 0o700); }
      mergeIntoStaging(from, staging, skip, r);
    } else if (st.isFile()) {
      if (d) { if (!sameBytes(src, dst)) throw new CommitConflict(`${src} differs from the copy of the 0.13 directory`); continue; }
      fs.copyFileSync(fs.realpathSync(src), dst, fs.constants.COPYFILE_EXCL | fs.constants.COPYFILE_FICLONE);
      fsyncFile(dst);
      fs.chmodSync(dst, PRIVATE_KEY_FILES.includes(e) ? 0o600 : st.mode & 0o777);
      if (!sameBytes(src, dst)) throw new Error(`the copy of ${src} does not match it`);
    }
  }
}

/**
 * Install a complete staging directory as `target` by ONE rename: that rename is the commit. Returns
 * 'committed' when this staging went in, 'exists' when `target` already holds a committed directory (another
 * start committed first, or an earlier one did): the caller checks it is the same identity and discards its
 * staging. Nothing at `target` is ever overwritten by it:
 *   - a husk (no commit record) holding nothing, or only a lock whose holder is gone, is removed with rmdir,
 *     which cannot remove a directory with anything in it, and the rename is tried again;
 *   - a husk with files: they are copied into the staging (a file that differs is a conflict), and the husk is
 *     renamed aside to `.<nodeId>.husk` beside it, kept. That name is taken once and kept, so a later rename
 *     can never move a directory installed since; and the staging takes in the files of a husk set aside by
 *     another start before each attempt;
 *   - a husk whose lock a live process holds: EIDENTITYLOCK, nothing changed.
 */
function commitStaged(staging, target, { nodeId, examine, skip }) {
  const asideHusk = path.join(path.dirname(target), `.${nodeId}.husk`);
  for (let attempt = 0; attempt < 12; attempt++) {
    if (fs.existsSync(asideHusk)) mergeIntoStaging(asideHusk, staging, skip);
    try {
      fs.renameSync(staging, target);
      fsyncDir(path.dirname(target));
      return 'committed';
    } catch (e) {
      if (!RENAME_TAKEN.has(e.code)) throw e;
    }
    const t = examine(target);
    if (t.state === 'absent') continue;
    if (t.state === 'committed') return 'exists';
    if (t.state === 'conflict') throw new CommitConflict(t.reason);
    const lockPath = path.join(target, 'lock.pid');
    const lock = readLockFile(lockPath);
    if (lock) {
      if (lockHeldInProcess(target) || (lock.pid !== process.pid && lockIsHeldByLiveProcess(lock))) {
        throw lockError(`[SYM] A live process (PID ${lock.pid ?? 'unknown'}) holds ${lockPath}, but ${nodeId}'s identity is not installed there: ` +
          'a node of an earlier release is running in that directory without its identity. Stop it, then start this agent again; nothing was changed.', lock);
      }
      removeStaleLock(lockPath, lock);
    }
    let rest = [];
    try { rest = fs.readdirSync(target).filter((n) => n !== 'lock.pid'); } catch { continue; }
    if (!rest.length) {
      try { fs.rmdirSync(target); } catch (e) { if (!['ENOENT', 'ENOTEMPTY', 'EEXIST'].includes(e.code)) throw e; }
      continue;
    }
    mergeIntoStaging(target, staging, skip);
    try { fs.renameSync(target, asideHusk); } catch (e) { if (e.code !== 'ENOENT' && !RENAME_TAKEN.has(e.code)) throw e; }
  }
  throw new Error(`[SYM] could not install ${target}: what was there kept changing; nothing was overwritten. Start again.`);
}

/**
 * Stage a copy of the 0.13 directory `src` (null: none) for `nodeId` and commit it as `target`. `identityText`,
 * when given, is written as identity.json after everything else, then the commit record; the copy is verified
 * against `src` byte for byte before the commit. Returns 'committed' | 'exists'; a conflict throws CommitConflict.
 */
function commitCopy(src, target, { nodeId, identityText, source, holdsIdentity, from }) {
  const skip = skipTop(['identity.json']);
  const examine = (t) => examineTarget(t, nodeId, source, holdsIdentity);
  const pre = examine(target);
  if (pre.state === 'committed') return 'exists';
  if (pre.state === 'conflict') throw new CommitConflict(pre.reason);
  const staging = makeStaging(path.dirname(target), nodeId);
  try {
    if (src) copyChildren(src, staging, skip);
    if (identityText) writeNewFileSynced(path.join(staging, 'identity.json'), identityText, 0o600);
    markStaged(staging, nodeId, from);
    if (src) {
      const d = firstDifference(src, staging, skip);
      if (d) throw new Error(`[SYM] the copy of ${path.join(src, d)} does not match its source (did it change while it was copied?); nothing was installed, the source is untouched. Start again.`);
    }
    if (identityText && !sameIdentity(source, JSON.parse(fs.readFileSync(path.join(staging, 'identity.json'), 'utf8')))) {
      throw new Error('[SYM] the staged identity.json does not read back as the identity it was written from; nothing was installed');
    }
    return commitStaged(staging, target, { nodeId, skip, examine });
  } finally {
    fs.rmSync(staging, { recursive: true, force: true });
  }
}

/**
 * Install a new directory for `nodeId` at `target` (which must not exist), built by `build(staging)` in a staging
 * directory and committed by one rename: for a new identity, and for an import (relocation.js, whose
 * `beforeCommit` sets the tombstoned copy of a node coming back aside once the new one is complete).
 */
function installNewDir(target, nodeId, build, kind = 'partial', { beforeCommit } = {}) {
  const staging = makeStaging(path.dirname(target), nodeId, kind);
  try {
    build(staging);
    markStaged(staging, nodeId, kind);
    if (beforeCommit) beforeCommit();
    fs.renameSync(staging, target);
    fsyncDir(path.dirname(target));
  } finally {
    fs.rmSync(staging, { recursive: true, force: true });
  }
}

// ── 0.13 directories ─────────────────────────────────────────────────────

/**
 * The 0.13 directory at `p`, or null: a real directory, or a link to a directory that is NOT a compat link (a
 * 0.13 node kept its directory on another volume behind one; it is followed and copied).
 */
function legacyAt(p) {
  const st = lstatOrNull(p);
  if (!st) return null;
  if (st.isSymbolicLink()) {
    if (compatLinkNodeId(p)) return null;
    const t = statOrNull(p);
    return t && t.isDirectory() ? { path: p, link: true } : null;
  }
  return st.isDirectory() ? { path: p, link: false } : null;
}

/** The 0.13 directories of `name`: nodes/<name>, and SYM_IDENTITY_DIR/<name> (or the same) for the identity. */
function legacySources(name) {
  const idRoot = process.env.SYM_IDENTITY_DIR;
  const nodes = legacyAt(path.join(NODES_DIR, name));
  const ids = idRoot ? legacyAt(path.join(idRoot, name)) : nodes;
  return { nodes, ids, idRoot };
}

/** True while a 0.13 identity.json sits under `name` (in nodes/<name>/ or SYM_IDENTITY_DIR/<name>/). */
function legacyIdentityUnder(name) {
  const { nodes, ids } = legacySources(name);
  return [nodes, ids].some((l) => l && fs.existsSync(path.join(l.path, 'identity.json')));
}

/** Whether `dir` holds anything but a lock. */
function hasContent(dir) {
  try { return fs.readdirSync(dir).some((n) => n !== 'lock.pid'); } catch { return false; }
}

/**
 * Hold the 0.13 directory's own lock (`nodes/<name>/lock.pid`, the file a 0.13 process of the agent takes)
 * while it is copied and set aside, so no 0.13 process starts in it meanwhile. The lock says it is a
 * migration's: another 0.14 start that finds it goes on beside it (the staged commit makes that safe) instead
 * of waiting. A live holder that is not a migration is a process running in that directory: `liveHolder`.
 */
function takeLegacyLock(dir) {
  const lockPath = path.join(dir, 'lock.pid');
  const token = randomTag() + randomTag();
  let got;
  try {
    got = acquireLockAt(lockPath, { migrating: true, token });
  } catch {
    // The directory does not take a lock (read-only, not ours): copy it all the same, unless a process holds it.
    const l = readLockFile(lockPath);
    got = l && lockIsLive(l) ? { ok: false, lock: l } : { ok: true, none: true };
    if (got.ok) return { release() {} };
  }
  if (!got.ok) {
    const l = got.lock;
    if (l && (l.migrating || l.pid === process.pid)) return { release() {} };
    return { liveHolder: (l && l.pid) || 'unknown', release() {} };
  }
  return {
    /** Remove the lock wherever the directory went (set aside), if it is still this one. */
    release(also = []) {
      for (const p of [lockPath, ...also.map((d) => path.join(d, 'lock.pid'))]) {
        const l = readLockFile(p);
        if (l && l.pid === process.pid && l.token === token) { try { fs.unlinkSync(p); } catch { /* */ } }
      }
    },
  };
}

/**
 * Rename the 0.13 directory (or link) at `at` aside, to `<root>/.legacy-0.13/<name>`: kept, never deleted.
 * Returns where it went, or null when it is no longer there (another start set it aside).
 */
function setAside(at, root, name) {
  const st = lstatOrNull(at);
  if (!st || compatLinkNodeId(at)) return null;
  const dir = path.join(root, LEGACY_ASIDE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  for (const dest of [path.join(dir, name), path.join(dir, `${name}.${Date.now()}-${randomTag()}`)]) {
    try {
      fs.renameSync(at, dest);
      fsyncDir(dir);
      fsyncDir(root);
      return dest;
    } catch (e) {
      if (e.code === 'ENOENT') return null;
      if (!RENAME_TAKEN.has(e.code)) throw e;
      const again = lstatOrNull(at);
      if (!again || compatLinkNodeId(at)) return null; // set aside meanwhile; what is there now is the link
    }
  }
  return null;
}

/**
 * After the commit: the 0.13 directories of `name` go aside and compat links take their place. The link is
 * made first, under a name of its own, and renamed onto the old path right after the directory left it, so a
 * 0.13 rollback finds the old path empty for one rename only.
 */
function setAsideAndLink(name, nodeId, srcs) {
  const plans = [[NODES_DIR, srcs.nodes]];
  if (srcs.idRoot) plans.push([srcs.idRoot, srcs.ids]);
  const aside = [];
  for (const [root, src] of plans) {
    const at = path.join(root, name);
    if (!src) { if (root === NODES_DIR || fs.existsSync(path.join(root, 'by-id', nodeId))) linkCompat(at, nodeId); continue; }
    const tmp = path.join(root, `.${name}.link-${process.pid}-${randomTag()}`);
    try {
      fs.symlinkSync(path.join('by-id', nodeId), tmp, process.platform === 'win32' ? 'junction' : 'dir');
    } catch {
      // No link can be made here: the 0.13 directory stays where it is (a 0.13 rollback still reads it), and the
      // next start tries again. The identity is installed and the name claimed either way.
      continue;
    }
    let went = null;
    try { went = setAside(at, root, name); } catch { /* the identity is installed and indexed: the next start sets it aside */ } finally {
      try { fs.renameSync(tmp, at); } catch { try { removeLink(tmp); } catch { /* */ } }
      linkCompat(at, nodeId);
    }
    if (went) {
      aside.push(went);
      securePrivateFiles([went], { narrowDirs: !src.link });
    }
  }
  return aside;
}

/**
 * Copy one 0.13 node (`nodes/<name>/`, and its identity at `SYM_IDENTITY_DIR/<name>/` when that is set) to
 * `nodes/by-id/<nodeId>/` (and `SYM_IDENTITY_DIR/by-id/<nodeId>/`), and COMMIT it: the copy is staged beside
 * its destination, identity.json last, synced, verified byte for byte against the source, and installed by one
 * rename. Of several starts doing this at once each stages its own copy, one rename wins, and the rest find
 * the same identity installed and discard theirs: nothing is moved, so nothing can be lost between two of
 * them. Then the name is claimed (an exclusive create of its index entry), the 0.13 directory is renamed aside
 * to `.legacy-0.13/<name>` (kept, never deleted), and `nodes/<name>` becomes a link to the by-id directory for
 * one release (a 0.13 rollback reads the old path).
 *
 * A by-id directory already there without the commit record (an empty one, a lock, an earlier release's
 * interrupted move, a node that ran there without its identity) is merged into the staged copy and replaced
 * through the same commit, never read as "the identity is in place". One that holds a DIFFERENT identity, or a
 * file that differs, is a second claim on the nodeId: 'skipped-duplicate', and nothing is changed. A 0.13
 * process running in the directory (its lock live): 'skipped-live', nothing changed (the start refuses with
 * EIDENTITYLOCK). An identity this host exported (tombstoned): 'tombstoned'.
 *
 * A 0.13 identity file is read with the same parser a load uses, so one that exists and cannot be established
 * (unreadable, not JSON, no nodeId) HALTS (IdentityHaltError). A 0.13 identity in `nodes/<name>/` while
 * SYM_IDENTITY_DIR is set and it is not in `SYM_IDENTITY_DIR/<name>/` HALTS: it is neither where the identity dir
 * looks nor safe to leave for a mint.
 *
 * `onlyNodeId`: a start pinned to a nodeId migrates the directory under `name` only if its identity IS that
 * nodeId; another agent's directory is left as it is ('skipped-duplicate').
 * @returns {{ status: 'moved'|'indexed'|'already'|'not-a-node'|'skipped-live'|'skipped-duplicate'|'tombstoned', nodeId?: string, reason?: string }}
 * @private
 */
function migrateName(name, onlyNodeId) {
  const srcs = legacySources(name);
  if (!srcs.nodes && !srcs.ids) {
    const linked = compatLinkNodeId(path.join(NODES_DIR, name));
    const held = nodeIdForName(name);
    if (held) return { status: 'already', nodeId: held };
    if (linked && identityInPlace(linked) && !indexEntries().has(linked) && (!onlyNodeId || linked === onlyNodeId)) {
      return claimName(name, linked) === linked ? { status: 'indexed', nodeId: linked } : { status: 'skipped-duplicate', nodeId: linked, reason: 'another start claimed the name first' };
    }
    return { status: 'not-a-node' };
  }
  const idFile = srcs.ids && path.join(srcs.ids.path, 'identity.json');
  const inNodeDir = srcs.nodes && path.join(srcs.nodes.path, 'identity.json');
  if (!idFile || !fs.existsSync(idFile)) {
    if (srcs.idRoot && inNodeDir && fs.existsSync(inNodeDir)) {
      const want = path.join(srcs.idRoot, name, 'identity.json');
      throw new IdentityHaltError(name, inNodeDir,
        `SYM_IDENTITY_DIR (${srcs.idRoot}) is set, but this agent's identity is still in its node directory and not in ${path.dirname(want)}. ` +
        `It was not moved, and a new one will not be made in its place. Copy it to ${want} (keep the original until the agent has started), ` +
        'or unset SYM_IDENTITY_DIR.');
    }
    return { status: 'not-a-node' };
  }
  const read = parseIdentity(readIdentityText(idFile, name), name, idFile); // halts on an identity it cannot establish
  const nodeId = read.identity.nodeId;
  if (!isNodeIdText(nodeId)) throw new IdentityHaltError(name, idFile, `the nodeId ${JSON.stringify(String(nodeId).slice(0, 40))} cannot name a directory under nodes/by-id`);
  // The operator copied the identity to SYM_IDENTITY_DIR as the halt above says, and kept the original: the
  // two must be one identity. The copy in the node directory is left out of the node directory's copy.
  if (srcs.idRoot && inNodeDir && fs.existsSync(inNodeDir)) {
    const other = parseIdentity(readIdentityText(inNodeDir, name), name, inNodeDir).source;
    if (!sameIdentity(read.source, other) || !sameIdentity(other, read.source)) {
      throw new IdentityHaltError(name, inNodeDir, `two different identities sit under "${name}": ${idFile} (${nodeId}) and ${inNodeDir} (${other.nodeId}). Nothing was moved; keep the one that is this agent.`);
    }
  }
  if (onlyNodeId && nodeId !== onlyNodeId) return { status: 'skipped-duplicate', nodeId, reason: `the 0.13 identity under "${name}" is ${nodeId}, not the pinned ${onlyNodeId}; it was left as it is` };
  const held = nodeIdForName(name);
  if (held && held !== nodeId) return { status: 'skipped-duplicate', nodeId, reason: `the name "${name}" already indexes node ${held}; the 0.13 identity ${nodeId} under it was left as it is` };
  const tomb = readTombstone(nodeId);
  if (tomb) return { status: 'tombstoned', nodeId, tomb };
  const lock = srcs.nodes ? takeLegacyLock(srcs.nodes.path) : { release() {} };
  if (lock.liveHolder) return { status: 'skipped-live', nodeId, holderPid: lock.liveHolder };
  let aside = [];
  try {
    const nodeTarget = nodeDirById(nodeId);
    const idTarget = identityDirById(nodeId);
    const split = idTarget !== nodeTarget;
    const text = JSON.stringify(read.identity, null, 2);
    try {
      commitCopy(srcs.nodes && srcs.nodes.path, nodeTarget, { nodeId, identityText: split ? null : text, source: read.source, holdsIdentity: !split, from: `0.13 nodes/${name}` });
      if (split) commitCopy(srcs.ids.path, idTarget, { nodeId, identityText: text, source: read.source, holdsIdentity: true, from: `0.13 SYM_IDENTITY_DIR/${name}` });
    } catch (e) {
      if (e instanceof CommitConflict) return { status: 'skipped-duplicate', nodeId, reason: `the 0.13 identity under "${name}" was not migrated: ${e.message}` };
      throw e;
    }
    // The record that the name is this node: claimed once the identity is installed. Of two starts, the
    // second finds the entry made and loads what it names.
    const winner = claimName(name, nodeId);
    if (winner !== nodeId) return { status: 'skipped-duplicate', nodeId, reason: `the name "${name}" was claimed for node ${winner} meanwhile` };
    aside = setAsideAndLink(name, nodeId, srcs);
    securePrivateFiles([nodeTarget, idTarget], { narrowDirs: true });
    return { status: 'moved', nodeId };
  } finally {
    lock.release(aside);
  }
}

/**
 * Migrate the 0.13 directory of `name` to the by-id layout (see migrateName). Idempotent, safe from several
 * processes at once, and it takes no lock but the 0.13 directory's own.
 * @param {string} name
 * @param {string} [onlyNodeId]
 * @returns {'moved'|'indexed'|'skipped-live'|'skipped-duplicate'|'not-a-node'|'already'|'tombstoned'}
 */
function migrateNodeDir(name, onlyNodeId) {
  const problem = basicNameProblem(name);
  if (problem) throw new Error(problem);
  return migrateName(name, onlyNodeId).status;
}

/**
 * Migrate every 0.13 node directory under the state root to the by-id layout (design D9, §6 of the
 * design: a one-time, idempotent copy). Safe to run at every start and from several processes.
 * @returns {{ moved: number, already: number, skippedLive: number, duplicates: number }}
 */
function migrateIdentities() {
  const out = { moved: 0, already: 0, skippedLive: 0, duplicates: 0 };
  const names = new Set();
  for (const root of [NODES_DIR, process.env.SYM_IDENTITY_DIR].filter(Boolean)) {
    let entries = [];
    try { entries = fs.readdirSync(root); } catch { continue; }
    for (const n of entries) if (n !== 'by-id' && n !== 'by-name' && !n.startsWith('.') && !basicNameProblem(n)) names.add(n);
  }
  for (const name of names) {
    let r;
    try { r = migrateNodeDir(name); } catch { continue; }
    if (r === 'moved') out.moved++;
    else if (r === 'already' || r === 'indexed') out.already++;
    else if (r === 'skipped-live') out.skippedLive++;
    else if (r === 'skipped-duplicate') out.duplicates++;
  }
  return out;
}

// ── Loading ──────────────────────────────────────────────────────────────

/** Load the installed identity of `nodeId`: tombstone and export checked, file validated (halts, never mints). */
function loadInstalled(nodeId, label, { allowPendingExport = false } = {}) {
  const tomb = readTombstone(nodeId);
  if (tomb) throw new IdentityTombstonedError(nodeId, tomb);
  if (!allowPendingExport) {
    const intent = readExportIntent(nodeId);
    if (intent) throw new IdentityExportPendingError(nodeId, intent);
  }
  const idPath = path.join(identityDirById(nodeId), 'identity.json');
  const identity = readIdentityFile(idPath, label);
  if (identity.nodeId !== nodeId) throw new IdentityHaltError(label, idPath, `identity.json names ${identity.nodeId}, not ${nodeId}`);
  securePrivateFiles([nodeDirById(nodeId)]); // the 0.13 E2E keypair beside it, when the identity lives elsewhere
  return identity;
}

/** Where on this host an identity.json for `nodeId` is, other than where a load reads it. */
function strayCopiesOf(nodeId) {
  const out = [];
  const where = new Set([path.join(NODES_DIR, 'by-id', nodeId)]);
  if (process.env.SYM_IDENTITY_DIR) where.add(path.join(process.env.SYM_IDENTITY_DIR, 'by-id', nodeId));
  where.delete(identityDirById(nodeId));
  for (const root of [NODES_DIR, process.env.SYM_IDENTITY_DIR].filter(Boolean)) {
    let names = [];
    try { names = fs.readdirSync(path.join(root, LEGACY_ASIDE)); } catch { /* none */ }
    for (const n of names) where.add(path.join(root, LEGACY_ASIDE, n));
  }
  for (const d of where) {
    try { if (JSON.parse(fs.readFileSync(path.join(d, 'identity.json'), 'utf8')).nodeId === nodeId) out.push(path.join(d, 'identity.json')); } catch { /* none */ }
  }
  return out;
}

/**
 * The halt for an identity that is not installed where it is read: the name's index entry names it
 * (`indexed`), or a start asks for it by nodeId. When a copy of it is elsewhere on this host the halt says
 * where, and never tells the operator to remove the index entry.
 */
function indexedButMissing(name, nodeId, { indexed = true } = {}) {
  const idPath = path.join(identityDirById(nodeId), 'identity.json');
  const copies = strayCopiesOf(nodeId);
  const link = path.join(NODES_DIR, name);
  const what = indexed ? `the name "${name}" indexes node ${nodeId}, and its identity.json is not where it is read` : `the identity ${nodeId} is not installed where it is read`;
  if (copies.length) {
    return new IdentityHaltError(name, idPath,
      `${what}; it IS on this host, at ${copies.join(' and ')}.`,
      `Put a copy of it at ${idPath} (keep the original until the agent has started)` +
      `${process.env.SYM_IDENTITY_DIR ? ', or unset SYM_IDENTITY_DIR if this agent\'s key was never meant to live there' : ''}. Do not remove the name's index entry: the key is this agent.`);
  }
  return new IdentityHaltError(name, idPath,
    `${what}, and no copy of it is on this host. ` +
    'If SYM_IDENTITY_DIR changed or its volume is not mounted, restore that.',
    `Restore the keypair from your durable copy to ${idPath} and start again. If this agent's key is gone for good, it cannot return as "${name}"; ` +
    `to let the name start again as a DIFFERENT agent, remove ${nameIndexPath(name)} and the link ${link}.`);
}

/**
 * What on this host belongs to `name` without being an installed, indexed identity: each is a reason not to
 * mint. `{ identity: bool, text }`: `identity` when it holds an identity (a halt says so; never "absent").
 */
function nameTraces(name, migration, scan = { indexed: indexEntries(), installed: identitiesOnDisk() }) {
  const out = [];
  const indexed = scan.indexed;
  const idRoot = process.env.SYM_IDENTITY_DIR;
  for (const [root, label] of [[NODES_DIR, 'nodes'], [idRoot, 'SYM_IDENTITY_DIR']]) {
    if (!root) continue;
    const at = path.join(root, name);
    const st = lstatOrNull(at);
    if (st) {
      const linked = compatLinkNodeId(at);
      if (linked) {
        if (!identityInPlace(linked)) out.push({ identity: false, text: `${at} leads to by-id/${linked}, whose identity is not installed` });
        else out.push({ identity: true, nodeId: indexed.has(linked) ? null : linked, text: `${at} leads to ${linked}${indexed.has(linked) ? `, which the index gives the name(s) ${indexed.get(linked).join(', ')}` : ''}` });
      } else if (st.isSymbolicLink() || st.isDirectory()) {
        const l = legacyAt(at);
        if (l && fs.existsSync(path.join(l.path, 'identity.json'))) {
          out.push({ identity: true, legacy: true, text: `a 0.13 identity sits in ${at}${migration && migration.reason ? ` and was not migrated (${migration.reason})` : ''}` });
        } else if (st.isSymbolicLink()) {
          out.push({ identity: false, text: `${at} is a link to ${fs.readlinkSync(at)} with no identity in it` });
        } else if (hasContent(at)) {
          out.push({ identity: false, text: `${at} holds a node's files (${fs.readdirSync(at).filter((n) => n !== 'lock.pid').slice(0, 4).join(', ')}) and no identity` +
            `${label === 'nodes' && idRoot ? `, and ${path.join(idRoot, name, 'identity.json')} is not there (is the identity volume mounted?)` : ''}` });
        }
      } else {
        out.push({ identity: false, text: `${at} is a file, not a node directory` });
      }
    }
    let aside = [];
    try { aside = fs.readdirSync(path.join(root, LEGACY_ASIDE)).filter((n) => n === name || n.startsWith(`${name}.`)); } catch { /* none */ }
    for (const n of aside) {
      const d = path.join(root, LEGACY_ASIDE, n);
      let id = null;
      try { id = JSON.parse(fs.readFileSync(path.join(d, 'identity.json'), 'utf8')).nodeId; } catch { /* */ }
      out.push({ identity: Boolean(id), nodeId: id, text: `the 0.13 directory of "${name}" was set aside at ${d}${id ? ` (identity ${id})` : ''}` });
    }
  }
  for (const i of scan.installed) {
    if (i.name !== name || indexed.has(i.nodeId) || i.scrubbed) continue;
    out.push({ identity: true, nodeId: i.nodeId, text: `the identity ${i.nodeId} named "${name}" is installed at ${i.file} and no name indexes it` });
  }
  return out;
}

/**
 * An installed identity the name provably belongs to though its index entry is missing: a compat link
 * `nodes/<name>` to it, or the one installed identity whose `name` is this name and that no name indexes
 * (a start that crashed between installing it and claiming the name; an entry lost). `{ many }` when more
 * than one fits. Nothing is adoptable while any trace of the name holds another identity, or a 0.13 identity
 * that was not migrated (`traces`, from nameTraces): that is two claims on the name, and a halt.
 */
function adoptable(name, traces, scan = { indexed: indexEntries(), installed: identitiesOnDisk() }) {
  const indexed = scan.indexed;
  const consistent = (id) => traces.every((t) => !t.identity || (!t.legacy && t.nodeId === id));
  const ok = (id) => id && identityInPlace(id) && !indexed.has(id) && !readTombstone(id) && consistent(id);
  for (const p of [path.join(NODES_DIR, name), process.env.SYM_IDENTITY_DIR && path.join(process.env.SYM_IDENTITY_DIR, name)]) {
    const id = p && compatLinkNodeId(p);
    if (ok(id)) return { nodeId: id };
  }
  const named = scan.installed.filter((i) => i.name === name && !i.scrubbed && ok(i.nodeId));
  if (named.length === 1) return { nodeId: named[0].nodeId };
  return named.length ? { many: named } : null;
}

/**
 * Make a new identity for `name`: installed by one rename (the node dir, and the identity dir when
 * SYM_IDENTITY_DIR is set), THEN the name claimed by an exclusive create of its index entry. Returns null when
 * another first start of the name claimed it first: this identity was never anyone's, and it is removed.
 */
function mintIdentity(name) {
  const kp = generateSigningKeyPair();
  const identity = {
    nodeId: uuidv7(),
    name,
    hostname: normalizeMdnsHostname(os.hostname()),
    createdAt: Date.now(),
    publicKey: kp.publicKey.toString('base64url'),
    privateKey: kp.privateKey.toString('base64url'),
  };
  const nodeId = identity.nodeId;
  const text = JSON.stringify(identity, null, 2);
  const nodeTarget = nodeDirById(nodeId);
  const idTarget = identityDirById(nodeId);
  const split = idTarget !== nodeTarget;
  const withIdentity = (staging) => writeNewFileSynced(path.join(staging, 'identity.json'), text, 0o600);
  installNewDir(nodeTarget, nodeId, split ? () => {} : withIdentity);
  if (split) installNewDir(idTarget, nodeId, withIdentity);
  if (claimName(name, nodeId) !== nodeId) {
    fs.rmSync(nodeTarget, { recursive: true, force: true });
    if (split) fs.rmSync(idTarget, { recursive: true, force: true });
    return null;
  }
  ensureCompatLinks(name, nodeId);
  return identity;
}

/**
 * Load a node's identity by nodeId or by name (design D9). The state of an identity is read from records
 * committed in one step: an installed identity (a directory installed by one rename) and the name's index
 * entry (created exclusively, after the identity was installed). Nothing is inferred from a path that merely
 * exists.
 *
 *   - `{ nodeId }` loads that identity;
 *   - `{ name }` (pinned or not) first migrates a 0.13 identity still under the name (one path, see
 *     migrateName), then resolves the name by its index entry; an entry that cannot be read halts;
 *   - a 0.13 directory a live process holds refuses (EIDENTITYLOCK): the agent is running there;
 *   - `create: false` throws IdentityAbsentError when the identity is not on this host;
 *   - `create: true` (the default) is the ONLY path that mints, and it mints only when there is no trace
 *     of the name on this host: no index entry, no `nodes/<name>` (a link, or a directory with anything in it),
 *     no `SYM_IDENTITY_DIR/<name>`, no 0.13 directory set aside, no installed identity of that name that no name
 *     indexes. A trace that provably is this name's identity (a compat link to it, the one unindexed identity of
 *     that name) is adopted: the name is claimed for it. Any other trace HALTS (IdentityHaltError), saying what
 *     it is. Two first starts of a new name both mint; one claims the name, the other discards its identity
 *     and loads the winner;
 *   - a tombstoned identity (exported to another host) refuses: IdentityTombstonedError; one whose export
 *     did not finish refuses: IdentityExportPendingError.
 *
 * @param {{ nodeId?: string, name?: string, create?: boolean, allowPendingExport?: boolean }} o
 * @returns {{ nodeId: string, name: string, hostname: string, createdAt: number, publicKey: string, privateKey: string }}
 */
function loadIdentity({ nodeId: pin, name, create = true, allowPendingExport = false } = {}) {
  if (name !== undefined) validateName(name);
  if (!pin && !name) throw new Error('loadIdentity needs a nodeId or a name');
  if (pin && !isNodeIdText(pin)) throw new Error(`not a nodeId: ${String(pin).slice(0, 40)}`);
  const how = { allowPendingExport };
  if (!name) {
    if (identityInPlace(pin)) return loadInstalled(pin, pin, how);
    if (strayCopiesOf(pin).length) throw indexedButMissing(pin, pin, { indexed: false });
    throw new IdentityAbsentError(pin);
  }
  // 1. A 0.13 identity under the name is migrated first: the same path for a pinned start and an unpinned one.
  let migration = null;
  if (legacyIdentityUnder(name)) {
    migration = migrateName(name, pin);
    if (migration.status === 'skipped-live') {
      throw lockError(
        `[SYM] Agent '${name}' is running in its 0.13 directory: a live process (PID ${migration.holderPid}) holds ${path.join(NODES_DIR, name, 'lock.pid')}.\n\n` +
        '  One agent runs in one process. This start is refused; nothing was moved or changed. Stop that process (it is an older copy of ' +
        'this same agent), and start again: the agent is migrated then, with its store.', { pid: migration.holderPid });
    }
    if (migration.status === 'tombstoned') throw new IdentityTombstonedError(migration.nodeId, migration.tomb);
  }
  if (pin) {
    if (identityInPlace(pin)) {
      const identity = loadInstalled(pin, name, how);
      const held = nodeIdForName(name);
      if (!held) claimName(name, pin);
      else if (held !== pin) repointName(name, pin); // known: a pinned start re-points the name
      ensureCompatLinks(name, pin);
      return identity;
    }
    if (migration && migration.nodeId === pin) {
      throw new IdentityHaltError(name, path.join(NODES_DIR, name, 'identity.json'),
        `the identity ${pin} this start is pinned to is on this host, in the 0.13 directory of "${name}", and could not be migrated: ${migration.reason || migration.status}.`,
        'Resolve that, then start again. Nothing was changed.');
    }
    if (!create) {
      if (strayCopiesOf(pin).length) throw indexedButMissing(name, pin, { indexed: false });
      throw new IdentityAbsentError(`"${name}" (${pin})`, nameTraces(name, migration).map((t) => t.text));
    }
  }
  for (let round = 0; ; round++) {
    const indexed = nodeIdForName(name);
    if (indexed) {
      if (!identityInPlace(indexed)) {
        if (!create && !strayCopiesOf(indexed).length) throw new IdentityAbsentError(`"${name}" (${indexed})`);
        throw indexedButMissing(name, indexed);
      }
      const identity = loadInstalled(indexed, name, how);
      ensureCompatLinks(name, indexed);
      return identity;
    }
    if (round > 40) throw new Error(`[SYM] the name "${name}" did not settle (its index entry kept being claimed and lost); nothing was minted`);
    // One look at what is installed and indexed decides both what is a trace and what can be adopted; an identity
    // installed after it is another first start's, and the claim of the name settles which one the name is.
    const scan = { indexed: indexEntries(), installed: identitiesOnDisk() };
    const traces = nameTraces(name, migration, scan);
    const adopt = adoptable(name, traces, scan);
    if (nodeIdForName(name)) continue; // another start claimed the name meanwhile: load what it names
    if (adopt && adopt.nodeId) { claimName(name, adopt.nodeId); continue; } // the index decides; read it again
    if (adopt && adopt.many && round < 20) { pause(10); continue; } // first starts claiming it: the entry appears within ms
    if (traces.length) {
      if (!create && !traces.some((t) => t.identity)) throw new IdentityAbsentError(`"${name}"`, traces.map((t) => t.text));
      throw new IdentityHaltError(name, nameIndexPath(name),
        `no index entry names "${name}", and this host holds a trace of it: ${traces.map((t) => t.text).join('; ')}` +
        `${pin ? `; this start is pinned to ${pin}, which is not on this host` : ''}. ` +
        'Making a new identity here would orphan or overwrite its key, so none was made.',
        'If the trace is this agent, restore its index entry or its identity; if it is not, move it out of the way. Then start again.');
    }
    if (!create) throw new IdentityAbsentError(pin ? `"${name}" (${pin})` : `"${name}"`);
    const minted = mintIdentity(name);
    if (minted) return minted;
    // Another first start of this name claimed it first: the index says who it is.
  }
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
 * Rename a node: the name index moves; the identity (nodeId, key) does not (design D9). The new name is
 * claimed exclusively. The old name only needs to be a name at all, so an agent whose name a later rule
 * refuses (one Windows cannot hold) can be renamed to one it accepts.
 * @returns {string} the nodeId
 */
function renameIdentity(oldName, newName) {
  const problem = basicNameProblem(oldName);
  if (problem) throw new Error(problem);
  validateName(newName);
  const nodeId = nodeIdForName(oldName);
  if (!nodeId) throw new IdentityAbsentError(`"${oldName}"`);
  if (nodeIdForName(newName) || claimName(newName, nodeId) !== nodeId) throw new Error(`the name "${newName}" already indexes a node`);
  ensureCompatLinks(newName, nodeId);
  try { fs.unlinkSync(nameIndexPath(oldName)); } catch { /* */ }
  fsyncDir(path.dirname(nameIndexPath(oldName)));
  for (const root of [NODES_DIR, process.env.SYM_IDENTITY_DIR].filter(Boolean)) {
    const link = path.join(root, oldName);
    if (compatLinkNodeId(link) === nodeId) { try { removeLink(link); } catch { /* */ } }
  }
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
 * The file is read and stat'ed through ONE open, so `ino`/`dev` and `raw` describe the same file: that is
 * what lets a stale lock be removed only if it is still the lock that was judged stale (removeStaleLock).
 * @param {string} lockPath — absolute path to the lock.pid file
 * @returns {{pid: number|null, start: string|null, mtimeMs: number, ino: string, dev: string, raw: string, migrating: boolean, token: string|null}|null}
 *   null when the file is absent/unreadable; pid null when content is
 *   unparseable (corrupt or mid-write).
 */
function readLockFile(lockPath) {
  let fd;
  try { fd = fs.openSync(lockPath, 'r'); } catch { return null; }
  let raw; let st;
  try {
    st = fs.fstatSync(fd, { bigint: true });
    const buf = Buffer.alloc(Math.min(Number(st.size), 4096));
    const n = buf.length ? fs.readSync(fd, buf, 0, buf.length, 0) : 0;
    raw = buf.subarray(0, n).toString('utf8');
  } catch {
    return null;
  } finally {
    try { fs.closeSync(fd); } catch { /* */ }
  }
  const lines = raw.split('\n');
  const pid = parseInt(lines[0].trim(), 10);
  let meta = null;
  if (lines.length > 1 && lines[1].trim()) {
    try { meta = JSON.parse(lines[1]); } catch { /* metadata line corrupt — fall back to PID-only semantics */ }
  }
  return {
    pid: Number.isFinite(pid) && pid > 0 ? pid : null,
    start: meta && typeof meta.start === 'string' ? meta.start : null,
    mtimeMs: Number(st.mtimeMs),
    ino: String(st.ino),
    dev: String(st.dev),
    raw,
    migrating: Boolean(meta && meta.migrating === true),
    token: meta && typeof meta.token === 'string' ? meta.token : null,
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

/** Whether a node in THIS process holds the identity lock in `dir` (final re-review, Finding 7a). */
function lockHeldInProcess(dir) {
  return _heldLockPaths.has(path.join(dir, 'lock.pid'));
}

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

/** An EIDENTITYLOCK error: `lock` is the holder's parsed lock (its pid becomes `holderPid`). */
function lockError(message, lock) {
  const err = new Error(message);
  err.code = 'EIDENTITYLOCK';
  err.holderPid = lock && lock.pid !== undefined ? lock.pid : null;
  return err;
}

/**
 * Whether `lock` is held: by a live process (lockIsHeldByLiveProcess), or by this one. A lock with this
 * process's pid and another start time was another process's (the pid was reused): stale.
 */
function lockIsLive(lock) {
  if (lock.pid === process.pid) return !(lock.start && selfStartTime() && lock.start !== selfStartTime());
  return lockIsHeldByLiveProcess(lock);
}

/**
 * Remove the stale lock `judged` (as readLockFile read it) from `lockPath` ONLY IF it is still that lock, and
 * report whether it is gone. POSIX has no compare-and-delete, and the plain sequence (read, judge stale,
 * unlink, create) let two starters at a dead holder's lock both hold it: the slower one's unlink removed the
 * lock the faster one had just made (4 of 8 rounds with six starters). So removing one particular lock is a
 * right of its own, taken exclusively: a claim file named after that lock (`<lock>.break-<hash of its file
 * identity and content>`), which is itself a lock of this kind. Holding it, the lock is read again and
 * removed only if it is the same file (dev, ino), with the same content, still stale. Nobody else removes a
 * lock without the claim for it, and a lock that is replaced has another claim name, so between the read and
 * the unlink the file cannot change. A claim whose holder died (killed in those few system calls) is stale and
 * removed the same way, one level up (bounded). False when another start holds the claim (it is removing it).
 */
function removeStaleLock(lockPath, judged, depth = 0) {
  if (depth > 3) return false;
  const tag = crypto.createHash('sha256').update(`${judged.dev}:${judged.ino}:${judged.raw}`).digest('hex').slice(0, 16);
  const claim = `${lockPath}.break-${tag}`;
  let got;
  try { got = acquireLockAt(claim, {}, depth + 1); } catch { return false; }
  if (!got.ok) return false;
  try {
    const now = readLockFile(lockPath);
    if (!now) return true;
    // Not the lock judged stale: leave it. The same file with the same content is the same lock, and its holder,
    // dead when it was judged, is dead still (a reused pid has another start time).
    if (now.dev !== judged.dev || now.ino !== judged.ino || now.raw !== judged.raw) return false;
    try { fs.unlinkSync(lockPath); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    return true;
  } finally {
    _releaseLockIfOurs(claim);
  }
}

/**
 * Take the lock file `lockPath` (O_EXCL create; content: pid, then {start, createdAt, ...meta}). A stale lock
 * (see lockIsHeldByLiveProcess) is removed with removeStaleLock and the create tried again. Returns
 * `{ ok: true }` when this call made the lock, `{ ok: false, lock }` when a live process holds it (`lock`:
 * the holder's, possibly this process), or the lock is being taken by another start at this moment.
 * @private
 */
function acquireLockAt(lockPath, meta = {}, depth = 0) {
  let last = null;
  for (let attempt = 0; attempt < 8; attempt++) {
    // Made whole under a temp name and linked into place (createFileExclusive): a lock is never seen without its owner.
    if (createFileExclusive(lockPath, `${process.pid}\n${JSON.stringify({ start: selfStartTime(), createdAt: Date.now(), ...meta })}\n`, 0o644)) return { ok: true };
    const lock = readLockFile(lockPath);
    if (!lock) continue; // released between the create and the read: take it now
    last = lock;
    if (lockIsLive(lock)) return { ok: false, lock };
    if (!removeStaleLock(lockPath, lock, depth)) pause(2); // another start is removing it: look again in a moment
  }
  return { ok: false, lock: last, contended: true };
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
 * Lockfile lives at ~/.sym/nodes/by-id/<nodeId>/lock.pid: line 1 is the holder's
 * PID (legacy parsers read exactly this), line 2 is JSON metadata with the
 * holder's process start time — the disambiguator that makes staleness
 * detection immune to PID reuse. On acquire:
 *   1. If no lockfile exists, write PID+metadata and return a release fn.
 *   2. If the lockfile's holder is LIVE (see lockIsHeldByLiveProcess:
 *      alive PID *and* matching start time), throw EIDENTITYLOCK.
 *   3. Otherwise the lock is stale (dead PID, recycled PID, pre-boot
 *      legacy lock, aged-out corrupt content) — it is removed if it is still
 *      that same lock (removeStaleLock: one remover per lock), and step 1 runs again.
 *
 * The release function deletes the lockfile. SymNode calls it on stop();
 * a process-level 'exit' hook (plus default-disposition SIGHUP/SIGINT/
 * SIGTERM conversion) releases any still-held locks so ordinary
 * non-stop() exits don't leak. SIGKILL still leaks by nature — healed at
 * the next acquire by step 3.
 *
 * @param {string} name — node name
 * @returns {() => void} release function — call to delete the lockfile
 * @throws {Error} if another process already holds the lock
 */
function acquireIdentityLock(name, opts = {}) {
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

  const got = acquireLockAt(lockPath);
  if (got.ok) return makeRelease();
  const lock = got.lock;
  // Same-PID re-acquisition is allowed: this happens in tests that
  // create multiple SymNodes with the same name in sequence, in
  // hot-reload scenarios, and in recovery flows where a single
  // process re-initializes after a soft failure. The lock is meant
  // to catch CROSS-PROCESS duplicates (the actual bug), not
  // in-process re-init. While another holder in this process still
  // holds it, the re-acquirer gets a release that does nothing: its
  // release must not take the lock from under the live holder (final
  // re-review, Finding 7a: an in-process export freed a running node's lock).
  if (lock && lock.pid === process.pid && !got.contended) {
    if (_heldLockPaths.has(lockPath)) return function release() { /* the first holder releases it */ };
    return makeRelease();
  }
  throw lockError(
    got.contended
      ? `[SYM] Agent '${name}' is being started by another process at this moment (its lock, ${lockPath}, is being taken over from a holder that is gone). ` +
        'This process is refused; start again if that other start fails.'
      : `[SYM] Agent '${name}' is already live in PID ${lock && lock.pid !== null ? lock.pid : 'unknown'} on this host.\n\n` +
        `  An agent id names an AGENT, not a process. Two processes of the same agent ARE ` +
        `the same agent, so they share one identity and one store, and only one may hold ` +
        `the write lease at a time. This process is refused; the running one keeps it.\n\n` +
        `  If that other process is orphaned, stop it and start again. Do NOT work around ` +
        `this by choosing a different name: a different agent id is a DIFFERENT AGENT, with ` +
        `its own keypair and its own history, and peers will treat it as a stranger.`,
    lock);
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
  readExportIntent,
  TOMBSTONE,
  EXPORTING,
  COMMIT_MARK,
  LEGACY_ASIDE,
  IdentityHaltError,
  IdentityAbsentError,
  IdentityTombstonedError,
  IdentityExportPendingError,
  /** For relocation.js: durable writes, and installing a staged directory by one rename. */
  writeFileDurable,
  writeNewFileSynced,
  fsyncDir,
  installNewDir,
  PRIVATE_KEY_FILES,
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
  lockHeldInProcess,
  locksHeldByLiveProcess,
  lockHolderPid,
  acquireIdentityLock,
  log,
};
