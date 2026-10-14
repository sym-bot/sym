'use strict';

/**
 * Configuration helpers for SYM mesh nodes.
 *
 * Manages identity persistence, node directories, and logging.
 * Node data lives under ~/.sym/nodes/by-id/<nodeId>/ (0.14; 0.13 kept it at ~/.sym/nodes/<name>/).
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
 * Get the data directory for a named node. A name is an index (design D9): when the name is an agent on
 * this host, this is the node's by-id directory (`nodes/by-id/<nodeId>`); otherwise the 0.13 path
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
  constructor(nodeId, tomb, intent) {
    super(`[SYM] REFUSING TO START ${nodeId}: this identity was exported to another host` +
      `${tomb && tomb.movedAt ? ` on ${new Date(tomb.movedAt).toISOString()}` : ''} and is tombstoned here. ` +
      `It runs where it was imported; two live copies would be two agents claiming one key.` +
      (intent ? ' The export did not finish removing the key from this host: run the same `sym node export` again to finish it.' : ''));
    this.name = 'IdentityTombstonedError';
    this.code = 'EIDENTITYTOMBSTONED';
    this.tombstone = tomb || null;
  }
}

/**
 * Raised for an identity whose export began and did not finish (relocation.js wrote EXPORTING.json beside the key):
 * the source stopped using the key when the export began, so it is not started until the export is finished (run the
 * same export again: same out, same recipient) or, while no complete bundle was produced, abandoned (abortExport).
 */
class IdentityExportPendingError extends Error {
  constructor(nodeId, intent, tomb) {
    const i = intent || {};
    const complete = i.complete === true;
    super(`[SYM] REFUSING TO START ${nodeId}: an export of this identity` +
      `${i.out ? ` to ${i.out}` : ''}${i.startedAt ? `, begun ${new Date(i.startedAt).toISOString()},` : ''} did not finish. ` +
      (complete
        ? 'Its bundle is complete: the agent now lives in that bundle. Import it where it goes, and run the same `sym node export` here ' +
          'again to finish removing the key from this host.'
        : `This host stopped using the key when the export began${tomb ? '' : ' (an export of an earlier release: a bundle may exist)'}, so it does not start it here meanwhile. ` +
          'Finish the export (run the same `sym node export` again: the same --out and the same recipient), or abandon it ' +
          '(`sym node abort-export <name>`, refused once a complete bundle was produced), and the agent starts here again.'));
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
/** Beside the key while an export is under way (relocation.js): its out, its recipient, and the bundle's hash once known. */
const EXPORTING = 'EXPORTING.json';
/** The record an import writes into the node directory it installs (relocation.js): which bundle it came from. */
const COMMIT_MARK = '.sym-commit';
/** Where a 0.13 directory that is a second copy of an installed agent is set aside, under the root it was in. Never deleted by sym. */
const LEGACY_ASIDE = '.legacy-0.13';
const lstatOrNull = (p) => { try { return fs.lstatSync(p); } catch { return null; } };
const statOrNull = (p) => { try { return fs.statSync(p); } catch { return null; } };
const randomTag = () => crypto.randomBytes(4).toString('hex');
/** The errors a rename gives when its target is taken (by a directory that is not empty, on Windows by any). */
const RENAME_TAKEN = new Set(['EEXIST', 'ENOTEMPTY', 'EPERM', 'EISDIR', 'ENOTDIR']);
/** A short synchronous pause, for the few places that let another start finish a step of a few system calls. */
const pause = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
const linkType = () => (process.platform === 'win32' ? 'junction' : 'dir');

// ── Durable files ────────────────────────────────────────────────────────

/** fsync a directory, so a rename or create in it survives a crash. Best effort where unsupported (Windows). */
function fsyncDir(dir) {
  let fd;
  try { fd = fs.openSync(dir, 'r'); fs.fsyncSync(fd); } catch { /* not supported here */ } finally { if (fd !== undefined) try { fs.closeSync(fd); } catch { /* */ } }
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

/** A JSON file's state: absent (ENOENT), unreadable (exists, cannot be read or parsed), or ok with its value. */
function readJsonState(file) {
  let raw;
  try { raw = fs.readFileSync(file, 'utf8'); } catch (e) {
    if (e.code === 'ENOENT' || e.code === 'ENOTDIR') return { state: 'absent', file };
    return { state: 'unreadable', file, why: `it could not be read (${e.code || e.message})`, io: true };
  }
  try {
    const j = JSON.parse(raw);
    if (j && typeof j === 'object') return { state: 'ok', file, j };
  } catch { /* below */ }
  return { state: 'unreadable', file, why: raw.length ? 'it is not valid JSON' : 'it is empty' };
}

// ── Names ────────────────────────────────────────────────────────────────

/**
 * The one spelling of a name that every comparison uses: Unicode NFC, lower case. A name is compared this way on
 * every platform, so two agents whose names differ only in case (or in how an accent is encoded) are one name: a
 * case-insensitive file system (macOS, Windows) cannot hold their two 0.13 directories, and a host that could
 * (Linux) must not run two agents that one move to a Mac would merge.
 */
function foldName(name) { return String(name).normalize('NFC').toLowerCase(); }

/** The name index entry of `name`: `nodes/by-name/<folded name>.json`, holding { name: <exact name>, nodeId }. */
const nameIndexPath = (name) => path.join(NODES_DIR, 'by-name', `${encodeURIComponent(foldName(name))}.json`);
/** Where 0.14.0 - 0.14.2 kept it (the exact name): read when the folded entry is missing, written beside it for a rollback. */
const exactIndexPath = (name) => path.join(NODES_DIR, 'by-name', `${encodeURIComponent(name)}.json`);
const sameFile = (a, b) => { const x = statOrNull(a); const y = statOrNull(b); return Boolean(x && y && x.dev === y.dev && x.ino === y.ino); };

/** One index entry file, read for the folded name `f`: missing, unreadable (with why), or ok with its nodeId. */
function readEntryFile(file, f) {
  const r = readJsonState(file);
  if (r.state === 'absent') return { state: 'missing', file };
  if (r.state === 'unreadable') return { state: 'unreadable', file, why: r.why, io: Boolean(r.io) };
  if (!isNodeIdText(r.j.nodeId)) return { state: 'unreadable', file, why: 'it does not hold {"name", "nodeId"} for this name' };
  if (r.j.name !== undefined && (typeof r.j.name !== 'string' || foldName(r.j.name) !== f)) {
    return { state: 'unreadable', file, why: `it holds the entry of another name (${JSON.stringify(String(r.j.name).slice(0, 64))})` };
  }
  return { state: 'ok', file, nodeId: r.j.nodeId, name: typeof r.j.name === 'string' ? r.j.name : null };
}

/**
 * The index entry for `name`, a cache of which committed identity the name is: the folded entry, or (when that is
 * missing) the entry 0.14.0 - 0.14.2 wrote under the exact name. Two readable entries for one folded name that name
 * different nodes (two agents a case-sensitive 0.14.2 host made, "Kappa" and "kappa") are a conflict.
 */
function entryFor(name) {
  const f = foldName(name);
  const a = readEntryFile(nameIndexPath(name), f);
  if (exactIndexPath(name) === nameIndexPath(name)) return a;
  const b = readEntryFile(exactIndexPath(name), f);
  if (a.state === 'ok' && b.state === 'ok' && a.nodeId !== b.nodeId && !sameFile(a.file, b.file)) return { state: 'conflict', entries: [a, b] };
  if (a.state === 'ok') return a;
  if (b.state === 'ok') return { ...b, exactKey: true };
  return a.state === 'unreadable' ? a : b.state === 'unreadable' ? b : a;
}

/** Every readable index entry: nodeId -> [{ name, file }]. */
function indexEntries() {
  const out = new Map();
  const dir = path.join(NODES_DIR, 'by-name');
  let files = [];
  try { files = fs.readdirSync(dir); } catch { return out; }
  for (const f of files) {
    if (f.startsWith('.') || !f.endsWith('.json')) continue;
    const r = readJsonState(path.join(dir, f));
    if (r.state !== 'ok' || !isNodeIdText(r.j.nodeId)) continue;
    let name = typeof r.j.name === 'string' ? r.j.name : null;
    if (name === null) { try { name = decodeURIComponent(f.slice(0, -5)); } catch { continue; } }
    if (!out.has(r.j.nodeId)) out.set(r.j.nodeId, []);
    out.get(r.j.nodeId).push({ name, file: path.join(dir, f) });
  }
  return out;
}

/** Write the 0.14.2 exact-name entry beside the folded one when they are different files (a rollback reads it). */
function writeExactKey(name, nodeId) {
  const exact = exactIndexPath(name);
  if (exact === nameIndexPath(name) || sameFile(exact, nameIndexPath(name))) return;
  const there = readEntryFile(exact, foldName(name));
  if (there.state === 'ok') return; // the same node, or another one's (a conflict a start reports): never re-pointed here
  try { writeFileDurable(exact, JSON.stringify({ name, nodeId, at: Date.now() }), 0o644); } catch { /* a cache */ }
}

/**
 * Claim `name` for `nodeId` by an exclusive create of its index entry. Returns the nodeId the entry holds
 * afterwards: `nodeId` when this call claimed it (or it already named it), another when another identity holds it,
 * null when an entry is there that cannot be read (it is not replaced here).
 */
function claimName(name, nodeId, exactName = name) {
  const f = foldName(name);
  fs.mkdirSync(path.join(NODES_DIR, 'by-name'), { recursive: true });
  for (let i = 0; i < 8; i++) {
    if (createFileExclusive(nameIndexPath(name), JSON.stringify({ name: exactName, nodeId, at: Date.now() }))) {
      writeExactKey(exactName, nodeId);
      return nodeId;
    }
    const e = readEntryFile(nameIndexPath(name), f);
    if (e.state === 'ok') { if (e.nodeId === nodeId) writeExactKey(exactName, nodeId); return e.nodeId; }
    if (e.state === 'unreadable') {
      // Created in place where hard links are not supported, and not written yet: give it a moment.
      const st = statOrNull(e.file);
      if (st && st.size === 0 && Date.now() - st.mtimeMs < 2000) { pause(5); continue; }
      return null;
    }
  }
  return null;
}

/** Re-derive an entry whose content is not an entry (empty, not JSON, another name's): replaced in one step. */
function repairEntry(name, nodeId, exactName) {
  try { writeFileDurable(nameIndexPath(name), JSON.stringify({ name: exactName, nodeId, at: Date.now() }), 0o644); } catch { return; }
  writeExactKey(exactName, nodeId);
}

// ── Committed identities: the one source of truth ────────────────────────

const identityFileById = (nodeId) => path.join(identityDirById(nodeId), 'identity.json');

/**
 * The committed identity of `nodeId`: the identity.json where a load reads it (identityDirById). An agent exists
 * exactly when this file exists. `absent`, `unreadable` (it exists and cannot be read, or names another nodeId: a
 * load halts), or `ok` with its name.
 */
function readCommitted(nodeId) {
  const r = readJsonState(identityFileById(nodeId));
  if (r.state !== 'ok') return r;
  if (r.j.nodeId !== nodeId) return { state: 'unreadable', file: r.file, why: `it names ${String(r.j.nodeId).slice(0, 40)}, not ${nodeId}` };
  return { state: 'ok', file: r.file, identity: r.j, name: typeof r.j.name === 'string' ? r.j.name : null, scrubbed: !r.j.privateKey };
}

/** True when an identity is committed for `nodeId` (its file exists, readable or not). */
function isCommitted(nodeId) {
  try { fs.statSync(identityFileById(nodeId)); return true; } catch (e) { return !(e.code === 'ENOENT' || e.code === 'ENOTDIR'); }
}

/** Where committed identities are filed: SYM_IDENTITY_DIR/by-id when set, else nodes/by-id. */
const committedRoot = () => (process.env.SYM_IDENTITY_DIR ? path.join(process.env.SYM_IDENTITY_DIR, 'by-id') : path.join(NODES_DIR, 'by-id'));

/** Every committed identity on this host: [{ nodeId, state, name, scrubbed, file }]. Dot-entries are never identities. */
function scanCommitted() {
  const out = [];
  let names = [];
  try { names = fs.readdirSync(committedRoot()); } catch { return out; }
  for (const d of names) {
    if (d.startsWith('.') || !isNodeIdText(d)) continue;
    const r = readCommitted(d);
    if (r.state !== 'absent') out.push({ nodeId: d, ...r });
  }
  return out;
}

/** The live committed identities named `f` (folded) other than `except`: readable, holding their key, not moved away. */
function namedHere(scan, f, except = null) {
  return scan.filter((i) => i.state === 'ok' && !i.scrubbed && i.name !== null && foldName(i.name) === f && i.nodeId !== except && !readTombstone(i.nodeId));
}

/** The halt for two committed identities that are one name. Nothing is changed; the operator renames one. */
function twoAgentsHalt(name, ids, why) {
  return new IdentityHaltError(name, nameIndexPath(name),
    `${ids.length} agents on this host are named "${name}" (names are compared without regard to case): ${ids.map((id) => `${id} (${identityFileById(id)})`).join(', ')}${why ? `; ${why}` : ''}. ` +
    'A name is one agent, so neither was started and nothing was changed.',
    `Start the one you mean by its nodeId (loadIdentity({ nodeId })) and give the other another name (renameIdentity, or start it pinned under a new name). Do not remove either identity.json: each is an agent's key.`);
}

// ── The 0.13-compatible links (nodes/<name> -> by-id/<nodeId>): derived, like the index ──

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

/** A link to `by-id/<nodeId>` made under a name of its own beside `at`, ready to be renamed onto it; null when none can be made. */
function makeTempLink(at, nodeId) {
  const tmp = path.join(path.dirname(at), `.${path.basename(at)}.link-${process.pid}-${randomTag()}`);
  try { fs.symlinkSync(path.join('by-id', nodeId), tmp, linkType()); return tmp; } catch { return null; }
}

/**
 * Put the temp link `tmp` at `at` when nothing but a link is there. A real directory is never replaced, except an empty
 * one (or one holding only a stale lock), which is nothing.
 */
function putTempLink(tmp, at) {
  if (!tmp) return false;
  const st = lstatOrNull(at);
  let done = false;
  if (!st || st.isSymbolicLink() || (st.isDirectory() && removeEmptyDir(at))) {
    try { fs.renameSync(tmp, at); done = true; } catch { /* below */ }
    // The rename failed (not a crash: an error): a link made in place, where nothing is.
    if (!done && !lstatOrNull(at)) { try { fs.symlinkSync(fs.readlinkSync(tmp), at, linkType()); done = true; } catch { /* */ } }
  }
  if (lstatOrNull(tmp)) { try { removeLink(tmp); } catch { /* */ } }
  if (done) fsyncDir(path.dirname(at));
  return done;
}

/**
 * Make `link` lead to `by-id/<nodeId>`. A real directory is not replaced, except an empty one (or one holding only
 * a stale lock), which is nothing. Best effort: the link is a cache of the name, like the index.
 */
function linkCompat(link, nodeId) {
  const target = path.join('by-id', nodeId);
  const st = lstatOrNull(link);
  if (st && st.isSymbolicLink() && linkLeadsTo(link, target)) return true;
  if (st && !st.isSymbolicLink() && !(st.isDirectory() && removeEmptyDir(link))) return false;
  const tmp = makeTempLink(link, nodeId);
  if (putTempLink(tmp, link)) return true;
  try {
    if (!lstatOrNull(link)) { fs.symlinkSync(target, link, linkType()); return true; }
  } catch { /* */ }
  return false;
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

// ── Tombstones and export intents ────────────────────────────────────────

/** The tombstone a moved identity left, or null: beside the key, or (a copy for 0.14.2, and 0.14.0 - 0.14.2's own) in the node dir. */
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

// ── Key files: modes ─────────────────────────────────────────────────────

/** The files in a node's directory that hold a PRIVATE KEY: its signing identity and the 0.13 E2E keypair. */
const PRIVATE_KEY_FILES = ['identity.json', 'e2e-keypair.json'];

/**
 * Narrow a node's private key files to their owner (0600), and with `narrowDirs` the directories that hold
 * them (0700). A key file a 0.13 node wrote at the umask default (0644 — world-readable) stays world-readable
 * until this runs; it runs on every load, on everything a migration installs or sets aside, and on staging.
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
  securePrivateFiles([path.dirname(idPath)], { narrowDirs: true });
  return identity;
}

/** True when `other` is the identity `source` says: the same nodeId, and every key `source` has, the same. */
function sameIdentity(source, other) {
  return Boolean(source && other) && source.nodeId === other.nodeId &&
    (!source.privateKey || source.privateKey === other.privateKey) &&
    (!source.publicKey || source.publicKey === other.publicKey);
}
const sameIdentityBothWays = (a, b) => sameIdentity(a, b) && sameIdentity(b, a);

// ── Runtime leftovers: staging, temp links, temp entries, lock artifacts ──

/** A lock, a claim to remove one, or the temp file a lock is written under: runtime state, never a node's data. */
const isLockArtifact = (n) => n === 'lock.pid' || n.startsWith('lock.pid.') || (n.startsWith('.lock.pid') && n.endsWith('.tmp'));

/** Staging directories (this release's `.stage-`, an import's `.import-`, 0.14.3 candidates' `.partial-`): `.<id>.<kind>-<pid>-<rand>`. */
const STAGING_RE = /^\.([0-9A-Za-z][0-9A-Za-z_.-]*?)\.(stage|import|partial)-(\d+)-([0-9a-f]+)$/;
/** A process that made a leftover is gone, or (a pid reused) the leftover is older than any step that makes one takes. */
const LEFTOVER_MAX_AGE_MS = 10 * 60 * 1000;
function leftoverIsDead(pid, p) {
  if (pid === process.pid) return false;
  if (!pidIsAlive(pid)) return true;
  const st = lstatOrNull(p);
  return Boolean(st && Date.now() - st.mtimeMs > LEFTOVER_MAX_AGE_MS);
}

/**
 * Clear what processes that are gone left behind (design: on every load): staging directories (one may hold a
 * private key: it was never anyone's, and it is never read), temp links, temp index entries and temp key files.
 * Nothing that is set aside is touched: an aside is kept.
 */
function clearLeftovers() {
  const idRoot = process.env.SYM_IDENTITY_DIR;
  for (const dir of new Set([path.join(NODES_DIR, 'by-id'), idRoot && path.join(idRoot, 'by-id')].filter(Boolean))) {
    let names = [];
    try { names = fs.readdirSync(dir); } catch { continue; }
    for (const n of names) {
      const m = STAGING_RE.exec(n);
      if (!m || !leftoverIsDead(Number(m[3]), path.join(dir, n))) continue;
      try { fs.rmSync(path.join(dir, n), { recursive: true, force: true }); } catch { /* the next load */ }
    }
  }
  for (const dir of new Set([NODES_DIR, idRoot].filter(Boolean))) {
    let names = [];
    try { names = fs.readdirSync(dir); } catch { continue; }
    for (const n of names) {
      const m = /^\..+\.link-(\d+)-[0-9a-f]+$/.exec(n);
      if (m && leftoverIsDead(Number(m[1]), path.join(dir, n))) { try { removeLink(path.join(dir, n)); } catch { /* */ } }
    }
  }
  // What is set aside and may hold a key (a 0.13 directory, a husk, an import's archive) is narrowed, also when the start
  // that set it aside was killed before it did.
  for (const root of new Set([NODES_DIR, idRoot].filter(Boolean))) {
    let asides = [];
    try { asides = fs.readdirSync(path.join(root, LEGACY_ASIDE)); } catch { /* none */ }
    securePrivateFiles(asides.map((n) => path.join(root, LEGACY_ASIDE, n)).filter((d) => { const st = lstatOrNull(d); return st && st.isDirectory(); }), { narrowDirs: true });
  }
  for (const dir of new Set([path.join(NODES_DIR, 'by-id'), idRoot && path.join(idRoot, 'by-id')].filter(Boolean))) {
    let names = [];
    try { names = fs.readdirSync(dir).filter((n) => /^\.[^/]+\.(husk|moved)(-|$)/.test(n)); } catch { continue; }
    securePrivateFiles(names.map((n) => path.join(dir, n)).filter((d) => { const st = lstatOrNull(d); return st && st.isDirectory(); }), { narrowDirs: true });
  }
  const byName = path.join(NODES_DIR, 'by-name');
  let names = [];
  try { names = fs.readdirSync(byName); } catch { names = []; }
  for (const n of names) {
    const m = /^\..+\.(\d+)-[0-9a-f]+\.tmp$/.exec(n);
    if (m && leftoverIsDead(Number(m[1]), path.join(byName, n))) { try { fs.unlinkSync(path.join(byName, n)); } catch { /* */ } }
  }
}

/** A new staging directory for `nodeId` in `parent` (the directory it commits into, so the commit is one rename): 0700. */
function makeStaging(parent, nodeId, kind = 'stage') {
  fs.mkdirSync(parent, { recursive: true });
  const staging = path.join(parent, `.${nodeId}.${kind}-${process.pid}-${randomTag()}`);
  fs.mkdirSync(staging, { mode: 0o700 });
  fs.chmodSync(staging, 0o700);
  return staging;
}

/**
 * Remove, from a directory that holds nothing else, the lock artifacts of processes that are gone: a claim to remove a
 * lock that is itself gone, or a temp lock file. (lock.pid itself is removed only by removeStaleLock.)
 */
function clearDeadLockArtifacts(dir) {
  if (fs.existsSync(path.join(dir, 'lock.pid'))) return;
  let names = [];
  try { names = fs.readdirSync(dir); } catch { return; }
  // This process's own are left over from an attempt that failed: lock work is synchronous, so none is under way.
  const gone = (pid) => pid === process.pid || !pidIsAlive(pid);
  for (const n of names) {
    if (n.startsWith('lock.pid.')) {
      const l = readLockFile(path.join(dir, n));
      // A claim whose holder is gone (killed while it removed the lock, which is gone too) goes at once; one that cannot be
      // read yet is given the grace a lock being written gets.
      const gone = l && (l.pid === process.pid || (l.pid !== null ? !lockIsLive(l) : Date.now() - l.mtimeMs > LOCK_CORRUPT_GRACE_MS));
      if (gone) { try { fs.unlinkSync(path.join(dir, n)); } catch { /* */ } }
    } else if (n.startsWith('.lock.pid') && n.endsWith('.tmp')) {
      const m = /\.(\d+)-[0-9a-f]+\.tmp$/.exec(n);
      if (m && gone(Number(m[1]))) { try { fs.unlinkSync(path.join(dir, n)); } catch { /* */ } }
    }
  }
}

/** The live holder of the lock in `dir` (a process of this or an earlier release running there), or null. */
function liveLockIn(dir) {
  const lock = readLockFile(path.join(dir, 'lock.pid'));
  if (!lock) return null;
  if (lockHeldInProcess(dir)) return lock;
  if (lock.pid !== process.pid && lockIsHeldByLiveProcess(lock)) return lock;
  return null;
}

/**
 * Hold the short lock file `lockPath` while `fn` runs: a few system calls (a mint, setting a husk aside), never a
 * copy. A live holder is waited for (it is done within milliseconds), up to `waitMs`; a holder that is gone is
 * removed the atomic way (removeStaleLock).
 */
function withShortLock(lockPath, what, fn, waitMs = 10000) {
  fs.mkdirSync(path.dirname(lockPath), { recursive: true });
  const t0 = Date.now();
  for (;;) {
    const got = acquireLockAt(lockPath, { short: what });
    if (got.ok) break;
    // This process's own: lock work is synchronous, so it is a leftover of a step that threw.
    if (got.lock && got.lock.pid === process.pid && !got.contended) { removeStaleLock(lockPath, got.lock); continue; }
    if (Date.now() - t0 > waitMs) {
      throw lockError(`[SYM] Another start (PID ${got.lock && got.lock.pid !== null ? got.lock.pid : 'unknown'}) has been ${what} for over ${Math.round(waitMs / 1000)} s ` +
        `(${lockPath}). This start is refused; nothing was changed. Start again once that process has finished or exited.`, got.lock);
    }
    pause(5);
  }
  try { return fn(); } finally { _releaseLockIfOurs(lockPath); }
}

// ── 0.13 directories, and moving them in ─────────────────────────────────

/**
 * The 0.13 directory at `p`, or null: a real directory, or a link to a directory that is NOT a compat link (a
 * 0.13 node kept its directory on another volume behind one).
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
  try { return fs.readdirSync(dir).some((n) => !isLockArtifact(n)); } catch { return false; }
}

/** The device a new entry in `dir` lands on: `dir`'s, or its nearest existing ancestor's. */
function deviceOf(dir) {
  for (let d = path.resolve(dir); ; d = path.dirname(d)) {
    const st = statOrNull(d);
    if (st) return st.dev;
    if (path.dirname(d) === d) return null;
  }
}

/** True when the real directory `p` is a mount point: on another device than its parent. */
function isMountPoint(p) {
  const a = statOrNull(p); const b = statOrNull(path.dirname(p));
  return Boolean(a && b && a.dev !== b.dev);
}

/** Two paths are one directory (links followed). */
const sameDir = (a, b) => { const x = statOrNull(a); const y = statOrNull(b); return Boolean(x && y && x.isDirectory() && x.dev === y.dev && x.ino === y.ino); };

/**
 * Set `p` (a directory, or a link) aside to `<root>/.legacy-0.13/<name>`, in the root it is in (one rename, on its
 * volume), and narrow what holds a key at once. Kept, never deleted. A mount point cannot be renamed: it is narrowed
 * where it is. Returns where it is now.
 */
function setLegacyAside(p, root, name, moved) {
  const st = lstatOrNull(p);
  if (!st) return null;
  if (!st.isSymbolicLink() && isMountPoint(p)) { securePrivateFiles([p], { narrowDirs: true }); return p; }
  const dir = path.join(root, LEGACY_ASIDE);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  for (const dest of [path.join(dir, name), path.join(dir, `${name}.${Date.now()}-${randomTag()}`)]) {
    try {
      fs.renameSync(p, dest);
      if (moved) moved(); // the link in its place first (a 0.13 build reads the path), then the modes, then the syncs
      if (!st.isSymbolicLink()) securePrivateFiles([dest], { narrowDirs: true });
      fsyncDir(dir);
      fsyncDir(root);
      return dest;
    } catch (e) {
      if (e.code === 'ENOENT') return null;
      if (!RENAME_TAKEN.has(e.code)) throw e;
    }
  }
  return null;
}

/**
 * What is at `target` (a by-id directory a migration places into), for the identity `o.source`:
 *   empty | locks (only lock artifacts) | same (the same identity is there) | other (another identity, or a file that
 *   cannot be read where an identity is) | husk (anything else: a directory an earlier release made without the
 *   identity, a link that leads nowhere).
 */
function judgeTarget(target, o) {
  const l = lstatOrNull(target);
  if (!l) return { verdict: 'absent' };
  const isLink = l.isSymbolicLink();
  const st = isLink ? statOrNull(target) : l;
  if (!st || !st.isDirectory()) return { verdict: 'husk' };
  const r = readJsonState(path.join(target, 'identity.json'));
  if (r.state === 'unreadable') {
    if (o.holdsIdentity) return { verdict: 'other', reason: `${path.join(target, 'identity.json')} is there and ${r.why}`, halt: true };
  } else if (r.state === 'ok') {
    if (!sameIdentityBothWays(o.source, r.j)) return { verdict: 'other', reason: `a different identity.json is already filed under ${o.nodeId} (${path.join(target, 'identity.json')})` };
    if (o.holdsIdentity) return { verdict: 'same' };
  }
  if (isLink) return { verdict: 'husk' };
  let names = [];
  try { names = fs.readdirSync(target); } catch { return { verdict: 'husk' }; }
  if (!names.length) return { verdict: 'empty' };
  if (names.every(isLockArtifact)) return { verdict: 'locks' };
  return { verdict: 'husk' };
}

/**
 * Set the husk at `target` aside (`by-id/.<nodeId>.husk-<time>-<rand>`, beside it: one rename), under the nodeId's short
 * migration lock, so no other start sets it aside, or empties it, in between. A husk with content cannot be replaced by a
 * commit (a rename onto a directory that is not empty fails), so what this looks at under the lock is what it moves. A
 * husk whose lock a live process holds (a node of an earlier release running there without its identity) is not moved.
 */
function setHuskAside(target, o) {
  return withShortLock(path.join(path.dirname(target), `.${o.nodeId}.migrating`), `migrating ${o.nodeId}`, () => {
    const v = judgeTarget(target, o);
    if (v.verdict !== 'husk' && !(v.verdict === 'same' && !o.inUse) && !(o.forImport && v.verdict === 'other')) return { retry: true };
    if (o.src && !sourcePresent(o.src)) return { retry: true }; // the 0.13 directory was moved in meanwhile: look again
    const live = lstatOrNull(target).isSymbolicLink() ? null : liveLockIn(target);
    if (live) return { live };
    const aside = path.join(path.dirname(target), `.${o.nodeId}.husk-${Date.now()}-${randomTag()}`);
    try { fs.renameSync(target, aside); } catch (e) { if (e.code === 'ENOENT') return { retry: true }; throw e; }
    fsyncDir(path.dirname(target));
    if (!lstatOrNull(aside).isSymbolicLink()) securePrivateFiles([aside], { narrowDirs: true });
    return { aside };
  });
}

/**
 * Make `target` free for a directory an import installs for `nodeId`: an empty directory (or one holding only a stale
 * lock) goes, anything else is set aside as a husk (kept); a live process in it refuses (EIDENTITYLOCK). Returns the
 * aside, or null.
 */
function clearForInstall(target, nodeId) {
  let aside = null;
  for (let attempt = 0; attempt < 20; attempt++) {
    const v = judgeTarget(target, { nodeId, holdsIdentity: false, source: { nodeId } });
    if (v.verdict === 'absent') return aside;
    const live = lstatOrNull(target) && !lstatOrNull(target).isSymbolicLink() ? liveLockIn(target) : null;
    if (live) throw lockError(`[SYM] A live process (PID ${live.pid ?? 'unknown'}) runs in ${target}; stop it before importing ${nodeId}. Nothing was changed.`, live);
    if (v.verdict === 'empty' || v.verdict === 'locks') {
      const lock = readLockFile(path.join(target, 'lock.pid'));
      if (lock) removeStaleLock(path.join(target, 'lock.pid'), lock);
      clearDeadLockArtifacts(target);
      try { fs.rmdirSync(target); } catch { /* look again */ }
      continue;
    }
    const r = setHuskAside(target, { nodeId, holdsIdentity: false, source: { nodeId }, inUse: false, src: null, forImport: true });
    if (r.live) throw lockError(`[SYM] A live process (PID ${r.live.pid ?? 'unknown'}) runs in ${target}; stop it before importing ${nodeId}. Nothing was changed.`, r.live);
    if (r.aside) aside = r.aside;
  }
  throw new Error(`[SYM] could not make ${target} free for the import: what was there kept changing; nothing was overwritten.`);
}

/**
 * After the node is in place: from the husk set aside at `aside`, the files that are the same as the node's are removed
 * (they are in the node), and the ones that differ are kept there and reported. An aside left with nothing in it goes.
 */
function reportHusk(aside, nodeDir, nodeId) {
  if (!aside || lstatOrNull(aside).isSymbolicLink()) return { aside, kept: aside ? ['(a link)'] : [] };
  const kept = [];
  const walk = (rel) => {
    let names = [];
    try { names = fs.readdirSync(path.join(aside, rel)); } catch { return; }
    for (const n of names) {
      const r = rel ? path.join(rel, n) : n;
      const p = path.join(aside, r);
      const st = lstatOrNull(p);
      if (!st) continue;
      if (st.isDirectory()) { walk(r); try { fs.rmdirSync(p); } catch { /* not empty: kept */ } continue; }
      if (!rel && isLockArtifact(n)) {
        const l = readLockFile(p);
        if (!l || !lockIsHeldByLiveProcess(l)) { try { fs.unlinkSync(p); } catch { /* */ } continue; }
      }
      if (st.isFile() && sameBytes(p, path.join(nodeDir, r))) { try { fs.unlinkSync(p); } catch { kept.push(r); } continue; }
      kept.push(r);
    }
  };
  walk('');
  try { fs.rmdirSync(aside); return { aside: null, kept: [] }; } catch { /* kept */ }
  fsyncDir(path.dirname(aside));
  try {
    process.emitWarning(`[SYM] ${nodeId}: a directory an earlier release made at by-id/${nodeId} without the identity was set aside at ${aside}; ` +
      `${kept.length} file(s) in it differ from the agent's and are kept there: ${kept.slice(0, 8).join(', ')}${kept.length > 8 ? ', …' : ''}. The agent runs on its own files.`,
    { code: 'SYM_HUSK_SET_ASIDE' });
  } catch { /* */ }
  return { aside, kept };
}

/** Two regular files hold the same bytes (read in pieces: a store file can be large). */
function sameBytes(a, b) {
  const sa = statOrNull(a); const sb = statOrNull(b);
  if (!sa || !sb || !sa.isFile() || !sb.isFile() || sa.size !== sb.size) return false;
  let fa; let fb;
  try {
    fa = fs.openSync(a, 'r'); fb = fs.openSync(b, 'r');
    const ba = Buffer.alloc(Math.min(sa.size, 1 << 20) || 1); const bb = Buffer.alloc(ba.length);
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

/** Free bytes for a new file in `dir`, or null where it cannot be told. */
function freeBytes(dir) {
  if (typeof fs.statfsSync !== 'function') return null;
  for (let d = path.resolve(dir); ; d = path.dirname(d)) {
    try { const s = fs.statfsSync(d); return Number(s.bavail) * Number(s.bsize); } catch { if (path.dirname(d) === d) return null; }
  }
}

/**
 * Across volumes, an identity directory is not linked but its small key files are copied (identity.json, and the 0.13
 * e2e-keypair.json when it is there): staged beside `target`, synced, read back and compared, committed by one rename.
 * The space is checked first; the source is never changed.
 */
function copyIdentityFiles(src, target, o) {
  const files = PRIVATE_KEY_FILES.filter((f) => fs.existsSync(path.join(src, f)));
  const data = files.map((f) => fs.readFileSync(path.join(src, f)));
  const need = data.reduce((n, b) => n + b.length, 0) + 64 * 1024;
  const free = freeBytes(path.dirname(target));
  if (free !== null && free < need) {
    throw new IdentityHaltError(o.name, path.join(src, 'identity.json'),
      `the identity directory ${src} is on another volume than ${path.dirname(target)}, so its key files are copied, and that volume has ${free} bytes free; ${need} are needed. Nothing was changed.`,
      `Free at least ${need} bytes on the volume of ${path.dirname(target)} and start again.`);
  }
  const staging = makeStaging(path.dirname(target), o.nodeId);
  try {
    files.forEach((f, i) => writeNewFileSynced(path.join(staging, f), data[i], 0o600));
    fsyncDir(staging);
    files.forEach((f, i) => {
      if (!fs.readFileSync(path.join(staging, f)).equals(data[i])) throw new Error(`[SYM] the copy of ${path.join(src, f)} does not read back as its source; nothing was installed, the source is untouched`);
    });
    try { fs.renameSync(staging, target); } catch (e) { if (e.code === 'ENOENT' || RENAME_TAKEN.has(e.code)) return 'retry'; throw e; }
    if (o.committed) o.committed('copied');
    fsyncDir(path.dirname(target));
    return 'copied';
  } finally {
    fs.rmSync(staging, { recursive: true, force: true });
  }
}

/**
 * True when a link under `dir` is relative and leads out of `dir`: moved one level deeper (nodes/<name> ->
 * nodes/by-id/<nodeId>) it would lead somewhere else, so such a directory is linked to, never moved. One readdir per
 * directory (the entry types come with it); links to directories are not followed.
 */
function hasEscapingLink(dir) {
  const root = path.resolve(dir);
  const within = (p) => { const r = path.relative(root, p); return r === '' || (!r.startsWith('..') && !path.isAbsolute(r)); };
  const walk = (d) => {
    let entries = [];
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return false; }
    for (const e of entries) {
      const p = path.join(d, e.name);
      if (e.isSymbolicLink()) {
        let t = null;
        try { t = fs.readlinkSync(p); } catch { continue; }
        if (!path.isAbsolute(t) && !within(path.resolve(d, t))) return true;
      } else if (e.isDirectory() && walk(p)) return true;
    }
    return false;
  };
  return walk(root);
}

/**
 * Move the 0.13 directory `src` in as `target`: ONE rename on its volume (atomic, no disk). A 0.13 directory that is a
 * link, a mount point, on another volume than `target`, or holds a relative link that leads out of it, is not copied:
 * `target` becomes a link to the directory it is (absolute), so the store stays where its operator put it. An identity directory across volumes has its key files
 * copied instead (copyIdentityFiles). Returns 'renamed' | 'linked' | 'copied', or 'retry' when what is there changed.
 */
function moveInto(src, target, o) {
  const l = lstatOrNull(src);
  if (!l) return 'retry';
  // `o.committed(how)` runs right after the one call that installs `target`, before anything else (the syncs included): it
  // puts the compat links in place, so the moment in which a 0.14.2 or 0.13 build finds neither is one call wide.
  const linkTo = (dir) => {
    try { fs.symlinkSync(dir, target, linkType()); } catch (e) { if (e.code === 'EEXIST') return 'retry'; throw e; }
    if (o.committed) o.committed('linked');
    fsyncDir(path.dirname(target));
    return 'linked';
  };
  if (l.isSymbolicLink()) {
    let real;
    try { real = fs.realpathSync(src); } catch { return 'retry'; }
    return linkTo(real);
  }
  if (!l.isDirectory()) return 'retry';
  const crossing = isMountPoint(src) || deviceOf(src) !== deviceOf(path.dirname(target));
  if (!crossing && hasEscapingLink(src)) return linkTo(fs.realpathSync(src));
  if (!crossing) {
    try {
      fs.renameSync(src, target);
      if (o.committed) o.committed('renamed');
      fsyncDir(path.dirname(target));
      fsyncDir(path.dirname(src));
      return 'renamed';
    } catch (e) {
      if (e.code === 'ENOENT' || RENAME_TAKEN.has(e.code)) return 'retry';
      if (e.code !== 'EXDEV' && e.code !== 'EBUSY') throw e;
    }
  }
  if (o.kind === 'identity') return copyIdentityFiles(src, target, o);
  return linkTo(fs.realpathSync(src));
}

/**
 * Make `target` the directory of `o.nodeId`, from the 0.13 directory `src` (null: none). Returns
 *   { state: 'placed', how, husk } — this call moved it in; { state: 'already' } — it is in place (moved by another
 *   start, or `target` is a link to `src` itself); { state: 'duplicate' } — the same identity is installed and in use,
 *   and `src` is a second copy; { state: 'conflict', reason, halt } — another identity is filed under the nodeId;
 *   { state: 'live', lock } — a live process runs in a husk at `target`.
 * A husk at `target` is set aside first (setHuskAside); an empty one, or one holding only a stale lock, is replaced.
 */
/** The 0.13 directory `src` is still there as itself: not gone, and not replaced by the compat link a start put in its place. */
const sourcePresent = (src) => Boolean(src && lstatOrNull(src) && !compatLinkNodeId(src));

function place(src, target, o) {
  fs.mkdirSync(path.dirname(target), { recursive: true });
  let husk = null;
  const until = Date.now() + LOCK_CORRUPT_GRACE_MS + 1000; // a lock artifact still being written is waited for, no longer
  for (let attempt = 0; attempt < 40 || Date.now() < until; attempt++) {
    const srcHere = sourcePresent(src);
    const v = judgeTarget(target, o);
    if (v.verdict !== 'absent' && srcHere && sameDir(src, target)) return { state: 'already', husk };
    if (v.verdict === 'other') return { state: 'conflict', reason: v.reason, halt: Boolean(v.halt) };
    if (!srcHere) {
      if (v.verdict === 'same' || (!o.holdsIdentity && v.verdict !== 'absent')) return { state: 'already', husk };
      if (!src && v.verdict === 'absent') { fs.mkdirSync(target, { mode: 0o700 }); fs.chmodSync(target, 0o700); return { state: 'placed', how: 'made', husk }; }
      if (attempt < 20) { pause(5); continue; } // another start is between its steps
      return { state: 'gone', husk };
    }
    if (v.verdict === 'same' && o.inUse) return { state: 'duplicate', husk };
    if (v.verdict === 'empty') {
      try { fs.rmdirSync(target); } catch (e) { if (e.code !== 'ENOENT' && e.code !== 'ENOTEMPTY' && e.code !== 'EEXIST') throw e; }
      continue;
    }
    if (v.verdict === 'locks') {
      const live = liveLockIn(target);
      if (live) return { state: 'live', lock: live };
      const lock = readLockFile(path.join(target, 'lock.pid'));
      if (lock) removeStaleLock(path.join(target, 'lock.pid'), lock);
      clearDeadLockArtifacts(target);
      try { fs.rmdirSync(target); } catch { pause(attempt > 4 ? 20 : 2); }
      continue;
    }
    if (v.verdict === 'husk' || v.verdict === 'same') {
      const r = setHuskAside(target, { ...o, src });
      if (r.live) return { state: 'live', lock: r.live };
      if (r.aside) husk = r.aside;
      continue;
    }
    const how = moveInto(src, target, o);
    if (how === 'retry') continue;
    return { state: 'placed', how, husk };
  }
  throw new Error(`[SYM] could not install ${target}: what was there kept changing; nothing was overwritten. Start again.`);
}

/**
 * Migrate the 0.13 agent under `name` (`nodes/<name>/`, and its identity at `SYM_IDENTITY_DIR/<name>/` when that is
 * set) to `nodes/by-id/<nodeId>` (and `SYM_IDENTITY_DIR/by-id/<nodeId>`) by MOVING it: one rename of the whole directory
 * on its volume (place, moveInto), the node directory first and the identity last. The identity in place IS the commit:
 * from then on the agent exists by its nodeId. Right after the commit the 0.13 path becomes a compat link (made before
 * the commit, so it is one rename), then the name is claimed (an exclusive create of its index entry).
 *
 * Of several starts doing this at once, one rename wins and the others find the identity in place. A by-id directory an
 * earlier release left without the identity (a husk) is set aside whole first and reported (setHuskAside, reportHusk).
 * A 0.13 directory that is a link, a mount point or on another volume is not copied: by-id/<nodeId> becomes a link to it.
 *
 * Refusals change nothing: a 0.13 process running in the directory ('skipped-live'); another identity filed under the
 * nodeId, or the name given to another agent by the index ('skipped-duplicate'); an identity this host exported
 * ('tombstoned'); a start pinned to another nodeId ('other-agent': the 0.13 agent is left for its own start); another
 * agent whose name is this one but for case ('fold-collision'). A 0.13 identity file that cannot be read halts.
 * @returns {{ status: string, nodeId?: string, reason?: string, holderPid?: number, husk?: object }}
 * @private
 */
function migrateName(name, onlyNodeId) {
  const srcs = legacySources(name);
  if (!srcs.nodes && !srcs.ids) {
    const e = entryFor(name);
    return e.state === 'ok' && isCommitted(e.nodeId) ? { status: 'already', nodeId: e.nodeId } : { status: 'not-a-node' };
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
  // The operator copied the identity to SYM_IDENTITY_DIR as the halt above says, and kept the original: one identity.
  if (srcs.idRoot && inNodeDir && fs.existsSync(inNodeDir)) {
    const other = parseIdentity(readIdentityText(inNodeDir, name), name, inNodeDir).source;
    if (!sameIdentityBothWays(read.source, other)) {
      throw new IdentityHaltError(name, inNodeDir, `two different identities sit under "${name}": ${idFile} (${nodeId}) and ${inNodeDir} (${other.nodeId}). Nothing was moved; keep the one that is this agent.`);
    }
  }
  if (onlyNodeId && nodeId !== onlyNodeId) return { status: 'other-agent', nodeId, reason: `the 0.13 directory of "${name}" holds the agent ${nodeId}, not the pinned ${onlyNodeId}; it was left as it is` };
  const tomb = readTombstone(nodeId);
  if (tomb) return { status: 'tombstoned', nodeId, tomb };
  const f = foldName(name);
  // The name already given to another agent by the index: a stray 0.13 directory under exactly that agent's name is left
  // as it is; one under a name that differs only in case is a second agent (a case-sensitive file system let both exist).
  const e = entryFor(name);
  if (e.state === 'conflict') return { status: 'fold-collision', nodeId, reason: `two index entries answer to "${name}": ${e.entries.map((x) => `${x.file} (${x.nodeId})`).join(', ')}` };
  if (e.state === 'ok' && e.nodeId !== nodeId && isCommitted(e.nodeId)) {
    const c = readCommitted(e.nodeId);
    const theirs = e.name || (c.state === 'ok' && c.name) || name; // the exact name the entry is for
    if (theirs !== name && foldName(theirs) === f) return { status: 'fold-collision', nodeId, reason: `the name "${theirs}" of the agent ${e.nodeId} is this name but for case` };
    return { status: 'skipped-duplicate', nodeId, reason: `the name "${name}" already indexes node ${e.nodeId}; the 0.13 identity ${nodeId} under it was left as it is` };
  }
  const others = namedHere(scanCommitted(), f, nodeId);
  if (others.length) {
    const exact = others.find((o) => o.name === name);
    return { status: exact ? 'skipped-duplicate' : 'fold-collision', nodeId,
      reason: `the agent${others.length > 1 ? 's' : ''} ${others.map((o) => `${o.nodeId} ("${o.name}")`).join(', ')} already ${others.length > 1 ? 'have' : 'has'} this name; the 0.13 identity ${nodeId} under "${name}" was left as it is` };
  }
  // A 0.13 process running in its directory holds its lock there: refuse, change nothing.
  if (srcs.nodes) {
    const lock = readLockFile(path.join(srcs.nodes.path, 'lock.pid'));
    if (lock && !lock.migrating && lock.pid !== process.pid && lockIsHeldByLiveProcess(lock)) return { status: 'skipped-live', nodeId, holderPid: lock.pid };
  }
  // The identity's own name, for a scan to find it by: a 0.13 file named otherwise (copied under another name) is
  // renamed in place first, atomically, its key untouched (the commit below must carry the name).
  if (read.source.name === undefined || typeof read.source.name !== 'string' || foldName(read.source.name) !== f) {
    writeFileAtomic0600(idFile, JSON.stringify({ ...read.source, name }, null, 2));
    read.source.name = name;
  }
  const nodeTarget = nodeDirById(nodeId);
  const idTarget = identityDirById(nodeId);
  const split = idTarget !== nodeTarget;
  const inUse = (e.state === 'ok' && e.nodeId === nodeId) || indexEntries().has(nodeId);
  const base = { nodeId, source: read.source, name, inUse };
  const out = { status: 'already', nodeId };
  const conflict = (r) => ({ status: 'skipped-duplicate', nodeId, reason: `the 0.13 identity under "${name}" was not migrated: ${r.reason}`, halt: r.halt });
  const live = (r) => ({ status: 'husk-live', nodeId, holderPid: r.lock && r.lock.pid });
  // The 0.13 paths become compat links right after the commit: the links are made now, so that is one rename each. A 0.13
  // directory is never moved out from under a path that no link can then take (a 0.13 or 0.14.2 build reads it there).
  const tmpLinks = [];
  const linkFor = (root, src) => {
    if (!src || (!src.link && isMountPoint(src.path))) return null; // a mount point stays where it is: no link takes its place
    const t = makeTempLink(path.join(root, name), nodeId);
    if (!t) {
      throw new Error(`[SYM] cannot make the link ${path.join(root, name)} -> by-id/${nodeId} that takes the place of the 0.13 directory ` +
        `(the file system refused a symbolic link there), so "${name}" was not migrated; nothing was moved. A state root needs a file system that holds links.`);
    }
    tmpLinks.push(t);
    return t;
  };
  try {
    const husks = [];
    const nodesLink = linkFor(NODES_DIR, srcs.nodes);
    if (split) {
      const idLink = linkFor(srcs.idRoot, srcs.ids);
      const n = place(srcs.nodes && srcs.nodes.path, nodeTarget, { ...base, holdsIdentity: false, kind: 'node' });
      if (n.state === 'conflict') return conflict(n);
      if (n.state === 'live') return live(n);
      if (n.husk) husks.push([n.husk, nodeTarget]);
      // Right after the commit: SYM_IDENTITY_DIR/<name> first (0.14.2 finds the agent by it), then nodes/<name>.
      const committed = (how) => {
        if (how !== 'copied') putTempLink(idLink, path.join(srcs.idRoot, name));
        if (n.state === 'placed' && (n.how === 'renamed' || (n.how === 'linked' && srcs.nodes.link))) putTempLink(nodesLink, path.join(NODES_DIR, name));
      };
      const c = place(srcs.ids.path, idTarget, { ...base, holdsIdentity: true, kind: 'identity', committed }); // THE COMMIT
      if (c.state === 'conflict') return conflict(c);
      if (c.state === 'live') return live(c);
      if (c.husk) husks.push([c.husk, idTarget]);
      if (c.state === 'placed') { out.status = 'moved'; securePrivateFiles([idTarget], { narrowDirs: true }); }
      // The key's 0.13 copy, where it is not the commit: set aside (narrowed), and the link in its place.
      if (c.state === 'duplicate' || (c.state === 'placed' && c.how === 'copied')) {
        if (srcs.ids.link) putTempLink(idLink, path.join(srcs.idRoot, name));
        else setLegacyAside(srcs.ids.path, srcs.idRoot, name, () => putTempLink(idLink, path.join(srcs.idRoot, name)));
      }
      if (n.state === 'duplicate' && srcs.nodes) setLegacyAside(srcs.nodes.path, NODES_DIR, name, () => putTempLink(nodesLink, path.join(NODES_DIR, name)));
    } else {
      const committed = (how) => { if (how === 'renamed' || srcs.nodes.link) putTempLink(nodesLink, path.join(NODES_DIR, name)); }; // right after the commit
      const c = place(srcs.nodes.path, nodeTarget, { ...base, holdsIdentity: true, kind: 'node', committed }); // THE COMMIT
      if (c.state === 'conflict') return conflict(c);
      if (c.state === 'live') return live(c);
      if (c.husk) husks.push([c.husk, nodeTarget]);
      if (c.state === 'placed') {
        out.status = 'moved';
        securePrivateFiles([nodeTarget], { narrowDirs: true });
      }
      if (c.state === 'duplicate') {
        if (srcs.nodes.link) putTempLink(nodesLink, path.join(NODES_DIR, name));
        else setLegacyAside(srcs.nodes.path, NODES_DIR, name, () => putTempLink(nodesLink, path.join(NODES_DIR, name)));
      }
    }
    // Moved in by another start meanwhile, or the 0.13 directory went elsewhere: nothing is claimed for an identity not in place.
    if (!isCommitted(nodeId)) return { status: 'gone', nodeId, reason: `the 0.13 directory of "${name}" is no longer there and ${nodeId} is not installed` };
    // The name, claimed once the identity is in place. Of two starts, the second finds the entry made.
    const winner = claimName(name, nodeId, name);
    if (winner && winner !== nodeId) {
      out.reason = `the name "${name}" was claimed for node ${winner} meanwhile`;
      out.claimedBy = winner;
    }
    securePrivateFiles([nodeTarget, idTarget], { narrowDirs: true });
    out.husks = husks.map(([aside, dir]) => reportHusk(aside, dir, nodeId)).filter((h) => h.aside);
    return out;
  } finally {
    for (const t of tmpLinks) { if (lstatOrNull(t)) { try { removeLink(t); } catch { /* */ } } }
  }
}

/**
 * Migrate the 0.13 directory of `name` to the by-id layout (see migrateName). Idempotent, safe from several
 * processes at once.
 * @param {string} name
 * @param {string} [onlyNodeId]
 * @returns {'moved'|'skipped-live'|'skipped-duplicate'|'not-a-node'|'already'|'tombstoned'|'other-agent'|'fold-collision'|'husk-live'}
 */
function migrateNodeDir(name, onlyNodeId) {
  const problem = basicNameProblem(name);
  if (problem) throw new Error(problem);
  clearLeftovers();
  return migrateName(name, onlyNodeId).status;
}

/**
 * Migrate every 0.13 node directory under the state root to the by-id layout. Safe to run at every start and from
 * several processes; an error of one node is counted (that node's own start raises it).
 * @returns {{ moved: number, already: number, skippedLive: number, duplicates: number, errors: number }}
 */
function migrateIdentities() {
  const out = { moved: 0, already: 0, skippedLive: 0, duplicates: 0, errors: 0 };
  clearLeftovers();
  const names = new Set();
  for (const root of [NODES_DIR, process.env.SYM_IDENTITY_DIR].filter(Boolean)) {
    let entries = [];
    try { entries = fs.readdirSync(root); } catch { continue; }
    for (const n of entries) if (n !== 'by-id' && n !== 'by-name' && !n.startsWith('.') && !basicNameProblem(n)) names.add(n);
  }
  for (const name of names) {
    let r;
    try { r = migrateName(name).status; } catch { out.errors++; continue; }
    if (r === 'moved') out.moved++;
    else if (r === 'already') out.already++;
    else if (r === 'skipped-live' || r === 'husk-live') out.skippedLive++;
    else if (r === 'skipped-duplicate' || r === 'fold-collision') out.duplicates++;
  }
  return out;
}

// ── Loading ──────────────────────────────────────────────────────────────

/**
 * Whether the export `intent` produced a complete bundle: it says so (written after the bundle was renamed into place),
 * or a file whose sha256 is the bundle's recorded hash is at its out (a crash between the two).
 */
function exportProducedBundle(intent) {
  if (!intent) return false;
  if (intent.complete === true) return true;
  if (typeof intent.bundleHash !== 'string' || typeof intent.out !== 'string') return false;
  try { return crypto.createHash('sha256').update(fs.readFileSync(intent.out)).digest('hex') === intent.bundleHash; } catch { return false; }
}

/**
 * Refuse an identity that was moved away or is being moved (relocation.js), whatever else is true of it: an export
 * that produced its bundle is a move (IdentityTombstonedError); one that did not yet is pending (IdentityExportPendingError).
 */
function assertStartable(nodeId) {
  const intent = readExportIntent(nodeId);
  const tomb = readTombstone(nodeId);
  if (intent && !exportProducedBundle(intent)) throw new IdentityExportPendingError(nodeId, intent, tomb);
  if (tomb || intent) throw new IdentityTombstonedError(nodeId, tomb || { movedAt: intent.startedAt, bundle: intent.out }, intent);
}

/** Load the committed identity of `nodeId`: export and tombstone checked, file validated (halts, never mints), modes narrowed. */
function loadInstalled(nodeId, label, { allowPendingExport = false } = {}) {
  if (!allowPendingExport) assertStartable(nodeId);
  const idPath = identityFileById(nodeId);
  const identity = readIdentityFile(idPath, label);
  if (identity.nodeId !== nodeId) throw new IdentityHaltError(label, idPath, `identity.json names ${identity.nodeId}, not ${nodeId}`);
  const nodeDir = nodeDirById(nodeId);
  securePrivateFiles([nodeDir], { narrowDirs: true }); // the store's directory, and the 0.13 E2E keypair in it
  if (nodeDir !== path.dirname(idPath)) dropStrayKey(nodeDir, identity);
  clearDeadLockTemps(nodeDir);
  return identity;
}

/**
 * With SYM_IDENTITY_DIR the private key belongs only in the identity directory. A copy of it left in the node directory
 * (0.13 operators copied the key there and kept the original; 0.14.0 - 0.14.2 moved that copy along with the store) that
 * is the very identity just read from its committed place is removed: the key is not lost, it is where it is kept. A copy
 * that is anything else is left as it is (narrowed to 0600) for the operator.
 */
function dropStrayKey(nodeDir, identity) {
  const f = path.join(nodeDir, 'identity.json');
  const r = readJsonState(f);
  if (r.state !== 'ok' || !r.j.privateKey || !sameIdentityBothWays(identity, r.j)) return;
  try { fs.unlinkSync(f); fsyncDir(nodeDir); } catch { /* narrowed, and scrubbed by an export */ }
}

/** The temp files of locks a process that is gone was writing or removing, left in a node directory (a kill -9). */
function clearDeadLockTemps(dir) {
  let names = [];
  try { names = fs.readdirSync(dir); } catch { return; }
  for (const n of names) {
    const m = /^\.lock\.pid.*\.(\d+)-[0-9a-f]+\.tmp$/.exec(n);
    if (m && Number(m[1]) !== process.pid && !pidIsAlive(Number(m[1]))) { try { fs.unlinkSync(path.join(dir, n)); } catch { /* */ } }
  }
}

/** The directories on this host other than the committed one that may hold a copy of `nodeId`'s key files. */
function keyHoldersOf(nodeId) {
  const out = new Set();
  const idRoot = process.env.SYM_IDENTITY_DIR;
  const byIdDirs = new Set([path.join(NODES_DIR, 'by-id'), idRoot && path.join(idRoot, 'by-id')].filter(Boolean));
  for (const dir of byIdDirs) {
    out.add(path.join(dir, nodeId));
    let names = [];
    try { names = fs.readdirSync(dir); } catch { continue; }
    for (const n of names) if (n.startsWith(`.${nodeId}.husk`) || n.startsWith(`.${nodeId}.moved-`)) out.add(path.join(dir, n));
  }
  const holds = (d) => { try { return JSON.parse(fs.readFileSync(path.join(d, 'identity.json'), 'utf8')).nodeId === nodeId; } catch { return false; } };
  for (const root of [NODES_DIR, idRoot].filter(Boolean)) {
    let names = [];
    try { names = fs.readdirSync(path.join(root, LEGACY_ASIDE)); } catch { /* none */ }
    for (const n of names) if (holds(path.join(root, LEGACY_ASIDE, n))) out.add(path.join(root, LEGACY_ASIDE, n));
    // A 0.13 directory left in place (a mount point an identity was copied from, a store linked to): it holds a copy.
    try { names = fs.readdirSync(root); } catch { names = []; }
    for (const n of names) {
      if (n.startsWith('.') || n === 'by-id' || n === 'by-name') continue;
      const p = path.join(root, n);
      const st = lstatOrNull(p);
      if (st && st.isDirectory() && !st.isSymbolicLink() && holds(p)) out.add(p);
    }
  }
  return [...out];
}

/** Where on this host an identity.json for `nodeId` is, other than where a load reads it. */
function strayCopiesOf(nodeId) {
  const committed = identityFileById(nodeId);
  return keyHoldersOf(nodeId).map((d) => path.join(d, 'identity.json'))
    .filter((f) => f !== committed && (() => { try { return JSON.parse(fs.readFileSync(f, 'utf8')).nodeId === nodeId; } catch { return false; } })());
}

/**
 * The halt for an identity that is not installed where it is read: the name's index entry names it
 * (`indexed`), or a start asks for it by nodeId. When a copy of it is elsewhere on this host the halt says
 * where, and never tells the operator to remove the index entry.
 */
function indexedButMissing(name, nodeId, { indexed = true } = {}) {
  const idPath = identityFileById(nodeId);
  const copies = strayCopiesOf(nodeId);
  const link = path.join(NODES_DIR, name);
  const what = indexed ? `the name "${name}" indexes node ${nodeId}, and its identity.json is not where it is read` : `the identity ${nodeId} is not installed where it is read`;
  const dir = identityDirById(nodeId);
  const l = lstatOrNull(dir);
  const dangling = l && l.isSymbolicLink() && !statOrNull(dir) ? ` (${dir} is a link to ${fs.readlinkSync(dir)}, which is not there: is its volume mounted?)` : '';
  if (copies.length) {
    return new IdentityHaltError(name, idPath,
      `${what}${dangling}; it IS on this host, at ${copies.join(' and ')}.`,
      `Put a copy of it at ${idPath} (keep the original until the agent has started)` +
      `${process.env.SYM_IDENTITY_DIR ? ', or unset SYM_IDENTITY_DIR if this agent\'s key was never meant to live there' : ''}. Do not remove the name's index entry: the key is this agent.`);
  }
  return new IdentityHaltError(name, idPath,
    `${what}${dangling}, and no copy of it is on this host. ` +
    'If SYM_IDENTITY_DIR changed or its volume is not mounted, restore that.',
    `Restore the keypair from your durable copy to ${idPath} and start again. If this agent's key is gone for good, it cannot return as "${name}"; ` +
    `to let the name start again as a DIFFERENT agent, remove ${nameIndexPath(name)} and the link ${link}.`);
}

/**
 * What on this host is a claim on `name` besides a committed identity named so: each is a reason not to mint.
 * `{ kind, identity, nodeId, text, committed?, live?, other? }`: `identity` when it holds (or may hold) an identity.
 */
function nameTraces(name, entry, migration) {
  const f = foldName(name);
  const out = [];
  const idRoot = process.env.SYM_IDENTITY_DIR;
  const idOf = (d) => { try { const j = JSON.parse(fs.readFileSync(path.join(d, 'identity.json'), 'utf8')); return { nodeId: j.nodeId, name: j.name }; } catch { return null; } };
  if (entry && entry.state === 'unreadable') out.push({ kind: 'entry', identity: true, nodeId: null, text: `the index entry ${entry.file} exists, but ${entry.why}` });
  if (migration && ['skipped-duplicate', 'other-agent', 'gone'].includes(migration.status)) {
    out.push({ kind: 'migration', identity: true, other: true, nodeId: migration.nodeId, text: `a 0.13 identity (${migration.nodeId}) sits under "${name}" and was not migrated (${migration.reason || migration.status})` });
  }
  for (const [root, label] of [[NODES_DIR, 'nodes'], [idRoot, 'SYM_IDENTITY_DIR']]) {
    if (!root) continue;
    let names = [];
    try { names = fs.readdirSync(root).filter((n) => !n.startsWith('.') && n !== 'by-id' && n !== 'by-name' && foldName(n) === f); } catch { /* none */ }
    for (const n of names) {
      const at = path.join(root, n);
      const st = lstatOrNull(at);
      if (!st) continue;
      const linked = compatLinkNodeId(at);
      if (linked) {
        const committed = isCommitted(linked);
        out.push({ kind: 'link', identity: committed, committed, nodeId: linked, text: `${at} leads to by-id/${linked}${committed ? '' : ', whose identity is not installed (is its volume mounted?)'}` });
      } else if (st.isSymbolicLink() || st.isDirectory()) {
        const l = legacyAt(at);
        const id = l && idOf(l.path);
        if (id) out.push({ kind: 'legacy', identity: true, nodeId: id.nodeId, text: `a 0.13 identity (${id.nodeId}) sits in ${at}` });
        else if (st.isSymbolicLink()) { let t = '?'; try { t = fs.readlinkSync(at); } catch { /* */ } out.push({ kind: 'dangling', identity: false, text: `${at} is a link to ${t} with no identity in it` }); }
        else if (hasContent(at)) {
          out.push({ kind: 'files', identity: false, text: `${at} holds a node's files (${fs.readdirSync(at).filter((x) => !isLockArtifact(x)).slice(0, 4).join(', ')}) and no identity` +
            `${label === 'nodes' && idRoot ? `, and ${path.join(idRoot, n, 'identity.json')} is not there (is the identity volume mounted?)` : ''}` });
        }
      } else {
        out.push({ kind: 'file', identity: false, text: `${at} is a file, not a node directory` });
      }
    }
    let aside = [];
    try { aside = fs.readdirSync(path.join(root, LEGACY_ASIDE)); } catch { /* none */ }
    for (const n of aside) {
      const base = (/^(.*)\.\d+-[0-9a-f]{8}$/.exec(n) || [null, n])[1];
      if (foldName(base) !== f) continue;
      const d = path.join(root, LEGACY_ASIDE, n);
      const id = idOf(d);
      out.push({ kind: 'aside', identity: Boolean(id), nodeId: id && id.nodeId, text: `the 0.13 directory of "${base}" was set aside at ${d}${id ? ` (identity ${id.nodeId})` : ''}` });
    }
  }
  // Husks set aside, import archives, and the staging of a start under way, that hold an identity of this name.
  for (const dir of new Set([path.join(NODES_DIR, 'by-id'), idRoot && path.join(idRoot, 'by-id')].filter(Boolean))) {
    let names = [];
    try { names = fs.readdirSync(dir); } catch { continue; }
    for (const n of names) {
      const m = /^\.([0-9A-Za-z][0-9A-Za-z_.-]*?)\.(husk|moved|stage|import|partial)(?:-|$)/.exec(n);
      if (!m) continue;
      const id = idOf(path.join(dir, n));
      if (!id || typeof id.name !== 'string' || foldName(id.name) !== f || isCommitted(id.nodeId)) continue;
      const staging = STAGING_RE.exec(n);
      out.push({ kind: staging ? 'staging' : 'aside', identity: true, nodeId: id.nodeId, live: Boolean(staging && !leftoverIsDead(Number(staging[3]), path.join(dir, n))),
        text: `${path.join(dir, n)} holds the identity ${id.nodeId} named "${id.name}"${staging ? ' (a start under way)' : ''}` });
    }
  }
  return out;
}

/**
 * Which committed identity `name` is. The index entry is a cache of the answer: when it is readable and names a
 * committed identity, that is the answer (an entry 0.14.0 - 0.14.2 wrote for a rename or a pinned start, naming an
 * identity under another name, included). When it is missing or cannot be read, the answer is re-derived from the
 * committed identities (their `name`), with the compat link `nodes/<name>` as a second witness; with `write` the
 * entry is then written again (claimed when missing, replaced when its content is not an entry; an entry that could
 * not be read for an I/O error is left as it is). Never "no such agent" while something says otherwise:
 *   { nodeId, via: 'index'|'scan', alias } — the agent; { nodeId, missing: true } — the entry names an identity that is
 *   not in place (a halt, never a mint); { none: true, traces } — no committed identity is this name (mint only when
 *   `traces` is empty). Two committed identities that are this name halt.
 */
function resolveName(name, { write = true, migration = null } = {}) {
  const f = foldName(name);
  for (let round = 0; ; round++) {
    const e = entryFor(name);
    if (e.state === 'conflict') throw twoAgentsHalt(name, e.entries.map((x) => x.nodeId), `their index entries are ${e.entries.map((x) => x.file).join(' and ')}`);
    if (e.state === 'ok') {
      if (!isCommitted(e.nodeId)) return { nodeId: e.nodeId, missing: true, entry: e };
      const c = readCommitted(e.nodeId);
      const own = c.state === 'ok' && c.name !== null && foldName(c.name) === f;
      if (own && !c.scrubbed) {
        const others = namedHere(scanCommitted(), f, e.nodeId);
        if (others.length) {
          if (round < 20) { pause(5); continue; }
          throw twoAgentsHalt(name, [e.nodeId, ...others.map((o) => o.nodeId)], `the index names ${e.nodeId}`);
        }
      }
      if (e.exactKey && write) claimName(name, e.nodeId, e.name || name);
      return { nodeId: e.nodeId, via: 'index', entry: e, alias: c.state === 'ok' && c.name !== null && !own };
    }
    const scan = scanCommitted();
    const traces = nameTraces(name, e, migration);
    const ids = new Set(namedHere(scan, f).map((i) => i.nodeId));
    for (const t of traces) if (t.kind === 'link' && t.committed && !readTombstone(t.nodeId)) ids.add(t.nodeId);
    if (ids.size > 1) {
      if (round < 20) { pause(10); continue; }
      throw twoAgentsHalt(name, [...ids], 'and no index entry says which');
    }
    if (ids.size === 1) {
      const id = [...ids][0];
      const blocking = traces.filter((t) => t.identity && t.kind !== 'entry' && t.kind !== 'link' && (t.other || t.nodeId !== id));
      if (blocking.length) {
        throw new IdentityHaltError(name, nameIndexPath(name),
          `the identity ${id} is installed for "${name}" and no index entry names it, and this host holds another claim on the name: ${blocking.map((t) => t.text).join('; ')}. ` +
          'Nothing was changed.', 'Decide which one is this agent: start it by its nodeId, and move or rename the other. Do not remove an identity.json: each is an agent\'s key.');
      }
      if (write) {
        const c = readCommitted(id);
        const exact = (c.state === 'ok' && c.name) || name;
        if (e.state === 'missing') { const w = claimName(name, id, exact); if (w && w !== id) continue; }
        else if (e.state === 'unreadable' && !e.io) repairEntry(name, id, exact);
      }
      return { nodeId: id, via: 'scan', entry: e };
    }
    // Nothing committed is this name. Another start that is installing it right now is given a moment.
    if (traces.some((t) => t.live) && round < 300) { pause(10); continue; }
    return { none: true, traces, entry: e };
  }
}

/** The halt (or, for create: false with nothing that holds an identity, the absence) for a name with traces and no agent. */
function tracesHalt(name, traces, { create = true, pin = null } = {}) {
  if (!create && !traces.some((t) => t.identity)) return new IdentityAbsentError(pin ? `"${name}" (${pin})` : `"${name}"`, traces.map((t) => t.text));
  const entry = traces.find((t) => t.kind === 'entry');
  return new IdentityHaltError(name, nameIndexPath(name),
    `no installed identity is named "${name}", and this host holds a trace of it: ${traces.map((t) => t.text).join('; ')}` +
    `${pin ? `; this start is pinned to ${pin}, which is not on this host` : ''}. ` +
    'Making a new identity here would orphan or overwrite its key, so none was made.',
    entry
      ? `The index entry is the record of which node this name is: restore it (it holds {"name": ${JSON.stringify(name)}, "nodeId": "<the agent's nodeId>"}), or restore the identity it named. Do not delete it to "start over".`
      : 'If the trace is this agent, restore its identity (or its index entry); if it is not, move it out of the way. Then start again.');
}

/**
 * The halt for a start pinned to `pin` under a name whose index entry names another identity (`held`). The entry
 * is left as it is: a name is one agent's on this host.
 */
function nameHeldByAnother(name, pin, held) {
  const there = isCommitted(held);
  return new IdentityHaltError(name, nameIndexPath(name),
    `this start is pinned to ${pin}, and the name "${name}" is another agent's on this host: its index entry names ${held}` +
    `${there ? '' : ' (whose identity is not installed here)'}. A pinned start does not take a name from another identity: the next start of ` +
    `"${name}" by name would run as ${pin}, and ${held} would be left without its name. The index entry was left as it is.`,
    `Start ${pin} under its own name, or pin the start to ${held} if that is the agent meant. To give "${name}" to ${pin}, ` +
    `rename the other agent first (renameIdentity).`);
}

/**
 * An entry 0.14.0 - 0.14.2 wrote for a rename or a pinned start names `nodeId` under `name`, which is not its own: when
 * it is the identity's only name (no entry under its own name leads to it) and no other agent is named so, the identity
 * takes it, so the name can be derived from what is committed from now on.
 */
function adoptAliasName(name, nodeId, identity) {
  const c = readCommitted(nodeId);
  if (c.state !== 'ok' || c.scrubbed) return identity;
  if (c.name !== null) { const own = entryFor(c.name); if (own.state === 'ok' && own.nodeId === nodeId) return identity; }
  if (namedHere(scanCommitted(), foldName(name), nodeId).length) return identity;
  try { writeFileAtomic0600(c.file, JSON.stringify({ ...c.identity, name }, null, 2)); } catch { return identity; }
  return { ...identity, name };
}

/** The short lock under which a name is minted: one process at a time makes the agent of a name. */
const mintLockPath = (name) => path.join(NODES_DIR, 'by-id', `.mint-${encodeURIComponent(foldName(name))}.lock`);

/**
 * Make a new identity for `name`, under the name's mint lock: staged (identity.json written and synced in a staging
 * directory beside its destination) and committed by ONE rename; right after the commit the compat link, then the
 * name claimed by an exclusive create of its index entry. Returns null when the entry was taken meanwhile (only a
 * process of an earlier release, which takes no mint lock, can): this identity was never anyone's, and it is removed.
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
  const nodeTarget = nodeDirById(nodeId);
  const idTarget = identityDirById(nodeId);
  const split = idTarget !== nodeTarget;
  const idRoot = process.env.SYM_IDENTITY_DIR;
  if (split) {
    fs.mkdirSync(path.dirname(nodeTarget), { recursive: true });
    fs.mkdirSync(nodeTarget, { mode: 0o700 });
    fs.chmodSync(nodeTarget, 0o700);
  }
  const staging = makeStaging(path.dirname(idTarget), nodeId);
  const links = [];
  try {
    writeNewFileSynced(path.join(staging, 'identity.json'), JSON.stringify(identity, null, 2), 0o600);
    fsyncDir(staging);
    if (split) links.push([makeTempLink(path.join(idRoot, name), nodeId), path.join(idRoot, name)]);
    links.push([makeTempLink(path.join(NODES_DIR, name), nodeId), path.join(NODES_DIR, name)]);
    fs.renameSync(staging, idTarget); // THE COMMIT
    for (const [tmp, at] of links) putTempLink(tmp, at); // right after it
    fsyncDir(path.dirname(idTarget));
  } finally {
    fs.rmSync(staging, { recursive: true, force: true });
    for (const [tmp] of links) if (tmp && lstatOrNull(tmp)) { try { removeLink(tmp); } catch { /* */ } }
  }
  const winner = claimName(name, nodeId, name);
  if (winner !== nodeId) {
    fs.rmSync(idTarget, { recursive: true, force: true });
    if (split) fs.rmSync(nodeTarget, { recursive: true, force: true });
    if (winner) ensureCompatLinks(name, winner);
    return null;
  }
  return identity;
}

/**
 * Load a node's identity by nodeId or by name (design D9). An agent exists exactly when its identity is committed
 * (`by-id/<nodeId>/identity.json`, in SYM_IDENTITY_DIR when set). The name index and the compat links are caches of
 * which agent a name is, written after the commit and re-derived from the committed identities when they are missing
 * or cannot be read; nothing is inferred from a path that merely exists.
 *
 *   - `{ nodeId }` loads that identity;
 *   - `{ name }` (pinned or not) first migrates a 0.13 agent still under the name (migrateName: moved, not copied), then
 *     resolves the name (resolveName);
 *   - a 0.13 directory a live process holds refuses (EIDENTITYLOCK): the agent is running there;
 *   - a pinned start never takes a name another agent holds (R4-9): committed, indexed, or a 0.13 agent not yet
 *     migrated; it may claim a name nobody has;
 *   - `create: false` throws IdentityAbsentError when the identity is not on this host;
 *   - `create: true` (the default) is the ONLY path that mints, under the name's mint lock, and only when no committed
 *     identity, 0.13 directory, aside or staging holds the name and nothing else on the host is a trace of it;
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
  clearLeftovers();
  if (!name) {
    if (isCommitted(pin)) return loadInstalled(pin, pin, how);
    if (strayCopiesOf(pin).length) throw indexedButMissing(pin, pin, { indexed: false });
    throw new IdentityAbsentError(pin);
  }
  // 1. A 0.13 agent under the name is migrated first: the same path for a pinned start and an unpinned one.
  let migration = null;
  if (legacyIdentityUnder(name)) {
    migration = migrateName(name, pin);
    const s = migration.status;
    if (s === 'skipped-live') {
      throw lockError(
        `[SYM] Agent '${name}' is running in its 0.13 directory: a live process (PID ${migration.holderPid}) holds ${path.join(NODES_DIR, name, 'lock.pid')}.\n\n` +
        '  One agent runs in one process. This start is refused; nothing was moved or changed. Stop that process (it is an older copy of ' +
        'this same agent), and start again: the agent is migrated then, with its store.', { pid: migration.holderPid });
    }
    if (s === 'husk-live') {
      throw lockError(`[SYM] A live process (PID ${migration.holderPid ?? 'unknown'}) holds ${path.join(nodeDirById(migration.nodeId), 'lock.pid')}, but ${migration.nodeId}'s identity is not installed there: ` +
        'a node of an earlier release is running in that directory without its identity. Stop it, then start this agent again; nothing was changed.', { pid: migration.holderPid });
    }
    if (s === 'tombstoned') throw new IdentityTombstonedError(migration.nodeId, migration.tomb);
    if (s === 'fold-collision') {
      throw new IdentityHaltError(name, path.join(NODES_DIR, name, 'identity.json'),
        `the 0.13 agent ${migration.nodeId} under "${name}" and another agent on this host are one name (names are compared without regard to case): ${migration.reason}. The 0.13 agent was not migrated; nothing was changed.`,
        'Give one of them another name: rename the installed agent (renameIdentity), or move this 0.13 directory to another name. Then start again.');
    }
    if (s === 'skipped-duplicate' && migration.halt) throw new IdentityHaltError(name, path.join(NODES_DIR, name, 'identity.json'), migration.reason);
  }
  if (pin) return loadPinned(name, pin, create, how, migration);
  return resolveOrMint(name, { create, how, migration });
}

/**
 * Load the agent `name` is, or (create) mint it under the name's mint lock when nothing on this host holds the name.
 * `pin`: a pinned start whose pin is not on this host (create: true), which never gets the name's agent.
 */
function resolveOrMint(name, { create, how, migration, pin = null }) {
  for (let round = 0; round < 3; round++) {
    const r = resolveName(name, { write: true, migration });
    if (r.nodeId && pin && r.nodeId !== pin) throw nameHeldByAnother(name, pin, r.nodeId);
    if (r.nodeId) return loadResolved(name, r, create, how);
    if (r.traces.length) throw tracesHalt(name, r.traces, { create, pin });
    if (!create) throw new IdentityAbsentError(pin ? `"${name}" (${pin})` : `"${name}"`);
    const m = withShortLock(mintLockPath(name), `making the agent "${name}"`, () => {
      const again = resolveName(name, { write: true, migration });
      if (again.nodeId) return { r: again };
      if (again.traces.length) throw tracesHalt(name, again.traces, { create, pin });
      return { minted: mintIdentity(name) };
    });
    if (m.r && pin && m.r.nodeId !== pin) throw nameHeldByAnother(name, pin, m.r.nodeId);
    if (m.r) return loadResolved(name, m.r, create, how);
    if (m.minted) return m.minted;
  }
  throw new Error(`[SYM] the name "${name}" did not settle (its index entry kept being claimed and lost); nothing was minted`);
}

/** Load what a name resolved to (resolveName). */
function loadResolved(name, r, create, how) {
  if (r.missing) {
    if (!create && !strayCopiesOf(r.nodeId).length) throw new IdentityAbsentError(`"${name}" (${r.nodeId})`);
    throw indexedButMissing(name, r.nodeId);
  }
  let identity = loadInstalled(r.nodeId, name, how);
  if (r.alias) identity = adoptAliasName(name, r.nodeId, identity);
  ensureCompatLinks(name, r.nodeId);
  return identity;
}

/** A start pinned to `pin` under `name` (mesh-channel: name + nodeId, create: false). */
function loadPinned(name, pin, create, how, migration) {
  const r = resolveName(name, { write: false, migration });
  const held = r.nodeId || null;
  if (isCommitted(pin)) {
    if (held && held !== pin) throw nameHeldByAnother(name, pin, held);
    if (!held) {
      const claims = (r.traces || []).filter((t) => t.identity && (t.other || (t.nodeId && t.nodeId !== pin)));
      if (claims.length) {
        throw new IdentityHaltError(name, nameIndexPath(name),
          `this start is pinned to ${pin}, and the name "${name}" is held on this host by another agent: ${claims.map((t) => t.text).join('; ')}. ` +
          'A pinned start does not take a name from another agent; nothing was changed.',
          `Start "${name}" by name once (that migrates the agent it holds, and it runs as itself), and start ${pin} under its own name.`);
      }
    }
    const identity = loadInstalled(pin, name, how);
    if (!held || r.via !== 'index' || (r.entry && r.entry.exactKey)) {
      const w = claimName(name, pin, name);
      if (w && w !== pin) throw nameHeldByAnother(name, pin, w); // another start claimed it this moment
    }
    ensureCompatLinks(name, pin);
    return r.alias ? adoptAliasName(name, pin, identity) : identity;
  }
  if (migration && migration.nodeId === pin && !['moved', 'already', 'not-a-node'].includes(migration.status)) {
    throw new IdentityHaltError(name, path.join(NODES_DIR, name, 'identity.json'),
      `the identity ${pin} this start is pinned to is on this host, in the 0.13 directory of "${name}", and could not be migrated: ${migration.reason || migration.status}.`,
      'Resolve that, then start again. Nothing was changed.');
  }
  if (!create) {
    if (strayCopiesOf(pin).length) throw indexedButMissing(name, pin, { indexed: false });
    const elsewhere = held && held !== pin ? [`the name "${name}" is another agent's here (${held}), and was left as it is`] : [];
    throw new IdentityAbsentError(`"${name}" (${pin})`, [...elsewhere, ...(r.traces || []).map((t) => t.text)]);
  }
  // Not on this host, and the name is another identity's: the start is never answered with that one.
  if (held && held !== pin) throw nameHeldByAnother(name, pin, held);
  // create: true and a pin this host does not hold: a name nobody holds is minted (a new nodeId: the Known limit kept).
  return resolveOrMint(name, { create, how, migration, pin });
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
 * The nodeId the name is on this host (resolveName, writing nothing), or null when no agent is. Halts
 * (IdentityHaltError) where the host holds two answers.
 * @param {string} name
 * @returns {string|null}
 */
function nodeIdForName(name) {
  const r = resolveName(name, { write: false });
  return r.nodeId || null;
}

/**
 * Rename a node: the identity's own `name` is the commit of the rename; the index entry and the compat link follow
 * (the new name is claimed exclusively first, so a crash leaves both names leading to the agent, never neither).
 * The old name only needs to be a name at all, so an agent whose name a later rule refuses (one Windows cannot hold)
 * can be renamed to one it accepts.
 * @returns {string} the nodeId
 */
function renameIdentity(oldName, newName) {
  const problem = basicNameProblem(oldName);
  if (problem) throw new Error(problem);
  validateName(newName);
  const r = resolveName(oldName, { write: false });
  if (!r.nodeId || r.missing) throw new IdentityAbsentError(`"${oldName}"`);
  const nodeId = r.nodeId;
  const caseOnly = foldName(oldName) === foldName(newName);
  if (!caseOnly) {
    const n = resolveName(newName, { write: false });
    if ((n.nodeId && n.nodeId !== nodeId) || (!n.nodeId && n.traces.some((t) => t.identity))) throw new Error(`the name "${newName}" already indexes a node`);
    const w = claimName(newName, nodeId, newName);
    if (w !== nodeId) throw new Error(`the name "${newName}" already indexes a node`);
  } else {
    repairEntry(newName, nodeId, newName);
  }
  const c = readCommitted(nodeId);
  if (c.state === 'ok' && c.name !== newName) writeFileAtomic0600(c.file, JSON.stringify({ ...c.identity, name: newName }, null, 2));
  const byName = path.join(NODES_DIR, 'by-name');
  for (const f of new Set([nameIndexPath(oldName), exactIndexPath(oldName)])) {
    if (caseOnly && f === nameIndexPath(newName)) continue;
    const e = readEntryFile(f, foldName(oldName));
    if (e.state === 'ok' && e.nodeId === nodeId && !sameFile(f, nameIndexPath(newName))) { try { fs.unlinkSync(f); } catch { /* */ } }
  }
  fsyncDir(byName);
  for (const root of [NODES_DIR, process.env.SYM_IDENTITY_DIR].filter(Boolean)) {
    const link = path.join(root, oldName);
    if (oldName !== newName && compatLinkNodeId(link) === nodeId && !sameFile(link, path.join(root, newName))) { try { removeLink(link); } catch { /* */ } }
  }
  ensureCompatLinks(newName, nodeId);
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
  /** For relocation.js: durable writes, staging beside a destination, the committed state, and the key's copies. */
  writeFileDurable,
  writeNewFileSynced,
  writeFileAtomic0600,
  fsyncDir,
  makeStaging,
  setHuskAside,
  isCommitted,
  readCommitted,
  claimName,
  ensureCompatLinks,
  keyHoldersOf,
  clearForInstall,
  clearLeftovers,
  compatLinkNodeId,
  exportProducedBundle,
  assertStartable,
  foldName,
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
