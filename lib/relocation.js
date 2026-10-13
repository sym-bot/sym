'use strict';

/**
 * @module @sym-bot/sym/relocation
 * @description Moving a node to another host (sym 0.14, design D9.2). §3.1.3: "The private key MUST
 * NOT leave the node" — so a node is MOVED, never copied:
 *
 *   - `exportNode` holds the identity's lock throughout (no process can start it meanwhile), writes a
 *     TOMBSTONE at the source FIRST, then the bundle (fsynced, renamed into place, its directory
 *     fsynced). The source refuses to start that identity from then on (config.js
 *     IdentityTombstonedError), so no copy remains live: the relay's 4004 replacement cannot produce
 *     two live copies, because the source is tombstoned before the bundle exists. Once the bundle
 *     is durable the source LOSES THE KEY (security review): identity.json is rewritten without its
 *     private key, and the 0.13-compatible `nodes/<name>` link goes, so a 0.13 build on the source
 *     host (a rollback) cannot load the moved identity either.
 *   - The bundle holds the node's directory — its identity, store, key registry, grants and learned
 *     state — encrypted under an operator passphrase (scrypt → AES-256-GCM) or to a target host's
 *     X25519 key (ephemeral X25519 + HKDF-SHA256 → AES-256-GCM).
 *   - The bundle is SIGNED by the moving node's identity key, over its format, nodeId, sealing header
 *     (the target host key and ephemeral key included) and the digest of its contents (security
 *     review): a bundle sealed to a host key, which anyone holding that public key can seal, is
 *     authenticated by the node itself, and cannot be re-wrapped for another host.
 *   - `importNode` verifies the bundle against an EXPLICIT, INDEPENDENTLY PINNED (nodeId, key): one
 *     the operator gives (`expect`: the key or its sha256 fingerprint, e.g. from a validator's
 *     preserve act). There is no fallback to a key this host learned on first contact (security
 *     review). It never relies on anything the bundle says about itself: a bundle whose identity was
 *     re-keyed, or whose signature does not verify under the pinned key, is refused.
 *
 * Final re-review (Finding 7):
 *   - A bundle is sealed to the target host's key by default. A passphrase bundle can be opened, and
 *     so imported, on any host that has the passphrase, so it is a copy, not a move: it needs
 *     `copyable: true` (the CLI's --allow-copies), and the docs say so.
 *   - The clear header carries the node's public key and a signature over the header (`headerSig`),
 *     checked against the pin BEFORE the header's scrypt parameters are used (and those are bounded).
 *   - A host refuses a bundle it has imported before (`consumed-bundles.jsonl`), and one exported at
 *     or before its own tombstone of that node (a replay of an older move).
 *   - An import is staged in a directory of its own and renamed into place last: a refused import
 *     installs nothing. File modes travel with the files.
 *   - Export refuses while a node in this process holds the identity's lock.
 *
 * @copyright 2026 SYM.BOT. Apache 2.0 License.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { verifyStrict } = require('./core/ed25519');
const config = require('./config');
const { keyFingerprint, isIdentityKey } = require('./roster-keys');

const FORMAT = 'sym-node-bundle-v1';
const SKIP = new Set(['lock.pid', config.TOMBSTONE, 'interior.sock']);
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const HOST_KEY_FILE = 'host-key.json';
const CONSUMED_FILE = 'consumed-bundles.jsonl';
/** The scrypt parameters a bundle's header may ask for, at most (a hostile header must not cost more). */
const MAX_SCRYPT = { N: 1 << 17, r: 16, p: 4 };

/** This host's X25519 key pair for receiving bundles (created on first use, 0600). */
function hostKey({ create = true } = {}) {
  const file = path.join(config.SYM_DIR, HOST_KEY_FILE);
  try {
    const k = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (typeof k.publicKey === 'string' && typeof k.privateKey === 'string') return k;
  } catch { /* none yet */ }
  if (!create) return null;
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  const k = {
    publicKey: publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64url'),
    privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32).toString('base64url'),
    createdAt: Date.now(),
  };
  config.ensureDir(config.SYM_DIR);
  fs.writeFileSync(file, JSON.stringify(k, null, 2), { mode: 0o600 });
  return k;
}

function listFiles(root, rel = '') {
  // (paths relative to root; see exportLocked for the modes that travel with them)
  const out = [];
  for (const d of fs.readdirSync(path.join(root, rel), { withFileTypes: true })) {
    const p = path.join(rel, d.name);
    if (!rel && SKIP.has(d.name)) continue;
    if (d.name.endsWith('.tmp')) continue;
    if (d.isDirectory()) out.push(...listFiles(root, p));
    else if (d.isFile()) out.push(p);
  }
  return out;
}

/** The sealing key and its header, chosen before anything is sealed (so a signature can cover it). */
function sealParams({ passphrase, toHostKey }) {
  let key;
  let header;
  if (typeof passphrase === 'string' && passphrase.length >= 12) {
    const salt = crypto.randomBytes(16);
    const params = { N: 32768, r: 8, p: 1 };
    key = crypto.scryptSync(passphrase, salt, 32, { ...params, maxmem: 128 * 1024 * 1024 });
    header = { kdf: 'scrypt', salt: salt.toString('base64url'), ...params };
  } else if (typeof toHostKey === 'string' && toHostKey) {
    const raw = Buffer.from(toHostKey, 'base64url');
    if (raw.length !== 32) throw new Error('relocation: the target host key is not a 32-byte X25519 key');
    const eph = crypto.generateKeyPairSync('x25519');
    const ss = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: crypto.createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' }) });
    const ephPub = eph.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    key = Buffer.from(crypto.hkdfSync('sha256', ss, Buffer.concat([ephPub, raw]), Buffer.from('sym-node-bundle-v1', 'utf8'), 32));
    header = { kdf: 'x25519-hkdf', ephemeral: ephPub.toString('base64url'), to: toHostKey };
  } else {
    throw new Error('relocation: a passphrase (at least 12 characters) or a target host key is required');
  }
  return { key, header };
}

function sealWith(plain, { key }) {
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const body = Buffer.concat([c.update(plain), c.final()]);
  return { nonce: nonce.toString('base64url'), ciphertext: Buffer.concat([body, c.getAuthTag()]).toString('base64url') };
}

function seal(plain, opts) {
  const p = sealParams(opts);
  return { ...p.header, ...sealWith(plain, p) };
}

function unseal(bundle, { passphrase, hostPrivateKey }) {
  let key;
  if (bundle.kdf === 'scrypt') {
    if (typeof passphrase !== 'string') throw new Error('relocation: this bundle needs its passphrase');
    const ok = (v, max) => Number.isSafeInteger(v) && v >= 1 && v <= max;
    if (!ok(bundle.N, MAX_SCRYPT.N) || (bundle.N & (bundle.N - 1)) !== 0 || !ok(bundle.r, MAX_SCRYPT.r) || !ok(bundle.p, MAX_SCRYPT.p)) {
      throw new Error('relocation: the bundle asks for scrypt parameters outside the bound');
    }
    key = crypto.scryptSync(passphrase, Buffer.from(bundle.salt, 'base64url'), 32, { N: bundle.N, r: bundle.r, p: bundle.p, maxmem: 128 * 1024 * 1024 });
  } else if (bundle.kdf === 'x25519-hkdf') {
    const priv = hostPrivateKey || (hostKey({ create: false }) || {}).privateKey;
    if (!priv) throw new Error('relocation: this bundle is sealed to a host key this host does not hold');
    const privObj = crypto.createPrivateKey({ key: Buffer.concat([X25519_PKCS8_PREFIX, Buffer.from(priv, 'base64url')]), format: 'der', type: 'pkcs8' });
    const ephPub = Buffer.from(bundle.ephemeral, 'base64url');
    const ss = crypto.diffieHellman({ privateKey: privObj, publicKey: crypto.createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, ephPub]), format: 'der', type: 'spki' }) });
    const ownPub = crypto.createPublicKey(privObj).export({ type: 'spki', format: 'der' }).subarray(-32);
    key = Buffer.from(crypto.hkdfSync('sha256', ss, Buffer.concat([ephPub, ownPub]), Buffer.from('sym-node-bundle-v1', 'utf8'), 32));
  } else {
    throw new Error(`relocation: unknown bundle sealing '${bundle.kdf}'`);
  }
  const sealed = Buffer.from(bundle.ciphertext, 'base64url');
  const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(bundle.nonce, 'base64url'));
  d.setAuthTag(sealed.subarray(sealed.length - 16));
  try {
    return Buffer.concat([d.update(sealed.subarray(0, sealed.length - 16)), d.final()]);
  } catch {
    throw new Error('relocation: the bundle does not open (a wrong passphrase or host key, or the bundle was altered)');
  }
}

/** The Ed25519 public key a raw private key derives. */
function publicOf(privateKeyB64url) {
  const priv = crypto.createPrivateKey({ key: Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(privateKeyB64url, 'base64url')]), format: 'der', type: 'pkcs8' });
  return crypto.createPublicKey(priv).export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64url');
}

/**
 * Move a node off this host: tombstone it, then write its encrypted bundle.
 * @param {object} o
 * @param {string} [o.name]
 * @param {string} [o.nodeId]
 * @param {string} o.out - the bundle file to write
 * @param {string} [o.passphrase]
 * @param {string} [o.toHostKey] - the target host's X25519 public key (sym node host-key there)
 * @returns {{ nodeId: string, name: string, files: number, out: string, fingerprint: string }}
 */
function exportNode({ name, nodeId, out, passphrase, toHostKey, copyable = false } = {}) {
  if (!out) throw new Error('relocation: out (the bundle file) is required');
  const id = nodeId || (name && config.nodeIdForName(name));
  if (!id) throw new config.IdentityAbsentError(name ? `"${name}"` : 'the node');
  const dir = config.nodeDirById(id);
  if (config.readTombstone(id)) throw new Error(`relocation: ${id} is already tombstoned here (it was exported)`);
  const identity = config.loadIdentity({ nodeId: id, name, create: false });
  // A node running in THIS process holds the lock too (final re-review, Finding 7a).
  if (config.lockHeldInProcess(dir)) throw new Error(`relocation: ${identity.name} is running in this process; stop it before moving it`);
  const lock = config.readLockFile(path.join(dir, 'lock.pid'));
  if (lock && lock.pid !== process.pid && config.lockIsHeldByLiveProcess(lock)) {
    throw new Error(`relocation: ${identity.name} is running (PID ${lock.pid}); stop it before moving it`);
  }
  // Sealed to the target host by default. A passphrase bundle opens on any host with the passphrase:
  // it is a copy, and says so (final re-review, Finding 7b).
  if (typeof passphrase === 'string' && !(typeof toHostKey === 'string' && toHostKey) && copyable !== true) {
    throw new Error('relocation: a passphrase bundle can be imported on any host that has the passphrase, so it is a copy, not a move; seal it to the target host (toHostKey, --to-host), or pass copyable: true (--allow-copies)');
  }
  // Validate the sealing input before the tombstone: a refused export must leave the node startable.
  seal(Buffer.alloc(0), { passphrase, toHostKey });
  // The identity's lock, held until the export is done: no process starts it in between.
  const release = config.acquireIdentityLock(identity.name, { dir });
  try {
    return exportLocked({ id, dir, identity, out, passphrase, toHostKey });
  } finally {
    try { release(); } catch { /* the lock goes with the process either way */ }
  }
}

/** @private The export, under the identity's lock. */
function exportLocked({ id, dir, identity, out, passphrase, toHostKey }) {
  // THE TOMBSTONE FIRST. From here this host refuses to start the identity, before any bundle exists.
  const tomb = { nodeId: id, name: identity.name, movedAt: Date.now(), bundle: path.basename(out), fingerprint: keyFingerprint(identity.publicKey) };
  const tombPath = path.join(dir, config.TOMBSTONE);
  const fd = fs.openSync(tombPath, 'wx');
  try { fs.writeSync(fd, JSON.stringify(tomb, null, 2)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  // Each file with its mode (final re-review, Finding 7b), so a 0600 file stays 0600 on the target.
  const files = listFiles(dir).map((rel) => ({ path: rel.split(path.sep).join('/'), mode: fs.statSync(path.join(dir, rel)).mode & 0o777, data: fs.readFileSync(path.join(dir, rel)).toString('base64') }));
  // identity.json lives elsewhere when SYM_IDENTITY_DIR is set: it travels in the bundle all the same.
  if (!files.some((f) => f.path === 'identity.json')) {
    files.push({ path: 'identity.json', mode: 0o600, data: Buffer.from(JSON.stringify(identity, null, 2)).toString('base64') });
  }
  const contents = { format: FORMAT, nodeId: id, name: identity.name, publicKey: identity.publicKey, exportedAt: tomb.movedAt, files };
  // The sealing header is chosen first, so the node's signature covers it (the target host key and
  // the ephemeral key included): the bundle is the node's own statement, for that host only.
  // A host key, when given, wins over a passphrase.
  const sealing = sealParams(typeof toHostKey === 'string' && toHostKey ? { toHostKey } : { passphrase });
  const header = { format: FORMAT, nodeId: id, fingerprint: tomb.fingerprint, publicKey: identity.publicKey, exportedAt: tomb.movedAt, ...sealing.header };
  const signature = signBundle(header, contents, identity.privateKey);
  // The clear header is signed on its own as well, so an import checks it against the pin before it
  // uses anything the header says (the scrypt parameters).
  const headerSig = signHeader(header, identity.privateKey);
  const plain = Buffer.from(JSON.stringify({ ...contents, signature }), 'utf8');
  const bundle = { ...header, headerSig, ...sealWith(plain, sealing) };
  const tmp = `${out}.${process.pid}.tmp`;
  const bfd = fs.openSync(tmp, 'w', 0o600);
  try { fs.writeSync(bfd, JSON.stringify(bundle)); fs.fsyncSync(bfd); } finally { fs.closeSync(bfd); }
  fs.renameSync(tmp, out);
  fsyncDir(path.dirname(path.resolve(out)));
  // The bundle is durable: the source loses the key, and the 0.13 path to it.
  scrubSource(id, identity);
  return { nodeId: id, name: identity.name, files: files.length, out, fingerprint: tomb.fingerprint };
}

/** @private fsync a directory (a rename in it is durable after this); best effort where unsupported. */
function fsyncDir(dir) {
  let fd;
  try { fd = fs.openSync(dir, 'r'); fs.fsyncSync(fd); } catch { /* not supported here (Windows) */ } finally { if (fd !== undefined) try { fs.closeSync(fd); } catch { /* */ } }
}

/**
 * @private After a durable export: identity.json (in the node dir and SYM_IDENTITY_DIR) without its
 * private key, written atomically, and the 0.13-compatible `nodes/<name>` links removed.
 */
function scrubSource(id, identity) {
  const { privateKey, ...rest } = identity;
  void privateKey;
  const scrubbed = JSON.stringify({ ...rest, privateKey: null, movedAt: Date.now() }, null, 2);
  for (const d of new Set([config.nodeDirById(id), config.identityDirById(id)])) {
    const f = path.join(d, 'identity.json');
    if (!fs.existsSync(f)) continue;
    const tmp = `${f}.${process.pid}.tmp`;
    const fd = fs.openSync(tmp, 'w', 0o600);
    try { fs.writeSync(fd, scrubbed); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    fs.renameSync(tmp, f);
    fsyncDir(d);
  }
  for (const root of [config.NODES_DIR, process.env.SYM_IDENTITY_DIR].filter(Boolean)) {
    const link = path.join(root, identity.name);
    try { if (fs.lstatSync(link).isSymbolicLink()) fs.unlinkSync(link); } catch { /* none */ }
  }
}

/** @private The canonical bytes a bundle's signature covers. */
function bundleSigned(header, contents) {
  const digest = crypto.createHash('sha256');
  for (const f of contents.files) digest.update(String(f.path)).update('\0').update(String(f.data)).update('\n');
  const h = Object.keys(header).sort().map((k) => `${k}=${header[k]}`).join('\n');
  return Buffer.from(`sym-node-bundle-v1-signature\n${h}\nnodeId=${contents.nodeId}\npublicKey=${contents.publicKey}\nname=${contents.name}\nexportedAt=${contents.exportedAt}\nfiles=${digest.digest('hex')}`, 'utf8');
}

/** @private The canonical bytes the clear header's own signature covers. */
function headerSigned(header) {
  return Buffer.from(`sym-node-bundle-v1-header\n${Object.keys(header).sort().map((k) => `${k}=${header[k]}`).join('\n')}`, 'utf8');
}

function signHeader(header, privateKeyB64url) {
  const priv = crypto.createPrivateKey({ key: Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(privateKeyB64url, 'base64url')]), format: 'der', type: 'pkcs8' });
  return crypto.sign(null, headerSigned(header), priv).toString('base64url');
}

function verifyHeader(header, signature, publicKeyB64url) {
  if (typeof signature !== 'string' || !isIdentityKey(publicKeyB64url)) return false;
  try {
    return verifyStrict(headerSigned(header), publicKeyB64url, signature); // MMP §18.3.2
  } catch { return false; }
}

/** @private Bundles this host has imported: their signatures, so none is imported twice. */
function consumedBundles() {
  const out = new Set();
  try {
    for (const line of fs.readFileSync(path.join(config.SYM_DIR, CONSUMED_FILE), 'utf8').split('\n')) {
      try { const o = JSON.parse(line); if (o && typeof o.signature === 'string') out.add(o.signature); } catch { /* a partial line */ }
    }
  } catch { /* none yet */ }
  return out;
}

function signBundle(header, contents, privateKeyB64url) {
  const priv = crypto.createPrivateKey({ key: Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(privateKeyB64url, 'base64url')]), format: 'der', type: 'pkcs8' });
  return crypto.sign(null, bundleSigned(header, contents), priv).toString('base64url');
}

function verifyBundle(header, contents, signature, publicKeyB64url) {
  if (typeof signature !== 'string') return false;
  try {
    return verifyStrict(bundleSigned(header, contents), publicKeyB64url, signature); // MMP §18.3.2
  } catch { return false; }
}

/**
 * Bring a moved node onto this host, verified against an independently pinned key.
 * @param {object} o
 * @param {string} o.from - the bundle file
 * @param {string} [o.passphrase]
 * @param {string} [o.hostPrivateKey] - default: this host's host-key.json
 * @param {{ nodeId: string, key?: string, fingerprint?: string }} [o.expect] - the independent pin
 * @param {string} [o.name] - index it under another name
 * @returns {{ nodeId: string, name: string, files: number, pinnedBy: string }}
 */
function importNode({ from, passphrase, hostPrivateKey, expect, name } = {}) {
  const bundle = JSON.parse(fs.readFileSync(from, 'utf8'));
  if (!bundle || bundle.format !== FORMAT) throw new Error('relocation: not a sym node bundle');
  // THE INDEPENDENT PIN, checked against the clear header before anything the header says is used
  // (final re-review, Finding 7b: the scrypt parameters). Never what the bundle says about itself.
  let pinnedBy = null;
  if (!expect || !expect.nodeId || !(expect.key || expect.fingerprint)) {
    throw new Error(`relocation: refusing ${bundle.nodeId}: no explicit pinned key (give --expect-key or --expect-fingerprint, from the validator's preserve act or the source host)`);
  }
  if (expect.nodeId !== bundle.nodeId) throw new Error(`relocation: the bundle is ${bundle.nodeId}, not the expected ${expect.nodeId}`);
  if (expect.key) { pinnedBy = 'operator key'; if (expect.key !== bundle.publicKey) throw new Error(`relocation: refusing ${bundle.nodeId}: the bundle's key is not the pinned one (${pinnedBy}) — a re-keyed bundle`); }
  else { pinnedBy = 'operator fingerprint'; if (!isIdentityKey(bundle.publicKey) || keyFingerprint(bundle.publicKey) !== expect.fingerprint) throw new Error(`relocation: refusing ${bundle.nodeId}: the bundle's key is not the pinned one (${pinnedBy}) — a re-keyed bundle`); }
  const { ciphertext, nonce, headerSig, ...header } = bundle;
  void ciphertext; void nonce;
  if (!verifyHeader(header, headerSig, bundle.publicKey)) throw new Error(`relocation: refusing ${bundle.nodeId}: the bundle's header is not signed by the node it names`);
  const plain = JSON.parse(unseal(bundle, { passphrase, hostPrivateKey }).toString('utf8'));
  const idFile = (plain.files || []).find((f) => f.path === 'identity.json');
  if (!idFile) throw new Error('relocation: the bundle carries no identity');
  const identity = JSON.parse(Buffer.from(idFile.data, 'base64').toString('utf8'));
  if (!identity || typeof identity.nodeId !== 'string' || !isIdentityKey(identity.publicKey) || typeof identity.privateKey !== 'string') {
    throw new Error('relocation: the bundle\'s identity is malformed');
  }
  if (publicOf(identity.privateKey) !== identity.publicKey) throw new Error('relocation: the bundle\'s private key does not match its public key');
  if (identity.publicKey !== bundle.publicKey || identity.nodeId !== bundle.nodeId) throw new Error(`relocation: refusing ${identity.nodeId}: the bundle's key is not the pinned one (${pinnedBy}) — a re-keyed bundle`);
  // The node's own signature over the bundle: header (the sealing it was made for), identity and
  // contents. A bundle without one, or one that does not verify under the pinned key, is refused.
  const contents = { format: plain.format, nodeId: plain.nodeId, name: plain.name, publicKey: plain.publicKey, exportedAt: plain.exportedAt, files: plain.files || [] };
  if (plain.nodeId !== identity.nodeId || plain.publicKey !== identity.publicKey || header.exportedAt !== plain.exportedAt || !verifyBundle(header, contents, plain.signature, identity.publicKey)) {
    throw new Error(`relocation: refusing ${identity.nodeId}: the bundle is not signed by the node it carries (or its header or contents were changed)`);
  }
  // Not a bundle this host imported before, and not older than this host's own move of the node away
  // (a replayed earlier bundle would bring back a past self).
  if (consumedBundles().has(plain.signature)) throw new Error(`relocation: refusing ${identity.nodeId}: this bundle was already imported on this host`);
  const tomb = config.readTombstone(identity.nodeId);
  if (tomb && Number.isFinite(tomb.movedAt) && !(plain.exportedAt > tomb.movedAt)) {
    throw new Error(`relocation: refusing ${identity.nodeId}: the bundle was exported at or before this host moved the node away (a replay of an older move)`);
  }
  const dest = config.nodeDirById(identity.nodeId);
  if (fs.existsSync(dest) && !tomb) throw new Error(`relocation: ${identity.nodeId} already lives on this host`);
  const label = name || identity.name;
  config.validateName(label);
  const existing = config.nodeIdForName(label);
  if (existing && existing !== identity.nodeId) throw new Error(`relocation: the name "${label}" already indexes another node here; import with another name`);
  // STAGED: everything is written to a directory of its own, and renamed into place last, so an
  // import refused or failing on the way installs nothing (final re-review, Finding 7b).
  const staged = `${dest}.import-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
  try {
    for (const f of plain.files) {
      const rel = String(f.path);
      if (rel.includes('..') || path.isAbsolute(rel) || rel.includes('\\')) throw new Error(`relocation: refusing a bundle path outside the node: ${rel}`);
      const p = path.join(staged, ...rel.split('/'));
      config.ensureDir(path.dirname(p));
      const mode = rel === 'identity.json' ? 0o600 : (Number.isSafeInteger(f.mode) ? (f.mode & 0o777) : 0o644);
      fs.writeFileSync(p, Buffer.from(f.data, 'base64'), { mode });
      fs.chmodSync(p, mode);
    }
  } catch (err) {
    fs.rmSync(staged, { recursive: true, force: true });
    throw err;
  }
  if (fs.existsSync(dest)) {
    // It was moved away from here before: the tombstoned copy is archived, and the node comes back.
    fs.renameSync(dest, `${dest}.moved-${Date.now()}`);
  }
  fs.renameSync(staged, dest);
  fsyncDir(path.dirname(dest));
  const idDirExt = config.identityDirById(identity.nodeId);
  if (idDirExt !== dest) { config.ensureDir(idDirExt); fs.writeFileSync(path.join(idDirExt, 'identity.json'), Buffer.from(idFile.data, 'base64'), { mode: 0o600 }); }
  try { fs.appendFileSync(path.join(config.SYM_DIR, CONSUMED_FILE), JSON.stringify({ nodeId: identity.nodeId, signature: plain.signature, exportedAt: plain.exportedAt, importedAt: Date.now() }) + '\n', { mode: 0o600 }); }
  catch { /* best effort: the tombstone check still refuses an older bundle */ }
  // indexName is internal to config; loadIdentity by nodeId + name writes the index.
  config.loadIdentity({ nodeId: identity.nodeId, name: label, create: false });
  return { nodeId: identity.nodeId, name: label, files: plain.files.length, pinnedBy };
}

module.exports = { exportNode, importNode, hostKey, FORMAT };
