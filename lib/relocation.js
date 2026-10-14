'use strict';

/**
 * @module @sym-bot/sym/relocation
 * @description Moving a node to another host (sym 0.14, design D9.2). §3.1.3: "The private key MUST
 * NOT leave the node" — so a node is MOVED, never copied:
 *
 *   - `exportNode` holds the identity's lock throughout (no process can start it meanwhile), and the source stops
 *     using the key BEFORE any bundle can exist (0.14.3), each step durable before the next:
 *       1. an export INTENT (EXPORTING.json) beside the key: its out and its recipient;
 *       2. the TOMBSTONE beside the key (and a copy in the node directory, which is where 0.14.2 looks): from here the
 *          source refuses to start the identity, and so does a 0.14.2 build rolled back to;
 *       3. the bundle's hash, written into the intent; then the bundle (fsynced, renamed into place, its directory
 *          fsynced), and `complete` written into the intent;
 *       4. the source LOSES THE KEY (security review): identity.json is rewritten without its private key (and so is
 *          every other copy on this host: a 0.13 directory set aside, a husk set aside, the 0.13 E2E keypair), the
 *          0.13-compatible `nodes/<name>` link goes, and the intent goes.
 *     A crash after the tombstone and before a complete bundle leaves the agent refused, saying so
 *     (IdentityExportPendingError). Run the same export again (the same out, the same recipient) and it is finished;
 *     another out is refused while a complete bundle may exist at the intent's out. `abortExport` reverts the tombstone
 *     only when no complete bundle was produced (the hash recorded in the intent tells), and the node starts here again.
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
const SKIP = new Set(['lock.pid', config.TOMBSTONE, config.EXPORTING, config.COMMIT_MARK, 'interior.sock']);
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
    if (!rel && (SKIP.has(d.name) || d.name.startsWith('lock.pid.'))) continue;
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

/** The sha256 of `buf`, hex. */
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

/** Who a bundle is sealed to: a host key (a move), or a passphrase (a copy). A host key, when given, wins. */
const recipientOf = ({ passphrase, toHostKey }) => (typeof toHostKey === 'string' && toHostKey ? `host:${toHostKey}` : (typeof passphrase === 'string' ? 'passphrase' : null));
const describeRecipient = (r) => (r && r.startsWith('host:') ? `the host key ${r.slice(5)}` : 'a passphrase');

/** @private The intent beside the key, written durably. */
function writeIntent(id, intent) {
  config.writeFileDurable(path.join(config.identityDirById(id), config.EXPORTING), JSON.stringify(intent, null, 2), 0o600);
}

/** @private The tombstone beside the key, and a copy in the node directory, where 0.14.0 - 0.14.2 read it (a rollback). */
function writeTombstone(id, tomb) {
  const text = JSON.stringify(tomb, null, 2);
  config.writeFileDurable(path.join(config.identityDirById(id), config.TOMBSTONE), text, 0o600);
  const dir = config.nodeDirById(id);
  if (dir !== config.identityDirById(id) && fs.existsSync(dir)) config.writeFileDurable(path.join(dir, config.TOMBSTONE), text, 0o600);
}

/** @private The intent goes (the tombstone stays): the export is finished. */
function removeIntent(id) {
  for (const d of new Set([config.identityDirById(id), config.nodeDirById(id)])) {
    try { fs.unlinkSync(path.join(d, config.EXPORTING)); fsyncDir(d); } catch { /* */ }
  }
}

/**
 * Move a node off this host. The source stops using the key before any bundle can exist: an intent beside the key,
 * then the tombstone, then the bundle (its hash recorded in the intent first), then the source's key scrubbed. Run
 * again after an interruption (the same out, the same recipient), it finishes what was begun.
 * @param {object} o
 * @param {string} [o.name]
 * @param {string} [o.nodeId]
 * @param {string} o.out - the bundle file to write
 * @param {string} [o.passphrase]
 * @param {string} [o.toHostKey] - the target host's X25519 public key (sym node host-key there)
 * @returns {{ nodeId: string, name: string, files: number, out: string, fingerprint: string, resumed?: string }}
 */
function exportNode({ name, nodeId, out, passphrase, toHostKey, copyable = false } = {}) {
  if (!out) throw new Error('relocation: out (the bundle file) is required');
  const id = nodeId || (name && config.nodeIdForName(name));
  if (!id) throw new config.IdentityAbsentError(name ? `"${name}"` : 'the node');
  config.clearLeftovers();
  const dir = config.nodeDirById(id);
  const idDir = config.identityDirById(id);
  const outAbs = path.resolve(out);
  const intent = config.readExportIntent(id);
  const tomb = config.readTombstone(id);
  if (tomb && !intent) {
    // Finished, or (an earlier release) interrupted between its tombstone and the scrub: the scrub is finished here.
    const left = readIdentityJson(idDir);
    if (left && left.privateKey) {
      scrubSource(id, left);
      return { nodeId: id, name: left.name, files: 0, out: tomb.bundle || null, fingerprint: tomb.fingerprint || keyFingerprint(left.publicKey), resumed: 'scrub' };
    }
    throw new Error(`relocation: ${id} is already tombstoned here (it was exported${tomb.bundle ? ` to ${tomb.bundle}` : ''})`);
  }
  // A node running in THIS process holds the lock too (final re-review, Finding 7a).
  if (config.lockHeldInProcess(dir)) throw new Error(`relocation: ${(intent && intent.name) || name || id} is running in this process; stop it before moving it`);
  const lock = config.readLockFile(path.join(dir, 'lock.pid'));
  if (lock && lock.pid !== process.pid && config.lockIsHeldByLiveProcess(lock)) {
    throw new Error(`relocation: ${(intent && intent.name) || name || id} is running (PID ${lock.pid}); stop it before moving it`);
  }
  const complete = intent && config.exportProducedBundle(intent);
  if (!complete) {
    // Sealed to the target host by default. A passphrase bundle opens on any host with the passphrase:
    // it is a copy, and says so (final re-review, Finding 7b).
    if (typeof passphrase === 'string' && !(typeof toHostKey === 'string' && toHostKey) && copyable !== true) {
      throw new Error('relocation: a passphrase bundle can be imported on any host that has the passphrase, so it is a copy, not a move; seal it to the target host (toHostKey, --to-host), or pass copyable: true (--allow-copies)');
    }
    // Validate the sealing input before anything is written: a refused export leaves the node startable.
    seal(Buffer.alloc(0), { passphrase, toHostKey });
  }
  if (intent && !complete) {
    // A resume: the same recipient, and while a complete bundle may exist at the intent's out, the same out.
    const recipient = recipientOf({ passphrase, toHostKey });
    if (intent.recipient && intent.recipient !== recipient) {
      throw new Error(`relocation: the export of ${id} that did not finish is sealed to ${describeRecipient(intent.recipient)}; run it again with that recipient, or abandon it (sym node abort-export)`);
    }
    if (intent.out !== outAbs && (intent.bundleHash || !intent.tombstoned)) {
      throw new Error(`relocation: the export of ${id} that did not finish may have written a complete bundle to ${intent.out}; resume it with --out ${intent.out} ` +
        '(a second bundle elsewhere would be a second live copy of the key), or abandon it (sym node abort-export)');
    }
  }
  // The identity, with its key: read where it is committed (a pending export refuses a load).
  const identity = intent ? readIdentityJson(idDir) : config.loadIdentity({ nodeId: id, create: false });
  if (!identity || identity.nodeId !== id) throw new Error(`relocation: ${id}'s identity cannot be read at ${idDir}`);
  // The identity's lock, held until the export is done: no process starts it in between.
  const release = config.acquireIdentityLock(identity.name, { dir });
  try {
    return exportLocked({ id, dir, idDir, identity, out: outAbs, passphrase, toHostKey });
  } finally {
    try { release(); } catch { /* the lock goes with the process either way */ }
  }
}

/** @private The identity.json in `dir`, as JSON, or null. */
function readIdentityJson(dir) {
  try { return JSON.parse(fs.readFileSync(path.join(dir, 'identity.json'), 'utf8')); } catch { return null; }
}

/** @private The export, under the identity's lock. */
function exportLocked({ id, dir, idDir, identity, out, passphrase, toHostKey }) {
  const fingerprint = keyFingerprint(identity.publicKey);
  const pending = config.readExportIntent(id);
  if (pending && config.exportProducedBundle(pending)) {
    // The bundle is complete (the agent lives in it): what is left is the scrub.
    scrubSource(id, identity);
    removeIntent(id);
    return { nodeId: id, name: identity.name, files: 0, out: pending.out, fingerprint, resumed: 'scrub' };
  }
  if (!identity.privateKey) throw new Error(`relocation: ${id} holds no private key on this host; there is nothing to export`);
  if (pending && typeof pending.out === 'string') removeTempBundles(pending.out);
  const startedAt = pending && Number.isFinite(pending.startedAt) ? pending.startedAt : Date.now();
  const intent = { nodeId: id, name: identity.name, out, recipient: recipientOf({ passphrase, toHostKey }), startedAt, tombstoned: true };
  // 1. THE INTENT, beside the key.
  writeIntent(id, intent);
  // 2. THE TOMBSTONE, beside the key and in the node directory: from here this host (0.14.2 included) never starts the
  // identity again, so no bundle of it can ever exist beside a live source.
  const tomb = { nodeId: id, name: identity.name, movedAt: startedAt, bundle: out, fingerprint };
  writeTombstone(id, tomb);
  // Each file with its mode (final re-review, Finding 7b), so a 0600 file stays 0600 on the target.
  const files = listFiles(dir).filter((rel) => rel !== 'identity.json')
    .map((rel) => ({ path: rel.split(path.sep).join('/'), mode: fs.statSync(path.join(dir, rel)).mode & 0o777, data: fs.readFileSync(path.join(dir, rel)).toString('base64') }));
  // The identity travels as it was loaded (from SYM_IDENTITY_DIR when set), never a stray copy in the node directory.
  files.push({ path: 'identity.json', mode: 0o600, data: Buffer.from(JSON.stringify(identity, null, 2)).toString('base64') });
  const contents = { format: FORMAT, nodeId: id, name: identity.name, publicKey: identity.publicKey, exportedAt: startedAt, files };
  // The sealing header is chosen first, so the node's signature covers it (the target host key and
  // the ephemeral key included): the bundle is the node's own statement, for that host only.
  // A host key, when given, wins over a passphrase.
  const sealing = sealParams(typeof toHostKey === 'string' && toHostKey ? { toHostKey } : { passphrase });
  const header = { format: FORMAT, nodeId: id, fingerprint, publicKey: identity.publicKey, exportedAt: startedAt, ...sealing.header };
  const signature = signBundle(header, contents, identity.privateKey);
  // The clear header is signed on its own as well, so an import checks it against the pin before it
  // uses anything the header says (the scrypt parameters).
  const headerSig = signHeader(header, identity.privateKey);
  const plain = Buffer.from(JSON.stringify({ ...contents, signature }), 'utf8');
  const bytes = Buffer.from(JSON.stringify({ ...header, headerSig, ...sealWith(plain, sealing) }), 'utf8');
  // 3. THE BUNDLE: its hash first (so a later look can tell a complete bundle at `out`), then the file, durable, then
  // `complete`.
  intent.bundleHash = sha256(bytes);
  writeIntent(id, intent);
  const tmp = `${out}.${process.pid}.tmp`;
  const bfd = fs.openSync(tmp, 'w', 0o600);
  try { fs.writeSync(bfd, bytes); fs.fsyncSync(bfd); } finally { fs.closeSync(bfd); }
  fs.renameSync(tmp, out);
  fsyncDir(path.dirname(out));
  intent.complete = true;
  writeIntent(id, intent);
  // 4. The source loses the key (every copy of it on this host), and the 0.13 path to it; then the intent goes.
  scrubSource(id, identity);
  writeTombstone(id, { ...tomb, bundleHash: intent.bundleHash });
  removeIntent(id);
  return { nodeId: id, name: identity.name, files: files.length, out, fingerprint };
}

/** @private Remove the bundles an export to `out` left half written (`<out>.<pid>.tmp`). Returns how many. */
function removeTempBundles(out) {
  const base = `${path.basename(out)}.`;
  let names = [];
  try { names = fs.readdirSync(path.dirname(out)); } catch { return 0; }
  let n = 0;
  for (const f of names) if (f.startsWith(base) && /^\d+\.tmp$/.test(f.slice(base.length))) { try { fs.unlinkSync(path.join(path.dirname(out), f)); n++; } catch { /* */ } }
  fsyncDir(path.dirname(out));
  return n;
}

/**
 * Abandon an export that began and did not finish, ONLY while it produced no complete bundle (the intent records the
 * bundle's hash before the bundle is written, and `complete` after): the tombstone and the intent go, and the node starts
 * on this host again. Once a complete bundle was produced it is refused: the bundle is the node now (a copy of it may
 * exist), so it is imported where it goes.
 * @param {{ name?: string, nodeId?: string }} o
 * @returns {{ nodeId: string, aborted: boolean, bundle: string|null, bundleRemoved: boolean, partialRemoved: number }}
 */
function abortExport({ name, nodeId } = {}) {
  const id = nodeId || (name && config.nodeIdForName(name));
  if (!id) throw new config.IdentityAbsentError(name ? `"${name}"` : 'the node');
  const intent = config.readExportIntent(id);
  const tomb = config.readTombstone(id);
  if (!intent) {
    if (tomb) throw new Error(`relocation: the export of ${id} finished${tomb.bundle ? ` (${tomb.bundle})` : ''} and it is tombstoned here: the bundle is the node now; import it where it goes`);
    return { nodeId: id, aborted: false, bundle: null, bundleRemoved: false, partialRemoved: 0 };
  }
  const dir = config.nodeDirById(id);
  if (config.lockHeldInProcess(dir)) throw new Error(`relocation: ${id} is held by a node in this process`);
  const release = config.acquireIdentityLock(intent.name || name || 'node', { dir });
  try {
    if (config.exportProducedBundle(intent) || (!intent.tombstoned && typeof intent.out === 'string' && fs.existsSync(intent.out))) {
      throw new Error(`relocation: the export of ${id} produced a complete bundle (${intent.out}${intent.bundleHash ? `, sha256 ${intent.bundleHash}` : ''}): ` +
        'the bundle is the node now, and a copy of it may exist, so it is not abandoned. Import it where it goes, then run the same export here again to finish removing the key.');
    }
    const partialRemoved = typeof intent.out === 'string' ? removeTempBundles(intent.out) : 0;
    // The tombstones first, while the intent is still there (a crash in between leaves the export pending), then the intent.
    for (const d of new Set([config.identityDirById(id), dir])) {
      try { fs.unlinkSync(path.join(d, config.TOMBSTONE)); fsyncDir(d); } catch { /* */ }
    }
    removeIntent(id);
    return { nodeId: id, aborted: true, bundle: intent.out || null, bundleRemoved: false, partialRemoved };
  } finally {
    try { release(); } catch { /* */ }
  }
}

/** @private fsync a directory (a rename in it is durable after this); best effort where unsupported. */
function fsyncDir(dir) {
  let fd;
  try { fd = fs.openSync(dir, 'r'); fs.fsyncSync(fd); } catch { /* not supported here (Windows) */ } finally { if (fd !== undefined) try { fs.closeSync(fd); } catch { /* */ } }
}

/**
 * @private After a complete bundle: every copy of the key on this host loses its private key (identity.json in the
 * identity directory, a stray one in the node directory, a 0.13 directory or a husk set aside, a 0.13 directory left in
 * place; the 0.13 E2E keypair beside any of them), each rewritten atomically, and the 0.13-compatible `nodes/<name>`
 * links removed.
 */
function scrubSource(id, identity) {
  const movedAt = Date.now();
  for (const d of new Set([config.identityDirById(id), ...config.keyHoldersOf(id)])) {
    const j = readIdentityJson(d);
    if (j && j.nodeId === id && j.privateKey) config.writeFileAtomic0600(path.join(d, 'identity.json'), JSON.stringify({ ...j, privateKey: null, movedAt }, null, 2));
    const e2eFile = path.join(d, 'e2e-keypair.json');
    let e2e = null;
    try { e2e = JSON.parse(fs.readFileSync(e2eFile, 'utf8')); } catch { /* none */ }
    if (e2e && typeof e2e === 'object' && e2e.privateKey) config.writeFileAtomic0600(e2eFile, JSON.stringify({ ...e2e, privateKey: null, movedAt }, null, 2));
  }
  for (const root of [config.NODES_DIR, process.env.SYM_IDENTITY_DIR].filter(Boolean)) {
    let names = [];
    try { names = fs.readdirSync(root); } catch { continue; }
    for (const n of names) {
      const p = path.join(root, n);
      if (config.compatLinkNodeId(p) === id) { try { fs.unlinkSync(p); } catch { /* */ } }
    }
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
  const id = identity.nodeId;
  const dest = config.nodeDirById(id);
  const idDest = config.identityDirById(id);
  const split = idDest !== dest;
  const label = name || identity.name;
  config.validateName(label);
  for (const f of plain.files) {
    const rel = String(f.path);
    if (rel.includes('..') || path.isAbsolute(rel) || rel.includes('\\') || !rel) throw new Error(`relocation: refusing a bundle path outside the node: ${rel}`);
  }
  config.clearLeftovers();
  // "Already here" is decided from the committed identity, never from a directory that merely exists. The identity of
  // THIS bundle committed by an import that was interrupted before it finished is finished; any other is refused.
  const bundleTag = sha256(String(plain.signature)).slice(0, 32);
  const mark = (dir) => { try { return JSON.parse(fs.readFileSync(path.join(dir, config.COMMIT_MARK), 'utf8')); } catch { return null; } };
  const ours = (dir) => { const m = mark(dir); return Boolean(m && m.nodeId === id && m.bundle === bundleTag); };
  const committed = config.readCommitted(id);
  if (committed.state === 'unreadable') throw new Error(`relocation: ${id} already has an identity on this host that cannot be read (${committed.file}); nothing was imported`);
  const resuming = committed.state === 'ok' && !tomb && ours(idDest);
  if (committed.state === 'ok' && !tomb && !resuming) throw new Error(`relocation: ${id} already lives on this host`);
  const existing = config.nodeIdForName(label);
  if (existing && existing !== id) throw new Error(`relocation: the name "${label}" already indexes another node here; import with another name`);
  // STAGED: each directory is written in a staging directory of its own beside its destination and installed by one
  // rename, the IDENTITY FIRST (it is the commit: the agent exists from then on) and the node directory after, each
  // carrying the import's commit record. Directories are 0700, key files 0600, and with SYM_IDENTITY_DIR the private
  // key goes ONLY into the identity directory (final re-review, Finding 7b).
  const keyFiles = new Set(config.PRIVATE_KEY_FILES);
  const write = (root, f) => {
    const parts = String(f.path).split('/');
    let d = root;
    for (const part of parts.slice(0, -1)) {
      d = path.join(d, part);
      if (!fs.existsSync(d)) { fs.mkdirSync(d, { mode: 0o700 }); fs.chmodSync(d, 0o700); }
    }
    const mode = keyFiles.has(parts[parts.length - 1]) ? 0o600 : (Number.isSafeInteger(f.mode) ? (f.mode & 0o777) : 0o644);
    config.writeNewFileSynced(path.join(root, ...parts), Buffer.from(f.data, 'base64'), mode);
  };
  // What a node directory holds that is this host's own state (a lock, a tombstone, an export intent, the commit
  // record) is never taken from a bundle.
  const hostState = (rel) => SKIP.has(rel) || rel.startsWith('lock.pid.');
  const install = (target, build) => {
    const staging = config.makeStaging(path.dirname(target), id, 'import');
    try {
      build(staging);
      config.writeNewFileSynced(path.join(staging, config.COMMIT_MARK), JSON.stringify({ nodeId: id, from: 'import', bundle: bundleTag, at: Date.now() }) + '\n', 0o600);
      fsyncDir(staging);
      config.clearForInstall(target, id); // what is there (a node coming back, tombstoned; a directory a start made meanwhile) is kept aside
      fs.renameSync(staging, target);
      fsyncDir(path.dirname(target));
    } finally {
      fs.rmSync(staging, { recursive: true, force: true });
    }
  };
  const storeFiles = (staging) => { for (const f of plain.files) if (!(split && String(f.path) === 'identity.json') && !hostState(String(f.path))) write(staging, f); };
  if (!resuming) install(idDest, split ? (staging) => write(staging, idFile) : storeFiles); // THE COMMIT
  if (split && !ours(dest)) install(dest, storeFiles);
  const claimed = config.claimName(label, id, label);
  if (claimed && claimed !== id) throw new Error(`relocation: the name "${label}" was claimed for another node meanwhile; ${id} is installed here, unnamed: start it by its nodeId, or rename`);
  config.ensureCompatLinks(label, id);
  try { fs.appendFileSync(path.join(config.SYM_DIR, CONSUMED_FILE), JSON.stringify({ nodeId: id, signature: plain.signature, exportedAt: plain.exportedAt, importedAt: Date.now() }) + '\n', { mode: 0o600 }); }
  catch { /* best effort: the tombstone check still refuses an older bundle */ }
  config.loadIdentity({ nodeId: id, name: label, create: false });
  return { nodeId: id, name: label, files: plain.files.length, pinnedBy, ...(resuming ? { resumed: true } : {}) };
}

module.exports = { exportNode, abortExport, importNode, hostKey, FORMAT };
