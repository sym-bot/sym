'use strict';

/**
 * @module @sym-bot/sym/relocation
 * @description Moving a node to another host (sym 0.14, design D9.2). §3.1.3: "The private key MUST
 * NOT leave the node" — so a node is MOVED, never copied:
 *
 *   - `exportNode` writes a TOMBSTONE at the source FIRST, then the bundle. The source refuses to
 *     start that identity from then on (config.js IdentityTombstonedError), so no copy remains live:
 *     the relay's 4004 replacement cannot produce two live copies, because the source is tombstoned
 *     before the bundle exists.
 *   - The bundle holds the node's directory — its identity, store, key registry, grants and learned
 *     state — encrypted under an operator passphrase (scrypt → AES-256-GCM) or to a target host's
 *     X25519 key (ephemeral X25519 + HKDF-SHA256 → AES-256-GCM).
 *   - `importNode` verifies the bundle against an INDEPENDENTLY PINNED (nodeId, key): one the
 *     operator gives (`expect`: the key or its sha256 fingerprint, e.g. from a validator's preserve
 *     act), or, absent that, a proven or pinned binding this host's own nodes already hold for that
 *     nodeId. It never relies on anything the bundle says about itself: a bundle whose identity was
 *     re-keyed (signed by another key) is refused.
 *
 * @copyright 2026 SYM.BOT. Apache 2.0 License.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const config = require('./config');
const { keyFingerprint, isIdentityKey } = require('./roster-keys');

const FORMAT = 'sym-node-bundle-v1';
const SKIP = new Set(['lock.pid', config.TOMBSTONE, 'interior.sock']);
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const HOST_KEY_FILE = 'host-key.json';

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

function seal(plain, { passphrase, toHostKey }) {
  const nonce = crypto.randomBytes(12);
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
  const c = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const body = Buffer.concat([c.update(plain), c.final()]);
  return { ...header, nonce: nonce.toString('base64url'), ciphertext: Buffer.concat([body, c.getAuthTag()]).toString('base64url') };
}

function unseal(bundle, { passphrase, hostPrivateKey }) {
  let key;
  if (bundle.kdf === 'scrypt') {
    if (typeof passphrase !== 'string') throw new Error('relocation: this bundle needs its passphrase');
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
function exportNode({ name, nodeId, out, passphrase, toHostKey } = {}) {
  if (!out) throw new Error('relocation: out (the bundle file) is required');
  const id = nodeId || (name && config.nodeIdForName(name));
  if (!id) throw new config.IdentityAbsentError(name ? `"${name}"` : 'the node');
  const dir = config.nodeDirById(id);
  if (config.readTombstone(id)) throw new Error(`relocation: ${id} is already tombstoned here (it was exported)`);
  const identity = config.loadIdentity({ nodeId: id, name, create: false });
  const lock = config.readLockFile(path.join(dir, 'lock.pid'));
  if (lock && lock.pid !== process.pid && config.lockIsHeldByLiveProcess(lock)) {
    throw new Error(`relocation: ${identity.name} is running (PID ${lock.pid}); stop it before moving it`);
  }
  // Validate the sealing input before the tombstone: a refused export must leave the node startable.
  seal(Buffer.alloc(0), { passphrase, toHostKey });
  // THE TOMBSTONE FIRST. From here this host refuses to start the identity, before any bundle exists.
  const tomb = { nodeId: id, name: identity.name, movedAt: Date.now(), bundle: path.basename(out), fingerprint: keyFingerprint(identity.publicKey) };
  const tombPath = path.join(dir, config.TOMBSTONE);
  const fd = fs.openSync(tombPath, 'wx');
  try { fs.writeSync(fd, JSON.stringify(tomb, null, 2)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  const files = listFiles(dir).map((rel) => ({ path: rel.split(path.sep).join('/'), data: fs.readFileSync(path.join(dir, rel)).toString('base64') }));
  // identity.json lives elsewhere when SYM_IDENTITY_DIR is set: it travels in the bundle all the same.
  if (!files.some((f) => f.path === 'identity.json')) {
    files.push({ path: 'identity.json', data: Buffer.from(JSON.stringify(identity, null, 2)).toString('base64') });
  }
  const plain = Buffer.from(JSON.stringify({ format: FORMAT, nodeId: id, name: identity.name, publicKey: identity.publicKey, exportedAt: tomb.movedAt, files }), 'utf8');
  const bundle = { format: FORMAT, nodeId: id, fingerprint: tomb.fingerprint, ...seal(plain, { passphrase, toHostKey }) };
  const tmp = `${out}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(bundle), { mode: 0o600 });
  fs.renameSync(tmp, out);
  return { nodeId: id, name: identity.name, files: files.length, out, fingerprint: tomb.fingerprint };
}

/** A proven or pinned key this host's nodes hold for `nodeId` (the target host's roster entry), or null. */
function hostPinFor(nodeId) {
  const root = path.join(config.NODES_DIR, 'by-id');
  let dirs = [];
  try { dirs = fs.readdirSync(root); } catch { return null; }
  for (const d of dirs) {
    let text;
    try { text = fs.readFileSync(path.join(root, d, 'roster-keys', 'roster-keys.jsonl'), 'utf8'); } catch { continue; }
    let found = null;
    for (const line of text.split('\n')) {
      let r;
      try { r = JSON.parse(line); } catch { continue; }
      if (r && r.nodeId === nodeId && r.expired === true) found = null; // the binding expired (design D3)
      else if (r && r.nodeId === nodeId && (r.source === 'proven' || r.source === 'pinned') && isIdentityKey(r.key)) found = r.key;
    }
    if (found) return found;
  }
  return null;
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
  const plain = JSON.parse(unseal(bundle, { passphrase, hostPrivateKey }).toString('utf8'));
  const idFile = (plain.files || []).find((f) => f.path === 'identity.json');
  if (!idFile) throw new Error('relocation: the bundle carries no identity');
  const identity = JSON.parse(Buffer.from(idFile.data, 'base64').toString('utf8'));
  if (!identity || typeof identity.nodeId !== 'string' || !isIdentityKey(identity.publicKey) || typeof identity.privateKey !== 'string') {
    throw new Error('relocation: the bundle\'s identity is malformed');
  }
  if (publicOf(identity.privateKey) !== identity.publicKey) throw new Error('relocation: the bundle\'s private key does not match its public key');
  // THE INDEPENDENT PIN: never what the bundle says about itself.
  let pinned = null;
  let pinnedBy = null;
  if (expect && expect.nodeId) {
    if (expect.nodeId !== identity.nodeId) throw new Error(`relocation: the bundle is ${identity.nodeId}, not the expected ${expect.nodeId}`);
    if (expect.key) { pinned = expect.key; pinnedBy = 'operator key'; }
    else if (expect.fingerprint) { pinned = { fingerprint: expect.fingerprint }; pinnedBy = 'operator fingerprint'; }
  }
  if (!pinned) {
    const k = hostPinFor(identity.nodeId);
    if (k) { pinned = k; pinnedBy = 'this host\'s key registry'; }
  }
  if (!pinned) throw new Error(`relocation: refusing ${identity.nodeId}: no independently pinned key (give --expect-key or --expect-fingerprint, from the validator's preserve act or the source host)`);
  const ok = typeof pinned === 'string' ? pinned === identity.publicKey : keyFingerprint(identity.publicKey) === pinned.fingerprint;
  if (!ok) throw new Error(`relocation: refusing ${identity.nodeId}: the bundle's key is not the pinned one (${pinnedBy}) — a re-keyed bundle`);
  const dest = config.nodeDirById(identity.nodeId);
  if (fs.existsSync(dest)) {
    if (!config.readTombstone(identity.nodeId)) throw new Error(`relocation: ${identity.nodeId} already lives on this host`);
    // It was moved away from here before: the tombstoned copy is archived, and the node comes back.
    fs.renameSync(dest, `${dest}.moved-${Date.now()}`);
  }
  for (const f of plain.files) {
    const rel = String(f.path);
    if (rel.includes('..') || path.isAbsolute(rel)) throw new Error(`relocation: refusing a bundle path outside the node: ${rel}`);
    const p = path.join(dest, ...rel.split('/'));
    config.ensureDir(path.dirname(p));
    fs.writeFileSync(p, Buffer.from(f.data, 'base64'), rel === 'identity.json' ? { mode: 0o600 } : undefined);
  }
  const idDirExt = config.identityDirById(identity.nodeId);
  if (idDirExt !== dest) { config.ensureDir(idDirExt); fs.writeFileSync(path.join(idDirExt, 'identity.json'), Buffer.from(idFile.data, 'base64'), { mode: 0o600 }); }
  const label = name || identity.name;
  const existing = config.nodeIdForName(label);
  if (existing && existing !== identity.nodeId) throw new Error(`relocation: the name "${label}" already indexes another node here; import with another name`);
  // indexName is internal to config; loadIdentity by nodeId + name writes the index.
  config.loadIdentity({ nodeId: identity.nodeId, name: label, create: false });
  return { nodeId: identity.nodeId, name: label, files: plain.files.length, pinnedBy };
}

module.exports = { exportNode, importNode, hostKey, FORMAT };
