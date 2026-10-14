'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * 0.14.3, design v2 of the identity and on-disk state (lib/config.js, lib/relocation.js). The second candidate
 * (9f6847c) copied a 0.13 agent into a staging directory and committed the copy; an independent re-review reproduced
 * what copying does: ENOSPC where a store does not fit twice, seconds per start, private keys left in husks and
 * partial copies at 0644, a mount point copied onto the state volume, a relative link set aside dangling, and an export
 * whose bundle came before its tombstone (two importable bundles: two live copies of one key).
 *
 * Design v2: one source of truth (an agent exists exactly when its identity is committed; the name index and the
 * compat links are caches, re-derived from the committed identities); a 0.13 directory is MOVED in by one rename, or
 * linked to when it is a link, a mount point or on another volume; only the small identity files ever cross volumes;
 * the export stops the source before any bundle can exist. Each test below is a scenario of the re-review (rr-eN) or of
 * the first review (R1-eN) that fails on 9f6847c or on 0.14.2 (fe285a3), as its name says.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const cfg = require('../lib/config');
const relocation = require('../lib/relocation');

const { NODES_DIR, IdentityHaltError } = cfg;
const posix = process.platform !== 'win32';
const modeTest = posix ? it : it.skip;
const LIB = path.resolve(__dirname, '../lib');

let seq = 0;
const uniq = (b) => `${b}-${process.pid}-${++seq}-${Math.random().toString(36).slice(2, 6)}`;
const read = (p) => fs.readFileSync(p, 'utf8');
const exists = (p) => fs.existsSync(p);
const modeOf = (p) => fs.statSync(p).mode & 0o777;
const isLink = (p) => { try { return fs.lstatSync(p).isSymbolicLink(); } catch { return false; } };
const indexFile = (name) => path.join(NODES_DIR, 'by-name', `${encodeURIComponent(name)}.json`);

function makeIdentity(name, extra = {}) {
  const kp = crypto.generateKeyPairSync('ed25519');
  return {
    nodeId: cfg.uuidv7(), name, hostname: 'host.local', createdAt: 1,
    publicKey: kp.publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('base64url'),
    privateKey: kp.privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(16).toString('base64url'),
    ...extra,
  };
}

function put(file, text, mode = 0o644) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
  fs.chmodSync(file, mode);
}

/** A 0.13 node, as 0.13 wrote it: identity.json and the E2E keypair at the umask default, a small store. */
function legacyNode(name, { where = path.join(NODES_DIR, name), identity = makeIdentity(name), files = 6 } = {}) {
  put(path.join(where, 'identity.json'), JSON.stringify(identity, null, 2));
  put(path.join(where, 'e2e-keypair.json'), JSON.stringify({ publicKey: 'cHVi', privateKey: `e2e-${identity.nodeId}` }));
  for (let i = 0; i < files; i++) put(path.join(where, 'cmbs', `c${i}.json`), JSON.stringify({ i, pad: 'x'.repeat(300) }));
  return identity;
}

/** What 0.14.2 left for a 0.13 agent it migrated: the directory renamed in (modes as 0.13 left them), the index, the link. */
function migratedBy0142(name) {
  const id = makeIdentity(name);
  const dir = path.join(NODES_DIR, 'by-id', id.nodeId);
  legacyNode(name, { where: dir, identity: id });
  fs.chmodSync(dir, 0o755);
  put(indexFile(name), JSON.stringify({ name, nodeId: id.nodeId, at: 1 }));
  fs.symlinkSync(path.join('by-id', id.nodeId), path.join(NODES_DIR, name), 'dir');
  return id;
}

/** Every file under `roots` whose content holds `secret` (bundles left out), as paths. */
function holding(secret, roots = [cfg.SYM_DIR, process.env.SYM_IDENTITY_DIR].filter(Boolean), skip = () => false) {
  const out = [];
  const walk = (d) => {
    let es = [];
    try { es = fs.readdirSync(d); } catch { return; }
    for (const e of es) {
      const p = path.join(d, e);
      const st = fs.lstatSync(p);
      if (st.isDirectory()) walk(p);
      else if (st.isFile() && !skip(p) && fs.readFileSync(p, 'utf8').includes(secret)) out.push(p);
    }
  };
  for (const r of roots) walk(r);
  return out;
}

/** The regular files under `dir` (links not followed) as distinct inodes, with their bytes: a copy makes new ones. */
function inodes(dir) {
  const out = new Map();
  const walk = (d) => {
    let es = [];
    try { es = fs.readdirSync(d); } catch { return; }
    for (const e of es) {
      const p = path.join(d, e);
      const st = fs.lstatSync(p);
      if (st.isDirectory()) walk(p);
      else if (st.isFile()) out.set(`${st.dev}:${st.ino}`, st.size);
    }
  };
  walk(dir);
  return out;
}

function withIdentityDir(fn) {
  const prev = process.env.SYM_IDENTITY_DIR;
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-idroot-'));
  process.env.SYM_IDENTITY_DIR = root;
  try { return fn(root); } finally {
    if (prev === undefined) delete process.env.SYM_IDENTITY_DIR; else process.env.SYM_IDENTITY_DIR = prev;
    fs.rmSync(root, { recursive: true, force: true });
  }
}

/** Replace several fs functions for the duration of `body`. */
function patchMany(wraps, body) {
  const originals = {};
  for (const [k, w] of Object.entries(wraps)) { originals[k] = fs[k]; fs[k] = w(originals[k]); }
  try { return body(); } finally { for (const k of Object.keys(originals)) fs[k] = originals[k]; }
}

/** Run `code` in a child process against this state root, SIGKILLed at the first fs.<fn> call whose arguments match `re`. */
function killedAt(fn, re, code, when = 'before') {
  const script = `
    const fs = require('fs');
    const orig = fs.${fn}; const re = new RegExp(${JSON.stringify(re)});
    fs.${fn} = function (...a) {
      const hit = re.test(a.map(String).join(' -> '));
      if (hit && ${JSON.stringify(when)} === 'before') process.kill(process.pid, 'SIGKILL');
      const r = orig.apply(this, a);
      if (hit && ${JSON.stringify(when)} === 'after') process.kill(process.pid, 'SIGKILL');
      return r;
    };
    const cfg = require(${JSON.stringify(path.join(LIB, 'config.js'))});
    const relocation = require(${JSON.stringify(path.join(LIB, 'relocation.js'))});
    ${code}`;
  const r = spawnSync(process.execPath, ['-e', script], { env: process.env, encoding: 'utf8' });
  return { killed: r.signal === 'SIGKILL', stderr: r.stderr };
}

const hostKey = () => relocation.hostKey().publicKey;
const bundlePath = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sym-bundle-')), 'node.bundle');

describe('design v2: a 0.13 agent is moved, never copied (rr-e6, rr-e24, rr-e23: ENOSPC, seconds per start)', () => {
  it('the first start makes no copy of the store: every file is the inode it was (9f6847c copied each one)', () => {
    const name = uniq('nocopy');
    const id = legacyNode(name, { files: 40 });
    const before = inodes(path.join(NODES_DIR, name));
    assert.strictEqual(cfg.loadIdentity({ name }).privateKey, id.privateKey);
    const after = inodes(cfg.nodeDirById(id.nodeId));
    for (const k of before.keys()) assert.ok(after.has(k), `file ${k} is still the same inode, in by-id`);
    assert.ok(!exists(path.join(NODES_DIR, cfg.LEGACY_ASIDE, name)), 'nothing is set aside: there is no second copy');
    const extra = [...after.keys()].filter((k) => !before.has(k)).reduce((n, k) => n + after.get(k), 0);
    assert.ok(extra < 4096, `no more than a few bytes are new (${extra})`);
  });

  it('a 5,000-file store starts in well under a second (9f6847c: ~21 s for the copy and its byte-for-byte check)', () => {
    const name = uniq('fast');
    const id = makeIdentity(name);
    put(path.join(NODES_DIR, name, 'identity.json'), JSON.stringify(id));
    const cmbs = path.join(NODES_DIR, name, 'cmbs');
    fs.mkdirSync(cmbs, { recursive: true });
    for (let i = 0; i < 5000; i++) fs.writeFileSync(path.join(cmbs, `c${i}.json`), '{"x":1}');
    const t0 = Date.now();
    assert.strictEqual(cfg.loadIdentity({ name }).nodeId, id.nodeId);
    const ms = Date.now() - t0;
    assert.ok(ms < 3000, `the first start took ${ms} ms`);
    assert.strictEqual(fs.readdirSync(path.join(cfg.nodeDirById(id.nodeId), 'cmbs')).length, 5000);
  });
});

describe('design v2: a 0.13 directory behind a link, on a mount point, or holding a relative link outward is linked to, not copied', () => {
  it('rr-e7 / R1-e4: nodes/<name> a link to the store elsewhere: by-id/<id> is an absolute link to it; the store stays there (0.14.2 minted; 9f6847c copied it onto the state volume)', () => {
    const name = uniq('linked');
    const far = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sym-far-')), name);
    const id = legacyNode(name, { where: far });
    const before = inodes(far);
    fs.symlinkSync(far, path.join(NODES_DIR, name), 'dir');
    for (const o of [{ name }, { name, nodeId: id.nodeId, create: false }]) assert.strictEqual(cfg.loadIdentity(o).privateKey, id.privateKey);
    const dir = cfg.nodeDirById(id.nodeId);
    assert.ok(isLink(dir) && path.isAbsolute(fs.readlinkSync(dir)) && fs.realpathSync(dir) === fs.realpathSync(far), 'by-id/<id> leads to the store where it is');
    assert.deepStrictEqual([...inodes(far).keys()].sort(), [...before.keys()].sort(), 'the same files, none copied');
    assert.ok(!exists(path.join(NODES_DIR, cfg.LEGACY_ASIDE, name)), 'nothing set aside: no second copy');
    assert.ok(isLink(path.join(NODES_DIR, name)) && cfg.compatLinkNodeId(path.join(NODES_DIR, name)) === id.nodeId, 'nodes/<name> is the compat link');
  });

  it('rr-e22: nodes/<name> a RELATIVE link to the 0.13 directory: nothing is left dangling, and after an export no file holds the key (9f6847c set the relative link aside dangling and left the key 0644)', () => {
    const name = uniq('rellink');
    const base = fs.mkdtempSync(path.join(cfg.SYM_DIR, 'far-'));
    const id = legacyNode(name, { where: path.join(base, name) });
    fs.symlinkSync(path.relative(NODES_DIR, path.join(base, name)), path.join(NODES_DIR, name), 'dir');
    assert.strictEqual(cfg.loadIdentity({ name }).privateKey, id.privateKey);
    const dangling = [];
    const walk = (d) => { for (const e of fs.readdirSync(d)) { const p = path.join(d, e); const st = fs.lstatSync(p); if (st.isSymbolicLink() && !exists(p)) dangling.push(p); else if (st.isDirectory()) walk(p); } };
    walk(NODES_DIR);
    assert.deepStrictEqual(dangling, [], 'no link that leads nowhere');
    if (posix) assert.strictEqual(modeOf(path.join(base, name, 'identity.json')), 0o600, 'the key file where it is, narrowed');
    relocation.exportNode({ name, out: bundlePath(), toHostKey: hostKey() });
    assert.deepStrictEqual(holding(id.privateKey, [base, NODES_DIR]), [], 'no copy of the private key is left');
    assert.deepStrictEqual(holding(`e2e-${id.nodeId}`, [base, NODES_DIR]), [], 'nor of the 0.13 E2E key');
  });

  it('rr-e14: nodes/<name> a mount point (another device than nodes/): linked to where it is, never copied onto the state volume (9f6847c copied it)', () => {
    const name = uniq('mount');
    const id = legacyNode(name);
    const at = path.join(NODES_DIR, name);
    const real = fs.statSync;
    const mounted = (p, st) => { if (st && String(p) === at) { return Object.assign(Object.create(Object.getPrototypeOf(st)), st, { dev: st.dev + 1000 }); } return st; };
    const before = inodes(at);
    patchMany({
      statSync: () => function (p, ...a) { return mounted(p, real.call(fs, p, ...a)); },
    }, () => assert.strictEqual(cfg.loadIdentity({ name }).privateKey, id.privateKey));
    const dir = cfg.nodeDirById(id.nodeId);
    assert.ok(isLink(dir) && fs.realpathSync(dir) === fs.realpathSync(at), 'by-id/<id> links to the mount point');
    assert.ok(!isLink(at) && exists(path.join(at, 'identity.json')), 'the mounted directory is where it was');
    assert.deepStrictEqual([...inodes(at).keys()].sort(), [...before.keys()].sort(), 'no file copied');
    assert.strictEqual(cfg.loadIdentity({ name, nodeId: id.nodeId, create: false }).privateKey, id.privateKey, 'and the next start is the same agent');
  });
});

describe('design v2: husks', () => {
  it('rr-e25: a husk 0.14.2 ran beside a live 0.13 process (both stores grew): the agent starts, the husk is kept aside with what differs (9f6847c halted; 0.14.2 overwrote the key)', () => {
    const name = uniq('diverged');
    const id = legacyNode(name);
    put(path.join(NODES_DIR, name, 'attestations', 'attestations.jsonl'), '{"seq":1,"by":"0.13"}\n');
    const husk = cfg.nodeDirById(id.nodeId);
    put(path.join(husk, 'attestations', 'attestations.jsonl'), '{"seq":1,"by":"0.14.2"}\n');
    put(path.join(husk, 'cmbs', 'cmb-new-in-0142.json'), '{"x":1}');
    const warned = [];
    const onWarning = (w) => { if (w.code === 'SYM_HUSK_SET_ASIDE') warned.push(w.message); };
    process.on('warning', onWarning);
    try {
      for (const o of [{ name }, { name, nodeId: id.nodeId, create: false }]) assert.strictEqual(cfg.loadIdentity(o).privateKey, id.privateKey);
    } finally { process.removeListener('warning', onWarning); }
    assert.strictEqual(read(path.join(husk, 'attestations', 'attestations.jsonl')), '{"seq":1,"by":"0.13"}\n', 'the node is its 0.13 directory');
    const aside = fs.readdirSync(path.join(NODES_DIR, 'by-id')).filter((n) => n.startsWith(`.${id.nodeId}.husk-`));
    assert.strictEqual(aside.length, 1);
    const kept = path.join(NODES_DIR, 'by-id', aside[0]);
    assert.strictEqual(read(path.join(kept, 'attestations', 'attestations.jsonl')), '{"seq":1,"by":"0.14.2"}\n', 'what differs is kept');
    assert.ok(exists(path.join(kept, 'cmbs', 'cmb-new-in-0142.json')));
    if (posix) assert.strictEqual(modeOf(kept), 0o700, 'the aside narrowed');
  });

  it('rr-e5: 0.14.2 crashed between moving nodes/<name> and SYM_IDENTITY_DIR/<name> (a stray identity.json and the E2E key at 0644 in the node dir): after the start and an export, no file on the host holds either key (9f6847c left both in a husk)', () => {
    withIdentityDir((idRoot) => {
      const name = uniq('e5');
      const id = makeIdentity(name);
      legacyNode(name, { identity: id, files: 4 });
      put(path.join(idRoot, name, 'identity.json'), JSON.stringify(id, null, 2));
      fs.mkdirSync(path.join(NODES_DIR, 'by-id'), { recursive: true });
      fs.renameSync(path.join(NODES_DIR, name), cfg.nodeDirById(id.nodeId)); // 0.14.2's first rename, then the crash
      assert.strictEqual(cfg.loadIdentity({ name }).privateKey, id.privateKey);
      assert.ok(!exists(path.join(cfg.nodeDirById(id.nodeId), 'identity.json')), 'the stray copy of the key in the node directory is gone (the key is in SYM_IDENTITY_DIR)');
      relocation.exportNode({ name, out: bundlePath(), toHostKey: hostKey() });
      assert.deepStrictEqual(holding(id.privateKey), [], 'no file holds the private key');
      assert.deepStrictEqual(holding(`e2e-${id.nodeId}`), [], 'nor the 0.13 E2E private key');
    });
  });
});

describe('design v2: leftovers that hold a key are cleared on every load (rr-e11, rr-e12)', () => {
  it('a dead start\'s staging holding a private key is removed by any later load, and an export leaves no copy (9f6847c cleared it only while migrating)', () => {
    const name = uniq('leftover');
    const agent = cfg.loadIdentity({ name });
    const ghost = makeIdentity(name);
    const dead = path.join(NODES_DIR, 'by-id', `.${agent.nodeId}.partial-2147483646-0badc0de`);
    const deadMint = path.join(NODES_DIR, 'by-id', `.${ghost.nodeId}.stage-2147483645-0badc0de`);
    put(path.join(dead, 'identity.json'), JSON.stringify(agent), 0o644);
    put(path.join(deadMint, 'identity.json'), JSON.stringify(ghost), 0o644);
    const aside = path.join(NODES_DIR, cfg.LEGACY_ASIDE, uniq('aside'));
    put(path.join(aside, 'identity.json'), JSON.stringify(makeIdentity('x')), 0o644);
    cfg.loadIdentity({ name }); // a later start of the agent, already migrated
    assert.ok(!exists(dead) && !exists(deadMint), 'cleared');
    if (posix) assert.strictEqual(modeOf(path.join(aside, 'identity.json')), 0o600, 'a key set aside by a start that was killed before it narrowed it, narrowed now');
    relocation.exportNode({ name, out: bundlePath(), toHostKey: hostKey() });
    assert.deepStrictEqual(holding(agent.privateKey), []);
  });

  it('rr-e19: the temp files a killed lock holder left in the node directory are cleared on load', () => {
    const name = uniq('locktmp');
    const id = cfg.loadIdentity({ name });
    const dir = cfg.nodeDirById(id.nodeId);
    put(path.join(dir, '.lock.pid.2147483646-deadbeef.tmp'), '2147483646\n');
    put(path.join(dir, '.lock.pid.break-0123456789abcdef.2147483646-deadbeef.tmp'), '2147483646\n');
    cfg.loadIdentity({ name });
    assert.deepStrictEqual(fs.readdirSync(dir).filter((n) => n.startsWith('.lock')), []);
  });
});

describe('design v2: export stops the source before any bundle exists (rr-e13, rr-e13b, rr-e18, rr-e20)', () => {
  it('killed right after its bundle is in place: the source refuses, and a retry to ANOTHER out writes no second bundle (9f6847c wrote it: two importable bundles)', () => {
    const name = uniq('two-bundles');
    const id = cfg.loadIdentity({ name });
    const b1 = bundlePath(); const b2 = bundlePath();
    const k = killedAt('renameSync', `${b1.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\.\\d+\\.tmp -> `, `relocation.exportNode({ name: ${JSON.stringify(name)}, out: ${JSON.stringify(b1)}, toHostKey: ${JSON.stringify(hostKey())} });`, 'after');
    assert.ok(k.killed, `killed after the bundle rename (${k.stderr.slice(0, 200)})`);
    assert.ok(exists(b1), 'the bundle is complete');
    assert.throws(() => cfg.loadIdentity({ name }), (e) => e.code === 'EIDENTITYTOMBSTONED', 'the source does not start: the agent is in the bundle');
    const again = relocation.exportNode({ name, out: b2, toHostKey: hostKey() });
    assert.strictEqual(again.resumed, 'scrub');
    assert.ok(!exists(b2), 'no second bundle');
    assert.strictEqual(JSON.parse(read(path.join(cfg.identityDirById(id.nodeId), 'identity.json'))).privateKey, null, 'the source lost the key');
  });

  it('killed after the tombstone and before the bundle: refused (pending), another out refused while a bundle may exist, the same out finishes', () => {
    const name = uniq('pending');
    cfg.loadIdentity({ name });
    const b1 = bundlePath();
    const k = killedAt('openSync', `${path.basename(b1)}\\.\\d+\\.tmp`, `relocation.exportNode({ name: ${JSON.stringify(name)}, out: ${JSON.stringify(b1)}, toHostKey: ${JSON.stringify(hostKey())} });`);
    assert.ok(k.killed);
    assert.ok(!exists(b1));
    assert.throws(() => cfg.loadIdentity({ name }), (e) => e.code === 'EIDENTITYEXPORTING');
    assert.throws(() => relocation.exportNode({ name, out: bundlePath(), toHostKey: hostKey() }), /may have written a complete bundle/);
    assert.ok(relocation.exportNode({ name, out: b1, toHostKey: hostKey() }).nodeId);
    assert.ok(exists(b1));
  });

  it('a resume must use the same recipient', () => {
    const name = uniq('recipient');
    cfg.loadIdentity({ name });
    const b1 = bundlePath();
    const k = killedAt('openSync', `${path.basename(b1)}\\.\\d+\\.tmp`, `relocation.exportNode({ name: ${JSON.stringify(name)}, out: ${JSON.stringify(b1)}, toHostKey: ${JSON.stringify(hostKey())} });`);
    assert.ok(k.killed);
    const other = crypto.generateKeyPairSync('x25519').publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64url');
    assert.throws(() => relocation.exportNode({ name, out: b1, toHostKey: other }), /sealed to the host key/);
  });

  it('rr-e18: with SYM_IDENTITY_DIR the tombstone is also in the node directory (where 0.14.2 reads it), written before the bundle (9f6847c: only beside the key, so a 0.14.2 rollback started the node)', () => {
    withIdentityDir(() => {
      const name = uniq('rollback');
      const id = cfg.loadIdentity({ name });
      const b1 = bundlePath();
      const k = killedAt('openSync', `${path.basename(b1)}\\.\\d+\\.tmp`, `relocation.exportNode({ name: ${JSON.stringify(name)}, out: ${JSON.stringify(b1)}, toHostKey: ${JSON.stringify(hostKey())} });`);
      assert.ok(k.killed, 'killed before the bundle was written');
      assert.ok(exists(path.join(cfg.nodeDirById(id.nodeId), cfg.TOMBSTONE)), 'the tombstone 0.14.2 reads is there before any bundle');
      assert.ok(exists(path.join(cfg.identityDirById(id.nodeId), cfg.TOMBSTONE)));
    });
  });

  it('rr-e20: a node stopped in this process and exported is refused when it starts again (9f6847c took the lock again and ran the exported key)', async () => {
    const { SymNode } = require('../lib/node');
    const name = uniq('restart');
    const n = new SymNode({ name, silent: true });
    await n.stop();
    relocation.exportNode({ name, out: bundlePath(), toHostKey: hostKey() });
    assert.throws(() => n._takeOwnership(), (e) => e.code === 'EIDENTITYTOMBSTONED');
    assert.ok(!n._releaseIdentityLock, 'and it holds no lock');
  });

  it('abortExport is on the CLI (sym node abort-export), and refuses once a complete bundle exists', () => {
    const name = uniq('cli-abort');
    const id = cfg.loadIdentity({ name });
    const b1 = bundlePath();
    const k = killedAt('openSync', `${path.basename(b1)}\\.\\d+\\.tmp`, `relocation.exportNode({ name: ${JSON.stringify(name)}, out: ${JSON.stringify(b1)}, toHostKey: ${JSON.stringify(hostKey())} });`);
    assert.ok(k.killed);
    const cli = (...a) => spawnSync(process.execPath, [path.resolve(__dirname, '../bin/sym.js'), ...a], { env: process.env, encoding: 'utf8' });
    const r = cli('node', 'abort-export', name);
    assert.strictEqual(r.status, 0, r.stderr);
    assert.match(r.stdout, /abandoned/);
    assert.strictEqual(cfg.loadIdentity({ name }).privateKey, id.privateKey, 'it starts here again');
    const k2 = killedAt('openSync', 'identity\\.json\\.\\d+\\.tmp', `relocation.exportNode({ name: ${JSON.stringify(name)}, out: ${JSON.stringify(b1)}, toHostKey: ${JSON.stringify(hostKey())} });`);
    assert.ok(k2.killed && exists(b1), 'killed after a complete bundle');
    const r2 = cli('node', 'abort-export', '--node-id', id.nodeId);
    assert.notStrictEqual(r2.status, 0);
    assert.match(r2.stderr, /complete bundle/);
  });
});

describe('design v2: an import interrupted between its installs can be retried (rr-e16)', () => {
  for (const split of [true, false]) {
    it(`${split ? 'SYM_IDENTITY_DIR' : 'plain'}: killed after its first install, the retry completes and the agent starts by pin and by name (9f6847c: "already lives on this host", the pin absent)`, () => {
      const run = () => {
        const name = uniq('imp');
        const id = cfg.loadIdentity({ name });
        put(path.join(cfg.nodeDirById(id.nodeId), 'cmbs', 'm.json'), '{"m":1}');
        const out = bundlePath();
        relocation.exportNode({ name, out, toHostKey: hostKey() });
        // another host: this host's copies of the node removed
        fs.rmSync(cfg.nodeDirById(id.nodeId), { recursive: true, force: true });
        fs.rmSync(cfg.identityDirById(id.nodeId), { recursive: true, force: true });
        const k = killedAt('renameSync', '\\.import-', `relocation.importNode({ from: ${JSON.stringify(out)}, expect: { nodeId: ${JSON.stringify(id.nodeId)}, key: ${JSON.stringify(id.publicKey)} } });`, 'after');
        assert.ok(k.killed, k.stderr.slice(0, 300));
        // The identity is installed first (it is the commit): already between the installs the agent is here.
        assert.strictEqual(cfg.loadIdentity({ nodeId: id.nodeId }).privateKey, id.privateKey, 'committed by the first install');
        const r = relocation.importNode({ from: out, expect: { nodeId: id.nodeId, key: id.publicKey } });
        assert.strictEqual(r.nodeId, id.nodeId);
        assert.strictEqual(cfg.loadIdentity({ name, nodeId: id.nodeId, create: false }).privateKey, id.privateKey);
        assert.strictEqual(cfg.loadIdentity({ name }).privateKey, id.privateKey);
        assert.strictEqual(read(path.join(cfg.nodeDirById(id.nodeId), 'cmbs', 'm.json')), '{"m":1}', 'with its store');
        if (split) assert.ok(!exists(path.join(cfg.nodeDirById(id.nodeId), 'identity.json')), 'the private key only in the identity directory');
      };
      if (split) withIdentityDir(run); else run();
    });
  }
});

describe('design v2: a pin never takes a name held by another agent (rr-e17)', () => {
  it('a pinned start under a name whose 0.13 directory holds ANOTHER agent halts and moves nothing; the name\'s own start loads that agent (9f6847c claimed the name for the pin)', () => {
    const name = uniq('claude-foo');
    const old = legacyNode(name);
    const pin = cfg.loadIdentity({ name: uniq('pinned-elsewhere') });
    assert.throws(() => cfg.loadIdentity({ name, nodeId: pin.nodeId, create: false }), (e) => e instanceof IdentityHaltError && e.reason.includes(old.nodeId));
    assert.ok(!isLink(path.join(NODES_DIR, name)) && !exists(indexFile(name)), 'nothing moved, nothing claimed');
    assert.strictEqual(cfg.loadIdentity({ name }).privateKey, old.privateKey, 'by name: the 0.13 agent');
  });
});

describe('design v2: one source of truth; the index and the links are caches (rr-e1, rr-e8, R1-e7)', () => {
  modeTest('rr-e1: an agent 0.14.2 migrated (by-id dir 0755, key 0644): it loads, its directory narrowed to 0700 and its keys to 0600 (9f6847c left the directory 0755)', () => {
    const name = uniq('narrow');
    const id = migratedBy0142(name);
    const dir = cfg.nodeDirById(id.nodeId);
    assert.strictEqual(cfg.loadIdentity({ name }).privateKey, id.privateKey);
    assert.strictEqual(modeOf(dir), 0o700);
    assert.strictEqual(modeOf(path.join(dir, 'identity.json')), 0o600);
    assert.strictEqual(modeOf(path.join(dir, 'e2e-keypair.json')), 0o600);
  });

  it('rr-e1: an entry 0.14.2 wrote for a rename (the identity still under its old name) leads to the agent, and the identity takes the name', () => {
    const old = uniq('iota');
    const id = migratedBy0142(old);
    const renamed = uniq('iota2');
    fs.renameSync(indexFile(old), indexFile(renamed)); // what 0.14.2's renameIdentity did: the entry moved, identity.json kept its name
    fs.unlinkSync(path.join(NODES_DIR, old));
    fs.symlinkSync(path.join('by-id', id.nodeId), path.join(NODES_DIR, renamed), 'dir');
    put(indexFile(renamed), JSON.stringify({ name: renamed, nodeId: id.nodeId, at: 2 }));
    assert.strictEqual(cfg.loadIdentity({ name: renamed }).nodeId, id.nodeId);
    assert.strictEqual(JSON.parse(read(path.join(cfg.nodeDirById(id.nodeId), 'identity.json'))).name, renamed, 'derivable from the identity now');
    fs.unlinkSync(indexFile(renamed)); fs.unlinkSync(path.join(NODES_DIR, renamed)); // both caches lost
    assert.strictEqual(cfg.loadIdentity({ name: renamed }).nodeId, id.nodeId, 're-derived from the identity\'s name');
  });

  it('rr-e1: an entry 0.14.2 wrote for a pinned start under another identity\'s name keeps leading where it led; a pin of the other one halts (R4-9)', () => {
    const name = uniq('app');
    const a = cfg.loadIdentity({ name });
    const b = cfg.loadIdentity({ name: uniq('app-b') });
    put(indexFile(name), JSON.stringify({ name, nodeId: b.nodeId, at: 3 })); // 0.14.2 re-pointed the entry to the pin
    assert.strictEqual(cfg.loadIdentity({ name }).nodeId, b.nodeId, 'by name: what 0.14.2 ran under the name');
    assert.strictEqual(cfg.loadIdentity({ name, nodeId: b.nodeId, create: false }).nodeId, b.nodeId);
    assert.throws(() => cfg.loadIdentity({ name, nodeId: a.nodeId, create: false }), IdentityHaltError);
  });

  it('two committed identities that are one name halt, naming both; the index alone does not pick one silently', () => {
    const name = uniq('twins');
    const a = cfg.loadIdentity({ name });
    const b = makeIdentity(name);
    put(path.join(cfg.nodeDirById(b.nodeId), 'identity.json'), JSON.stringify(b), 0o600); // e.g. 0.14.2 minted in a moment it should not have
    assert.throws(() => cfg.loadIdentity({ name }), (e) => e instanceof IdentityHaltError && e.reason.includes(a.nodeId) && e.reason.includes(b.nodeId));
    assert.strictEqual(cfg.loadIdentity({ nodeId: a.nodeId }).nodeId, a.nodeId, 'each loads by its nodeId');
  });

  it('names are compared without regard to case: the index entry is keyed by the folded name and holds the exact name', () => {
    const name = `Case-${uniq('mixed')}`;
    const id = cfg.loadIdentity({ name });
    const folded = path.join(NODES_DIR, 'by-name', `${encodeURIComponent(name.toLowerCase())}.json`);
    assert.strictEqual(JSON.parse(read(folded)).name, name);
    assert.strictEqual(cfg.loadIdentity({ name: name.toLowerCase() }).nodeId, id.nodeId, 'the same agent under another case');
    assert.strictEqual(cfg.loadIdentity({ name: name.toUpperCase() }).nodeId, id.nodeId);
  });

  it('a 0.14.2 entry under the exact (unfolded) name is read, and the folded one written beside it', () => {
    const name = `Kappa-${uniq('k')}`;
    const id = migratedBy0142(name);
    fs.unlinkSync(path.join(NODES_DIR, name));
    assert.strictEqual(cfg.loadIdentity({ name }).nodeId, id.nodeId);
    assert.strictEqual(JSON.parse(read(path.join(NODES_DIR, 'by-name', `${encodeURIComponent(name.toLowerCase())}.json`))).nodeId, id.nodeId);
  });

  it('two 0.13 agents whose names fold together (a case-sensitive file system let both exist): the second halts, the first is not touched', () => {
    const lower = uniq('fold');
    const upper = lower.toUpperCase();
    const a = legacyNode(lower);
    if (exists(path.join(NODES_DIR, upper))) return; // case-insensitive: one directory, one agent (the start above is enough)
    const b = legacyNode(upper);
    assert.strictEqual(cfg.loadIdentity({ name: lower }).privateKey, a.privateKey);
    assert.throws(() => cfg.loadIdentity({ name: upper }), (e) => e instanceof IdentityHaltError && /without regard to case/.test(e.message));
    assert.ok(exists(path.join(NODES_DIR, upper, 'identity.json')) && JSON.parse(read(path.join(NODES_DIR, upper, 'identity.json'))).privateKey === b.privateKey, 'the second 0.13 agent is where it was');
  });
});

describe('design v2: the commit, the link, then the name (design point 6: a kill between commit and claim leaves a state 0.14.2 reads)', () => {
  it('killed at the name claim after the commit: nodes/<name> already leads to the committed identity, and the next start claims the name for it', () => {
    const name = uniq('claimkill');
    const id = legacyNode(name);
    const k = killedAt('linkSync', `by-name/${name}\\.json$`, `cfg.loadIdentity({ name: ${JSON.stringify(name)} });`);
    assert.ok(k.killed);
    assert.ok(!exists(indexFile(name)), 'the name was not claimed');
    assert.strictEqual(cfg.compatLinkNodeId(path.join(NODES_DIR, name)), id.nodeId, 'the compat link 0.14.2 reads is there');
    assert.strictEqual(fs.realpathSync(path.join(NODES_DIR, name, 'identity.json')), fs.realpathSync(path.join(cfg.nodeDirById(id.nodeId), 'identity.json')));
    assert.strictEqual(cfg.loadIdentity({ name }).privateKey, id.privateKey);
    assert.strictEqual(JSON.parse(read(indexFile(name))).nodeId, id.nodeId);
  });

  it('R1-e9: killed at the compat link: the next start puts it and loads the original; modes 0700/0600', () => {
    const name = uniq('linkkill');
    const id = legacyNode(name);
    const k = killedAt('renameSync', `\\.${name}\\.link-\\d+-[0-9a-f]+ -> `, `cfg.loadIdentity({ name: ${JSON.stringify(name)} });`);
    assert.ok(k.killed);
    for (let i = 0; i < 2; i++) assert.strictEqual(cfg.loadIdentity({ name }).privateKey, id.privateKey);
    assert.ok(isLink(path.join(NODES_DIR, name)));
    if (posix) { assert.strictEqual(modeOf(cfg.nodeDirById(id.nodeId)), 0o700); assert.strictEqual(modeOf(path.join(cfg.nodeDirById(id.nodeId), 'identity.json')), 0o600); }
  });

  it('a minter killed between its commit and its claim: the next start adopts that identity, and no second one is made', () => {
    const name = uniq('mintkill');
    const k = killedAt('linkSync', `by-name/${name}\\.json$`, `cfg.loadIdentity({ name: ${JSON.stringify(name)} });`);
    assert.ok(k.killed);
    const a = cfg.loadIdentity({ name });
    const b = cfg.loadIdentity({ name });
    assert.strictEqual(a.nodeId, b.nodeId);
    const named = fs.readdirSync(path.join(NODES_DIR, 'by-id')).filter((d) => !d.startsWith('.')).filter((d) => { try { return JSON.parse(read(path.join(NODES_DIR, 'by-id', d, 'identity.json'))).name === name; } catch { return false; } });
    assert.deepStrictEqual(named, [a.nodeId]);
  });
});

describe('design v2: across volumes only the key files are copied, after a free-space check', () => {
  const exdev = (from) => (o) => function (a, b) {
    if (String(a) === from) throw Object.assign(new Error('EXDEV: cross-device link not permitted (simulated)'), { code: 'EXDEV' });
    return o.call(fs, a, b);
  };

  it('too little space for the key files on the identity volume: halts with the bytes needed, the source untouched (9f6847c checked nothing)', () => {
    withIdentityDir((idRoot) => {
      const name = uniq('nospace');
      const id = makeIdentity(name);
      put(path.join(idRoot, name, 'identity.json'), JSON.stringify(id, null, 2), 0o600);
      put(path.join(NODES_DIR, name, 'cmbs', 'x.json'), '{}');
      const src = read(path.join(idRoot, name, 'identity.json'));
      assert.throws(() => patchMany({
        renameSync: exdev(path.join(idRoot, name)),
        statfsSync: (o) => function (p, ...a) { const s = o.call(fs, p, ...a); return { ...s, bavail: typeof s.bavail === 'bigint' ? 1n : 1, bsize: typeof s.bsize === 'bigint' ? 1024n : 1024 }; },
      }, () => cfg.loadIdentity({ name })), (e) => e instanceof IdentityHaltError && /bytes free/.test(e.reason) && /\d+ are needed/.test(e.reason));
      assert.strictEqual(read(path.join(idRoot, name, 'identity.json')), src);
      assert.ok(!cfg.isCommitted(id.nodeId));
      assert.strictEqual(cfg.loadIdentity({ name }).privateKey, id.privateKey, 'with the space, the next start finishes');
    });
  });
});

describe('design v2: the guards of the migration and the mint', () => {
  it('a mint holds the name\'s mint lock from its staging to its claim: one process at a time makes the agent of a name', () => {
    const name = uniq('mintlock');
    const lock = path.join(NODES_DIR, 'by-id', `.mint-${encodeURIComponent(name)}.lock`);
    const seen = [];
    patchMany({
      renameSync: (o) => function (a, b) { if (/\.stage-/.test(String(a))) seen.push(cfg.readLockFile(lock)); return o.call(fs, a, b); },
    }, () => cfg.loadIdentity({ name }));
    assert.strictEqual(seen.length, 1, 'one commit');
    assert.ok(seen[0] && seen[0].pid === process.pid, 'the mint lock was held by this process at the commit');
    assert.ok(!exists(lock), 'and released');
  });

  it('a 0.13 directory under a name the index gives to an agent whose name differs only in case: a second agent, it halts (never loads the other one)', () => {
    const name = `Fold${uniq('x')}`;
    const other = cfg.loadIdentity({ name });
    fs.unlinkSync(path.join(NODES_DIR, name));
    const lower = name.toLowerCase();
    const mine = legacyNode(lower);
    assert.throws(() => cfg.loadIdentity({ name: lower }), (e) => e instanceof IdentityHaltError && /without regard to case/.test(e.message) && e.message.includes(other.nodeId));
    assert.strictEqual(JSON.parse(read(path.join(NODES_DIR, lower, 'identity.json'))).privateKey, mine.privateKey, 'the 0.13 agent is where it was');
  });

  it('a committed directory is never set aside as a husk: the 0.13 copy replaced by a link while this start looks at it', () => {
    const name = uniq('nohusk');
    const id = legacyNode(name);
    const target = cfg.nodeDirById(id.nodeId);
    fs.mkdirSync(target, { recursive: true });
    fs.copyFileSync(path.join(NODES_DIR, name, 'identity.json'), path.join(target, 'identity.json')); // the same identity, committed, no entry
    let raced = false;
    patchMany({
      openSync: (o) => function (p, ...a) {
        if (!raced && String(p).includes(`.${id.nodeId}.migrating`)) { // another start set the 0.13 copy aside and put the link
          raced = true;
          fs.renameSync(path.join(NODES_DIR, name), path.join(os.tmpdir(), `${name}-elsewhere-${process.pid}`));
          fs.symlinkSync(path.join('by-id', id.nodeId), path.join(NODES_DIR, name), 'dir');
        }
        return o.call(fs, p, ...a);
      },
    }, () => cfg.migrateNodeDir(name));
    assert.ok(raced, 'the other start ran in between');
    assert.strictEqual(JSON.parse(read(path.join(target, 'identity.json'))).privateKey, id.privateKey, 'the committed directory is in place');
    assert.deepStrictEqual(fs.readdirSync(path.dirname(target)).filter((n) => n.startsWith(`.${id.nodeId}.husk`)), [], 'nothing was set aside');
    fs.rmSync(path.join(os.tmpdir(), `${name}-elsewhere-${process.pid}`), { recursive: true, force: true });
  });

  it('the compat link is in place before anything else after the commit (no sync in between): the moment a rollback finds neither is one call', () => {
    const name = uniq('order');
    const id = legacyNode(name);
    const target = cfg.nodeDirById(id.nodeId);
    let committed = false; let linkAtFirstSync = null;
    patchMany({
      renameSync: (o) => function (a, b) { const r = o.call(fs, a, b); if (String(b) === target) committed = true; return r; },
      fsyncSync: (o) => function (fd) { if (committed && linkAtFirstSync === null) linkAtFirstSync = isLink(path.join(NODES_DIR, name)); return o.call(fs, fd); },
    }, () => cfg.migrateNodeDir(name));
    assert.ok(committed);
    assert.strictEqual(linkAtFirstSync, true, 'the link was there at the first sync after the commit');
  });

  it('a husk holding only the claim of a lock remover that was killed (the lock itself gone): replaced at once, not "kept changing"', () => {
    const name = uniq('deadclaim');
    const id = legacyNode(name);
    const husk = cfg.nodeDirById(id.nodeId);
    put(path.join(husk, 'lock.pid.break-0123456789abcdef'), `2147483646\n${JSON.stringify({ start: 'x', createdAt: Date.now() })}\n`);
    const t0 = Date.now();
    assert.strictEqual(cfg.loadIdentity({ name }).privateKey, id.privateKey);
    assert.ok(Date.now() - t0 < 1500, `at once, not after the grace a lock being written gets (${Date.now() - t0} ms)`);
  });

  it('a 0.13 directory under a name whose entry leads to another agent under another name (a 0.14.2 alias): left as it is, not moved in', () => {
    const name = uniq('aliased');
    const x = cfg.loadIdentity({ name: uniq('x-own') });
    put(indexFile(name), JSON.stringify({ name, nodeId: x.nodeId, at: 1 }));
    const stray = legacyNode(name);
    assert.strictEqual(cfg.migrateNodeDir(name), 'skipped-duplicate');
    assert.ok(!exists(cfg.nodeDirById(stray.nodeId)), 'not moved in');
    assert.strictEqual(JSON.parse(read(path.join(NODES_DIR, name, 'identity.json'))).privateKey, stray.privateKey);
    assert.strictEqual(cfg.loadIdentity({ name }).nodeId, x.nodeId, 'the name leads where its entry led');
  });

  modeTest('with SYM_IDENTITY_DIR the node directory (the store) is narrowed to 0700 on load too', () => {
    withIdentityDir(() => {
      const name = uniq('nodedir');
      const id = cfg.loadIdentity({ name });
      fs.chmodSync(cfg.nodeDirById(id.nodeId), 0o755);
      cfg.loadIdentity({ name });
      assert.strictEqual(modeOf(cfg.nodeDirById(id.nodeId)), 0o700);
    });
  });
});
