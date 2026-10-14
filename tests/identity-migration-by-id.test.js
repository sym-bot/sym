'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * The 0.13 -> by-id identity migration must never cost an agent its key.
 *
 * 0.14.0 - 0.14.2 had two ways to destroy one. (1) The duplicate guard asked "does nodes/by-id/<nodeId>/
 * EXIST?" instead of "does an IDENTITY already sit there?", so a by-id directory made by anything else (a
 * lock, an interrupted move) left the 0.13 node where it was, unindexed, for good. (2) `loadIdentity` read
 * every answer it did not recognise as "no such agent" and MINTED: it renamed the 0.13 directory (the old
 * identity.json still in it) onto the new node's path and wrote the new identity over the old key.
 *
 * The tests below hold the line the founder drew ("the system must refuse to start rather than silently
 * create a replacement identity"): a name that has an identity on this host never gets a new one.
 * Every test uses its own agent name; the state root is shared by the file, as in config.test.js.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const cfg = require('../lib/config');

const { NODES_DIR, IdentityHaltError, IdentityTombstonedError } = cfg;
const posix = process.platform !== 'win32'; // modes are not a thing on Windows
const modeTest = posix ? it : it.skip;

let seq = 0;
const uniq = (b) => `${b}-${process.pid}-${++seq}-${Math.random().toString(36).slice(2, 6)}`;
const modeOf = (p) => fs.statSync(p).mode & 0o777;
const read = (p) => fs.readFileSync(p, 'utf8');
const exists = (p) => fs.existsSync(p);
const isLink = (p) => { try { return fs.lstatSync(p).isSymbolicLink(); } catch { return false; } };

/** A real Ed25519 identity, in the shape lib/config writes. */
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
  fs.chmodSync(file, mode); // explicit: the umask must not decide what a test means
}

/** What 0.13 left on disk: nodes/<name>/ with identity.json (and e2e-keypair.json) at the umask default. */
function legacyNode(name, { e2e = false, identity = makeIdentity(name), where = path.join(NODES_DIR, name), withIdentity = true } = {}) {
  if (withIdentity) put(path.join(where, 'identity.json'), JSON.stringify(identity, null, 2), 0o644);
  if (e2e) put(path.join(where, 'e2e-keypair.json'), JSON.stringify({ publicKey: 'cHVi', privateKey: 'cHJpdg==' }, null, 2), 0o644);
  put(path.join(where, 'cmbs', 'x.json'), '{"x":1}');
  return identity;
}

/** A nodes/by-id/<nodeId>/ that something else made: a lock, an interrupted run. No identity in it. */
function husk(nodeId, { lock = true } = {}) {
  const d = cfg.nodeDirById(nodeId);
  fs.mkdirSync(d, { recursive: true });
  if (lock) put(path.join(d, 'lock.pid'), '999999\n');
  return d;
}

/** Every identity.json under nodes/by-id and SYM_IDENTITY_DIR/by-id whose `name` field is `name`. */
function identitiesNamed(name) {
  const found = [];
  const roots = [path.join(NODES_DIR, 'by-id'), process.env.SYM_IDENTITY_DIR && path.join(process.env.SYM_IDENTITY_DIR, 'by-id')].filter(Boolean);
  for (const root of roots) {
    if (!exists(root)) continue;
    for (const d of fs.readdirSync(root)) {
      const f = path.join(root, d, 'identity.json');
      try { if (JSON.parse(read(f)).name === name) found.push(f); } catch { /* */ }
    }
  }
  return found;
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

/** Replace fs.<fn> for the duration of `body`; `wrap(original)` returns the replacement. */
function patchFs(fn, wrap, body) {
  const original = fs[fn];
  fs[fn] = wrap(original);
  try { return body(); } finally { fs[fn] = original; }
}
const exdev = (msg) => Object.assign(new Error(`EXDEV: cross-device link not permitted (${msg})`), { code: 'EXDEV' });

/**
 * T9: every case asserts it measured something. A run over nothing returns moved: 0 and would "pass" a
 * test that only checked for the absence of damage.
 */
function assertMoved(result, atLeast = 1) {
  assert.ok(result && result.moved >= atLeast, `the migration moved ${result && result.moved}, expected at least ${atLeast}: the test measured nothing`);
}

describe('T1/T2: the migration leaves key files private', () => {
  modeTest('identity.json written 0644 by 0.13 ends at 0600, and its directory at 0700', () => {
    const name = uniq('t1');
    const id = legacyNode(name);
    assert.strictEqual(modeOf(path.join(NODES_DIR, name, 'identity.json')), 0o644, 'setup: a 0.13 key file, world-readable');
    assert.strictEqual(cfg.migrateNodeDir(name), 'moved');
    const dir = cfg.nodeDirById(id.nodeId);
    assert.strictEqual(modeOf(path.join(dir, 'identity.json')), 0o600);
    assert.strictEqual(modeOf(dir), 0o700);
    assert.strictEqual(JSON.parse(read(path.join(dir, 'identity.json'))).privateKey, id.privateKey, 'the key is the same key');
  });

  modeTest('e2e-keypair.json ends at 0600 with its bytes unchanged', () => {
    const name = uniq('t2');
    const id = legacyNode(name, { e2e: true });
    const before = read(path.join(NODES_DIR, name, 'e2e-keypair.json'));
    assert.strictEqual(cfg.migrateNodeDir(name), 'moved');
    const f = path.join(cfg.nodeDirById(id.nodeId), 'e2e-keypair.json');
    assert.strictEqual(modeOf(f), 0o600);
    assert.strictEqual(read(f), before);
  });

  modeTest('with SYM_IDENTITY_DIR: the identity file is 0600 and both directories 0700 (T8)', () => {
    withIdentityDir((idRoot) => {
      const name = uniq('t8');
      const id = makeIdentity(name);
      put(path.join(idRoot, name, 'identity.json'), JSON.stringify(id, null, 2), 0o644);
      put(path.join(NODES_DIR, name, 'cmbs', 'x.json'), '{}');
      put(path.join(NODES_DIR, name, 'e2e-keypair.json'), '{}', 0o644);
      assert.strictEqual(cfg.migrateNodeDir(name), 'moved');
      const idDir = path.join(idRoot, 'by-id', id.nodeId);
      const nodeDir = cfg.nodeDirById(id.nodeId);
      assert.strictEqual(modeOf(path.join(idDir, 'identity.json')), 0o600);
      assert.strictEqual(modeOf(idDir), 0o700);
      assert.strictEqual(modeOf(nodeDir), 0o700);
      assert.strictEqual(modeOf(path.join(nodeDir, 'e2e-keypair.json')), 0o600);
      assert.ok(exists(path.join(nodeDir, 'cmbs', 'x.json')), 'the node dir moved with its store');
      assert.strictEqual(cfg.nodeIdForName(name), id.nodeId, 'the index resolves');
      assert.strictEqual(cfg.loadIdentity({ name, create: false }).privateKey, id.privateKey);
    });
  });

  modeTest('loading narrows a key file an earlier release already migrated at 0644 (and the E2E keypair beside it)', () => {
    const name = uniq('heal');
    const id = legacyNode(name, { e2e: true });
    cfg.migrateNodeDir(name);
    const dir = cfg.nodeDirById(id.nodeId);
    fs.chmodSync(path.join(dir, 'identity.json'), 0o644); fs.chmodSync(path.join(dir, 'e2e-keypair.json'), 0o644);
    assert.strictEqual(cfg.loadIdentity({ name, create: false }).nodeId, id.nodeId);
    assert.strictEqual(modeOf(path.join(dir, 'identity.json')), 0o600);
    assert.strictEqual(modeOf(path.join(dir, 'e2e-keypair.json')), 0o600);
  });

  modeTest('a rewrite of identity.json (bare Windows hostname) lands at 0600, not at the old file mode', () => {
    const name = uniq('rewrite');
    const id = legacyNode(name, { identity: makeIdentity(name, { hostname: 'bare-host' }) });
    cfg.migrateNodeDir(name);
    const f = path.join(cfg.nodeDirById(id.nodeId), 'identity.json');
    const onDisk = JSON.parse(read(f)); onDisk.hostname = 'bare-host';
    put(f, JSON.stringify(onDisk, null, 2), 0o644);
    const loaded = cfg.loadIdentity({ name, create: false });
    assert.strictEqual(loaded.hostname, 'bare-host.local');
    assert.strictEqual(JSON.parse(read(f)).hostname, 'bare-host.local', 'the rewrite happened');
    assert.strictEqual(modeOf(f), 0o600);
  });

  modeTest('a newly made agent: identity 0600, its directory 0700', () => {
    const name = uniq('fresh');
    const id = cfg.loadIdentity({ name });
    const dir = cfg.nodeDirById(id.nodeId);
    assert.strictEqual(modeOf(path.join(dir, 'identity.json')), 0o600);
    assert.strictEqual(modeOf(dir), 0o700);
  });
});

describe('T3-T5: a by-id directory that merely exists is not a second claim on the nodeId', () => {
  it('T3: the node is merged into an existing by-id dir that holds only lock.pid', () => {
    const name = uniq('t3');
    const id = legacyNode(name);
    const dest = husk(id.nodeId);
    assert.strictEqual(cfg.migrateNodeDir(name), 'moved');
    assert.strictEqual(JSON.parse(read(path.join(dest, 'identity.json'))).privateKey, id.privateKey, 'the identity is under the nodeId, key unchanged');
    assert.ok(exists(path.join(dest, 'lock.pid')), 'what was already there stays');
    assert.ok(exists(path.join(dest, 'cmbs', 'x.json')), 'the store came with it');
    assert.strictEqual(cfg.nodeIdForName(name), id.nodeId);
    assert.ok(isLink(path.join(NODES_DIR, name)), 'nodes/<name> is the compat link');
    assert.strictEqual(fs.realpathSync(path.join(NODES_DIR, name)), fs.realpathSync(dest));
  });

  it('T3: an EMPTY by-id dir is merged into too', () => {
    const name = uniq('t3e');
    const id = legacyNode(name);
    husk(id.nodeId, { lock: false });
    assert.strictEqual(cfg.migrateNodeDir(name), 'moved');
    assert.ok(exists(path.join(cfg.nodeDirById(id.nodeId), 'identity.json')));
  });

  it('T4: a pinned start recovers once the node is migrated', () => {
    const name = uniq('t4');
    const id = legacyNode(name);
    husk(id.nodeId);
    assertMoved(cfg.migrateIdentities());
    const loaded = cfg.loadIdentity({ nodeId: id.nodeId, create: false });
    assert.strictEqual(loaded.nodeId, id.nodeId);
    assert.strictEqual(loaded.privateKey, id.privateKey);
  });

  it('T5: an unpinned start never mints over a husk: same nodeId, same key, and no second identity exists', () => {
    const name = uniq('t5');
    const id = legacyNode(name);
    husk(id.nodeId);
    const loaded = cfg.loadIdentity({ name });
    assert.strictEqual(loaded.nodeId, id.nodeId);
    assert.strictEqual(loaded.privateKey, id.privateKey);
    const files = identitiesNamed(name);
    assert.strictEqual(files.length, 1, `exactly one identity answers to ${name}: ${files.join(', ')}`);
    assert.strictEqual(JSON.parse(read(files[0])).privateKey, id.privateKey, 'and it still holds the original private key');
  });

  it('the reported repro: a 0.13 dir plus a pre-existing EMPTY by-id/<oldNodeId>/ keeps the old key (0.14.2 minted and overwrote it)', () => {
    const name = uniq('repro');
    const old = legacyNode(name);
    fs.mkdirSync(path.join(NODES_DIR, 'by-id', old.nodeId), { recursive: true });
    const loaded = cfg.loadIdentity({ name });
    assert.strictEqual(loaded.nodeId, old.nodeId, 'not a new nodeId');
    assert.strictEqual(loaded.privateKey, old.privateKey);
    assert.strictEqual(identitiesNamed(name).length, 1);
    assert.strictEqual(JSON.parse(read(path.join(cfg.nodeDirById(old.nodeId), 'identity.json'))).privateKey, old.privateKey, 'the old private key is still on disk');
    assert.strictEqual(cfg.nodeIdForName(name), old.nodeId);
  });

  it('the same identity on both sides is an interrupted move, resumed, not a duplicate', () => {
    const name = uniq('resume-same');
    const id = legacyNode(name);
    const dest = cfg.nodeDirById(id.nodeId);
    put(path.join(dest, 'identity.json'), read(path.join(NODES_DIR, name, 'identity.json')), 0o600);
    assert.strictEqual(cfg.migrateNodeDir(name), 'moved');
    assert.ok(exists(path.join(dest, 'cmbs', 'x.json')));
    assert.ok(isLink(path.join(NODES_DIR, name)));
    assert.strictEqual(cfg.loadIdentity({ name, create: false }).privateKey, id.privateKey);
  });
});

describe('T6/T7: a real duplicate is refused, and refusing is a halt, never a mint', () => {
  function duplicate(name) {
    const mine = legacyNode(name);
    const other = makeIdentity(name, { nodeId: mine.nodeId }); // another key, filed under the same nodeId
    const dest = cfg.nodeDirById(mine.nodeId);
    put(path.join(dest, 'identity.json'), JSON.stringify(other, null, 2), 0o600);
    return { mine, other, dest };
  }

  it('T6: a DIFFERENT identity.json already under the nodeId: skipped-duplicate, and nothing is overwritten', () => {
    const name = uniq('t6');
    const { mine, dest } = duplicate(name);
    const legacyBefore = read(path.join(NODES_DIR, name, 'identity.json'));
    const destBefore = read(path.join(dest, 'identity.json'));
    assert.strictEqual(cfg.migrateNodeDir(name), 'skipped-duplicate');
    assert.strictEqual(read(path.join(NODES_DIR, name, 'identity.json')), legacyBefore, 'the 0.13 identity is byte-unchanged');
    assert.strictEqual(read(path.join(dest, 'identity.json')), destBefore, 'the one already filed is byte-unchanged');
    assert.strictEqual(cfg.nodeIdForName(name), null, 'nothing was indexed');
    assert.ok(!exists(path.join(dest, 'cmbs')), 'and nothing was merged in beside it');
    assert.ok(mine.privateKey);
  });

  it('T7: loading that name halts (IdentityHaltError) and does not touch the 0.13 file', () => {
    const name = uniq('t7');
    const { dest } = duplicate(name);
    const legacyBefore = read(path.join(NODES_DIR, name, 'identity.json'));
    const destBefore = read(path.join(dest, 'identity.json'));
    const dirsBefore = fs.readdirSync(path.join(NODES_DIR, 'by-id')).length;
    assert.throws(() => cfg.loadIdentity({ name }), (e) => e instanceof IdentityHaltError && /0\.13 identity/.test(e.reason));
    assert.strictEqual(read(path.join(NODES_DIR, name, 'identity.json')), legacyBefore);
    assert.strictEqual(read(path.join(dest, 'identity.json')), destBefore);
    assert.strictEqual(fs.readdirSync(path.join(NODES_DIR, 'by-id')).length, dirsBefore, 'no new node directory was made');
    assert.strictEqual(cfg.nodeIdForName(name), null);
  });

  it('a differing store file in an existing by-id dir is a conflict too: nothing moves', () => {
    const name = uniq('conflict');
    const id = legacyNode(name);
    const dest = husk(id.nodeId, { lock: false });
    put(path.join(dest, 'cmbs', 'x.json'), '{"x":2}');
    assert.strictEqual(cfg.migrateNodeDir(name), 'skipped-duplicate');
    assert.ok(exists(path.join(NODES_DIR, name, 'identity.json')), 'the 0.13 node is where it was');
    assert.strictEqual(read(path.join(dest, 'cmbs', 'x.json')), '{"x":2}');
    assert.throws(() => cfg.loadIdentity({ name }), IdentityHaltError);
  });

  it('a name the index already gives to ANOTHER node is not re-pointed by a stray 0.13 directory', () => {
    const name = uniq('held');
    const held = cfg.loadIdentity({ name });
    const stray = makeIdentity(name);
    fs.unlinkSync(path.join(NODES_DIR, name)); // a real directory where the index says there is a link
    legacyNode(name, { identity: stray });
    assert.strictEqual(cfg.migrateNodeDir(name), 'skipped-duplicate');
    assert.strictEqual(cfg.nodeIdForName(name), held.nodeId, 'the index is untouched');
    assert.strictEqual(cfg.loadIdentity({ name }).nodeId, held.nodeId, 'and the indexed agent still loads');
    assert.strictEqual(JSON.parse(read(path.join(NODES_DIR, name, 'identity.json'))).privateKey, stray.privateKey, 'the stray key is not destroyed');
  });
});

describe('F4: a name that indexes a node whose identity is missing halts', () => {
  it('create (the default) halts and neither mints nor re-points the index', () => {
    const name = uniq('f4');
    const first = cfg.loadIdentity({ name });
    fs.rmSync(path.join(cfg.nodeDirById(first.nodeId), 'identity.json'));
    const dirsBefore = fs.readdirSync(path.join(NODES_DIR, 'by-id')).length;
    assert.throws(() => cfg.loadIdentity({ name }), (e) => e instanceof IdentityHaltError && e.reason.includes(first.nodeId));
    assert.strictEqual(cfg.nodeIdForName(name), first.nodeId, 'the index still names the agent');
    assert.strictEqual(fs.readdirSync(path.join(NODES_DIR, 'by-id')).length, dirsBefore, 'nothing was minted');
  });

  it('create: false is still IdentityAbsentError (EIDENTITYABSENT)', () => {
    const name = uniq('f4b');
    const first = cfg.loadIdentity({ name });
    fs.rmSync(path.join(cfg.nodeDirById(first.nodeId), 'identity.json'));
    assert.throws(() => cfg.loadIdentity({ name, create: false }), (e) => e.code === 'EIDENTITYABSENT');
    assert.throws(() => cfg.loadIdentity({ nodeId: first.nodeId, create: false }), (e) => e.code === 'EIDENTITYABSENT');
  });

  it('an identity volume that is not mounted at boot halts instead of making a replacement agent', () => {
    withIdentityDir((idRoot) => {
      const name = uniq('f4v');
      const first = cfg.loadIdentity({ name });
      assert.ok(exists(path.join(idRoot, 'by-id', first.nodeId, 'identity.json')), 'setup: the key is on the identity volume');
      const away = `${idRoot}.away`;
      fs.renameSync(idRoot, away);
      try {
        assert.throws(() => cfg.loadIdentity({ name }), IdentityHaltError);
        assert.strictEqual(cfg.nodeIdForName(name), first.nodeId);
      } finally { fs.rmSync(idRoot, { recursive: true, force: true }); fs.renameSync(away, idRoot); }
      assert.strictEqual(cfg.loadIdentity({ name }).privateKey, first.privateKey, 'mounted again: the same agent');
    });
  });
});

describe('the safety net: the mint path never buries a 0.13 identity', () => {
  it('F5: SYM_IDENTITY_DIR switched on for a 0.13 node whose identity is in its node dir halts, and moves nothing', () => {
    withIdentityDir(() => {
      const name = uniq('f5');
      const id = legacyNode(name);
      const before = read(path.join(NODES_DIR, name, 'identity.json'));
      assert.throws(() => cfg.migrateNodeDir(name), (e) => e instanceof IdentityHaltError && /SYM_IDENTITY_DIR/.test(e.reason));
      assert.throws(() => cfg.loadIdentity({ name }), IdentityHaltError);
      assert.strictEqual(read(path.join(NODES_DIR, name, 'identity.json')), before);
      assert.ok(!isLink(path.join(NODES_DIR, name)) && exists(path.join(NODES_DIR, name, 'cmbs')), 'the node dir was not moved');
      assert.strictEqual(identitiesNamed(name).length, 0, 'and no identity was made');
      assert.ok(id.privateKey);
    });
  });

  it('F7: a stray symlink at nodes/<name> that leads to an identity but is not a by-id link does not read as indexed, and halts', () => {
    const name = uniq('f7');
    const elsewhere = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sym-stray-')), 'agent');
    const id = legacyNode(name, { where: elsewhere });
    fs.mkdirSync(NODES_DIR, { recursive: true });
    fs.symlinkSync(elsewhere, path.join(NODES_DIR, name), 'dir');
    assert.strictEqual(cfg.migrateNodeDir(name), 'not-a-node', 'nothing was indexed, so not "already"');
    assert.strictEqual(cfg.nodeIdForName(name), null);
    assert.throws(() => cfg.loadIdentity({ name }), IdentityHaltError);
    assert.strictEqual(fs.readlinkSync(path.join(NODES_DIR, name)), elsewhere, 'the link is left alone');
    assert.strictEqual(JSON.parse(read(path.join(elsewhere, 'identity.json'))).privateKey, id.privateKey);
  });

  it('a hand-made nodes/<name>/ with NO identity still becomes the new agent\'s directory (documented, unchanged)', () => {
    const name = uniq('nodir-id');
    put(path.join(NODES_DIR, name, 'cmbs', 'kept.json'), '{"k":1}');
    const id = cfg.loadIdentity({ name });
    assert.ok(exists(path.join(cfg.nodeDirById(id.nodeId), 'cmbs', 'kept.json')), 'the store moved with the new identity');
    assert.ok(isLink(path.join(NODES_DIR, name)));
  });

  it('a brand-new name still mints exactly one identity', () => {
    const name = uniq('brand-new');
    const a = cfg.loadIdentity({ name });
    const b = cfg.loadIdentity({ name });
    assert.strictEqual(a.nodeId, b.nodeId);
    assert.strictEqual(identitiesNamed(name).length, 1);
  });
});

describe('F10: a public key without a private key halts', () => {
  it('is not loaded, not repaired, and the file is untouched', () => {
    const name = uniq('f10');
    const id = makeIdentity(name); delete id.privateKey;
    legacyNode(name, { identity: id });
    const f = path.join(NODES_DIR, name, 'identity.json');
    const before = read(f);
    assert.throws(() => cfg.loadIdentity({ name }), (e) => e instanceof IdentityHaltError && /no private key/.test(e.reason));
    assert.strictEqual(read(f), before);
  });
});

describe('F6: rewriting identity.json is atomic', () => {
  it('a failure while writing leaves the original key file intact, and no temp file behind', () => {
    const name = uniq('f6');
    const id = legacyNode(name, { identity: makeIdentity(name, { hostname: 'bare-host' }) });
    const f = path.join(NODES_DIR, name, 'identity.json');
    const before = read(f);
    let injected = 0;
    patchFs('writeSync', (orig) => function (fd, ...rest) {
      injected++;
      throw Object.assign(new Error('ENOSPC: no space left on device (injected)'), { code: 'ENOSPC' });
    }, () => {
      assert.throws(() => cfg.loadIdentity({ name }), /ENOSPC/);
    });
    assert.ok(injected >= 1, 'the failure was reached');
    assert.strictEqual(read(f), before, 'the key file is byte-identical: it was never truncated');
    assert.deepStrictEqual(fs.readdirSync(path.join(NODES_DIR, name)).filter((n) => n.endsWith('.tmp')), []);
    assert.strictEqual(cfg.loadIdentity({ name }).privateKey, id.privateKey, 'and the next start succeeds with the same key');
  });
});

describe('F9: a move across filesystems copies, verifies, then removes', () => {
  it('EXDEV on the identity dir: the identity arrives intact at 0600 and the source is gone', () => {
    withIdentityDir((idRoot) => {
      const name = uniq('f9');
      const id = makeIdentity(name);
      put(path.join(idRoot, name, 'identity.json'), JSON.stringify(id, null, 2), 0o644);
      put(path.join(idRoot, name, 'sub', 'a.txt'), 'a');
      put(path.join(NODES_DIR, name, 'cmbs', 'x.json'), '{}');
      const result = patchFs('renameSync', (orig) => function (a, b) {
        if (String(a).startsWith(idRoot) && String(b).startsWith(idRoot)) throw exdev('simulated');
        return orig.call(fs, a, b);
      }, () => cfg.migrateNodeDir(name));
      assert.strictEqual(result, 'moved');
      const dest = path.join(idRoot, 'by-id', id.nodeId);
      assert.strictEqual(JSON.parse(read(path.join(dest, 'identity.json'))).privateKey, id.privateKey);
      assert.strictEqual(read(path.join(dest, 'sub', 'a.txt')), 'a');
      if (posix) assert.strictEqual(modeOf(path.join(dest, 'identity.json')), 0o600);
      assert.ok(!exists(path.join(idRoot, name, 'identity.json')) || isLink(path.join(idRoot, name)), 'the source is gone (only the compat link is left)');
      assert.strictEqual(cfg.loadIdentity({ name, create: false }).privateKey, id.privateKey);
    });
  });

  it('a copy that fails leaves the source untouched and no half-copy at the destination', () => {
    withIdentityDir((idRoot) => {
      const name = uniq('f9b');
      const id = makeIdentity(name);
      put(path.join(idRoot, name, 'identity.json'), JSON.stringify(id, null, 2), 0o600);
      put(path.join(NODES_DIR, name, 'cmbs', 'x.json'), '{}');
      const src = read(path.join(idRoot, name, 'identity.json'));
      assert.throws(() => patchFs('renameSync', (orig) => function (a, b) {
        if (String(a).startsWith(idRoot) && String(b).startsWith(idRoot)) throw exdev('simulated');
        return orig.call(fs, a, b);
      }, () => patchFs('copyFileSync', () => function () { throw Object.assign(new Error('EIO: injected'), { code: 'EIO' }); },
        () => cfg.migrateNodeDir(name))), /EIO/);
      assert.strictEqual(read(path.join(idRoot, name, 'identity.json')), src, 'the identity is where it was');
      assert.ok(!exists(path.join(idRoot, 'by-id', id.nodeId)), 'no half-copy');
      // the fault clears: the next run completes the move
      assert.strictEqual(cfg.loadIdentity({ name }).privateKey, id.privateKey);
      assert.ok(exists(path.join(idRoot, 'by-id', id.nodeId, 'identity.json')));
    });
  });
});

describe('F9 on a real second filesystem (Linux: nodes/by-id lives on /dev/shm, a tmpfs)', () => {
  const shm = '/dev/shm';
  const second = process.platform === 'linux' && exists(shm) && fs.statSync(shm).dev !== fs.statSync(os.tmpdir()).dev;
  (second ? it : it.skip)('rename fails with EXDEV for real, and the node still arrives whole, private, and unchanged', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-exdev-'));
    const far = fs.mkdtempSync(path.join(shm, 'sym-exdev-'));
    try {
      const state = path.join(root, 'state');
      fs.mkdirSync(path.join(state, 'nodes'), { recursive: true });
      fs.symlinkSync(far, path.join(state, 'nodes', 'by-id'), 'dir'); // everything filed by nodeId lands on the other filesystem
      const script = `
        const fs = require('fs'), path = require('path');
        const c = require(${JSON.stringify(path.resolve(__dirname, '../lib/config.js'))});
        const name = 'exdev-agent';
        const id = JSON.parse(process.env.LEGACY_IDENTITY);
        const dir = path.join(c.NODES_DIR, name);
        fs.mkdirSync(path.join(dir, 'cmbs'), { recursive: true });
        fs.writeFileSync(path.join(dir, 'identity.json'), JSON.stringify(id, null, 2), { mode: 0o644 }); fs.chmodSync(path.join(dir, 'identity.json'), 0o644);
        fs.writeFileSync(path.join(dir, 'e2e-keypair.json'), '{}'); fs.chmodSync(path.join(dir, 'e2e-keypair.json'), 0o644);
        fs.writeFileSync(path.join(dir, 'cmbs', 'x.json'), '{"x":1}');
        let sawExdev = false;
        const orig = fs.renameSync;
        fs.renameSync = function (a, b) { try { return orig.call(fs, a, b); } catch (e) { if (e.code === 'EXDEV') sawExdev = true; throw e; } };
        const loaded = c.loadIdentity({ name });
        const dest = c.nodeDirById(id.nodeId);
        console.log(JSON.stringify({
          sawExdev, same: loaded.nodeId === id.nodeId && loaded.privateKey === id.privateKey,
          sourceGone: !fs.existsSync(path.join(dir, 'cmbs')) || fs.lstatSync(dir).isSymbolicLink(),
          store: fs.readFileSync(path.join(dest, 'cmbs', 'x.json'), 'utf8'),
          idMode: fs.statSync(path.join(dest, 'identity.json')).mode & 0o777, e2eMode: fs.statSync(path.join(dest, 'e2e-keypair.json')).mode & 0o777,
          dirMode: fs.statSync(dest).mode & 0o777, onOtherFs: fs.realpathSync(dest).startsWith(fs.realpathSync(${JSON.stringify(far)})),
        }));`;
      const id = makeIdentity('exdev-agent');
      const out = await new Promise((resolve, reject) => {
        const child = spawn(process.execPath, ['-e', script], {
          env: { ...process.env, SYM_STATE_DIR: state, LEGACY_IDENTITY: JSON.stringify(id) }, stdio: ['ignore', 'pipe', 'pipe'],
        });
        let so = ''; let se = '';
        child.stdout.on('data', (d) => { so += d; }); child.stderr.on('data', (d) => { se += d; });
        child.on('exit', (code) => (code === 0 ? resolve(so) : reject(new Error(`child exited ${code}: ${se}`))));
      });
      const r = JSON.parse(out);
      assert.strictEqual(r.onOtherFs, true, 'setup: the node lives on the other filesystem');
      assert.strictEqual(r.sawExdev, true, 'the kernel really refused the rename');
      assert.strictEqual(r.same, true);
      assert.strictEqual(r.sourceGone, true);
      assert.strictEqual(r.store, '{"x":1}');
      assert.strictEqual(r.idMode, 0o600);
      assert.strictEqual(r.e2eMode, 0o600);
      assert.strictEqual(r.dirMode, 0o700);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
      fs.rmSync(far, { recursive: true, force: true });
    }
  });
});

describe('F11: the window between the move and the index is not a mint race', () => {
  it('a second starter that arrives mid-move finds the agent instead of making a new one', () => {
    const name = uniq('f11');
    const id = legacyNode(name);
    let racer = null;
    patchFs('renameSync', (orig) => function (a, b) {
      const r = orig.call(fs, a, b);
      if (racer === null && a === path.join(NODES_DIR, name)) { // the node dir has just moved; the index is not final yet
        racer = 'running';
        try { racer = cfg.loadIdentity({ name }); } catch (e) { racer = e; }
      }
      return r;
    }, () => { assert.strictEqual(cfg.loadIdentity({ name }).nodeId, id.nodeId); });
    assert.ok(racer && racer.nodeId, `the racing starter loaded an identity: ${racer && racer.message}`);
    assert.strictEqual(racer.nodeId, id.nodeId, 'the same agent');
    assert.strictEqual(identitiesNamed(name).length, 1);
  });

  it('an interrupted move is resumed by the next start: the identity moves last, and its absence re-enters the move', () => {
    const name = uniq('f11r');
    const id = legacyNode(name);
    put(path.join(NODES_DIR, name, 'aaa.json'), '{}'); put(path.join(NODES_DIR, name, 'zzz.json'), '{}'); // names on both sides of identity.json
    husk(id.nodeId); // forces a merge, entry by entry
    patchFs('renameSync', (orig) => function (a, b) {
      if (path.basename(String(a)) === 'identity.json' && String(a).startsWith(NODES_DIR)) throw Object.assign(new Error('EIO: injected'), { code: 'EIO' });
      return orig.call(fs, a, b);
    }, () => { assert.throws(() => cfg.migrateNodeDir(name), /EIO/); });
    assert.ok(exists(path.join(NODES_DIR, name, 'identity.json')), 'the identity had not moved yet');
    for (const f of ['aaa.json', 'zzz.json', path.join('cmbs', 'x.json')]) assert.ok(exists(path.join(cfg.nodeDirById(id.nodeId), f)), `but the rest had: ${f}`);
    assert.strictEqual(cfg.nodeIdForName(name), id.nodeId, 'the name was indexed first');
    const loaded = cfg.loadIdentity({ name });
    assert.strictEqual(loaded.nodeId, id.nodeId);
    assert.strictEqual(loaded.privateKey, id.privateKey);
    assert.ok(isLink(path.join(NODES_DIR, name)), 'finished: nodes/<name> is the compat link');
    assert.strictEqual(identitiesNamed(name).length, 1);
  });
});

describe('F11: another process finishing the move underneath this one', () => {
  it('a step that fails because the other process just did it is re-run against what it left, and reads as moved', () => {
    const name = uniq('f11-other');
    const id = legacyNode(name);
    const legacy = path.join(NODES_DIR, name);
    const dest = cfg.nodeDirById(id.nodeId);
    let helped = false;
    const result = patchFs('renameSync', (orig) => function (a, b) {
      if (!helped && a === legacy) { // the other process gets there first: it moves the directory and leaves the link
        helped = true;
        orig.call(fs, a, b);
        fs.symlinkSync(path.join('by-id', id.nodeId), legacy, 'dir');
        throw Object.assign(new Error(`ENOENT: no such file or directory, rename '${a}' -> '${b}'`), { code: 'ENOENT' });
      }
      return orig.call(fs, a, b);
    }, () => cfg.migrateNodeDir(name));
    assert.ok(helped, 'the other process ran');
    assert.strictEqual(result, 'already');
    assert.strictEqual(JSON.parse(read(path.join(dest, 'identity.json'))).privateKey, id.privateKey);
    assert.strictEqual(cfg.loadIdentity({ name, create: false }).privateKey, id.privateKey);
  });

  it('a path that now leads through the other process\'s link to the destination is never "merged" onto itself (that would delete it)', () => {
    const name = uniq('f11-alias');
    const id = legacyNode(name);
    put(path.join(NODES_DIR, name, 'aaa.json'), '{"a":1}');
    const legacy = path.join(NODES_DIR, name);
    const dest = husk(id.nodeId); // forces an entry-by-entry merge
    let helped = false; let listings = 0;
    const result = patchFs('readdirSync', (orig) => function (p, ...rest) {
      const names = orig.call(fs, p, ...rest);
      if (!helped && p === legacy && ++listings === 2) { // the 2nd listing is the merge's own, after the conflict check's
        helped = true; // the other process finishes the whole move while this one holds the list
        for (const n of names) fs.renameSync(path.join(legacy, n), path.join(dest, n));
        fs.rmdirSync(legacy);
        fs.symlinkSync(path.join('by-id', id.nodeId), legacy, 'dir');
      }
      return names;
    }, () => cfg.migrateNodeDir(name));
    assert.ok(helped, 'the other process ran');
    assert.strictEqual(result, 'already');
    for (const f of ['identity.json', 'aaa.json', path.join('cmbs', 'x.json')]) assert.ok(exists(path.join(dest, f)), `${f} survived`);
    assert.strictEqual(JSON.parse(read(path.join(dest, 'identity.json'))).privateKey, id.privateKey);
  });
});

describe('F11 with real processes: several starters at once never make a second identity', () => {
  /** Four processes call loadIdentity({ name }) at the same moment on a 0.13 node, in a state root of their own. */
  async function race({ withHusk }) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-race-'));
    try {
      const state = path.join(root, 'state');
      const nodes = path.join(state, 'nodes');
      const name = 'racing-agent';
      const id = makeIdentity(name);
      fs.mkdirSync(path.join(nodes, name, 'cmbs'), { recursive: true });
      for (let i = 0; i < 30; i++) fs.writeFileSync(path.join(nodes, name, 'cmbs', `c${i}.json`), '{}');
      fs.writeFileSync(path.join(nodes, name, 'identity.json'), JSON.stringify(id, null, 2));
      if (withHusk) { fs.mkdirSync(path.join(nodes, 'by-id', id.nodeId), { recursive: true }); fs.writeFileSync(path.join(nodes, 'by-id', id.nodeId, 'lock.pid'), '999999\n'); }
      const code = `
        const c = require(${JSON.stringify(path.resolve(__dirname, '../lib/config.js'))});
        process.stdin.once('data', () => {
          try { const i = c.loadIdentity({ name: ${JSON.stringify(name)} }); console.log(JSON.stringify({ id: i.nodeId, key: i.privateKey })); }
          catch (e) { console.log(JSON.stringify({ error: e.name + ': ' + String(e.message).split('\\n')[0].slice(0, 200) })); }
          process.exit(0);
        });
        console.log('ready');`;
      const kids = Array.from({ length: 4 }, () => spawn(process.execPath, ['-e', code], { env: { ...process.env, SYM_STATE_DIR: state }, stdio: ['pipe', 'pipe', 'inherit'] }));
      await Promise.all(kids.map((k) => new Promise((resolve) => k.stdout.once('data', resolve))));
      const done = kids.map((k) => new Promise((resolve) => { let b = ''; k.stdout.on('data', (d) => { b += d; }); k.on('exit', () => resolve(JSON.parse(b.trim().split('\n').pop()))); }));
      kids.forEach((k) => k.stdin.write('go\n'));
      const outcomes = await Promise.all(done);
      const kept = JSON.parse(fs.readFileSync(path.join(nodes, 'by-id', id.nodeId, 'identity.json'), 'utf8'));
      return { id, outcomes, kept };
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  }

  for (const withHusk of [false, true]) {
    it(`${withHusk ? 'with a by-id dir that already exists' : 'plain'}: every starter that loads gets the original agent, and the key survives`, async () => {
      let loaded = 0;
      for (let round = 0; round < 5; round++) {
        const { id, outcomes, kept } = await race({ withHusk });
        assert.strictEqual(kept.privateKey, id.privateKey, 'the original private key is still the one on disk');
        for (const o of outcomes) {
          if (o.error) continue; // a starter may be told to start again; it must not become somebody else
          loaded++;
          assert.strictEqual(o.id, id.nodeId, 'the same nodeId');
          assert.strictEqual(o.key, id.privateKey, 'the same key');
        }
      }
      assert.ok(loaded >= 5, `starters loaded the agent (${loaded}): the test measured something`);
    });
  }
});

describe('F13: the live-lock fallback checks the tombstone', () => {
  it('an identity exported away does not load from an unmoved 0.13 directory a live process holds', async () => {
    const name = uniq('f13');
    const id = legacyNode(name);
    const dir = path.join(NODES_DIR, name);
    const child = spawn(process.execPath, ['-e', `
      const c = require(${JSON.stringify(path.resolve(__dirname, '../lib/config.js'))});
      c.acquireIdentityLock(${JSON.stringify(name)}, { dir: ${JSON.stringify(dir)} });
      console.log('held'); setInterval(() => {}, 1000);`], { stdio: ['ignore', 'pipe', 'inherit'] });
    try {
      await new Promise((resolve, reject) => { child.stdout.once('data', resolve); child.once('exit', () => reject(new Error('lock holder exited'))); });
      assert.strictEqual(cfg.migrateNodeDir(name), 'skipped-live', 'setup: a live process holds the old directory');
      assert.strictEqual(cfg.loadIdentity({ name }).nodeId, id.nodeId, 'not tombstoned: it loads in place');
      put(path.join(cfg.nodeDirById(id.nodeId), cfg.TOMBSTONE), JSON.stringify({ movedAt: Date.now() }));
      assert.throws(() => cfg.loadIdentity({ name }), (e) => e instanceof IdentityTombstonedError);
    } finally { child.kill(); }
  });
});

describe('T9: the checks measure something', () => {
  it('assertMoved fails a run that moved nothing, and a populated run passes it', () => {
    const name = uniq('t9');
    legacyNode(name);
    assertMoved(cfg.migrateIdentities());
    assert.throws(() => assertMoved(cfg.migrateIdentities()), /measured nothing/, 'a second pass moves nothing and must not satisfy the guard');
  });
});
