'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * 0.14.3: the state of an identity is read from records committed in one atomic step, never inferred from
 * whatever is at a path.
 *
 * An independent review (R1) of the 0.14.3 candidate (632b95d) proved, by running them, that a partial
 * destination, an unreadable index, a node directory without identity.json and a stale lock's content were
 * each read as a state of the identity, and that each patch for one of them had made another. The design that
 * replaces them (lib/config.js):
 *   - a 0.13 directory is COPIED to a staging directory beside its by-id destination, identity.json last,
 *     synced, verified, and installed by ONE rename; the 0.13 directory is then set aside, never deleted;
 *   - a name is claimed by an exclusive create of its index entry, after the identity is installed;
 *   - an index entry is "absent" only on ENOENT; a mint happens only when nothing on the host is a trace of
 *     the name; a stale lock is removed only by the one process holding the right to remove that lock.
 * Every test here fails on 632b95d and passes on this branch; each names the R1 finding it holds.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
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
const ASIDE = cfg.LEGACY_ASIDE || '.legacy-0.13';

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

/** A 0.13 node: nodes/<name>/ with identity.json and a small store. */
function legacyNode(name, { where = path.join(NODES_DIR, name), identity = makeIdentity(name), files = 6 } = {}) {
  put(path.join(where, 'identity.json'), JSON.stringify(identity, null, 2));
  for (let i = 0; i < files; i++) put(path.join(where, 'cmbs', `c${i}.json`), JSON.stringify({ i, pad: 'x'.repeat(300) }));
  put(path.join(where, 'inbox.json'), '{"seq":7}');
  return identity;
}

/**
 * Every path under `dir` with its kind and bytes (links followed), sorted. The runtime files a start leaves in a
 * node directory (its lock, a claim to break one, the temp file a lock is written under before it is linked into
 * place) are not the node's data and are left out: a process killed at the wrong moment leaves one behind.
 */
function treeOf(dir) {
  const out = [];
  const walk = (d, rel) => {
    for (const e of fs.readdirSync(d).sort()) {
      if (!rel && (e === 'lock.pid' || e.startsWith('lock.pid.') || (e.startsWith('.lock.pid') && e.endsWith('.tmp')))) continue;
      const p = path.join(d, e); const r = rel ? `${rel}/${e}` : e;
      const st = fs.statSync(p);
      if (st.isDirectory()) { out.push(`D ${r}`); walk(p, r); } else out.push(`F ${r} ${crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex')}`);
    }
  };
  walk(dir, '');
  return out;
}

/** Installed identities (non-dot by-id entries) whose name is `name`. */
function identitiesNamed(name) {
  const found = [];
  const roots = [path.join(NODES_DIR, 'by-id'), process.env.SYM_IDENTITY_DIR && path.join(process.env.SYM_IDENTITY_DIR, 'by-id')].filter(Boolean);
  for (const root of roots) {
    let ds = []; try { ds = fs.readdirSync(root); } catch { continue; }
    for (const d of ds) {
      if (d.startsWith('.')) continue;
      try { if (JSON.parse(read(path.join(root, d, 'identity.json'))).name === name) found.push(d); } catch { /* */ }
    }
  }
  return [...new Set(found)];
}

function withIdentityDir(fn) {
  const prev = process.env.SYM_IDENTITY_DIR;
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-idroot-'));
  process.env.SYM_IDENTITY_DIR = root;
  const done = () => {
    if (prev === undefined) delete process.env.SYM_IDENTITY_DIR; else process.env.SYM_IDENTITY_DIR = prev;
    fs.rmSync(root, { recursive: true, force: true });
  };
  let r;
  try { r = fn(root); } catch (e) { done(); throw e; }
  if (r && typeof r.then === 'function') return r.finally(done);
  done();
  return r;
}

/** Replace fs.<fn> for the duration of `body`. */
function patchFs(fn, wrap, body) {
  const original = fs[fn];
  fs[fn] = wrap(original);
  try { return body(); } finally { fs[fn] = original; }
}

/** Replace several fs functions at once: `wraps` maps a name to (original) => replacement. */
function patchMany(wraps, body) {
  const originals = {};
  for (const [k, w] of Object.entries(wraps)) { originals[k] = fs[k]; fs[k] = w(originals[k]); }
  try { return body(); } finally { for (const k of Object.keys(originals)) fs[k] = originals[k]; }
}

const MUTATING = ['renameSync', 'copyFileSync', 'mkdirSync', 'writeFileSync', 'openSync', 'unlinkSync', 'rmdirSync', 'rmSync', 'symlinkSync', 'linkSync', 'chmodSync', 'writeSync', 'fsyncSync'];
class Injected extends Error {}

/** Run `body`, throwing an Injected error at the k-th mutating fs call (1-based); returns the number of calls made. */
function failAt(k, body) {
  let n = 0;
  const wraps = {};
  for (const fn of MUTATING) {
    wraps[fn] = (orig) => function (...a) {
      if (fn === 'openSync' && !/[wax+]/.test(String(a[1] || 'r'))) return orig.apply(fs, a); // a read is not a step
      if (++n === k) throw new Injected(`injected at step ${k} (${fn})`);
      return orig.apply(fs, a);
    };
  }
  // Whatever the body throws once a step failed (the failure, or what the code made of it) is the crash; the
  // state it leaves is what the caller checks.
  try { patchMany(wraps, body); } catch { /* the crash */ }
  return n;
}

describe('R1-1: a migration interrupted at any step changes nothing in the 0.13 directory, and the next start loads the whole store', () => {
  for (const withHusk of [false, true]) {
    it(`every step of the migration${withHusk ? ', over a by-id directory holding a stale lock (the 0.14.0-0.14.2 husk)' : ''}`, () => {
      // 632b95d moved the store entry by entry: an interruption left part of it in by-id and the rest in nodes/<name>,
      // and the copy across volumes deleted the source as it went (R1 measured files missing after kill -9).
      const probe = uniq('r11-probe');
      legacyNode(probe);
      const steps = failAt(Infinity, () => cfg.migrateNodeDir(probe));
      assert.ok(steps > 10, `the migration took ${steps} steps: the test measures something`);
      let checked = 0;
      for (let k = 1; k <= steps; k++) {
        const name = uniq('r11');
        const id = legacyNode(name);
        if (withHusk) put(path.join(cfg.nodeDirById(id.nodeId), 'lock.pid'), '2147483646\n');
        const before = treeOf(path.join(NODES_DIR, name));
        failAt(k, () => cfg.migrateNodeDir(name));
        // The 0.13 directory: in place and byte-identical, or set aside byte-identical with the link in its place.
        const legacy = path.join(NODES_DIR, name);
        const where = isLink(legacy) ? path.join(NODES_DIR, ASIDE, name) : legacy;
        if (!exists(where)) assert.fail(`step ${k}: the 0.13 directory is no longer at nodes/${name} and was not set aside (moved or deleted, not kept)`);
        assert.deepStrictEqual(treeOf(where), before, `step ${k}: the 0.13 directory (${path.relative(NODES_DIR, where)}) is byte-identical`);
        // What a 0.13 rollback reads: nodes/<name>/identity.json is the original key.
        assert.strictEqual(JSON.parse(read(path.join(legacy, 'identity.json'))).privateKey, id.privateKey, `step ${k}: a 0.13 reader still finds the key at nodes/<name>`);
        const loaded = cfg.loadIdentity({ name });
        assert.strictEqual(loaded.nodeId, id.nodeId, `step ${k}: the same agent`);
        assert.strictEqual(loaded.privateKey, id.privateKey, `step ${k}: the same key`);
        const dest = cfg.nodeDirById(id.nodeId);
        assert.deepStrictEqual(treeOf(dest).filter((l) => !l.includes(' identity.json') && !l.includes(` ${cfg.COMMIT_MARK || '.sym-commit'}`)),
          before.filter((l) => !l.includes(' identity.json')), `step ${k}: the whole store is in by-id`);
        assert.deepStrictEqual(identitiesNamed(name), [id.nodeId], `step ${k}: exactly one identity`);
        checked++;
      }
      assert.strictEqual(checked, steps);
    });
  }
});

describe('R1-2: a node directory without its identity is never handed to a new one', () => {
  for (const pinned of [false, true]) {
    it(`SYM_IDENTITY_DIR's volume not mounted at boot (${pinned ? 'pinned' : 'by name'}): the start halts, mints nothing, touches nothing; mounted, the agent loads with its store`, () => {
      withIdentityDir((mnt) => {
        const name = uniq('r12');
        const vol = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-keyvol-'));
        const id = makeIdentity(name);
        put(path.join(vol, name, 'identity.json'), JSON.stringify(id, null, 2)); // the key lives on the volume
        for (let i = 0; i < 3; i++) put(path.join(NODES_DIR, name, 'cmbs', `c${i}.json`), `{"i":${i}}`); // the store
        const store = treeOf(path.join(NODES_DIR, name));
        const opts = pinned ? { name, nodeId: id.nodeId, create: false } : { name };
        assert.throws(() => cfg.loadIdentity(opts), (e) => (pinned ? e.code === 'EIDENTITYABSENT' : e instanceof IdentityHaltError) && /holds a node's files/.test(e.message) && /mounted/.test(e.message));
        assert.deepStrictEqual(identitiesNamed(name), [], 'nothing was minted');
        assert.strictEqual(cfg.nodeIdForName(name), null, 'the name was not claimed');
        assert.deepStrictEqual(treeOf(path.join(NODES_DIR, name)), store, 'the store is where it was');
        // mount it
        fs.rmSync(mnt, { recursive: true, force: true }); fs.renameSync(vol, mnt);
        const loaded = cfg.loadIdentity(opts);
        assert.strictEqual(loaded.privateKey, id.privateKey);
        assert.ok(exists(path.join(cfg.nodeDirById(id.nodeId), 'cmbs', 'c2.json')), 'with its store');
      });
    });
  }
});

describe('R1-3: what a 0.13 node kept behind a link is followed and copied', () => {
  it('nodes/<name> a link to the node\'s directory on another volume: the original loads, the volume is untouched', () => {
    const name = uniq('r13-dir');
    const durable = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sym-durable-')), name);
    const id = legacyNode(name, { where: durable });
    const before = treeOf(durable);
    fs.mkdirSync(NODES_DIR, { recursive: true });
    fs.symlinkSync(durable, path.join(NODES_DIR, name), 'dir');
    for (const opts of [{ name }, { name, nodeId: id.nodeId, create: false }]) {
      const loaded = cfg.loadIdentity(opts);
      assert.strictEqual(loaded.privateKey, id.privateKey, JSON.stringify(Object.keys(opts)));
    }
    assert.deepStrictEqual(treeOf(durable), before, 'the durable directory is byte-unchanged');
    assert.ok(exists(path.join(cfg.nodeDirById(id.nodeId), 'cmbs', 'c5.json')), 'the store was copied');
    assert.deepStrictEqual(identitiesNamed(name), [id.nodeId]);
  });

  it('identity.json a RELATIVE link to a key file elsewhere: the original loads, and the installed identity is a file, not a link that now leads nowhere', () => {
    const name = uniq('r13-rel');
    const id = makeIdentity(name);
    put(path.join(cfg.SYM_DIR, 'keys', `${name}.json`), JSON.stringify(id), 0o600);
    put(path.join(NODES_DIR, name, 'cmbs', 'x.json'), '{}');
    fs.symlinkSync(`../../keys/${name}.json`, path.join(NODES_DIR, name, 'identity.json'));
    const loaded = cfg.loadIdentity({ name });
    assert.strictEqual(loaded.privateKey, id.privateKey);
    const installed = path.join(cfg.nodeDirById(id.nodeId), 'identity.json');
    assert.ok(!isLink(installed), 'a file');
    assert.strictEqual(JSON.parse(read(installed)).privateKey, id.privateKey);
    assert.strictEqual(JSON.parse(read(path.join(cfg.SYM_DIR, 'keys', `${name}.json`))).privateKey, id.privateKey, 'the key file it led to is untouched');
  });
});

describe('the staged commit: what it checks before the one rename', () => {
  it('a copy that does not read back as its source is not installed, and the source is untouched', () => {
    const name = uniq('verify');
    const id = legacyNode(name);
    const before = treeOf(path.join(NODES_DIR, name));
    assert.throws(() => patchFs('copyFileSync', (o) => function (a, b, ...r) {
      const out = o.call(fs, a, b, ...r);
      if (String(b).endsWith('c3.json')) fs.appendFileSync(b, ' '); // a copy that came out different
      return out;
    }, () => cfg.migrateNodeDir(name)), /does not match/);
    assert.ok(!exists(cfg.nodeDirById(id.nodeId)), 'nothing installed');
    assert.deepStrictEqual(treeOf(path.join(NODES_DIR, name)), before, 'the source is untouched');
    assert.strictEqual(cfg.nodeIdForName(name), null);
    assert.strictEqual(cfg.loadIdentity({ name }).privateKey, id.privateKey, 'the next start copies it right');
  });

  it('a directory inside the 0.13 node that is a relative link is copied as the directory it leads to', () => {
    const name = uniq('sublink');
    const id = makeIdentity(name);
    put(path.join(NODES_DIR, name, 'identity.json'), JSON.stringify(id));
    put(path.join(NODES_DIR, `${name}-store`, 'x.json'), '{"x":1}');
    fs.symlinkSync(`../${name}-store`, path.join(NODES_DIR, name, 'cmbs'), 'dir');
    cfg.loadIdentity({ name });
    const cmbs = path.join(cfg.nodeDirById(id.nodeId), 'cmbs');
    assert.ok(!isLink(cmbs) && read(path.join(cmbs, 'x.json')) === '{"x":1}', 'a real directory holding the files');
  });

  it('a by-id husk whose lock a live process holds is not replaced: EIDENTITYLOCK, nothing changed', async () => {
    const name = uniq('husk-live');
    const id = legacyNode(name);
    const husk = cfg.nodeDirById(id.nodeId);
    fs.mkdirSync(husk, { recursive: true });
    put(path.join(husk, 'inbox.json'), '{"seq":99}');
    const child = spawn(process.execPath, ['-e', `
      const c = require(${JSON.stringify(path.join(LIB, 'config.js'))});
      c.acquireIdentityLock('h', { dir: ${JSON.stringify(husk)} }); console.log('held'); setInterval(() => {}, 1000);`], { stdio: ['ignore', 'pipe', 'inherit'] });
    try {
      await new Promise((resolve, reject) => { child.stdout.once('data', resolve); child.once('exit', () => reject(new Error('holder exited'))); });
      assert.throws(() => cfg.loadIdentity({ name }), (e) => e.code === 'EIDENTITYLOCK');
      assert.strictEqual(read(path.join(husk, 'inbox.json')), '{"seq":99}', 'the husk is where it was');
      assert.ok(!exists(path.join(husk, 'identity.json')));
      assert.ok(!isLink(path.join(NODES_DIR, name)), 'the 0.13 directory is where it was');
    } finally { child.kill('SIGKILL'); await new Promise((r) => child.once('exit', r)); }
  });

  it('a staging directory of a live process is left alone; one of a process that is gone is cleared', () => {
    const name = uniq('partials');
    const id = legacyNode(name);
    const live = path.join(NODES_DIR, 'by-id', `.${id.nodeId}.partial-${process.ppid}-aaaaaaaa`); // our parent is alive
    const dead = path.join(NODES_DIR, 'by-id', `.${id.nodeId}.partial-2147483646-bbbbbbbb`);
    put(path.join(live, 'x'), '1'); put(path.join(dead, 'x'), '1');
    cfg.loadIdentity({ name });
    assert.ok(exists(live), 'a live process\'s staging is not touched');
    assert.ok(!exists(dead), 'a dead one\'s is cleared');
    fs.rmSync(live, { recursive: true, force: true });
  });
});

describe('R1-4: a stale identity lock is removed only if it is still the lock judged stale', () => {
  it('a start that judged a dead holder\'s lock stale does not remove the lock another start took meanwhile', async () => {
    // 632b95d read the lock, judged it stale, unlinked whatever was there, and created its own: with six starters at a
    // SIGKILLed holder's lock, 4 of 8 rounds had two or more simultaneous holders.
    const name = uniq('r14');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-r14-'));
    const lockPath = path.join(dir, 'lock.pid');
    put(lockPath, '2147483646\n{"start":"Thu Jan  1 00:00:00 1970","createdAt":1}\n'); // dead holder
    const other = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
    try {
      const otherLock = `${other.pid}\n${JSON.stringify({ start: cfg.processStartTime(other.pid), createdAt: Date.now() })}\n`;
      let raced = false;
      // The other start runs after this one READ the stale lock (its judgement) and before the first thing this one
      // writes in the lock's directory (632b95d: its unlink of the lock; here: its claim to remove that lock): it
      // removes the stale lock and takes its own.
      let judged = false;
      const inDir = (p) => path.dirname(String(p)) === dir;
      const race = (p) => { if (judged && !raced && inDir(p)) { raced = true; fs.unlinkSync(lockPath); fs.writeFileSync(lockPath, otherLock); } };
      let err = null;
      patchMany({
        readFileSync: (orig) => function (p, ...rest) { if (String(p) === lockPath) judged = true; return orig.call(fs, p, ...rest); },
        unlinkSync: (orig) => function (p, ...rest) { race(p); return orig.call(fs, p, ...rest); },
        linkSync: (orig) => function (a, b, ...rest) { race(b); return orig.call(fs, a, b, ...rest); },
        openSync: (orig) => function (p, flags, ...rest) {
          if (/[wax+]/.test(String(flags || 'r'))) race(p); else if (String(p) === lockPath) judged = true;
          return orig.call(fs, p, flags, ...rest);
        },
      }, () => {
        try { cfg.acquireIdentityLock(name, { dir }); } catch (e) { err = e; }
      });
      assert.ok(raced, 'the other start ran between the judgement and the removal');
      assert.ok(err && err.code === 'EIDENTITYLOCK' && err.holderPid === other.pid, `refused, naming the live holder (got ${err && err.code})`);
      assert.strictEqual(read(lockPath), otherLock, 'the other start\'s lock is intact');
      assert.deepStrictEqual(fs.readdirSync(dir).filter((n) => n !== 'lock.pid'), [], 'no claim file left behind');
    } finally { other.kill('SIGKILL'); fs.rmSync(dir, { recursive: true, force: true }); }
  });
});

describe('R1-6: two first starts of a new name never both win', () => {
  it('a second start that runs while the first is between installing its identity and claiming the name gets the same agent', () => {
    const name = uniq('r16');
    let ran = false; let checking = false; let second = null;
    const named = () => {
      try {
        return fs.readdirSync(path.join(NODES_DIR, 'by-id')).some((d) => !d.startsWith('.') &&
          (() => { try { return JSON.parse(fs.readFileSync(path.join(NODES_DIR, 'by-id', d, 'identity.json'), 'utf8')).name === name; } catch { return false; } })());
      } catch { return false; }
    };
    const hook = (orig) => function (...a) {
      const r = orig.apply(fs, a);
      if (!ran && !checking) {
        checking = true;
        try { if (named()) { ran = true; try { second = cfg.loadIdentity({ name }); } catch (e) { second = e; } } } finally { checking = false; }
      }
      return r;
    };
    const first = patchMany(Object.fromEntries(MUTATING.map((k) => [k, hook])), () => cfg.loadIdentity({ name }));
    assert.ok(ran, 'the second start ran inside the first one\'s mint');
    assert.ok(second && second.nodeId, `the second start loaded: ${second && second.message}`);
    assert.strictEqual(second.nodeId, first.nodeId, 'one agent');
    assert.strictEqual(second.privateKey, first.privateKey);
    assert.strictEqual(cfg.nodeIdForName(name), first.nodeId);
    assert.deepStrictEqual(identitiesNamed(name), [first.nodeId], 'one identity on disk');
  });

  it('three real processes starting one new name at once: one agent, every round', async () => {
    let rounds = 0;
    for (let round = 0; round < 4; round++) {
      const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-r16-'));
      try {
        const state = path.join(root, 'state');
        const code = `const c = require(${JSON.stringify(path.join(LIB, 'config.js'))});
          process.stdin.once('data', () => { try { const i = c.loadIdentity({ name: 'fresh' }); console.log(JSON.stringify({ id: i.nodeId })); }
            catch (e) { console.log(JSON.stringify({ error: e.code || String(e.message).split('\\n')[0] })); } process.exit(0); }); console.log('ready');`;
        const kids = Array.from({ length: 3 }, () => spawn(process.execPath, ['-e', code], { env: { ...process.env, SYM_STATE_DIR: state }, stdio: ['pipe', 'pipe', 'inherit'] }));
        await Promise.all(kids.map((k) => new Promise((r) => k.stdout.once('data', r))));
        const outs = kids.map((k) => new Promise((r) => { let b = ''; k.stdout.on('data', (d) => { b += d; }); k.on('exit', () => r(JSON.parse(b.trim().split('\n').pop()))); }));
        kids.forEach((k) => k.stdin.write('go\n'));
        const res = await Promise.all(outs);
        assert.deepStrictEqual(res.filter((o) => o.error), [], `round ${round}: every start loaded`);
        assert.strictEqual(new Set(res.map((o) => o.id)).size, 1, `round ${round}: one agent, not ${new Set(res.map((o) => o.id)).size}`);
        const installed = fs.readdirSync(path.join(state, 'nodes', 'by-id')).filter((d) => !d.startsWith('.'));
        assert.deepStrictEqual(installed, [res[0].id], `round ${round}: one identity on disk`);
        rounds++;
      } finally { fs.rmSync(root, { recursive: true, force: true }); }
    }
    assert.strictEqual(rounds, 4);
  });
});

describe('R1-7: an index entry is "absent" only when there is none', () => {
  function made() {
    const name = uniq('r17');
    const orig = cfg.loadIdentity({ name });
    return { name, orig, idx: indexFile(name), link: path.join(NODES_DIR, name) };
  }

  it('deleted, and the compat link too: the original is found and the name claimed for it again (632b95d made a new identity)', () => {
    const { name, orig, idx, link } = made();
    fs.unlinkSync(idx); fs.unlinkSync(link);
    assert.strictEqual(cfg.loadIdentity({ name }).nodeId, orig.nodeId);
    assert.strictEqual(cfg.nodeIdForName(name), orig.nodeId);
    assert.deepStrictEqual(identitiesNamed(name), [orig.nodeId]);
  });

  for (const how of ['empty', 'not json', 'another name']) {
    it(`${how}, and no compat link: the start halts, naming where the identity is; nothing is minted`, () => {
      const { name, orig, idx, link } = made();
      fs.writeFileSync(idx, how === 'empty' ? '' : how === 'not json' ? '{"nodeId":' : JSON.stringify({ name: 'someone-else', nodeId: orig.nodeId }));
      fs.unlinkSync(link);
      assert.throws(() => cfg.loadIdentity({ name }), (e) => e instanceof IdentityHaltError && e.message.includes(orig.nodeId) && !/remove .*by-name/.test(e.message));
      assert.throws(() => cfg.loadIdentity({ name, create: false }), IdentityHaltError);
      assert.deepStrictEqual(identitiesNamed(name), [orig.nodeId], 'no second identity');
    });
  }

  (posix && process.getuid && process.getuid() !== 0 ? it : it.skip)('unreadable (mode 000): halts, nothing minted', () => {
    const { name, orig, idx, link } = made();
    fs.chmodSync(idx, 0); fs.unlinkSync(link);
    try {
      assert.throws(() => cfg.loadIdentity({ name }), IdentityHaltError);
      assert.deepStrictEqual(identitiesNamed(name), [orig.nodeId]);
    } finally { fs.chmodSync(idx, 0o644); }
  });

  it('a read error that is not ENOENT (EMFILE): halts, nothing minted', () => {
    const { name, orig, idx, link } = made();
    fs.unlinkSync(link);
    patchFs('readFileSync', (o) => function (p, ...a) {
      if (String(p) === idx) throw Object.assign(new Error('EMFILE: too many open files'), { code: 'EMFILE' });
      return o.call(fs, p, ...a);
    }, () => { assert.throws(() => cfg.loadIdentity({ name }), IdentityHaltError); });
    assert.deepStrictEqual(identitiesNamed(name), [orig.nodeId]);
    assert.strictEqual(cfg.loadIdentity({ name }).nodeId, orig.nodeId, 'once it reads, the same agent');
  });

  it('index writes are synced: the entry is created exclusively and fsynced before it is relied on', () => {
    const name = uniq('r17-sync');
    const synced = [];
    const opened = new Map();
    patchMany({
      openSync: (o) => function (p, ...a) { const fd = o.call(fs, p, ...a); opened.set(fd, String(p)); return fd; },
      fsyncSync: (o) => function (fd) { synced.push(opened.get(fd)); return o.call(fs, fd); },
    }, () => cfg.loadIdentity({ name }));
    const dir = path.dirname(indexFile(name));
    assert.ok(synced.some((p) => p && p.startsWith(dir + path.sep) && p.includes(encodeURIComponent(name))), 'the entry\'s content was fsynced');
    if (posix) assert.ok(synced.includes(dir), 'and the by-name directory');
  });
});

describe('R1-8: an export interrupted before its bundle is durable is resumable or abortable, never a false "exported"', () => {
  async function made(name) {
    const id = cfg.loadIdentity({ name });
    put(path.join(cfg.nodeDirById(id.nodeId), 'cmbs', 'm.json'), '{"memory":1}');
    return id;
  }
  const out = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sym-bundle-')), 'node.bundle');

  it('the start is refused saying the export did not finish (not "exported to another host"), and running the export again finishes it', async () => {
    const name = uniq('r18');
    const id = await made(name);
    const file = out();
    const toHostKey = relocation.hostKey().publicKey;
    assert.throws(() => patchFs('renameSync', (o) => function (a, b) {
      if (String(b) === file) throw Object.assign(new Error('EIO: crash before the bundle was durable'), { code: 'EIO' });
      return o.call(fs, a, b);
    }, () => relocation.exportNode({ name, out: file, toHostKey })), /EIO/);
    assert.ok(!exists(file), 'no bundle');
    assert.throws(() => cfg.loadIdentity({ name }), (e) => e.code === 'EIDENTITYEXPORTING' && !/exported to another host/.test(e.message));
    assert.strictEqual(cfg.readTombstone(id.nodeId), null, 'not tombstoned: nothing was moved');
    const r = relocation.exportNode({ name, out: file, toHostKey });
    assert.strictEqual(r.nodeId, id.nodeId);
    assert.ok(exists(file), 'the bundle');
    assert.ok(cfg.readTombstone(id.nodeId), 'tombstoned now');
    assert.strictEqual(JSON.parse(read(path.join(cfg.identityDirById(id.nodeId), 'identity.json'))).privateKey, null, 'the source lost the key');
  });

  it('abortExport removes the bundle it wrote and the intent: the node starts here again', async () => {
    const name = uniq('r18-abort');
    const id = await made(name);
    const file = out();
    const toHostKey = relocation.hostKey().publicKey;
    // interrupted after the bundle is durable and before the tombstone
    assert.throws(() => patchFs('openSync', (o) => function (p, ...a) {
      if (String(p).includes(cfg.TOMBSTONE)) throw Object.assign(new Error('EIO: crash before the tombstone'), { code: 'EIO' });
      return o.call(fs, p, ...a);
    }, () => relocation.exportNode({ name, out: file, toHostKey })), /EIO/);
    assert.ok(exists(file), 'the bundle is durable');
    assert.throws(() => cfg.loadIdentity({ name }), (e) => e.code === 'EIDENTITYEXPORTING');
    const a = relocation.abortExport({ name });
    assert.strictEqual(a.aborted, true);
    assert.strictEqual(a.bundleRemoved, true);
    assert.ok(!exists(file), 'the bundle is gone');
    assert.strictEqual(cfg.loadIdentity({ name }).privateKey, id.privateKey, 'the node starts again, with its key');
  });
});

describe('R1-9: with SYM_IDENTITY_DIR the tombstone lives beside the key, and an import writes the key only there', () => {
  it('an export killed after its bundle is durable: a rebuilt node directory does not bring a second live copy back; exporting again finishes the scrub', () => {
    withIdentityDir(() => {
      const name = uniq('r19');
      const id = cfg.loadIdentity({ name });
      const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sym-bundle-')), 'node.bundle');
      const toHostKey = relocation.hostKey().publicKey;
      assert.throws(() => patchFs('openSync', (o) => function (p, ...a) {
        if (/identity\.json\.\d+\.tmp$/.test(String(p))) throw Object.assign(new Error('EIO: crash before the scrub'), { code: 'EIO' });
        return o.call(fs, p, ...a);
      }, () => relocation.exportNode({ name, out: file, toHostKey })), /EIO/);
      assert.ok(exists(file), 'the bundle is durable');
      fs.rmSync(cfg.nodeDirById(id.nodeId), { recursive: true, force: true }); // the disposable node dir is rebuilt
      assert.throws(() => cfg.loadIdentity({ name, nodeId: id.nodeId, create: false }), (e) => e.code === 'EIDENTITYTOMBSTONED');
      assert.throws(() => cfg.loadIdentity({ name }), (e) => e.code === 'EIDENTITYTOMBSTONED');
      const again = relocation.exportNode({ name, out: file + '2', toHostKey });
      assert.ok(again.resumed, 'the interrupted export was finished');
      assert.strictEqual(JSON.parse(read(path.join(cfg.identityDirById(id.nodeId), 'identity.json'))).privateKey, null, 'the source no longer holds the key');
    });
  });

  modeTest('import: directories 0700, key files 0600, and the private key only in the identity directory', () => {
    withIdentityDir(() => {
      const name = uniq('r19-imp');
      const id = cfg.loadIdentity({ name });
      put(path.join(cfg.nodeDirById(id.nodeId), 'cmbs', 'deep', 'm.json'), '{"memory":1}');
      put(path.join(cfg.nodeDirById(id.nodeId), 'e2e-keypair.json'), '{}', 0o600);
      const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sym-bundle-')), 'node.bundle');
      relocation.exportNode({ name, out: file, toHostKey: relocation.hostKey().publicKey });
      // another host: this host's copies of the node removed
      fs.rmSync(cfg.nodeDirById(id.nodeId), { recursive: true, force: true });
      fs.rmSync(cfg.identityDirById(id.nodeId), { recursive: true, force: true });
      relocation.importNode({ from: file, expect: { nodeId: id.nodeId, key: id.publicKey } });
      const nd = cfg.nodeDirById(id.nodeId); const idd = cfg.identityDirById(id.nodeId);
      assert.strictEqual(modeOf(nd), 0o700);
      assert.strictEqual(modeOf(path.join(nd, 'cmbs')), 0o700);
      assert.strictEqual(modeOf(path.join(nd, 'cmbs', 'deep')), 0o700);
      assert.strictEqual(modeOf(path.join(nd, 'e2e-keypair.json')), 0o600);
      assert.strictEqual(modeOf(idd), 0o700);
      assert.strictEqual(modeOf(path.join(idd, 'identity.json')), 0o600);
      assert.ok(!exists(path.join(nd, 'identity.json')), 'no private key in the disposable node directory');
      assert.strictEqual(cfg.loadIdentity({ name, nodeId: id.nodeId, create: false }).privateKey, id.privateKey);
    });
  });
});

describe('R1-10: a crash after the commit never leaves a state read as "new"', () => {
  it('the compat link cannot be made: the 0.13 directory stays in place for a 0.13 rollback, and the next start finishes', () => {
    // 632b95d had already moved everything; the failed link left nodes/<name> empty or absent, and a 0.13 build reading
    // it would make a new identity.
    const name = uniq('r110');
    const id = legacyNode(name);
    patchFs('symlinkSync', (o) => function (target, p, ...a) {
      if (String(p).startsWith(NODES_DIR + path.sep) && !String(p).includes(`${path.sep}by-id${path.sep}`)) throw Object.assign(new Error('EPERM: injected'), { code: 'EPERM' });
      return o.call(fs, target, p, ...a);
    }, () => { try { cfg.migrateNodeDir(name); } catch { /* a failure is fine; what it leaves is the test */ } });
    assert.strictEqual(JSON.parse(read(path.join(NODES_DIR, name, 'identity.json'))).privateKey, id.privateKey, 'a 0.13 reader still finds the key');
    assert.ok(exists(path.join(NODES_DIR, name, 'cmbs', 'c0.json')), 'and its store');
    const loaded = cfg.loadIdentity({ name });
    assert.strictEqual(loaded.privateKey, id.privateKey);
    assert.ok(isLink(path.join(NODES_DIR, name)), 'finished: the link');
  });

  it('a new identity installed and the start killed before it claimed the name: the next start finds that identity, not a new one', () => {
    const name = uniq('r110-mint');
    const byName = path.join(NODES_DIR, 'by-name');
    let thrown = false;
    const stop = (o) => function (p, ...a) {
      if (!thrown && String(p).startsWith(byName + path.sep) && (o !== fs.readFileSync)) { thrown = true; throw Object.assign(new Error('killed before the claim'), { code: 'EINTR' }); }
      return o.call(fs, p, ...a);
    };
    patchMany({ writeFileSync: stop, openSync: (o) => function (p, flags, ...a) { return /[wa]/.test(String(flags || 'r')) ? stop(o)(p, flags, ...a) : o.call(fs, p, flags, ...a); } },
      () => { try { cfg.loadIdentity({ name }); } catch { /* killed */ } });
    assert.ok(thrown, 'the start was stopped at the claim');
    const made = identitiesNamed(name);
    assert.strictEqual(made.length, 1, 'its identity was installed');
    assert.strictEqual(cfg.loadIdentity({ name }).nodeId, made[0], 'the next start loads it');
    assert.deepStrictEqual(identitiesNamed(name), made, 'and makes no other');
  });
});

describe('R1-11: names Windows cannot hold, and Windows junctions', () => {
  it('validateName refuses the names Windows reserves or cannot hold (the rule of mesh-channel\'s nodeNameProblem)', () => {
    for (const bad of ['CON', 'con', 'NUL', 'nul.txt', 'AUX', 'PRN.log', 'COM1', 'lpt9', 'a:b', 'a*b', 'a?b', 'a"b', 'a<b', 'a>b', 'a|b', 'trailing.', 'trailing ']) {
      assert.throws(() => cfg.validateName(bad), Error, bad);
    }
    for (const good of ['console', 'conman', 'nullable', 'com', 'com10x', 'a.b', 'agent-a@mesh', 'claude-code', '日本語']) {
      assert.doesNotThrow(() => cfg.validateName(good), good);
    }
    assert.throws(() => cfg.loadIdentity({ name: 'NUL' }));
  });

  it('a compat link that reads back as an absolute path (a junction) is recognised, not re-made on every check', () => {
    const name = uniq('r111');
    const id = cfg.loadIdentity({ name });
    const link = path.join(NODES_DIR, name);
    const absolute = path.join(NODES_DIR, 'by-id', id.nodeId);
    fs.unlinkSync(indexFile(name)); // the link is then what tells which node the name is
    let remade = 0;
    patchMany({
      readlinkSync: (o) => function (p, ...a) { return String(p) === link ? absolute : o.call(fs, p, ...a); },
      unlinkSync: (o) => function (p, ...a) { if (String(p) === link) remade++; return o.call(fs, p, ...a); },
      renameSync: (o) => function (a, b) { if (String(b) === link) remade++; return o.call(fs, a, b); },
      symlinkSync: (o) => function (t, p, ...a) { if (String(p) === link) remade++; return o.call(fs, t, p, ...a); },
    }, () => {
      for (let i = 0; i < 3; i++) assert.strictEqual(cfg.loadIdentity({ name }).nodeId, id.nodeId);
    });
    assert.strictEqual(remade, 0, 'the link was not re-made');
  });
});

describe('error texts: the operator is never told to delete what leads to a key that is on disk', () => {
  it('SYM_IDENTITY_DIR switched on after the agent was made: the halt says where the key is, and not to remove the index', () => {
    const name = uniq('err-iddir');
    const id = cfg.loadIdentity({ name });
    withIdentityDir(() => {
      assert.throws(() => cfg.loadIdentity({ name }), (e) => e instanceof IdentityHaltError &&
        e.message.includes(path.join(cfg.nodeDirById(id.nodeId), 'identity.json')) && !e.message.includes(`remove ${indexFile(name)}`));
      assert.throws(() => cfg.loadIdentity({ name, create: false }), (e) => e instanceof IdentityHaltError && !/No identity/.test(e.message), 'not "no identity on this host"');
      assert.throws(() => cfg.loadIdentity({ nodeId: id.nodeId, create: false }), (e) => e instanceof IdentityHaltError);
    });
    assert.strictEqual(cfg.loadIdentity({ name }).privateKey, id.privateKey);
  });
});
