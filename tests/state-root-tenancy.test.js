/**
 * The identity tree follows SYM_STATE_DIR — two rooted deployments on one host are two agents.
 *
 * lib/config.js used to compute SYM_DIR as `$HOME/.sym`, importing only node builtins, while
 * lib/core/state-root.js in the SAME package already resolved SYM_STATE_DIR. So the module
 * that mints identities, keypairs, stores and the single-writer lock was tenancy-blind by
 * construction: two team roots on one host, each with its own SYM_STATE_DIR, still shared
 * one ~/.sym/nodes, and the second daemon's observer was refused the identity lock the first
 * one held. Renaming the observer would have satisfied the lock and left the boundary
 * exactly as broken. (xmesh mission-79aed0, F-B4, 2026-08-18 — verified on disk: <root>/sym
 * existed for NO team root; ~/.sym/nodes/xmesh did.)
 *
 * SYM_DIR is a module-level constant, so each root is exercised in a child process that
 * requires config fresh under its own environment — the way two daemons actually do.
 */
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { tmpdir } = require('./_tmpdir');

const CONFIG = path.resolve(__dirname, '..', 'lib', 'config.js');

/** Spawn a process that acquires the lock for `name` in `stateDir`, prints READY once it holds
 *  it, and stays alive until killed. Resolves when READY is seen — no spin-waiting on files. */
function holdLock(stateDir, name) {
  const { spawn } = require('node:child_process');
  const child = spawn(process.execPath, ['-e',
    `const c=require(${JSON.stringify(CONFIG)});c.acquireIdentityLock(${JSON.stringify(name)});process.stdout.write('READY');setInterval(()=>{},1000);`],
    { env: { ...process.env, SYM_STATE_DIR: stateDir }, stdio: ['ignore', 'pipe', 'pipe'] });
  return new Promise((resolve, reject) => {
    let out = '', err = '';
    child.stdout.on('data', (d) => { out += d; if (out.includes('READY')) resolve(child); });
    child.stderr.on('data', (d) => { err += d; });
    child.on('exit', (code) => reject(new Error(`holder exited ${code} before READY: ${err.slice(0, 300)}`)));
    setTimeout(() => reject(new Error(`holder never signalled READY: ${err.slice(0, 300)}`)), 8000);
  });
}

/** Run a snippet against a fresh require of lib/config under the given SYM_STATE_DIR. */
function inRoot(stateDir, code) {
  const env = { ...process.env };
  if (stateDir === null) delete env.SYM_STATE_DIR; else env.SYM_STATE_DIR = stateDir;
  delete env.SYM_IDENTITY_DIR;   // the lock path must come from the tree, not the override
  return execFileSync(process.execPath, ['-e', `const c=require(${JSON.stringify(CONFIG)});${code}`], { env, encoding: 'utf8', timeout: 20_000 }).trim();
}

test('SYM_DIR and NODES_DIR follow SYM_STATE_DIR', () => {
  const root = tmpdir('sym-root-');
  const out = inRoot(root, 'console.log(JSON.stringify({d:c.SYM_DIR,n:c.NODES_DIR}))');
  assert.deepEqual(JSON.parse(out), { d: root, n: path.join(root, 'nodes') });
});

test('with SYM_STATE_DIR unset, nothing moves for anyone: ~/.sym as before', () => {
  const out = inRoot(null, 'console.log(c.SYM_DIR)');
  assert.equal(out, path.join(os.homedir(), '.sym'), 'the developer default is unchanged');
});

test('the SAME node name in two roots holds TWO locks — no collision, no shared identity', async () => {
  const a = tmpdir('sym-tenant-a-');
  const b = tmpdir('sym-tenant-b-');
  const holder = await holdLock(a, 'xmesh');
  try {
    assert.ok(fs.existsSync(path.join(a, 'nodes', 'xmesh', 'lock.pid')), 'root A holds its lock under ITS tree');

    // Root B, same name: must acquire, not throw EIDENTITYLOCK.
    const out = inRoot(b, `try{c.acquireIdentityLock('xmesh');console.log('ACQUIRED')}catch(e){console.log('REFUSED '+e.code)}`);
    assert.equal(out, 'ACQUIRED', 'a different root is a different agent — the lock does not collide across tenants');
    // B's process has exited by now and its exit hook released the lock (correctly), so the
    // lock FILE is gone; the node DIR it created under B's tree is the durable evidence that
    // B's identity lives in B's root and nowhere near A's or the host-global tree.
    assert.ok(fs.existsSync(path.join(b, 'nodes', 'xmesh')), "root B's node dir is under B's tree");
    assert.ok(fs.existsSync(path.join(a, 'nodes', 'xmesh', 'lock.pid')), "root A's lock is untouched by B's acquisition");
  } finally { holder.kill(); }
});

test('and the SAME root still refuses a second holder — the single-writer rule is intact', async () => {
  const a = tmpdir('sym-tenant-same-');
  const holder = await holdLock(a, 'xmesh');
  try {
    const out = inRoot(a, `try{c.acquireIdentityLock('xmesh');console.log('ACQUIRED')}catch(e){console.log('REFUSED '+e.code)}`);
    assert.equal(out, 'REFUSED EIDENTITYLOCK', 'rooting the tree must not weaken the lock within a root');
  } finally { holder.kill(); }
});
