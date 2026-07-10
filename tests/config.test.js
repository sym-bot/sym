'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');
const {
  SYM_DIR, NODES_DIR, ensureDir, nodeDir,
  uuidv7, validateName, generateSigningKeyPair, loadOrCreateIdentity,
  normalizeMdnsHostname, pidIsAlive, lockHolderPid, resolveAvailableName, log,
  acquireIdentityLock, readLockFile, processStartTime,
} = require('../lib/config');

describe('uuidv7', () => {
  it('should return lowercase 8-4-4-4-12 hex format', () => {
    const id = uuidv7();
    assert.match(id, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  });

  it('should have version nibble 7', () => {
    const id = uuidv7();
    assert.strictEqual(id[14], '7');
  });

  it('should have variant bits 10xx', () => {
    const id = uuidv7();
    const variantChar = id[19];
    assert.ok('89ab'.includes(variantChar), `variant char should be 8/9/a/b, got '${variantChar}'`);
  });

  it('should produce unique IDs', () => {
    const ids = new Set(Array.from({ length: 100 }, () => uuidv7()));
    assert.strictEqual(ids.size, 100);
  });

  it('should be time-ordered (monotonic timestamps)', () => {
    const a = uuidv7();
    const b = uuidv7();
    // Extract timestamp hex (first 12 chars without hyphen)
    const tsA = a.replace(/-/g, '').slice(0, 12);
    const tsB = b.replace(/-/g, '').slice(0, 12);
    assert.ok(tsB >= tsA, `${tsB} should be >= ${tsA}`);
  });
});

describe('validateName', () => {
  it('should accept valid names', () => {
    assert.doesNotThrow(() => validateName('claude-code'));
    assert.doesNotThrow(() => validateName('a'));
    assert.doesNotThrow(() => validateName('my-node-123'));
  });

  it('should accept unicode names within 64 bytes', () => {
    assert.doesNotThrow(() => validateName('日本語'));
  });

  it('should reject empty string', () => {
    assert.throws(() => validateName(''), /non-empty/);
  });

  it('should reject names > 64 bytes', () => {
    assert.throws(() => validateName('a'.repeat(65)), /1-64 bytes/);
  });

  it('should reject control characters', () => {
    assert.throws(() => validateName('test\x00node'), /control/);
    assert.throws(() => validateName('test\nnewline'), /control/);
    assert.throws(() => validateName('test\ttab'), /control/);
  });

  it('should reject non-string input', () => {
    assert.throws(() => validateName(null), /non-empty/);
    assert.throws(() => validateName(undefined), /non-empty/);
  });
});

describe('generateSigningKeyPair', () => {
  it('should return 32-byte raw Buffer keys', () => {
    const kp = generateSigningKeyPair();
    assert.ok(Buffer.isBuffer(kp.publicKey), 'publicKey should be Buffer');
    assert.ok(Buffer.isBuffer(kp.privateKey), 'privateKey should be Buffer');
    assert.strictEqual(kp.publicKey.length, 32);
    assert.strictEqual(kp.privateKey.length, 32);
  });

  it('should produce different keys each call', () => {
    const a = generateSigningKeyPair();
    const b = generateSigningKeyPair();
    assert.ok(!a.publicKey.equals(b.publicKey), 'different calls should produce different keys');
  });

  it('should produce base64url-safe strings when encoded', () => {
    const kp = generateSigningKeyPair();
    const encoded = kp.publicKey.toString('base64url');
    assert.ok(!encoded.includes('+'), 'base64url should not contain +');
    assert.ok(!encoded.includes('='), 'base64url should not contain =');
    assert.ok(!encoded.includes('/'), 'base64url should not contain /');
  });
});

describe('loadOrCreateIdentity', () => {
  const testName = `test-identity-${Date.now()}`;

  after(() => {
    fs.rmSync(nodeDir(testName), { recursive: true, force: true });
  });

  it('should create new identity with UUID v7 and keypair', () => {
    const id = loadOrCreateIdentity(testName);
    assert.ok(id.nodeId, 'should have nodeId');
    assert.strictEqual(id.nodeId[14], '7', 'new node should use UUID v7');
    assert.strictEqual(id.name, testName);
    assert.ok(id.hostname, 'should have hostname');
    assert.ok(id.createdAt, 'should have createdAt');
    assert.ok(id.publicKey, 'should have Ed25519 publicKey');
    assert.ok(id.privateKey, 'should have Ed25519 privateKey');
  });

  it('should return same identity on second call', () => {
    const a = loadOrCreateIdentity(testName);
    const b = loadOrCreateIdentity(testName);
    assert.strictEqual(a.nodeId, b.nodeId);
    assert.strictEqual(a.publicKey, b.publicKey);
  });

  it('should migrate legacy identity without keypair', () => {
    const legacyName = `test-legacy-${Date.now()}`;
    const dir = nodeDir(legacyName);
    ensureDir(dir);
    const legacy = { nodeId: 'aaaaaaaa-bbbb-4ccc-dddd-eeeeeeeeeeee', name: legacyName, hostname: 'test', createdAt: Date.now() };
    fs.writeFileSync(path.join(dir, 'identity.json'), JSON.stringify(legacy));

    const id = loadOrCreateIdentity(legacyName);
    assert.strictEqual(id.nodeId, legacy.nodeId, 'should preserve v4 nodeId');
    assert.ok(id.publicKey, 'should add publicKey during migration');
    assert.ok(id.privateKey, 'should add privateKey during migration');

    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('should migrate legacy identity with bare hostname to .local form', () => {
    const legacyName = `test-bare-host-${Date.now()}`;
    const dir = nodeDir(legacyName);
    ensureDir(dir);
    const legacy = {
      nodeId: 'bbbbbbbb-cccc-4ddd-eeee-ffffffffffff',
      name: legacyName,
      hostname: 'xmesh-hp',
      createdAt: Date.now(),
      publicKey: 'x', privateKey: 'y',
    };
    fs.writeFileSync(path.join(dir, 'identity.json'), JSON.stringify(legacy));

    const id = loadOrCreateIdentity(legacyName);
    assert.strictEqual(id.hostname, 'xmesh-hp.local', 'bare hostname should be normalized to .local');

    const persisted = JSON.parse(fs.readFileSync(path.join(dir, 'identity.json'), 'utf8'));
    assert.strictEqual(persisted.hostname, 'xmesh-hp.local', 'migration should be persisted to disk');

    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('should create new identity with normalized mDNS hostname', () => {
    const id = loadOrCreateIdentity(testName);
    assert.ok(id.hostname.includes('.'), 'new identity hostname must contain a dot (either .local or FQDN)');
  });
});

describe('normalizeMdnsHostname', () => {
  it('appends .local to bare hostnames', () => {
    assert.strictEqual(normalizeMdnsHostname('xmesh-hp'), 'xmesh-hp.local');
    assert.strictEqual(normalizeMdnsHostname('laptop'), 'laptop.local');
  });

  it('passes through already-.local hostnames', () => {
    assert.strictEqual(normalizeMdnsHostname('xmesh-hp.local'), 'xmesh-hp.local');
  });

  it('passes through FQDNs unchanged', () => {
    assert.strictEqual(normalizeMdnsHostname('host.example.com'), 'host.example.com');
  });

  it('strips trailing dot', () => {
    assert.strictEqual(normalizeMdnsHostname('xmesh-hp.local.'), 'xmesh-hp.local');
  });

  it('handles null/empty gracefully', () => {
    assert.strictEqual(normalizeMdnsHostname(null), null);
    assert.strictEqual(normalizeMdnsHostname(''), '');
    assert.strictEqual(normalizeMdnsHostname(undefined), undefined);
  });
});

describe('ensureDir', () => {
  it('should create nested directories', () => {
    const dir = path.join(os.tmpdir(), `sym-test-${Date.now()}`, 'a', 'b');
    ensureDir(dir);
    assert.ok(fs.existsSync(dir));
    fs.rmSync(path.join(os.tmpdir(), `sym-test-${Date.now()}`), { recursive: true, force: true });
  });
});

describe('nodeDir', () => {
  it('should return path under NODES_DIR', () => {
    const dir = nodeDir('test-node');
    assert.ok(dir.startsWith(NODES_DIR));
    assert.ok(dir.endsWith('test-node'));
  });
});

describe('resolveAvailableName', () => {
  const base = `test-resolve-${Date.now()}`;
  const writeLock = (name, pid) => {
    ensureDir(nodeDir(name));
    fs.writeFileSync(path.join(nodeDir(name), 'lock.pid'), String(pid));
  };
  // A real, live, foreign process (our child — alive, pid !== process.pid).
  let liveChild;
  before(() => {
    liveChild = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
  });
  after(() => {
    if (liveChild) { try { liveChild.kill('SIGKILL'); } catch {} }
    for (let i = 1; i <= 4; i++) {
      const n = i === 1 ? base : `${base}-${i}`;
      fs.rmSync(nodeDir(n), { recursive: true, force: true });
    }
    fs.rmSync(nodeDir(`${base}-long`), { recursive: true, force: true });
  });

  it('returns the base name when no lockfile exists', () => {
    assert.strictEqual(resolveAvailableName(base), base);
  });

  it('returns the base name when the holder PID is dead (stale lock)', () => {
    writeLock(base, 2147483646); // implausible PID → ESRCH → treated as free
    assert.strictEqual(resolveAvailableName(base), base);
  });

  it('returns the base name when the holder is our own process', () => {
    writeLock(base, process.pid);
    assert.strictEqual(resolveAvailableName(base), base);
  });

  it('suffixes to -2 when the base is held by a live foreign process', () => {
    writeLock(base, liveChild.pid);
    assert.strictEqual(resolveAvailableName(base), `${base}-2`);
  });

  it('skips multiple live holders to the next free suffix', () => {
    writeLock(base, liveChild.pid);
    writeLock(`${base}-2`, liveChild.pid);
    assert.strictEqual(resolveAvailableName(base), `${base}-3`);
  });

  it('keeps a suffixed slot whose prior holder has died', () => {
    writeLock(base, liveChild.pid);     // base: live → skip
    writeLock(`${base}-2`, 2147483646); // -2: dead → reclaimable
    assert.strictEqual(resolveAvailableName(base), `${base}-2`);
  });

  it('does not overflow the 64-byte name limit (skips over-long candidates)', () => {
    // A base near the limit: appending "-2" would exceed 64 bytes, so that
    // candidate is skipped. With the base held live and no room to suffix,
    // it falls back to the base (acquireIdentityLock then hard-fails).
    const longBase = 'x'.repeat(63); // 63 bytes; "-2" → 65 bytes, over limit
    ensureDir(nodeDir(longBase));
    fs.writeFileSync(path.join(nodeDir(longBase), 'lock.pid'), String(liveChild.pid));
    assert.strictEqual(resolveAvailableName(longBase), longBase);
    fs.rmSync(nodeDir(longBase), { recursive: true, force: true });
  });

  it('validates the base name (throws on invalid input)', () => {
    assert.throws(() => resolveAvailableName(''), /non-empty string/);
  });
});

describe('pidIsAlive', () => {
  it('is true for our own process', () => {
    assert.strictEqual(pidIsAlive(process.pid), true);
  });
  it('is false for an implausible/dead PID', () => {
    assert.strictEqual(pidIsAlive(2147483646), false);
  });
  it('is false for non-finite input', () => {
    assert.strictEqual(pidIsAlive(NaN), false);
  });
});

describe('lockHolderPid', () => {
  const name = `test-holder-${Date.now()}`;
  after(() => { fs.rmSync(nodeDir(name), { recursive: true, force: true }); });

  it('returns null when no lockfile exists', () => {
    assert.strictEqual(lockHolderPid(name), null);
  });
  it('returns the numeric PID when present', () => {
    ensureDir(nodeDir(name));
    fs.writeFileSync(path.join(nodeDir(name), 'lock.pid'), '12345');
    assert.strictEqual(lockHolderPid(name), 12345);
  });
  it('returns null for non-numeric content', () => {
    ensureDir(nodeDir(name));
    fs.writeFileSync(path.join(nodeDir(name), 'lock.pid'), 'not-a-pid');
    assert.strictEqual(lockHolderPid(name), null);
  });
  it('parses the PID from the v2 pid+metadata format', () => {
    ensureDir(nodeDir(name));
    fs.writeFileSync(path.join(nodeDir(name), 'lock.pid'), '4242\n{"start":"Mon Jan  5 10:00:00 2026","createdAt":1}\n');
    assert.strictEqual(lockHolderPid(name), 4242);
  });
});

describe('acquireIdentityLock', () => {
  const DEAD_PID = 2147483646; // implausible → ESRCH
  let liveChild;
  const made = [];
  const mkName = () => {
    const n = `test-lock-${Date.now()}-${made.length}`;
    made.push(n);
    return n;
  };
  const lockPathOf = (name) => path.join(nodeDir(name), 'lock.pid');
  const writeLock = (name, content) => {
    ensureDir(nodeDir(name));
    fs.writeFileSync(lockPathOf(name), content);
  };
  before(() => {
    liveChild = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
  });
  after(() => {
    if (liveChild) { try { liveChild.kill('SIGKILL'); } catch {} }
    for (const n of made) fs.rmSync(nodeDir(n), { recursive: true, force: true });
  });

  it('acquires a free identity and writes pid + start-time metadata', () => {
    const name = mkName();
    const release = acquireIdentityLock(name);
    const lock = readLockFile(lockPathOf(name));
    assert.strictEqual(lock.pid, process.pid);
    assert.strictEqual(lock.start, processStartTime(process.pid));
    release();
    assert.strictEqual(fs.existsSync(lockPathOf(name)), false);
  });

  it('reclaims a stale lock whose holder PID is dead', () => {
    const name = mkName();
    writeLock(name, String(DEAD_PID));
    const release = acquireIdentityLock(name); // must NOT throw
    assert.strictEqual(readLockFile(lockPathOf(name)).pid, process.pid);
    release();
  });

  it('throws EIDENTITYLOCK when a live foreign process holds the lock', () => {
    const name = mkName();
    writeLock(name, String(liveChild.pid));
    assert.throws(() => acquireIdentityLock(name), (e) => e.code === 'EIDENTITYLOCK' && e.holderPid === liveChild.pid);
  });

  it('reclaims a lock whose PID is alive but was recycled (start-time mismatch)', () => {
    const name = mkName();
    // A live PID recorded with a DIFFERENT process start time = the PID
    // was reused by an unrelated process after the real holder died.
    writeLock(name, `${liveChild.pid}\n{"start":"Thu Jan  1 00:00:00 2004","createdAt":1}\n`);
    const release = acquireIdentityLock(name); // must NOT throw
    assert.strictEqual(readLockFile(lockPathOf(name)).pid, process.pid);
    release();
  });

  it('reclaims a legacy pid-only lock written before the current boot', () => {
    const name = mkName();
    writeLock(name, String(liveChild.pid)); // "alive" PID…
    const old = new Date(Date.now() - 365 * 24 * 3600 * 1000);
    fs.utimesSync(lockPathOf(name), old, old); // …but the lock predates boot
    const release = acquireIdentityLock(name); // must NOT throw
    assert.strictEqual(readLockFile(lockPathOf(name)).pid, process.pid);
    release();
  });

  it('reclaims an aged-out corrupt lockfile but respects a fresh one', () => {
    const name = mkName();
    writeLock(name, 'garbage');
    assert.throws(() => acquireIdentityLock(name), /already locked/); // fresh: maybe mid-write
    const old = new Date(Date.now() - 60 * 1000);
    fs.utimesSync(lockPathOf(name), old, old);
    const release = acquireIdentityLock(name); // aged out: reclaim
    assert.strictEqual(readLockFile(lockPathOf(name)).pid, process.pid);
    release();
  });

  it('allows same-process re-acquisition', () => {
    const name = mkName();
    const r1 = acquireIdentityLock(name);
    const r2 = acquireIdentityLock(name); // same PID → allowed
    r2();
    r1();
    assert.strictEqual(fs.existsSync(lockPathOf(name)), false);
  });

  it('releases the lock on plain process exit (no explicit release call)', async () => {
    const name = mkName();
    const script = `require(${JSON.stringify(require.resolve('../lib/config'))}).acquireIdentityLock(${JSON.stringify(name)});`;
    await new Promise((resolve, reject) => {
      const c = spawn(process.execPath, ['-e', script], { stdio: 'ignore', env: process.env });
      c.on('error', reject);
      c.on('close', (code) => (code === 0 ? resolve() : reject(new Error(`child exited ${code}`))));
    });
    assert.strictEqual(fs.existsSync(lockPathOf(name)), false);
  });

  it('releases the lock on SIGTERM when the host has no handler', async () => {
    const name = mkName();
    const script = `
      require(${JSON.stringify(require.resolve('../lib/config'))}).acquireIdentityLock(${JSON.stringify(name)});
      console.log('locked');
      setInterval(() => {}, 1000);`;
    await new Promise((resolve, reject) => {
      const c = spawn(process.execPath, ['-e', script], { stdio: ['ignore', 'pipe', 'ignore'], env: process.env });
      c.on('error', reject);
      c.stdout.on('data', (d) => {
        if (String(d).includes('locked')) {
          assert.strictEqual(readLockFile(lockPathOf(name)).pid, c.pid);
          c.kill('SIGTERM');
        }
      });
      c.on('close', () => resolve());
    });
    assert.strictEqual(fs.existsSync(lockPathOf(name)), false);
  });
});

describe('log', () => {
  it('should not throw', () => {
    assert.doesNotThrow(() => log('test', 'hello'));
  });
});
