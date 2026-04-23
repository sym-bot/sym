'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const {
  SYM_DIR, NODES_DIR, ensureDir, nodeDir,
  uuidv7, validateName, generateSigningKeyPair, loadOrCreateIdentity,
  normalizeMdnsHostname, log,
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

describe('log', () => {
  it('should not throw', () => {
    assert.doesNotThrow(() => log('test', 'hello'));
  });
});
