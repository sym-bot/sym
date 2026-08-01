'use strict';

/**
 * B-3 / AC-3.2 — the system refuses to start rather than replace an identity.
 *
 * Founder ruling D-04: "An agent may lose its machine and recover its data, but if it loses its
 * private key, it cannot prove that it is the same agent. Therefore the key must be preserved,
 * and the system must refuse to start rather than silently create a replacement identity."
 *
 * What this replaces was quiet and destructive: an unreadable identity.json logged a warning,
 * generated a fresh keypair, and OVERWROTE the file. The agent kept its name and lost the only
 * thing that made it itself — and the damage surfaced later and elsewhere, as peers rejecting
 * its blocks as forged against the public key they had pinned. A transient cause (a full disk,
 * a permissions blip, a partial write) was enough to trigger it permanently.
 *
 * The distinction these tests pin is the one that matters: minting a FIRST key for an agent that
 * never had one is fine; minting a REPLACEMENT for a key that exists but cannot be read is not.
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

/**
 * Point SYM_IDENTITY_DIR at a throwaway dir. No require-cache busting: identityDir() reads the
 * environment at call time, deliberately. (Reloading lib/config here re-ran _installExitHooks,
 * whose module-level guard reset with the cache — and each reload added another set of signal
 * listeners, which keep Node's event loop alive and hung the whole suite.)
 */
const cfg = require('../lib/config');
function freshConfig(identityDirPath) {
  const prev = process.env.SYM_IDENTITY_DIR;
  if (identityDirPath) process.env.SYM_IDENTITY_DIR = identityDirPath;
  else delete process.env.SYM_IDENTITY_DIR;
  return { cfg, restore: () => { if (prev === undefined) delete process.env.SYM_IDENTITY_DIR; else process.env.SYM_IDENTITY_DIR = prev; } };
}

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'sym-identity-'));

test('an identity survives restart unchanged — same key, same nodeId', () => {
  const dir = tmp();
  const { cfg, restore } = freshConfig(dir);
  try {
    const a = cfg.loadOrCreateIdentity('agent-a@mesh');
    const b = cfg.loadOrCreateIdentity('agent-a@mesh');
    assert.equal(a.privateKey, b.privateKey, 'the key must not change on reload');
    assert.equal(a.nodeId, b.nodeId);
  } finally { restore(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('unparseable identity HALTS and does not touch the file', () => {
  const dir = tmp();
  const { cfg, restore } = freshConfig(dir);
  try {
    cfg.loadOrCreateIdentity('agent-b@mesh');
    const idPath = path.join(dir, 'agent-b@mesh', 'identity.json');
    const corrupt = '{ not json at all';
    fs.writeFileSync(idPath, corrupt);

    assert.throws(() => cfg.loadOrCreateIdentity('agent-b@mesh'), (e) => {
      assert.equal(e.name, 'IdentityHaltError');
      assert.match(e.message, /REFUSING TO START/);
      // The ruling itself is in the operator-facing text, not just in a doc.
      assert.match(e.message, /refuse to start rather than silently create a replacement identity/);
      return true;
    });

    // The decisive assertion: a failed load must not have rewritten anything.
    assert.equal(fs.readFileSync(idPath, 'utf8'), corrupt, 'a failed load must never overwrite the identity');
  } finally { restore(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('an identity file with no nodeId HALTS rather than being replaced', () => {
  const dir = tmp();
  const { cfg, restore } = freshConfig(dir);
  try {
    const agentDir = path.join(dir, 'agent-c@mesh');
    fs.mkdirSync(agentDir, { recursive: true });
    const idPath = path.join(agentDir, 'identity.json');
    fs.writeFileSync(idPath, JSON.stringify({ note: 'not an identity' }));
    assert.throws(() => cfg.loadOrCreateIdentity('agent-c@mesh'), /REFUSING TO START/);
    assert.match(fs.readFileSync(idPath, 'utf8'), /not an identity/, 'untouched');
  } finally { restore(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('a missing public key is DERIVED from the private key, never regenerated', () => {
  // Revert-to-prove: generating a fresh pair here would change privateKey, and every peer
  // holding the old public key would read this agent as forged from that moment on.
  const dir = tmp();
  const { cfg, restore } = freshConfig(dir);
  try {
    const orig = cfg.loadOrCreateIdentity('agent-d@mesh');
    const idPath = path.join(dir, 'agent-d@mesh', 'identity.json');
    const stripped = JSON.parse(fs.readFileSync(idPath, 'utf8'));
    delete stripped.publicKey;
    fs.writeFileSync(idPath, JSON.stringify(stripped));

    const migrated = cfg.loadOrCreateIdentity('agent-d@mesh');
    assert.equal(migrated.privateKey, orig.privateKey, 'the private key must be preserved exactly');
    assert.equal(migrated.publicKey, orig.publicKey, 'and the public key derived back to the same value');
  } finally { restore(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('an agent that never had a keypair gets its FIRST one — this is not a replacement', () => {
  // The legitimate case the halt must not break: pre-v0.3.7 identities carry a nodeId and no
  // keys. There is nothing to replace, and the nodeId is preserved so the agent stays itself.
  const dir = tmp();
  const { cfg, restore } = freshConfig(dir);
  try {
    const agentDir = path.join(dir, 'agent-e@mesh');
    fs.mkdirSync(agentDir, { recursive: true });
    const nodeId = 'aaaaaaaa-bbbb-4ccc-dddd-eeeeeeeeeeee';
    fs.writeFileSync(path.join(agentDir, 'identity.json'),
      JSON.stringify({ nodeId, name: 'agent-e@mesh', hostname: 'h', createdAt: 1 }));

    const id = cfg.loadOrCreateIdentity('agent-e@mesh');
    assert.equal(id.nodeId, nodeId, 'the agent keeps its identity');
    assert.ok(id.privateKey && id.publicKey, 'and gains a first keypair');
  } finally { restore(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('SYM_IDENTITY_DIR puts the keypair outside the node dir — the rebuild path', () => {
  // AC-3.1's premise: the store is disposable because blocks are refetchable; the key is not,
  // so it lives on a durable volume and a rebuilt sandbox restores only that.
  const durable = tmp();
  const { cfg, restore } = freshConfig(durable);
  try {
    const id = cfg.loadOrCreateIdentity('agent-f@mesh');
    const externalPath = path.join(durable, 'agent-f@mesh', 'identity.json');
    assert.ok(fs.existsSync(externalPath), 'identity is written to the durable volume');
    assert.equal(cfg.identityDir('agent-f@mesh'), path.join(durable, 'agent-f@mesh'));
    assert.notEqual(cfg.identityDir('agent-f@mesh'), cfg.nodeDir('agent-f@mesh'),
      'identity and store must be separable — that is the whole point');

    // Simulate the rebuild: the node dir is gone, the durable key remains.
    fs.rmSync(cfg.nodeDir('agent-f@mesh'), { recursive: true, force: true });
    const afterRebuild = cfg.loadOrCreateIdentity('agent-f@mesh');
    assert.equal(afterRebuild.privateKey, id.privateKey, 'the agent returns as itself');
    assert.equal(afterRebuild.nodeId, id.nodeId);
  } finally { restore(); fs.rmSync(durable, { recursive: true, force: true }); }
});
