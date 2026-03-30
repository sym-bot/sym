'use strict';

const { describe, it, after } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { nodeDir } = require('../lib/config');

// Use unique names to avoid state conflicts
const nodeName = `test-node-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;

describe('SymNode', () => {
  let SymNode;

  // Dynamic require to avoid top-level import issues
  it('should load SymNode', () => {
    SymNode = require('../lib/node').SymNode;
    assert.ok(SymNode, 'SymNode should be exported');
  });

  it('should require a name', () => {
    assert.throws(() => new SymNode({}), /requires a name/);
  });

  it('should set name and nodeId in constructor', () => {
    const node = new SymNode({ name: nodeName, silent: true });
    assert.strictEqual(node.name, nodeName);
    assert.ok(node.nodeId, 'nodeId should be set');
    assert.strictEqual(node.nodeId.length, 36, 'nodeId should be full UUID');
  });

  it('should return full nodeId in status()', async () => {
    const node = new SymNode({ name: nodeName, silent: true, relayOnly: true });
    await node.start();
    const s = node.status();
    assert.strictEqual(s.nodeId, node.nodeId);
    assert.strictEqual(s.nodeId.length, 36);
    assert.strictEqual(s.name, nodeName);
    assert.strictEqual(s.running, true);
    assert.strictEqual(s.peerCount, 0);
    await node.stop();
  });

  it('should start and stop without error', async () => {
    const name = `test-lifecycle-${Date.now()}`;
    const node = new SymNode({ name, silent: true, relayOnly: true });
    await node.start();
    assert.strictEqual(node.status().running, true);
    await node.stop();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  });

  it('should return empty peers when no connections', () => {
    const node = new SymNode({ name: nodeName, silent: true });
    const peers = node.peers();
    assert.ok(Array.isArray(peers));
    assert.strictEqual(peers.length, 0);
  });

  it('should return null coherence when no peers', () => {
    const node = new SymNode({ name: nodeName, silent: true });
    const c = node.coherence();
    assert.strictEqual(c, null);
  });

  it('should remember and recall', async () => {
    const name = `test-memory-${Date.now()}`;
    const node = new SymNode({ name, silent: true, relayOnly: true });
    await node.start();

    const entry = node.remember({
      focus: 'testing memory',
      issue: 'none',
      intent: 'verify remember/recall',
      motivation: 'test coverage',
      commitment: 'test suite',
      perspective: 'developer',
      mood: { text: 'focused', valence: 0.5, arousal: 0.3 },
    });
    assert.ok(entry, 'remember should return entry');
    assert.ok(entry.key, 'entry should have key');

    const results = node.recall('testing memory');
    assert.ok(results.length >= 1, 'should find the memory');

    const count = node.memories();
    assert.ok(count >= 1, 'should have at least 1 memory');

    await node.stop();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  });

  after(() => {
    fs.rmSync(nodeDir(nodeName), { recursive: true, force: true });
  });
});
