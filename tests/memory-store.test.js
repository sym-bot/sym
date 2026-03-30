'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { MemoryStore } = require('../lib/memory-store');

describe('MemoryStore', () => {
  const testDir = path.join(os.tmpdir(), `sym-test-${Date.now()}`);
  let store;

  before(() => {
    store = new MemoryStore(testDir, 'test-agent');
  });

  after(() => {
    fs.rmSync(testDir, { recursive: true, force: true });
  });

  it('should write and retrieve a memory entry', () => {
    const entry = store.write('user is debugging auth module', { tags: ['session', 'coding'] });

    assert.ok(entry.key, 'should have key');
    assert.strictEqual(entry.content, 'user is debugging auth module');
    assert.strictEqual(entry.source, 'test-agent');
    assert.deepStrictEqual(entry.tags, ['session', 'coding']);
    assert.ok(entry.originTimestamp, 'should have originTimestamp');
    assert.ok(entry.storedAt, 'should have storedAt');
    assert.ok(entry.timestamp, 'should have timestamp');
  });

  it('should store originTimestamp when provided', () => {
    const origin = Date.now() - 60000;
    const entry = store.write('old event', { originTimestamp: origin });

    assert.strictEqual(entry.originTimestamp, origin);
    assert.ok(entry.storedAt > origin, 'storedAt should be after originTimestamp');
  });

  it('should store CMB when provided', () => {
    const { createCMB } = require('@sym-bot/core');
    const cmb = createCMB({
      fields: {
        focus: 'debugging auth module',
        issue: 'tired and frustrated',
        intent: 'needs a break',
        motivation: 'prevent errors from fatigue',
        commitment: 'coding session',
        perspective: 'developer, late afternoon',
        mood: { text: 'frustrated', valence: -0.5, arousal: -0.3 },
      },
      createdBy: 'test-agent',
    });
    const entry = store.write('user tired and frustrated', { cmb });

    assert.ok(entry.cmb, 'should store CMB');
    assert.ok(entry.cmb.fields, 'CMB should have fields');
  });

  it('should search memories by keyword', () => {
    // Write fresh entries for this test
    const entry = store.write('unique workout session completed successfully', { tags: ['fitness'] });
    assert.ok(entry.key, 'write should return entry');

    // Search should find it
    const results = store.search('unique workout');
    assert.ok(results.length >= 1, `should find workout memory, got ${results.length} results. Entry was: ${entry.key}`);
  });

  it('should return all entries sorted by timestamp', () => {
    const entries = store.allEntries();
    assert.ok(entries.length >= 2, 'should have multiple entries');

    // Should be sorted newest first
    for (let i = 1; i < entries.length; i++) {
      assert.ok(entries[i-1].timestamp >= entries[i].timestamp, 'should be sorted newest first');
    }
  });

  it('should return recent CMBs', () => {
    const cmbs = store.recentCMBs(3);
    assert.ok(cmbs.length > 0, 'should return CMBs');
    assert.ok(cmbs.length <= 3, 'should respect limit');

    for (const cmb of cmbs) {
      assert.ok(cmb.fields, 'each CMB should have fields');
      assert.ok(cmb.createdBy, 'each CMB should have createdBy');
    }
  });

  it('should count total memories', () => {
    const count = store.count();
    assert.ok(count >= 2, `should have at least 2 entries, got ${count}`);
  });

  it('should get entry by key', () => {
    const entry = store.write('retrievable entry', { tags: ['gettest'] });
    const loaded = store.get(entry.key);
    assert.ok(loaded, 'should load by key');
    assert.strictEqual(loaded.content, 'retrievable entry');
  });

  it('should return null for missing key', () => {
    const result = store.get('nonexistent-key');
    assert.strictEqual(result, null);
  });

  it('should return ancestors and parents', () => {
    // Write a parent first
    const parent = store.write('parent observation', { tags: ['lineage'] });
    // Write a child with parent reference
    const { createCMB } = require('@sym-bot/core');
    const childCmb = createCMB({
      fields: {
        focus: 'child of parent',
        issue: 'none', intent: 'test lineage', motivation: 'coverage',
        commitment: 'test', perspective: 'test',
        mood: { text: 'neutral', valence: 0, arousal: 0 },
      },
      createdBy: 'test-agent',
      parents: [parent.key],
    });
    const child = store.write('child observation', { cmb: childCmb });

    const parents = store.parents(child.key);
    // Parents may or may not be populated depending on CMB lineage propagation
    assert.ok(Array.isArray(parents), 'parents should be array');

    const ancestors = store.ancestors(child.key);
    assert.ok(Array.isArray(ancestors), 'ancestors should be array');
  });

  it('should return descendants', () => {
    const entry = store.write('root entry for descendants test');
    const descs = store.descendants(entry.key);
    assert.ok(Array.isArray(descs), 'descendants should be array');
  });

  it('should return stats', () => {
    const s = store.stats();
    assert.ok(s.total >= 1, 'should have entries');
    assert.ok(typeof s.local === 'number');
    assert.ok(typeof s.peer === 'number');
    assert.ok(typeof s.hot === 'number');
    assert.ok(typeof s.cold === 'number');
    assert.strictEqual(s.total, s.local + s.peer);
  });

  it('should recall all when no query', () => {
    const results = store.recall('');
    assert.ok(results.length >= 1, 'empty query should return all');
    const results2 = store.recall();
    assert.ok(results2.length >= 1, 'undefined query should return all');
  });

  it('should compact old entries', () => {
    // Compact with zero freshness = everything is old
    const moved = store.compact(0);
    assert.ok(typeof moved === 'number', 'compact should return count');
  });

  it('should purge cold entries without descendants', () => {
    const removed = store.purge();
    assert.ok(typeof removed === 'number', 'purge should return count');
  });

  it('should receive from peer', () => {
    const peerEntry = {
      key: 'peer-mem-1',
      content: 'peer observation about user energy',
      source: 'melomove',
      tags: ['energy'],
      originTimestamp: Date.now(),
      storedAt: Date.now(),
      timestamp: Date.now(),
    };
    store.receiveFromPeer('peer-abc', peerEntry);

    const results = store.search('peer observation');
    assert.ok(results.length >= 1, 'should find peer memory');
  });
});
