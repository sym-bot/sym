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
    const cmb = createCMB({ rawText: 'user tired and frustrated', createdBy: 'test-agent' });
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
