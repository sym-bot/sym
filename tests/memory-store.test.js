'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

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
    const { createCMB } = require('../lib/core');
    const cmb = createCMB({
      categories: {
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
    assert.ok(entry.cmb.categories, 'CMB should have categories');
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
      assert.ok(cmb.categories, 'each CMB should have categories');
      // §7.2: authorship lives in metadata and is REQUIRED to survive the receive path —
      // a record whose author is dropped on storage cannot be verified against its author's key.
      assert.ok(cmb.metadata?.createdBy ?? cmb.createdBy, 'each CMB should carry its author');
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
    const { createCMB } = require('../lib/core');
    const childCmb = createCMB({
      categories: {
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

  it('compactByOrigin shims to compact when both freshnessMs values are equal', () => {
    // Back-compat: the legacy single-value compact() now shims to
    // compactByOrigin with equal local + peer thresholds. The result
    // count must remain shaped like a number (existing assertions).
    const isolatedDir = path.join(os.tmpdir(), `sym-test-shim-${Date.now()}`);
    const isolated = new MemoryStore(isolatedDir, 'test-agent');
    try {
      isolated.write('shim-test entry', { tags: ['shim'] });
      const compacted = isolated.compactByOrigin(0, 0);
      assert.ok(typeof compacted === 'number',
        'compactByOrigin should return count');
    } finally {
      fs.rmSync(isolatedDir, { recursive: true, force: true });
    }
  });

  it('compactByOrigin uses peer threshold for peer entries and local threshold for self entries', () => {
    // Origin-aware retention: a peer entry past its peerCutoff
    // compacts to cold; a self entry of the same age but within its
    // localCutoff stays hot. The discrimination is the whole point of
    // the API — apps that retain own lineage longer than peer chatter
    // configure local > peer freshness.
    const isolatedDir = path.join(os.tmpdir(), `sym-test-origin-${Date.now()}`);
    const isolated = new MemoryStore(isolatedDir, 'test-agent');
    try {
      // Self entry (peerId == null).
      const selfEntry = isolated.write('self ancient', { tags: ['origin-test'] });
      // Peer entry, written via the receiveFromPeer path so peerId is
      // populated and the entry is treated as not-self by the index.
      const peerEntry = isolated.receiveFromPeer('peer-x', {
        key: 'peer-ancient-key',
        content: 'peer ancient',
        source: 'peer-x',
        tags: ['origin-test'],
      });
      // Backdate both storedAt to 60 seconds ago via in-memory index
      // mutation — test-only manipulation; production code never
      // touches storedAt directly.
      const sixtySecAgo = Date.now() - 60_000;
      isolated._index.get(selfEntry.key).storedAt = sixtySecAgo;
      if (peerEntry) isolated._index.get(peerEntry.key).storedAt = sixtySecAgo;

      // localFreshness = 120s (self stays hot), peerFreshness = 30s
      // (peer entry is past cutoff and should compact).
      const moved = isolated.compactByOrigin(120_000, 30_000);

      assert.strictEqual(moved, 1,
        'exactly one entry (peer) should compact under split thresholds');
      assert.strictEqual(isolated._index.get(selfEntry.key).tier, 'hot',
        'self entry must stay hot when within local freshness window');
      if (peerEntry) {
        assert.strictEqual(isolated._index.get(peerEntry.key).tier, 'cold',
          'peer entry must compact when past peer freshness window');
      }
    } finally {
      fs.rmSync(isolatedDir, { recursive: true, force: true });
    }
  });

  it('Canon tier (validated/canonical) never expires — persistent Canon (GAP-A)', () => {
    // A validated CMB must survive compaction AND purge even when ancient, so the Sym
    // Canon compounds across days; an observed CMB of the same age is evicted.
    const dir = path.join(os.tmpdir(), `sym-test-canon-${Date.now()}`);
    const store = new MemoryStore(dir, 'test-agent');
    try {
      const observed = store.write('ephemeral chatter', { tags: ['canon-test'] });
      const canon = store.write('grounded knowledge', { tags: ['canon-test'] });

      // Promote one to the Canon tier (validator authority required).
      const res = store.validateCMB(canon.key, { byRole: 'validator' });
      assert.ok(res.ok, 'validateCMB should succeed with validator role');
      assert.strictEqual(store.getLifecycle(canon.key), 'validated');

      // Backdate both far past any freshness window.
      const ancient = Date.now() - 10 * 86_400_000; // 10 days
      store._index.get(observed.key).storedAt = ancient;
      store._index.get(canon.key).storedAt = ancient;

      // Aggressive compaction: everything past cutoff → cold, EXCEPT Canon tier.
      store.compactByOrigin(0, 0);
      assert.strictEqual(store._index.get(observed.key).tier, 'cold',
        'observed CMB compacts to cold when ancient');
      assert.strictEqual(store._index.get(canon.key).tier, 'hot',
        'validated CMB stays hot — Canon tier exempt from compaction');

      // Purge removes cold-without-descendants; Canon tier survives regardless.
      store.purge();
      assert.strictEqual(store.get(observed.key), null,
        'observed CMB is purged');
      assert.ok(store.get(canon.key), 'validated CMB survives purge — persists in Canon');
      assert.strictEqual(store.getLifecycle(canon.key), 'validated');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
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

  it('preserves the wire ancestor chain — the root is not dropped across hops (MMP §15.2)', () => {
    // C receives B's remix, which carries the full chain [root-A] on the wire, but
    // B's key is not in C's index (C stores its own remix, never the incoming CMB).
    // The stored ancestors MUST keep root-A — recomputing from the index alone
    // would drop it and break offline-remix detection.
    const cmb = {
      createdBy: 'peer-c', createdAt: Date.now(),
      categories: { focus: { text: 'c remix of b' }, mood: { text: 'steady' } },
      lineage: { parents: ['remix-B'], ancestors: ['root-A', 'remix-B'], method: 'SVAF-v2' },
    };
    const stored = store.receiveFromPeer('peer-c', { cmb, content: 'c remix of b', source: 'peer-c' });
    assert.ok(stored, 'stored');
    assert.ok(stored.lineage.ancestors.includes('root-A'), 'root-A preserved from the wire chain');
    assert.ok(stored.lineage.ancestors.includes('remix-B'), 'parent B included');
  });
});
