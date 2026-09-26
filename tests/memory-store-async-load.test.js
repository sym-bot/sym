'use strict';

/**
 * MemoryStore#load — build the index WITHOUT holding the event loop.
 *
 * The constructor used to read and parse every file in the store synchronously. A runtime that
 * constructs several nodes at boot held its event loop for minutes doing it (core-team, 26 Sep
 * 2026; the largest store was 3,237 files), long enough that its watchdog killed it before it
 * answered a request. The index is now built by load(), which SymNode.start() awaits, and any
 * access before that builds it synchronously exactly as before.
 *
 * What these pin is the property that makes the change safe: whichever path builds the index, it
 * is the SAME index, and no caller can ever observe a store that was not built.
 */
const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { MemoryStore } = require('../lib/memory-store');

function seededDir(n) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-memstore-'));
  const writer = new MemoryStore(dir, 'seed-agent');
  for (let i = 0; i < n; i++) writer.write(`topic ${i} about issue ${i % 7}`, { tags: ['seed'] });
  return dir;
}
// allEntries() is the 20 most recent, not a count — the index's own size is the true count, and
// reading it goes through the accessor, so it still exercises the build-on-first-touch guarantee.
const snapshot = (store) => {
  const keys = [...store._index.byKey.keys()].sort();
  return { keys, entries: keys.map((k) => JSON.stringify(store._cache.get(k))), count: store._index.byKey.size };
};

describe('MemoryStore#load', () => {
  it('builds the SAME index as the synchronous path', async () => {
    const dir = seededDir(40);
    const viaSync = new MemoryStore(dir, 'reader');
    viaSync._ensureIndex();
    const viaLoad = new MemoryStore(dir, 'reader');
    await viaLoad.load({ batch: 7 });
    assert.ok(snapshot(viaSync).count >= 40, 'the fixture must actually contain entries');
    assert.deepStrictEqual(snapshot(viaLoad), snapshot(viaSync),
      'the async path may change how the bytes are read, never what the index holds');
  });

  it('a store used WITHOUT load() still sees every entry (the synchronous fallback)', () => {
    const dir = seededDir(12);
    const store = new MemoryStore(dir, 'reader');   // no load(), no start()
    assert.strictEqual(store._index.byKey.size, 12,
      'an unbuilt index must never read as an empty store — it is built on first touch');
  });

  it('load() YIELDS to the event loop instead of holding it', async () => {
    // Structural, not a stopwatch: a callback queued before the load must run during it.
    const dir = seededDir(120);
    const store = new MemoryStore(dir, 'reader');
    let ranDuring = false, loading = true;
    setTimeout(() => { if (loading) ranDuring = true; }, 0);
    await store.load({ batch: 8 });
    loading = false;
    assert.strictEqual(ranDuring, true);
  });

  it('touching the store DURING a load never double-indexes, and keeps a write made then', async () => {
    const dir = seededDir(60);
    const store = new MemoryStore(dir, 'reader');
    const pending = store.load({ batch: 4 });
    const written = store.write('written mid-load', { tags: ['race'] });   // forces the sync fallback
    await pending;
    const keys = [...store._index.byKey.keys()];
    assert.strictEqual(keys.length, new Set(keys).size, 'no key may be indexed twice');
    assert.ok(store._index.byKey.has(written.key), 'the write made during the load must survive it');
    assert.strictEqual(store._index.byKey.size, 61);
  });

  it('is idempotent, and concurrent callers share one load', async () => {
    const dir = seededDir(20);
    const store = new MemoryStore(dir, 'reader');
    await Promise.all([store.load(), store.load(), store.load()]);
    await store.load();
    assert.strictEqual(store._index.byKey.size, 20);
  });
});
