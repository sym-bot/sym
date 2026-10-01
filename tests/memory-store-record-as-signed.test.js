'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * The store keeps a record exactly as it was signed. What the store needs for itself lives on the
 * entry that wraps the record, never inside it.
 *
 * Both write paths stored `{ ...cmb, lineage }`: the store's expanded lineage (direct parents plus a
 * locally computed ancestor closure) copied onto the record as a top-level member. A two-section
 * record has exactly two members, `categories` and `metadata`, and its lineage lives in
 * metadata.lineage (§8.8.1). The third member read as the pre-boundary shape, so classifyAddress
 * took its parents as the record's, derived a remix address, and reported every stored v2 remix as
 * a MISMATCH, which reads as tampering, though the record was untouched.
 *
 * Stores written before the fix hold that member on disk, so reading must drop it as well.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { tmpdir } = require('./_tmpdir');
const { MemoryStore } = require('../lib/memory-store');
const { createCMB, classifyAddress } = require('../lib/core');

function cat7(t) {
  return {
    focus: t, issue: t, intent: t, motivation: t, commitment: t,
    perspective: 'observer', mood: { text: 'neutral', valence: 0, arousal: 0 },
  };
}

function remixOf(parentKey, text) {
  return createCMB({ categories: cat7(text), createdBy: 'peer', lineage: { parents: [parentKey], method: 'svaf-heuristic' } });
}

describe('MemoryStore keeps the record as signed', () => {
  it('a stored v2 remix is the two-section record and classifies as verified', () => {
    const store = new MemoryStore(tmpdir('sym-store-as-signed-'), 'receiver');
    const root = store.write('root', { cmb: createCMB({ categories: cat7('the root block'), createdBy: 'receiver' }) });
    const remix = remixOf(root.key, 'a remix of the root block');
    assert.strictEqual(classifyAddress(remix).state, 'verified', 'precondition: the record verifies as signed');

    const received = store.receiveFromPeer('peer', { content: 'remix', cmb: remix });
    const written = store.write('local remix', { cmb: remixOf(root.key, 'a local remix of the root block') });
    for (const [label, entry] of [['receiveFromPeer', received], ['write', written]]) {
      const cmb = store.get(entry.key).cmb;
      assert.deepStrictEqual(classifyAddress(cmb), { state: 'verified', scheme: 'block-v2', reason: null }, `${label}: the stored remix verifies`);
      assert.deepStrictEqual(Object.keys(cmb).sort(), ['categories', 'metadata'], `${label}: exactly the two sections`);
      assert.deepStrictEqual(cmb.metadata.lineage.parents, [root.key], `${label}: its own lineage, as signed`);
      // The store's closure is still kept, on the entry.
      assert.deepStrictEqual(entry.lineage.ancestors, [root.key], `${label}: the entry carries the store's closure`);
      assert.deepStrictEqual(store.ancestors(entry.key), [root.key], `${label}: and the index walks from it`);
    }
  });

  it('a store file written before the fix reads back as the record it was signed as', async () => {
    const dir = tmpdir('sym-store-legacy-staple-');
    const root = createCMB({ categories: cat7('the root block'), createdBy: 'peer' });
    const remix = remixOf(root.metadata.key, 'a remix of the root block');
    const lineage = { parents: [root.metadata.key], ancestors: [root.metadata.key], method: 'svaf-heuristic' };
    // The exact shape receiveFromPeer used to persist.
    const stale = { key: remix.metadata.key, content: 'remix', peerId: 'peer', tier: 'hot', lifecycle: 'observed', storedAt: Date.now(), cmb: { ...remix, lineage }, lineage };
    fs.writeFileSync(path.join(dir, `${stale.key}.json`), JSON.stringify(stale, null, 2));
    assert.strictEqual(classifyAddress(stale.cmb).state, 'mismatch', 'precondition: the stapled member is what misclassified it');

    // Both ways a store builds its index: on first touch (synchronous) and through load().
    const syncStore = new MemoryStore(dir, 'receiver');
    const asyncStore = new MemoryStore(dir, 'receiver');
    await asyncStore.load();
    for (const [label, store] of [['first touch', syncStore], ['load()', asyncStore]]) {
      const entry = store.get(stale.key);
      assert.strictEqual(classifyAddress(entry.cmb).state, 'verified', `${label}: the stored remix verifies`);
      assert.deepStrictEqual(Object.keys(entry.cmb).sort(), ['categories', 'metadata'], `${label}: the stapled member is gone`);
      assert.deepStrictEqual(store.ancestors(stale.key), [root.metadata.key], `${label}: the closure still comes from the entry`);
    }

    // Compaction re-reads the file and writes it back; what it writes is the record as signed.
    syncStore.compact(-1);
    const rewritten = JSON.parse(fs.readFileSync(path.join(dir, `${stale.key}.json`), 'utf8'));
    assert.strictEqual(rewritten.tier, 'cold', 'precondition: compaction rewrote the file');
    assert.deepStrictEqual(Object.keys(rewritten.cmb).sort(), ['categories', 'metadata'], 'the rewritten file holds the record as signed');
  });
});
