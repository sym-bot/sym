'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * The SVAF gate measures with receiver-local vectors, and those vectors must never land on a record.
 *
 * A record carries no vector (§7.1; see the NO VECTOR note in createCMB): a vector is covered by
 * neither the address nor the signature, so one written into a stored record is a value nobody can
 * check, and it is served and re-read as if it were part of what the author said.
 *
 * The gate's anchors are the store's own cached records (MemoryStore.anchors returns entry.cmb),
 * and the gate used to attach each category's vector to them IN PLACE. The vectors then sat on the
 * cached record until the next write of that entry, which is routine: a peer remix citing the
 * record advances its lifecycle and persists it. Every anchor the gate ever read was written back
 * to disk with a vector on each category.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { tmpdir } = require('./_tmpdir');
const { MemoryStore } = require('../lib/memory-store');
const { createCMB, processHeuristicSVAF, CAT7_CATEGORIES } = require('../lib/core');

const POLICY = { stableThreshold: 0.35, guardedThreshold: 0.75, temporalLambda: 0.3, freshnessSeconds: 3600 };

function cat7(t) {
  return {
    focus: t, issue: t, intent: t, motivation: t, commitment: t,
    perspective: 'observer', mood: { text: 'neutral', valence: 0, arousal: 0 },
  };
}

function vectorCategories(record) {
  return CAT7_CATEGORIES.filter((c) => record?.categories?.[c] && 'vector' in record.categories[c]);
}

describe('SVAF gate: anchors are measured, never written to', () => {
  it('after a gate pass the store holds no vector, and the next persist writes none', async () => {
    const dir = tmpdir('sym-svaf-anchor-vectors-');
    const store = new MemoryStore(dir, 'receiver');
    const anchor = store.write('anchor', { cmb: createCMB({ categories: cat7('the build pipeline caches artifacts per commit'), createdBy: 'receiver' }) });
    const incoming = createCMB({ categories: cat7('the build pipeline caches artifacts per branch'), createdBy: 'peer' });

    const now = Date.now();
    const r = await processHeuristicSVAF({
      msg: { type: 'cmb', cmb: incoming, content: 'incoming' },
      peerName: 'peer', localName: 'receiver', originTs: now, now, ageSeconds: 0,
      recentCMBs: store.recentCMBs(5), config: POLICY,
    });
    // Precondition: the gate really measured against the anchor rather than taking a cold-start exit.
    assert.strictEqual(r.coldStartCause, undefined, 'the anchor was consulted');
    assert.ok(Object.values(r.categoryVerdicts).some((v) => v !== 'silent'), 'at least one category was graded against it');

    assert.deepStrictEqual(vectorCategories(store.get(anchor.key).cmb), [], 'the cached anchor record carries no vector');
    assert.deepStrictEqual(vectorCategories(incoming), [], 'the incoming record the gate was handed carries no vector');

    // The routine write that used to carry the vectors to disk: a peer remix citing the anchor
    // advances the anchor's lifecycle, which persists the anchor's whole entry.
    const remix = createCMB({ categories: cat7('a remix that cites the cached anchor'), createdBy: 'peer', lineage: { parents: [anchor.key], method: 'test' } });
    assert.ok(store.receiveFromPeer('peer', { content: 'remix', cmb: remix }), 'the remix is stored');
    const onDisk = JSON.parse(fs.readFileSync(path.join(dir, `${anchor.key}.json`), 'utf8'));
    assert.strictEqual(onDisk.lifecycle, 'remixed', 'precondition: the anchor entry was persisted again');
    assert.deepStrictEqual(vectorCategories(onDisk.cmb), [], 'the persisted anchor carries no vector');
  });
});
