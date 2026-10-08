'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * §15.8 severance never edits a signed record, and a record kept as its author signed it is never
 * severed at all.
 *
 * When the gate admits a block unchanged, the record it stores IS the author's signed block (the
 * collapse). Severance used to null that record's metadata.lineage, which the signature covers, so
 * a severed record no longer verified under its author's key. MMP 2.0 update 1 (§15.5, #17) then
 * says the §15.8 tether does not apply to a collapsed integration at all: the receiver produced no
 * remix and asserts no descent of its own, and the record's lineage is its author's. So a collapsed
 * record is stored exactly as signed, its lineage walked as signed, with no tether.
 *
 * Severance remains this node's judgement about records it minted itself (the retroactive audit),
 * kept where this node's judgements live: on the entry (entry.lineage.severed) and in the store's
 * lineage index, never in the record. Every walk of stored lineage honours the entry: the index, the
 * §15.8 anchor walk, and a rebuild of the index from disk.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const { MemoryStore } = require('../lib/memory-store');
const { createCMB, signCMB, verifyCMB, resolveTetherAnchor } = require('../lib/core');

const ALIGNED = { decision: 'aligned', total_drift: 0.1, category_drifts: { focus: 0.1 }, gate_values: { focus: 1 } };

function rawKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  return { pub: publicKey.slice(-32).toString('base64url'), priv: privateKey.slice(-32).toString('base64url') };
}
const AUTHOR = rawKeypair();

const { awaitSemantic } = require('./_semantic');

function cat7(t) {
  return {
    focus: t, issue: t, intent: t, motivation: t, commitment: t,
    perspective: 'peerA', mood: { text: 'neutral', valence: 0, arousal: 0 },
  };
}

const TOPIC_A = 'quarterly financial audit of the accounting ledger and tax filings';
const TOPIC_B = [
  'hiking trail conditions in the mountain snow this weekend',
  'which boots and crampons to pack for the icy mountain ascent',
  'trailhead parking permits and the shuttle bus timetable',
  'weather forecast apps for alpine ridge crossings',
  'campsite reservations near the mountain trailhead',
];
const LAUNDERED = 'fresh snowfall reported on the upper mountain trail sections';
const CITES_SEVERED = 'deep snow drifts covering the mountain hiking path near the summit ridge';

async function withNode(opts, fn) {
  const name = `sever-signed-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), ...opts });
  await node.start();
  try {
    return await fn(node, name);
  } finally {
    await node.stop();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  }
}

/** A remix of `parentKey`, signed by AUTHOR. */
function signedRemix(text, parentKey) {
  const cmb = createCMB({ categories: cat7(text), createdBy: 'peerA', lineage: { parents: [parentKey], method: 'SVAF-v2' } });
  signCMB(cmb, AUTHOR.priv);
  return cmb;
}

/** The severance as every reader of stored lineage must see it, live and after a rebuild from disk. */
function assertSevered(node, label, record, rootKey, authorKey = AUTHOR.pub) {
  const entry = node._store.get(record.metadata.key);
  assert.ok(entry, `${label}: stored`);
  assert.strictEqual(verifyCMB(entry.cmb, authorKey).valid, true, `${label}: the stored record still verifies under its author's key`);
  assert.deepStrictEqual(entry.cmb.metadata.lineage, record.metadata.lineage, `${label}: its lineage is exactly as signed`);
  assert.strictEqual(entry.lineage?.severed, true, `${label}: the severance is on the entry`);
  assert.strictEqual(entry.provenance?.tether?.severed, true, `${label}: and in its provenance`);
  for (const [where, store] of [['live', node._store], ['rebuilt from disk', new MemoryStore(node._store._dir, 'reader')]]) {
    assert.deepStrictEqual(store.parents(record.metadata.key), [], `${label} (${where}): no parents in the lineage index`);
    assert.deepStrictEqual(store.ancestors(record.metadata.key), [], `${label} (${where}): no ancestors`);
    assert.ok(!store.descendants(rootKey).includes(record.metadata.key), `${label} (${where}): no longer walked as the root's descendant`);
  }
  // The §15.8 walk from a block citing the severed one stops there: it does not reach the root
  // through a lineage this node severed.
  const next = signedRemix(CITES_SEVERED, record.metadata.key);
  const anchor = resolveTetherAnchor(next, (k) => node._store.get(k));
  assert.strictEqual(anchor.key, record.metadata.key, `${label}: the anchor walk does not pass through the severance`);
}

describe('§15.8 severance keeps the author\'s record as signed', () => {
  for (const path of ['heuristic', 'neural']) {
    it(`${path} gate: a collapsed record is stored as signed and never severed (§15.5, MMP 2.0 update 1)`, async () => {
      await awaitSemantic();
      const opts = path === 'neural' ? { svafEvaluator: { evaluate: async () => ALIGNED } } : {};
      await withNode(opts, async (node) => {
        const root = node.remember(cat7(TOPIC_A));
        for (const t of TOPIC_B) node.remember(cat7(t)); // the recent window the heuristic gate admits against
        const record = signedRemix(LAUNDERED, root.key);
        const frame = { type: 'cmb', timestamp: Date.now(), content: LAUNDERED, cmb: JSON.parse(JSON.stringify(record)), _cmbVerified: true };
        const now = Date.now();
        if (path === 'neural') await node._frameHandler._processNeuralSVAF(ALIGNED, frame, 'peerA', 'peerA', now, now);
        else await node._frameHandler._processHeuristicSVAF(frame, 'peerA', 'peerA', now, now, 0);
        const entry = node._store.get(record.metadata.key);
        assert.strictEqual(entry?.collapsed, true, 'precondition: the stored record is the author\'s block');
        assert.strictEqual(verifyCMB(entry.cmb, AUTHOR.pub).valid, true, 'it verifies under its author\'s key');
        assert.deepStrictEqual(entry.cmb.metadata.lineage, record.metadata.lineage, 'its lineage is exactly as signed');
        assert.notStrictEqual(entry.lineage?.severed, true, 'not severed');
        assert.strictEqual(entry.tether, undefined, 'no tether attestation');
        assert.strictEqual(entry.provenance?.tether, undefined, 'no tether evaluated');
        assert.deepStrictEqual(node._store.parents(record.metadata.key), [root.key], 'walked as its author signed it');
      });
    });
  }

  it('the retroactive audit severs a record of this node\'s own on the entry, and the record still verifies', async () => {
    await awaitSemantic();
    await withNode({}, async (node) => {
      const root = node.remember(cat7(TOPIC_A));
      const own = node.remember(cat7(LAUNDERED), { parents: [{ key: root.key }] });
      const record = JSON.parse(JSON.stringify(own.cmb));
      const r1 = await node.auditLineageTethers({ sever: true });
      assert.strictEqual(r1.severed, 1, 'precondition: the audit severed it');
      assertSevered(node, 'audit', record, root.key, node._identity.publicKey);
      const r2 = await node.auditLineageTethers({ sever: true });
      assert.strictEqual(r2.audited, 0, 'a severed record is a root to the audit: there is no chain left to check');
    });
  });
});
