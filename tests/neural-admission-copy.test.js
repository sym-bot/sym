'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * The neural admission path stores a copy of the incoming record, never the caller's object.
 *
 * It built its entry as `{ ...msg }`, so the entry's record WAS msg.cmb, and everything the path
 * then did to "its" record (the admission attestation, the tether annotations, severance, and the
 * key and lineage it writes when the content does not collapse onto the incoming address) landed on
 * the frame the caller handed in. The heuristic path builds a new record and never had this.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const { createCMB } = require('../lib/core');

const ALIGNED = { decision: 'aligned', total_drift: 0.1, category_drifts: { focus: 0.1 }, gate_values: { focus: 1 } };

function cat7(t) {
  return {
    focus: t, issue: t, intent: t, motivation: t, commitment: t,
    perspective: 'peerA', mood: { text: 'neutral', valence: 0, arousal: 0 },
  };
}

async function withNode(fn) {
  const name = `neural-copy-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), svafEvaluator: { evaluate: async () => ALIGNED } });
  await node.start();
  try {
    return await fn(node);
  } finally {
    await node.stop();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  }
}

describe('neural admission works on a copy of the incoming record', () => {
  it('the caller\'s record is untouched, whether the content collapses onto its address or not', async () => {
    await withNode(async (node) => {
      const root = node.remember(cat7('quarterly financial audit of the accounting ledger and tax filings'));
      const cases = [];
      // Collapses: correctly addressed, cites a root this node holds (so the tether is evaluated),
      // and carries a sender's attestation the path must not store.
      const collapses = createCMB({ categories: cat7('fresh snowfall reported on the upper mountain trail sections'), createdBy: 'peerA', lineage: { parents: [root.key], method: 'SVAF-v2' } });
      collapses.tether = { of: collapses.metadata.key, anchor: root.key, verdict: 'tethered', by: 'another-integrator', drift: 0 };
      cases.push(['collapses', collapses]);
      // Does not collapse: the address it carries is not its content's, so the path writes a new
      // key and lineage on the record it stores.
      const misaddressed = createCMB({ categories: cat7('a record whose carried address is not its own'), createdBy: 'peerA' });
      misaddressed.metadata.key = 'cmb-' + '9'.repeat(64);
      cases.push(['does not collapse', misaddressed]);

      for (const [label, cmb] of cases) {
        const frame = { type: 'cmb', timestamp: Date.now(), content: label, cmb };
        const before = structuredClone(frame);
        const now = Date.now();
        await node._frameHandler._processNeuralSVAF(ALIGNED, frame, 'peerA', 'peerA', now, now);
        assert.ok(node._store.count() > 1, `${label}: precondition: something was stored`);
        assert.deepStrictEqual(frame.cmb, before.cmb, `${label}: the caller's record is exactly as it was handed in`);
      }
    });
  });

  it('a record that does not collapse is minted as this node\'s own remix, never rewritten under its author\'s name', async () => {
    // The path used to write the new key and lineage into the author's record and store that: a
    // record naming the author, carrying the author's signature, over content and descent the author
    // never signed. It is minted the way the heuristic gate mints one (buildFusedRecord).
    await withNode(async (node) => {
      const record = createCMB({ categories: cat7('a record whose carried address is not its own content'), createdBy: 'peerA' });
      record.metadata.key = 'cmb-' + '8'.repeat(64);
      record.metadata.sig = 'not-a-signature-over-anything-this-node-will-store';
      const now = Date.now();
      await node._frameHandler._processNeuralSVAF(ALIGNED, { type: 'cmb', timestamp: now, content: 'x', cmb: record }, 'peerA', 'peerA', now, now);
      const minted = node._store.recall('').find((e) => e.cmb?.categories?.focus?.text === record.categories.focus.text);
      assert.ok(minted, 'stored');
      assert.strictEqual(minted.cmb.metadata.createdBy, node.name, 'this node authors the remix it mints');
      assert.strictEqual(minted.cmb.metadata.sig, undefined, 'and carries no signature it did not make');
      assert.deepStrictEqual(minted.cmb.metadata.lineage.parents, [record.metadata.key], 'citing the block it came from');
      assert.notStrictEqual(minted.collapsed, true);
    });
  });
});
