'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * MMP §15.8 applies to every remix a node integrates, whichever gate admitted it.
 *
 * The frame handler offers each inbound block to the injected Layer-4 evaluator first and runs the
 * heuristic baseline only when that evaluator declines. The heuristic path resolved the lineage
 * root, evaluated the stored record against it, severed a drifted chain and signed a tether
 * attestation. The neural path did none of it: a remix the neural evaluator admitted kept a
 * laundered lineage, carried no attestation, and kept whatever attestation the sender had attached.
 *
 * The neural evaluator is dormant in a stock install (models/svaf_v2.pt is not shipped), so it is
 * stubbed here with the result shape it returns.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const { createCMB, isSemanticReady, verifyTetherAttestation } = require('../lib/core');

const ALIGNED = { decision: 'aligned', total_drift: 0.1, category_drifts: { focus: 0.1 }, gate_values: { focus: 1 } };

// The reject floor is calibrated on the semantic kernel (§9.2.1), as in the other tether tests.
async function awaitSemantic(timeoutMs = 30000) {
  const t0 = Date.now();
  while (!isSemanticReady()) {
    if (Date.now() - t0 > timeoutMs) throw new Error('semantic encoder did not become ready');
    await new Promise((r) => setTimeout(r, 200));
  }
}

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
const TOPIC_B_ROOT = 'overall report on snowy mountain hiking trail conditions this weekend';
const TOPIC_B_NEW = 'fresh snowfall reported on the upper mountain trail sections';

async function withNode(baseName, opts, fn) {
  const name = `${baseName}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), ...opts });
  await node.start();
  try {
    return await fn(node);
  } finally {
    await node.stop();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  }
}

function remixFrame(text, parentKey, extra = {}) {
  const cmb = createCMB({ categories: cat7(text), createdBy: 'peerA' });
  cmb.metadata.lineage = { parents: [parentKey], method: 'SVAF-v2' };
  Object.assign(cmb, extra);
  return { type: 'cmb', timestamp: Date.now(), content: text, cmb };
}

/** Seed a node with a root and the recent topic-B window both gates admit against. */
function seed(node, rootText) {
  const root = node.remember(cat7(rootText));
  for (const t of TOPIC_B) node.remember(cat7(t));
  return root;
}

/** Admit one remix of `rootText` through the named path; return the stored entry. */
async function admitThrough(path, rootText, frameOf) {
  return withNode(`tether-${path}`, path === 'neural' ? { svafEvaluator: { evaluate: async () => ALIGNED } } : {}, async (node) => {
    const root = seed(node, rootText);
    const frame = frameOf(root.key);
    const now = Date.now();
    if (path === 'neural') await node._frameHandler._processNeuralSVAF(ALIGNED, frame, 'peerA', 'peerA', now, now);
    else await node._frameHandler._processHeuristicSVAF(frame, 'peerA', 'peerA', now, now, 0);
    const stored = node._store.get(frame.cmb.metadata.key);
    assert.ok(stored, `${path}: the remix is stored`);
    const att = stored.cmb.tether;
    return {
      root, stored, att,
      attValid: att ? verifyTetherAttestation(att, node._identity.publicKey).valid : null,
      nodeId: node.nodeId,
    };
  });
}

describe('MMP §15.8 lineage tether on the neural admission path', () => {
  it('the stock dispatch, with a neural evaluator that admits, severs a laundered chain and attests it', async () => {
    await awaitSemantic();
    await withNode('tether-neural-dispatch', { svafEvaluator: { evaluate: async () => ALIGNED } }, async (node) => {
      // The root is held as a verified peer admission: a remix citing a block this node authored
      // would be dropped as an echo before any gate runs.
      const root = createCMB({ categories: cat7(TOPIC_A), createdBy: 'peerR' });
      node._store.receiveFromPeer('peerR', { key: root.metadata.key, content: TOPIC_A, source: 'peerR', cmb: root, _cmbVerified: true });
      const frame = remixFrame(TOPIC_B_NEW, root.metadata.key);
      await node._frameHandler._handleMemoryShare('peerA', 'peerA', frame);

      const stored = node._store.get(frame.cmb.metadata.key);
      assert.ok(stored, 'the neural evaluator admitted the remix');
      assert.strictEqual(stored.svaf?.method, 'neural', 'precondition: the neural path stored it');
      assert.strictEqual(stored.cmb.metadata.lineage, null, 'the laundered lineage is severed');
      assert.strictEqual(stored.cmb.provenance?.tether?.severed, true);
      assert.strictEqual(stored.cmb.provenance.tether.departedFrom, root.metadata.key);
      const att = stored.cmb.tether;
      assert.ok(att, 'a tether attestation is attached');
      assert.strictEqual(att.verdict, 'severed');
      assert.strictEqual(att.anchor, root.metadata.key);
      assert.strictEqual(att.by, node.nodeId);
      assert.strictEqual(verifyTetherAttestation(att, node._identity.publicKey).valid, true);
    });
  });

  for (const [label, rootText] of [['a laundered chain', TOPIC_A], ['a faithful chain', TOPIC_B_ROOT]]) {
    it(`${label}: the neural path reaches the verdict the heuristic path does`, async () => {
      await awaitSemantic();
      const frameOf = (rootKey) => remixFrame(TOPIC_B_NEW, rootKey);
      const neural = await admitThrough('neural', rootText, frameOf);
      const heuristic = await admitThrough('heuristic', rootText, frameOf);
      for (const r of [neural, heuristic]) {
        assert.ok(r.att, 'attested');
        assert.strictEqual(r.attValid, true);
        assert.strictEqual(r.att.by, r.nodeId);
        assert.strictEqual(r.att.anchor, r.root.key);
      }
      assert.strictEqual(neural.att.verdict, heuristic.att.verdict, 'same verdict');
      assert.strictEqual(neural.att.kernelId, heuristic.att.kernelId, 'one kernel, so the drifts are comparable');
      assert.strictEqual(neural.att.drift.toFixed(6), heuristic.att.drift.toFixed(6), 'same drift: one computation');
      const withoutDrift = ({ drift, ...rest }) => rest; // drift is compared above, to the precision it is signed at
      assert.deepStrictEqual(withoutDrift(neural.stored.cmb.provenance.tether), withoutDrift(heuristic.stored.cmb.provenance.tether), 'same provenance');
      assert.deepStrictEqual(neural.stored.cmb.metadata.lineage, heuristic.stored.cmb.metadata.lineage, 'same lineage outcome');
      assert.strictEqual(neural.att.verdict, rootText === TOPIC_A ? 'severed' : 'tethered');
    });
  }

  it('an unresolvable root: neither path attests or severs, and neither stores the sender\'s attestation', async () => {
    await awaitSemantic();
    const sendersOwn = { of: 'cmb-' + 'c'.repeat(64), anchor: 'cmb-' + 'd'.repeat(64), verdict: 'tethered', by: 'some-other-integrator', drift: 0 };
    const frameOf = () => remixFrame(TOPIC_B_NEW, 'cmb-' + 'e'.repeat(64), { tether: { ...sendersOwn } });
    for (const path of ['neural', 'heuristic']) {
      const r = await admitThrough(path, TOPIC_B_ROOT, frameOf);
      assert.strictEqual(r.att, undefined, `${path}: no tether attestation is stored`);
      assert.strictEqual(r.stored.cmb.provenance?.tether, undefined, `${path}: the tether is unverified, not evaluated`);
      assert.deepStrictEqual(r.stored.cmb.metadata.lineage.parents, ['cmb-' + 'e'.repeat(64)], `${path}: lineage is kept`);
    }
  });
});
