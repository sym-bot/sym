'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * MMP §15.8 on the neural admission path, as MMP 2.0 update 1 states it.
 *
 * The frame handler offers each inbound block to the injected Layer-4 evaluator first and runs the
 * heuristic baseline only when that evaluator declines. Both paths keep the incoming text, so both
 * collapse onto the author's record, kept exactly as signed, and the §15.8 tether does not apply to
 * a collapsed integration (§15.5): the receiver produced no remix and asserts no descent of its own.
 * So neither path severs, evaluates or attests a tether, and neither keeps an attestation a sender
 * attached. (Until update 1 both paths severed and attested; this suite pinned that they agreed.)
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
const { createCMB, verifyTetherAttestation } = require('../lib/core');

const ALIGNED = { decision: 'aligned', total_drift: 0.1, category_drifts: { focus: 0.1 }, gate_values: { focus: 1 } };

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

// A signed v2.0 remix from peerA (Core Secure, 0.14): the lineage is inside the signed metadata.
const { identity, signedRecord, admitAs } = require('./_core-secure');
const PEER = identity('peerA');
function remixFrame(text, parentKey, extra = {}) {
  const cmb = signedRecord(PEER, { categories: cat7(text), lineage: { parents: [parentKey], method: 'SVAF-v2' } });
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
    const att = stored.tether;
    return {
      root, stored, att,
      attValid: att ? verifyTetherAttestation(att, node._identity.publicKey).valid : null,
      nodeId: node.nodeId,
    };
  });
}

describe('MMP §15.8 lineage tether on the neural admission path', () => {
  it('the stock dispatch, with a neural evaluator that admits, keeps a laundered chain as signed: no severance, no attestation', async () => {
    await awaitSemantic();
    await withNode('tether-neural-dispatch', { svafEvaluator: { evaluate: async () => ALIGNED } }, async (node) => {
      const root = createCMB({ categories: cat7(TOPIC_A), createdBy: 'peerR' });
      node._store.receiveFromPeer('peerR', { key: root.metadata.key, content: TOPIC_A, source: 'peerR', cmb: root, _cmbVerified: true });
      const frame = remixFrame(TOPIC_B_NEW, root.metadata.key);
      await node._frameHandler._handleMemoryShare(PEER.nodeId, PEER.name, frame, admitAs(node, PEER));

      const stored = node._store.get(frame.cmb.metadata.key);
      assert.ok(stored, 'the neural evaluator admitted the record');
      assert.strictEqual(stored.svaf?.method, 'neural', 'precondition: the neural path stored it');
      assert.strictEqual(stored.collapsed, true);
      assert.notStrictEqual(stored.lineage?.severed, true, 'not severed');
      assert.deepStrictEqual(node._store.parents(stored.key), [root.metadata.key], 'its signed lineage is walked');
      assert.strictEqual(stored.provenance?.tether, undefined);
      assert.strictEqual(stored.tether, undefined, 'no tether attestation');
    });
  });

  for (const [label, rootText] of [['a laundered chain', TOPIC_A], ['a faithful chain', TOPIC_B_ROOT]]) {
    it(`${label}: the neural path and the heuristic path store the same thing, with no tether`, async () => {
      await awaitSemantic();
      const frameOf = (rootKey) => remixFrame(TOPIC_B_NEW, rootKey);
      const neural = await admitThrough('neural', rootText, frameOf);
      const heuristic = await admitThrough('heuristic', rootText, frameOf);
      for (const r of [neural, heuristic]) {
        assert.strictEqual(r.att, undefined, 'not attested');
        assert.strictEqual(r.stored.collapsed, true);
        assert.strictEqual(r.stored.provenance?.tether, undefined);
      }
      assert.deepStrictEqual(neural.stored.cmb.metadata.lineage, heuristic.stored.cmb.metadata.lineage, 'same record lineage, as signed');
      assert.deepStrictEqual(neural.stored.lineage, heuristic.stored.lineage, 'same lineage in the store');
    });
  }

  it('an unresolvable root: neither path attests or severs, and neither stores the sender\'s attestation', async () => {
    await awaitSemantic();
    const sendersOwn = { of: 'cmb-' + 'c'.repeat(64), anchor: 'cmb-' + 'd'.repeat(64), verdict: 'tethered', by: 'some-other-integrator', drift: 0 };
    const frameOf = () => remixFrame(TOPIC_B_NEW, 'cmb-' + 'e'.repeat(64), { tether: { ...sendersOwn } });
    for (const path of ['neural', 'heuristic']) {
      const r = await admitThrough(path, TOPIC_B_ROOT, frameOf);
      assert.strictEqual(r.att, undefined, `${path}: no tether attestation is stored`);
      assert.strictEqual(r.stored.provenance?.tether, undefined, `${path}: the tether is unverified, not evaluated`);
      assert.deepStrictEqual(r.stored.cmb.metadata.lineage.parents, ['cmb-' + 'e'.repeat(64)], `${path}: lineage is kept`);
    }
  });
});
