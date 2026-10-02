'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * 0.14.0 release review B-F5: the neural admission path awaits the §15.8 tether, which encodes with
 * the model and can fail. The gate's one `.catch` took any failure for an evaluator failure and ran
 * the heuristic gate on the same frame, after the neural path had already recorded its decision and
 * signed and gossiped an attestation: one frame, decided and attested twice. Now only the evaluator's
 * own failure falls back; a later one is contained, and a tether that cannot be evaluated leaves the
 * record stored unverified.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const { createCMB } = require('../lib/core');

const ALIGNED = { decision: 'aligned', total_drift: 0.1, category_drifts: { focus: 0.1 }, gate_values: { focus: 1 } };
const cat7 = (t) => ({ focus: t, issue: t, intent: t, motivation: t, commitment: t, perspective: 'peerA', mood: { text: 'neutral', valence: 0, arousal: 0 } });

async function withNode(fn) {
  const name = `neural-after-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), svafEvaluator: { evaluate: async () => ALIGNED } });
  await node.start();
  const fh = node._frameHandler;
  const seen = { heuristic: 0, decisions: 0, logs: [] };
  const heuristic = fh._processHeuristicSVAF.bind(fh);
  fh._processHeuristicSVAF = (...a) => { seen.heuristic++; return heuristic(...a); };
  const record = node._recordDecision.bind(node);
  node._recordDecision = (d) => { seen.decisions++; return record(d); };
  node._log = (m) => seen.logs.push(m);
  try { return await fn(node, seen); } finally {
    await node.stop();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  }
}

const frame = (text) => { const cmb = createCMB({ categories: cat7(text), createdBy: 'peerA' }); return { type: 'cmb', timestamp: Date.now(), content: text, cmb }; };

describe('the neural path after its decision', () => {
  it('a tether that cannot be evaluated leaves the record stored unverified, decided and attested once', async () => {
    await withNode(async (node, seen) => {
      // A lineage anchor whose categories cannot be read: what a model fault during the encode does.
      const broken = new Proxy({}, { get() { throw new Error('encoder fault'); }, ownKeys() { throw new Error('encoder fault'); } });
      node._frameHandler._prepareLineageTether = () => ({ key: 'anchor-key', categories: broken });
      const f = frame('a remix whose tether the model cannot encode');
      await node._frameHandler._handleMemoryShare('peerA', 'peerA', f);
      const key = f.cmb.metadata.key;
      assert.strictEqual(seen.heuristic, 0, 'the heuristic gate did not run on the frame as well');
      assert.strictEqual(seen.decisions, 1, 'one decision');
      assert.strictEqual(node._attestations.byCmb(key).length, 1, 'one attestation for the frame');
      const stored = node._store.get(key);
      assert.ok(stored, 'the admitted record is stored');
      assert.strictEqual(stored.tether ?? null, null, 'with no tether verdict: unverified');
      assert.ok(seen.logs.some((l) => /tether of a record from peerA not evaluated: encoder fault/.test(l)));
    });
  });

  it('any other failure after the decision is contained: logged, and the frame is not gated again', async () => {
    await withNode(async (node, seen) => {
      node._store.receiveFromPeer = () => { throw new Error('disk full'); };
      const f = frame('an admitted record the store cannot write');
      await node._frameHandler._handleMemoryShare('peerA', 'peerA', f);
      assert.strictEqual(seen.heuristic, 0, 'not gated again');
      assert.strictEqual(seen.decisions, 1);
      assert.strictEqual(node._attestations.byCmb(f.cmb.metadata.key).length, 1, 'attested once');
      assert.ok(seen.logs.some((l) => /failed after its decision: disk full — not gated again/.test(l)), seen.logs.join('\n'));
    });
  });

  it("the evaluator's own failure still falls back to the heuristic gate", async () => {
    await withNode(async (node, seen) => {
      node._svafEvaluator = { evaluate: async () => { throw new Error('model not loaded'); } };
      await node._frameHandler._handleMemoryShare('peerA', 'peerA', frame('a record the neural evaluator cannot judge'));
      assert.strictEqual(seen.heuristic, 1);
      assert.ok(seen.logs.some((l) => /SVAF neural error: model not loaded — falling back to heuristic/.test(l)));
    });
  });
});
