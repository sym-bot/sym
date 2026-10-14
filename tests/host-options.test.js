'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * The two constructor options XMesh depends on, now documented (0.14.1, README "Public API"): `svafEvaluator`
 * (the admission seam) and `cliHostMode` (forward only). These tests state the documented behaviour and nothing
 * else, driven through the real receive path with a signed record on a confirmed session, and read the outcome
 * from the store and the events a host sees.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const { identity, signedRecord, admitAs } = require('./_core-secure');
const { settle } = require('./_settle');

const PEER = identity('peerA');
const cat7 = (t) => ({ focus: t, issue: t, intent: t, motivation: t, commitment: t, perspective: 'peerA', mood: { text: 'neutral', valence: 0, arousal: 0 } });
const frameOf = (text) => ({ type: 'cmb', timestamp: Date.now(), content: text, cmb: signedRecord(PEER, { categories: cat7(text) }) });
const ALIGNED = { decision: 'aligned', total_drift: 0.1, category_drifts: { focus: 0.1 }, gate_values: { focus: 1 } };
const REJECTED = { decision: 'rejected', total_drift: 9, category_drifts: { focus: 9 }, gate_values: { focus: 0 } };

async function withNode(opts, fn) {
  const name = `host-opts-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), ...opts });
  await node.start();
  const seen = { accepted: [], decisions: [], logs: [] };
  node.on('cmb-accepted', (e) => seen.accepted.push(e));
  node.on('svaf-decision', (d) => seen.decisions.push(d));
  node._log = (m) => seen.logs.push(m);
  try { return await fn(node, seen); } finally {
    await node.stop();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  }
}
const deliver = async (node, f) => { node._frameHandler.handle(admitAs(node, PEER), f); await settle(); };

describe('svafEvaluator: the admission seam', () => {
  it('is called once per record that reaches the gate, with (candidate, anchors, ageSeconds) as documented', async () => {
    const calls = [];
    await withNode({ svafEvaluator: { evaluate: async (...a) => { calls.push(a); return null; } } }, async (node) => {
      node.remember(cat7('something this node already holds'));
      await deliver(node, frameOf('an observation from a peer'));
    });
    assert.strictEqual(calls.length, 1);
    const [candidate, anchors, ageSeconds] = calls[0];
    assert.deepStrictEqual(Object.keys(candidate).sort(), ['confidence', 'source', 'tags', 'text']);
    assert.match(candidate.text, /focus: an observation from a peer/, 'text is the record rendered as "category: text; ..."');
    assert.ok(Array.isArray(candidate.tags) && typeof candidate.confidence === 'number' && typeof candidate.source === 'string');
    assert.ok(Array.isArray(anchors) && anchors.length >= 1 && anchors.length <= 5, 'at most the five most recent entries');
    for (const a of anchors) assert.deepStrictEqual(Object.keys(a).sort(), ['source', 'tags', 'text']);
    assert.strictEqual(typeof ageSeconds, 'number');
  });

  it('null: the open baseline decides (what a stock node always does), and the admitted record is stored', async () => {
    await withNode({ svafEvaluator: { evaluate: async () => null } }, async (node, seen) => {
      const f = frameOf('the baseline decides this one');
      await deliver(node, f);
      assert.ok(node._store.get(f.cmb.metadata.key), 'the baseline admitted it');
      assert.strictEqual(seen.decisions.length, 1);
      assert.strictEqual(seen.decisions[0].method, 'heuristic', 'and the decision is the baseline\'s');
    });
  });

  it('a result decides instead: rejected is not stored, anything else is admitted as the evaluator decided', async () => {
    await withNode({ svafEvaluator: { evaluate: async () => REJECTED } }, async (node, seen) => {
      const f = frameOf('the evaluator refuses this one');
      await deliver(node, f);
      assert.strictEqual(node._store.get(f.cmb.metadata.key), null, 'not stored');
      assert.strictEqual(seen.decisions.length, 1);
      assert.deepStrictEqual([seen.decisions[0].method, seen.decisions[0].decision], ['neural', 'rejected']);
    });
    await withNode({ svafEvaluator: { evaluate: async () => ALIGNED } }, async (node, seen) => {
      const f = frameOf('the evaluator admits this one');
      await deliver(node, f);
      assert.ok(node._store.get(f.cmb.metadata.key), 'stored');
      assert.deepStrictEqual([seen.decisions[0].method, seen.decisions[0].decision], ['neural', 'aligned']);
    });
  });

  it('the admission waits for the evaluator: a slow evaluate delays the record by exactly that long (the scheduler seam)', async () => {
    let release;
    const gate = new Promise((r) => { release = r; });
    await withNode({ svafEvaluator: { evaluate: async () => { await gate; return null; } } }, async (node) => {
      const f = frameOf('held in the queue');
      node._frameHandler.handle(admitAs(node, PEER), f);
      await new Promise((r) => setTimeout(r, 150));
      assert.strictEqual(node._store.get(f.cmb.metadata.key), null, 'not admitted while evaluate is pending');
      release();
      await settle();
      assert.ok(node._store.get(f.cmb.metadata.key), 'admitted once it answers');
    });
  });

  it('an evaluator that throws is logged and the baseline decides: the record is not lost', async () => {
    await withNode({ svafEvaluator: { evaluate: async () => { throw new Error('model not loaded'); } } }, async (node, seen) => {
      const f = frameOf('the evaluator is down');
      await deliver(node, f);
      assert.ok(node._store.get(f.cmb.metadata.key), 'admitted by the baseline');
      assert.ok(seen.logs.some((l) => /SVAF neural error: model not loaded/.test(l)), 'and said');
    });
  });

  it('without the option a stock node runs the baseline', async () => {
    await withNode({}, async (node, seen) => {
      const f = frameOf('a stock node');
      await deliver(node, f);
      assert.ok(node._store.get(f.cmb.metadata.key));
      assert.strictEqual(seen.decisions[0].method, 'heuristic');
    });
  });
});

describe('cliHostMode: forward only', () => {
  it('a verified record is announced as cmb-accepted and nothing more: no SVAF, no attestation, not stored, not remixed', async () => {
    await withNode({ cliHostMode: true, svafEvaluator: { evaluate: async () => { throw new Error('the gate must not run'); } } }, async (node, seen) => {
      const f = frameOf('forwarded, not kept');
      await deliver(node, f);
      assert.strictEqual(seen.accepted.length, 1, 'announced once');
      assert.strictEqual(seen.accepted[0].remixed, false);
      assert.match(seen.accepted[0].content, /focus: forwarded, not kept/);
      assert.strictEqual(node._store.get(f.cmb.metadata.key), null, 'not stored');
      assert.strictEqual(node._store.count(), 0);
      assert.strictEqual(seen.decisions.length, 0, 'no SVAF evaluation was recorded');
      assert.strictEqual(node._attestations.byCmb(f.cmb.metadata.key).length, 0, 'no admission attestation');
      assert.ok(!seen.logs.some((l) => /SVAF neural error/.test(l)), 'the evaluator was never called');
    });
  });

  it('the same record on a node without the option is evaluated, attested and stored (the control)', async () => {
    await withNode({}, async (node, seen) => {
      const f = frameOf('forwarded, not kept');
      await deliver(node, f);
      assert.ok(node._store.get(f.cmb.metadata.key));
      assert.strictEqual(node._attestations.byCmb(f.cmb.metadata.key).length, 1);
      assert.strictEqual(seen.decisions.length, 1);
    });
  });

  it('the option is false by default', () => {
    const name = `host-opts-default-${Date.now()}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    try { assert.strictEqual(node._cliHostMode, false); } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });
});
