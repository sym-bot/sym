'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * MMP §15.8 Lineage Tether — end-to-end severance through the heuristic gate.
 *
 * The drift-laundering scenario the tether exists to close: a chain's root is
 * about topic A; the receiver's RECENT anchors are about topic B (so the
 * §9.2 gate, which reads the five most recent anchors, admits topic-B
 * traffic); an incoming topic-B CMB carrying lineage back to the topic-A root
 * would — without the tether — store a remix whose content has nothing to do
 * with the root it cites. With the tether, the remix is stored as a fresh
 * root (lineage severed, departed source in provenance). A faithful chain
 * (remix genuinely about its root's topic) keeps its lineage intact.
 *
 * Uses the real store + real encoder (semantic when available, n-gram
 * otherwise — both sides of the tether comparison share one kernel by
 * construction, §15.8 in-gate evaluation).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const { createCMB, isSemanticReady, verifyTetherAttestation, kernelId } = require('@sym-bot/core');

// The tether's reject-floor calibration assumes the semantic kernel (the
// production default — §9.2.1: thresholds are meaningful only within a pinned
// encoder). The encoder loads async at module require; wait for it so the
// test exercises the deployed configuration, not the n-gram warmup fallback.
async function awaitSemantic(timeoutMs = 30000) {
  const t0 = Date.now();
  while (!isSemanticReady()) {
    if (Date.now() - t0 > timeoutMs) throw new Error('semantic encoder did not become ready');
    await new Promise((r) => setTimeout(r, 200));
  }
}

async function withNode(baseName, fn) {
  const name = `${baseName}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
  await node.start();
  try {
    return await fn(node);
  } finally {
    await node.stop();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  }
}

function cat7(topicText) {
  return {
    focus: topicText,
    issue: topicText,
    intent: topicText,
    motivation: topicText,
    commitment: topicText,
    perspective: 'peerA',
    mood: { text: 'neutral', valence: 0, arousal: 0 },
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
const TOPIC_B_NEW = 'fresh snowfall reported on the upper mountain trail sections';
// A topic-B root DISTINCT from the recent-5 anchors (a faithful incoming must
// admit against the recents — near-duplicating one would be redundant-banned).
const TOPIC_B_ROOT = 'overall report on snowy mountain hiking trail conditions this weekend';

// The store normalizes a severed (null) lineage to root shape.
function isRootShaped(lineage) {
  return lineage == null
    || ((lineage.parents ?? []).length === 0 && (lineage.ancestors ?? []).length === 0);
}

function inboundFrame(topicText, rootKey) {
  const cmb = createCMB({ fields: cat7(topicText), createdBy: 'peerA' });
  cmb.metadata.lineage = { parents: [rootKey], ancestors: [rootKey], method: 'SVAF-v2' };
  return { type: 'cmb', timestamp: Date.now(), content: topicText, source: 'peerA', cmb };
}

async function seedAndReceive(node, rootTopic, incomingTopic) {
  await awaitSemantic();
  const root = node.remember(cat7(rootTopic));
  assert.ok(root && root.key, 'seed root stored');
  for (const t of TOPIC_B) node.remember(cat7(t)); // fills the recent-5 window
  const accepted = [];
  node.on('cmb-accepted', (e) => accepted.push(e));
  const now = Date.now();
  await node._frameHandler._processHeuristicSVAF(
    inboundFrame(incomingTopic, root.key), 'peerA', 'peerA', now, now, 0);
  return { root, accepted };
}

describe('MMP §15.8 lineage tether — severance through the gate', () => {
  it('drift laundering severs: topic-B remix citing a topic-A root is stored as a fresh root', async () => {
    await withNode('tether-sever', async (node) => {
      const { accepted } = await seedAndReceive(node, TOPIC_A, TOPIC_B_NEW);
      assert.strictEqual(accepted.length, 1, 'incoming admits (aligned with recent topic-B anchors)');
      const cmb = accepted[0].cmb;
      assert.ok(isRootShaped(cmb.metadata.lineage), 'lineage severed — stored as a fresh root');
      assert.ok(cmb.provenance.tether, 'tether recorded in provenance');
      assert.strictEqual(cmb.provenance.tether.severed, true);
      assert.ok(cmb.provenance.tether.drift > 0.5, `drift ${cmb.provenance.tether.drift} exceeds the reject floor`);
      assert.ok(cmb.provenance.tether.departedFrom, 'departed source recorded informally');

      // §15.8 tether attestation: the integrator's signed record of this exact
      // evaluation rides the remix, verifiable against the node's identity key,
      // and names the kernel the verdict was made in.
      const att = cmb.tether;
      assert.ok(att, 'tether attestation attached');
      assert.strictEqual(att.verdict, 'severed');
      assert.strictEqual(att.of, cmb.metadata.key);
      assert.strictEqual(att.kernelId, kernelId(), 'attestation names the evaluating kernel');
      const v = verifyTetherAttestation(att, node._identity.publicKey);
      assert.deepStrictEqual({ signed: v.signed, valid: v.valid }, { signed: true, valid: true });
    });
  });

  it('faithful chain keeps lineage: topic-B remix citing a topic-B root stays tethered', async () => {
    await withNode('tether-keep', async (node) => {
      const { root, accepted } = await seedAndReceive(node, TOPIC_B_ROOT, TOPIC_B_NEW);
      assert.strictEqual(accepted.length, 1, 'incoming admits');
      const cmb = accepted[0].cmb;
      assert.ok(!isRootShaped(cmb.metadata.lineage), 'lineage intact');
      assert.ok(cmb.metadata.lineage.ancestors.includes(root.key), 'chain still reaches its root');
      assert.strictEqual(cmb.provenance.tether.severed, false);
      assert.ok(cmb.provenance.tether.drift <= 0.5);
      assert.strictEqual(cmb.tether?.verdict, 'tethered', 'kept chains carry a tethered attestation');
    });
  });

  it('tether disabled (SYM_LINEAGE_TETHER analogue: opts.lineageTether=false) → no severance', async () => {
    const name = `tether-off-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), lineageTether: false });
    await node.start();
    try {
      await awaitSemantic();
      const root = node.remember(cat7(TOPIC_A));
      for (const t of TOPIC_B) node.remember(cat7(t));
      const accepted = [];
      node.on('cmb-accepted', (e) => accepted.push(e));
      const now = Date.now();
      await node._frameHandler._processHeuristicSVAF(
        inboundFrame(TOPIC_B_NEW, root.key), 'peerA', 'peerA', now, now, 0);
      assert.strictEqual(accepted.length, 1);
      assert.ok(!isRootShaped(accepted[0].cmb.metadata.lineage), 'lineage untouched when the tether is disabled');
    } finally {
      await node.stop();
      fs.rmSync(nodeDir(name), { recursive: true, force: true });
    }
  });
});
