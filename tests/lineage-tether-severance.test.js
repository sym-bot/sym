'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * MMP §15.8 Lineage Tether through the heuristic gate, as MMP 2.0 update 1 states it.
 *
 * The drift-laundering scenario the tether exists to close: a chain's root is about topic A; an
 * incoming topic-B record cites it. The tether is the REMIXING node's duty (§15.8: "at integration
 * time, the remixing node MUST evaluate its remix"), and it does not apply to a collapsed integration
 * (§15.5): the receiver produced no remix and asserts no descent of its own. sym's gate keeps the
 * incoming text, so every integration it makes collapses onto the author's record, kept exactly as
 * signed. Until update 1 this suite pinned the opposite: the receiver severed and attested the
 * author's chain. It now pins that the receiver does neither, whatever the drift, and that disabling
 * the tether changes nothing here.
 *
 * Uses the real store + real encoder (semantic when available, n-gram otherwise).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const { createCMB } = require('../lib/core');

// The tether's reject-floor calibration assumes the semantic kernel (the
// production default — §9.2.1: thresholds are meaningful only within a pinned
// encoder). The encoder loads async at module require; wait for it so the
const { awaitSemantic } = require('./_semantic');

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

// A record's lineage with no parents: a root.
function isRootShaped(lineage) {
  return lineage == null
    || ((lineage.parents ?? []).length === 0 && (lineage.ancestors ?? []).length === 0);
}

function inboundFrame(topicText, rootKey) {
  const cmb = createCMB({ categories: cat7(topicText), createdBy: 'peerA' });
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

describe('MMP §15.8 lineage tether — not the receiver\'s on a collapsed integration', () => {
  for (const [label, rootTopic] of [['a laundered chain (topic-B record citing a topic-A root)', TOPIC_A], ['a faithful chain (topic-B record citing a topic-B root)', TOPIC_B_ROOT]]) {
    it(`${label}: admitted, kept as signed, never severed, no tether attestation`, async () => {
      await withNode('tether-collapsed', async (node) => {
        const { root, accepted } = await seedAndReceive(node, rootTopic, TOPIC_B_NEW);
        assert.strictEqual(accepted.length, 1, 'incoming admits (aligned with recent topic-B anchors)');
        const entry = accepted[0];
        assert.strictEqual(entry.collapsed, true, 'the gate kept the author\'s record');
        assert.ok(!isRootShaped(entry.cmb.metadata.lineage), 'the record\'s own lineage is untouched');
        assert.notStrictEqual(entry.lineage?.severed, true, 'not severed');
        assert.deepStrictEqual(node._store.parents(entry.key), [root.key], 'the store walks its signed lineage');
        assert.strictEqual(entry.provenance?.tether, undefined, 'no tether evaluated');
        assert.strictEqual(entry.tether, undefined, 'no tether attestation');
      });
    });
  }

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
