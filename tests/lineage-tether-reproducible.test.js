'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * MMP §15.8 — the tether is CONTENT-ONLY, so it is REPRODUCIBLE.
 *
 * "No vector crosses the wire: the root is content-addressed, so any holder of the root re-encodes
 * its text and recomputes the tether." That sentence is the reason a tether attestation can be
 * checked at all: a node that holds the root and the record recomputes the number the integrator
 * signed. It holds only if the number is a function of the two texts and the kernel — nothing that
 * belongs to the integrator alone.
 *
 * The gate measured the remix side on its FUSED vectors, and a fused vector is the receiver's
 * attention readout over its own recent anchors. Two nodes holding the same root and the same
 * record signed different drifts, and neither could reproduce the other's.
 *
 * The cold-start exit returned without a tether at all, so a node with nothing in its anchor window
 * stored a remix with its lineage unexamined — a laundered chain passed exactly where memory is
 * thinnest.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const core = require('../lib/core');
const { createCMB, evaluateLineageTetherFromText, processHeuristicSVAF } = core;

// The reject-floor calibration assumes the semantic kernel (§9.2.1: thresholds are meaningful only
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

function cat7(t) {
  return {
    focus: t, issue: t, intent: t, motivation: t, commitment: t,
    perspective: 'peerA', mood: { text: 'neutral', valence: 0, arousal: 0 },
  };
}

const ROOT = 'overall report on snowy mountain hiking trail conditions this weekend';
const INCOMING = 'fresh snowfall reported on the upper mountain trail sections';
const LAUNDERED_ROOT = 'quarterly financial audit of the accounting ledger and tax filings';
// Two different memories of the same domain: both admit INCOMING, through different anchors.
const MEMORY_1 = [
  'hiking trail conditions in the mountain snow this weekend',
  'which boots and crampons to pack for the icy mountain ascent',
  'trailhead parking permits and the shuttle bus timetable',
  'weather forecast apps for alpine ridge crossings',
  'campsite reservations near the mountain trailhead',
];
const MEMORY_2 = [
  'avalanche risk bulletin for the backcountry slopes above the trail',
  'snowshoe routes recommended for beginners on the mountain this winter',
  'trail map showing the switchbacks up to the alpine lake',
  'mountain hut booking for the overnight hike in the snow',
  'icy patches reported on the lower forest section of the trail',
];

const POLICY = { stableThreshold: 0.25, guardedThreshold: 0.5, temporalLambda: 0.3, freshnessSeconds: 1800 };

function remixFrame(text, rootKey) {
  const cmb = createCMB({ categories: cat7(text), createdBy: 'peerA', lineage: { parents: [rootKey], method: 'SVAF-v2' } });
  return { type: 'cmb', timestamp: Date.now(), content: text, cmb };
}

/** Deliver a frame to a node's gate and return the record it stored for it. */
async function admit(node, frame) {
  const accepted = [];
  const onAccepted = (e) => accepted.push(e);
  node.on('cmb-accepted', onAccepted);
  const now = Date.now();
  try {
    await node._frameHandler._processHeuristicSVAF(frame, 'peerA', 'peerA', now, now, 0);
  } finally {
    node.off('cmb-accepted', onAccepted);
  }
  return accepted.find((e) => e.key === frame.cmb.metadata.key) || null;
}

describe('§15.8 tether is reproducible by any holder of the root and the record (B-L5)', () => {
  it('the tether is a function of the root and the record alone: two nodes with different memories measure the same, and neither signs one about a collapsed record', async () => {
    await awaitSemantic();
    const seen = [];
    for (const [label, memory] of [['n1', MEMORY_1], ['n2', MEMORY_2]]) {
      await withNode(`tether-repro-${label}`, async (node) => {
        const root = node.remember(cat7(ROOT));
        for (const t of memory) node.remember(cat7(t));
        const stored = await admit(node, remixFrame(INCOMING, root.key));
        assert.ok(stored, `${label}: the record admits`);
        // MMP 2.0 update 1, §15.5: the gate kept the author's record, so the tether is not the receiver's.
        assert.strictEqual(stored.collapsed, true);
        assert.strictEqual(stored.tether, undefined, `${label}: no tether signed about a collapsed record`);
        const ev = await evaluateLineageTetherFromText({
          remixCategories: stored.cmb.categories, anchorCategories: root.cmb.categories,
          categoryWeights: node._svafCategoryWeights, guardedThreshold: node._svafGuardedThreshold,
        });
        seen.push({ label, ev, record: stored.cmb });
      });
    }
    const [a, b] = seen;
    assert.strictEqual(a.record.metadata.key, b.record.metadata.key, 'precondition: the same record on both nodes');
    assert.strictEqual(a.ev.kernelId, b.ev.kernelId, 'precondition: one kernel, so the drifts are comparable');
    assert.strictEqual(a.ev.drift.toFixed(6), b.ev.drift.toFixed(6), 'both measure the same drift: memory plays no part');
    assert.strictEqual(a.ev.tethered, b.ev.tethered);
  });

  it('a vector no text backs is not content, and never enters the tether', async () => {
    // A vector is outside the content address and is not served by cmb-fetch, so a holder who
    // fetched the root has none: a tether that used one could not be recomputed by anyone else.
    const v = Array.from({ length: 8 }, (_, i) => (i === 0 ? 1 : 0));
    const r = await evaluateLineageTetherFromText({
      remixCategories: { focus: { text: '', vector: v } },
      anchorCategories: { focus: { text: '', vector: v } },
      guardedThreshold: 0.5,
    });
    assert.strictEqual(r.checked, false, 'nothing content-addressed to compare');
    assert.deepStrictEqual(r.evaluableCategories, []);
  });

  it('both sides are encoded in ONE kernel even when the encoder switches mid-evaluation', async () => {
    // The semantic encoder loads asynchronously and replaces the lexical one while the node is
    // running, so the two sides of a single evaluation could otherwise straddle the switch: the
    // remix encoded lexically, the anchor semantically, in spaces that share a dimension and
    // nothing else. §15.8: both sides MUST be encoded within a single kernel.
    const ctxPath = require.resolve('../lib/core/context-encoder');
    const ltPath = require.resolve('../lib/core/lineage-tether');
    const realCtx = require.cache[ctxPath];
    const realLt = require.cache[ltPath];
    let kernel = 'kernel-before';
    let encodes = 0;
    const fakeCtx = {
      ...realCtx.exports,
      kernelId: () => kernel,
      encodeForSVAF: async () => {
        const k = kernel;
        if (++encodes === 1) kernel = 'kernel-after'; // the switch lands right after the first encode
        return { h1: k === 'kernel-before' ? [1, 0] : [0, 1], h2: [] };
      },
    };
    try {
      require.cache[ctxPath] = { id: ctxPath, filename: ctxPath, loaded: true, exports: fakeCtx };
      delete require.cache[ltPath];
      const lt = require(ltPath);
      const same = { focus: { text: 'the same words on both sides' } };
      const r = await lt.evaluateLineageTetherFromText({ remixCategories: same, anchorCategories: same, guardedThreshold: 0.5 });
      assert.strictEqual(r.kernelId, 'kernel-after', 'the verdict names the kernel both sides were encoded in');
      assert.strictEqual(r.drift, 0, 'identical text in one kernel has no drift');
      assert.strictEqual(r.tethered, true);
    } finally {
      require.cache[ctxPath] = realCtx;
      require.cache[ltPath] = realLt;
    }
  });
});

describe('§15.8 and cold start (B-L6): a cold-start admission is a collapsed integration like a warm one', () => {
  it('an empty-memory admission of a record keeps it as signed, with no tether, as a warm one does', async () => {
    await awaitSemantic();
    const root = createCMB({ categories: cat7(LAUNDERED_ROOT), createdBy: 'author' });
    const frame = remixFrame(INCOMING, root.metadata.key);
    const r = await processHeuristicSVAF({
      msg: frame, peerName: 'peerA', localName: 'receiver', originTs: Date.now(), now: Date.now(), ageSeconds: 0,
      recentCMBs: [], config: POLICY,
      tetherAnchor: { key: root.metadata.key, categories: root.categories },
    });
    assert.strictEqual(r.accepted, true, 'cold start admits to bootstrap memory');
    assert.strictEqual(r.coldStartCause, 'empty-memory', 'precondition: this is the cold-start exit');
    assert.strictEqual(r.fusedEntry.collapsed, true, 'the author\'s record, kept as signed');
    assert.strictEqual(r.tether, null, 'the §15.8 tether does not apply to a collapsed integration (§15.5)');
  });

  it('a fresh node and a warm node store a peer root alike: as signed, with no tether', async () => {
    await awaitSemantic();
    for (const warm of [false, true]) {
      await withNode(`tether-cold-${warm ? 'warm' : 'cold'}`, async (node) => {
        if (warm) for (const t of MEMORY_1) node.remember(cat7(t));
        const peerRoot = createCMB({ categories: cat7(ROOT), createdBy: 'peerA' });
        const stored = await admit(node, { type: 'cmb', timestamp: Date.now(), content: ROOT, cmb: peerRoot });
        assert.ok(stored, `${warm ? 'warm' : 'cold'}: the root admits`);
        assert.strictEqual(stored.collapsed, true);
        assert.strictEqual(stored.tether, undefined);
        assert.strictEqual(stored.provenance?.tether, undefined);
      });
    }
  });
});
