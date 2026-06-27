'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * Regression guard for the PUBLIC "real-time mesh communication" claim:
 * an inbound CMB received from a peer MUST surface to the application layer.
 *
 * Background — the bug this guards against (introduced in 0.7.5, commit
 * 7f5c380 "dedup received CMBs to stop mesh replay storm"):
 *
 *   The receive-path dedup in lib/frame-handler.js recorded an inbound CMB's
 *   content-hash key as "seen" BEFORE the CMB had actually surfaced — the
 *   record sat above the SVAF evaluation. So any first pass that did NOT
 *   surface the CMB (an SVAF reject with neutral mood delivers nothing; B's
 *   memory then evolves) still poisoned the key. When the SAME CMB re-arrived
 *   on the next Bonjour reconnect (anchor replay re-sends recent memory on
 *   every reconnect) it was deduped and silently dropped — even though SVAF
 *   would now admit it. The node could broadcast but went receive-blind.
 *
 * The fix is record-AFTER-surface: a key is only remembered once the CMB has
 * genuinely surfaced (admitted/stored, non-neutral mood delivered, or
 * CLI-host forwarded). A not-yet-surfaced key never blocks a later legitimate
 * delivery; a CMB that surfaced once is still suppressed on identical re-send,
 * preserving the original anti-replay-storm intent.
 *
 * These tests stub the receiver's SVAF evaluator for determinism and speed so
 * they run in the main `npm test` suite (no neural-model spawn, no real
 * transport). A full two-node wire path lives in
 * tests/integration/e2e-cmb-path.js.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const { createCMB } = require('@sym-bot/core');

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

const ALIGNED = { decision: 'aligned', total_drift: 0.1, field_drifts: { focus: 0.1 }, gate_values: { g: 1 } };
const REJECTED = { decision: 'rejected', total_drift: 9, field_drifts: {}, gate_values: { g: 0 } };

function cmbFrame(focusText, mood = { text: 'neutral', valence: 0, arousal: 0 }) {
  const cmb = createCMB({
    fields: {
      focus: focusText,
      issue: 'inbound surfacing regression',
      intent: 'verify receive path',
      motivation: 'public real-time claim',
      commitment: 'guard against silent drop',
      perspective: 'peerA',
      mood,
    },
    createdBy: 'peerA',
  });
  return { type: 'cmb', timestamp: Date.now(), cmb };
}

// Each call returns a fresh deserialized copy, the way a real wire arrival
// would — no shared object identity / key mutation across deliveries.
function wireCopy(frame) {
  return JSON.parse(JSON.stringify(frame));
}

// A directed (peer-bound) frame: marked with `directed` + `to` = the receiving
// node's id, the way node.remember({to}) marks a targeted send on the wire
// (MMP §4.4.4 / §9.2.2). `to` must equal the receiver's nodeId for the
// directed-delivery branch to fire.
function directedFrame(receiverNode, focusText, mood) {
  const frame = cmbFrame(focusText, mood);
  frame.to = receiverNode.nodeId;
  frame.directed = true;
  return frame;
}

async function settle(ms = 150) {
  await new Promise((r) => setTimeout(r, ms));
}

describe('inbound CMB surfacing — public real-time mesh claim', () => {
  it('a first-seen inbound CMB surfaces (admitted) — baseline receive works', async () => {
    await withNode('surface-basic', async (node) => {
      node._svafEvaluator.evaluate = async () => ALIGNED;
      let surfaced = 0;
      node.on('cmb-accepted', () => { surfaced++; });
      node._frameHandler.handle('peerA', 'peerA', wireCopy(cmbFrame('first inbound CMB')));
      await settle();
      assert.strictEqual(surfaced, 1, 'inbound CMB must surface to the application layer');
    });
  });

  it('a key recorded by a non-surfacing reject does NOT block a later admit (the 0.7.5 regression)', async () => {
    await withNode('surface-no-poison', async (node) => {
      // First evaluation rejects (neutral mood → nothing surfaces); subsequent
      // evaluations admit — modelling B's memory evolving between reconnect
      // anchor replays so the same CMB becomes admissible.
      let first = true;
      node._svafEvaluator.evaluate = async () => {
        if (first) { first = false; return REJECTED; }
        return ALIGNED;
      };
      const surfaces = [];
      node.on('cmb-accepted', () => surfaces.push('cmb-accepted'));
      node.on('memory-received', () => surfaces.push('memory-received'));
      node.on('mood-delivered', () => surfaces.push('mood-delivered'));

      const frame = cmbFrame('shared question to the mesh'); // neutral mood

      // Arrival #1: SVAF rejects, neutral mood → surfaces nothing.
      node._frameHandler.handle('peerA', 'peerA', wireCopy(frame));
      await settle();
      assert.strictEqual(surfaces.length, 0, 'neutral reject surfaces nothing (precondition)');

      // Arrival #2: identical CMB re-sent (reconnect anchor replay). SVAF now
      // admits. Pre-fix this was deduped and silently dropped — receive-blind.
      node._frameHandler.handle('peerA', 'peerA', wireCopy(frame));
      await settle();
      assert.ok(
        surfaces.length > 0,
        'the re-sent CMB MUST surface — a not-yet-surfaced key must never silently swallow a later legitimate delivery',
      );
    });
  });

  it('an admitted CMB re-sent identically surfaces only once — anti-replay-storm preserved', async () => {
    await withNode('surface-storm-bounded', async (node) => {
      node._svafEvaluator.evaluate = async () => ALIGNED;
      let surfaced = 0;
      node.on('cmb-accepted', () => { surfaced++; });
      const frame = cmbFrame('admitted observation that keeps getting replayed');
      // Five identical wire-fresh re-sends (five Bonjour reconnect replays).
      for (let i = 0; i < 5; i++) {
        node._frameHandler.handle('peerA', 'peerA', wireCopy(frame));
        await settle(60);
      }
      assert.strictEqual(surfaced, 1, 'an identical CMB must surface exactly once; the replay storm stays bounded');
    });
  });

  it('inbound surfacing is bidirectional — both meshed nodes receive', async () => {
    await withNode('surface-bidi-a', async (nodeA) => {
      await withNode('surface-bidi-b', async (nodeB) => {
        nodeA._svafEvaluator.evaluate = async () => ALIGNED;
        nodeB._svafEvaluator.evaluate = async () => ALIGNED;
        let aSurfaced = 0;
        let bSurfaced = 0;
        nodeA.on('cmb-accepted', () => { aSurfaced++; });
        nodeB.on('cmb-accepted', () => { bSurfaced++; });

        // A→B and B→A, each a distinct CMB so neither is deduped.
        nodeB._frameHandler.handle('peerA', 'peerA', wireCopy(cmbFrame('from A to B')));
        nodeA._frameHandler.handle('peerB', 'peerB', wireCopy(cmbFrame('from B to A')));
        await settle();

        assert.strictEqual(bSurfaced, 1, 'B must surface the CMB sent from A');
        assert.strictEqual(aSurfaced, 1, 'A must surface the CMB sent from B');
      });
    });
  });
});

/**
 * Directed (peer-bound) delivery — MMP §9.2.2.
 *
 * A CMB addressed to this node (sym_send to=X → wire frame carries
 * directed:true + to:<nodeId>) is a request between two agents and MUST be
 * surfaced to the application layer regardless of the SVAF verdict — SVAF
 * governs MEMORY admission only, not delivery. A group-bound broadcast (no
 * `to`) stays fully SVAF-gated for surfacing.
 *
 * The surfaced entry carries an ingestion indicator so the agent can tell the
 * two outcomes apart: `remixed:true` when SVAF admitted it into memory as a
 * remix, `remixed:false` when it was delivered but not stored (the
 * directed-but-SVAF-rejected case), alongside the SVAF `decision`.
 */
describe('directed (peer-bound) delivery + ingestion flag — MMP §9.2.2', () => {
  it('a directed CMB that SVAF REJECTS still surfaces, flagged remixed:false (delivered-only)', async () => {
    await withNode('directed-reject', async (node) => {
      node._svafEvaluator.evaluate = async () => REJECTED;
      const surfaced = [];
      node.on('cmb-accepted', (e) => surfaced.push(e));
      node._frameHandler.handle('peerA', 'peerA', wireCopy(directedFrame(node, 'urgent: please review the auth token flow')));
      await settle();
      assert.strictEqual(surfaced.length, 1, 'a directed CMB MUST surface even when SVAF rejects it for memory');
      assert.strictEqual(surfaced[0].directed, true, 'surfaced entry is flagged directed');
      assert.strictEqual(surfaced[0].remixed, false, 'an SVAF-rejected directed CMB is delivered-only — not ingested');
      assert.strictEqual(surfaced[0].decision, 'rejected', 'the SVAF verdict travels with the delivered entry');
    });
  });

  it('a directed CMB that SVAF ADMITS surfaces flagged remixed:true (ingested)', async () => {
    await withNode('directed-admit', async (node) => {
      node._svafEvaluator.evaluate = async () => ALIGNED;
      const surfaced = [];
      node.on('cmb-accepted', (e) => surfaced.push(e));
      node._frameHandler.handle('peerA', 'peerA', wireCopy(directedFrame(node, 'directed observation that aligns with memory')));
      await settle();
      assert.strictEqual(surfaced.length, 1, 'a directed CMB that admits surfaces exactly once (admit path)');
      assert.strictEqual(surfaced[0].remixed, true, 'an admitted CMB is ingested — remixed into local memory');
    });
  });

  it('a group-bound broadcast that SVAF REJECTS does NOT surface (broadcast delivery stays SVAF-gated)', async () => {
    await withNode('broadcast-reject', async (node) => {
      node._svafEvaluator.evaluate = async () => REJECTED;
      const surfaced = [];
      node.on('cmb-accepted', (e) => surfaced.push(e));
      // No `to`/`directed` → group-bound. Neutral mood so the mood fast-path
      // surfaces nothing either.
      node._frameHandler.handle('peerA', 'peerA', wireCopy(cmbFrame('ambient broadcast unrelated to my domain')));
      await settle();
      assert.strictEqual(surfaced.length, 0, 'a rejected broadcast MUST NOT surface — receiver-autonomous attention');
    });
  });

  it('a directed CMB addressed to a DIFFERENT node is treated as a normal broadcast (not force-surfaced)', async () => {
    await withNode('directed-not-me', async (node) => {
      node._svafEvaluator.evaluate = async () => REJECTED;
      const surfaced = [];
      node.on('cmb-accepted', (e) => surfaced.push(e));
      const frame = cmbFrame('directed at someone else');
      frame.directed = true;
      frame.to = 'some-other-node-id'; // not this node's nodeId
      node._frameHandler.handle('peerA', 'peerA', wireCopy(frame));
      await settle();
      assert.strictEqual(surfaced.length, 0, 'a CMB directed at another node must not be force-surfaced here');
    });
  });
});
