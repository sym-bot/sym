'use strict';

/**
 * End-to-end CMB path integration test — MMP §4.2 wire frame, §4.4.4
 * targeted routing envelope, §9.2 receiver-autonomous SVAF evaluation,
 * §14 lineage propagation.
 *
 * Two in-process SymNodes with bidirectionally-wired mock transports.
 * nodeA emits a targeted CMB to nodeB; we verify the full chain:
 *   1. nodeA's local store has the CMB.
 *   2. The wire frame reaches nodeB's frame-handler (a `message` event
 *      or `mood-delivered` event fires on nodeB — either proves SVAF
 *      ran on the inbound frame).
 *   3. If SVAF admits the CMB, nodeB's meshmem contains a remix entry
 *      with `svaf.{decision, totalDrift, fieldDrifts}` populated and
 *      `lineage.parents` pointing back to nodeA's CMB key.
 *
 * The test accepts either "admitted" or "rejected/mood-delivered" as a
 * valid outcome of SVAF evaluation — the goal is to prove the pipeline
 * runs end-to-end, not to hand-tune inputs that guarantee admission.
 * For a captured admitted CMB (paper §4.1 artifact), see the separate
 * live two-machine test.
 *
 * NOT run by `npm test` — the SVAF async chain (neural model spawn or
 * heuristic fallback) plus five in-process SymNodes makes this heavy
 * and timing-sensitive under the main suite's parallel test-file
 * concurrency. Run explicitly with:
 *
 *     npm run test:integration
 *
 * which switches to --test-concurrency=1 and gives SVAF enough
 * wall-clock to complete. Unit-level regression for `remember({to})`
 * and `peers().peerId` lives in `tests/remember-targeted.test.js` and
 * runs in the main suite.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../../lib/node');
const { NullDiscovery } = require('../../lib/discovery');
const { nodeDir } = require('../../lib/config');

function bidirectionalPair() {
  const listenersA = {};
  const listenersB = {};
  const tA = {
    on: (ev, fn) => { listenersA[ev] = fn; },
    send: (frame) => {
      setImmediate(() => { if (listenersB.message) listenersB.message(frame); });
    },
    close: () => {
      if (listenersA.close) listenersA.close();
      setImmediate(() => { if (listenersB.close) listenersB.close(); });
    },
  };
  const tB = {
    on: (ev, fn) => { listenersB[ev] = fn; },
    send: (frame) => {
      setImmediate(() => { if (listenersA.message) listenersA.message(frame); });
    },
    close: () => {
      if (listenersB.close) listenersB.close();
      setImmediate(() => { if (listenersA.close) listenersA.close(); });
    },
  };
  return [tA, tB];
}

async function waitFor(predicate, { timeoutMs = 8000, intervalMs = 50 } = {}) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (predicate()) return true;
    await new Promise(r => setTimeout(r, intervalMs));
  }
  return false;
}

describe('E2E CMB path — MMP §4.2 / §4.4.4 / §9.2', () => {
  it('targeted CMB from A reaches B\'s frame-handler and SVAF runs', async () => {
    const aName = `e2e-a-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const bName = `e2e-b-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const nodeA = new SymNode({ name: aName, silent: true, discovery: new NullDiscovery() });
    const nodeB = new SymNode({ name: bName, silent: true, discovery: new NullDiscovery() });
    await nodeA.start();
    await nodeB.start();

    const [tA, tB] = bidirectionalPair();
    // Wire inbound frames into each side's frame-handler.
    tA.on('message', (frame) => nodeA._frameHandler.handle(nodeB.nodeId, bName, frame));
    tB.on('message', (frame) => nodeB._frameHandler.handle(nodeA.nodeId, aName, frame));

    // Register each as a peer on the other.
    nodeA._addPeer(nodeA._createPeer(tA, nodeB.nodeId, bName, true, 'bonjour'));
    nodeB._addPeer(nodeB._createPeer(tB, nodeA.nodeId, aName, false, 'bonjour'));

    // Handshake frames flow during _addPeer — give the async round-trip
    // a moment to settle before emitting the CMB.
    await new Promise(r => setTimeout(r, 300));

    // Record outcomes on the receiver side. Any of these events proves
    // the inbound frame reached the frame-handler and SVAF ran.
    const outcomes = { memoryReceived: null, moodDelivered: null };
    nodeB.on('memory-received', (evt) => { outcomes.memoryReceived = evt; });
    nodeB.on('mood-delivered', (evt) => { outcomes.moodDelivered = evt; });

    const fields = {
      focus: 'E2E CMB-path validation between in-process SymNode peers',
      issue: 'verify targeted send → wire → frame-handler → SVAF chain',
      intent: 'exercise MMP §4.4.4 targeted routing end-to-end',
      motivation: 'pre-publish validation before real two-machine test',
      commitment: 'regression CI guard for the full CMB receive pipeline',
      perspective: 'nodeA sender',
      mood: { text: 'procedural', valence: 0, arousal: 0 },
    };
    const entry = nodeA.remember(fields, { to: nodeB.nodeId });
    assert.ok(entry, 'nodeA.remember(fields, {to}) returns a local entry');
    assert.ok(entry.key, 'local entry has a CMB key');

    // Wait until SVAF has run on B — either remix-store (accept) or
    // mood-delivery (reject with non-neutral mood is the only way to see
    // a mood-delivered event; neutral rejects emit nothing, so we fall
    // back to checking for a frame arrival via peer.lastSeen drift).
    const lastSeenBefore = nodeB._peers.get(nodeA.nodeId)?.lastSeen;
    const proofOfProcessing = await waitFor(() => {
      if (outcomes.memoryReceived) return true;
      if (outcomes.moodDelivered) return true;
      const lastSeenNow = nodeB._peers.get(nodeA.nodeId)?.lastSeen;
      return lastSeenNow && lastSeenBefore && lastSeenNow > lastSeenBefore;
    });
    assert.ok(
      proofOfProcessing,
      'nodeB frame-handler must process the inbound CMB ' +
      '(memory-received, mood-delivered, or lastSeen advance)',
    );

    // When SVAF admits the CMB, the stored remix must carry the MMP-spec
    // contract: svaf block + lineage.parents pointing to A's CMB.
    if (outcomes.memoryReceived && outcomes.memoryReceived.decision !== 'rejected') {
      const storedEntry = outcomes.memoryReceived.entry;
      assert.ok(storedEntry, 'memory-received event should carry the fused entry');
      assert.ok(storedEntry.svaf, 'admitted remix MUST have svaf block (§9.2)');
      assert.ok(typeof storedEntry.svaf.decision === 'string', 'svaf.decision is a string');
      assert.ok(typeof storedEntry.svaf.totalDrift === 'number', 'svaf.totalDrift is numeric');
      assert.ok(storedEntry.svaf.fieldDrifts && typeof storedEntry.svaf.fieldDrifts === 'object', 'svaf.fieldDrifts is an object');
      const parents = storedEntry.cmb?.lineage?.parents || [];
      assert.ok(parents.length >= 1, 'lineage.parents must include at least one parent key (§14)');
      assert.strictEqual(parents[0], entry.key, 'parent key points back to nodeA\'s original CMB');
    }

    await nodeA.stop();
    await nodeB.stop();
    fs.rmSync(nodeDir(aName), { recursive: true, force: true });
    fs.rmSync(nodeDir(bName), { recursive: true, force: true });
  });

  it('broadcast CMB reaches all connected peers', async () => {
    const aName = `e2e-broadcast-a-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const bName = `e2e-broadcast-b-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const cName = `e2e-broadcast-c-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const nodeA = new SymNode({ name: aName, silent: true, discovery: new NullDiscovery() });
    const nodeB = new SymNode({ name: bName, silent: true, discovery: new NullDiscovery() });
    const nodeC = new SymNode({ name: cName, silent: true, discovery: new NullDiscovery() });
    await nodeA.start();
    await nodeB.start();
    await nodeC.start();

    const [tA_B, tB_A] = bidirectionalPair();
    const [tA_C, tC_A] = bidirectionalPair();
    tA_B.on('message', (f) => nodeA._frameHandler.handle(nodeB.nodeId, bName, f));
    tB_A.on('message', (f) => nodeB._frameHandler.handle(nodeA.nodeId, aName, f));
    tA_C.on('message', (f) => nodeA._frameHandler.handle(nodeC.nodeId, cName, f));
    tC_A.on('message', (f) => nodeC._frameHandler.handle(nodeA.nodeId, aName, f));

    nodeA._addPeer(nodeA._createPeer(tA_B, nodeB.nodeId, bName, true, 'bonjour'));
    nodeA._addPeer(nodeA._createPeer(tA_C, nodeC.nodeId, cName, true, 'bonjour'));
    nodeB._addPeer(nodeB._createPeer(tB_A, nodeA.nodeId, aName, false, 'bonjour'));
    nodeC._addPeer(nodeC._createPeer(tC_A, nodeA.nodeId, aName, false, 'bonjour'));

    await new Promise(r => setTimeout(r, 300));

    const outcomesB = { memoryReceived: null, moodDelivered: null };
    const outcomesC = { memoryReceived: null, moodDelivered: null };
    nodeB.on('memory-received', (evt) => { outcomesB.memoryReceived = evt; });
    nodeB.on('mood-delivered', (evt) => { outcomesB.moodDelivered = evt; });
    nodeC.on('memory-received', (evt) => { outcomesC.memoryReceived = evt; });
    nodeC.on('mood-delivered', (evt) => { outcomesC.moodDelivered = evt; });

    const entry = nodeA.remember({
      focus: 'E2E broadcast validation',
      issue: 'verify default fan-out still reaches every peer',
      intent: 'broadcast regression guard at wire + handler level',
      motivation: 'ensure opts.to omission preserves broadcast semantics',
      commitment: 'both peers must see the inbound CMB',
      perspective: 'nodeA sender',
      mood: { text: 'procedural', valence: 0, arousal: 0 },
    });
    assert.ok(entry, 'broadcast remember returns an entry');

    const bGotIt = await waitFor(() => outcomesB.memoryReceived || outcomesB.moodDelivered);
    const cGotIt = await waitFor(() => outcomesC.memoryReceived || outcomesC.moodDelivered);
    assert.ok(bGotIt, 'nodeB frame-handler must process inbound broadcast CMB');
    assert.ok(cGotIt, 'nodeC frame-handler must process inbound broadcast CMB');

    await nodeA.stop();
    await nodeB.stop();
    await nodeC.stop();
    fs.rmSync(nodeDir(aName), { recursive: true, force: true });
    fs.rmSync(nodeDir(bName), { recursive: true, force: true });
    fs.rmSync(nodeDir(cName), { recursive: true, force: true });
  });
});
