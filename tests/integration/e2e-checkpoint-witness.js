'use strict';

/**
 * End-to-end checkpoint + witness cycle (Phase D3).
 *
 * A commits a Merkle checkpoint over its attestation chain at the interval and
 * gossips it; B verifies it, COUNTERSIGNS it (witness), and gossips the witness
 * back; A records it. A's reconciliation then reads consistent + witnessed — so a
 * later suppression of any attestation <= the committed seq would diverge from the
 * witnessed root (omission-evidence).
 *
 * Run with: npm run test:integration
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../../lib/node');
const { NullDiscovery } = require('../../lib/discovery');
const { nodeDir } = require('../../lib/config');

function pair() {
  const la = {}, lb = {};
  const tA = { on: (e, f) => { la[e] = f; }, send: (fr) => setImmediate(() => lb.message && lb.message(fr)), close: () => { la.close && la.close(); setImmediate(() => lb.close && lb.close()); } };
  const tB = { on: (e, f) => { lb[e] = f; }, send: (fr) => setImmediate(() => la.message && la.message(fr)), close: () => { lb.close && lb.close(); setImmediate(() => la.close && la.close()); } };
  return [tA, tB];
}
const sleep = ms => new Promise(r => setTimeout(r, ms));

describe('E2E checkpoint + witness (D3)', () => {
  it('A checkpoints its chain, B witnesses it, and A reconciles consistent + witnessed', async () => {
    const aName = `e2e-cp-a-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const bName = `e2e-cp-b-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const A = new SymNode({ name: aName, silent: true, discovery: new NullDiscovery(), group: 'sym-bot-team', checkpointInterval: 2 });
    const B = new SymNode({ name: bName, silent: true, discovery: new NullDiscovery(), group: 'sym-bot-team', checkpointInterval: 2 });
    await A.start(); await B.start();
    A._svafEvaluator.evaluate = async () => null;
    B._svafEvaluator.evaluate = async () => null;

    const [tA, tB] = pair();
    tA.on('message', f => A._frameHandler.handle(B.nodeId, bName, f));
    tB.on('message', f => B._frameHandler.handle(A.nodeId, aName, f));
    A._addPeer(A._createPeer(tA, B.nodeId, bName, true, 'bonjour'));
    B._addPeer(B._createPeer(tB, A.nodeId, aName, false, 'bonjour'));
    await sleep(400);

    // B sends two distinct CMBs to A; A admits both, reaching seq 2 → A checkpoints.
    for (const n of [1, 2]) {
      B.remember({ focus: `checkpoint e2e ${n}`, issue: 'x', intent: 'D3', motivation: 'm', commitment: 'c', perspective: 'B', mood: { text: 'procedural', valence: 0, arousal: 0 } }, { to: A.nodeId });
      await sleep(150);
    }

    const ready = await (async () => { for (let i = 0; i < 80; i++) { await sleep(50); const r = A.reconcileChain(A.nodeId); if (r.checkpoint && r.witnesses >= 1) return true; } return false; })();
    assert.ok(ready, 'A committed a checkpoint and received B\'s witness');

    const cp = A._attestations.latestCheckpoint(A.nodeId);
    assert.strictEqual(cp.upto_seq, 2, 'checkpoint committed at the interval');
    assert.ok(B._attestations.latestCheckpoint(A.nodeId), 'B received A\'s checkpoint');

    const recon = A.reconcileChain(A.nodeId);
    assert.strictEqual(recon.consistent, true, 'held chain reproduces the committed root');
    assert.strictEqual(recon.complete, true);
    assert.ok(recon.witnesses >= 1, 'at least one roster witness countersigned the checkpoint');

    await A.stop(); await B.stop();
    fs.rmSync(nodeDir(aName), { recursive: true, force: true });
    fs.rmSync(nodeDir(bName), { recursive: true, force: true });
  });
});
