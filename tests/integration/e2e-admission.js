'use strict';

require('../_isolate-home'); // sandbox HOME/USERPROFILE: node state must never land in the real ~/.sym

/**
 * End-to-end Admission Attestation — the gate attaches a signed attestation to the
 * remix it stores (MMP admission-attestation layer, Phase C).
 *
 * Two wired in-process nodes; A sends a directed CMB to B; B gates it (heuristic
 * forced) and ADMITS it; the stored remix's entry.admission must be a valid signed
 * attestation bound to A's CMB, attributed to B, signed by B's identity key.
 *
 * Run with: npm run test:integration (heuristic path loads the encoder).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../../lib/node');
const { NullDiscovery } = require('../../lib/discovery');
const { nodeDir } = require('../../lib/config');
const { verifyAttestation } = require('../../lib/core');

function bidirectionalPair() {
  const la = {}, lb = {};
  const tA = { on: (e, f) => { la[e] = f; }, send: (fr) => setImmediate(() => lb.message && lb.message(fr)), close: () => { la.close && la.close(); setImmediate(() => lb.close && lb.close()); } };
  const tB = { on: (e, f) => { lb[e] = f; }, send: (fr) => setImmediate(() => la.message && la.message(fr)), close: () => { lb.close && lb.close(); setImmediate(() => la.close && la.close()); } };
  return [tA, tB];
}
const sleep = ms => new Promise(r => setTimeout(r, ms));

describe('E2E Admission Attestation — gate attaches a signed verdict to the remix', () => {
  it('an admitted directed CMB yields a valid attestation on B\'s stored remix', async () => {
    const aName = `e2e-adm-a-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const bName = `e2e-adm-b-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const A = new SymNode({ name: aName, silent: true, discovery: new NullDiscovery(), room: 'sym-bot-team' }); // same room as B (MMP §5.8: rooms do not exchange)
    const B = new SymNode({ name: bName, silent: true, discovery: new NullDiscovery(), room: 'sym-bot-team' });
    await A.start(); await B.start();
    try {
      A._svafEvaluator.evaluate = async () => null;  // force the deterministic heuristic gate
      B._svafEvaluator.evaluate = async () => null;

      const [tA, tB] = bidirectionalPair();
      tA.on('message', f => A._frameHandler.handle(B.nodeId, bName, f));
      tB.on('message', f => B._frameHandler.handle(A.nodeId, aName, f));
      A._addPeer(A._createPeer(tA, B.nodeId, bName, true, 'bonjour'));
      B._addPeer(B._createPeer(tB, A.nodeId, aName, false, 'bonjour'));
      await sleep(400);

      let received = null;
      B.on('memory-received', (evt) => { received = evt; });

      const entry = A.remember({
        focus: 'e2e admission attestation', issue: 'gate must attach a signed verdict',
        intent: 'phase C', motivation: 'durable audit record', commitment: 'on the remix',
        perspective: 'A', mood: { text: 'procedural', valence: 0, arousal: 0 },
      }, { to: B.nodeId });

      const admitted = await (async () => { for (let i = 0; i < 100 && !received; i++) await sleep(50); return !!received; })();
      assert.ok(admitted, 'B must process and admit the directed CMB');

      // On the store entry, beside the record (§8.8.1: the record is exactly its two sections).
      const att = received.entry?.admission;
      assert.ok(att, 'stored remix\'s entry carries an admission attestation');
      assert.strictEqual(att.of, entry.key, 'attestation is bound to A\'s gated CMB');
      assert.strictEqual(att.by, B.nodeId, 'attested by the gating node B');
      assert.strictEqual(att.roster, 'sym-bot-team', 'scoped to B\'s roster');
      assert.strictEqual(att.method, 'heuristic');
      assert.ok(['aligned', 'guarded'].includes(att.verdict), 'overall verdict from the gate');
      assert.strictEqual(Object.keys(att.categories).length, 7, 'a verdict for each CAT7 category');
      assert.strictEqual(att.seq, 1, 'first link in B\'s attester chain');
      assert.strictEqual(att.prev, 'genesis');
      assert.deepStrictEqual(verifyAttestation(att, B._identity.publicKey), { signed: true, valid: true }, 'signature verifies against B\'s identity key');

    } finally {
      await Promise.allSettled([A.stop(), B.stop()]);
      fs.rmSync(nodeDir(aName), { recursive: true, force: true });
      fs.rmSync(nodeDir(bName), { recursive: true, force: true });
    }
  });
});
