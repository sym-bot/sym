'use strict';

require('../_isolate-home'); // sandbox HOME/USERPROFILE: node state must never land in the real ~/.sym

/**
 * End-to-end Admission Attestation gossip (Phase D2).
 *
 * B sends a directed CMB to A; A gates + admits it, signs an attestation, and
 * gossips it on the dedicated `attestation` frame. B (the CMB's author) ingests it:
 * roster-scope check, verify A's ORIGINAL signature against A's authenticated
 * identity key, record into the index. So the cross-mesh audit trail forms — B
 * learns A's verdict about B's own CMB — and a forged attestation is dropped.
 *
 * Run with: npm run test:integration
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../../lib/node');
const { NullDiscovery } = require('../../lib/discovery');
const { nodeDir } = require('../../lib/config');
const { verifyAttestation } = require('../../lib/core');

function pair() {
  const la = {}, lb = {};
  const tA = { on: (e, f) => { la[e] = f; }, send: (fr) => setImmediate(() => lb.message && lb.message(fr)), close: () => { la.close && la.close(); setImmediate(() => lb.close && lb.close()); } };
  const tB = { on: (e, f) => { lb[e] = f; }, send: (fr) => setImmediate(() => la.message && la.message(fr)), close: () => { lb.close && lb.close(); setImmediate(() => la.close && la.close()); } };
  return [tA, tB];
}
const sleep = ms => new Promise(r => setTimeout(r, ms));

describe('E2E Admission Attestation gossip (D2)', () => {
  it('an attestation gossips to the roster, verifies, and records; a forgery is dropped', async () => {
    const aName = `e2e-gos-a-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const bName = `e2e-gos-b-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const A = new SymNode({ name: aName, silent: true, discovery: new NullDiscovery(), room: 'sym-bot-team' });
    const B = new SymNode({ name: bName, silent: true, discovery: new NullDiscovery(), room: 'sym-bot-team' });
    await A.start(); await B.start();
    A._svafEvaluator.evaluate = async () => null;
    B._svafEvaluator.evaluate = async () => null;

    const [tA, tB] = pair();
    A.connectTransport(tA, { role: 'client', expectNodeId: B.nodeId });
    B.connectTransport(tB, { role: 'server' });
    await sleep(400);
    const announced = [];
    B.on('attestation-received', (e) => announced.push(e));
    // The handshake binds A's key for the session (security review D): durable only once earned.
    assert.strictEqual(B._identityKey(A.nodeId), A._identity.publicKey, 'B has A\'s identity key, proven by the handshake');
    assert.strictEqual(B._keySource(A.nodeId), 'session');

    const entry = B.remember({
      focus: 'attestation gossip e2e', issue: 'verify attestation reaches the author',
      intent: 'D2', motivation: 'cross-mesh audit trail', commitment: 'roster gossip',
      perspective: 'B', mood: { text: 'procedural', valence: 0, arousal: 0 },
    }); // room-bound: no attestation about a directed record is sent (sym-attest-v1 §5.1, MMP 2.0 update 1)
    const K = entry.key;

    const arrived = await (async () => { for (let i = 0; i < 100; i++) { await sleep(50); if (B.attestationsFor(K).length) return true; } return false; })();
    assert.ok(arrived, 'A\'s attestation about K gossiped to B');

    const att = B.attestationsFor(K)[0];
    assert.strictEqual(att.by, A.nodeId, 'attested by the gating node A');
    assert.strictEqual(att.of, K, 'bound to B\'s gated CMB');
    assert.deepStrictEqual(verifyAttestation(att, A._identity.publicKey), { signed: true, valid: true }, 'A\'s original signature verifies end-to-end');
    assert.ok(A.attestationsFor(K).length >= 1, 'the gater A also holds it');
    // The author sees A's verdict live, over the real frame path, without polling.
    const live = announced.filter((e) => e.of === K);
    assert.strictEqual(live.length, 1, "B announced A's attestation once");
    assert.strictEqual(live[0].by, A.nodeId);
    assert.strictEqual(live[0].byName, aName);
    assert.strictEqual(live[0].from, aName);
    assert.strictEqual(live[0].relayed, false);
    assert.strictEqual(live[0].verified, true);
    assert.strictEqual(live[0].keySource, 'session');
    assert.strictEqual(live[0].sig, att.sig);

    // A forged attestation (bad signature) must be dropped on ingest.
    const before = B._attestations.size();
    B._receiveSessionFrame(B._peers.get(A.nodeId).transport, {
      type: 'attestation',
      attestation: { of: K, by: A.nodeId, at: Date.now(), roster: 'sym-bot-team', verdict: 'aligned', categories: {}, role: 'participant', seq: 99, prev: 'x', sig: 'AAAAforged', sigAlg: 'ed25519' },
    });
    await sleep(50);
    assert.strictEqual(B._attestations.size(), before, 'a forged attestation is rejected, not recorded');
    assert.strictEqual(announced.filter((e) => e.sig === 'AAAAforged').length, 0, 'a forged attestation is never announced');

    await A.stop(); await B.stop();
    fs.rmSync(nodeDir(aName), { recursive: true, force: true });
    fs.rmSync(nodeDir(bName), { recursive: true, force: true });
  });
});
