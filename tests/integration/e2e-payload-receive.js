'use strict';

/**
 * End-to-end PAYLOAD receive integration test — the cross-device drop hunt.
 *
 * remember-payload.test.js proves the SEND side: a payload-bearing CMB rides
 * the wire frame to peers. What was never covered is the RECEIVE side:
 *
 *   wire frame → frame-handler → SVAF → cmb-accepted → _pushInbox → inbox()
 *
 * The fleet symptom (sym-coo, Mac→Windows bonjour): CAT7 fields arrive intact
 * but `m.payload` is empty on the receiver's inbox drain. The asymmetry
 * (research-bot→Mac carried payload; Mac→coo dropped it) is NOT OS-specific —
 * SVAF admit vs reject depends on the receiver's own memory drift, and the two
 * verdicts surface the CMB through different objects:
 *
 *   - directed REJECT  → _surfaceDirectedReject({...msg})        — raw wire CMB
 *   - SVAF ADMIT       → receiveFromPeer → store entry → emit     — store copy
 *
 * This test wires two in-process nodes and asserts the payload survives to
 * nodeB.inbox() regardless of which verdict SVAF reaches, so a per-node drift
 * difference can never silently drop the payload on one peer but not another.
 *
 * Run with: npm run test:integration  (heavy SVAF async chain; not in `npm test`)
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
    send: (frame) => { setImmediate(() => { if (listenersB.message) listenersB.message(frame); }); },
    close: () => { if (listenersA.close) listenersA.close(); setImmediate(() => { if (listenersB.close) listenersB.close(); }); },
  };
  const tB = {
    on: (ev, fn) => { listenersB[ev] = fn; },
    send: (frame) => { setImmediate(() => { if (listenersA.message) listenersA.message(frame); }); },
    close: () => { if (listenersB.close) listenersB.close(); setImmediate(() => { if (listenersA.close) listenersA.close(); }); },
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

describe('E2E payload receive — payload survives to receiver inbox (§4.4.4 + opaque payload)', () => {
  it('a directed payload-bearing CMB surfaces on nodeB.inbox() WITH its payload', async () => {
    const aName = `e2e-pay-a-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const bName = `e2e-pay-b-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const nodeA = new SymNode({ name: aName, silent: true, discovery: new NullDiscovery() });
    const nodeB = new SymNode({ name: bName, silent: true, discovery: new NullDiscovery() });
    await nodeA.start();
    await nodeB.start();

    // Force the deterministic heuristic SVAF path on the receiver: the neural
    // evaluator spawns a model subprocess that is slow/unavailable in CI and is
    // irrelevant to payload preservation (payload rides alongside CAT7, not
    // through the evaluator). Returning null makes frame-handler fall back to
    // processHeuristicSVAF — pure JS, fast, and it exercises the same
    // cmb-accepted → _pushInbox surfacing on both admit and reject branches.
    nodeB._svafEvaluator.evaluate = async () => null;

    const [tA, tB] = bidirectionalPair();
    tA.on('message', (frame) => nodeA._frameHandler.handle(nodeB.nodeId, bName, frame));
    tB.on('message', (frame) => nodeB._frameHandler.handle(nodeA.nodeId, aName, frame));
    nodeA._addPeer(nodeA._createPeer(tA, nodeB.nodeId, bName, true, 'bonjour'));
    nodeB._addPeer(nodeB._createPeer(tB, nodeA.nodeId, aName, false, 'bonjour'));

    // Let the handshake round-trip settle so B knows A's identity key (so the
    // signed CMB verifies) and the E2E shared secret is derived (exercises the
    // encrypt→decrypt path the real bonjour transport uses).
    await new Promise(r => setTimeout(r, 400));

    const payload = {
      type: 'llm-request',
      request_id: 'rcv-test-1',
      system_prompt: 'You are a test responder.',
      user_message: 'echo back the payload across the wire',
      nested: { sequence: 42, verify_token: 'PAYLOAD-OK' },
    };

    const entry = nodeA.remember({
      focus: 'llm-request:rcv-test-1 — payload receive validation',
      issue: 'verify opaque payload survives the full receive→inbox path',
      intent: 'exercise §4.4.4 directed delivery with opaque payload',
      motivation: 'reproduce/close the Mac→Windows cross-device payload drop',
      commitment: 'inbox message must carry the payload on either SVAF verdict',
      perspective: 'nodeA sender',
      mood: { text: 'procedural', valence: 0, arousal: 0 },
    }, { to: nodeB.nodeId, payload });

    assert.ok(entry, 'nodeA.remember({to, payload}) returns a local entry');
    assert.deepStrictEqual(entry.cmb.payload, payload, 'sender local CMB carries the payload');

    // Directed CMBs surface unconditionally (§4.4.4) — admit OR reject — so the
    // inbox must populate regardless of B's SVAF drift verdict.
    const surfaced = await waitFor(() => nodeB.inbox({ peek: true }).messages.length > 0);
    assert.ok(surfaced, 'directed CMB must surface on nodeB.inbox() regardless of SVAF verdict');

    const msgs = nodeB.inbox().messages;
    const mine = msgs.find(m => m.key === entry.key || m.fields?.focus?.text?.includes('rcv-test-1') || String(m.content).includes('rcv-test-1'));
    assert.ok(mine, 'the directed CMB is present on nodeB inbox');

    // THE ASSERTION THAT WAS NEVER MADE: payload survived to the inbox message.
    assert.ok(mine.payload, `inbox message MUST carry payload (got ${JSON.stringify(mine.payload)})`);
    assert.deepStrictEqual(mine.payload, payload, 'inbox payload matches what nodeA sent — no drop');

    await nodeA.stop();
    await nodeB.stop();
    fs.rmSync(nodeDir(aName), { recursive: true, force: true });
    fs.rmSync(nodeDir(bName), { recursive: true, force: true });
  });
});
