'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * The `message` and `mood-delivered` events carry the same frozen `verification` and `session` facts
 * an inbox entry carries, by the same field names (mesh-channel 0.11.0, which until now resolved a
 * message's or a mood's signer key through node.keyBindings(), a separate and later view). A host
 * decides from the event alone.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const { connectNodes, until } = require('./_core-secure');

const uniq = (b) => `${b}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
const mk = (b) => new SymNode({ name: uniq(b), silent: true, discovery: new NullDiscovery(), room: 'ev' });
const cats = (focus, mood = 'calm') => ({ focus, issue: 'i', intent: 'inform', motivation: 'm', commitment: 'c', perspective: 'p', mood: { text: mood } });
async function stopAll(...nodes) {
  for (const n of nodes) { try { await n.stop(); } catch { /* */ } try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ } }
}

describe('message and mood-delivered carry the inbox entry\'s verification and session facts', () => {
  it('a message, a mood from a refused record and a mood frame: each decided from the event alone', async () => {
    const A = mk('ev-a'); const B = mk('ev-b');
    try {
      await A.start(); await B.start();
      await connectNodes(A, B);
      const aKey = A._identity.publicKey;
      // The reference: what an inbox entry carries for a directed record from A.
      B._svafEvaluator.evaluate = async () => ({ decision: 'aligned', total_drift: 0.1, category_drifts: { focus: 0.1 }, gate_values: { g: 1 } });
      const ref = A.remember(cats('a directed record, for the reference'), { to: B.nodeId });
      await until(() => B.inboxStatus().seq >= 1, 3000);
      const item = B.inboxGet('in0001');
      assert.ok(item && item.verification && item.session, 'the inbox entry has its facts');
      void ref;

      // 1. A message.
      const msgs = [];
      B.on('message', (from, text, meta) => msgs.push(meta));
      A.send('hello B', { to: B.nodeId });
      await until(() => msgs.length > 0, 3000);
      const m = msgs[0];
      assert.deepStrictEqual(Object.keys(m.verification).sort(), Object.keys(item.verification).sort(), 'the inbox entry\'s verification fields');
      assert.deepStrictEqual(Object.keys(m.session).sort(), Object.keys(item.session).sort(), 'and its session fields');
      assert.strictEqual(m.verification.authorNodeId, A.nodeId);
      assert.strictEqual(m.verification.authorKey, aKey, 'the key that verified the record, from the event');
      assert.strictEqual(m.verification.assertionId, m.assertionId);
      assert.strictEqual(m.verification.audience, 'directed');
      assert.strictEqual(m.verification.relayed, false);
      assert.strictEqual(m.session.nodeId, A.nodeId);
      assert.strictEqual(m.session.identityKey, aKey);
      assert.strictEqual(m.session.transport, 'lan');
      assert.strictEqual(m.verified, true);
      assert.strictEqual(m.profile, 'core-secure');
      assert.ok(Object.isFrozen(m) && Object.isFrozen(m.verification) && Object.isFrozen(m.session), 'frozen');

      // 2. A mood carried by a record that SVAF refused.
      const moods = [];
      B.on('mood-delivered', (d) => moods.push(d));
      B._svafEvaluator.evaluate = async () => ({ decision: 'rejected', total_drift: 0.9, category_drifts: {}, gate_values: {} });
      A.remember(cats('a record SVAF refuses, carrying affect', 'exhausted'));
      await until(() => moods.length > 0, 3000);
      const d = moods[0];
      assert.strictEqual(d.verified, true);
      assert.deepStrictEqual(Object.keys(d.verification).sort(), Object.keys(item.verification).sort());
      assert.strictEqual(d.verification.authorNodeId, A.nodeId);
      assert.strictEqual(d.verification.authorKey, aKey);
      assert.strictEqual(d.verification.assertionId, d.assertionId);
      assert.strictEqual(d.session.nodeId, A.nodeId);
      assert.strictEqual(d.session.identityKey, aKey);
      assert.ok(Object.isFrozen(d.verification) && Object.isFrozen(d.session));

      // 3. A mood frame: no record (verification null), its session's facts.
      B._moodThreshold = 2; // take any mood
      A.broadcastMood('focused');
      await until(() => moods.length > 1, 3000);
      const f = moods[1];
      assert.strictEqual(f.mood, 'focused');
      assert.strictEqual(f.verified, false);
      assert.strictEqual(f.verification, null, 'nothing signed it: no verification facts');
      assert.deepStrictEqual(Object.keys(f.session).sort(), Object.keys(item.session).sort());
      assert.strictEqual(f.session.nodeId, A.nodeId);
      assert.strictEqual(f.session.identityKey, aKey, 'the session that carried it proved this key');
      assert.strictEqual(f.profile, 'core-secure');
    } finally { await stopAll(A, B); }
  });
});
