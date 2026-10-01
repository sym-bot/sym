'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * Directed delivery and authorship, from the 2026-10-01 MMP 2.0 audit of sym-mesh-channel.
 *
 * - B-D1  a directed reply citing one of the receiver's own CMBs was dropped as an "echo"
 * - B-D2  directed de-duplication used the content key for 7 days, so a new directed send of
 *         words already seen (even as a broadcast) never surfaced (§8.8.2)
 * - B-D3  a directed CMB SVAF admitted, but whose key the store already held, surfaced nowhere
 * - B-D4  a directed CMB SVAF rejected surfaced twice when it carried a non-neutral mood
 * - B-D5  a directed send identical to the sender's HEAD, or already stored, sent nothing
 * - B-L1  admission rewrote the author's record to name the receiver as author and dropped the
 *         signature, while keeping the author's address
 * - the "<receiver>+<sender>" label: entries now carry `author`, and the inbox reads it
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const core = require('../lib/core');
const { MemoryStore } = require('../lib/memory-store');
const { recordCreatedBy } = require('../lib/record');

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

const ALIGNED = { decision: 'aligned', total_drift: 0.1, category_drifts: { focus: 0.1 }, gate_values: { g: 1 } };
const REJECTED = { decision: 'rejected', total_drift: 9, category_drifts: {}, gate_values: { g: 0 } };
const NEUTRAL = { text: 'neutral', valence: 0, arousal: 0 };

function mkCmb(focus, { by = 'peerA', parents, mood = NEUTRAL } = {}) {
  const cmb = core.createCMB({
    categories: { focus, issue: 'audit regression', intent: 'verify', motivation: 'MMP 2.0 audit', commitment: 'guard', perspective: by, mood },
    createdBy: by,
  });
  if (parents) cmb.metadata.lineage = { parents, method: 'rule-a' };
  return cmb;
}
const frame = (cmb) => JSON.parse(JSON.stringify({ type: 'cmb', timestamp: Date.now(), cmb }));
const directed = (node, cmb) => Object.assign(frame(cmb), { to: node.nodeId, directed: true });
const settle = (ms = 150) => new Promise((r) => setTimeout(r, ms));
const tick = () => new Promise((r) => setTimeout(r, 5)); // distinct createdTimestamp

function collect(node) {
  const out = { accepted: [], moods: 0 };
  node.on('cmb-accepted', (e) => out.accepted.push(e));
  node.on('mood-delivered', () => { out.moods++; });
  return out;
}

describe('directed delivery (MMP §9.2.2, §8.8.2)', () => {
  it('B-D1: a directed reply whose parent is the receiver\'s own CMB surfaces', async () => {
    await withNode('d1', async (node) => {
      node._svafEvaluator.evaluate = async () => ALIGNED;
      const mine = node.remember({ focus: 'my question to peerA', issue: 'x', intent: 'ask', motivation: 'm', commitment: 'c', perspective: 'me', mood: NEUTRAL });
      assert.ok(mine?.key, 'precondition: a local CMB exists');
      const seen = collect(node);
      node._frameHandler.handle('peerA', 'peerA', directed(node, mkCmb('peerA answers your question', { parents: [mine.key] })));
      await settle();
      assert.strictEqual(seen.accepted.length, 1);
    });
  });

  it('B-D1: a broadcast citing the receiver\'s own CMB is still skipped as an echo', async () => {
    await withNode('d1-echo', async (node) => {
      node._svafEvaluator.evaluate = async () => ALIGNED;
      const mine = node.remember({ focus: 'my broadcast', issue: 'x', intent: 'tell', motivation: 'm', commitment: 'c', perspective: 'me', mood: NEUTRAL });
      const seen = collect(node);
      node._frameHandler.handle('peerA', 'peerA', frame(mkCmb('remix of your broadcast', { parents: [mine.key] })));
      await settle();
      assert.strictEqual(seen.accepted.length, 0);
    });
  });

  it('B-D2: a directed send of words already surfaced as a broadcast surfaces again', async () => {
    await withNode('d2', async (node) => {
      node._svafEvaluator.evaluate = async () => REJECTED; // memory refuses both; delivery must not
      const seen = collect(node);
      node._svafEvaluator.evaluate = async () => ALIGNED;
      node._frameHandler.handle('peerA', 'peerA', frame(mkCmb('status: done')));
      await settle();
      await tick();
      node._svafEvaluator.evaluate = async () => REJECTED;
      node._frameHandler.handle('peerA', 'peerA', directed(node, mkCmb('status: done')));
      await settle();
      assert.strictEqual(seen.accepted.length, 2, 'the broadcast and the later directed send both surface');
      assert.strictEqual(seen.accepted[1].directed, true);
    });
  });

  it('B-D2: a replay of the same directed record still surfaces only once', async () => {
    await withNode('d2-replay', async (node) => {
      node._svafEvaluator.evaluate = async () => REJECTED;
      const seen = collect(node);
      const f = directed(node, mkCmb('please review the fix list'));
      node._frameHandler.handle('peerA', 'peerA', JSON.parse(JSON.stringify(f)));
      await settle();
      node._frameHandler.handle('peerA', 'peerA', JSON.parse(JSON.stringify(f)));
      await settle();
      assert.strictEqual(seen.accepted.length, 1);
    });
  });

  it('B-D3: an admitted directed CMB whose key is already stored surfaces as delivered-not-stored', async () => {
    await withNode('d3', async (node) => {
      node._svafEvaluator.evaluate = async () => ALIGNED;
      const seen = collect(node);
      node._frameHandler.handle('peerA', 'peerA', frame(mkCmb('ack')));
      await settle();
      await tick();
      node._frameHandler.handle('peerA', 'peerA', directed(node, mkCmb('ack')));
      await settle();
      assert.strictEqual(seen.accepted.length, 2);
      assert.strictEqual(seen.accepted[1].directed, true);
      assert.strictEqual(seen.accepted[1].remixed, false);
      assert.strictEqual(seen.accepted[1].decision, 'redundant');
    });
  });

  it('B-D4: a rejected directed CMB with a non-neutral mood surfaces exactly once', async () => {
    await withNode('d4', async (node) => {
      node._svafEvaluator.evaluate = async () => REJECTED;
      const seen = collect(node);
      node._frameHandler.handle('peerA', 'peerA', directed(node, mkCmb('urgent: the build is red', { mood: { text: 'alarmed', valence: -0.7, arousal: 0.8 } })));
      await settle();
      assert.strictEqual(seen.accepted.length, 1);
      assert.strictEqual(seen.moods, 0, 'the mood fast-path does not deliver it a second time');
    });
  });

  it('a rejected broadcast with a non-neutral mood still delivers its mood (MMP §9.3)', async () => {
    await withNode('d4-mood', async (node) => {
      node._svafEvaluator.evaluate = async () => REJECTED;
      const seen = collect(node);
      node._frameHandler.handle('peerA', 'peerA', frame(mkCmb('the build is red', { mood: { text: 'alarmed', valence: -0.7, arousal: 0.8 } })));
      await settle();
      assert.strictEqual(seen.moods, 1);
    });
  });
});

describe('author and inbox id on surfaced entries', () => {
  it('carries the author and the delivering peer, and the inbox reads the author', async () => {
    await withNode('author', async (node) => {
      node._svafEvaluator.evaluate = async () => ALIGNED;
      const seen = collect(node);
      node._frameHandler.handle('peer-a-id', 'peerA', frame(mkCmb('authorship check', { by: 'claude-sym-agent-a' })));
      await settle();
      const e = seen.accepted[0];
      assert.deepStrictEqual(e.author, { name: 'claude-sym-agent-a', nodeId: null, via: { name: 'peerA', nodeId: 'peer-a-id' } });
      assert.ok(!String(e.author.name).includes('+'));
      const item = node.inboxGet(e.inboxId);
      assert.ok(item, 'the surfaced entry names its inbox id');
      assert.strictEqual(item.from, 'claude-sym-agent-a');
      assert.strictEqual(item.seq, e.inboxSeq);
    });
  });
});

describe('inboxAck (channel push/receive share one id)', () => {
  it('acks out of cursor order, stops counting the item, and still returns it on drain', async () => {
    await withNode('ack', async (node) => {
      node._svafEvaluator.evaluate = async () => ALIGNED;
      const seen = collect(node);
      node._frameHandler.handle('peerA', 'peerA', frame(mkCmb('first')));
      node._frameHandler.handle('peerA', 'peerA', frame(mkCmb('second')));
      await settle();
      const [, second] = seen.accepted;
      assert.strictEqual(node.inboxStatus().undrained, 2);
      assert.strictEqual(node.inboxAck(second.inboxId), true);
      assert.strictEqual(node.inboxAck(second.inboxId), false, 'acking twice is a no-op');
      assert.strictEqual(node.inboxAck('in9999'), false, 'unknown id');
      assert.strictEqual(node.inboxStatus().undrained, 1);
      const drained = node.inbox();
      assert.strictEqual(drained.drained, 2, 'acked items are returned, not skipped');
      assert.deepStrictEqual(drained.messages.map((m) => !!m.acked), [false, true]);
      assert.strictEqual(node.inboxStatus().undrained, 0);
    });
  });

  it('persists the ack across a restart', async () => {
    const name = `ack-restart-${Date.now()}`;
    let node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    await node.start();
    try {
      node._svafEvaluator.evaluate = async () => ALIGNED;
      const seen = collect(node);
      node._frameHandler.handle('peerA', 'peerA', frame(mkCmb('survives restart')));
      await settle();
      node.inboxAck(seen.accepted[0].inboxId);
      await settle(1200); // the inbox write is throttled to one per second
      await node.stop();
      node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
      await node.start();
      assert.strictEqual(node.inboxStatus().undrained, 0);
      assert.strictEqual(node.inboxGet(seen.accepted[0].inboxId).acked, true);
    } finally {
      await node.stop();
      fs.rmSync(nodeDir(name), { recursive: true, force: true });
    }
  });
});

describe('B-L1: admission keeps the author\'s record (MMP §8.8.4, §15.2)', () => {
  it('a collapsed admission stores the author\'s createdBy, timestamp and signature unchanged', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-l1-'));
    const store = new MemoryStore(dir, 'claude-sym-agent-b');
    const config = { stableThreshold: 0.25, guardedThreshold: 0.5, temporalLambda: 0.3, freshnessSeconds: 1800 };
    try {
      const texts = ['lineage tether audit of the remix path', 'remix lineage tether audit, the sender label on the receive path'];
      for (const [i, focus] of texts.entries()) { // #0 takes the cold-start exit, #1 the main path
        const incoming = mkCmb(focus, { by: 'claude-sym-agent-a', parents: ['cmb-' + String(i).repeat(64)] });
        incoming.metadata.sig = `test-signature-${i}`;
        incoming.metadata.sigAlg = 'ed25519';
        const msg = { type: 'cmb', timestamp: Date.now(), cmb: JSON.parse(JSON.stringify(incoming)) };
        const tetherAnchor = core.resolveTetherAnchor(msg.cmb, (k) => store.get(k));
        const r = await core.processHeuristicSVAF({
          msg, peerName: 'claude-sym-agent-a', localName: 'claude-sym-agent-b',
          originTs: Date.now(), now: Date.now(), ageSeconds: 1, recentCMBs: store.recentCMBs(5), config, tetherAnchor,
        });
        assert.ok(r.accepted, `#${i} admitted (${r.decision})`);
        const stored = store.receiveFromPeer('peer-a-id', r.fusedEntry, {});
        assert.strictEqual(stored.key, incoming.metadata.key, `#${i} collapses onto the author's address`);
        assert.strictEqual(recordCreatedBy(stored.cmb), 'claude-sym-agent-a', `#${i} author unchanged`);
        assert.strictEqual(stored.cmb.metadata.createdTimestamp, incoming.metadata.createdTimestamp);
        assert.strictEqual(stored.cmb.metadata.sig, incoming.metadata.sig, `#${i} signature carried`);
        assert.deepStrictEqual(stored.cmb.metadata.lineage?.parents, incoming.metadata.lineage.parents, `#${i} author's lineage carried`);
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('B-D5: directed sends that mint nothing still deliver (MMP §4.4.4)', () => {
  function fakePeer(node, peerId, { accept = true } = {}) {
    const frames = [];
    node._peers.set(peerId, { peerId, name: peerId, lastSeen: Date.now(), transport: { send: (f) => { frames.push(f); return accept; }, close() {} } });
    return frames;
  }
  const cats = (focus) => ({ focus, issue: 'x', intent: 'tell', motivation: 'm', commitment: 'c', perspective: 'me', mood: NEUTRAL });

  it('the same words sent to a second peer are sent, not collapsed into silence', async () => {
    await withNode('d5', async (node) => {
      const a = fakePeer(node, 'peer-a');
      const b = fakePeer(node, 'peer-b');
      const first = node.remember(cats('review request'), { to: 'peer-a' });
      const second = node.remember(cats('review request'), { to: 'peer-b' });
      assert.strictEqual(first.delivery.dispatched, 1);
      assert.ok(second, 'a result, not null');
      assert.strictEqual(second.delivery.undelivered, false);
      assert.strictEqual(a.length, 1);
      assert.strictEqual(b.length, 1);
      assert.strictEqual(b[0].directed, true);
    });
  });

  it('a transport that refuses the frame makes the send undelivered', async () => {
    await withNode('d6', async (node) => {
      fakePeer(node, 'peer-stale', { accept: false });
      const r = node.remember(cats('are you there'), { to: 'peer-stale' });
      assert.strictEqual(r.delivery.dispatched, 0);
      assert.strictEqual(r.delivery.undelivered, true);
    });
  });
});
