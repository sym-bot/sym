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
 *
 * Revised after the xmesh review of PR #43 (mission-79236e8a6dbb), which found that the first cut
 * dropped a repeated directed send at the receiver (F1), keyed directed de-duplication on unsigned
 * frame fields (F2), skipped the post-admit tail for broadcasts (F3), withheld §9.3 mood delivery
 * from directed CMBs (F4), and signed rebuilt categories that had lost their `meta` (F5). Tests now
 * sign real records and drive a real receiving node where the claim is about delivery.
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
const crypto = require('crypto');

// Raw 32-byte Ed25519 keypair (base64url), the shape node identities use.
function rawKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  return { pub: publicKey.slice(-32).toString('base64url'), priv: privateKey.slice(-32).toString('base64url') };
}
const PEER_A = rawKeypair();

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

function mkCmb(focus, { by = 'peerA', parents, mood = NEUTRAL, to } = {}) {
  const cmb = core.createCMB({
    categories: { focus, issue: 'audit regression', intent: 'verify', motivation: 'MMP 2.0 audit', commitment: 'guard', perspective: by, mood },
    createdBy: by,
    to: to ?? null,
  });
  if (parents) cmb.metadata.lineage = { parents, method: 'rule-a' };
  return cmb;
}
const signed = (cmb, kp = PEER_A) => { core.signCMB(cmb, kp.priv); return cmb; };
const frame = (cmb) => JSON.parse(JSON.stringify({ type: 'cmb', timestamp: Date.now(), cmb }));
const directed = (node, cmb) => Object.assign(frame(cmb), { to: node.nodeId, directed: true });
// Waits for every in-flight frame to finish, not a fixed guess at how long that takes.
const { settle } = require('./_settle');
const tick = () => new Promise((r) => setTimeout(r, 5)); // distinct createdTimestamp

function collect(node) {
  const out = { accepted: [], moods: 0 };
  node.on('cmb-accepted', (e) => out.accepted.push(e));
  node.on('mood-delivered', () => { out.moods++; });
  return out;
}

describe('directed delivery (MMP §9.2.2, §8.8.2)', () => {
  it('B-D1: a signed directed reply whose parent is the receiver\'s own CMB surfaces', async () => {
    await withNode('d1', async (node) => {
      node._pinPeerKey('peerA', PEER_A.pub);
      node._svafEvaluator.evaluate = async () => ALIGNED;
      const mine = node.remember({ focus: 'my question to peerA', issue: 'x', intent: 'ask', motivation: 'm', commitment: 'c', perspective: 'me', mood: NEUTRAL });
      assert.ok(mine?.key, 'precondition: a local CMB exists');
      const seen = collect(node);
      const reply = signed(mkCmb('peerA answers your question', { parents: [mine.key], to: node.nodeId }));
      node._frameHandler.handle('peerA', 'peerA', directed(node, reply));
      await settle();
      assert.strictEqual(seen.accepted.length, 1);
    });
  });

  it('re-review F1: frame flags alone do not exempt a reply from echo suppression', async () => {
    await withNode('d1-forged', async (node) => {
      node._pinPeerKey('peerA', PEER_A.pub);
      node._svafEvaluator.evaluate = async () => ALIGNED;
      const mine = node.remember({ focus: 'my broadcast', issue: 'x', intent: 'tell', motivation: 'm', commitment: 'c', perspective: 'me', mood: NEUTRAL });
      const seen = collect(node);
      // Signed as a broadcast (metadata.to null), frame forged to say directed.
      node._frameHandler.handle('peerA', 'peerA', directed(node, signed(mkCmb('remix pong', { parents: [mine.key] }))));
      await settle();
      assert.strictEqual(seen.accepted.length, 0, 'a signed broadcast citing my CMB is an echo, whatever the frame says');
    });
  });

  it('r3 F1: a verified directed CMB from an emitter that signs no addressee field stays directed', async () => {
    await withNode('d1-no-to-field', async (node) => {
      node._pinPeerKey('peerA', PEER_A.pub);
      node._svafEvaluator.evaluate = async () => REJECTED;
      const seen = collect(node);
      const cmb = mkCmb('from another implementation');
      delete cmb.metadata.to; // signs no addressee at all
      node._frameHandler.handle('peerA', 'peerA', directed(node, signed(cmb)));
      await settle();
      assert.strictEqual(seen.accepted.length, 1, 'delivered (§9.2.2) on the frame flags');
    });
  });

  it('r3 F2: an unauthenticated directed reply citing my CMB is delivered once, not processed', async () => {
    await withNode('d1-unsigned-reply', async (node) => {
      let evaluations = 0;
      node._svafEvaluator.evaluate = async () => { evaluations++; return ALIGNED; };
      const mine = node.remember({ focus: 'my question', issue: 'x', intent: 'ask', motivation: 'm', commitment: 'c', perspective: 'me', mood: NEUTRAL });
      const seen = collect(node);
      const f = directed(node, mkCmb('unsigned answer', { parents: [mine.key] }));
      node._frameHandler.handle('peerA', 'peerA', JSON.parse(JSON.stringify(f)));
      await settle();
      node._frameHandler.handle('peerA', 'peerA', JSON.parse(JSON.stringify(f)));
      await settle();
      assert.strictEqual(seen.accepted.length, 1, 'delivered once');
      assert.strictEqual(seen.accepted[0].decision, 'echo');
      assert.strictEqual(seen.accepted[0].remixed, false);
      assert.strictEqual(evaluations, 0, 'never admitted or remixed: no ping-pong');
    });
  });

  it('re-review F1: a signed broadcast with a forged directed frame is not treated as directed', async () => {
    await withNode('d1-signed-to', async (node) => {
      node._pinPeerKey('peerA', PEER_A.pub);
      node._svafEvaluator.evaluate = async () => REJECTED;
      const seen = collect(node);
      node._frameHandler.handle('peerA', 'peerA', directed(node, signed(mkCmb('signed for everyone'))));
      await settle();
      assert.strictEqual(seen.accepted.length, 0, 'memory rejected it and it was never addressed to me');
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

  it('B-D2: a new signed directed send of words already surfaced as a broadcast surfaces again', async () => {
    await withNode('d2', async (node) => {
      node._pinPeerKey('peerA', PEER_A.pub);
      const seen = collect(node);
      node._svafEvaluator.evaluate = async () => ALIGNED;
      node._frameHandler.handle('peerA', 'peerA', frame(signed(mkCmb('status: done'))));
      await settle();
      await tick();
      node._svafEvaluator.evaluate = async () => REJECTED; // memory refuses it; delivery must not
      node._frameHandler.handle('peerA', 'peerA', directed(node, signed(mkCmb('status: done', { to: node.nodeId }))));
      await settle();
      assert.strictEqual(seen.accepted.length, 2, 'the broadcast and the later directed send both surface');
      assert.strictEqual(seen.accepted[1].directed, true);
    });
  });

  it('B-D2: a replay of the same signed directed record still surfaces only once', async () => {
    await withNode('d2-replay', async (node) => {
      node._pinPeerKey('peerA', PEER_A.pub);
      node._svafEvaluator.evaluate = async () => REJECTED;
      const seen = collect(node);
      const f = directed(node, signed(mkCmb('please review the fix list', { to: node.nodeId })));
      node._frameHandler.handle('peerA', 'peerA', JSON.parse(JSON.stringify(f)));
      await settle();
      node._frameHandler.handle('peerA', 'peerA', JSON.parse(JSON.stringify(f)));
      await settle();
      assert.strictEqual(seen.accepted.length, 1);
    });
  });

  it('B-R8: a signed addressee decides: a relay that strips the frame\'s directed flag cannot turn it into a broadcast', async () => {
    await withNode('r8', async (node) => {
      node._pinPeerKey('peerA', PEER_A.pub);
      node._svafEvaluator.evaluate = async () => REJECTED; // as a broadcast it would be gated away
      const seen = collect(node);
      const f = frame(signed(mkCmb('for your eyes: the rollback plan', { to: node.nodeId })));
      assert.strictEqual(f.directed, undefined, 'precondition: the frame does not say directed');
      node._frameHandler.handle('peerA', 'peerA', f);
      await settle();
      assert.strictEqual(seen.accepted.length, 1, 'it surfaces as the directed CMB its author signed');
      assert.strictEqual(seen.accepted[0].directed, true);
    });
  });

  it('N1: a relay cannot replay a signed directed record by re-spelling its signature or adding an assertionId', async () => {
    await withNode('d2-respell', async (node) => {
      node._pinPeerKey('peerA', PEER_A.pub);
      node._svafEvaluator.evaluate = async () => REJECTED;
      const seen = collect(node);
      const f = directed(node, signed(mkCmb('approve the release', { to: node.nodeId })));
      const sig = f.cmb.metadata.sig;
      // The same 64 signature bytes, spelled three other ways base64url decoding accepts.
      const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
      const last = B64.indexOf(sig[sig.length - 1]);
      const twin = B64[(last & 0b110000) | ((last + 1) & 0b001111)]; // same top 2 data bits, other padding bits
      assert.deepStrictEqual(Buffer.from(sig.slice(0, -1) + twin, 'base64url'), Buffer.from(sig, 'base64url'));
      const variants = [
        (c) => { c.cmb.metadata.sig = sig + '='; },
        (c) => { c.cmb.metadata.sig = sig.slice(0, -1) + twin; },
        (c) => { c.cmb.metadata.assertionId = 'asrt-0000000000000000000000000000000000000000000000000000000000000000'; },
      ];
      node._frameHandler.handle('peerA', 'peerA', JSON.parse(JSON.stringify(f)));
      await settle();
      for (const v of variants) {
        const copy = JSON.parse(JSON.stringify(f));
        v(copy);
        node._frameHandler.handle('peerA', 'peerA', copy);
        await settle();
      }
      assert.strictEqual(seen.accepted.length, 1, 'every re-spelling is the same assertion');
    });
  });

  it('K1: two copies of one record in flight at once surface once', async () => {
    await withNode('k1', async (node) => {
      node._pinPeerKey('peerA', PEER_A.pub);
      node._pinPeerKey('peerB', PEER_A.pub);
      let release;
      const gate = new Promise((r) => { release = r; });
      node._svafEvaluator.evaluate = async () => { await gate; return ALIGNED; }; // the first copy is still in SVAF
      const seen = collect(node);
      const f = frame(signed(mkCmb('the same record, arriving twice')));
      node._frameHandler.handle('peerA', 'peerA', JSON.parse(JSON.stringify(f)));
      node._frameHandler.handle('peerB', 'peerB', JSON.parse(JSON.stringify(f))); // via a second peer, meanwhile
      release();
      await settle();
      assert.strictEqual(seen.accepted.length, 1);
      assert.strictEqual(node._frameHandler._inFlightKeys.size, 0, 'the in-flight mark is released');
    });
  });

  it('K3: a broadcast flood cannot evict a directed assertion mark', async () => {
    await withNode('k3', async (node) => {
      node._pinPeerKey('peerA', PEER_A.pub);
      node._svafEvaluator.evaluate = async () => REJECTED;
      const seen = collect(node);
      const f = directed(node, signed(mkCmb('approve the release', { to: node.nodeId })));
      node._frameHandler.handle('peerA', 'peerA', JSON.parse(JSON.stringify(f)));
      await settle();
      const now = Date.now();
      for (let i = 0; i <= 10000; i++) node._frameHandler._recordSeenCmbKey(`cmb-flood-${i}`, now);
      node._frameHandler.handle('peerA', 'peerA', JSON.parse(JSON.stringify(f)));
      await settle();
      assert.strictEqual(seen.accepted.length, 1, 'the replay is still recognised');
    });
  });

  it('F2: an unverified directed CMB cannot widen its de-duplication key with unsigned fields', async () => {
    await withNode('d2-unsigned', async (node) => {
      node._svafEvaluator.evaluate = async () => REJECTED;
      const seen = collect(node);
      const base = directed(node, mkCmb('unsigned flood attempt')); // peerA's key is unknown: unverified
      for (let i = 0; i < 3; i++) {
        const f = JSON.parse(JSON.stringify(base));
        f.timestamp = i + 1; // a bare frame field the sender chooses
        node._frameHandler.handle('peerA', 'peerA', f);
        await settle(); // sequential arrivals: concurrent identical arrivals race SVAF (pre-existing, broadcast too)
      }
      await tick();
      node._frameHandler.handle('peerA', 'peerA', directed(node, mkCmb('unsigned flood attempt'))); // new createdTimestamp, no signature
      await settle();
      assert.strictEqual(seen.accepted.length, 1, 'one surface per content for records nothing authenticates');
    });
  });

  it('B-D3: an admitted directed CMB whose key is already stored surfaces as delivered-not-stored', async () => {
    await withNode('d3', async (node) => {
      node._pinPeerKey('peerA', PEER_A.pub);
      node._svafEvaluator.evaluate = async () => ALIGNED;
      const seen = collect(node);
      node._frameHandler.handle('peerA', 'peerA', frame(signed(mkCmb('ack'))));
      await settle();
      await tick();
      node._frameHandler.handle('peerA', 'peerA', directed(node, signed(mkCmb('ack', { to: node.nodeId }))));
      await settle();
      assert.strictEqual(seen.accepted.length, 2);
      assert.strictEqual(seen.accepted[1].directed, true);
      assert.strictEqual(seen.accepted[1].remixed, false);
      assert.strictEqual(seen.accepted[1].decision, 'redundant');
    });
  });

  it('F4: a rejected directed CMB surfaces once AND still delivers its mood (MMP §9.3)', async () => {
    await withNode('d4', async (node) => {
      node._svafEvaluator.evaluate = async () => REJECTED;
      const seen = collect(node);
      node._frameHandler.handle('peerA', 'peerA', directed(node, mkCmb('urgent: the build is red', { mood: { text: 'alarmed', valence: -0.7, arousal: 0.8 } })));
      await settle();
      assert.strictEqual(seen.accepted.length, 1, 'one cmb-accepted');
      assert.strictEqual(seen.moods, 1, 'the affect channel is separate and has no directed exemption');
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

describe('re-review F7: a directed CMB the store failed to write', () => {
  it('surfaces with decision not-stored, not redundant', async () => {
    await withNode('f7', async (node) => {
      node._pinPeerKey('peerA', PEER_A.pub);
      node._svafEvaluator.evaluate = async () => ALIGNED;
      node._store._persist = () => false; // the disk refuses the write
      const seen = collect(node);
      node._frameHandler.handle('peerA', 'peerA', directed(node, signed(mkCmb('store me', { to: node.nodeId }))));
      await settle();
      assert.strictEqual(seen.accepted.length, 1);
      assert.strictEqual(seen.accepted[0].decision, 'not-stored');
    });
  });
});

describe('r3 F8 / R2-F12: inbox alarm on an empty ring; creatorRole reaches the store', () => {
  it('neverDrained holds when every item was evicted undrained', async () => {
    await withNode('f8', async (node) => {
      node._inboxSeq = 3; node._inbox = []; node._inboxCursor = 0;
      assert.strictEqual(node.inboxStatus().neverDrained, true);
    });
  });

  it('a validator-origin admission is weighted 2.0 (§6.4)', async () => {
    await withNode('r2f12', async (node) => {
      const entry = { content: 'validator says', cmb: mkCmb('validator observation') };
      const stored = node._store.receiveFromPeer('peer-v', entry, { creatorRole: 'validator' });
      assert.strictEqual(stored.anchorWeight, 2.0);
    });
  });
});

describe('F3: an admitted broadcast the store already holds', () => {
  it('still emits memory-received and is marked, so a replay does not re-run SVAF', async () => {
    await withNode('f3', async (node) => {
      const cats = { focus: 'shared anchor', issue: 'audit regression', intent: 'verify', motivation: 'MMP 2.0 audit', commitment: 'guard', perspective: 'peerA', mood: NEUTRAL };
      node.remember(cats); // the receiver already holds this cognition key, as its own
      let evaluations = 0;
      node._svafEvaluator.evaluate = async () => { evaluations++; return ALIGNED; };
      let memoryReceived = 0;
      node.on('memory-received', () => { memoryReceived++; });
      const cmb = core.createCMB({ categories: cats, createdBy: 'peerA' });
      node._frameHandler.handle('peerA', 'peerA', frame(cmb));
      await settle();
      node._frameHandler.handle('peerA', 'peerA', frame(cmb));
      await settle();
      assert.strictEqual(memoryReceived, 1, 'the admitted path still completes');
      assert.strictEqual(evaluations, 1, 'the replay is suppressed before SVAF');
    });
  });
});

describe('author and inbox id on surfaced entries', () => {
  it('carries the author and the delivering peer; the inbox `from` is the peer when nothing proves the author (K5)', async () => {
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
      assert.strictEqual(item.from, 'peerA', 'an unsigned claim is not who the inbox says it is from');
      assert.strictEqual(item.author.name, 'claude-sym-agent-a', 'the claim is kept, as a claim');
      assert.strictEqual(item.seq, e.inboxSeq);
    });
  });

  it('K5: the inbox `from` is the author when its signature proved who that is', async () => {
    await withNode('author-proven', async (node) => {
      node._pinPeerKey('peerA', PEER_A.pub);
      node._svafEvaluator.evaluate = async () => ALIGNED;
      const seen = collect(node);
      const cmb = signed(mkCmb('proven authorship', { by: 'peerA' }));
      cmb.metadata.createdByNodeId = undefined;
      node._frameHandler.handle('peerA', 'peerA', frame(cmb));
      await settle();
      const item = node.inboxGet(seen.accepted[0].inboxId);
      assert.strictEqual(item.from, 'peerA');
    });
  });

  it('every surfaced path carries author.via: rejected-directed, CLI-host and admitted', async () => {
    const paths = {
      'rejected-directed': async (node) => { node._svafEvaluator.evaluate = async () => REJECTED; return directed(node, mkCmb('via rejected')); },
      'cli-host': async (node) => { node._frameHandler._cliHostMode = true; return frame(mkCmb('via cli host')); },
      admitted: async (node) => { node._svafEvaluator.evaluate = async () => ALIGNED; return frame(mkCmb('via admitted')); },
    };
    for (const [label, setup] of Object.entries(paths)) {
      await withNode(`via-${label}`, async (node) => {
        const seen = collect(node);
        node._frameHandler.handle('peer-a-id', 'peerA', await setup(node));
        await settle();
        assert.strictEqual(seen.accepted.length, 1, label);
        assert.deepStrictEqual(seen.accepted[0].author?.via, { name: 'peerA', nodeId: 'peer-a-id' }, `${label}: author.via`);
        assert.deepStrictEqual(node.inboxGet(seen.accepted[0].inboxId).author?.via, { name: 'peerA', nodeId: 'peer-a-id' }, `${label}: inbox item author.via`);
      });
    }
  });

  it('a frame-supplied source never names the deliverer (agent-a review, mission-56a137ffa8e4 F2)', async () => {
    for (const [label, verdict, mk] of [
      ['admitted broadcast', ALIGNED, (node) => frame(mkCmb('forged deliverer A'))],
      ['rejected directed', REJECTED, (node) => directed(node, mkCmb('forged deliverer B'))],
    ]) {
      await withNode(`src-${label.replace(' ', '-')}`, async (node) => {
        node._svafEvaluator.evaluate = async () => verdict;
        const seen = collect(node);
        const f = mk(node);
        f.source = node.name; // pose as the receiver itself
        node._frameHandler.handle('peer-a-id', 'peerA', f);
        await settle();
        assert.strictEqual(seen.accepted.length, 1, label);
        assert.ok(String(seen.accepted[0].source).endsWith('peerA'), `${label}: source names the connection, got ${seen.accepted[0].source}`);
        assert.notStrictEqual(seen.accepted[0].source, node.name, `${label}: not the receiver's own name`);
      });
    }
  });

  it('F15: an unverified createdByNodeId is not presented as the author identity, and msg.source is ignored', async () => {
    await withNode('author-forged', async (node) => {
      node._svafEvaluator.evaluate = async () => ALIGNED;
      const seen = collect(node);
      const cmb = mkCmb('who wrote this', { by: 'peerA' });
      cmb.metadata.createdByNodeId = 'victim-node-id';
      const f = frame(cmb);
      f.source = 'founder';
      node._frameHandler.handle('peer-a-id', 'peerA', f);
      await settle();
      assert.strictEqual(seen.accepted[0].author.name, 'peerA');
      assert.strictEqual(seen.accepted[0].author.nodeId, null);
    });
  });

  it('F15: a signed record whose createdByNodeId is the verified delivering peer carries that nodeId', async () => {
    await withNode('author-verified', async (node) => {
      node._pinPeerKey('peer-a-id', PEER_A.pub);
      node._svafEvaluator.evaluate = async () => ALIGNED;
      const seen = collect(node);
      const cmb = mkCmb('signed by its author', { by: 'peerA' });
      cmb.metadata.createdByNodeId = 'peer-a-id';
      node._frameHandler.handle('peer-a-id', 'peerA', frame(signed(cmb)));
      await settle();
      assert.strictEqual(seen.accepted[0].author.nodeId, 'peer-a-id');
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
      assert.strictEqual(node.inboxStatus().neverDrained, true, 're-review F4: one ack does not make an undrained inbox attended');
      node.inboxAck(seen.accepted[0].inboxId);
      assert.strictEqual(node.inboxStatus().neverDrained, false, 'every item read: the inbox is attended');
      const drained = node.inbox();
      assert.strictEqual(drained.drained, 2, 'acked items are returned, not skipped');
      assert.deepStrictEqual(drained.messages.map((m) => !!m.acked), [true, true]);
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
      await node.stop(); // re-review F8: stop() flushes the throttled inbox write
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
        const incoming = core.createCMB({
          categories: { focus, issue: 'audit regression', intent: 'verify', motivation: 'MMP 2.0 audit', commitment: 'guard', perspective: 'claude-sym-agent-a', mood: { text: 'alarmed', valence: -0.7, arousal: 0.8 } },
          createdBy: 'claude-sym-agent-a',
          lineage: { parents: ['cmb-' + String(i).repeat(64)], method: 'rule-a' },
          // A signed per-category section that fusion must carry through (review F5).
          categoryParents: { issue: ['cmb-' + 'f'.repeat(64)] },
        });
        signed(incoming);
        assert.strictEqual(core.verifyCMB(incoming, PEER_A.pub).valid, true, 'precondition: the author\'s record verifies');
        const msg = { type: 'cmb', timestamp: Date.now(), cmb: JSON.parse(JSON.stringify(incoming)) };
        msg.cmb.categories.focus.injected = 'a field no signature covers';
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
        assert.strictEqual(core.verifyCMB(stored.cmb, PEER_A.pub).valid, true, `#${i} the stored record still verifies under the author's key`);
        assert.strictEqual(stored.cmb.categories.focus.injected, undefined, `#${i} r3 F5: unsigned extra fields are not carried`);
        assert.deepStrictEqual(
          { v: stored.cmb.categories.mood.valence, a: stored.cmb.categories.mood.arousal },
          { v: -0.7, a: 0.8 }, `#${i} re-review F6: the author's affect is kept`);
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
  // A real receiving node: every frame A hands to its transport is handled by B's frame handler.
  function pipe(a, b) {
    b._pinPeerKey(a.nodeId, a._identity.publicKey);
    a._peers.set(b.nodeId, {
      peerId: b.nodeId, name: b.name, lastSeen: Date.now(),
      transport: { send: (f) => { const copy = JSON.parse(JSON.stringify(f)); setImmediate(() => b._frameHandler.handle(a.nodeId, a.name, copy)); return true; }, close() {} },
    });
  }
  const cats = (focus) => ({ focus, issue: 'x', intent: 'tell', motivation: 'm', commitment: 'c', perspective: 'me', mood: NEUTRAL });

  for (const [label, verdict] of [['memory rejects', REJECTED], ['memory admits', ALIGNED]]) {
    it(`F1: the same words sent twice to the same peer surface twice at that peer (${label})`, async () => {
      await withNode('d5-a', (a) => withNode('d5-b', async (b) => {
        pipe(a, b);
        b._svafEvaluator.evaluate = async () => verdict;
        const seen = collect(b);
        const first = a.remember(cats('please review'), { to: b.nodeId });
        await settle();
        await tick();
        const second = a.remember(cats('please review'), { to: b.nodeId });
        await settle();
        assert.strictEqual(first.delivery.dispatched, 1);
        assert.strictEqual(second.delivery.dispatched, 1);
        assert.strictEqual(seen.accepted.filter((e) => e.directed).length, 2, 'the receiver surfaced both requests');
        for (const e of seen.accepted) assert.strictEqual(e._cmbVerified, true, 'each re-sent record verifies under the sender\'s key');
      }));
    });
  }

  it('re-review F9: two directed sends of the same words in one millisecond both surface', async () => {
    await withNode('d5-a', (a) => withNode('d5-b', async (b) => {
      pipe(a, b);
      b._svafEvaluator.evaluate = async () => REJECTED;
      const seen = collect(b);
      a.remember(cats('ping'), { to: b.nodeId });
      a.remember(cats('ping'), { to: b.nodeId }); // no await, no tick
      await settle();
      assert.strictEqual(seen.accepted.length, 2);
    }));
  });

  it('re-review F2: a caller-supplied record that collapses is not sent unre-signed, and says so', async () => {
    await withNode('d5-caller', async (node) => {
      const frames = fakePeer(node, 'peer-a');
      const first = node.remember(cats('forwarded'), { to: 'peer-a' });
      const own = JSON.parse(JSON.stringify(first.cmb)); // a record the caller holds, already signed
      const r = node.remember(null, { cmb: own, to: 'peer-a' }); // same content: collapses onto HEAD
      assert.strictEqual(r.collapsed, true);
      assert.strictEqual(r.delivery.undelivered, true, 'not sent, and the caller is told');
      assert.strictEqual(frames.length, 1, 'only the first send went out');
    });
  });

  it('re-review F5: a directed send matching a peer\'s stored CMB returns the caller\'s entry, not the peer\'s', async () => {
    await withNode('d5-peer-dup', async (node) => {
      fakePeer(node, 'peer-a');
      node._svafEvaluator.evaluate = async () => ALIGNED;
      const shared = { focus: 'shared words', issue: 'x', intent: 'tell', motivation: 'm', commitment: 'c', perspective: 'peerA', mood: NEUTRAL };
      node._frameHandler.handle('peerA', 'peerA', frame(core.createCMB({ categories: shared, createdBy: 'peerA' })));
      await settle();
      const r = node.remember(shared, { to: 'peer-a' });
      assert.strictEqual(r.duplicate, true);
      for (const f of ['peerId', 'remixed', 'author', 'inboxId', 'svaf']) {
        assert.strictEqual(r[f], undefined, `no peer provenance field ${f} on the caller's result`);
      }
      assert.strictEqual(r.source, node.name, 'r3 F11: the caller\'s own source, like any entry it writes');
      assert.strictEqual(typeof r.content, 'string');
      assert.strictEqual(r.delivery.dispatched, 1);
    });
  });

  it('r3 F3: a send whose store write failed is not reported as a duplicate', async () => {
    await withNode('d5-persist', async (node) => {
      fakePeer(node, 'peer-a');
      node._store._persist = () => false;
      const r = node.remember(cats('cannot store'), { to: 'peer-a' });
      assert.ok(r, 'a result');
      assert.strictEqual(r.duplicate, false);
      assert.strictEqual(r.persisted, false);
      assert.strictEqual(r.delivery.dispatched, 1, 'still delivered');
    });
  });

  it('r3 F6: a caller-supplied record that collapses is returned unmodified', async () => {
    await withNode('d5-unmodified', async (node) => {
      fakePeer(node, 'peer-a');
      const first = node.remember(cats('forwarded'), { to: 'peer-a' });
      const own = JSON.parse(JSON.stringify(first.cmb));
      own.metadata.lineage = { parents: ['cmb-' + 'e'.repeat(64)], method: 'rule-a' };
      const before = JSON.stringify(own);
      node.remember(null, { cmb: own, to: 'peer-a' });
      assert.strictEqual(JSON.stringify(own), before, 'the caller\'s signed record is not mutated');
    });
  });

  it('F12: a directed send of an already-stored record returns an entry with its delivery result', async () => {
    await withNode('d5-dup', async (node) => {
      fakePeer(node, 'peer-a');
      node.remember(cats('first'), { to: 'peer-a' });
      node.remember(cats('second'), { to: 'peer-a' });
      const again = node.remember(cats('first'), { to: 'peer-a' }); // stored, but not HEAD
      assert.ok(again && typeof again.content === 'string', 'entry-shaped, not a bare {key, cmb}');
      assert.strictEqual(again.duplicate, true);
      assert.strictEqual(again.delivery.dispatched, 1);
    });
  });

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
