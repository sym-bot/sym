'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * 0.14.0 review follow-up: each checkpoint a node takes costs every node in the room a witness signed,
 * gossiped and verified. The per-peer budget bounded what one peer delivers, but an attester could
 * flood new checkpoints through every peer at once, and every node would witness each one. A node now
 * takes one attester's new checkpoints at most at 4 a second after a burst of 128 (an honest attester
 * commits one every 8 attestations: 0.5 a second in a busy room), whichever peer brings them, and past
 * that does not store, witness or relay them.
 *
 * Deterministic: the clock is injected (node._gossipClock), with real Ed25519 signatures.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const { signCheckpoint } = require('../lib/core');

const ROOM = 'g';
const kp = () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', { publicKeyEncoding: { type: 'spki', format: 'der' }, privateKeyEncoding: { type: 'pkcs8', format: 'der' } });
  return { pub: publicKey.slice(-32).toString('base64url'), priv: privateKey.slice(-32).toString('base64url') };
};

function withNode(n, fn) {
  const name = `checkpoint-rate-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: ROOM });
  try {
    const keys = Array.from({ length: n }, (_, i) => ({ id: `att-${i}`, ...kp() }));
    for (const k of keys) node._roster.bind(k.id, k.pub, 'proven');
    const sent = [];
    node._gossipToRoster = (frame) => sent.push(frame);
    const clock = { t: 1_800_000_000_000 };
    node._gossipClock = () => clock.t;
    const reports = [];
    node.on('metric', (m) => { if (m.type === 'checkpoint-over-rate') reports.push(m); });
    return fn({ node, keys, clock, sent, reports });
  } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
}

const checkpoint = (k, upto_seq, at = upto_seq) => signed({ type: 'checkpoint', by: k.id, roster: ROOM, upto_seq, root: `root-${k.id}-${upto_seq}`, at }, k.priv);
function signed(fields, priv) { const o = { ...fields }; signCheckpoint(o, priv); return o; }
const witnessesBy = (sent, node, attester) => sent.filter((f) => f.type === 'sym-attest-witness' && f.witness.by === node.nodeId && f.witness.attester === attester);
const relayed = (sent, attester) => sent.filter((f) => f.type === 'sym-attest-checkpoint' && f.checkpoint.by === attester);

describe('checkpoint rate — one attester', () => {
  it("a flooding attester's checkpoints past the bound are not stored, witnessed or relayed, whichever peers bring them", () => {
    withNode(1, ({ node, keys: [A], clock, sent, reports }) => {
      const t0 = clock.t;
      const outcome = { taken: 0, overRate: 0, other: 0 };
      const dropped = [];
      // 1,000 new checkpoints a second for 5 s, spread over five peers (each well within its budget).
      for (let i = 0; i < 5000; i++) {
        clock.t = t0 + i;
        const cp = checkpoint(A, 8 * (i + 1));
        const r = node._ingestCheckpoint(cp, `peer-${i % 5}`);
        if (r.ok) outcome.taken++;
        else if (r.reason === 'over-rate') { outcome.overRate++; dropped.push(cp); }
        else outcome.other++;
      }
      // A burst of 128, then 4 a second for 5 s.
      assert.ok(Math.abs(outcome.taken - (128 + 20)) <= 1, `taken ${outcome.taken}`);
      assert.strictEqual(outcome.other, 0);
      assert.strictEqual(witnessesBy(sent, node, A.id).length, outcome.taken, 'this node witnessed only what it took');
      assert.strictEqual(relayed(sent, A.id).length, outcome.taken, 'and relayed only that');
      for (const cp of dropped.slice(-50)) assert.strictEqual(node._attestations.checkpointAt(A.id, cp.upto_seq), null, 'a dropped one is not stored');
      // Said once in the window, every drop counted, the attester and the peers named.
      assert.strictEqual(reports.length, 1);
      node._sayDrops(node._dropReports.get(`checkpoint-over-rate|${A.id}`));
      assert.strictEqual(reports.reduce((s, m) => s + m.dropped, 0), outcome.overRate);
      assert.strictEqual(node.metrics().checkpointsOverRate, outcome.overRate);
      assert.strictEqual(reports[0].attester, A.id);
      assert.deepStrictEqual([...new Set(reports.flatMap((m) => m.fromPeerIds))].sort(), ['peer-0', 'peer-1', 'peer-2', 'peer-3', 'peer-4']);
      // The same checkpoints again, from yet more peers, while the rate is spent: still not taken.
      for (const cp of dropped.slice(0, 100)) assert.strictEqual(node._ingestCheckpoint(cp, 'peer-9').reason, 'over-rate');
      assert.strictEqual(witnessesBy(sent, node, A.id).length, outcome.taken);
      // A second root for a position it holds is still recorded as a conflict: that spends nothing.
      const heldPos = node._attestations.latestCheckpoint(A.id).upto_seq;
      const fork = signed({ type: 'checkpoint', by: A.id, roster: ROOM, upto_seq: heldPos, root: 'forked', at: 1 }, A.priv);
      assert.strictEqual(node._ingestCheckpoint(fork, 'peer-0').reason, 'conflict');
      assert.strictEqual(node._attestations.hasConflict(A.id, heldPos), true);
    });
  });

  it('an honest attester at its normal rate is never limited, including over a burst', () => {
    withNode(4, ({ node, keys, clock, sent }) => {
      const t0 = clock.t;
      const seq = new Map(keys.map((k) => [k.id, 0]));
      let refused = 0;
      const next = (k) => { const n = seq.get(k.id) + 8; seq.set(k.id, n); return checkpoint(k, n); };
      // Four attesters, each committing a checkpoint every 2 s (gating 4 CMBs a second) for 10 minutes.
      for (let ms = 0; ms < 600_000; ms += 500) {
        clock.t = t0 + ms;
        const k = keys[(ms / 500) % 4];
        if (!node._ingestCheckpoint(next(k), 'hub').ok) refused++;
      }
      // Then one gates 1,024 CMBs back to back: 128 checkpoints in one second, and carries on as before.
      const t1 = clock.t;
      for (let i = 0; i < 128; i++) {
        clock.t = t1 + Math.floor(i * 1000 / 128);
        if (!node._ingestCheckpoint(next(keys[0]), 'hub').ok) refused++;
      }
      for (let ms = 2000; ms <= 60_000; ms += 2000) {
        clock.t = t1 + ms;
        if (!node._ingestCheckpoint(next(keys[0]), 'hub').ok) refused++;
      }
      assert.strictEqual(refused, 0, 'every checkpoint was taken');
      const own = sent.filter((f) => f.type === 'sym-attest-witness' && f.witness.by === node.nodeId).length;
      assert.strictEqual(own, 1200 + 128 + 30, 'and witnessed');
    });
  });

  it('forged checkpoints naming an honest attester do not spend its rate', () => {
    withNode(1, ({ node, keys: [H], clock }) => {
      const t0 = clock.t;
      let pos = 0;
      for (let i = 0; i < 2000; i++) {
        clock.t = t0 + Math.floor(i / 2);
        pos += 8;
        const forged = { type: 'checkpoint', by: H.id, roster: ROOM, upto_seq: pos, root: 'x', at: 1, sig: crypto.randomBytes(64).toString('base64url') };
        assert.strictEqual(node._ingestCheckpoint(forged, 'mallory').reason, 'bad-signature');
      }
      // Its own checkpoints, a burst of them, are all still taken.
      for (let i = 0; i < 100; i++) assert.strictEqual(node._ingestCheckpoint(checkpoint(H, (pos += 8)), 'hub').ok, true, `checkpoint ${i}`);
    });
  });
});
