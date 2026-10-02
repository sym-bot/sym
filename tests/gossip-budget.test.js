'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * 0.14.0: one peer's gossiped attestations, checkpoints and witnesses have a budget of new statements
 * (2,000 a second, a burst of 10,000), spent before the signature is checked. The earlier, rejected
 * attempts spent it on repeats and unsigned frames, left attestations unbudgeted, budgeted 100 a
 * second (below a busy room's legitimate rate, so a drop read as an omission), emitted a metric per
 * dropped frame, and scanned the bucket map on every call. Each case below fails on one of those.
 *
 * Deterministic: the budget's clock is injected (node._gossipClock), and frames are ingested the way
 * the frame handler hands them over (_ingestAttestation / _ingestCheckpoint / _ingestWitness), with
 * real Ed25519 signatures.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const { signAttestation, signCheckpoint, signWitness } = require('../lib/core');
const { chainHash, isCanonicalSig } = require('../lib/attestation-store');

const ROOM = 'g';
const kp = () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', { publicKeyEncoding: { type: 'spki', format: 'der' }, privateKeyEncoding: { type: 'pkcs8', format: 'der' } });
  return { pub: publicKey.slice(-32).toString('base64url'), priv: privateKey.slice(-32).toString('base64url') };
};
const signed = (fields, priv, sign) => { const o = { ...fields }; sign(o, priv); return o; };
const forgedSig = () => crypto.randomBytes(64).toString('base64url');

/** A node (not started) that holds the keys of `n` attesters, on an injected clock. */
function withNode(n, fn) {
  const name = `gossip-budget-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: ROOM });
  try {
    const keys = Array.from({ length: n }, (_, i) => ({ id: `att-${i}`, ...kp() }));
    for (const k of keys) node._pinPeerKey(k.id, k.pub);
    node._gossipToRoster = () => {};
    const clock = { t: 1_800_000_000_000 };
    node._gossipClock = () => clock.t;
    const metrics = [];
    node.on('metric', (m) => { if (m.type === 'gossip-over-budget') metrics.push(m); });
    return fn({ node, keys, clock, metrics });
  } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
}

const ingest = (node, peer, f) => (f.type === 'attestation' ? node._ingestAttestation(f.attestation, peer, peer)
  : f.type === 'checkpoint' ? node._ingestCheckpoint(f.checkpoint, peer) : node._ingestWitness(f.witness, peer));

let ofSeq = 0;
const attestation = (k, seq) => ({ type: 'attestation', attestation: signed({ of: `cmb-${++ofSeq}`, by: k.id, at: 1, roster: ROOM, method: 'heuristic', verdict: 'aligned', categories: {}, role: 'participant', seq, prev: 'p' }, k.priv, signAttestation) });
const forgedAttestation = (k) => ({ type: 'attestation', attestation: { of: `cmb-forged-${++ofSeq}`, by: k.id, at: 1, roster: ROOM, verdict: 'aligned', categories: {}, seq: ofSeq, prev: 'p', sig: forgedSig(), sigAlg: 'ed25519' } });

/**
 * A busy room through one peer, second by second: R attesters each gating G CMBs a second, a
 * checkpoint every 8 attestations, and every other attester witnessing each checkpoint —
 * R·G + R·G/8 + R·G/8·(R−1) new statements a second (640 at R = 32, G = 4). This is what a peer
 * delivers when it is this node's only path to the room; in a full mesh it delivers ~20 of them.
 */
function* busyRoom(keys, G, seconds) {
  const seq = new Map(keys.map((k) => [k.id, 0]));
  for (let s = 0; s < seconds; s++) {
    const frames = [];
    for (let g = 0; g < G; g++) {
      for (const k of keys) {
        const n = seq.get(k.id) + 1;
        seq.set(k.id, n);
        frames.push(attestation(k, n));
        if (n % 8 === 0) {
          const cp = signed({ type: 'checkpoint', by: k.id, roster: ROOM, upto_seq: n, root: `root-${k.id}-${n}`, at: n }, k.priv, signCheckpoint);
          frames.push({ type: 'checkpoint', checkpoint: cp });
          for (const w of keys) {
            if (w === k) continue;
            frames.push({ type: 'witness', witness: signed({ type: 'witness', attester: k.id, roster: ROOM, upto_seq: n, root: cp.root, by: w.id, role: 'participant', at: n }, w.priv, signWitness) });
          }
        }
      }
    }
    yield frames;
  }
}

describe('gossip budget — sized for a busy room', () => {
  it("drops a flood, but none of an honest peer's traffic at a busy room's rate (640 new statements a second through one peer)", () => {
    withNode(32, ({ node, keys, clock, metrics }) => {
      const counts = { attestation: 0, checkpoint: 0, witness: 0 };
      let refused = 0;
      const start = clock.t;
      const room = busyRoom(keys, 4, 22);
      for (let sec = 0; sec < 20; sec++) {
        const frames = room.next().value;
        const second = clock.t;
        frames.forEach((f, i) => {
          clock.t = second + Math.floor((i * 1000) / frames.length);
          const r = ingest(node, 'hub', f);
          counts[f.type]++;
          if (!r.ok && r.reason !== 'pending') refused++;
        });
        clock.t = second + 1000;
      }
      assert.deepStrictEqual(counts, { attestation: 2560, checkpoint: 320, witness: 9920 }, '640 a second for 20 s');
      assert.strictEqual(refused, 0, 'every statement from the honest peer was taken');
      assert.strictEqual(metrics.length, 0, 'and nothing was reported dropped');
      assert.ok(clock.t - start === 20000);

      // A flood from another peer: forged attestations at 20,000 a second for 2 s, the honest peer
      // carrying on at its rate alongside.
      const flood = { verified: 0, dropped: 0 };
      const t0 = clock.t;
      for (let ms = 0; ms < 2000; ms++) {
        clock.t = t0 + ms;
        for (let j = 0; j < 20; j++) {
          const r = ingest(node, 'flooder', forgedAttestation(keys[j % keys.length]));
          if (r.reason === 'over-budget') flood.dropped++; else flood.verified++;
        }
        if (ms % 1000 === 0) {
          for (const f of room.next().value) { const r = ingest(node, 'hub', f); if (!r.ok && r.reason !== 'pending') refused++; }
        }
      }
      // A burst of 10,000, then 2,000 a second: ~14,000 signature checks bought, of 40,000 sent.
      assert.ok(Math.abs(flood.verified - 14000) <= 2, `verified ${flood.verified}`);
      assert.strictEqual(flood.verified + flood.dropped, 40000);
      assert.strictEqual(refused, 0, 'the honest peer lost nothing during the flood');
      assert.ok(metrics.length >= 1 && metrics.every((m) => m.fromPeerId === 'flooder'));
    });
  });
});

describe('gossip budget — only new statements spend it', () => {
  it('repeats, re-spelled signatures, unsigned frames and unknown signers are dropped before it and spend nothing', () => {
    withNode(3, ({ node, keys: [A, W, X] }) => {
      const tokens = () => node._gossipBuckets.get('p')?.tokens ?? node._gossipBurst;
      const spent = () => node._gossipBurst - tokens();
      // One of each held: an attestation, a checkpoint and its witness, a conflict, a waiting witness.
      const att = attestation(A, 1);
      const cp = signed({ type: 'checkpoint', by: A.id, roster: ROOM, upto_seq: 8, root: 'r8', at: 1 }, A.priv, signCheckpoint);
      const fork = signed({ type: 'checkpoint', by: A.id, roster: ROOM, upto_seq: 8, root: 'forked', at: 2 }, A.priv, signCheckpoint);
      const wit = signed({ type: 'witness', attester: A.id, roster: ROOM, upto_seq: 8, root: 'r8', by: W.id, role: 'participant', at: 1 }, W.priv, signWitness);
      const witFork = signed({ type: 'witness', attester: A.id, roster: ROOM, upto_seq: 8, root: 'forked', by: W.id, role: 'participant', at: 2 }, W.priv, signWitness);
      const waiting = signed({ type: 'witness', attester: X.id, roster: ROOM, upto_seq: 16, root: 'r16', by: W.id, role: 'participant', at: 1 }, W.priv, signWitness);
      for (const f of [att, { type: 'checkpoint', checkpoint: cp }, { type: 'checkpoint', checkpoint: fork }, { type: 'witness', witness: wit }, { type: 'witness', witness: witFork }, { type: 'witness', witness: waiting }]) ingest(node, 'p', f);
      assert.strictEqual(node._attestations.hasConflict(A.id, 8), true);
      assert.strictEqual(node._attestations.witnessSeen(X.id, 16, W.id).root, 'r16', 'one waits for its checkpoint');
      const before = spent();
      assert.strictEqual(before, 6, 'each new statement spent one');

      const s = att.attestation.sig;
      const respelled = [s + '=', s + '==', ` ${s}`, `${s.slice(0, 40)}\n${s.slice(40)}`, s.replace(/-/g, '+').replace(/_/g, '/'), `${s}!`];
      const repeats = [];
      for (let i = 0; i < 5000; i++) {
        repeats.push(att);
        repeats.push({ type: 'attestation', attestation: { ...att.attestation, sig: respelled[i % respelled.length] } });
        repeats.push({ type: 'checkpoint', checkpoint: { ...cp, sig: forgedSig() } });      // held: same position, same root
        repeats.push({ type: 'checkpoint', checkpoint: { ...fork, sig: forgedSig() } });    // the conflict already refused
        repeats.push({ type: 'witness', witness: { ...wit, sig: forgedSig() } });            // held
        repeats.push({ type: 'witness', witness: { ...witFork, sig: forgedSig() } });        // the conflict already refused
        repeats.push({ type: 'witness', witness: { ...waiting, sig: forgedSig() } });        // waiting
        repeats.push({ type: 'checkpoint', checkpoint: { ...cp, upto_seq: 9, sig: undefined } });   // unsigned
        repeats.push({ type: 'witness', witness: { ...wit, upto_seq: 9, sig: '' } });               // unsigned
        repeats.push({ type: 'attestation', attestation: { ...att.attestation, by: 'nobody', sig: forgedSig() } }); // no key held
      }
      const reasons = new Set();
      for (const f of repeats) { const r = ingest(node, 'p', f); assert.strictEqual(r.ok, false); reasons.add(r.reason); }
      assert.deepStrictEqual([...reasons].sort(), ['duplicate', 'malformed', 'unknown-attester-key']);
      assert.strictEqual(spent(), before, `50,000 repeats spent nothing (${spent() - before})`);
      assert.strictEqual(node._attestations.size(), 1, 'and a re-spelled signature is not a second attestation');
      assert.strictEqual(ingest(node, 'p', attestation(A, 2)).ok, true, 'a new statement is still taken');
    });
  });

  it('a checkpoint older than every position held is dropped before it', () => {
    withNode(1, ({ node, keys: [A] }) => {
      for (let n = 1; n <= 32; n++) ingest(node, 'p', { type: 'checkpoint', checkpoint: signed({ type: 'checkpoint', by: A.id, roster: ROOM, upto_seq: 100 + n, root: `r${n}`, at: n }, A.priv, signCheckpoint) });
      const spent = node._gossipBurst - node._gossipBuckets.get('p').tokens;
      for (let i = 0; i < 1000; i++) {
        const r = ingest(node, 'p', { type: 'checkpoint', checkpoint: { type: 'checkpoint', by: A.id, roster: ROOM, upto_seq: i % 100, root: 'old', at: 1, sig: forgedSig() } });
        assert.strictEqual(r.reason, 'stale');
      }
      assert.strictEqual(node._gossipBurst - node._gossipBuckets.get('p').tokens, spent);
    });
  });
});

describe('gossip budget — forged frames cannot starve genuine ones', () => {
  it("a flood spends only its sender's budget; the same statement from an honest peer is taken; the flooder is heard again once it stops", () => {
    withNode(32, ({ node, keys, clock }) => {
      let seq = 0;
      const genuine = () => attestation(keys[0], ++seq);
      const t0 = clock.t;
      let honestRefused = 0;
      let floodVerified = 0;
      // 10 s of forgeries at 4,000 a second, all naming attester 0, while an honest peer relays
      // attester 0's genuine attestations at 640 a second.
      for (let ms = 0; ms < 10000; ms++) {
        clock.t = t0 + ms;
        for (let j = 0; j < 4; j++) if (ingest(node, 'flooder', forgedAttestation(keys[0])).reason !== 'over-budget') floodVerified++;
        if (ms % 25 < 16) { const r = ingest(node, 'honest', genuine()); if (!r.ok) honestRefused++; }
      }
      assert.strictEqual(honestRefused, 0, 'every genuine statement from the honest peer was taken');
      assert.ok(floodVerified <= 10000 + 10 * 2000 + 1, `what the flooder could send is bounded: ${floodVerified}`);
      // During the flood the flooder's own genuine relay is dropped, unverified, and marks nothing...
      const g = genuine();
      assert.strictEqual(ingest(node, 'flooder', g).reason, 'over-budget');
      assert.strictEqual(node._attestations.has(g.attestation.sig), false);
      // ...so the same statement from the honest peer is taken.
      assert.strictEqual(ingest(node, 'honest', g).ok, true);
      // Not for ever: once the flood stops, the bucket refills and the flooder's genuine frames pass.
      clock.t += 1000;
      for (let i = 0; i < 100; i++) assert.strictEqual(ingest(node, 'flooder', genuine()).ok, true, `genuine ${i} after the flood`);
    });
  });
});

describe('gossip budget — what it reports, and what it keeps', () => {
  it('a drop is said with the peer named, at most once per 10 s, and every drop is counted', () => {
    withNode(2, ({ node, keys, clock, metrics }) => {
      node._peers.set('flooder', { peerId: 'flooder', name: 'the-flooder', transport: { send() {} } });
      const logs = [];
      node._log = (m) => logs.push(m);
      let dropped = 0;
      const t0 = clock.t;
      for (let i = 0; i < 40000; i++) {
        clock.t = t0 + Math.floor(i / 8);   // 8,000 a second for 5 s
        const f = i % 2 ? forgedAttestation(keys[i % 2]) : { type: 'witness', witness: { type: 'witness', attester: 'x', roster: ROOM, upto_seq: i, root: 'r', by: keys[0].id, role: 'participant', at: 1, sig: forgedSig() } };
        if (ingest(node, 'flooder', f).reason === 'over-budget') dropped++;
      }
      assert.ok(dropped > 10000, `${dropped} dropped`);
      assert.strictEqual(metrics.length, 1, 'said once in the window, at the first drop');
      const report = node._dropReports.get('gossip-over-budget|flooder');
      assert.ok(report.timer, 'the rest of the window is said when it closes');
      node._sayDrops(report);   // what the timer does
      assert.strictEqual(metrics.length, 2);
      assert.strictEqual(metrics.reduce((s, m) => s + m.dropped, 0), dropped, 'every drop is counted');
      assert.strictEqual(node.metrics().gossipOverBudget, dropped, 'and kept in the node metrics');
      for (const m of metrics) {
        assert.strictEqual(m.fromPeerId, 'flooder');
        assert.strictEqual(m.from, 'the-flooder');
      }
      assert.deepStrictEqual(Object.keys(metrics[1].frames).sort(), ['attestation', 'witness']);
      assert.deepStrictEqual(metrics[1].authors.sort(), [keys[0].id, keys[1].id].sort(), 'whose statements were dropped');
      assert.strictEqual(logs.filter((l) => l.includes('over its budget')).length, 2);
    });
  });

  it('keeps at most 4,096 buckets, evicting the least recently active, without scanning the map', () => {
    withNode(1, ({ node, keys: [A] }) => {
      let iterations = 0;   // iterator steps taken over the bucket map
      const counted = (it) => ({ next() { iterations++; return it.next(); }, [Symbol.iterator]() { return this; } });
      class Counted extends Map {
        entries() { return counted(super.entries()); }
        keys() { return counted(super.keys()); }
        values() { return counted(super.values()); }
        forEach(fn, self) { for (const [k, v] of this) fn.call(self, v, k, this); }
        [Symbol.iterator]() { return counted(super.entries()); }
      }
      node._gossipBuckets = new Counted();
      const frame = () => forgedAttestation(A);
      for (let i = 0; i < 50; i++) ingest(node, 'busy', frame());
      for (let p = 0; p < 6000; p++) {
        ingest(node, `peer-${p}`, frame());
        if (p % 1000 === 0) ingest(node, 'busy', frame());   // still active
      }
      assert.strictEqual(node._gossipBuckets.size, 4096);
      assert.ok(node._gossipBuckets.has('busy'), 'an active peer keeps its bucket');
      assert.strictEqual(node._gossipBurst - node._gossipBuckets.get('busy').tokens, 50 + 6, 'and what it spent');
      assert.ok(!node._gossipBuckets.has('peer-0'), 'the least recently active went');
      assert.strictEqual(iterations, 6001 - 4096, 'one step at the head per eviction, nothing else');
    });
  });
});

describe('gossip budget — the frame handler', () => {
  it('says a dropped attestation once a minute per peer and reason, with a count, not once per frame', () => {
    withNode(1, ({ node, keys: [A], clock }) => {
      const logs = [];
      node._log = (m) => logs.push(m);
      const realNow = Date.now;
      let now = realNow();
      Date.now = () => now;
      try {
        // Naming a signer this node holds no key for: dropped before any budget, so free to send.
        for (let i = 0; i < 5000; i++) node._frameHandler._handleAttestation('p', 'peer-p', { attestation: { ...forgedAttestation(A).attestation, by: `nobody-${i}` } });
        assert.strictEqual(logs.length, 1, logs.slice(0, 3).join('\n'));
        now += 61_000;
        node._frameHandler._handleAttestation('p', 'peer-p', { attestation: { ...forgedAttestation(A).attestation, by: 'nobody' } });
        assert.strictEqual(logs.length, 2);
        assert.match(logs[1], /and 4999 more since it was last said/);
        // A drop past the budget, or for a signature not spelled canonically, is said by the node, not here.
        node._gossipBuckets.set('q', { tokens: 0, at: clock.t });
        node._frameHandler._handleAttestation('q', 'peer-q', forgedAttestation(A));
        node._frameHandler._handleAttestation('q', 'peer-q', { attestation: { ...forgedAttestation(A).attestation, sig: `${forgedSig()}=` } });
        assert.strictEqual(logs.filter((l) => l.startsWith('Attestation from peer-q')).length, 0, logs.join('\n'));
        for (const r of node._dropReports.values()) clearTimeout(r.timer);
      } finally { Date.now = realNow; }
    });
  });
});

// 0.14.0 review follow-up: base64url decoding ignores padding, whitespace and stray characters, so one
// signature can be spelled many ways that all verify. The chain hash and the Merkle root are computed
// over the signature as written, so a re-spelling stored first made the attester's chain look broken.
describe('signature spelling', () => {
  it('a re-spelled signature arriving first is refused, unverified and free; the canonical one is then stored and the chain verifies', () => {
    withNode(1, ({ node, keys: [A] }) => {
      const reported = [];
      node.on('metric', (m) => { if (m.type === 'signature-not-canonical') reported.push(m); });
      const a1 = signed({ of: 'cmb-s1', by: A.id, at: 1, roster: ROOM, method: 'heuristic', verdict: 'aligned', categories: {}, role: 'participant', seq: 1, prev: 'genesis' }, A.priv, signAttestation);
      const a2 = signed({ of: 'cmb-s2', by: A.id, at: 2, roster: ROOM, method: 'heuristic', verdict: 'aligned', categories: {}, role: 'participant', seq: 2, prev: chainHash(a1.sig) }, A.priv, signAttestation);
      const s = a1.sig;
      const respelled = [`${s}=`, `${s}==`, ` ${s}`, `${s.slice(0, 40)}\n${s.slice(40)}`, s.replace(/-/g, '+').replace(/_/g, '/'), `${s}!`];
      assert.ok(respelled.every((x) => x !== s && Buffer.from(x, 'base64url').equals(Buffer.from(s, 'base64url'))), 'every one is the same signature');
      for (const sig of respelled) {
        assert.strictEqual(node._ingestAttestation({ ...a1, sig }, 'm', 'm').reason, 'non-canonical-signature');
      }
      assert.strictEqual(node._gossipBuckets.has('m'), false, 'nothing was spent: no signature was checked');
      assert.strictEqual(node._attestations.has(s), false, 'nothing was stored');
      assert.strictEqual(node._ingestAttestation(a1, 'p', 'p').ok, true, 'the canonical spelling is stored');
      assert.strictEqual(node._ingestAttestation(a2, 'p', 'p').ok, true);
      assert.deepStrictEqual(node._attestations.verifyChain(A.id), { ok: true, gaps: [], breaks: [] }, 'and the chain verifies');
      assert.strictEqual(node._attestations.chainOf(A.id)[0].sig, s);
      // Counted, and said once per 10 s with the peer named.
      assert.strictEqual(node.metrics().signaturesNotCanonical, respelled.length);
      assert.strictEqual(reported.length, 1);
      node._sayDrops(node._dropReports.get('signature-not-canonical|m'));
      assert.deepStrictEqual([reported.length, reported[0].fromPeerId, reported[0].dropped + reported[1].dropped], [2, 'm', respelled.length]);
    });
  });

  it('a checkpoint or witness not spelled canonically is refused too, before any signature check', () => {
    withNode(2, ({ node, keys: [A, W] }) => {
      const cp = signed({ type: 'checkpoint', by: A.id, roster: ROOM, upto_seq: 8, root: 'r8', at: 1 }, A.priv, signCheckpoint);
      const w = signed({ type: 'witness', attester: A.id, roster: ROOM, upto_seq: 8, root: 'r8', by: W.id, role: 'participant', at: 1 }, W.priv, signWitness);
      assert.strictEqual(node._ingestCheckpoint({ ...cp, sig: `${cp.sig}=` }, 'm').reason, 'non-canonical-signature');
      assert.strictEqual(node._ingestWitness({ ...w, sig: ` ${w.sig}` }, 'm').reason, 'non-canonical-signature');
      assert.strictEqual(node._gossipBuckets.has('m'), false);
      assert.strictEqual(node._ingestCheckpoint(cp, 'p').ok, true);
      assert.strictEqual(node._ingestWitness(w, 'p').ok, true);
      assert.strictEqual(node._attestations.checkpointAt(A.id, 8).sig, cp.sig);
      assert.strictEqual(node._attestations.witnessAt(A.id, 8, W.id).sig, w.sig);
    });
  });

  it("this node's own signatures are canonical, and one that were not would be neither recorded nor gossiped", () => {
    withNode(1, ({ node, keys: [A] }) => {
      const sent = [];
      node._gossipToRoster = (f) => sent.push(f);
      const verdicts = { focus: 'admit', issue: 'admit', intent: 'admit', motivation: 'admit', commitment: 'admit', perspective: 'admit', mood: 'admit' };
      for (let i = 0; i < 200; i++) assert.ok(node._buildAdmissionAttestation(`cmb-own-${i}`, 'aligned', verdicts, 'heuristic'));
      node._ingestCheckpoint(signed({ type: 'checkpoint', by: A.id, roster: ROOM, upto_seq: 8, root: 'r8', at: 1 }, A.priv, signCheckpoint), 'p');
      const own = sent.map((f) => f.attestation || f.checkpoint || f.witness).filter((x) => (x.by === node.nodeId));
      assert.deepStrictEqual([...new Set(own.map((x) => x.type || 'attestation'))].sort(), ['attestation', 'checkpoint', 'witness']);
      assert.ok(own.every((x) => isCanonicalSig(x.sig)), 'every signature this node made is canonical');
      // A signer that wrote a short signature: refused at home, not only by peers.
      const realSign = crypto.sign;
      const seq = node._attestSeq;
      const before = sent.length;
      const cps = node._attestations.checkpointsOf(node.nodeId).length;
      const cp16 = signed({ type: 'checkpoint', by: A.id, roster: ROOM, upto_seq: 16, root: 'r16', at: 2 }, A.priv, signCheckpoint);
      crypto.sign = (...a) => realSign(...a).subarray(0, 63);
      try {
        assert.strictEqual(node._buildAdmissionAttestation('cmb-short', 'aligned', verdicts, 'heuristic'), null);
        assert.strictEqual(node._emitCheckpoint(), null);
        node._attestations.recordCheckpoint(cp16);   // held, so this node would witness it
        node._witnessCheckpoint(cp16);
      } finally { crypto.sign = realSign; }
      assert.strictEqual(node._attestSeq, seq, 'the chain did not advance');
      assert.strictEqual(sent.length, before, 'nothing was gossiped');
      assert.strictEqual(node._attestations.byCmb('cmb-short').length, 0, 'nothing was recorded');
      assert.strictEqual(node._attestations.checkpointsOf(node.nodeId).length, cps, 'no checkpoint of its own was recorded');
      assert.strictEqual(node._attestations.witnessAt(A.id, 16, node.nodeId), null, 'nor a witness');
    });
  });
});
