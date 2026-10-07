'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * 0.14.0, part A2 review of the gossip budget:
 *
 * - F1: role grants were outside the budget and were deduplicated by the signature as written, so one
 *   captured grant re-spelled (padding, whitespace, a +/ swap) was stored, appended and relayed again
 *   for every spelling, by every node. They now take the same order as every other signed statement
 *   (malformed, spelling, repeat by the signature's bytes, unknown signer, then the budget), and the
 *   store bounds what it keeps, and so what it relays.
 * - F2: the budget was keyed by the peer id a sender declares and a new id started with the whole
 *   burst, so minting ids bought 10,000 signature checks each. It is now kept per lane (the
 *   connection a frame came by; over the relay, the relay connection and the sender id it names), a
 *   new lane starts with 100, and every lane draws on one ceiling.
 * - F4: a throwing log or metric sink took a frame's handling, or the node's shutdown, with it.
 * - F5: an over-long signature was decoded and hashed by the repeat check before it was refused.
 * - F6: a further conflicting root for a position already conflicted was verified at the peer's
 *   budget, where the attester's rate was meant to bound it.
 * - Its suggestions: the door's refusal was logged once per frame; an ESIGN from the synthesis loop
 *   was blamed on the delegate; the checkpoint-over-rate line named the attester only.
 *
 * Deterministic: the budget's clock is injected (node._gossipClock).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { WebSocketServer } = require('ws');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const { RelayConnection } = require('../lib/relay');
const { RoleGrantStore } = require('../lib/role-grant-store');
const { signAttestation, signCheckpoint, signWitness, signGrant, verifyGrant } = require('../lib/core');
const { admitAs } = require('./_core-secure');

const ROOM = 'g';
const kp = (id) => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', { publicKeyEncoding: { type: 'spki', format: 'der' }, privateKeyEncoding: { type: 'pkcs8', format: 'der' } });
  // nodeIds are canonical lowercase at every door, a grant's included (security review B).
  return { id: id.toLowerCase(), pub: publicKey.slice(-32).toString('base64url'), priv: privateKey.slice(-32).toString('base64url') };
};
const signed = (fields, priv, sign) => { const o = { ...fields }; sign(o, priv); return o; };
const forgedSig = () => crypto.randomBytes(64).toString('base64url');
let n = 0;
const forged = (k) => ({ of: `cmb-${++n}`, by: k.id, at: 1, roster: ROOM, verdict: 'aligned', categories: {}, seq: n, prev: 'p', sig: forgedSig(), sigAlg: 'ed25519' });
// The wire form (sym-attest-v1): every field what the extension says, only the signature forged.
const hex = () => crypto.randomBytes(32).toString('hex');
const CATS7 = { focus: 'admit', issue: 'admit', intent: 'guard', motivation: 'admit', commitment: 'silent', perspective: 'admit', mood: 'admit' };
const wireForged = (k, extra = {}) => ({ of: `cmb-${hex()}`, assertionId: `asrt-${hex()}`, by: k.id, at: 1, room: ROOM, method: 'heuristic', verdict: 'aligned', categories: CATS7, role: 'participant', seq: ++n + 1, prev: hex(), sigAlg: 'ed25519', sig: forgedSig(), ...extra });
// Since 0.14 every role-grant names the key it confers authority on (design D3).
const SOME_KEY = Buffer.alloc(32, 9).toString('base64url');
const forgedGrant = (by, grantee) => ({ type: 'role-grant', grantee, granteeKey: SOME_KEY, role: 'validator', grantedBy: by, grantedAt: ++n, sig: forgedSig(), sigAlg: 'ed25519' });
const respell = (s) => [`${s}=`, `${s}==`, ` ${s}`, `${s.slice(0, 40)}\n${s.slice(40)}`, s.replace(/-/g, '+').replace(/_/g, '/'), `${s}!`].filter((x) => x !== s);

/** A node (not started) on an injected clock, with what it gossips captured. */
function withNode(opts, fn) {
  const name = `lanes-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: ROOM, ...opts });
  try {
    const sent = [];
    node._gossipToRoster = (f) => sent.push(f);
    const clock = { t: Date.now() + 1000 };
    node._gossipClock = () => clock.t;
    const metrics = [];
    node.on('metric', (m) => metrics.push(m));
    return fn({ node, sent, clock, metrics });
  } finally {
    for (const r of node._dropReports.values()) clearTimeout(r.timer);
    node._releaseIdentityLock?.();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  }
}

describe('role grants are gossip under the budget (F1)', () => {
  it('a captured grant re-spelled is refused or a repeat: never stored, written or relayed again, and nothing is spent', () => {
    const A = kp('anchor-A');
    withNode({ anchor: { nodeId: A.id, publicKey: A.pub } }, ({ node, sent }) => {
      const g = signGrant({ type: 'role-grant', grantee: 'node-v', granteeKey: SOME_KEY, role: 'validator', grantedBy: A.id, grantedAt: 1 }, A.priv);
      assert.strictEqual(node._ingestRoleGrant(g, 'p').ok, true);
      assert.strictEqual(sent.length, 1, 'relayed once');
      const tokens = node._gossipBuckets.get('p').tokens;
      assert.strictEqual(node._gossipNewLane - tokens, 1, 'a new grant spent one');
      const spellings = respell(g.sig);
      assert.ok(spellings.length >= 5 && spellings.every((sig) => verifyGrant({ ...g, sig }, A.pub).valid), 'every spelling verifies: that was the amplification');
      const reasons = new Set();
      for (let i = 0; i < 6000; i++) {
        const r = node._ingestRoleGrant({ ...g, sig: spellings[i % spellings.length] }, 'p');
        assert.strictEqual(r.ok, false);
        reasons.add(r.reason);
      }
      for (let i = 0; i < 1000; i++) reasons.add(node._ingestRoleGrant({ ...g }, 'q').reason);
      assert.deepStrictEqual([...reasons].sort(), ['duplicate', 'non-canonical-signature']);
      assert.strictEqual(node._roleGrants.size(), 1, 'one grant held');
      assert.strictEqual(node._roleGrants.grantsFor('node-v').length, 1);
      const file = path.join(node._dir, 'role-grants', 'role-grants.jsonl');
      assert.strictEqual(fs.readFileSync(file, 'utf8').trim().split('\n').length, 1, 'one line written');
      assert.strictEqual(sent.length, 1, 'and nothing relayed again');
      assert.strictEqual(node._gossipBuckets.get('p').tokens, tokens, 'nothing spent');
      assert.strictEqual(node._gossipBuckets.has('q'), false);
      assert.strictEqual(node.metrics().signaturesNotCanonical, 6000, 'the refusals are counted');
    });
  });

  it("new grants spend the lane's budget before their signatures are checked, and only a grant kept is relayed", () => {
    const A = kp('anchor-A');
    withNode({ anchor: { nodeId: A.id, publicKey: A.pub } }, ({ node, sent }) => {
      const P = kp('grantor-P');
      const Q = kp('grantor-Q');
      node._roster.bind(P.id, P.pub, 'proven');
      node._roster.bind(Q.id, Q.pub, 'proven');
      // Since 0.13.17 only a record rooted at the anchor is kept, or checked at all: P and Q are
      // validators by the anchor's grant, so their grants are rooted and reach the signature check.
      for (const G of [P, Q]) {
        assert.strictEqual(node._roleGrants.record(signGrant({ type: 'role-grant', grantee: G.id, granteeKey: G.pub, role: 'validator', grantedBy: A.id, grantedAt: 0 }, A.priv)).stored, true);
      }
      const reasons = {};
      for (let i = 0; i < 300; i++) {
        const r = node._ingestRoleGrant(forgedGrant(P.id, `x-${i}`), 'p');
        reasons[r.reason] = (reasons[r.reason] || 0) + 1;
      }
      assert.deepStrictEqual(reasons, { 'bad-signature': 100, 'over-budget': 200 }, 'a new peer checks 100, then refuses unverified');
      // A grantor whose key is not held costs nothing.
      for (let i = 0; i < 100; i++) assert.strictEqual(node._ingestRoleGrant(forgedGrant('nobody', 'x'), 'p5').reason, 'unknown-grantor-key');
      assert.strictEqual(node._gossipBuckets.has('p5'), false);
      assert.strictEqual(sent.length, 0, 'nothing refused was relayed');
      // Genuine grants from one grantor to one grantee: kept up to the pair's bound, and only those relayed.
      let kept = 0;
      for (let i = 0; i < 70; i++) {
        const r = node._ingestRoleGrant(signGrant({ type: 'role-grant', grantee: 'node-x', granteeKey: SOME_KEY, role: 'validator', grantedBy: P.id, grantedAt: i }, P.priv), 'p2');
        if (r.ok) kept++; else assert.strictEqual(r.reason, 'pair-full');
      }
      assert.strictEqual(kept, 16, 'the pair bound (16 since the security review: role-resolve-cost)');
      assert.strictEqual(sent.length, 16);
      // Another grantor's grant to the same grantee is not kept out by the first one's.
      assert.strictEqual(node._ingestRoleGrant(signGrant({ type: 'role-grant', grantee: 'node-x', granteeKey: SOME_KEY, role: 'validator', grantedBy: Q.id, grantedAt: 1 }, Q.priv), 'p3').ok, true);
    });
  });

  it("the store dedups by the signature's bytes, keeps the canonical spelling, and bounds what it keeps without evicting", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'grants-'));
    try {
      const A = kp('A');
      const P = kp('P');
      const Q = kp('Q');
      const keys = new Map([[P.id, P.pub], [Q.id, Q.pub]]);
      // maxGrants counts the anchor's two grants that root P and Q (0.13.17: only a rooted record is kept).
      const opts = { anchor: { nodeId: A.id, publicKey: A.pub }, keys, dir, maxPerGrantor: 3, maxPerPair: 2, maxGrants: 7 };
      const st = new RoleGrantStore(opts);
      const keyOf = (grantee) => ({ [P.id]: P.pub, [Q.id]: Q.pub })[grantee] || SOME_KEY;
      const grant = (by, grantee, at) => signGrant({ type: 'role-grant', grantee, granteeKey: keyOf(grantee), role: 'validator', grantedBy: by.id, grantedAt: at }, by.priv);
      const g = grant(A, 'v', 1);
      assert.strictEqual(st.record({ ...g, sig: `${g.sig}=` }).stored, true, 'a direct caller may hand over another spelling');
      assert.strictEqual(st.grantsFor('v')[0].sig, g.sig, 'it is kept as its signer wrote it');
      for (const sig of [g.sig, ...respell(g.sig)]) assert.strictEqual(st.record({ ...g, sig }).reason, 'duplicate');
      assert.strictEqual(st.has(` ${g.sig}`), true);
      assert.strictEqual(st.size(), 1);
      for (const G of [P, Q]) assert.strictEqual(st.record(grant(A, G.id, 0)).stored, true);

      const r = (by, grantee, at) => st.record(grant(by, grantee, at)).reason ?? 'stored';
      assert.deepStrictEqual([r(P, 'x', 1), r(P, 'x', 2), r(P, 'x', 3)], ['stored', 'stored', 'pair-full']);
      assert.deepStrictEqual([r(P, 'y', 4), r(P, 'z', 5)], ['stored', 'grantor-full']);
      assert.strictEqual(st.record(forgedGrant(P.id, 'w')).reason, 'grantor-full', 'refused before its signature is checked');
      assert.deepStrictEqual([r(Q, 'x', 6), r(Q, 'y', 7)], ['stored', 'store-full']);
      assert.strictEqual(st.size(), 7);
      assert.deepStrictEqual([r(A, 'x', 8), r(A, 'z', 9)], ['stored', 'stored'], "the anchor's own are never refused");
      assert.deepStrictEqual(st.grantsFor('x').map((x) => x.grantedAt), [1, 2, 6, 8], 'nothing kept was evicted');
      const again = new RoleGrantStore(opts);
      assert.strictEqual(again.size(), 9, 'and a restart reads back what was kept');
      assert.strictEqual(again.resolveRole('x', 100), 'validator');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
});

describe('the budget is kept per PROVEN peer (F2; Core Secure design D1)', () => {
  // Until 0.14 the budget was kept per connection lane, because the id a sender declared was free to
  // claim. A peer is now a confirmed session's proven nodeId, so the per-connection lanes — an
  // identity workaround — are gone and the budget is the proven peer's. Minting an identity costs a
  // completed handshake, and buys a hundred checks, not a burst; the ceiling bounds all of them.
  it('a peer seen for the first time has 100 checks and earns the rest at the rate, up to the burst', () => {
    withNode({}, ({ node, clock }) => {
      const A = kp('att-A');
      node._roster.bind(A.id, A.pub, 'proven');
      const send = (count, peer) => {
        let checked = 0;
        for (let i = 0; i < count; i++) if (node._ingestAttestation(forged(A), peer, peer).reason !== 'over-budget') checked++;
        return checked;
      };
      assert.strictEqual(send(300, 'peer-1'), 100, 'a new peer: 100');
      clock.t += 50;
      assert.strictEqual(send(300, 'peer-1'), 100, '2,000 a second: 100 in 50 ms');
      clock.t += 60_000;
      assert.strictEqual(send(12_000, 'peer-1'), 10_000, 'and at most the burst once it has earned it');
      assert.deepStrictEqual([...node._gossipBuckets.keys()], ['peer-1'], 'keyed by the proven peer');
    });
  });

  it('a peer\'s frames over any of its sessions spend one budget; checkpoints, witnesses and grants too', () => {
    withNode({}, ({ node }) => {
      const A = kp('att-A');
      node._roster.bind(A.id, A.pub, 'proven');
      const lan = admitAs(node, { nodeId: 'peer-two-paths' });
      const relay = { ...lan, kind: 'relay', sessionId: 'f'.repeat(32), has: lan.has };
      for (let i = 0; i < 60; i++) node._frameHandler.handle(i % 2 ? lan : relay, { type: 'sym-attest-attestation', attestation: wireForged(A) });
      for (let i = 0; i < 10; i++) {
        node._frameHandler.handle(lan, { type: 'sym-attest-checkpoint', checkpoint: { by: A.id, room: ROOM, uptoSeq: i + 1, root: hex(), at: 1, sigAlg: 'ed25519', sig: forgedSig() } });
        node._frameHandler.handle(relay, { type: 'sym-attest-witness', witness: { attester: A.id, room: ROOM, uptoSeq: i + 1, root: hex(), by: A.id, role: 'participant', at: 1, sigAlg: 'ed25519', sig: forgedSig() } });
        node._frameHandler.handle(lan, { type: 'role-grant', grant: forgedGrant(A.id, `x-${i}`) });
      }
      assert.deepStrictEqual([...node._gossipBuckets.keys()], ['peer-two-paths']);
      // A role grant from a grantor no chain reaches costs nothing (0.13.17, 0.14 D3).
      assert.strictEqual(node._gossipNewLane - node._gossipBuckets.get('peer-two-paths').tokens, 80, 'each spent one of the one budget');
    });
  });

  it('forgeries spend only their own peer\'s lane, never the shared ceiling, and a forgery in a session\'s own name ends it (security review D, p7-ceiling; re-review N1)', () => {
    withNode({}, ({ node, metrics }) => {
      const A = kp('att-A');
      node._roster.bind(A.id, A.pub, 'proven');
      let badSig = 0;
      const ingest = (peer) => { if (node._ingestAttestation(forged(A), peer, peer).reason === 'bad-signature') badSig++; };
      // 300 peers, 101 forgeries each: each peer's own 100, and the ceiling untouched.
      for (let i = 0; i < 300; i++) for (let j = 0; j < 101; j++) ingest(`id-${i}`);
      assert.strictEqual(badSig, 300 * 100, 'each peer checks its own 100');
      assert.strictEqual(node._gossipGlobal.tokens, node._gossipGlobalBurst, 'no forgery spent the shared ceiling');
      assert.strictEqual(metrics.filter((m) => m.type === 'gossip-over-ceiling').length, 0);
      // A relayed statement that fails here is dropped, never charged to the relayer (0.14.0 re-review
      // N1): its binding for the signer may differ from this node's.
      const s = admitAs(node, { nodeId: 'relayer-1' });
      assert.strictEqual(node._ingestAttestation(forged(A), 'relayer-1', 'relayer-1', s).reason, 'bad-signature');
      assert.strictEqual(s.closed, false, 'a relayed statement that fails does not close the relayer\'s session');
      assert.strictEqual(node._penalised('relayer-1'), false);
      assert.ok(metrics.some((m) => m.type === 'relayed-signature-unverified' && m.peer === 'relayer-1' && m.author === A.id));
      // A statement in the session's OWN name that its proven key did not sign is attributable: the
      // session ends and its id waits out a penalty.
      const own = admitAs(node, { nodeId: A.id, publicKey: A.pub });
      assert.strictEqual(node._ingestAttestation(forged(A), A.id, A.id, own).reason, 'bad-signature');
      assert.strictEqual(own.closed, true, 'a forged signature in its own name closes the session');
      assert.strictEqual(node._penalised(A.id), true, 'and its nodeId is not admitted again for a while');
      assert.ok(metrics.some((m) => m.type === 'forged-signature' && m.peer === A.id));
    });
  });

  it('the ceiling bounds VERIFIED statements, spent after the signature checks out', () => {
    withNode({ gossipBudget: { globalBurst: 5, globalPerSecond: 1 } }, ({ node, metrics }) => {
      const A = kp('att-A');
      node._roster.bind(A.id, A.pub, 'proven');
      const real = (i) => signed({ of: `cmb-${crypto.randomBytes(32).toString('hex')}`, by: A.id, at: 1, roster: ROOM, verdict: 'aligned', categories: {}, seq: 1000 + i, prev: 'p' }, A.priv, signAttestation);
      const reasons = {};
      for (let i = 0; i < 8; i++) { const r = node._ingestAttestation(real(i), `peer-${i}`, `peer-${i}`); reasons[r.reason || 'stored'] = (reasons[r.reason || 'stored'] || 0) + 1; }
      assert.strictEqual(reasons['over-ceiling'], 3, 'past the ceiling, verified statements are dropped unstored');
      assert.ok(metrics.some((m) => m.type === 'gossip-over-ceiling'));
    });
  });

  it('the frame handler\'s drop line is said once a minute per peer and reason', () => {
    withNode({}, ({ node }) => {
      const A = kp('att-A');
      node._roster.bind(A.id, A.pub, 'proven');
      const logs = [];
      node._log = (m) => logs.push(m);
      const p = admitAs(node, { nodeId: 'peer-flooding' });
      for (let i = 0; i < 50; i++) node._frameHandler.handle(p, { type: 'sym-attest-attestation', attestation: wireForged(A) });
      for (let i = 0; i < 50; i++) node._frameHandler.handle(p, { type: 'sym-attest-attestation', attestation: wireForged(A, { by: `nobody-${i}` }) });
      assert.strictEqual(logs.filter((l) => /Attestation from .* dropped \(bad-signature\)/.test(l)).length, 1);
      assert.strictEqual(logs.filter((l) => /dropped \(unknown-attester-key\)/.test(l)).length, 1);
    });
  });
});

describe('drop reporting cannot break gossip or shutdown (F4)', () => {
  it('a throwing metric listener neither breaks ingest nor loses or repeats a count', () => {
    withNode({}, ({ node }) => {
      const A = kp('att-A');
      node._roster.bind(A.id, A.pub, 'proven');
      const said = [];
      node.on('metric', (m) => { if (m.type === 'gossip-over-budget') said.push(m); });
      node.on('metric', () => { throw new Error('a bad sink'); });
      const reasons = {};
      for (let i = 0; i < 300; i++) {
        const r = node._ingestAttestation(forged(A), 'p', 'p');
        reasons[r.reason] = (reasons[r.reason] || 0) + 1;
      }
      assert.deepStrictEqual(reasons, { 'bad-signature': 100, 'over-budget': 200 });
      assert.strictEqual(said.length, 1, 'the first drop was said, and the sink threw');
      const report = node._dropReports.get('gossip-over-budget|p');
      node._sayDrops(report);
      node._sayDrops(report);
      assert.strictEqual(said.length, 2, 'the rest once, not again');
      assert.strictEqual(said.reduce((s, m) => s + m.dropped, 0), 200, 'every drop said once');
      assert.strictEqual(node.metrics().gossipOverBudget, 200);
    });
  });

  for (const how of ['a throwing metric listener', 'a report that throws']) {
    it(`stop() finishes with ${how}: the relay is closed and the identity lock released`, async () => {
      const name = `lanes-stop-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
      const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: ROOM });
      try {
        node._roster.bind('att', kp('att').pub, 'proven');
        const t = Date.now();
        node._gossipClock = () => t;
        node._gossipBuckets.set('q', { tokens: 0, at: t });
        node._ingestAttestation(forged({ id: 'att' }), 'q', 'q');   // said at once
        node._ingestAttestation(forged({ id: 'att' }), 'q', 'q');   // waits for the window to close
        assert.ok(node._dropReports.get('gossip-over-budget|q').dropped > 0, 'a drop waits to be said');
        if (how === 'a report that throws') node._sayDrops = () => { throw new Error('a bad report'); };
        else node.on('metric', () => { throw new Error('a bad sink'); });
        let destroyed = false;
        let released = false;
        const destroy = node._relay.destroy.bind(node._relay);
        node._relay.destroy = () => { destroyed = true; destroy(); };
        const release = node._releaseIdentityLock;
        node._releaseIdentityLock = () => { released = true; release?.(); };
        node._running = true;
        await node.stop();
        assert.deepStrictEqual([destroyed, released], [true, true]);
      } finally {
        for (const r of node._dropReports.values()) clearTimeout(r.timer);
        fs.rmSync(nodeDir(name), { recursive: true, force: true });
      }
    });
  }
});

describe('an over-long signature (F5)', () => {
  it('is malformed, refused before anything decodes or looks it up; a re-spelling is refused before the lookup too', () => {
    withNode({}, ({ node }) => {
      const A = kp('att-A');
      const W = kp('wit-W');
      node._roster.bind(A.id, A.pub, 'proven');
      node._roster.bind(W.id, W.pub, 'proven');
      let lookups = 0;
      const has = node._attestations.has.bind(node._attestations);
      node._attestations.has = (sig) => { lookups++; return has(sig); };
      let grantLookups = 0;
      const grantHas = node._roleGrants.has.bind(node._roleGrants);
      node._roleGrants.has = (sig) => { grantLookups++; return grantHas(sig); };
      const att = signed({ of: 'cmb-1', by: A.id, at: 1, roster: ROOM, method: 'heuristic', verdict: 'aligned', categories: {}, role: 'participant', seq: 1, prev: 'p' }, A.priv, signAttestation);
      const cp = signed({ type: 'checkpoint', by: A.id, roster: ROOM, upto_seq: 8, root: 'r8', at: 1 }, A.priv, signCheckpoint);
      const w = signed({ type: 'witness', attester: A.id, roster: ROOM, upto_seq: 8, root: 'r8', by: W.id, role: 'participant', at: 1 }, W.priv, signWitness);
      const g = signGrant({ type: 'role-grant', grantee: 'v', granteeKey: SOME_KEY, role: 'validator', grantedBy: A.id, grantedAt: 1 }, A.priv);
      const ingest = (sig) => [
        node._ingestAttestation({ ...att, sig }, 'p', 'p').reason,
        node._ingestCheckpoint({ ...cp, sig }, 'p').reason,
        node._ingestWitness({ ...w, sig }, 'p').reason,
        node._ingestRoleGrant({ ...g, sig }, 'p').reason,
      ];
      for (const sig of [`${att.sig}${'A'.repeat(900_000)}`, 'A'.repeat(129), '', undefined, 42]) assert.deepStrictEqual(ingest(sig), ['malformed', 'malformed', 'malformed', 'malformed']);
      assert.deepStrictEqual(ingest('A'.repeat(128)), Array(4).fill('non-canonical-signature'), '128 characters is not too long');
      assert.deepStrictEqual(ingest(`${att.sig}=`), Array(4).fill('non-canonical-signature'));
      assert.deepStrictEqual([lookups, grantLookups], [0, 0], 'none was looked up');
      assert.strictEqual(node._ingestAttestation(att, 'p', 'p').ok, true);
      assert.strictEqual(lookups, 1, 'a canonical one is');
    });
  });
});

describe('equivocation at one position (F6)', () => {
  it('a further root for a conflicted position is dropped before the budget and the signature; the first conflict is kept although the rate is spent', () => {
    withNode({ checkpointRate: { perSecond: 4, burst: 2 } }, ({ node, sent, metrics }) => {
      const A = kp('att-A');
      node._roster.bind(A.id, A.pub, 'proven');
      const cp = (seq, root) => signed({ type: 'checkpoint', by: A.id, roster: ROOM, upto_seq: seq, root, at: seq }, A.priv, signCheckpoint);
      const ingest = (c) => node._ingestCheckpoint(c, 'p');
      assert.deepStrictEqual([ingest(cp(8, 'r8')).ok, ingest(cp(16, 'r16')).ok, ingest(cp(24, 'r24')).reason], [true, true, 'over-rate'], "the attester's rate is spent");
      const relayed = sent.length;
      assert.strictEqual(ingest(cp(8, 'forked')).reason, 'conflict', 'a second root at a held position: the evidence');
      assert.strictEqual(node._attestations.conflictAt(A.id, 8).root, 'forked', 'kept although the rate is spent');
      assert.strictEqual(metrics.filter((m) => m.type === 'attestation-conflict').length, 1);
      const tokens = node._gossipBuckets.get('p').tokens;
      for (let i = 0; i < 2000; i++) {
        const third = i % 2 ? { ...cp(8, 'r8'), root: `fork-${i}`, sig: forgedSig() } : cp(8, `fork-${i}`);
        assert.strictEqual(ingest(third).reason, 'conflict');
      }
      assert.strictEqual(node._gossipBuckets.get('p').tokens, tokens, 'a third root spends nothing: no signature is checked');
      assert.strictEqual(node._attestations.conflictAt(A.id, 8).root, 'forked', 'and changes nothing');
      assert.strictEqual(sent.length, relayed, 'nor is relayed');
    });
  });
});

describe('part A2 review suggestions', () => {
  it("the door's refusal is said once a minute per peer and reason, with a count, not once per frame", () => {
    const { RoomOwnershipRegistry } = require('../lib/room-ownership');
    const { FrameHandler } = require('../lib/frame-handler');
    const GATED = 'x-review--team-02779b950c3d8d7378fd11d6';
    const owners = new RoomOwnershipRegistry();
    owners.pin(GATED, 'owner-node', 'ownerkey', 'config');
    const logged = [];
    const node = { _room: GATED, _roomOwners: owners, _log: (m) => logged.push(m), _peers: new Map(), emit() {} };
    node._roomDoor = (peerId) => SymNode.prototype._roomDoor.call(node, peerId);
    const fh = new FrameHandler(node);
    const sess = (id) => ({ nodeId: id, name: id, confirmed: true, has: () => true });
    const realNow = Date.now;
    let now = realNow();
    Date.now = () => now;
    try {
      const refused = () => logged.filter((l) => l.startsWith('Door refused'));
      const m = sess('m');
      for (let i = 0; i < 1000; i++) fh.handle(m, { type: 'cmb', cmb: {} });
      assert.strictEqual(refused().length, 1, 'a thousand frames from one unadmitted peer: one line');
      for (let i = 0; i < 500; i++) fh.handle(sess('mallory'), { type: 'cmb', cmb: {} });
      assert.strictEqual(refused().length, 2, 'another peer: one more');
      now += 61_000;
      fh.handle(m, { type: 'mood', mood: {} });
      assert.strictEqual(refused().length, 3);
      assert.match(refused()[2], /and 999 more since it was last said/);
    } finally { Date.now = realNow; }
  });

  it('an ESIGN from the synthesis loop is said as the node failing to sign, not as a delegate error', () => {
    withNode({}, ({ node }) => {
      const logs = [];
      node._log = (m) => logs.push(m);
      node._synthesisDelegate = () => ({ focus: 'a synthesis' });
      node._hasNewDomainData = true; // the synthesis is the remix path (§15.7): it needs new domain data
      node.remember = () => { const e = new Error('CMB signing failed: no key'); e.code = 'ESIGN'; throw e; };
      node._frameHandler._handleXMeshInsight('p', 'p', { anomaly: 0.1 });
      assert.ok(logs.includes('Synthesis not shared: this node cannot sign its records'), logs.join('\n'));
      assert.ok(!logs.some((l) => l.startsWith('Synthesis delegate error')));
      node._synthesisDelegate = () => { throw new Error('the delegate broke'); };
      node._frameHandler._handleXMeshInsight('p', 'p', { anomaly: 0.1 });
      assert.ok(!logs.includes('Synthesis delegate error: the delegate broke'), 'a second insight within 10 s is paced: no synthesis (security review)');
      node._frameHandler._lastSynthesisAt = 0;
      node._frameHandler._handleXMeshInsight('p', 'p', { anomaly: 0.1 });
      assert.ok(logs.includes('Synthesis delegate error: the delegate broke'), 'a delegate error is still said as one');
    });
  });

  it('the checkpoint-over-rate line names the peers that brought the checkpoints', () => {
    withNode({ checkpointRate: { perSecond: 4, burst: 1 } }, ({ node }) => {
      const logs = [];
      node._log = (m) => logs.push(m);
      const A = kp('att-A');
      node._roster.bind(A.id, A.pub, 'proven');
      const cp = (seq) => signed({ type: 'checkpoint', by: A.id, roster: ROOM, upto_seq: seq, root: `r${seq}`, at: seq }, A.priv, signCheckpoint);
      assert.strictEqual(node._ingestCheckpoint(cp(8), 'peer-one-xyz').ok, true);
      assert.strictEqual(node._ingestCheckpoint(cp(16), 'peer-two-xyz').reason, 'over-rate');
      assert.ok(logs.some((l) => /over their rate .* brought by peer-two/.test(l)), logs.join('\n'));
    });
  });
});
