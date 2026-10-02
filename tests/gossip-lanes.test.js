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

const ROOM = 'g';
const kp = (id) => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', { publicKeyEncoding: { type: 'spki', format: 'der' }, privateKeyEncoding: { type: 'pkcs8', format: 'der' } });
  return { id, pub: publicKey.slice(-32).toString('base64url'), priv: privateKey.slice(-32).toString('base64url') };
};
const signed = (fields, priv, sign) => { const o = { ...fields }; sign(o, priv); return o; };
const forgedSig = () => crypto.randomBytes(64).toString('base64url');
let n = 0;
const forged = (k) => ({ of: `cmb-${++n}`, by: k.id, at: 1, roster: ROOM, verdict: 'aligned', categories: {}, seq: n, prev: 'p', sig: forgedSig(), sigAlg: 'ed25519' });
const forgedGrant = (by, grantee) => ({ type: 'role-grant', grantee, role: 'validator', grantedBy: by, grantedAt: ++n, sig: forgedSig(), sigAlg: 'ed25519' });
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
      const g = signGrant({ type: 'role-grant', grantee: 'node-V', role: 'validator', grantedBy: A.id, grantedAt: 1 }, A.priv);
      assert.strictEqual(node._ingestRoleGrant(g, 'p', 'tcp:1').ok, true);
      assert.strictEqual(sent.length, 1, 'relayed once');
      const tokens = node._gossipBuckets.get('tcp:1').tokens;
      assert.strictEqual(node._gossipNewLane - tokens, 1, 'a new grant spent one');
      const spellings = respell(g.sig);
      assert.ok(spellings.length >= 5 && spellings.every((sig) => verifyGrant({ ...g, sig }, A.pub).valid), 'every spelling verifies: that was the amplification');
      const reasons = new Set();
      for (let i = 0; i < 6000; i++) {
        const r = node._ingestRoleGrant({ ...g, sig: spellings[i % spellings.length] }, 'p', 'tcp:1');
        assert.strictEqual(r.ok, false);
        reasons.add(r.reason);
      }
      for (let i = 0; i < 1000; i++) reasons.add(node._ingestRoleGrant({ ...g }, 'q', 'tcp:2').reason);
      assert.deepStrictEqual([...reasons].sort(), ['duplicate', 'non-canonical-signature']);
      assert.strictEqual(node._roleGrants.size(), 1, 'one grant held');
      assert.strictEqual(node._roleGrants.grantsFor('node-V').length, 1);
      const file = path.join(node._dir, 'role-grants', 'role-grants.jsonl');
      assert.strictEqual(fs.readFileSync(file, 'utf8').trim().split('\n').length, 1, 'one line written');
      assert.strictEqual(sent.length, 1, 'and nothing relayed again');
      assert.strictEqual(node._gossipBuckets.get('tcp:1').tokens, tokens, 'nothing spent');
      assert.strictEqual(node._gossipBuckets.has('tcp:2'), false);
      assert.strictEqual(node.metrics().signaturesNotCanonical, 6000, 'the refusals are counted');
    });
  });

  it("new grants spend the lane's budget before their signatures are checked, and only a grant kept is relayed", () => {
    withNode({}, ({ node, sent }) => {
      const P = kp('grantor-P');
      const Q = kp('grantor-Q');
      node._pinPeerKey(P.id, P.pub);
      node._pinPeerKey(Q.id, Q.pub);
      const reasons = {};
      for (let i = 0; i < 300; i++) {
        const r = node._ingestRoleGrant(forgedGrant(P.id, `x-${i}`), 'p', 'tcp:1');
        reasons[r.reason] = (reasons[r.reason] || 0) + 1;
      }
      assert.deepStrictEqual(reasons, { 'bad-signature': 100, 'over-budget': 200 }, 'a new lane checks 100, then refuses unverified');
      // A grantor whose key is not held costs nothing.
      for (let i = 0; i < 100; i++) assert.strictEqual(node._ingestRoleGrant(forgedGrant('nobody', 'x'), 'p', 'tcp:5').reason, 'unknown-grantor-key');
      assert.strictEqual(node._gossipBuckets.has('tcp:5'), false);
      assert.strictEqual(sent.length, 0, 'nothing refused was relayed');
      // Genuine grants from one grantor to one grantee: kept up to the pair's bound, and only those relayed.
      let kept = 0;
      for (let i = 0; i < 70; i++) {
        const r = node._ingestRoleGrant(signGrant({ type: 'role-grant', grantee: 'node-X', role: 'validator', grantedBy: P.id, grantedAt: i }, P.priv), 'p', 'tcp:2');
        if (r.ok) kept++; else assert.strictEqual(r.reason, 'pair-full');
      }
      assert.strictEqual(kept, 64);
      assert.strictEqual(sent.length, 64);
      // Another grantor's grant to the same grantee is not kept out by the first one's.
      assert.strictEqual(node._ingestRoleGrant(signGrant({ type: 'role-grant', grantee: 'node-X', role: 'validator', grantedBy: Q.id, grantedAt: 1 }, Q.priv), 'p', 'tcp:3').ok, true);
    });
  });

  it("the store dedups by the signature's bytes, keeps the canonical spelling, and bounds what it keeps without evicting", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'grants-'));
    try {
      const A = kp('A');
      const P = kp('P');
      const Q = kp('Q');
      const keys = new Map([[P.id, P.pub], [Q.id, Q.pub]]);
      const opts = { anchor: { nodeId: A.id, publicKey: A.pub }, keys, dir, maxPerGrantor: 3, maxPerPair: 2, maxGrants: 5 };
      const st = new RoleGrantStore(opts);
      const grant = (by, grantee, at) => signGrant({ type: 'role-grant', grantee, role: 'validator', grantedBy: by.id, grantedAt: at }, by.priv);
      const g = grant(A, 'V', 1);
      assert.strictEqual(st.record({ ...g, sig: `${g.sig}=` }).stored, true, 'a direct caller may hand over another spelling');
      assert.strictEqual(st.grantsFor('V')[0].sig, g.sig, 'it is kept as its signer wrote it');
      for (const sig of [g.sig, ...respell(g.sig)]) assert.strictEqual(st.record({ ...g, sig }).reason, 'duplicate');
      assert.strictEqual(st.has(` ${g.sig}`), true);
      assert.strictEqual(st.size(), 1);

      const r = (by, grantee, at) => st.record(grant(by, grantee, at)).reason ?? 'stored';
      assert.deepStrictEqual([r(P, 'X', 1), r(P, 'X', 2), r(P, 'X', 3)], ['stored', 'stored', 'pair-full']);
      assert.deepStrictEqual([r(P, 'Y', 4), r(P, 'Z', 5)], ['stored', 'grantor-full']);
      assert.strictEqual(st.record(forgedGrant(P.id, 'W')).reason, 'grantor-full', 'refused before its signature is checked');
      assert.deepStrictEqual([r(Q, 'X', 6), r(Q, 'Y', 7)], ['stored', 'store-full']);
      assert.strictEqual(st.size(), 5);
      assert.deepStrictEqual([r(A, 'X', 8), r(A, 'Z', 9)], ['stored', 'stored'], "the anchor's own are never refused");
      assert.deepStrictEqual(st.grantsFor('X').map((x) => x.grantedAt), [1, 2, 6, 8], 'nothing kept was evicted');
      const again = new RoleGrantStore(opts);
      assert.strictEqual(again.size(), 7, 'and a restart reads back what was kept');
      assert.strictEqual(again.resolveRole('X', 100), 'validator');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
});

describe('the budget is kept per connection, not per declared id (F2)', () => {
  it('a lane seen for the first time has 100 checks and earns the rest at the rate, up to the burst', () => {
    withNode({}, ({ node, clock }) => {
      const A = kp('att-A');
      node._pinPeerKey(A.id, A.pub);
      const send = (count, lane) => {
        let checked = 0;
        for (let i = 0; i < count; i++) if (node._ingestAttestation(forged(A), 'p', 'p', lane).reason !== 'over-budget') checked++;
        return checked;
      };
      assert.strictEqual(send(300, 'tcp:1'), 100, 'a new lane: 100');
      clock.t += 50;
      assert.strictEqual(send(300, 'tcp:1'), 100, '2,000 a second: 100 in 50 ms');
      clock.t += 60_000;
      assert.strictEqual(send(12_000, 'tcp:1'), 10_000, 'and at most the burst once it has earned it');
    });
  });

  it('fresh ids on one connection share its lane', () => {
    withNode({}, ({ node }) => {
      const A = kp('att-A');
      node._pinPeerKey(A.id, A.pub);
      const lane = node._newLane('tcp');
      let rejected = 0;
      node.on('metric', (m) => { if (m.type === 'attestation-rejected') rejected++; });
      for (let i = 0; i < 1000; i++) node._frameHandler.handle(`id-${i}`, `id-${i}`, { type: 'attestation', attestation: forged(A) }, lane);
      assert.strictEqual(rejected, 100, 'checked: one new lane, not 1,000');
      assert.strictEqual(node.metrics().gossipOverBudget, 900);
      assert.deepStrictEqual([...node._gossipBuckets.keys()], [lane]);
      // Checkpoints, witnesses and role grants go by the lane as well.
      const other = node._newLane('tcp');
      for (let i = 0; i < 30; i++) {
        node._frameHandler.handle(`c-${i}`, `c-${i}`, { type: 'checkpoint', checkpoint: { type: 'checkpoint', by: A.id, roster: ROOM, upto_seq: i + 1, root: `r${i}`, at: 1, sig: forgedSig() } }, other);
        node._frameHandler.handle(`w-${i}`, `w-${i}`, { type: 'witness', witness: { type: 'witness', attester: A.id, roster: ROOM, upto_seq: i + 1, root: 'r', by: A.id, role: 'participant', at: 1, sig: forgedSig() } }, other);
        node._frameHandler.handle(`g-${i}`, `g-${i}`, { type: 'role-grant', grant: forgedGrant(A.id, `x-${i}`) }, other);
      }
      assert.deepStrictEqual([...node._gossipBuckets.keys()], [lane, other]);
      assert.strictEqual(node._gossipNewLane - node._gossipBuckets.get(other).tokens, 90, 'each spent one of its lane');
    });
  });

  it('fresh sender ids over the relay are a lane each, of 100, and all of them together stay under the ceiling', () => {
    withNode({}, ({ node, clock, metrics }) => {
      const A = kp('att-A');
      node._pinPeerKey(A.id, A.pub);
      const logs = [];
      node._log = (m) => logs.push(m);
      const relay = (id, frame) => node._relay._handlePeerMessage(id, id, frame, `relay:1:${id}`);
      const checked = () => metrics.filter((m) => m.type === 'attestation-rejected').length;
      // 300 ids, 101 forgeries each.
      for (let i = 0; i < 300; i++) for (let j = 0; j < 101; j++) relay(`id-${i}`, { type: 'attestation', attestation: forged(A) });
      assert.strictEqual(checked(), 20_000, 'the ceiling: a burst of 20,000, however many ids');
      assert.ok(node._gossipBuckets.has('relay:1:id-0'), 'the relay frame came with its lane');
      assert.strictEqual(node._gossipBuckets.get('relay:1:id-0').tokens, 0, 'each id has 100');
      assert.strictEqual(node._gossipBuckets.get('relay:1:id-299').tokens, 100, 'those past the ceiling checked nothing');
      // What the ceiling dropped is said in one report, not one per id.
      const ceiling = () => metrics.filter((m) => m.type === 'gossip-over-ceiling');
      assert.strictEqual(ceiling().length, 1, 'said once, at the first drop');
      node._sayDrops(node._dropReports.get('gossip-over-ceiling|*'));
      assert.strictEqual(ceiling().length, 2);
      assert.strictEqual(ceiling().reduce((s, m) => s + m.dropped, 0), 100 * 101, 'every drop counted');
      assert.strictEqual(ceiling()[0].perSecond, 4000);
      assert.strictEqual(ceiling()[1].fromPeerIds.length, 16, 'naming up to 16 peers');
      assert.strictEqual(node.metrics().gossipOverBudget, 300 * 101 - 20_000);
      // The frame handler's own drop line is said once per connection and reason, not once per id:
      // checked forgeries, and frames naming a signer whose key is not held (dropped for free).
      for (let i = 0; i < 1000; i++) relay(`free-${i}`, { type: 'attestation', attestation: { ...forged(A), by: `nobody-${i}` } });
      assert.strictEqual(logs.filter((l) => /Attestation from .* dropped \(bad-signature\)/.test(l)).length, 1);
      assert.strictEqual(logs.filter((l) => /dropped \(unknown-attester-key\)/.test(l)).length, 1);
      // The ceiling refills at 4,000 a second.
      clock.t += 1000;
      const before = checked();
      for (let i = 0; i < 50; i++) for (let j = 0; j < 100; j++) relay(`next-${i}`, { type: 'attestation', attestation: forged(A) });
      assert.strictEqual(checked() - before, 4000);
    });
  });

  it('each TCP connection, accepted or dialled, is a lane of its own, whatever id it claims', async () => {
    const net = require('net');
    const { EventEmitter } = require('events');
    const { writeFrame } = require('../lib/frame-parser');
    const name = `lanes-tcp-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: ROOM });
    const A = kp('att-A');
    const sockets = [];
    const server = net.createServer((sock) => { sockets.push(sock); writeFrame(sock, { type: 'attestation', attestation: forged(A) }); });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    try {
      await node.start();
      node._pinPeerKey(A.id, A.pub);
      const accepted = () => {
        const t = new EventEmitter();
        t._closed = false;
        t.send = () => true;
        t.trySend = () => ({ ok: true });
        t.close = () => { t._closed = true; };
        return t;
      };
      // Accepted: two connections, one after the other, claiming one id.
      for (let i = 0; i < 2; i++) {
        const t = accepted();
        node._discovery.emit('inbound-connection', t, 'p-in', 'p-in', { type: 'handshake', nodeId: 'p-in', name: 'p-in' });
        t.emit('message', { type: 'attestation', attestation: forged(A) });
        t.close();
      }
      // Dialled.
      node._connectToPeer('127.0.0.1', server.address().port, 'p-out', 'p-out');
      for (let i = 0; i < 250 && node._gossipBuckets.size < 3; i++) await new Promise((r) => setTimeout(r, 20));
      assert.deepStrictEqual([...node._gossipBuckets.keys()].sort(), ['tcp:1', 'tcp:2', 'tcp:3']);
    } finally {
      await node.stop();
      for (const sock of sockets) sock.destroy();
      await new Promise((r) => server.close(() => r()));
      fs.rmSync(nodeDir(name), { recursive: true, force: true });
    }
  });

  it('the relay hands each frame over with its lane: this connection and the sender id it names', async () => {
    const wss = new WebSocketServer({ port: 0 });
    let connections = 0;
    wss.on('connection', (ws) => {
      const c = ++connections;
      ws.once('message', () => {
        for (const from of c === 1 ? ['a', 'b', 'a'] : ['a']) ws.send(JSON.stringify({ from, fromName: from, payload: { type: 'ping' } }));
        if (c === 1) setTimeout(() => ws.close(), 50);
      });
    });
    const got = [];
    let running = true;
    const rc = new RelayConnection({
      relayUrl: `ws://127.0.0.1:${wss.address().port}`, relayToken: 'x'.repeat(40), log: () => {},
      getIdentity: () => ({ nodeId: 'c'.repeat(64) }), isRunning: () => running, getPeers: () => new Map(), getMeshNode: () => null,
      createPeer: () => { throw new Error('no peers expected'); }, addPeer: () => {}, onPeerLeft: () => {}, onAuthRefused: () => {},
      handlePeerMessage: (id, name, msg, lane) => got.push([id, lane]),
      nodeName: 'lanes', peerWakeChannels: new Map(), saveWakeChannels: () => {},
    });
    try {
      rc.connect();
      for (let i = 0; i < 250 && got.length < 4; i++) await new Promise((r) => setTimeout(r, 20));
      assert.deepStrictEqual(got, [['a', 'relay:1:a'], ['b', 'relay:1:b'], ['a', 'relay:1:a'], ['a', 'relay:2:a']], 'a reconnection is a new lane');
    } finally { running = false; rc.destroy(); await new Promise((r) => wss.close(() => r())); }
  });
});

describe('drop reporting cannot break gossip or shutdown (F4)', () => {
  it('a throwing metric listener neither breaks ingest nor loses or repeats a count', () => {
    withNode({}, ({ node }) => {
      const A = kp('att-A');
      node._pinPeerKey(A.id, A.pub);
      const said = [];
      node.on('metric', (m) => { if (m.type === 'gossip-over-budget') said.push(m); });
      node.on('metric', () => { throw new Error('a bad sink'); });
      const reasons = {};
      for (let i = 0; i < 300; i++) {
        const r = node._ingestAttestation(forged(A), 'p', 'p', 'tcp:1');
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
        node._pinPeerKey('att', kp('att').pub);
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
      node._pinPeerKey(A.id, A.pub);
      node._pinPeerKey(W.id, W.pub);
      let lookups = 0;
      const has = node._attestations.has.bind(node._attestations);
      node._attestations.has = (sig) => { lookups++; return has(sig); };
      let grantLookups = 0;
      const grantHas = node._roleGrants.has.bind(node._roleGrants);
      node._roleGrants.has = (sig) => { grantLookups++; return grantHas(sig); };
      const att = signed({ of: 'cmb-1', by: A.id, at: 1, roster: ROOM, method: 'heuristic', verdict: 'aligned', categories: {}, role: 'participant', seq: 1, prev: 'p' }, A.priv, signAttestation);
      const cp = signed({ type: 'checkpoint', by: A.id, roster: ROOM, upto_seq: 8, root: 'r8', at: 1 }, A.priv, signCheckpoint);
      const w = signed({ type: 'witness', attester: A.id, roster: ROOM, upto_seq: 8, root: 'r8', by: W.id, role: 'participant', at: 1 }, W.priv, signWitness);
      const g = signGrant({ type: 'role-grant', grantee: 'V', role: 'validator', grantedBy: A.id, grantedAt: 1 }, A.priv);
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
      node._pinPeerKey(A.id, A.pub);
      const cp = (seq, root) => signed({ type: 'checkpoint', by: A.id, roster: ROOM, upto_seq: seq, root, at: seq }, A.priv, signCheckpoint);
      const ingest = (c) => node._ingestCheckpoint(c, 'p', 'tcp:1');
      assert.deepStrictEqual([ingest(cp(8, 'r8')).ok, ingest(cp(16, 'r16')).ok, ingest(cp(24, 'r24')).reason], [true, true, 'over-rate'], "the attester's rate is spent");
      const relayed = sent.length;
      assert.strictEqual(ingest(cp(8, 'forked')).reason, 'conflict', 'a second root at a held position: the evidence');
      assert.strictEqual(node._attestations.conflictAt(A.id, 8).root, 'forked', 'kept although the rate is spent');
      assert.strictEqual(metrics.filter((m) => m.type === 'attestation-conflict').length, 1);
      const tokens = node._gossipBuckets.get('tcp:1').tokens;
      for (let i = 0; i < 2000; i++) {
        const third = i % 2 ? { ...cp(8, 'r8'), root: `fork-${i}`, sig: forgedSig() } : cp(8, `fork-${i}`);
        assert.strictEqual(ingest(third).reason, 'conflict');
      }
      assert.strictEqual(node._gossipBuckets.get('tcp:1').tokens, tokens, 'a third root spends nothing: no signature is checked');
      assert.strictEqual(node._attestations.conflictAt(A.id, 8).root, 'forked', 'and changes nothing');
      assert.strictEqual(sent.length, relayed, 'nor is relayed');
    });
  });
});
