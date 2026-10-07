'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * Design D3: a grant or revoke that arrives before the grant rooting its grantor (gossip has no
 * order) is not lost — and not parked in a pending set that anyone can flood (0.13.17's fix, which
 * 0.14 replaces). The node asks the session that delivered it for the chain, with a directed
 * `role-chain-fetch`, and holds the record only for that fetch: at most 64 per session, until the
 * answer or a timeout. The answer is ordinary signed grants, verified top-down.
 *
 * Ports of the 0.13.17 review's reproductions ooo.js and rev.js (out-of-order grants and revokes)
 * and pending-abuse.js (crowding, forged and padded copies, retry cost).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const { signGrant } = require('../lib/core');
const { connectNodes, until, admitAs, deliver } = require('./_core-secure');

function kp(nodeId) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    nodeId,
    priv: privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(16).toString('base64url'),
    pub: publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('base64url'),
  };
}
const grant = (type, grantee, role, grantor, at, extra = {}) =>
  signGrant({ type, grantee: grantee.nodeId, role, grantedBy: grantor.nodeId, grantedAt: at, ...(type === 'role-grant' ? { granteeKey: grantee.pub } : {}), ...extra }, grantor.priv);
const uniq = (base) => `${base}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;

const A = kp('anchor-node'), V = kp('validator-node'), X = kp('x-node');
const t = Date.now();
const gAV = grant('role-grant', V, 'validator', A, t - 3000);
const gVX = grant('role-grant', X, 'validator', V, t - 2000);
const rVX = grant('role-revoke', X, undefined, V, t - 1000);
const gAX = grant('role-grant', X, 'validator', A, t - 5000);
const RECS = { AV: gAV, VX: gVX, rVX, AX: gAX };

function boot(base, extra = {}) {
  const n = new SymNode({ name: uniq(base), silent: true, discovery: new NullDiscovery(), room: 'chain', anchor: { nodeId: A.nodeId, publicKey: A.pub }, ...extra });
  // These tests are about role-chain-fetch: the admission-time sync (anti-entropy, tested on its
  // own below) is left out, so a record reaches the store only by the order the test delivers it.
  if (!extra.sync) n._onRoleDigest = () => {};
  return n;
}
async function stopAll(...nodes) {
  for (const n of nodes) { try { await n.stop(); } catch { /* */ } try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ } }
}

describe('a grant or revoke that arrives before its root is resolved by role-chain-fetch (D3)', () => {
  // The roles 0.13.16 resolved for each order (it kept every record): the peer P that relays them
  // holds the whole chain, as a relaying peer does.
  for (const [order, role] of [
    [['AV', 'VX'], 'validator'],
    [['VX', 'AV'], 'validator'],          // the grant arrives first (grantor key unknown)
    [['AV', 'VX', 'rVX'], 'participant'],
    [['AV', 'rVX', 'VX'], 'participant'],
    [['rVX', 'VX', 'AV'], 'participant'], // both before their root
    [['VX', 'rVX', 'AV'], 'participant'],
    [['AX', 'rVX', 'AV'], 'participant'], // rev.js: a revoke before the grant rooting its revoker
  ]) {
    it(`${order.join(' → ')}: X ends ${role}`, async () => {
      const P = boot('chain-p'); const N = boot('chain-n');
      try {
        await P.start(); await N.start();
        for (const k of ['AX', 'AV', 'VX', 'rVX']) if (order.includes(k)) P._roleGrants.record(RECS[k]);
        await connectNodes(P, N);
        const s = N._peers.get(P.nodeId).transport;
        for (const k of order) deliver(N, s, { type: RECS[k].type, grant: RECS[k] });
        await until(() => N._roleGrants.size() === order.length, 3000);
        assert.strictEqual(N._roleGrants.size(), order.length, 'every record stored');
        assert.strictEqual(N.resolveRole(X.nodeId, Date.now(), { key: X.pub }), role);
        const early = order.some((k, i) => (k === 'VX' || k === 'rVX') && order.indexOf('AV') > i);
        assert.strictEqual(N._chainStats.fetched > 0, early, 'a fetch only when a record came before the grant vouching its grantor\'s key');
      } finally { await stopAll(P, N); }
    });
  }

  it('a record held for a fetch is never written or relayed; the resolved one is, once', async () => {
    const P = boot('chain-p2'); const N = boot('chain-n2');
    try {
      await P.start(); await N.start();
      P._roleGrants.record(gAV); P._roleGrants.record(gVX);
      await connectNodes(P, N);
      const relayed = [];
      const orig = N._gossipToRoster.bind(N);
      N._gossipToRoster = (f, except) => { relayed.push(f.grant && f.grant.sig); return orig(f, except); };
      const file = path.join(N._dir, 'role-grants', 'role-grants.jsonl');
      const s = N._peers.get(P.nodeId).transport;
      // Hold the fetch's answer back for a moment: the early record is held, not written.
      const sent = [];
      const send = s.send.bind(s);
      let hold = true;
      s.send = (f) => { if (hold && f.type === 'role-chain-fetch') { sent.push(f); return true; } return send(f); };
      deliver(N, s, { type: 'role-grant', grant: gVX });
      assert.strictEqual(sent.length, 1, 'one fetch, to the session that delivered it');
      assert.deepStrictEqual(sent[0].grantees, [V.nodeId]);
      assert.strictEqual(fs.existsSync(file) ? fs.readFileSync(file, 'utf8').includes(gVX.sig) : false, false, 'not written while held');
      assert.deepStrictEqual(relayed, [], 'not relayed while held');
      hold = false;
      send(sent[0]);
      await until(() => N._roleGrants.size() === 2, 3000);
      assert.ok(fs.readFileSync(file, 'utf8').includes(gVX.sig), 'written once resolved');
      assert.strictEqual(relayed.filter((x) => x === gVX.sig).length, 1, 'and relayed once');
      assert.strictEqual(N._chainStats.resolved, 1);
    } finally { await stopAll(P, N); }
  });

  it('a session that never answers: the held record is dropped at the timeout, and nothing is kept', async () => {
    const N = boot('chain-timeout', { chainFetchTimeoutMs: 150 });
    try {
      await N.start();
      const mute = admitAs(N, { nodeId: 'mute-peer', name: 'mute', publicKey: kp('m').pub });
      deliver(N, mute, { type: 'role-grant', grant: gVX });
      assert.ok(mute.sent.some((f) => f.type === 'role-chain-fetch'));
      assert.strictEqual(mute._chainHold.grants.size, 1);
      await until(() => N._chainStats.timedOut === 1, 2000);
      assert.strictEqual(mute._chainHold.grants.size, 0);
      assert.strictEqual(N._roleGrants.size(), 0);
    } finally { await stopAll(N); }
  });

  it('an answer nobody asked for, or for another session\'s fetch, is not read', async () => {
    const N = boot('chain-unsolicited');
    try {
      await N.start();
      const a = admitAs(N, { nodeId: 'peer-a', name: 'a', publicKey: kp('a').pub });
      const b = admitAs(N, { nodeId: 'peer-b', name: 'b', publicKey: kp('b').pub });
      deliver(N, a, { type: 'role-chain', reqId: 'rc-nothing', grants: [gAV] });
      assert.strictEqual(N._roleGrants.size(), 0, 'unsolicited');
      deliver(N, a, { type: 'role-grant', grant: gVX });
      const reqId = a.sent.find((f) => f.type === 'role-chain-fetch').reqId;
      deliver(N, b, { type: 'role-chain', reqId, grants: [gAV] });
      assert.strictEqual(N._roleGrants.size(), 0, 'another session cannot answer it');
      deliver(N, a, { type: 'role-chain', reqId, grants: [gAV] });
      assert.strictEqual(N._roleGrants.size(), 2, 'the asked session can');
    } finally { await stopAll(N); }
  });
});

describe('anti-entropy for grants and revokes (security review D, p7-ceiling)', () => {
  it('a revoke this node missed reaches it at the next admission: the digests differ, the store syncs', async () => {
    const P = boot('ae-p', { sync: true }); const N = boot('ae-n', { sync: true });
    try {
      await P.start(); await N.start();
      // N knows V as validator and V's grant of X; P also holds the revoke N never got.
      for (const r of [gAV, gVX]) { P._roleGrants.record(r); N._roleGrants.record(r); }
      P._roleGrants.record(rVX);
      assert.strictEqual(N.resolveRole(X.nodeId, Date.now(), { key: X.pub }), 'validator', 'before: the revoke was lost on the way');
      await connectNodes(P, N);
      await until(() => N._roleGrants.size() === 3, 4000);
      assert.strictEqual(N.resolveRole(X.nodeId, Date.now(), { key: X.pub }), 'participant', 'after: the revoke arrived by the sync');
      assert.ok(N._chainStats.synced >= 1);
      assert.strictEqual(N._roleGrants.digest().digest, P._roleGrants.digest().digest, 'the stores agree');
    } finally { await stopAll(P, N); }
  });

  it('a sync is paged in sync order (each record after its chain), and the pages are bounded', async () => {
    const N = boot('ae-serve');
    try {
      await N.start();
      const ys = Array.from({ length: 70 }, (_, i) => kp(`ae-y${i}`));
      for (const [i, y] of ys.entries()) N._roleGrants.record(grant('role-grant', y, 'validator', A, t - 500 + i));
      const asker = admitAs(N, { nodeId: 'ae-asker', name: 'a', publicKey: kp('ae-q').pub });
      deliver(N, asker, { type: 'role-chain-fetch', reqId: 'rs-1', sync: true, after: 0 });
      const first = asker.sent.find((f) => f.type === 'role-chain');
      assert.strictEqual(first.grants.length, 64, 'a page holds at most 64');
      assert.strictEqual(first.next, 64, 'and says where the next starts');
      deliver(N, asker, { type: 'role-chain-fetch', reqId: 'rs-2', sync: true, after: first.next });
      const second = asker.sent.filter((f) => f.type === 'role-chain')[1];
      assert.strictEqual(second.grants.length, 6);
      assert.strictEqual(second.next, undefined, 'the last page');
    } finally { await stopAll(N); }
  });
});

describe('role-chain-fetch cannot be flooded (port of pending-abuse.js)', () => {
  const junk = (i) => signGrant({ type: 'role-grant', grantee: `g${i}`, granteeKey: kp('j').pub, role: 'validator', grantedBy: `nobody-${i}`, grantedAt: t }, kp('j').priv);

  it('(a) crowding: one session holds at most 64; it cannot displace another session\'s held record', async () => {
    const N = boot('chain-crowd');
    try {
      await N.start();
      const honest = admitAs(N, { nodeId: 'honest-peer', name: 'h', publicKey: kp('h').pub });
      const evil = admitAs(N, { nodeId: 'evil-peer', name: 'e', publicKey: kp('e').pub });
      deliver(N, honest, { type: 'role-grant', grant: gVX });
      for (let i = 0; i < 1024; i++) deliver(N, evil, { type: 'role-grant', grant: junk(i) });
      assert.strictEqual(evil._chainHold.grants.size, 64, 'at most 64 per session');
      assert.strictEqual(evil.sent.filter((f) => f.type === 'role-chain-fetch').length, 64, 'and as many fetches');
      assert.strictEqual(honest._chainHold.grants.size, 1, 'the honest session\'s record is untouched');
      const reqId = honest.sent.find((f) => f.type === 'role-chain-fetch').reqId;
      deliver(N, honest, { type: 'role-chain', reqId, grants: [gAV] });
      assert.strictEqual(N.resolveRole(X.nodeId, Date.now(), { key: X.pub }), 'validator');
    } finally { await stopAll(N); }
  });

  it('(b) a forged copy sent ahead of the genuine record does not keep it out, and is dropped without charging the relayer (re-review N1)', async () => {
    const N = boot('chain-forged');
    try {
      await N.start();
      const s = admitAs(N, { nodeId: 'relayer', name: 'r', publicKey: kp('r').pub });
      const h = admitAs(N, { nodeId: 'honest-relayer', name: 'h', publicKey: kp('h2').pub });
      deliver(N, s, { type: 'role-grant', grant: { ...gVX, grantedAt: gVX.grantedAt + 1 } }); // the genuine sig on altered fields
      deliver(N, h, { type: 'role-grant', grant: gVX });
      assert.strictEqual(s._chainHold.grants.size, 1, 'held apart: the forgery on its session');
      assert.strictEqual(h._chainHold.grants.size, 1, 'the genuine record on its own');
      deliver(N, s, { type: 'role-chain', reqId: s.sent.find((f) => f.type === 'role-chain-fetch').reqId, grants: [gAV] });
      // V's statement, relayed: its signature fails under this node's key for V, which the relayer's
      // binding for V may not share. Dropped and counted, never charged to the relayer (re-review N1).
      assert.strictEqual(s.closed, false, 'a relayed statement that fails does not close the relayer\'s session');
      assert.strictEqual(s._chainHold.grants.size, 0, 'the forgery is dropped');
      deliver(N, h, { type: 'role-chain', reqId: h.sent.find((f) => f.type === 'role-chain-fetch').reqId, grants: [gAV] });
      assert.strictEqual(N.resolveRole(X.nodeId, Date.now(), { key: X.pub }), 'validator', 'the genuine one stored, the forgery dropped');
      assert.strictEqual(N._roleGrants.size(), 2);
    } finally { await stopAll(N); }
  });

  it('(c) a padded copy (an unsigned field) is stored, persisted and relayed as its signed fields only (A5)', async () => {
    const N = boot('chain-padded');
    try {
      await N.start();
      const s = admitAs(N, { nodeId: 'relayer', name: 'r', publicKey: kp('r').pub });
      const relayed = [];
      N._gossipToRoster = (f) => relayed.push(f.grant);
      deliver(N, s, { type: 'role-grant', grant: { ...gVX, junk: 'x'.repeat(100_000) } });
      const reqId = s.sent.find((f) => f.type === 'role-chain-fetch').reqId;
      deliver(N, s, { type: 'role-chain', reqId, grants: [{ ...gAV, note: 'unsigned' }] });
      const kept = N._roleGrants.grantsFor(X.nodeId)[0];
      assert.deepStrictEqual(Object.keys(kept).sort(), ['grantedAt', 'grantedBy', 'grantee', 'granteeKey', 'role', 'sig', 'sigAlg', 'type']);
      assert.ok(relayed.every((g) => !('junk' in g) && !('note' in g)), 'relayed as signed');
      const file = fs.readFileSync(path.join(N._dir, 'role-grants', 'role-grants.jsonl'), 'utf8');
      assert.ok(!file.includes('junk') && !file.includes('unsigned'), 'persisted as signed');
    } finally { await stopAll(N); }
  });

  it('(d) a store does no work for held records (there is no pending set to retry)', async () => {
    const N = boot('chain-cost');
    try {
      await N.start();
      const evil = admitAs(N, { nodeId: 'evil-peer', name: 'e', publicKey: kp('e').pub });
      for (let i = 0; i < 64; i++) deliver(N, evil, { type: 'role-grant', grant: junk(i) });
      const ys = Array.from({ length: 200 }, (_, i) => kp(`y${i}`));
      const recs = ys.map((y, i) => grant('role-grant', y, 'validator', A, t - 1000 + i));
      const t0 = process.hrtime.bigint();
      for (const r of recs) N._roleGrants.record(r);
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      assert.strictEqual(N._roleGrants.size(), 200);
      assert.ok(ms < 2000, `200 stores in ${ms.toFixed(0)} ms`);
    } finally { await stopAll(N); }
  });

  it('the server answers at most 4 a second per session (burst 16), with at most 64 grants', async () => {
    const N = boot('chain-serve');
    try {
      await N.start();
      N._roleGrants.record(gAV); N._roleGrants.record(gVX);
      const asker = admitAs(N, { nodeId: 'asker', name: 'a', publicKey: kp('q').pub });
      for (let i = 0; i < 100; i++) deliver(N, asker, { type: 'role-chain-fetch', reqId: `q${i}`, grantees: [X.nodeId] });
      const answers = asker.sent.filter((f) => f.type === 'role-chain');
      assert.strictEqual(answers.length, 16);
      assert.deepStrictEqual(answers[0].grants.map((g) => g.sig), [gAV.sig, gVX.sig], 'top-down: the grantor\'s root first');
    } finally { await stopAll(N); }
  });
});
