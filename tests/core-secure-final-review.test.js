'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * The final re-review of f0d936a (BLOCK): the founder's three rulings and the findings beside them,
 * each as a regression test that fails on f0d936a. The reviewer's repros are in
 * /private/tmp/claude-501/-Users-hongwei-sym-agent-a/sym-014-final-review/ (grant-probes.js P1-P4,
 * node-probes.js Q1, digest-churn.js, fork-a, fork-b).
 *
 *   A  the kept grant set is a function of the records held (Findings 1, 2)
 *   B  the anchor ratifies; a revoked key gains nothing by backdating (Finding 4, Low 8a)
 *   C  the interior read side is scoped to the mind's mission (Finding 6)
 *   3  the cost of relayed forgeries is bounded without blaming the relayer
 *   7  relocation: in-process locks, replays, staging, modes, the header checked first
 *   lows
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const config = require('../lib/config');
const relocation = require('../lib/relocation');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const { RoleGrantStore } = require('../lib/role-grant-store');
const { signGrant, signAttestation } = require('../lib/core');
const { identity, connectNodes, until, signedRecord, admitAs, deliver } = require('./_core-secure');

const uniq = (b) => `${b}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
function mk(base, extra = {}) { return new SymNode({ name: uniq(base), silent: true, discovery: new NullDiscovery(), room: extra.room || 'fr', ...extra }); }
async function stopAll(...nodes) {
  for (const n of nodes) { try { await n.stop(); } catch { /* */ } try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ } }
}
function kp() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { nodeId: crypto.randomUUID(), priv: privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(16).toString('base64url'), pub: publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('base64url') };
}
const grantOf = (type, grantee, role, grantor, at, extra = {}) => signGrant({ type, grantee: grantee.nodeId, ...(role ? { role } : {}), grantedBy: grantor.nodeId, grantedAt: at, ...(type === 'role-grant' ? { granteeKey: grantee.pub } : {}), ...extra }, grantor.priv);
const DAY = 86_400_000;

/** Offer `records` in `order` until a pass keeps nothing (as a load, or a chain fetch, does). */
function feed(store, records) {
  let left = records;
  for (let progress = true; progress && left.length;) {
    progress = false;
    const next = [];
    for (const g of left) {
      const r = store.record(g);
      if (r.stored) progress = true;
      else if (r.reason === 'unknown-grantor-key') next.push(g);
    }
    left = next;
  }
}
/** A deterministic shuffle. */
function shuffled(list, seed) {
  const a = [...list];
  let x = seed;
  for (let i = a.length - 1; i > 0; i--) { x = (x * 1103515245 + 12345) & 0x7fffffff; const j = x % (i + 1); [a[i], a[j]] = [a[j], a[i]]; }
  return a;
}

describe('A: the kept grant set is a function of the records held (Findings 1 and 2)', () => {
  it('stores fed the same records in different orders keep the same records and resolve the same authority, with full budgets, cutoffs and ratifications', () => {
    const A = kp(), V = kp(), Q = kp(), W = kp(), X = kp(), M = kp();
    const t0 = Date.now() - 30 * DAY;
    const sybils = Array.from({ length: 5 }, () => kp());
    const rVW = grantOf('role-revoke', W, undefined, V, t0 + 2 * DAY, { cutoff: t0 + 2 * DAY });
    const records = [
      grantOf('role-grant', V, 'validator', A, t0),
      grantOf('role-grant', Q, 'validator', A, t0),
      grantOf('role-grant', M, 'validator', A, t0),
      grantOf('role-grant', W, 'validator', A, t0 + 1),
      grantOf('role-grant', X, 'validator', V, t0 + 5 * DAY),
      rVW,
      grantOf('role-revoke', V, undefined, A, t0 + 10 * DAY, { cutoff: t0 + 3 * DAY, ratify: [rVW.sig] }),
      grantOf('role-revoke', X, undefined, Q, t0 + 11 * DAY, { cutoff: t0 + 11 * DAY }),
      grantOf('role-revoke', X, undefined, Q, t0 + 12 * DAY, { cutoff: t0 + 6 * DAY }),
      ...sybils.map((y, i) => grantOf('role-grant', y, 'validator', M, t0 + 20 + i)),
      ...sybils.flatMap((y, i) => [grantOf('role-revoke', W, undefined, y, t0 + 30 + i, { cutoff: t0 + 30 + i }), grantOf('role-grant', kp(), 'validator', y, t0 + 40 + i)]),
    ];
    const roles = (s) => [V, Q, W, X, M, ...sybils].map((n) => [s.resolveRole(n.nodeId, n.pub, Date.now()), s.resolveRole(n.nodeId, n.pub, t0 + 4 * DAY)].join('/'));
    let first = null;
    for (let seed = 1; seed <= 12; seed++) {
      const s = new RoleGrantStore({ anchor: { nodeId: A.nodeId, publicKey: A.pub }, subtreeBudget: 6 });
      feed(s, seed === 1 ? records : shuffled(records, seed));
      const view = { digest: s.digest().digest, size: s.size(), roles: roles(s) };
      if (!first) first = view;
      else assert.deepStrictEqual(view, first, `order ${seed}`);
    }
    assert.ok(first.size < records.length, 'the budget bound M\'s subtree');
  });

  it('a grant and a revoke signed in the same millisecond resolve alike whichever was kept first', () => {
    const A = kp(), V = kp();
    const t = Date.now() - DAY;
    const g = grantOf('role-grant', V, 'validator', A, t);
    const r = grantOf('role-revoke', V, undefined, A, t, { cutoff: t });
    const X = new RoleGrantStore({ anchor: { nodeId: A.nodeId, publicKey: A.pub } });
    const Y = new RoleGrantStore({ anchor: { nodeId: A.nodeId, publicKey: A.pub } });
    X.record(g); X.record(r);
    Y.record(r); Y.record(g);
    assert.deepStrictEqual([X.resolveRole(V.nodeId, V.pub, Date.now()), Y.resolveRole(V.nodeId, V.pub, Date.now())], ['participant', 'participant']);
  });

  it('P2: a grant signed by a grantor revoked from before it is kept by every store, whatever arrived first (equal digests)', () => {
    const A = kp(), P = kp(), X = kp();
    const t0 = Date.now() - 30 * DAY;
    const gP = grantOf('role-grant', P, 'validator', A, t0);
    const gX = grantOf('role-grant', X, 'validator', P, t0 + 5 * DAY);
    const rP = grantOf('role-revoke', P, undefined, A, t0 + 10 * DAY, { cutoff: t0 + 3 * DAY });
    const B = new RoleGrantStore({ anchor: { nodeId: A.nodeId, publicKey: A.pub } });
    const C = new RoleGrantStore({ anchor: { nodeId: A.nodeId, publicKey: A.pub } });
    for (const g of [gP, gX, rP]) assert.strictEqual(B.record(g).stored, true);
    for (const g of [gP, rP, gX]) assert.strictEqual(C.record(g).stored, true, 'never refused as unrooted');
    assert.strictEqual(B.digest().digest, C.digest().digest);
    assert.deepStrictEqual([B.resolveRole(X.nodeId, X.pub, Date.now()), C.resolveRole(X.nodeId, X.pub, Date.now())], ['participant', 'participant']);
  });

  it('P4 / revoke-tighten: a revoker tightens its cutoff with a second revoke, and stores agree whichever came first', () => {
    const A = kp(), Q = kp(), P = kp();
    const t = (n) => 1_000_000 + n * 1000;
    const base = [grantOf('role-grant', Q, 'validator', A, t(0)), grantOf('role-grant', P, 'validator', Q, t(1))];
    const r5 = grantOf('role-revoke', P, undefined, Q, t(5), { cutoff: t(5) });
    const r2 = grantOf('role-revoke', P, undefined, Q, t(6), { cutoff: t(2) });
    const X = new RoleGrantStore({ anchor: { nodeId: A.nodeId, publicKey: A.pub } });
    const Y = new RoleGrantStore({ anchor: { nodeId: A.nodeId, publicKey: A.pub } });
    for (const b of base) { X.record(b); Y.record(b); }
    assert.deepStrictEqual([X.record(r5).stored, X.record(r2).stored], [true, true]);
    assert.deepStrictEqual([Y.record(r2).stored, Y.record(r5).stored], [true, true]);
    assert.strictEqual(X.digest().digest, Y.digest().digest);
    assert.deepStrictEqual([X.resolveRole(P.nodeId, P.pub, t(3)), Y.resolveRole(P.nodeId, P.pub, t(3))], ['participant', 'participant'], 'P untrusted from t2, as Q meant');
  });

  it('P3: one validator\'s sybil tree stays inside its subtree budget, and resolution of its target stays bounded', () => {
    const A = kp(), M = kp(), T = kp();
    const s = new RoleGrantStore({ anchor: { nodeId: A.nodeId, publicKey: A.pub }, subtreeBudget: 8 });
    const t0 = Date.now() - 30 * DAY;
    s.record(grantOf('role-grant', M, 'validator', A, t0));
    s.record(grantOf('role-grant', T, 'validator', A, t0));
    const sybils = [];
    for (let i = 0; i < 3; i++) { const y = kp(); sybils.push(y); s.record(grantOf('role-grant', y, 'validator', M, t0 + 1 + i)); }
    for (const y of sybils) for (let j = 0; j < 2; j++) s.record(grantOf('role-grant', { nodeId: T.nodeId, pub: kp().pub }, 'validator', y, t0 + 10 + j));
    for (const sg of [M, ...sybils]) for (let k = 0; k < 50; k++) s.record(grantOf('role-revoke', T, undefined, sg, t0 + 1000 + k, { cutoff: t0 + 1000 + k }));
    assert.strictEqual(s.size(), 2 + 8, 'the anchor\'s two, and M\'s subtree at its budget');
    assert.ok(s.grantsFor(T.nodeId).length <= 1 + 8, 'what a resolution of T replays is bounded by the budget');
  });

  it('digest-churn: two nodes that learned the same records in different orders run no whole-store sync', async () => {
    const A = kp(), P = kp(), X = kp();
    const t0 = Date.now() - 30 * DAY;
    const gP = grantOf('role-grant', P, 'validator', A, t0);
    const gX = grantOf('role-grant', X, 'validator', P, t0 + 5 * DAY);
    const rP = grantOf('role-revoke', P, undefined, A, t0 + 10 * DAY, { cutoff: t0 + 3 * DAY });
    const B = mk('churn-b', { anchor: { nodeId: A.nodeId, publicKey: A.pub } });
    const C = mk('churn-c', { anchor: { nodeId: A.nodeId, publicKey: A.pub } });
    try {
      await B.start(); await C.start();
      for (const g of [gP, gX, rP]) B._roleGrants.record(g);
      for (const g of [gP, rP, gX]) C._roleGrants.record(g);
      await connectNodes(B, C);
      await new Promise((r) => setTimeout(r, 300));
      assert.strictEqual(B._roleGrants.digest().digest, C._roleGrants.digest().digest);
      assert.deepStrictEqual([B._chainStats.synced || 0, C._chainStats.synced || 0], [0, 0], 'no whole-store sync');
    } finally { await stopAll(B, C); }
  });
});

describe('B: the anchor ratifies; a revoked key gains nothing by backdating (Finding 4)', () => {
  it('P1: a revoke a revoked validator signs later, dated before its cutoff, changes nothing at any time', () => {
    const A = kp(), V = kp(), W = kp();
    const t0 = Date.now() - 30 * DAY;
    const s = new RoleGrantStore({ anchor: { nodeId: A.nodeId, publicKey: A.pub } });
    s.record(grantOf('role-grant', V, 'validator', A, t0));
    s.record(grantOf('role-grant', W, 'validator', A, t0 + 1));
    s.record(grantOf('role-revoke', V, undefined, A, t0 + 20 * DAY)); // a 0.13 revoke: cutoff = its time
    assert.strictEqual(s.record(grantOf('role-revoke', W, undefined, V, t0 + 2 * DAY, { cutoff: t0 + DAY })).stored, true, 'kept: verifiable');
    for (const at of [Date.now(), t0 + 10 * DAY, t0 + 1.5 * DAY]) assert.strictEqual(s.resolveRole(W.nodeId, W.pub, at), 'validator', `W at ${at}`);
  });

  it('the revoker is checked at every breakpoint from its cutoff to its signed time (Low 8a), and at resolution, not only when kept (M7)', () => {
    const A = kp(), Q = kp(), W = kp();
    const t = (n) => 1_000_000 + n * 1000;
    const st = new RoleGrantStore({ anchor: { nodeId: A.nodeId, publicKey: A.pub } });
    st.record(grantOf('role-grant', W, 'validator', A, t(0)));
    st.record(grantOf('role-grant', Q, 'validator', A, t(1)));
    st.record(grantOf('role-revoke', Q, undefined, A, t(2), { cutoff: t(2) }));
    st.record(grantOf('role-grant', Q, 'validator', A, t(3)));
    st.record(grantOf('role-revoke', W, undefined, Q, t(4), { cutoff: t(1.5) }));
    assert.strictEqual(st.resolveRole(W.nodeId, W.pub, t(2.5)), 'validator', 'Q was not authorised over all of [t1.5, t4]: no effect');
    assert.strictEqual(st.resolveRole(W.nodeId, W.pub, t(10)), 'validator');
    // M7: a revoke effective when kept loses its effect when a later record shows its revoker had no
    // rank at its cutoff.
    const B = kp(), Z = kp();
    const s2 = new RoleGrantStore({ anchor: { nodeId: A.nodeId, publicKey: A.pub } });
    s2.record(grantOf('role-grant', Z, 'validator', A, t(0)));
    s2.record(grantOf('role-grant', B, 'validator', A, t(0)));
    s2.record(grantOf('role-revoke', Z, undefined, B, t(10), { cutoff: t(5) }));
    assert.strictEqual(s2.resolveRole(Z.nodeId, Z.pub, t(20)), 'participant', 'effective as kept');
    s2.record(grantOf('role-revoke', B, undefined, A, t(30), { cutoff: t(3) }));
    s2.record(grantOf('role-grant', B, 'validator', A, t(31)));
    assert.strictEqual(s2.resolveRole(B.nodeId, B.pub, t(40)), 'validator', 'B holds rank again now');
    assert.strictEqual(s2.resolveRole(Z.nodeId, Z.pub, t(40)), 'validator', 'but B had none at its revoke\'s cutoff: re-checked at resolution');
  });

  it('revokeRole requires a cutoff and checks its ratify list; the anchor\'s ratification keeps a revoked validator\'s statement', async () => {
    const node = mk('ratify', {});
    const A = { nodeId: node.nodeId, pub: node._identity.publicKey };
    const anchored = mk('ratify-a', { anchor: { nodeId: A.nodeId, publicKey: A.pub } });
    try {
      const V = kp(); const W = kp();
      anchored._roster.bind(V.nodeId, V.pub, 'pinned');
      anchored._roster.bind(W.nodeId, W.pub, 'pinned');
      const s = anchored._roleGrants;
      const t0 = Date.now() - 10 * DAY;
      s.record(signGrant({ type: 'role-grant', grantee: V.nodeId, role: 'validator', grantedBy: A.nodeId, grantedAt: t0, granteeKey: V.pub }, node._identity.privateKey));
      s.record(signGrant({ type: 'role-grant', grantee: W.nodeId, role: 'validator', grantedBy: A.nodeId, grantedAt: t0, granteeKey: W.pub }, node._identity.privateKey));
      const rVW = grantOf('role-revoke', W, undefined, V, t0 + DAY, { cutoff: t0 + DAY });
      s.record(rVW);
      assert.strictEqual(anchored.resolveRole(W.nodeId), 'participant');
      assert.throws(() => node.revokeRole(V.nodeId), (e) => e.code === 'ECUTOFF', 'no default cutoff');
      assert.throws(() => node.revokeRole(V.nodeId, { cutoff: Date.now() + 60_000 }), (e) => e.code === 'ECUTOFF', 'not in the future');
      assert.throws(() => node.revokeRole(V.nodeId, { cutoff: t0, ratify: ['x'] }), (e) => e.code === 'ERATIFY');
      assert.deepStrictEqual(anchored.roleStatementsBy(V.nodeId, Date.now()).map((g) => g.sig), [rVW.sig], 'what V signed, for the revoker to review');
      // The anchor's node signs the revoke; the anchored node keeps it.
      const plain = signGrant({ type: 'role-revoke', grantee: V.nodeId, grantedBy: A.nodeId, grantedAt: Date.now(), cutoff: t0 + 2 * DAY }, node._identity.privateKey);
      s.record(plain);
      assert.strictEqual(anchored.resolveRole(W.nodeId), 'validator', 'V revoked without ratifying its revoke of W: it lapses');
      const ratifying = signGrant({ type: 'role-revoke', grantee: V.nodeId, grantedBy: A.nodeId, grantedAt: Date.now() + 1, cutoff: t0 + 2 * DAY, ratify: [rVW.sig] }, node._identity.privateKey);
      s.record(ratifying);
      assert.strictEqual(anchored.resolveRole(W.nodeId), 'participant', 'ratified: it stands');
    } finally { await stopAll(node, anchored); }
  });

  it('an attestation dated before the record it attests is refused at ingest and excluded from the aggregate', async () => {
    const b = mk('att-date', {});
    try {
      await b.start();
      const X = identity('x');
      const sX = admitAs(b, X);
      b._roster.bind(X.nodeId, X.publicKey, 'pinned');
      const rec = b.remember({ focus: 'a record attested later' });
      const key = rec.cmb.metadata.key;
      const created = rec.cmb.metadata.createdTimestamp;
      const att = (at, seq) => { const o = { of: key, by: X.nodeId, at, roster: b._room, verdict: 'aligned', categories: {}, seq, prev: 'genesis' }; signAttestation(o, X.privateKey); return o; };
      assert.strictEqual(b._ingestAttestation(att(created - 1000, 1), X.nodeId, X.name, sX).reason, 'dated-before-record');
      const late = att(created + 1, 2);
      b._attestations.record(att(created - 5, 3)); // as if held from before
      b._attestations.record(late);
      const agg = b.aggregateAttestations(key);
      assert.ok(agg.excluded.some((e) => e.reason === 'dated-before-record'));
      void sX;
    } finally { await stopAll(b); }
  });
});

describe('C: the interior read side is scoped to the mind\'s mission (Finding 6)', () => {
  function conn(p) {
    const s = net.createConnection(p); let buf = ''; const waiters = new Map(); let n = 0;
    s.on('data', (d) => { buf += d; let i; while ((i = buf.indexOf('\n')) !== -1) { const m = JSON.parse(buf.slice(0, i)); buf = buf.slice(i + 1); const w = waiters.get(m.id); if (w) { waiters.delete(m.id); w(m); } } });
    return { ask: (req) => new Promise((r) => { const id = ++n; waiters.set(id, r); s.write(JSON.stringify({ ...req, id }) + '\n'); }), close: () => new Promise((r) => { s.once('close', r); s.end(); }) };
  }
  const cats = (focus) => ({ focus, issue: 'i', intent: 'inform', motivation: 'm', commitment: 'c', perspective: 'p', mood: { text: 'calm' } });
  // A mind's categories leave intent to its kind (the signed intent).
  const mindCats = (focus) => ({ focus, issue: 'i', motivation: 'm', commitment: 'c', perspective: 'p', mood: { text: 'calm' } });

  it('mission B never sees mission A\'s deliveries or notes, and a mind never moves the host\'s inbox', async () => {
    const peerA = mk('peer-a', { room: 'r' });
    const node = mk('scoped', { room: 'r' });
    try {
      await peerA.start(); await node.start();
      node._svafEvaluator.evaluate = async () => ({ decision: 'aligned', total_drift: 0.1, category_drifts: { focus: 0.1 }, gate_values: { g: 1 } });
      const interior = node.interior();
      const sock = await interior.listen();
      const mA = interior.startMind({ id: 'mission-A', kinds: ['observation'], allowTo: [peerA.nodeId] });
      await connectNodes(peerA, node);
      peerA.remember(cats('customer A secret for mission A'), { to: node.nodeId });
      peerA.remember(cats('a room broadcast heard during mission A'));
      await until(() => node.inboxStatus().seq >= 2, 3000);
      const ca = conn(sock);
      const dA = await ca.ask({ type: 'deliveries', capability: mA.capability, peek: true });
      assert.deepStrictEqual(dA.items.map((x) => x.record.categories.focus.text), ['customer A secret for mission A', 'a room broadcast heard during mission A'], 'mission A sees its own counterparty, and the room');
      const sub = await ca.ask({ type: 'submit', capability: mA.capability, kind: 'observation', categories: mindCats('mission A private note'), to: peerA.nodeId });
      assert.strictEqual(sub.type, 'submitted');
      await ca.close();
      await until(() => !interior.busy, 2000);
      const before = node.inboxStatus();
      const mB = interior.startMind({ id: 'mission-B', kinds: ['observation'], allowTo: [] });
      const c = conn(sock);
      const d = await c.ask({ type: 'deliveries', capability: mB.capability, after: 0 });
      assert.deepStrictEqual(d.items, [], 'no delivery from before mission B');
      const r = await c.ask({ type: 'recall', capability: mB.capability, query: '' });
      assert.deepStrictEqual(r.items, [], 'recall holds nothing of mission A');
      for (const m of node.inbox({ peek: true }).messages) {
        const ack = await c.ask({ type: 'ack', capability: mB.capability, delivery: m.id });
        assert.strictEqual(ack.reason, 'not-in-view', `${m.directed ? 'directed' : 'broadcast'} from before mission B`);
      }
      const recalled = await c.ask({ type: 'recall', capability: mB.capability, query: 'broadcast heard during mission' });
      assert.deepStrictEqual(recalled.items, [], 'a broadcast from before mission B is not recalled either');
      // During mission B: a directed record from a node outside its allowTo is not in its view; a
      // room broadcast is.
      peerA.remember(cats('for the node, not for mission B'), { to: node.nodeId });
      peerA.remember(cats('a room broadcast during mission B'));
      await until(() => node.inboxStatus().seq >= 4, 3000);
      const during = await c.ask({ type: 'deliveries', capability: mB.capability, peek: true });
      assert.deepStrictEqual(during.items.map((x) => x.record.categories.focus.text), ['a room broadcast during mission B']);
      const cite = await c.ask({ type: 'submit', capability: mB.capability, kind: 'observation', categories: mindCats('cites A'), parents: [sub.key] });
      assert.strictEqual(cite.reason, 'parent-not-in-store', 'a key outside the scope is refused as if absent');
      await c.ask({ type: 'deliveries', capability: mB.capability });
      assert.strictEqual(node.inboxStatus().cursor, before.cursor, 'the host\'s inbox cursor is untouched');
      assert.strictEqual(node.inbox({ peek: true }).messages.length, 4);
      // Reads are rate-limited per mind.
      let limited = 0;
      for (let i = 0; i < 40; i++) if ((await c.ask({ type: 'mission', capability: mB.capability })).reason === 'rate') limited++;
      assert.ok(limited > 0, 'past the burst, reads are refused');
      await c.close();
    } finally { await stopAll(node, peerA); }
  });
});

describe('3: relayed forgeries cost bounded work, and nobody is blamed (Finding 3)', () => {
  it('Q1: 400 forged 200 KiB records relayed in another\'s name are mostly dropped before any work, with bounded logs and decisions', async () => {
    const b = mk('q1', {});
    try {
      await b.start();
      const logs = []; b._log = (m) => logs.push(m);
      const metrics = {}; b.on('metric', (m) => { metrics[m.type] = (metrics[m.type] || 0) + 1; });
      const X = identity('x'); const M = identity('m');
      admitAs(b, X);
      const sM = admitAs(b, M);
      const big = 'z'.repeat(200 * 1024);
      const before = b._decisionLog.count();
      for (let i = 0; i < 400; i++) {
        const rec = signedRecord(M, { categories: { focus: `forged ${i} ${big}` }, room: b._room });
        rec.metadata.createdByNodeId = X.nodeId;
        deliver(b, sM, { type: 'cmb', cmb: rec });
      }
      assert.strictEqual(sM.closed, false, 'the relayer is not blamed');
      assert.ok((metrics['relayed-signature-unverified'] || 0) <= 8, `verified and failed at most 8: ${metrics['relayed-signature-unverified']}`);
      assert.ok((metrics['relayed-signer-muted'] || 0) + (metrics['cmb-over-verify-budget'] || 0) >= 380, 'the rest dropped before any work');
      assert.ok(logs.length <= 10, `log lines: ${logs.length}`);
      assert.ok(b._decisionLog.count() - before <= 2, 'decision-log entries bounded');
    } finally { await stopAll(b); }
  });
});

describe('3b: the verification lane bounds work on records naming many signers', () => {
  it('400 records naming 400 unknown authors: most are dropped before any schema, hash or signature work', async () => {
    const b = mk('lane', {});
    try {
      await b.start();
      const metrics = {}; b.on('metric', (m) => { metrics[m.type] = (metrics[m.type] || 0) + 1; });
      const M = identity('m');
      const sM = admitAs(b, M);
      // Small records, so the loop runs well inside a second and the lane's refill stays small.
      const one = signedRecord(M, { categories: { focus: `forged ${'z'.repeat(1024)}` }, room: b._room });
      for (let i = 0; i < 400; i++) {
        const rec = JSON.parse(JSON.stringify(one));
        rec.metadata.createdByNodeId = crypto.randomUUID();
        deliver(b, sM, { type: 'cmb', cmb: rec });
      }
      assert.ok((metrics['cmb-over-verify-budget'] || 0) >= 200, `dropped before any work: ${metrics['cmb-over-verify-budget']}`);
    } finally { await stopAll(b); }
  });
});

describe('7: relocation (Finding 7)', () => {
  it('7a: a same-process re-acquire of an identity lock returns a release that does nothing; export refuses while a node in this process runs', async () => {
    const node = mk('reloc-live', {});
    try {
      await node.start();
      const lockFile = path.join(node._dir, 'lock.pid');
      const release = config.acquireIdentityLock(node.name, { dir: node._dir });
      release();
      assert.ok(fs.existsSync(lockFile), 'the running node keeps its lock');
      const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'b-')), 'n.bundle');
      assert.throws(() => relocation.exportNode({ name: node.name, out, toHostKey: relocation.hostKey().publicKey }), /running in this process/);
      assert.strictEqual(config.readTombstone(node.nodeId), null, 'not tombstoned');
    } finally { await stopAll(node); }
  });

  it('7b: an import is staged and refused whole, a replayed or consumed bundle is refused, file modes travel, and the header is checked before its scrypt parameters are used', async () => {
    const name = uniq('reloc');
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    const nodeId = node.nodeId; const pub = node._identity.publicKey;
    node.remember({ focus: 'travels' });
    await node.stop();
    const dir = config.nodeDirById(nodeId);
    fs.writeFileSync(path.join(dir, 'secret-0600.txt'), 'x', { mode: 0o600 });
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'b-'));
    const out = path.join(tmp, 'n.bundle');
    assert.throws(() => relocation.exportNode({ name, out, passphrase: 'a long operator passphrase' }), /a copy, not a move/, 'a passphrase bundle needs copyable');
    relocation.exportNode({ name, out, passphrase: 'a long operator passphrase', copyable: true });
    const pass = 'a long operator passphrase';
    // A header whose scrypt parameters were raised is refused before scrypt runs.
    const b = JSON.parse(fs.readFileSync(out, 'utf8'));
    const hostile = path.join(tmp, 'hostile.bundle');
    fs.writeFileSync(hostile, JSON.stringify({ ...b, N: 1 << 20 }));
    const t = Date.now();
    assert.throws(() => relocation.importNode({ from: hostile, passphrase: pass, expect: { nodeId, key: pub } }), /header is not signed/);
    assert.ok(Date.now() - t < 500, 'no scrypt was run');
    // The bundle of the move away, back on this host: a replay.
    assert.throws(() => relocation.importNode({ from: out, passphrase: pass, expect: { nodeId, key: pub } }), /at or before this host moved/);
    // Another host (this host's copy removed): a name already indexing another node refuses the whole
    // import, and nothing is installed.
    fs.rmSync(dir, { recursive: true, force: true });
    if (config.identityDirById(nodeId) !== dir) fs.rmSync(config.identityDirById(nodeId), { recursive: true, force: true });
    const other = config.loadIdentity({ name: uniq('other') });
    assert.throws(() => relocation.importNode({ from: out, passphrase: pass, expect: { nodeId, key: pub }, name: config.nodeIdForName ? other.name : other.name }), /already indexes another node/);
    assert.strictEqual(fs.existsSync(dir), false, 'nothing installed');
    assert.deepStrictEqual(fs.readdirSync(path.dirname(dir)).filter((f) => f.startsWith(path.basename(dir))), [], 'no staged directory left');
    relocation.importNode({ from: out, passphrase: pass, expect: { nodeId, key: pub } });
    assert.strictEqual(fs.statSync(path.join(dir, 'secret-0600.txt')).mode & 0o777, 0o600, 'its mode travelled');
    assert.strictEqual(fs.statSync(path.join(config.identityDirById(nodeId), 'identity.json')).mode & 0o777, 0o600);
    // Imported once here: never again.
    fs.rmSync(dir, { recursive: true, force: true });
    if (config.identityDirById(nodeId) !== dir) fs.rmSync(config.identityDirById(nodeId), { recursive: true, force: true });
    assert.throws(() => relocation.importNode({ from: out, passphrase: pass, expect: { nodeId, key: pub } }), /already imported on this host/);
    fs.rmSync(config.nodeDirById(other.nodeId), { recursive: true, force: true });
  });
});

describe('lows', () => {
  it('emit releases the identity\'s lock when it cannot connect', async () => {
    const { connect } = require('../lib/emit');
    const name = uniq('emitter');
    const receiver = { nodeId: crypto.randomUUID(), key: identity('r').publicKey };
    await assert.rejects(() => connect({ server: '127.0.0.1:1', receiver, name, timeoutMs: 500 }));
    const id = config.loadIdentity({ name, create: false });
    assert.strictEqual(config.lockHeldInProcess(config.nodeDirById(id.nodeId)), false, 'the lock was released');
    assert.strictEqual(fs.existsSync(path.join(config.nodeDirById(id.nodeId), 'lock.pid')), false);
    await assert.rejects(() => connect({ server: 'not-an-address', receiver, name }));
    assert.strictEqual(config.lockHeldInProcess(config.nodeDirById(id.nodeId)), false);
  });
});
