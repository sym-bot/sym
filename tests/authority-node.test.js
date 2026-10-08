'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * MMP §6.6 on real nodes: the four frames (authority-statement, authority-digest, authority-fetch,
 * authority-set) with their bounds and pacing (§6.6.8), the retired time-replay frames (§6.6.11),
 * in-force grants as a view of the key registry and a grant naming this node with a foreign key
 * (§6.6.9), the origin weight of a received record (§6.6.10), persistence that re-verifies everything
 * it reads (§6.6.7), and the property the rest is for: two nodes that receive the same statements in
 * different orders, over real sessions, reach the same root.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { SymNode } = require('../lib/node');
const { BonjourDiscovery, NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const A = require('../lib/core/authority');
const { AuthorityStore } = require('../lib/authority-store');
const { RETIRED_FRAMES } = require('../lib/node-authority');
const { until, connectNodes, admitAs, deliver, identity } = require('./_core-secure');

// ── Statements made off the mesh, by keys the test holds ──────────────────────

const PRIV = new Map();
function party() {
  const id = identity('p');
  PRIV.set(id.publicKey, id.privateKey);
  return { nodeId: id.nodeId, key: id.publicKey };
}
const anchorKey = party();
const PIN = { threshold: 1, keys: [{ key: anchorKey.key }] };
const sid = (s) => A.statementId(s);
function make(by, fields) {
  const s = { ...fields, authorisedBy: by === 'anchor' ? 'anchor' : sid(by), nonce: A.freshNonce(), sigs: [] };
  const key = by === 'anchor' ? anchorKey.key : by.subject.key;
  return A.signStatement(s, PRIV.get(key), key);
}
const grant = (by, subject, role, scope) => make(by, { kind: 'grant', subject, role, ...(scope ? { scope } : {}) });
const revoke = (by, targets) => make(by, { kind: 'revoke', targets: targets.map(sid) });
const endorse = (by, targets) => make(by, { kind: 'endorse', targets: targets.map(sid) });
function shuffled(list) { const a = [...list]; for (let i = a.length - 1; i > 0; i--) { const j = crypto.randomInt(i + 1); [a[i], a[j]] = [a[j], a[i]]; } return a; }
function offline(statements) {
  const st = new AuthorityStore({ pin: A.parsePin(PIN) });
  for (let pass = 0; pass < 6; pass++) for (const s of statements) st.ingest(s);
  return st;
}
/** A mesh with depth, removals, a rescue, an over-quota bucket and some forgeries. */
function scenery() {
  const gA = grant('anchor', party(), 'admin');
  const gB = grant('anchor', party(), 'admin');
  const gC = grant(gA, party(), 'admin');
  const gV = grant(gC, party(), 'validator');
  const P = Array.from({ length: 6 }, () => grant(gV, party(), 'participant'));
  const rV = revoke(gA, [gV]);
  const eP = endorse(gA, P.slice(0, 2));
  const D = Array.from({ length: 18 }, () => grant(gB, party(), 'issuer', 'test-world:w1'));
  const seats = D.map((d) => grant(d, party(), 'test-seat', 'test-world:w1'));
  const forged = { ...P[3], sigs: [{ key: anchorKey.key, sig: P[3].sigs[0].sig }] };
  return { all: [gA, gB, gC, gV, ...P, rV, eP, ...D, ...seats], forged: [forged] };
}

// ── Nodes ─────────────────────────────────────────────────────────────────────

const uniq = (b) => `${b}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
const made = [];
function node(base, opts = {}) {
  const n = new SymNode({ name: uniq(base), silent: true, discovery: new NullDiscovery(), room: 'auth', anchor: PIN, ...opts });
  made.push(n);
  return n;
}
async function stopAll() {
  for (const n of made.splice(0)) { try { await n.stop(); } catch { /* */ } try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ } }
}
const sessionTo = (n, other) => { const p = n._peers.get(other.nodeId); return p && p.transport; };
const confirmed = (n, other) => { const s = sessionTo(n, other); return !!(s && s.confirmed && !s.closed); };

describe('§6.6: the same statements in different orders, over real sessions, reach the same root', () => {
  it('two nodes fed over TCP on the loopback, children first on one and shuffled on the other', async () => {
    try {
      const { all, forged } = scenery();
      const want = offline(all);
      const lan = (room) => new BonjourDiscovery({ mdns: false, room, serviceType: `_${room}._tcp` });
      const r1 = `auth-a-${Math.random().toString(36).slice(2, 8)}`; const r2 = `auth-b-${Math.random().toString(36).slice(2, 8)}`;
      const X = node('auth-x', { discovery: lan(r1), room: r1 }); const F1 = node('auth-f1', { discovery: lan(r1), room: r1 });
      const Y = node('auth-y', { discovery: lan(r2), room: r2 }); const F2 = node('auth-f2', { discovery: lan(r2), room: r2 });
      for (const n of [X, F1, Y, F2]) await n.start();
      await until(() => confirmed(X, F1) && confirmed(F1, X) && confirmed(Y, F2) && confirmed(F2, Y), 15000);
      assert.ok(confirmed(X, F1) && confirmed(Y, F2), 'both pairs joined over TCP');
      // F1 and F2 hold nothing: they only carry frames. X gets every child before its chain (each
      // waits pending, fetched from F1, which has nothing to send); Y gets a shuffle. Forgeries too.
      const order1 = [...forged, ...offline(all).authorityOrder(new Set(all.map(sid))).reverse().map((e) => e.s)];
      const order2 = shuffled([...all, ...forged]);
      for (const s of order1) sessionTo(F1, X).send({ type: 'authority-statement', statement: s });
      for (const s of order2) sessionTo(F2, Y).send({ type: 'authority-statement', statement: s });
      await until(() => X.authorityRoot() === want.root() && Y.authorityRoot() === want.root(), 15000);
      assert.strictEqual(X.authorityRoot(), want.root());
      assert.strictEqual(Y.authorityRoot(), want.root());
      for (const s of all) assert.strictEqual(X._authority.statusOf(sid(s)), Y._authority.statusOf(sid(s)), 'the same status for every statement');
      // The carriers pull what they were told differs, and agree too.
      await until(() => F1.authorityRoot() === want.root() && F2.authorityRoot() === want.root(), 15000);
      assert.strictEqual(F1.authorityRoot(), want.root());
      assert.strictEqual(F2.authorityRoot(), want.root());
      assert.ok(X.authorityStatus().stats.pending > 0, 'X held statements pending for their chains');
      assert.ok(X.authorityStatus().stats.invalid >= 1, 'and refused the forgery');
    } finally { await stopAll(); }
  });

  it('a late joiner pulls the whole live set page by page after one digest; each page waits for the work the last one cost', async () => {
    try {
      // 150 grants, each naming a key the joiner has not seen: 17 checks apiece against a lane of 100 that
      // earns 2,000 a second. The pull is paced by that debt; nothing is dropped.
      const statements = Array.from({ length: 150 }, () => grant('anchor', party(), 'participant'));
      const X = node('auth-src'); const Z = node('auth-late');
      for (const s of statements) X._authority.ingest(s);
      X._authoritySettle();
      await X.start(); await Z.start();
      await connectNodes(Z, X);
      await until(() => Z.authorityRoot() === X.authorityRoot(), 15000);
      assert.strictEqual(Z.authorityRoot(), X.authorityRoot());
      assert.strictEqual(Z.authorityStatus().inForce, 150);
      assert.strictEqual(Z.authorityStatus().stats.overBudget, 0, 'an answer to its own pull is never dropped for budget');
      assert.ok(X.authorityStatus().stats.served >= 3, 'three pages of at most 64');
    } finally { await stopAll(); }
  });

  it('a pull longer than the responder\'s burst is paced, not refused: 1,100 statements in 18 pages arrive whole', async () => {
    try {
      const statements = Array.from({ length: 1100 }, () => grant('anchor', party(), 'participant'));
      const fast = { gossipBudget: { perSecond: 1e6, burst: 1e6, newLane: 1e6 } };
      const X = node('auth-src-big'); const Z = node('auth-late-big', fast);
      for (const s of statements) X._authority.ingest(s);
      X._authoritySettle();
      await X.start(); await Z.start();
      await connectNodes(Z, X);
      await until(() => Z.authorityRoot() === X.authorityRoot(), 30000);
      assert.strictEqual(Z.authorityRoot(), X.authorityRoot());
      assert.strictEqual(Z.authorityStatus().inForce, 1100);
    } finally { await stopAll(); }
  });
});

describe('§6.6.8: the frames, their bounds and pacing', () => {
  function rig(opts = {}) {
    const N = node('auth-frames', opts);
    const peer = identity('frames-peer');
    const s = admitAs(N, peer);
    N._sessions.add(s);
    return { N, s, sent: s.sent };
  }

  it('a fetch by ids answers each live statement with its chain and the in-force revokes and endorses naming it, and lists the rest missing', async () => {
    try {
      const { N, s, sent } = rig();
      const gA = grant('anchor', party(), 'admin');
      const gV = grant(gA, party(), 'validator');
      const gP = grant(gV, party(), 'participant');
      const rP = revoke(gA, [gP]);
      for (const x of [gA, gV, gP, rP]) N.submitAuthority(x);
      const ghost = `auth-${'0'.repeat(64)}`;
      deliver(N, s, { type: 'authority-fetch', reqId: 'q1', ids: [sid(gV), ghost] });
      const ans = sent.find((f) => f.type === 'authority-set' && f.reqId === 'q1');
      assert.ok(ans);
      assert.deepStrictEqual(ans.statements.map(sid), [sid(gA), sid(gV)], 'gV with its chain, in authority order');
      assert.deepStrictEqual(ans.missing, [ghost]);
      // gP is removed (not live): asking for it gives nothing; the revoke is live.
      deliver(N, s, { type: 'authority-fetch', reqId: 'q2', ids: [sid(rP)] });
      assert.deepStrictEqual(sent.find((f) => f.reqId === 'q2').statements.map(sid), [sid(gA), sid(rP)]);
      // Malformed fetches are not answered: both selectors, too many ids, repeated ids, a long reqId.
      const n = sent.length;
      deliver(N, s, { type: 'authority-fetch', reqId: 'b1', ids: [sid(gA)], after: '' });
      deliver(N, s, { type: 'authority-fetch', reqId: 'b2', ids: Array.from({ length: 65 }, (_, i) => `auth-${String(i).padStart(64, '0')}`) });
      deliver(N, s, { type: 'authority-fetch', reqId: 'b3', ids: [sid(gA), sid(gA)] });
      deliver(N, s, { type: 'authority-fetch', reqId: 'x'.repeat(129), ids: [sid(gA)] });
      assert.strictEqual(sent.length, n);
    } finally { await stopAll(); }
  });

  it('answers are paced per session: the burst at once, the rest in turn at 4 a second, at most 64 waiting; a repeated full pull is answered', async () => {
    try {
      const { N, s, sent } = rig();
      const { SERVE_BURST, SERVE_QUEUE_MAX } = require('../lib/node-authority');
      N.submitAuthority(grant('anchor', party(), 'participant'));
      deliver(N, s, { type: 'authority-fetch', reqId: 'full-1', after: '' });
      deliver(N, s, { type: 'authority-fetch', reqId: 'full-2', after: '' });
      assert.ok(sent.some((f) => f.reqId === 'full-1') && sent.some((f) => f.reqId === 'full-2'), 'sym does not refuse a fresh full pull');
      const answered = () => sent.filter((f) => f.type === 'authority-set').length;
      for (let i = 0; i < SERVE_BURST + SERVE_QUEUE_MAX + 5; i++) deliver(N, s, { type: 'authority-fetch', reqId: `q${i}`, ids: [`auth-${'1'.repeat(64)}`] });
      const now = answered();
      assert.ok(now >= SERVE_BURST && now <= SERVE_BURST + 1, `the burst is answered at once (${now})`);
      assert.strictEqual(s._authServeQueue.length, SERVE_QUEUE_MAX, 'the rest wait, at most 64; past that a request is dropped');
      await until(() => answered() >= now + 2, 2000);
      assert.ok(answered() >= now + 2, 'and the waiting ones are answered in turn');
    } finally { await stopAll(); }
  });

  it('a statement whose chain is not held is pending for its session: one fetch per missing id, at most 64 held, released with the session', async () => {
    try {
      const { N, s, sent } = rig({ gossipBudget: { newLane: 1e6, burst: 1e6 } });
      const gA = grant('anchor', party(), 'admin');
      const kids = Array.from({ length: 70 }, () => grant(gA, party(), 'participant'));
      for (const k of kids) deliver(N, s, { type: 'authority-statement', statement: k });
      assert.strictEqual(s._authPending.size, A.AUTHORITY_PENDING_MAX);
      const fetches = sent.filter((f) => f.type === 'authority-fetch');
      assert.deepStrictEqual(fetches.map((f) => f.ids), [[sid(gA)]], 'one fetch in flight for the missing id');
      // The answer to that fetch brings the chain: the pending statements come into force.
      deliver(N, s, { type: 'authority-set', reqId: fetches[0].reqId, statements: [gA] });
      await until(() => N._authority.size() === 65, 2000);
      assert.strictEqual(N._authority.size(), 1 + A.AUTHORITY_PENDING_MAX);
      assert.strictEqual(s._authPending.size, 0);
      // An answer nobody asked for is not ingested.
      const stray = grant('anchor', party(), 'admin');
      deliver(N, s, { type: 'authority-set', reqId: 'never-asked', statements: [stray] });
      assert.strictEqual(N._authority.has(sid(stray)), false);
      // A session closing releases what it held.
      deliver(N, s, { type: 'authority-statement', statement: grant(stray, party(), 'participant') });
      assert.strictEqual(s._authPending.size, 1);
      N._authorityReleaseSession(s);
      assert.strictEqual(s._authPending, null);
    } finally { await stopAll(); }
  });

  it('the lane is charged for keys not seen before, and repeats and statements not of the shape are free', async () => {
    try {
      const { N, s } = rig();
      const { FRESH_KEY_COST } = require('../lib/node-authority');
      N._gossipClock = () => 1_000_000; // a still clock: the lane does not refill during the test
      // A new peer's lane holds 100 checks; each grant names a fresh subject key (and the first, a fresh
      // signing key): 1 + 16 per fresh key, so about six are verified and the rest are over budget.
      const flood = Array.from({ length: 40 }, () => grant('anchor', party(), 'participant'));
      for (const f of flood) deliver(N, s, { type: 'authority-statement', statement: f });
      const held = N._authority.size();
      assert.ok(held >= 2 && held <= Math.floor(100 / (1 + FRESH_KEY_COST)), `a sixteenth of the checks (${held} held)`);
      assert.ok(N.authorityStatus().stats.overBudget > 0);
      // A repeat of a held statement, and a statement not of the shape, cost nothing.
      const tokens = () => N._gossipBuckets.get(s.nodeId).tokens;
      const before = tokens();
      const heldOne = flood.find((f) => N._authority.has(sid(f)));
      for (let i = 0; i < 500; i++) deliver(N, s, { type: 'authority-statement', statement: heldOne });
      for (let i = 0; i < 500; i++) deliver(N, s, { type: 'authority-statement', statement: { ...heldOne, nonce: 'short' } });
      assert.ok(tokens() >= before, 'nothing was spent');
      assert.ok(N.authorityStatus().stats.duplicate >= 500);
    } finally { await stopAll(); }
  });

  it('a statement refused for capacity says nothing against its sender: no relay failure, no mute', async () => {
    try {
      const { N, s } = rig({ gossipBudget: { newLane: 1e6, burst: 1e6 } });
      N._authority._maxHeld = 20;
      const gA = grant('anchor', party(), 'admin');
      const sub = grant(gA, party(), 'admin');
      N.submitAuthority(gA); N.submitAuthority(sub);
      for (let i = 0; i < 18; i++) N.submitAuthority(grant(gA, party(), 'participant'));
      for (let i = 0; i < 30; i++) deliver(N, s, { type: 'authority-statement', statement: grant(sub, party(), 'participant') });
      assert.ok(N.authorityStatus().stats.overCapacity >= 1, 'some were refused for capacity');
      assert.strictEqual(N._relayMuted(s.nodeId, 'authority-statements'), false);
    } finally { await stopAll(); }
  });

  it('a differing digest starts a pull; an equal one does not; a malformed one is ignored', async () => {
    try {
      const { N, s, sent } = rig({ gossipBudget: { newLane: 1e6, burst: 1e6 } });
      N.submitAuthority(grant('anchor', party(), 'participant'));
      deliver(N, s, { type: 'authority-digest', root: N.authorityRoot(), count: 1 });
      deliver(N, s, { type: 'authority-digest', root: 'nothex', count: 1 });
      assert.ok(!sent.some((f) => f.type === 'authority-fetch'));
      deliver(N, s, { type: 'authority-digest', root: 'a'.repeat(64), count: 3 });
      const pull = sent.filter((f) => f.type === 'authority-fetch');
      assert.strictEqual(pull.length, 1);
      assert.strictEqual(pull[0].after, '');
    } finally { await stopAll(); }
  });

  it('the retired time-replay frames are ignored, counted, and never sent', async () => {
    try {
      const { N, s, sent } = rig();
      for (const type of RETIRED_FRAMES) deliver(N, s, { type, grant: { type: 'role-grant', role: 'anchor' } });
      assert.strictEqual(N.authorityStatus().stats.retired, RETIRED_FRAMES.size);
      assert.strictEqual(N._authority.size(), 0);
      assert.ok(!sent.some((f) => RETIRED_FRAMES.has(f.type)));
    } finally { await stopAll(); }
  });

  it('with no anchor pinned the frames do nothing and nothing is sent', async () => {
    try {
      const N = node('auth-unanchored', { anchor: null });
      const s = admitAs(N, identity('u'));
      deliver(N, s, { type: 'authority-statement', statement: grant('anchor', party(), 'admin') });
      deliver(N, s, { type: 'authority-fetch', reqId: 'q', after: '' });
      deliver(N, s, { type: 'authority-digest', root: 'a'.repeat(64), count: 1 });
      for (let i = 0; i < 20; i++) deliver(N, s, { type: 'authority-statement', statement: grant('anchor', party(), 'admin') });
      assert.strictEqual(N._authority.size(), 0);
      assert.deepStrictEqual(s.sent.filter((f) => /^authority-/.test(f.type)), []);
      assert.strictEqual(N._relayMuted(s.nodeId, 'authority-statements'), false, 'what it cannot judge counts nothing against the session');
      assert.strictEqual(N.authorityStatus().stats.invalid, 0);
    } finally { await stopAll(); }
  });
});

describe('§6.6.9 and §6.6.10 on a node', () => {
  it('an in-force grant is a binding source; a conflicting one leaves the binding as it was; one naming this node with a foreign key confers nothing and is reported', async () => {
    try {
      const N = node('auth-view');
      const p = party(); const q = party(); const qOther = party();
      N._roster.bind(q.nodeId, q.key, 'proven');
      const metrics = [];
      N.on('metric', (m) => metrics.push(m));
      N.submitAuthority(grant('anchor', p, 'validator'));
      N.submitAuthority(grant('anchor', { nodeId: q.nodeId, key: qOther.key }, 'admin'));
      const foreign = grant('anchor', { nodeId: N.nodeId, key: qOther.key }, 'admin');
      N.submitAuthority(foreign);
      assert.strictEqual(N._identityKey(p.nodeId), p.key, 'the grant taught the key');
      assert.strictEqual(N._identityKey(q.nodeId), q.key, 'a proven binding stays');
      assert.strictEqual(N.resolveRole(q.nodeId), 'participant', 'roles follow the key the node is bound to');
      assert.strictEqual(N.resolveRole(N.nodeId), 'participant', 'a grant to this nodeId with a foreign key confers nothing');
      assert.ok(metrics.some((m) => m.type === 'authority-foreign-self-key' && m.id === sid(foreign)));
    } finally { await stopAll(); }
  });

  it('a received record\'s origin role is its author\'s authority over it now; a scoped grant counts only inside its scope', async () => {
    try {
      const world = (p, cmb) => !!(cmb && cmb.world === p);
      const N = node('auth-origin', { authorityScopes: { 'test-world': world } });
      const admin = party(); const scoped = party();
      const gAdmin = grant('anchor', admin, 'admin');
      N.submitAuthority(gAdmin);
      N.submitAuthority(grant('anchor', scoped, 'validator', 'test-world:w1'));
      const msg = (who, cmb) => ({ _cmbVerified: true, _verifiedAuthorNodeId: who.nodeId, _authorKey: who.key, cmb });
      assert.strictEqual(N._authorOriginRole(msg(admin, {})), 'admin');
      assert.strictEqual(N._authorOriginRole(msg(scoped, { world: 'w1' })), 'validator');
      assert.strictEqual(N._authorOriginRole(msg(scoped, { world: 'w2' })), 'participant');
      assert.strictEqual(N._authorOriginRole({ ...msg(admin, {}), _cmbVerified: false }), 'participant', 'an unverified record counts with nothing');
      N.submitAuthority(revoke('anchor', [gAdmin]));
      assert.strictEqual(N._authorOriginRole(msg(admin, {})), 'participant', 'judged when used: the revoke is in force');
    } finally { await stopAll(); }
  });
});

describe('§6.6.7: persistence carries no authority of its own', () => {
  it('one file, whatever the pin: every statement judged again at load, in any order; what does not count is kept as bytes, never deleted', async () => {
    const name = uniq('auth-persist');
    let nodeId = null;
    try {
      const { all } = scenery();
      const want = offline(all);
      const N = new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: 'auth', anchor: PIN });
      nodeId = N.nodeId;
      for (const s of all) N.submitAuthority(s);
      assert.strictEqual(N.authorityRoot(), want.root());
      await N.stop();
      const file = path.join(nodeDirById(nodeId), 'authority', 'statements.jsonl');
      const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean);
      for (const l of lines) {
        const o = JSON.parse(l);
        for (const k of Object.keys(o)) assert.ok(['kind', 'authorisedBy', 'subject', 'role', 'scope', 'targets', 'nonce', 'issuedAt', 'sigs'].includes(k), `only statement members on disk (${k})`);
      }
      const planted = grant('anchor', party(), 'admin');
      planted.sigs = [{ key: anchorKey.key, sig: all[5].sigs[0].sig }];
      fs.writeFileSync(file, [...shuffled(lines), JSON.stringify(planted), '{not json'].join('\n') + '\n');
      const N2 = new SymNode({ name, nodeId, create: false, silent: true, discovery: new NullDiscovery(), room: 'auth', anchor: PIN });
      assert.strictEqual(N2.authorityRoot(), want.root());
      assert.strictEqual(N2._authority.has(sid(planted)), false, 'a forgery counts for nothing');
      const report = N2._authority.loadReport();
      assert.strictEqual(report.corrupt, 1, 'a line that is not a statement is dropped');
      assert.strictEqual(report.unverified, 1, 'a statement that does not count under this pin is kept, as the bytes it was');
      await N2.stop();
      assert.ok(fs.readFileSync(file, 'utf8').includes(JSON.stringify(planted)), 'still on disk');
      // A mistyped pin: nothing is held, and nothing is deleted.
      const other = party();
      const N3 = new SymNode({ name, nodeId, create: false, silent: true, discovery: new NullDiscovery(), room: 'auth', anchor: { threshold: 1, keys: [{ key: other.key }] } });
      assert.strictEqual(N3._authority.size(), 0);
      await N3.stop();
      assert.strictEqual(fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).length, lines.length + 1, 'every statement is still in the file');
      // The pin corrected: everything counts again.
      const N4 = new SymNode({ name, nodeId, create: false, silent: true, discovery: new NullDiscovery(), room: 'auth', anchor: PIN });
      assert.strictEqual(N4.authorityRoot(), want.root());
      await N4.stop();
    } finally { if (nodeId) fs.rmSync(nodeDirById(nodeId), { recursive: true, force: true }); }
  });

  it('a re-pin that keeps a threshold of the old keys keeps what they signed (§6.6.1): 2 of 3 re-pinned to 2 of 2', () => {
    const dir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'auth-repin-'));
    try {
      const k1 = party(); const k2 = party(); const k3 = party();
      const pin3 = A.parsePin({ threshold: 2, keys: [{ key: k1.key }, { key: k2.key }, { key: k3.key }] });
      const anchorBy = (fields, signers) => { let st = { ...fields, authorisedBy: 'anchor', nonce: A.freshNonce(), sigs: [] }; for (const k of signers) st = A.signStatement(st, PRIV.get(k.key), k.key); return st; };
      const gA = anchorBy({ kind: 'grant', subject: party(), role: 'admin' }, [k1, k2]);
      const gV = grant(gA, party(), 'validator');
      const gP = grant(gV, party(), 'participant');
      const st = new AuthorityStore({ pin: pin3, dir });
      for (const x of [gA, gV, gP]) assert.strictEqual(st.ingest(x).result, 'held');
      const pin2 = A.parsePin({ threshold: 2, keys: [{ key: k1.key }, { key: k2.key }] }); // k3 dropped
      const re = new AuthorityStore({ pin: pin2, dir });
      assert.strictEqual(re.resolve().inForce.size, 3, 'the same three statements, in force under the new pin');
      // And back under a pin they do not satisfy: none counts, none is lost.
      const lone = A.parsePin({ threshold: 1, keys: [{ key: k3.key }] });
      assert.strictEqual(new AuthorityStore({ pin: lone, dir }).size(), 0);
      assert.strictEqual(new AuthorityStore({ pin: pin2, dir }).resolve().inForce.size, 3);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('a torn append costs nothing: each record starts on a line of its own', () => {
    const dir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'auth-torn-'));
    try {
      const gA = grant('anchor', party(), 'admin');
      const gV = grant(gA, party(), 'validator');
      const gP = grant(gV, party(), 'participant');
      const st = new AuthorityStore({ pin: A.parsePin(PIN), dir });
      st.ingest(gA);
      fs.appendFileSync(path.join(dir, 'statements.jsonl'), JSON.stringify(gV).slice(0, 40)); // a write cut short
      st.ingest(gV); st.ingest(gP);
      const again = new AuthorityStore({ pin: A.parsePin(PIN), dir });
      assert.strictEqual(again.size(), 3, 'only the torn bytes are lost');
      assert.strictEqual(again.loadReport().corrupt, 1);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
});

describe('§6.6.8: the asking rule bounds what a session can make this node verify', () => {
  // M holds no grant. It makes X ask (a digest naming a root X lacks; pending statements whose
  // links X fetches) and answers every ask with 64 statements under fresh keys: the most costly an
  // answer can be. X verifies no more than M's lane at X pays for, and the lane never goes negative.
  const pendingGrant = () => {
    const signer = party(); const sub = party();
    return A.signStatement({ kind: 'grant', authorisedBy: `auth-${crypto.randomBytes(32).toString('hex')}`, subject: sub, role: 'participant', nonce: A.freshNonce(), sigs: [] }, PRIV.get(signer.key), signer.key);
  };
  async function scene({ pages, open }) {
    const X = node('ask-x'); const M = node('ask-m', { anchor: null });
    await X.start(); await M.start();
    await connectNodes(M, X);
    const pool = Array.from({ length: pages * 64 }, pendingGrant);
    let answered = 0;
    M._onAuthorityFetch = (session, msg) => {
      if (answered >= pages) return;
      const page = pool.slice(answered * 64, answered * 64 + 64); answered++;
      session.send({ type: 'authority-digest', root: crypto.randomBytes(32).toString('hex'), count: 1 });
      session.send({ type: 'authority-set', reqId: msg.reqId, statements: page });
    };
    const verified = () => { const st = X._authorityStats; return st.pending + st.invalid + st.held; };
    let lowest = Infinity;
    const watch = setInterval(() => { const b = X._gossipBuckets.get(M.nodeId); if (b && b.tokens < lowest) lowest = b.tokens; }, 5);
    const t0 = Date.now();
    open(M._peers.get(X.nodeId).transport);
    await new Promise((r) => setTimeout(r, 3000));
    clearInterval(watch);
    const secs = (Date.now() - t0) / 1000;
    return { X, M, secs, verified: verified(), lowest, answered };
  }
  it('a digest-driven pull loop: X pulls only when M\'s lane can pay a page', async () => {
    try {
      const r = await scene({ pages: 60, open: (toX) => toX.send({ type: 'authority-digest', root: crypto.randomBytes(32).toString('hex'), count: 1 }) });
      const allows = (100 + 2000 * r.secs) / 33 + 64;
      assert.ok(r.verified <= allows, `verified ${r.verified}, the lane pays for ${allows.toFixed(0)}`);
      assert.ok(r.answered >= 1, 'X did pull');
      assert.ok(r.lowest >= 0, `the lane never went negative (lowest ${r.lowest})`);
    } finally { await stopAll(); }
  });
  it('a fetch cascade: pending statements ask for their links under the same rule, and a full pending hold refuses before verifying', async () => {
    try {
      const r = await scene({ pages: 64, open: (toX) => { for (let i = 0; i < 64; i++) toX.send({ type: 'authority-statement', statement: pendingGrant() }); } });
      const allows = (100 + 2000 * r.secs) / 33 + 64;
      assert.ok(r.verified <= allows, `verified ${r.verified}, the lane pays for ${allows.toFixed(0)}`);
      assert.ok(r.lowest >= 0, `the lane never went negative (lowest ${r.lowest})`);
      assert.ok(r.X._authorityStats.pendingFull > 0, 'past 64 pending, refused before any signature check');
    } finally { await stopAll(); }
  });
  it('a pull that ends with the roots apart is started again, after a backoff that doubles', async () => {
    try {
      const X = node('repull-x', { gossipBudget: { newLane: 1e6, burst: 1e6 } }); const M = node('repull-m', { anchor: null });
      await X.start(); await M.start();
      await connectNodes(M, X);
      const at = [];
      M._onAuthorityFetch = (session, msg) => { at.push(Date.now()); session.send({ type: 'authority-set', reqId: msg.reqId, statements: [] }); };
      M._peers.get(X.nodeId).transport.send({ type: 'authority-digest', root: 'b'.repeat(64), count: 1 });
      await until(() => at.length >= 3, 9000);
      assert.ok(at.length >= 3, 'pulled again while the roots stay apart');
      assert.ok(at[2] - at[1] > (at[1] - at[0]) * 1.5, 'each wait longer than the last');
      // The peer reports X's root: no more pulls.
      M._peers.get(X.nodeId).transport.send({ type: 'authority-digest', root: X.authorityRoot(), count: 0 });
      const n = at.length;
      await new Promise((r) => setTimeout(r, 3000));
      assert.strictEqual(at.length, n);
    } finally { await stopAll(); }
  });
});

describe('§6.6.8: a fetch answer is the closure', () => {
  it('an endorse that keeps a rescued revoke in force goes with it, so the asker reaches the same root', () => {
    const pin = A.parsePin(PIN);
    const Ak = party(); const Pk = party(); const Gk = party(); const Kk = party();
    const gA = grant('anchor', Ak, 'admin'); const gP = grant(gA, Pk, 'admin'); const gG = grant(gP, Gk, 'admin'); const gK = grant(gG, Kk, 'participant');
    const R = revoke(gP, [gG]); const rP = revoke('anchor', [gP]); const E = endorse(gA, [R]); const E2 = endorse(gA, [gK]);
    const Y = new AuthorityStore({ pin });
    for (let i = 0; i < 3; i++) for (const x of [gA, gP, gG, gK, R, rP, E, E2]) Y.ingest(x);
    const ans = Y.answerIds([sid(gK)]);
    assert.ok(ans.statements.some((x) => sid(x) === sid(E)), 'the endorse of the revoke is in the answer');
    const X = new AuthorityStore({ pin });
    for (const x of ans.statements) X.ingest(x);
    assert.strictEqual(X.statusOf(sid(R)), Y.statusOf(sid(R)));
    assert.strictEqual(X.root(), Y.root());
  });
});


