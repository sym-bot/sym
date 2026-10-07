'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * The 0.14.0 re-review at 72daeb6 (docs/handover/agent-a/sym-0.14.0-rereview-notes.txt in
 * sym-bot/xmesh): each finding as a regression test that fails on 72daeb6 for its own reason.
 *
 *   N1  the forgery penalty is charged only to a session that signed in its own name
 *   N2  a revoke carries a cutoff; receipt time is no part of the rule
 *   N3  a verified directed record earns its author a durable binding
 *   N4  no cap refuses a revoke
 *   N5  a 0.13 grant store is never rewritten, so nothing skipped at load is lost
 *   caps  record size limits that fit one sealed frame (draft spec PR #37)
 *   leads the open leads the notes left
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const { signAttestation, signCheckpoint, signWitness, signGrant } = require('../lib/core');
const { identity, connectNodes, until, signedRecord, admitAs, deliver } = require('./_core-secure');

const uniq = (b) => `${b}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
function mk(base, extra = {}) { return new SymNode({ name: uniq(base), silent: true, discovery: new NullDiscovery(), room: extra.room || 'rr', ...extra }); }
async function stopAll(...nodes) {
  for (const n of nodes) { try { await n.stop(); } catch { /* */ } try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ } }
}
const hex = () => crypto.randomBytes(32).toString('hex');
const CATS7 = { focus: 'admit', issue: 'admit', intent: 'guard', motivation: 'admit', commitment: 'silent', perspective: 'admit', mood: 'admit' };
const signedAs = (fields, priv, sign) => { const o = { ...fields }; sign(o, priv); return o; };

describe('N1: the forgery penalty is charged only to a session that signed in its own name', () => {
  it('a squatter holds X\'s nodeId here: an honest peer relaying X\'s genuine statements keeps its session, and they are dropped, not stored', async () => {
    const ANC = identity('anchor-n1');
    const b = mk('n1-b', { anchor: { nodeId: ANC.nodeId, publicKey: ANC.publicKey } });
    try {
      await b.start();
      const metrics = [];
      b.on('metric', (m) => metrics.push(m));
      const X = identity('x-genuine');
      const Km = identity('m-squatter');
      // The squatter M proved a session as X under its own key: X -> Km is X's session-scoped binding here.
      const sM = admitAs(b, { nodeId: X.nodeId, name: 'm-as-x', publicKey: Km.publicKey });
      assert.strictEqual(b._identityKey(X.nodeId), Km.publicKey, 'the scene: the squatter\'s key verifies X here');
      const A = identity('a-honest');
      const sA = admitAs(b, A);

      // 1. X's genuine record, relayed by A.
      deliver(b, sA, { type: 'cmb', cmb: signedRecord(X, { categories: { focus: 'X said this' }, room: b._room }) });
      // 2. X's genuine attestation, checkpoint and witness, relayed by A.
      b._ingestAttestation(signedAs({ of: `cmb-${hex()}`, by: X.nodeId, at: Date.now(), roster: b._room, verdict: 'aligned', categories: CATS7, seq: 1, prev: 'genesis' }, X.privateKey, signAttestation), A.nodeId, A.name, sA);
      b._ingestCheckpoint(signedAs({ by: X.nodeId, upto_seq: 1, root: hex(), at: Date.now(), roster: b._room }, X.privateKey, signCheckpoint), A.nodeId, sA);
      b._ingestWitness(signedAs({ attester: A.nodeId, upto_seq: 1, root: hex(), by: X.nodeId, role: 'participant', at: Date.now(), roster: b._room }, X.privateKey, signWitness), A.nodeId, sA);
      // 3. A grant by G, whom the anchor vouched here under K1 and elsewhere under K2, signed with K2.
      const G1 = identity('g-k1'); const G2 = { ...identity('g-k2'), nodeId: G1.nodeId };
      const W = identity('w');
      b._roleGrants.record(signGrant({ type: 'role-grant', grantee: G1.nodeId, role: 'validator', grantedBy: ANC.nodeId, grantedAt: Date.now() - 10_000, granteeKey: G1.publicKey }, ANC.privateKey));
      deliver(b, sA, { type: 'role-grant', grant: signGrant({ type: 'role-grant', grantee: W.nodeId, role: 'validator', grantedBy: G2.nodeId, grantedAt: Date.now() - 5_000, granteeKey: W.publicKey }, G2.privateKey) });

      assert.strictEqual(sA.closed, false, 'the honest relayer\'s session is not closed');
      assert.strictEqual(b._penalised(A.nodeId), false, 'and the relayer is not refused');
      const kinds = metrics.filter((m) => m.type === 'relayed-signature-unverified' && m.peer === A.nodeId).map((m) => m.kind).sort();
      assert.deepStrictEqual(kinds, ['attestation', 'checkpoint', 'record', 'role-grant', 'witness'], 'each relayed statement is dropped and counted');
      assert.ok(!metrics.some((m) => m.type === 'forged-signature'), 'none is called a forgery');
      assert.strictEqual(b._store.allEntries().length, 0, 'the record is not stored');
      assert.strictEqual(b._roleGrants.size(), 1, 'the grant is not stored');

      // The squatter's session delivering a record in its own name (X) that its proven key did not
      // sign is attributable: it is closed and refused.
      deliver(b, sM, { type: 'cmb', cmb: signedRecord(X, { categories: { focus: 'X said this too' }, room: b._room }) });
      assert.strictEqual(sM.closed, true, 'the session that sent a record in its own name its key did not sign is closed');
      assert.strictEqual(b._penalised(X.nodeId), true);
    } finally { await stopAll(b); }
  });

  it('a statement in the session\'s own name that fails under a key the session did not prove is a view mismatch, not a forgery', async () => {
    const ANC = identity('anchor-n1b');
    const b = mk('n1b-b', { anchor: { nodeId: ANC.nodeId, publicKey: ANC.publicKey } });
    try {
      await b.start();
      const metrics = [];
      b.on('metric', (m) => metrics.push(m));
      // The anchor vouched G under K1 here; G's session proves K2 (another node holds the grant
      // vouching K2, this one does not yet).
      const G1 = identity('g-k1'); const G2 = { ...identity('g-k2'), nodeId: G1.nodeId };
      const W = identity('w');
      b._roleGrants.record(signGrant({ type: 'role-grant', grantee: G1.nodeId, role: 'validator', grantedBy: ANC.nodeId, grantedAt: Date.now() - 10_000, granteeKey: G1.publicKey }, ANC.privateKey));
      const sG2 = admitAs(b, { nodeId: G2.nodeId, name: 'g-k2', publicKey: G2.publicKey });
      deliver(b, sG2, { type: 'role-grant', grant: signGrant({ type: 'role-grant', grantee: W.nodeId, role: 'validator', grantedBy: G2.nodeId, grantedAt: Date.now() - 5_000, granteeKey: W.publicKey }, G2.privateKey) });
      assert.strictEqual(sG2.closed, false, 'its proven key is not one this node\'s chain vouches for G: not attributable');
      assert.ok(metrics.some((m) => m.type === 'relayed-signature-unverified' && m.kind === 'role-grant'));
      // G's session under the vouched key K1, sending a grant in its own name its key did not sign: a forgery.
      sG2.closed = true;
      const sG1 = admitAs(b, { nodeId: G1.nodeId, name: 'g-k1', publicKey: G1.publicKey });
      const forged = signGrant({ type: 'role-grant', grantee: W.nodeId, role: 'validator', grantedBy: G1.nodeId, grantedAt: Date.now() - 4_000, granteeKey: W.publicKey }, G2.privateKey);
      deliver(b, sG1, { type: 'role-grant', grant: forged });
      assert.strictEqual(sG1.closed, true, 'attributable: closed');
      assert.ok(metrics.some((m) => m.type === 'forged-signature' && m.kind === 'role-grant'));
    } finally { await stopAll(b); }
  });
});

describe('N3: a verified directed record earns its author a durable binding', () => {
  it('a peer that only exchanges directed records is bound durably: after it leaves, a squatter with its nodeId is refused (1009)', async () => {
    const b = mk('n3-b'); const x = mk('n3-x');
    try {
      await b.start(); await x.start();
      await connectNodes(x, b);
      const got = [];
      b.on('message', (from, text) => got.push(text));
      x.send('a directed message, never stored', { to: b.nodeId });
      await until(() => got.length > 0, 3000);
      assert.deepStrictEqual(got, ['a directed message, never stored']);
      assert.strictEqual(b._store.allEntries().length, 0, 'nothing was admitted to memory');
      assert.strictEqual(b._roster.get(x.nodeId), x._identity.publicKey, 'the directed exchange earned a durable binding');
      assert.strictEqual(b._roster.source(x.nodeId), 'proven');

      await x.stop();
      await until(() => !b._peers.has(x.nodeId), 3000);
      assert.strictEqual(b._identityKey(x.nodeId), x._identity.publicKey, 'the binding outlives the session');
      // A squatter's confirmed session for x's nodeId under another key: refused with 1009.
      const Km = identity('m');
      const sent = [];
      const squat = { nodeId: x.nodeId, name: 'squatter', identityKey: Km.publicKey, kind: 'relay', relayFrom: x.nodeId, confirmed: true, closed: false, sessionId: hex().slice(0, 32),
        trySend(f) { sent.push(f); return { ok: true }; }, send(f) { sent.push(f); return true; }, close(reason) { this.closed = true; this.closedReason = reason; } };
      b._admitSession(squat);
      assert.strictEqual(squat.closed, true);
      assert.strictEqual(squat.closedReason, 'key-conflict');
      assert.ok(sent.some((f) => f.type === 'error' && f.code === 1009), 'sealed 1009 IDENTITY_CONFLICT');
    } finally { await stopAll(b, x); }
  });

  it('a directed record SVAF does not admit (remixed:false) earns the binding too; a broadcast SVAF refuses does not', async () => {
    const b = mk('n3b-b');
    try {
      await b.start();
      const X = identity('x'); const Y = identity('y');
      const sX = admitAs(b, X); const sY = admitAs(b, Y);
      b._svafEvaluator.evaluate = async () => ({ decision: 'rejected', total_drift: 0.99, category_drifts: {}, gate_values: {} });
      const accepted = [];
      b.on('cmb-accepted', (e) => accepted.push(e));
      deliver(b, sX, { type: 'cmb', cmb: signedRecord(X, { categories: { focus: 'for b only' }, room: b._room, to: b.nodeId }) });
      deliver(b, sY, { type: 'cmb', cmb: signedRecord(Y, { categories: { focus: 'for the room' }, room: b._room }) });
      await until(() => accepted.length > 0, 2000);
      await new Promise((r) => setTimeout(r, 100));
      assert.ok(accepted.some((e) => e.remixed === false && e.directed === true), 'the directed record surfaced unstored');
      assert.strictEqual(b._roster.get(X.nodeId), X.publicKey, 'directed: earned');
      assert.strictEqual(b._roster.get(Y.nodeId), undefined, 'a refused broadcast earns nothing');
      void sX; void sY;
    } finally { await stopAll(b); }
  });
});

// ── Role grants (N2, N4, N5) ───────────────────────────────────────────────────────────────────────
const { RoleGrantStore } = require('../lib/role-grant-store');
const { grantPayload, verifyGrant } = require('../lib/core/role-grant');
function kp(nodeId) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { nodeId: nodeId || crypto.randomUUID(), priv: privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(16).toString('base64url'), pub: publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('base64url') };
}
const grantOf = (type, grantee, role, grantor, at, extra = {}) => signGrant({ type, grantee: grantee.nodeId, ...(role ? { role } : {}), grantedBy: grantor.nodeId, grantedAt: at, ...(type === 'role-grant' ? { granteeKey: grantee.pub } : {}), ...extra }, grantor.priv);

describe('N2: a revoke carries a cutoff; when a node received anything is no part of the rule', () => {
  // V legitimately revokes W on "day 1"; the anchor revokes V on "day 3" (its cutoff: day 3).
  const ANC = kp(), V = kp(), W = kp();
  const t = Date.now() - 1_000_000;
  const R = {
    AV: grantOf('role-grant', V, 'validator', ANC, t),
    AW: grantOf('role-grant', W, 'validator', ANC, t + 1),
    rVW: grantOf('role-revoke', W, undefined, V, t + 100_000),
    rAV: grantOf('role-revoke', V, undefined, ANC, t + 300_000),
  };
  const roleOfW = (store) => store.resolveRole(W.nodeId, W.pub, Date.now());

  it('an early receiver, a late receiver and a store upgraded from 0.13 all resolve W as revoked', () => {
    // The early receiver was online on day 1: each record reached it moments after it was signed.
    const clock = { now: t };
    const early = new RoleGrantStore({ anchor: { nodeId: ANC.nodeId, publicKey: ANC.pub }, now: () => clock.now });
    for (const k of ['AV', 'AW', 'rVW', 'rAV']) { clock.now = R[k].grantedAt + 500; assert.strictEqual(early.record(R[k]).stored, true, k); }
    clock.now = Date.now();
    assert.strictEqual(roleOfW(early), 'participant', 'early receiver');
    const late = new RoleGrantStore({ anchor: { nodeId: ANC.nodeId, publicKey: ANC.pub } });
    for (const k of ['AV', 'AW', 'rAV']) late.record(R[k]);
    assert.strictEqual(late.record(R.rVW).stored, true, 'V\'s revoke, signed before V\'s cutoff, stands when it arrives after V\'s own revoke');
    assert.strictEqual(roleOfW(late), 'participant', 'late receiver');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'n2-upgrade-'));
    try {
      // A 0.13 store: bare lines, no receipt times, in the order 0.13 happened to write them.
      fs.writeFileSync(path.join(dir, 'role-grants.jsonl'), ['AV', 'AW', 'rAV', 'rVW'].map((k) => JSON.stringify(R[k])).join('\n') + '\n');
      const upgraded = new RoleGrantStore({ anchor: { nodeId: ANC.nodeId, publicKey: ANC.pub }, dir });
      assert.strictEqual(upgraded.loadReport().loaded, 4);
      assert.strictEqual(roleOfW(upgraded), 'participant', 'upgraded store');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('a newcomer that learns the store by anti-entropy sync resolves W as revoked', async () => {
    const boot = (b) => new SymNode({ name: uniq(b), silent: true, discovery: new NullDiscovery(), room: 'n2', anchor: { nodeId: ANC.nodeId, publicKey: ANC.pub } });
    const P = boot('n2-p'); const N = boot('n2-n');
    try {
      await P.start(); await N.start();
      for (const k of ['AV', 'AW', 'rVW', 'rAV']) assert.strictEqual(P._roleGrants.record(R[k]).stored, true);
      await connectNodes(P, N);
      await until(() => N._roleGrants.size() === 4, 3000);
      assert.strictEqual(N._roleGrants.size(), 4, 'the whole store arrived');
      assert.strictEqual(N.resolveRole(W.nodeId, Date.now(), { key: W.pub }), 'participant');
    } finally { await stopAll(P, N); }
  });

  it('the cutoff reaches back: what the revoked node signed at or after it never counts, even before the revoke was signed', () => {
    const X = kp();
    const store = new RoleGrantStore({ anchor: { nodeId: ANC.nodeId, publicKey: ANC.pub } });
    store.record(R.AV); store.record(R.AW);
    assert.strictEqual(store.record(grantOf('role-revoke', V, undefined, ANC, t + 300_000, { cutoff: t + 50_000 })).stored, true);
    assert.strictEqual(store.resolveRole(V.nodeId, V.pub, t + 40_000), 'validator', 'before the cutoff');
    assert.strictEqual(store.resolveRole(V.nodeId, V.pub, t + 60_000), 'participant', 'from the cutoff, before the revoke was signed');
    assert.deepStrictEqual(store.record(R.rVW), { stored: false, reason: 'unrooted' }, 'V\'s revoke of W, signed after the cutoff, does not count');
    assert.strictEqual(roleOfW(store), 'validator');
    assert.strictEqual(store.record(grantOf('role-grant', X, 'validator', V, t + 10_000)).stored, true, 'V\'s grant before the cutoff stands as a statement');
  });

  it('a revoker reaches back only over time it was itself authorised for', () => {
    const Q = kp(); const X = kp();
    const store = new RoleGrantStore({ anchor: { nodeId: ANC.nodeId, publicKey: ANC.pub } });
    store.record(grantOf('role-grant', X, 'validator', ANC, t));
    store.record(grantOf('role-grant', Q, 'validator', ANC, t + 200_000)); // Q a validator from t+200 s
    assert.deepStrictEqual(store.record(grantOf('role-revoke', X, undefined, Q, t + 300_000, { cutoff: t + 100_000 })), { stored: false, reason: 'unrooted' }, 'a cutoff before Q held rank');
    assert.strictEqual(store.record(grantOf('role-revoke', X, undefined, Q, t + 300_000, { cutoff: t + 250_000 })).stored, true);
  });

  it('wire: a revoke without a cutoff signs the bytes 0.13 signed; the cutoff is signed when present, at most the revoke\'s time, only on a revoke', () => {
    const r = { type: 'role-revoke', grantee: 'g', grantedBy: 'b', grantedAt: 5 };
    assert.strictEqual(grantPayload(r).toString(), 'role-revoke|g||b|5|');
    assert.strictEqual(grantPayload({ ...r, cutoff: 3 }).toString(), 'role-revoke|g||b|5||3');
    const c = grantOf('role-revoke', W, undefined, ANC, t + 10, { cutoff: t });
    assert.strictEqual(verifyGrant(c, ANC.pub).valid, true);
    assert.strictEqual(verifyGrant({ ...c, cutoff: t + 1 }, ANC.pub).valid, false, 'the cutoff is signed');
    const store = new RoleGrantStore({ anchor: { nodeId: ANC.nodeId, publicKey: ANC.pub } });
    assert.strictEqual(store.record(grantOf('role-revoke', W, undefined, ANC, t, { cutoff: t + 1 })).reason, 'malformed', 'a cutoff after the revoke');
    assert.strictEqual(store.record(grantOf('role-grant', W, 'validator', ANC, t, { cutoff: t })).reason, 'malformed', 'a cutoff on a grant');
    assert.strictEqual(store.record(grantOf('role-revoke', W, undefined, ANC, t, { granteeKey: 'abc|1' })).reason, 'malformed', 'a revoke key that is not a key');
    store.record(c);
    assert.strictEqual(store.grantsFor(W.nodeId)[0].cutoff, t, 'kept with its cutoff');
  });
});

describe('N4: no cap refuses a revoke; revokes are bounded by their grants', () => {
  it('past every grant cap a validator can still revoke; one revoke per grant its grantee holds', () => {
    const A = kp(), M = kp(), H = kp(), X = kp();
    const store = new RoleGrantStore({ anchor: { nodeId: A.nodeId, publicKey: A.pub }, maxPerGrantor: 2, maxPerPair: 1, maxGrants: 5 });
    const t = Date.now() - 100_000;
    store.record(grantOf('role-grant', M, 'validator', A, t));
    store.record(grantOf('role-grant', H, 'validator', A, t));
    assert.strictEqual(store.record(grantOf('role-grant', X, 'validator', H, t + 1)).stored, true, 'H grants X (H\'s pair with X is now full)');
    // M fills what is left of the store with sybil grants.
    for (let i = 0; i < 2; i++) store.record(grantOf('role-grant', kp(), 'validator', M, t + 2 + i));
    assert.strictEqual(store.record(grantOf('role-grant', kp(), 'validator', H, t + 9)).reason, 'store-full', 'the grant caps are full');
    const rHX = grantOf('role-revoke', X, undefined, H, t + 10);
    assert.strictEqual(store.record(rHX).stored, true, 'H\'s revoke of X is kept: pair-full, grantor-full and store-full never refuse a revoke');
    assert.strictEqual(store.resolveRole(X.nodeId, X.pub, Date.now()), 'participant');
    const rHM = grantOf('role-revoke', M, undefined, H, t + 11);
    assert.strictEqual(store.record(rHM).stored, true, 'and H can revoke the flooder');
    // Bounded by grants: X holds one grant, so H keeps one revoke for X; a grantee with none, none.
    assert.strictEqual(store.record(grantOf('role-revoke', X, undefined, H, t + 12)).reason, 'nothing-to-revoke');
    assert.strictEqual(store.record(grantOf('role-revoke', kp(), undefined, H, t + 13)).reason, 'nothing-to-revoke');
    assert.strictEqual(store.record(grantOf('role-revoke', kp(), undefined, A, t + 14)).stored, true, 'the anchor\'s own are never refused');
  });
});

describe('N4 at the node: a whole-store sync never sends a revoke ahead of the grant it clears', () => {
  it('a revoke whose grant is on a later page still counts after the sync', async () => {
    const A = kp(), V = kp(), Q = kp(), X = kp();
    const t = Date.now() - 100_000;
    const recs = [
      grantOf('role-grant', V, 'validator', A, t),
      grantOf('role-grant', Q, 'validator', A, t),
      grantOf('role-grant', X, 'validator', Q, t + 1),
      grantOf('role-revoke', X, undefined, V, t + 2),
      // V's own later grants fill the first page after its revoke (64 records a page).
      ...Array.from({ length: 70 }, (_, i) => grantOf('role-grant', kp(), 'validator', V, t + 3 + i)),
    ];
    const boot = (b) => new SymNode({ name: uniq(b), silent: true, discovery: new NullDiscovery(), room: 'n4', anchor: { nodeId: A.nodeId, publicKey: A.pub } });
    const P = boot('n4-p'); const N = boot('n4-n');
    try {
      await P.start(); await N.start();
      for (const g of recs) assert.strictEqual(P._roleGrants.record(g).stored, true);
      await connectNodes(P, N);
      await until(() => N._roleGrants.size() === recs.length, 5000);
      assert.strictEqual(N._roleGrants.size(), recs.length, 'every record arrived');
      assert.strictEqual(N.resolveRole(X.nodeId, Date.now(), { key: X.pub }), 'participant', 'V\'s revoke of X counts');
    } finally { await stopAll(P, N); }
  });
});

describe('N5: a 0.13 grant store is never rewritten, so a record skipped at load is never lost', () => {
  it('a record whose root is not yet held stays on disk and loads once its root does', () => {
    const A = kp(), Q = kp(), X = kp(), V = kp();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'n5-'));
    try {
      const t = Date.now() - 100_000;
      const file = path.join(dir, 'role-grants.jsonl');
      const lines = [grantOf('role-grant', V, 'validator', A, t), grantOf('role-grant', X, 'validator', Q, t + 2)].map((g) => JSON.stringify(g)).join('\n') + '\n';
      fs.writeFileSync(file, lines); // as 0.13 wrote it: bare lines
      const s1 = new RoleGrantStore({ anchor: { nodeId: A.nodeId, publicKey: A.pub }, dir });
      assert.deepStrictEqual({ loaded: s1.loadReport().loaded, skipped: s1.loadReport().skipped }, { loaded: 1, skipped: { 'unknown-grantor-key': 1 } });
      assert.strictEqual(fs.readFileSync(file, 'utf8'), lines, 'the file is exactly as it was: nothing dropped, nothing rewritten');
      s1.record(grantOf('role-grant', Q, 'validator', A, t + 1)); // Q's root arrives
      const s2 = new RoleGrantStore({ anchor: { nodeId: A.nodeId, publicKey: A.pub }, dir });
      assert.strictEqual(s2.loadReport().loaded, 3, 'the skipped record loads at the next start');
      assert.strictEqual(s2.resolveRole(X.nodeId, X.pub, Date.now()), 'validator');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
});

// ── Record size limits (draft spec PR #37, §8.8.6) ─────────────────────────────────────────────────
const { categoryKeyV1, MAX_RECORD_BYTES, MAX_SEALED_CHARS, CAT7_CATEGORIES } = require('../lib/core/cmb-encoder');
const { buildEncryptedFrame } = require('../lib/core/cmb-encrypted-frame');
const { blockKeyV2, signCMB, assertionIdV2_0 } = require('../lib/core');

describe('caps: a received record over a §8.8.6 limit is refused before any other work', () => {
  /** A record an implementation without this release's minting limits would sign. */
  function v2Record(peer, texts, room) {
    const categories = {};
    for (const f of CAT7_CATEGORIES) { const text = texts[f] || 'neutral'; categories[f] = { text, meta: { key: categoryKeyV1(f, text), parents: [] } }; }
    const cmb = { categories, metadata: { key: blockKeyV2(categories), addressScheme: 'mmp-cmb-merkle-v2', signatureSuite: 'mmp-sig-v2.0', createdByNodeId: peer.nodeId, createdBy: peer.name, createdTimestamp: Date.now(), room, to: null, lineage: null, application: null } };
    cmb.metadata.assertionId = assertionIdV2_0(cmb);
    signCMB(cmb, peer.privateKey);
    return cmb;
  }
  for (const [label, texts, why] of [
    ['600 KiB of text in all (each category under 256 KiB)', { focus: 'a'.repeat(200 * 1024), issue: 'b'.repeat(200 * 1024), intent: 'c'.repeat(200 * 1024) }, /categories together are too long/],
    ['400 KiB of text that encodes to over 720 KiB', { focus: '"'.repeat(200 * 1024), issue: '"'.repeat(200 * 1024) }, /record is too long/],
  ]) {
    it(label, async () => {
      const b = mk('caps-b');
      try {
        await b.start();
        const P = identity('peer-big');
        const s = admitAs(b, P);
        let encoded = 0;
        b._svafEvaluator.evaluate = async () => { encoded++; return null; };
        const metrics = [];
        b.on('metric', (m) => metrics.push(m));
        const cmb = v2Record(P, texts, b._room);
        deliver(b, s, { type: 'cmb', cmb });
        await new Promise((r) => setTimeout(r, 100));
        assert.ok(metrics.some((m) => m.type === 'cmb-signature-rejected' && m.reason === 'malformed-record' && why.test(m.error)), 'refused by its size');
        assert.strictEqual(encoded, 0, 'before SVAF encoded anything');
        assert.strictEqual(b._store.allEntries().length, 0);
      } finally { await stopAll(b); }
    });
  }

  it('a sealed frame longer than a 720 KiB record can produce is refused unopened, and the session is unharmed', async () => {
    const p = mk('caps-p'); const n = mk('caps-n');
    try {
      await p.start(); await n.start();
      await connectNodes(p, n);
      const sN = n._peers.get(p.nodeId).transport;
      const refused = [];
      sN.on('refused', (type, reason) => refused.push(reason));
      const huge = { categories: { focus: { text: 'x', meta: { key: 'k', parents: [] } } }, metadata: { key: 'cmb-x', assertionId: 'asrt-x', createdByNodeId: p.nodeId, room: n._room, to: null } };
      const frame = buildEncryptedFrame({ cmb: huge, sessionId: sN.sessionId, direction: sN.role === 'client' ? 'server-to-client' : 'client-to-server', sequence: '0', trafficKey: crypto.randomBytes(32) });
      frame.sealed = 'A'.repeat(MAX_SEALED_CHARS + 1);
      sN.receiveWire(frame);
      assert.deepStrictEqual(refused, ['record-too-large'], 'refused by its length, before the AEAD is tried');
      assert.strictEqual(sN.closed, false);
      const got = [];
      n.on('verified-record', (e) => got.push(e.record.metadata.key));
      const sent = p.remember({ focus: 'still heard after the oversized frame', issue: 'caps' });
      await until(() => got.includes(sent.cmb.metadata.key), 3000);
      assert.ok(got.includes(sent.cmb.metadata.key), 'the next genuine record arrives on the same session');
      assert.ok(MAX_SEALED_CHARS === Math.ceil(4 * (MAX_RECORD_BYTES + 16) / 3));
    } finally { await stopAll(p, n); }
  });
});

// ── The notes' open leads ──────────────────────────────────────────────────────────────────────────
const { canonicalRecordV2_0 } = require('../lib/core/record-canonical');

describe('leads', () => {
  it('a record with no metadata.to is refused: the MMP v2.0 record schema requires `to` (null for a room-bound record)', () => {
    const schema = path.join(os.homedir().replace(/\/[^/]*sandbox[^/]*$/, ''), 'code', 'mesh-memory-protocol', 'schema', 'cmb.schema.json');
    const real = path.join('/Users', os.userInfo().username, 'code', 'mesh-memory-protocol', 'schema', 'cmb.schema.json');
    const file = fs.existsSync(real) ? real : schema;
    if (fs.existsSync(file)) assert.ok(JSON.parse(fs.readFileSync(file, 'utf8')).properties.metadata.required.includes('to'), 'the published schema requires metadata.to');
    const A = identity('a');
    const r = signedRecord(A, { categories: { focus: 'room-bound' }, room: 'r' });
    assert.doesNotThrow(() => canonicalRecordV2_0(r), 'to: null is a room-bound record');
    const absent = JSON.parse(JSON.stringify(r));
    delete absent.metadata.to;
    assert.throws(() => canonicalRecordV2_0(absent), /to is not a lowercase UUID or null/);
  });

  it('a signed attestation, checkpoint or witness whose room is spelled in another Unicode form is compared in NFC', async () => {
    const b = mk('nfc-b', { room: 'café' });
    try {
      await b.start();
      const X = identity('x');
      const sX = admitAs(b, X);
      b._roster.bind(X.nodeId, X.publicKey, 'pinned');
      const decomposed = 'café';
      assert.notStrictEqual(decomposed, b._room);
      const att = signedAs({ of: `cmb-${hex()}`, by: X.nodeId, at: Date.now(), roster: decomposed, verdict: 'aligned', categories: CATS7, seq: 1, prev: 'genesis' }, X.privateKey, signAttestation);
      assert.notStrictEqual(b._ingestAttestation(att, X.nodeId, X.name, sX).reason, 'roster-mismatch');
      const cp = signedAs({ by: X.nodeId, upto_seq: 1, root: hex(), at: Date.now(), roster: decomposed }, X.privateKey, signCheckpoint);
      assert.notStrictEqual(b._ingestCheckpoint(cp, X.nodeId, sX).reason, 'roster-mismatch');
      const w = signedAs({ attester: X.nodeId, upto_seq: 2, root: hex(), by: X.nodeId, role: 'participant', at: Date.now(), roster: decomposed }, X.privateKey, signWitness);
      assert.notStrictEqual(b._ingestWitness(w, X.nodeId, sX).reason, 'roster-mismatch');
      assert.strictEqual(b._ingestAttestation({ ...att, sig: att.sig, roster: 'another-room' }, X.nodeId, X.name, sX).reason, 'roster-mismatch', 'another room is still refused');
    } finally { await stopAll(b); }
  });

  it('remember() and send() refuse an addressee that is not a lowercase UUID, before minting', async () => {
    const b = mk('to-b');
    try {
      await b.start();
      const id = crypto.randomUUID();
      for (const bad of [id.toUpperCase(), 'peer-a', 42, [id]]) {
        assert.throws(() => b.remember({ focus: 'to someone' }, { to: bad }), (e) => e.code === 'EBADTO', String(bad));
      }
      assert.strictEqual(b._store.allEntries().length, 0, 'nothing minted');
      assert.ok(b.remember({ focus: 'to a nodeId' }, { to: id }), 'a lowercase UUID is taken');
      assert.strictEqual(b.send('hello', { to: id.toUpperCase() }), 0, 'send says it delivered nothing');
    } finally { await stopAll(b); }
  });

  it('a node whose own nodeId is not a lowercase UUID says so at start', async () => {
    const b = mk('id-b');
    const lines = [];
    const metrics = [];
    b._log = (l) => lines.push(l);
    b.on('metric', (m) => metrics.push(m));
    try {
      await b.start();
      assert.ok(!metrics.some((m) => m.type === 'node-id-not-canonical'), 'a minted identity is a UUIDv7');
      await b.stop();
      b.nodeId = 'legacy-node-id';
      await b.start();
      assert.ok(metrics.some((m) => m.type === 'node-id-not-canonical'));
      assert.ok(lines.some((l) => /not a lowercase UUID/.test(l)));
    } finally { b.nodeId = b._identity.nodeId; await stopAll(b); }
  });
});
