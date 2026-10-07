'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * The independent security review of 0.14.0 (BLOCK at 341dafb): every probe it filed, as a
 * regression test with its bound asserted. Each fails on 341dafb. The probes are named in the test
 * titles (cs-review-{P,A,B,C,D}/<probe>). What another test file already covers is named there.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');
const { SymNode } = require('../lib/node');
const { NullDiscovery, BonjourDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const { PeerSession, freshX25519 } = require('../lib/session');
const { RoleGrantStore } = require('../lib/role-grant-store');
const { RosterKeyRegistry } = require('../lib/roster-keys');
const { canonicalRecordV2_0, signedProjection } = require('../lib/core/record-canonical');
const { verifyCMB, signGrant, verifyAttestationRole, categoryKeyV1 } = require('../lib/core');
const { clientHello } = require('../lib/core/handshake-v2-flow');
const { buildControlFrame, openControlFrame } = require('../lib/core/sealed-control');
const { assertNoDowngrade } = require('../lib/core/mmp-extensions');
const { fakeRelay } = require('./_fake-relay');
const { identity, memoryPipe, connectNodes, until, signedRecord, admitAs, deliver } = require('./_core-secure');

const uniq = (b) => `${b}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
const CATS = (focus) => ({ focus, issue: 'review', intent: 'probe', motivation: 'm', commitment: 'c', perspective: 'p', mood: { text: 'calm', valence: 0.5, arousal: 0.2 } });
const ALIGNED = { decision: 'aligned', total_drift: 0.1, category_drifts: { focus: 0.1 }, gate_values: { g: 1 } };
const TOKEN = 'x'.repeat(40);
function mk(base, extra = {}) { return new SymNode({ name: uniq(base), silent: true, discovery: new NullDiscovery(), room: extra.room || 'rv', ...extra }); }
async function stopAll(...nodes) {
  for (const n of nodes) { try { await n.stop(); } catch { /* */ } try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ } }
}
function kp(nodeId) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { nodeId, priv: privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(16).toString('base64url'), pub: publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('base64url') };
}
const grantOf = (type, grantee, role, grantor, at, extra = {}) => signGrant({ type, grantee: grantee.nodeId, role, grantedBy: grantor.nodeId, grantedAt: at, ...(type === 'role-grant' ? { granteeKey: grantee.pub } : {}), ...extra }, grantor.priv);

describe('A. the signed audience governs every send (cs-review-P)', () => {
  it('anchor-leak / anchor-leak-b: a record A sent directed to B is never replayed to a later peer M, nor served to it by cmb-fetch', async () => {
    const a = mk('al-a'); const b = mk('al-b'); const m = mk('al-m');
    try {
      await a.start(); await b.start(); await m.start();
      await connectNodes(a, b);
      const sent = a.remember(CATS('a secret for B only'), { to: b.nodeId });
      const key = sent.cmb.metadata.key;
      const atM = [];
      m.on('verified-record', (e) => atM.push(e.record.metadata.key));
      await connectNodes(a, m);
      await new Promise((r) => setTimeout(r, 300));
      assert.ok(!atM.includes(key), 'not replayed to M as an anchor');
      const s = m._peers.get(a.nodeId).transport;
      const answers = [];
      const orig = m._frameHandler._handleCmbFetchResult.bind(m._frameHandler);
      m._frameHandler._handleCmbFetchResult = (pid, pn, msg, sess) => { answers.push(msg); return orig(pid, pn, msg, sess); };
      s.send({ type: 'cmb-fetch', reqId: 'q1', key });
      await until(() => answers.length > 0, 2000);
      assert.deepStrictEqual({ returned: answers[0].returned, missing: answers[0].missing }, { returned: [], missing: [key] }, 'listed missing, as if not held');
      assert.ok(!atM.includes(key));
      // B (the addressee) may fetch it.
      const bs = b._peers.get(a.nodeId).transport;
      const got = [];
      const origB = b._frameHandler._handleCmbFetchResult.bind(b._frameHandler);
      b._frameHandler._handleCmbFetchResult = (pid, pn, msg, sess) => { got.push(msg); return origB(pid, pn, msg, sess); };
      bs.send({ type: 'cmb-fetch', reqId: 'q2', key });
      await until(() => got.length > 0, 2000);
      assert.deepStrictEqual(got[0].returned, [key], 'the addressee is served');
      // The seal point itself refuses it on M's session.
      assert.strictEqual(a._peers.get(m.nodeId).transport.trySend({ type: 'cmb', cmb: sent.cmb }).reason, 'not-addressed');
    } finally { await stopAll(a, b, m); }
  });
});

describe('A, each door on its own (the seal point behind them is not counted on)', () => {
  it('the anchors offered to a new session are room-bound records only (its cmb-anchors names no directed record)', async () => {
    const a = mk('anc-a');
    try {
      await a.start();
      const B = identity('b-for-anchor');
      const directed = a.remember(CATS('for B only, never context'), { to: B.nodeId });
      const room = a.remember(CATS('room-bound context'));
      const m = admitAs(a, identity('m-new'));
      a._greetSession(a._peers.get(m.nodeId), m, true);
      const anchors = m.sent.find((f) => f.type === 'cmb-anchors');
      assert.ok(anchors && anchors.keys.includes(room.cmb.metadata.key), 'room-bound context is offered');
      assert.ok(!anchors.keys.includes(directed.cmb.metadata.key), 'the directed record is not even named');
      assert.ok(!m.sent.some((f) => f.type === 'cmb' && f.cmb.metadata.key === directed.cmb.metadata.key));
    } finally { await stopAll(a); }
  });

  it('cmb-fetch lists a directed record as missing to anyone but its addressee, even on a session that would carry it', async () => {
    const a = mk('fetch-a');
    try {
      await a.start();
      const B = identity('b-for-fetch');
      const directed = a.remember(CATS('fetched by B only'), { to: B.nodeId });
      const key = directed.cmb.metadata.key;
      const m = admitAs(a, identity('m-fetch'));
      deliver(a, m, { type: 'cmb-fetch', reqId: 'q', key });
      assert.ok(!m.sent.some((f) => f.type === 'cmb'), 'not sent');
      assert.deepStrictEqual(m.sent.find((f) => f.type === 'cmb-fetch-result').missing, [key]);
      const b = admitAs(a, B);
      deliver(a, b, { type: 'cmb-fetch', reqId: 'q2', key });
      assert.ok(b.sent.some((f) => f.type === 'cmb' && f.cmb.metadata.key === key), 'the addressee is served');
    } finally { await stopAll(a); }
  });
});

describe('B. a record is its signed projection (cs-review-B/p3-unsigned, cs-review-A/relay-metadata, draft spec PR #34)', () => {
  const A = identity('author-a');
  it('the three negative cases: a carried meta.key mismatch, an uppercase `to`, a coerced type — each refused', () => {
    const r = signedRecord(A, { categories: CATS('room record'), room: 'r' });
    const t1 = JSON.parse(JSON.stringify(r)); t1.categories.focus.meta.key = '0'.repeat(64);
    assert.strictEqual(verifyCMB(t1, A.publicKey).valid, true, 'the signature still verifies: meta.key is outside it');
    assert.throws(() => canonicalRecordV2_0(t1), (e) => e.reason === 'content-mismatch');
    const d = signedRecord(A, { categories: CATS('directed'), room: 'r', to: identity('b').nodeId });
    const t2 = JSON.parse(JSON.stringify(d)); t2.metadata.to = t2.metadata.to.toUpperCase();
    assert.throws(() => canonicalRecordV2_0(t2), /lowercase UUID/);
    const t2b = JSON.parse(JSON.stringify(d)); t2b.metadata.to = [d.metadata.to];
    assert.throws(() => canonicalRecordV2_0(t2b), /lowercase UUID/, 'an array is not a recipient');
    const t3 = JSON.parse(JSON.stringify(r)); t3.metadata.createdTimestamp = String(t3.metadata.createdTimestamp);
    assert.throws(() => canonicalRecordV2_0(t3), /not an integer/, 'a number written as its decimal string is not coerced');
    const t4 = JSON.parse(JSON.stringify(r)); t4.metadata.injectedByRelay = 'x';
    assert.throws(() => canonicalRecordV2_0(t4), /unknown member/, 'a member the schema does not define refuses the record');
  });

  it('unsigned members are dropped, an unknown category too; what is stored and hooked is the projection', async () => {
    const b = mk('proj-b', { room: 'r' });
    try {
      await b.start();
      b._svafEvaluator.evaluate = async () => ALIGNED;
      const sy = admitAs(b, identity('relayer-y'));
      admitAs(b, A);
      const hooked = [];
      b.on('verified-record', (e) => hooked.push(e));
      const r = signedRecord(A, { categories: CATS('room record by A'), room: 'r', lineage: { parents: [], method: 'SVAF-v2' } });
      const t = JSON.parse(JSON.stringify(r));
      t.categories.mood.valence = -1; t.categories.mood.arousal = 1;
      t.categories.injectedCategory = { text: 'unsigned extra category' };
      deliver(b, sy, { type: 'cmb', cmb: t });
      await until(() => hooked.length > 0, 3000);
      const rec = hooked[0].record;
      assert.deepStrictEqual(Object.keys(rec.categories.mood).sort(), ['meta', 'text'], 'valence and arousal dropped');
      assert.strictEqual(rec.categories.injectedCategory, undefined, 'an unknown category dropped');
      assert.ok(!rec.metadata.lineage || !('method' in rec.metadata.lineage), 'lineage.method dropped');
      await until(() => b._store.get(r.metadata.key), 3000);
      const st = b._store.get(r.metadata.key);
      assert.strictEqual(st.cmb.categories.mood.valence, undefined, 'and not stored');
      assert.strictEqual(verifyCMB(st.cmb, A.publicKey).valid, true, 'the projection still verifies');
    } finally { await stopAll(b); }
  });

  it('every published v2.0 vector\'s category keys equal their recomputation, and the vectors pass the strict constructor (cs-review-A/vectors)', () => {
    const vdir = path.join(os.homedir().replace(/\/[^/]*sandbox[^/]*$/, ''), 'code', 'mesh-memory-protocol', 'conformance', 'v2');
    const real = path.join('/Users', os.userInfo().username, 'code', 'mesh-memory-protocol', 'conformance', 'v2');
    const dir = fs.existsSync(real) ? real : vdir;
    if (!fs.existsSync(dir)) return; // the spec mirror is not on this host
    const file = path.join(dir, 'record-signature-v2.json');
    if (!fs.existsSync(file)) return;
    const vec = JSON.parse(fs.readFileSync(file, 'utf8'));
    const cases = (vec.cases || []).filter((c) => c.record && c.record.metadata && c.record.metadata.signatureSuite === 'mmp-sig-v2.0');
    assert.ok(cases.length > 0);
    for (const c of cases) {
      for (const [name, cat] of Object.entries(c.record.categories)) assert.strictEqual(categoryKeyV1(name, cat.text), cat.meta.key, `${c.label}: ${name}`);
      assert.doesNotThrow(() => canonicalRecordV2_0(c.record), c.label);
    }
  });
});

describe('C. a revoke carries a cutoff: what the revoked node signed before it stands, at or after it never counts (cs-review-B; re-review N2 replaces draft spec PR #33\'s receipt time)', () => {
  const ANC = kp('anchor'), V = kp('validator-v'), W = kp('validator-w'), H = kp('honest-h'), ATT = kp('attacker');
  const t0 = Date.now() - 100_000;
  // V was granted at t0 and revoked at t0+50 s, its trust withdrawn from t0+500 ms (the cutoff).
  const CUT = t0 + 500;
  function world() {
    const roster = new RosterKeyRegistry({ anchor: { nodeId: ANC.nodeId, publicKey: ANC.pub }, self: { nodeId: 'receiver', publicKey: kp('receiver').pub } });
    const store = new RoleGrantStore({ anchor: { nodeId: ANC.nodeId, publicKey: ANC.pub }, keys: roster, selfId: 'receiver' });
    roster.setGrantView((id) => store.vouchedKey(id));
    store.record(grantOf('role-grant', V, 'validator', ANC, t0));
    store.record(grantOf('role-grant', W, 'validator', ANC, t0 + 10));
    store.record(grantOf('role-revoke', V, undefined, ANC, t0 + 50_000, { cutoff: CUT }));
    return { roster, store };
  }

  it('p2-revoked-vouch: a revoked validator\'s grant dated at or after its cutoff is not kept; one before it is kept but confers nothing now; no key is bound', () => {
    const { roster, store } = world();
    assert.strictEqual(store.resolveRole(V.nodeId, V.pub, Date.now()), 'participant');
    const r = store.record(grantOf('role-grant', { nodeId: H.nodeId, pub: ATT.pub }, 'validator', V, t0 + 1000));
    assert.deepStrictEqual(r, { stored: false, reason: 'unrooted' }, 'V signed it after its cutoff');
    assert.strictEqual(roster.get(H.nodeId), undefined, 'the attacker key is bound to nobody');
    const early = store.record(grantOf('role-grant', { nodeId: H.nodeId, pub: ATT.pub }, 'validator', V, t0 + 100));
    assert.strictEqual(early.stored, true, 'a statement V signed before its cutoff stands');
    assert.strictEqual(store.resolveRole(H.nodeId, ATT.pub, Date.now()), 'participant', 'and confers nothing while V is revoked (the §6.6 cascade)');
    assert.strictEqual(roster.get(H.nodeId), undefined, 'so it vouches no key');
    const self = store.record(grantOf('role-grant', { nodeId: 'receiver', pub: ATT.pub }, 'validator', V, t0 + 1001));
    assert.strictEqual(self.stored, false);
    assert.strictEqual(roster.get('receiver'), roster._self.publicKey, 'this node\'s own id is always its own key');
  });

  it('p2c-backdate: a revoked validator\'s revoke dated after its cutoff strips nothing, and its attestation dated after it weighs as a participant', () => {
    const { store } = world();
    assert.deepStrictEqual(store.record(grantOf('role-revoke', W, undefined, V, t0 + 1000)), { stored: false, reason: 'unrooted' });
    assert.strictEqual(store.resolveRole(W.nodeId, W.pub, Date.now()), 'validator', 'W keeps its role');
    const role = (at) => verifyAttestationRole({ by: V.nodeId, at, role: 'validator' }, (id, t) => store.resolveRole(id, V.pub, t)).resolved;
    assert.strictEqual(role(t0 + 1000), 'participant', 'dated after the cutoff: a participant\'s');
    assert.strictEqual(role(t0 + 100), 'validator', 'dated before it: it stands');
  });

  it('a revoke signed before its revoker\'s cutoff stands, whichever arrives first', () => {
    const ANC2 = kp('anchor-2'), V2 = kp('v-2'), X = kp('x-2');
    const t = Date.now() - 10_000;
    const recs = {
      AV: grantOf('role-grant', V2, 'validator', ANC2, t),
      AX: grantOf('role-grant', X, 'validator', ANC2, t + 1),
      rVX: grantOf('role-revoke', X, undefined, V2, t + 2),
      rAV: grantOf('role-revoke', V2, undefined, ANC2, t + 5),
    };
    for (const order of [['AV', 'AX', 'rVX', 'rAV'], ['AV', 'AX', 'rAV', 'rVX']]) {
      const store = new RoleGrantStore({ anchor: { nodeId: ANC2.nodeId, publicKey: ANC2.pub } });
      for (const k of order) assert.strictEqual(store.record(recs[k]).stored, true, `${order.join(' ')}: ${k}`);
      assert.strictEqual(store.resolveRole(X.nodeId, X.pub, Date.now()), 'participant', `${order.join(' → ')}: the revoke stands`);
    }
  });

  it('a revoke signed at or after its revoker\'s cutoff has no effect, whichever arrives first', () => {
    const ANC3 = kp('anchor-3'), V3 = kp('v-3'), W3 = kp('w-3');
    const t = Date.now() - 100_000;
    const recs = {
      AV: grantOf('role-grant', V3, 'validator', ANC3, t),
      AW: grantOf('role-grant', W3, 'validator', ANC3, t + 1),
      rVW: grantOf('role-revoke', W3, undefined, V3, t + 20),
      // The anchor revoked V3 at t+30, withdrawing its trust from t+10.
      rAV: grantOf('role-revoke', V3, undefined, ANC3, t + 30, { cutoff: t + 10 }),
    };
    for (const order of [['AV', 'AW', 'rVW', 'rAV'], ['AV', 'AW', 'rAV', 'rVW']]) {
      const store = new RoleGrantStore({ anchor: { nodeId: ANC3.nodeId, publicKey: ANC3.pub } });
      for (const k of order) store.record(recs[k]);
      assert.strictEqual(store.resolveRole(W3.nodeId, W3.pub, Date.now()), 'validator', `${order.join(' → ')}: V3 signed after its cutoff`);
    }
  });

  it('a grant naming this node with a foreign key is inert and reported (p2b-node)', () => {
    const reported = [];
    const own = kp('me');
    const store = new RoleGrantStore({ anchor: { nodeId: ANC.nodeId, publicKey: ANC.pub }, selfId: own.nodeId, selfKey: own.pub, onForeignSelfGrant: (g) => reported.push(g) });
    const r = store.record(grantOf('role-grant', { nodeId: own.nodeId, pub: ATT.pub }, 'validator', ANC, Date.now() - 1));
    assert.strictEqual(r.inert, 'foreign-key-for-self');
    assert.strictEqual(reported.length, 1);
    assert.strictEqual(store.resolveRole(own.nodeId, own.pub, Date.now()), 'participant');
    assert.strictEqual(store.vouchedKey(own.nodeId), undefined);
  });

  it('p2b-node: at the node, a grant a revoked validator dated after its cutoff is not stored or relayed, and records forged under it are refused', async () => {
    const ANCN = identity('anchor-n');
    const b = mk('p2b', { anchor: { nodeId: ANCN.nodeId, publicKey: ANCN.publicKey }, room: 'r' });
    try {
      await b.start();
      const P = identity('relay-peer');
      const s = admitAs(b, P);
      const g = (o, k) => ({ type: o.type, grant: signGrant({ ...o }, k) });
      const VV = identity('validator-n'); const HH = identity('honest-n'); const AT = identity('att-n');
      deliver(b, s, g({ type: 'role-grant', grantee: VV.nodeId, role: 'validator', grantedBy: ANCN.nodeId, grantedAt: t0, granteeKey: VV.publicKey }, ANCN.privateKey));
      deliver(b, s, g({ type: 'role-revoke', grantee: VV.nodeId, grantedBy: ANCN.nodeId, grantedAt: t0 + 50_000, cutoff: t0 + 500 }, ANCN.privateKey));
      deliver(b, s, g({ type: 'role-grant', grantee: HH.nodeId, role: 'validator', grantedBy: VV.nodeId, grantedAt: t0 + 1000, granteeKey: AT.publicKey }, VV.privateKey));
      deliver(b, s, g({ type: 'role-grant', grantee: b.nodeId, role: 'validator', grantedBy: VV.nodeId, grantedAt: t0 + 1001, granteeKey: AT.publicKey }, VV.privateKey));
      assert.strictEqual(b._roster.source(HH.nodeId), undefined);
      assert.strictEqual(b._roster.source(b.nodeId), 'self');
      assert.strictEqual(b._roleGrants.size(), 2, 'only the anchor\'s two');
      const hooked = [];
      b.on('verified-record', (e) => hooked.push(e));
      deliver(b, s, { type: 'cmb', cmb: signedRecord({ ...HH, publicKey: AT.publicKey, privateKey: AT.privateKey }, { categories: { focus: 'forged as H' }, room: 'r' }) });
      deliver(b, s, { type: 'cmb', cmb: signedRecord({ nodeId: b.nodeId, name: b.name, publicKey: AT.publicKey, privateKey: AT.privateKey }, { categories: { focus: 'forged as me' }, room: 'r' }) });
      await new Promise((r) => setTimeout(r, 200));
      assert.strictEqual(hooked.length, 0, 'neither verifies');
    } finally { await stopAll(b); }
  });
});

describe('D. no shared budget before verification; bounds (cs-review-B, cs-review-D)', () => {
  it('p10-hold-size / pending-abuse-014 (c): 64 padded early records hold nothing past their signed fields and 64 KiB', async () => {
    const b = mk('p10', { anchor: { nodeId: crypto.randomUUID(), publicKey: crypto.randomBytes(32).toString('base64url') } });
    try {
      await b.start();
      const s = admitAs(b, identity('m'));
      const big = 'x'.repeat(900 * 1024);
      for (let i = 0; i < 64; i++) {
        deliver(b, s, { type: 'role-grant', grant: { type: 'role-grant', grantee: big + i, role: 'validator', grantedBy: crypto.randomUUID(), grantedAt: Date.now(), granteeKey: crypto.randomBytes(32).toString('base64url'), sigAlg: 'ed25519', sig: crypto.randomBytes(64).toString('base64url'), pad: big } });
      }
      assert.ok(!s._chainHold || s._chainHold.grants.size === 0, 'a grantee over 128 characters is malformed: never held');
      for (let i = 0; i < 100; i++) {
        deliver(b, s, { type: 'role-grant', grant: { type: 'role-grant', grantee: crypto.randomUUID(), role: 'validator', grantedBy: crypto.randomUUID(), grantedAt: Date.now(), granteeKey: crypto.randomBytes(32).toString('base64url'), sigAlg: 'ed25519', sig: crypto.randomBytes(64).toString('base64url'), pad: big } });
      }
      assert.ok(s._chainHold.grants.size <= 64);
      assert.ok(s._chainHold.bytes <= 64 * 1024, `held ${s._chainHold.bytes} bytes`);
      for (const e of s._chainHold.grants.values()) assert.ok(!('pad' in e.grant), 'held as its signed fields only');
    } finally { await stopAll(b); }
  });

  it('role-linear / role-resolve-cost: a delegation reaches at most 8 grants, and resolution stays fast at 16 records per pair', () => {
    const A = kp('anchor-l');
    const s = new RoleGrantStore({ anchor: { nodeId: A.nodeId, publicKey: A.pub } });
    const t = Date.now() - 1e6;
    let prev = A;
    let depthReached = 0;
    for (let d = 1; d <= 24; d++) {
      const g = kp(`l${d}`);
      if (s.record(grantOf('role-grant', g, 'validator', prev, t + d)).stored) depthReached = d;
      prev = g;
    }
    assert.strictEqual(depthReached, 8, 'the 9th link is not rooted');
    const B = kp('anchor-c');
    const st = new RoleGrantStore({ anchor: { nodeId: B.nodeId, publicKey: B.pub } });
    const chain = [kp('c0')];
    st.record(grantOf('role-grant', chain[0], 'validator', B, t));
    const t1 = process.hrtime.bigint();
    for (let d = 1; d <= 7; d++) {
      const g = kp(`c${d}`); chain.push(g);
      for (let i = 0; i < 16; i++) st.record(grantOf('role-grant', g, 'validator', chain[d - 1], t + d * 1000 + i));
    }
    const storeMs = Number(process.hrtime.bigint() - t1) / 1e6;
    const t2 = process.hrtime.bigint();
    assert.strictEqual(st.resolveRole(chain[7].nodeId, chain[7].pub, Date.now()), 'validator');
    const resMs = Number(process.hrtime.bigint() - t2) / 1e6;
    assert.ok(storeMs < 5000, `7 levels x 16 stored in ${storeMs.toFixed(0)} ms (was exponential)`);
    assert.ok(resMs < 500, `resolved in ${resMs.toFixed(0)} ms`);
  });

  it('record-flood: one peer\'s distinct records are evaluated at most at the session budget', async () => {
    const N = mk('rf-n', { room: 'g' }); const E = mk('rf-e', { room: 'g' });
    try {
      await N.start(); await E.start();
      await connectNodes(E, N);
      let evaluated = 0;
      N._svafEvaluator.evaluate = async () => { evaluated++; return null; };
      const author = { nodeId: E.nodeId, name: E.name, publicKey: E._identity.publicKey, privateKey: E._identity.privateKey };
      const s = E._peers.get(N.nodeId).transport;
      const metrics = [];
      N.on('metric', (m) => { if (m.type === 'cmb-over-budget') metrics.push(m); });
      for (let i = 0; i < 120; i++) s.send({ type: 'cmb', cmb: signedRecord(author, { room: 'g', categories: { focus: `distinct record ${i}` } }) });
      await until(() => metrics.length + evaluated >= 120, 4000);
      assert.ok(evaluated <= 32 + 8 * 4, `evaluated ${evaluated}: the burst (32) and 8 a second`);
      assert.ok(metrics.length >= 50, 'the rest dropped unevaluated, and counted');
    } finally { await stopAll(N, E); }
  });

  it('fetch-amp: a peer that does not read its socket gets nothing more once 2 MiB is unsent; a record is served once a minute per session', async () => {
    const V = mk('fa', { room: 'g' });
    try {
      await V.start();
      const entry = V.remember(CATS('a record with a large payload'), { payload: { blob: 'x'.repeat(300 * 1024) } });
      const s = admitAs(V, identity('evil'));
      let pending = 0;
      const sentRecords = [];
      s.pendingBytes = () => pending;
      s.send = (f) => { if (f.type === 'cmb') { sentRecords.push(f); pending += 600 * 1024; } return true; };
      for (let i = 0; i < 6; i++) deliver(V, s, { type: 'cmb-fetch', reqId: `r${i}`, key: entry.key });
      assert.strictEqual(sentRecords.length, 1, 'served once; a repeat within a minute is withheld');
      V._frameHandler._lastServeReset = true;
      s._fetchServe.served.clear();
      pending = 3 * 1024 * 1024;
      deliver(V, s, { type: 'cmb-fetch', reqId: 'r-full', key: entry.key });
      assert.strictEqual(sentRecords.length, 1, 'nothing more while 2 MiB is unsent');
      for (let i = 0; i < 20; i++) deliver(V, s, { type: 'cmb-fetch', reqId: `flood${i}`, key: 'cmb-' + 'a'.repeat(64) });
      assert.ok(s._fetchServe.tokens < 1, 'and fetches are rate-limited per session');
    } finally { await stopAll(V); }
  });

  it('relay-orphan / growth-014 3b / relay-rehello: hellos from one relay from hold one authenticating session, counted, and a restarted client confirms', async () => {
    const node = mk('ro', { relayOnly: true });
    try {
      await node.start();
      const out = [];
      node._relay.transportFor = (to) => ({ trySend: (f) => { out.push({ to, f }); return { ok: true }; }, send() { return true; }, close() {}, destroy() {} });
      const from = '00000000-0000-7000-8000-00000000000a';
      const b = () => crypto.randomBytes(32).toString('base64url');
      for (let i = 0; i < 200; i++) node._relayEnvelope(from, 'evil', { type: 'client-hello', protocolVersion: '2.0', room: 'rv', nodeId: from, name: 'evil', identityPublicKey: b(), e2ePublicKey: freshX25519().publicKey, nonce: b(), implementation: { name: 'x', version: '1' }, extensions: ['cmb-encrypted-v2'] });
      const authenticating = [...node._sessions].filter((x) => !x.confirmed && !x.closed);
      assert.strictEqual(authenticating.length, 1, 'one authenticating slot per (relay, from)');
      assert.strictEqual(node._relayHandshakesInFlight(), 1, 'and it is counted');
      assert.ok(out.filter((o) => o.f.type === 'server-hello').length <= 4 + 1, 'a from\'s hellos are rate-limited (burst 4, 1 a second)');
      assert.ok(node._relaySessions.get(from), 'the state entry is kept for the live attempt (it was orphaned)');
    } finally { await stopAll(node); }
  });

  it('pacer-starve: 300 strangers pinging cannot delay an honest relay session\'s record', async () => {
    const relay = fakeRelay({ ratePerSec: 1e6, burst: 1e6 });
    const V = new SymNode({ name: uniq('ps-v'), silent: true, relayOnly: true, discovery: new NullDiscovery(), relay: relay.url, relayToken: TOKEN, room: 'g' });
    const H = new SymNode({ name: uniq('ps-h'), silent: true, relayOnly: true, discovery: new NullDiscovery(), relay: relay.url, relayToken: TOKEN, room: 'g' });
    try {
      await V.start(); await H.start();
      await until(() => V._peers.has(H.nodeId) && H._peers.has(V.nodeId), 10000);
      H._svafEvaluator.evaluate = async () => ALIGNED;
      const froms = Array.from({ length: 300 }, (_, i) => `0190aaaa-0000-7000-8000-${String(i).padStart(12, '0')}`);
      for (let k = 0; k < 2; k++) { for (const f of froms) relay.inject(f, V.nodeId, { type: 'ping' }); await new Promise((r) => setTimeout(r, 300)); }
      assert.ok(V._relay._queue.class2 <= 64, `1011 replies queued: ${V._relay._queue.class2}`);
      assert.ok((V._unknownSessionDropped || 0) >= 300, `600 pings from 300 strangers: at most 2 a second answered (burst 8), the rest dropped (${V._unknownSessionDropped})`);
      assert.ok(V._unknownSessionSaid.size <= 1024);
      const got = [];
      H.on('verified-record', (e) => got.push(e));
      const t0 = Date.now();
      V.remember(CATS('honest record after the flood'), { to: H.nodeId });
      await until(() => got.length > 0, 8000);
      assert.ok(got.length > 0 && Date.now() - t0 < 5000, `arrived after ${Date.now() - t0} ms (was 46 s)`);
    } finally { await stopAll(V, H); await relay.close(); }
  });

  it('the pacer is fair: a confirmed session\'s frame goes before every queued stranger reply, and a destination keeps its order', () => {
    const { FairQueue, CLASS2_MAX } = require('../lib/relay');
    const q = new FairQueue();
    for (let i = 0; i < 100; i++) q.push(2, { to: `s${i}`, bytes: 10 });
    assert.strictEqual(q.length, CLASS2_MAX, 'stranger replies held at their bound');
    q.push(1, { to: 'h', bytes: 10, n: 'finish' });
    q.push(0, { to: 'h', bytes: 10, n: 'sealed-after-finish' });
    q.push(0, { to: 'peer', bytes: 10, n: 'record' });
    assert.strictEqual(q.take().n, 'record', 'confirmed-session traffic first');
    assert.strictEqual(q.take().n, 'finish', 'then the handshake, and h\'s sealed frame after its finish, never before');
    assert.strictEqual(q.take().n, 'sealed-after-finish');
    assert.strictEqual(q.take().to, 's0', 'then the strangers, in turn');
  });

  it('announce-starve-014: 1000 announced strangers do not keep an honest peer from a session', async () => {
    const relay = fakeRelay({ ratePerSec: 1e6, burst: 1e6 });
    const V = new SymNode({ name: uniq('as-v'), silent: true, relayOnly: true, discovery: new NullDiscovery(), relay: relay.url, relayToken: TOKEN, room: 'g' });
    try {
      await V.start();
      await until(() => V._relay._relayWs && V._relay._relayWs.readyState === 1, 5000);
      for (let i = 0; i < 1000; i++) { const id = `ffff${String(i).padStart(4, '0')}-0000-7000-8000-000000000000`; V._relay._handleRelayPeerJoined(id, 'a'); V._relay._handleRelayPeerJoined(id, 'a'); }
      assert.ok(V._relayUnknownInFlight() <= 32, 'unknown candidates hold their share only');
      const H = new SymNode({ name: uniq('as-h'), silent: true, relayOnly: true, discovery: new NullDiscovery(), relay: relay.url, relayToken: TOKEN, room: 'g' });
      try {
        const t0 = Date.now();
        await H.start();
        const ok = await until(() => V._peers.has(H.nodeId) && H._peers.has(V.nodeId), 15000, 100);
        assert.ok(ok, `the honest peer confirmed (after ${Date.now() - t0} ms; was never within 45 s)`);
      } finally { await stopAll(H); }
    } finally { await stopAll(V); await relay.close(); }
  });

  it('hello-cost: held-open LAN hellos are capped per host and in all', async () => {
    const node = new SymNode({ name: uniq('hc'), silent: true, discovery: new BonjourDiscovery({ mdns: false }), room: 'g' });
    const socks = [];
    try {
      await node.start();
      const b = () => crypto.randomBytes(32).toString('base64url');
      const { sendFrame } = require('../lib/frame-parser');
      for (let i = 0; i < 40; i++) {
        await new Promise((res) => {
          const s = net.createConnection({ port: node._port, host: '127.0.0.1' }, () => { sendFrame(s, { type: 'client-hello', protocolVersion: '2.0', room: 'g', nodeId: crypto.randomUUID(), name: 'x', identityPublicKey: b(), e2ePublicKey: freshX25519().publicKey, nonce: b(), implementation: { name: 'x', version: '1' }, extensions: ['cmb-encrypted-v2'] }); res(); });
          s.on('error', res); s.on('data', () => {}); socks.push(s);
        });
      }
      await new Promise((r) => setTimeout(r, 300));
      const inflight = [...node._sessions].filter((s) => !s.confirmed && !s.closed && s.kind === 'bonjour').length;
      assert.ok(inflight <= 8, `authenticating from one host: ${inflight} (at most 8)`);
    } finally { for (const s of socks) s.destroy(); await stopAll(node); }
  });

  it('relay-slots: a flood of never-finishing relay hellos does not keep an honest peer out', async () => {
    const relay = fakeRelay({ ratePerSec: 1e6, burst: 1e6 });
    const a = new SymNode({ name: uniq('rs-target'), silent: true, relayOnly: true, discovery: new NullDiscovery(), relay: relay.url, relayToken: TOKEN, room: 'relay-room' });
    const bots = [];
    try {
      await a.start();
      await until(() => a._relay._relayWs && a._relay._relayWs.readyState === 1, 5000);
      for (let i = 0; i < 64; i++) {
        const id = { ...identity('bot' + i), nodeId: `00000000-0000-7000-8000-${String(i).padStart(12, '0')}` };
        const { frame } = clientHello({ room: 'relay-room', nodeId: id.nodeId, name: id.name, identityPublicKey: id.publicKey, e2ePublicKey: freshX25519().publicKey, implementation: { name: 'bot', version: '1' }, extensions: ['cmb-encrypted-v2'] });
        relay.inject(id.nodeId, a.nodeId, frame);
        bots.push(id);
      }
      await new Promise((r) => setTimeout(r, 300));
      assert.ok(a._relayHandshakesInFlight() <= 32, 'unknown froms hold 32 slots at most');
      const h = new SymNode({ name: uniq('rs-honest'), silent: true, relayOnly: true, discovery: new NullDiscovery(), relay: relay.url, relayToken: TOKEN, room: 'relay-room' });
      try {
        await h.start();
        assert.ok(await until(() => a._peers.has(h.nodeId) && h._peers.has(a.nodeId), 15000, 100), 'the honest peer gets a session');
      } finally { await stopAll(h); }
    } finally { await stopAll(a); await relay.close(); }
  });
});

describe('E. Legacy Import over the relay (cs-review-C/legacy-relay-squat)', () => {
  for (const gated of [false, true]) {
    it(`a relay token holder answering as the routed 0.13 node reads nothing${gated ? ' (gated room: not even a session)' : ''}`, async () => {
      const WebSocket = require('ws');
      const { e2eGenerateKeyPair, e2eDeriveSharedSecret, decryptCategories } = require('../lib/core');
      const relay = fakeRelay({});
      const L = identity('legacy-013');
      const real = e2eGenerateKeyPair(); // the routed node's persistent X25519 key: the attacker knows only its public half
      const owner = identity('owner');
      const node = new SymNode({ name: uniq('lrs'), silent: true, relayOnly: true, discovery: new NullDiscovery(), relay: relay.url, relayToken: TOKEN, room: 'r1', legacyRoutes: [{ nodeId: L.nodeId, endpoint: 'relay', key: L.publicKey, e2eKey: real.publicKey.toString('base64') }] });
      if (gated) node._roomOwners.pin('r1', owner.nodeId, owner.publicKey, 'config');
      const ws = new WebSocket(relay.url);
      const opened = new Promise((r) => ws.once('open', r));
      const got = [];
      try {
        await node.start();
        await new Promise((r) => setTimeout(r, 300));
        const mine = e2eGenerateKeyPair();
        let secret = null;
        await opened;
        ws.send(JSON.stringify({ type: 'relay-auth', nodeId: L.nodeId, name: 'squatter', token: TOKEN }));
        ws.on('message', (d) => {
          const m = JSON.parse(String(d));
          if (!m.payload) return;
          const p = m.payload;
          if (p.type === 'handshake') {
            // Answers with the routed node's public keys, its own X25519 key in place of the pinned one.
            secret = e2eDeriveSharedSecret(mine.privateKey, Buffer.from(p.e2ePublicKey, 'base64'));
            ws.send(JSON.stringify({ to: m.from, payload: { type: 'handshake', nodeId: L.nodeId, name: 'legacy-013', version: '0.2.3', extensions: [], room: 'r1', publicKey: L.publicKey, e2ePublicKey: mine.publicKey.toString('base64'), lifecycleRole: 'participant' } }));
          } else if (p.type === 'cmb' && secret) {
            try { got.push(decryptCategories(p.cmb.categories, p.cmb._e2e.nonce, secret).focus); } catch { got.push('undecryptable'); }
          }
        });
        await new Promise((r) => setTimeout(r, 800));
        assert.strictEqual(node._peers.has(L.nodeId), false, 'no session for the squatter');
        if (gated) assert.strictEqual(node._roomDoor(L.nodeId).pass, false);
        node.remember(CATS('room broadcast secret'));
        node.remember(CATS('directed secret for the 0.13 node'), { to: L.nodeId });
        await new Promise((r) => setTimeout(r, 500));
        assert.deepStrictEqual(got, [], 'nothing reached it, let alone in a form it could open');
      } finally { ws.close(); await stopAll(node); await relay.close(); }
    });
  }
});

describe('F. errors are information (cs-review-A/relay-errors, relay-failed-rehandshake)', () => {
  const relayNode = (base, relay, extra = {}) => new SymNode({ name: uniq(base), silent: true, relayOnly: true, discovery: new NullDiscovery(), relay: relay.url, relayToken: TOKEN, room: 'relay-room', ...extra });
  const sess = (n, o) => n._peers.get(o.nodeId)?.transports.get('relay');

  it('a clear 2001, a clear 1011, a replayed sealed frame: the confirmed session stays, with no peer-left', async () => {
    const captured = [];
    const relay = fakeRelay({ tap: (e) => { captured.push(e); } });
    const a = relayNode('re-a', relay); const b = relayNode('re-b', relay);
    try {
      await a.start(); await b.start();
      await until(() => sess(a, b)?.confirmed && sess(b, a)?.confirmed, 8000);
      const left = [];
      a.on('peer-left', () => left.push(1));
      const got = [];
      a.on('verified-record', (e) => got.push(e));
      b.remember(CATS('a record to replay'));
      await until(() => got.length > 0, 4000);
      const s0 = sess(a, b);
      relay.inject(b.nodeId, a.nodeId, { type: 'error', code: 2001, message: 'informational' });
      const f = captured.filter((e) => e.from === b.nodeId && e.to === a.nodeId && e.payload.type === 'cmb-encrypted').pop();
      relay.inject(b.nodeId, a.nodeId, f.payload);
      await new Promise((r) => setTimeout(r, 300));
      assert.strictEqual(sess(a, b), s0, 'the same session');
      assert.strictEqual(s0.closed, false);
      assert.strictEqual(a._sessionStats.desync, 0, 'a replay is discarded, not a desync');
      assert.ok(a._sessionStats.refusedByReason.replay >= 1);
      // A clear 1011 to the client: it re-handshakes, keeping the session until the new one supersedes it.
      const [lo, hi] = a.nodeId < b.nodeId ? [a, b] : [b, a];
      const before = sess(lo, hi);
      relay.inject(hi.nodeId, lo.nodeId, { type: 'error', code: 1011, message: 'unknown session', detail: `session:${before.sessionId}` });
      await until(() => sess(lo, hi) && sess(lo, hi) !== before, 6000);
      assert.notStrictEqual(sess(lo, hi), before, 'a new session supersedes it');
      assert.deepStrictEqual(left, [], 'no peer-left at any point');
    } finally { await stopAll(a, b); await relay.close(); }
  });

  it('a re-handshake that fails leaves the confirmed session exactly as it was; no clear error crosses', async () => {
    let dropFinish = false; const errors = [];
    const relay = fakeRelay({ tap: (e) => {
      if (e.payload.type === 'error') errors.push(e.payload);
      if (dropFinish && e.payload.type === 'client-finish') return false;
      return undefined;
    } });
    const a = relayNode('fr-a', relay, { handshakeTimeoutMs: 1500 }); const b = relayNode('fr-b', relay, { handshakeTimeoutMs: 1500 });
    try {
      await a.start(); await b.start();
      await until(() => sess(a, b)?.confirmed && sess(b, a)?.confirmed, 8000);
      const [lo, hi] = a.nodeId < b.nodeId ? [a, b] : [b, a];
      const s1lo = sess(lo, hi); const s1hi = sess(hi, lo);
      const left = [];
      lo.on('peer-left', () => left.push('lo')); hi.on('peer-left', () => left.push('hi'));
      dropFinish = true;
      relay.inject(hi.nodeId, lo.nodeId, { type: 'error', code: 1011, message: 'unknown session' });
      await new Promise((r) => setTimeout(r, 2500));
      assert.strictEqual(s1lo.closed, false, 'the client\'s confirmed session is kept');
      assert.strictEqual(s1hi.closed, false, 'the server\'s too');
      assert.deepStrictEqual(left, []);
      assert.deepStrictEqual(errors.filter((e) => e.code !== 1011), [], 'the failed attempt sent no error');
    } finally { await stopAll(a, b); await relay.close(); }
  });

  it('a clear error on a confirmed LAN session is ignored; a sealed 1010 closes it', async () => {
    const a = mk('le-a'); const b = mk('le-b');
    try {
      await a.start(); await b.start();
      const { tc } = await connectNodes(a, b);
      const s = b._peers.get(a.nodeId).transport;
      for (const code of [1009, 1010, 2001, 4400]) s.receiveWire({ type: 'error', code, message: 'anyone can write this' });
      assert.strictEqual(s.closed, false, 'clear errors change nothing');
      assert.ok(b._sessionStats.refusedByReason['clear-error-ignored'] >= 4);
      a._peers.get(b.nodeId).transport.trySend({ type: 'error', code: 1010, message: 'session closed: test' });
      await until(() => s.closed, 2000);
      assert.strictEqual(s.closedReason, 'peer-closed');
      void tc;
    } finally { await stopAll(a, b); }
  });

  it('a peer that refused this node with 1009 is not re-dialled over the LAN, discovery\'s re-offer included', async () => {
    const { EventEmitter } = require('events');
    const disco = new EventEmitter();
    disco.start = async () => 0; disco.stop = async () => {}; disco.reconnect = () => {};
    const node = new SymNode({ name: uniq('nr'), silent: true, discovery: disco, room: 'default' });
    const dialled = [];
    node._connectToPeer = (address, port, peerId) => dialled.push(peerId);
    try {
      await node.start();
      const larger = `ffffffff-ffff-7fff-bfff-${crypto.randomBytes(6).toString('hex')}`;
      node._onSessionClosed({ kind: 'bonjour', role: 'client', nodeId: null, expectNodeId: larger, _sessionsClosed: true }, { reason: 'identity-conflict', wasConfirmed: true });
      disco.emit('peer-found', '127.0.0.1', 2, larger, 'v2', { mmp: '2.0', room: 'default' });
      assert.deepStrictEqual(dialled, [], 'not dialled');
    } finally { await stopAll(node); }
  });

  it('a relay frame type never rides inside a sealed control frame; a selection outside both offers is refused', () => {
    const key = crypto.randomBytes(32);
    assert.throws(() => buildControlFrame({ frame: { type: 'relay-peers', peers: [] }, sessionId: 'a'.repeat(32), direction: 'client-to-server', sequence: 0, trafficKey: key }), /refusing to seal/);
    assert.throws(() => buildControlFrame({ frame: { type: 'relay-anything-new', x: 1 }, sessionId: 'a'.repeat(32), direction: 'client-to-server', sequence: 0, trafficKey: key }), /refusing to seal/, 'every relay-* type, not only the ones known today');
    assert.throws(() => assertNoDowngrade(['cmb-encrypted-v2'], ['cmb-encrypted-v2'], ['cmb-encrypted-v2', 'sym-attest-v1']), /not offered by both/);
    assert.throws(() => assertNoDowngrade(['cmb-encrypted-v2'], ['cmb-encrypted-v2'], ['cmb-encrypted-v2', 'cmb-encrypted-v2']), /twice/);
    void openControlFrame;
  });

  it('case-alias: an upper-case alias of a nodeId is refused at the hello and at every other door', () => {
    const X = identity('x');
    const { frame } = clientHello({ room: 'r', nodeId: X.nodeId.toUpperCase(), name: 'x', identityPublicKey: X.publicKey, e2ePublicKey: freshX25519().publicKey, implementation: { name: 'x', version: '1' }, extensions: ['cmb-encrypted-v2'] });
    const [, ts] = memoryPipe();
    const S = identity('s');
    const server = new PeerSession({ role: 'server', transport: ts, local: S, room: 'r', extensions: ['cmb-encrypted-v2'], implementation: { name: 'x', version: '1' } });
    let closed = null;
    server.on('closed', (c) => { closed = c; });
    server.receiveWire(frame);
    assert.ok(closed, 'refused');
    const { wireNodeId } = require('../lib/wire-identity');
    assert.strictEqual(wireNodeId(X.nodeId.toUpperCase()), null, 'a relay from / announcement');
    assert.strictEqual(wireNodeId(X.nodeId), X.nodeId);
    const { parseInvite, buildInvite } = require('../lib/invite');
    const url = buildInvite({ room: 'r', issuer: { nodeId: X.nodeId, publicKey: X.publicKey } }).replace(X.nodeId, X.nodeId.toUpperCase());
    assert.ok(parseInvite(url).error, 'an invite');
  });

  it('rooms compare in NFC', () => {
    const nfd = 'café'; const nfc = 'café';
    const n = mk('nfc', { room: nfd });
    try { assert.strictEqual(n._room, nfc, 'kept and announced in NFC'); } finally { n.stop().catch(() => {}); }
  });
});

describe('G. the host hook fires once per assertion (cs-review-P/hook-replay, cs-review-B/p5-dup-hook)', () => {
  it('one signed directed record delivered five times by two relayers raises verified-record once', async () => {
    const b = mk('p5', { room: 'r' });
    try {
      await b.start();
      const A = identity('author-a');
      admitAs(b, A); const sy = admitAs(b, identity('relayer-y')); const sz = admitAs(b, identity('relayer-z'));
      let hooks = 0;
      b.on('verified-record', () => hooks++);
      const rec = signedRecord(A, { categories: CATS('an actionable directed request'), room: 'r', to: b.nodeId });
      for (let i = 0; i < 5; i++) deliver(b, i % 2 ? sy : sz, { type: 'cmb', cmb: JSON.parse(JSON.stringify(rec)) });
      await new Promise((r) => setTimeout(r, 500));
      assert.strictEqual(hooks, 1);
      // A flushed de-dup cache does not bring it back: the hook remembers the assertion.
      b._frameHandler._seenCmbKeys.clear();
      b._frameHandler._seenDirectedKeys.clear();
      deliver(b, sy, { type: 'cmb', cmb: JSON.parse(JSON.stringify(rec)) });
      await new Promise((r) => setTimeout(r, 200));
      assert.strictEqual(hooks, 1, 'not even after the de-duplication marks are gone');
    } finally { await stopAll(b); }
  });

  it('a directed record older than 24 h by its signed time is refused (its de-duplication marks are not kept longer)', async () => {
    const b = mk('dw', { room: 'r' });
    try {
      await b.start();
      const A = identity('author-old');
      const s = admitAs(b, A);
      const metrics = [];
      b.on('metric', (m) => metrics.push(m));
      const { createCMB, signCMB, assertionIdV2_0 } = require('../lib/core');
      const cmb = createCMB({ categories: { focus: 'an old directed request' }, createdBy: A.name, emitV2: true, createdByNodeId: A.nodeId, room: 'r', to: b.nodeId });
      cmb.metadata.createdTimestamp = Date.now() - 25 * 3600 * 1000;
      cmb.metadata.assertionId = assertionIdV2_0(cmb);
      signCMB(cmb, A.privateKey);
      deliver(b, s, { type: 'cmb', cmb });
      await until(() => metrics.some((m) => m.type === 'cmb-directed-stale'), 2000);
      assert.ok(metrics.some((m) => m.type === 'cmb-directed-stale'));
    } finally { await stopAll(b); }
  });
});

describe('the rest of the review (cs-review-B/p11-cli-compact, node-level attestation weight)', () => {
  it('p11-cli-compact: `sym keys` lists read-only, and a live peer\'s binding survives the node\'s restart', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'p11-'));
    try {
      const L = identity('live-peer');
      const { FORMAT_MARKER } = require('../lib/roster-keys');
      const old = Date.now() - 31 * 864e5;
      fs.writeFileSync(path.join(dir, 'roster-keys.jsonl'), JSON.stringify(FORMAT_MARKER) + '\n' + JSON.stringify({ nodeId: L.nodeId, key: L.publicKey, source: 'proven', seen: old }) + '\n');
      const running = new RosterKeyRegistry({ dir, isLive: (id) => id === L.nodeId });
      assert.strictEqual(running.get(L.nodeId), L.publicKey, 'the running node keeps its live peer');
      const cli = new RosterKeyRegistry({ dir, readOnly: true });
      assert.strictEqual(cli.get(L.nodeId), L.publicKey);
      const restarted = new RosterKeyRegistry({ dir });
      assert.strictEqual(restarted.get(L.nodeId), L.publicKey, 'the live peer was seen, and that was written');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('p2c-backdate at the node: a revoked validator\'s attestation dated at or after its cutoff weighs as a participant', async () => {
    const ANCN = identity('anchor-att');
    const node = mk('att-w', { anchor: { nodeId: ANCN.nodeId, publicKey: ANCN.publicKey } });
    try {
      const V = identity('validator-att');
      const t0 = Date.now() - 100_000;
      node._roleGrants.record(signGrant({ type: 'role-grant', grantee: V.nodeId, role: 'validator', grantedBy: ANCN.nodeId, grantedAt: t0, granteeKey: V.publicKey }, ANCN.privateKey));
      node._roster.bind(V.nodeId, V.publicKey, 'pinned');
      const inWindow = { by: V.nodeId, at: t0 + 1000 };
      assert.strictEqual(node._attesterRole(inWindow), 'validator', 'signed while V was a validator: it counts');
      node._roleGrants.record(signGrant({ type: 'role-revoke', grantee: V.nodeId, grantedBy: ANCN.nodeId, grantedAt: t0 + 50_000, cutoff: t0 + 2000 }, ANCN.privateKey));
      assert.strictEqual(node._attesterRole(inWindow), 'validator', 'and, signed before the cutoff, keeps its standing after V is revoked, for every receiver');
      const backdated = { by: V.nodeId, at: t0 + 3000 };
      assert.strictEqual(node._attesterRole(backdated), 'participant', 'one dated at or after the cutoff never counts, whenever it was signed (re-review N2)');
    } finally { await stopAll(node); }
  });
});

describe('the rest of the review (cs-review-C)', () => {
  it('floor-probe: the sticky floor survives 31 days unseen and a restart, and a churn of identities', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'floor-'));
    try {
      const L = '01a0fd21-0000-7000-8000-00000000000a';
      const K = identity('l').publicKey;
      let t = Date.now();
      let reg = new RosterKeyRegistry({ dir, now: () => t, isRouted: (id) => id === L });
      reg.bind(L, K, 'proven'); reg.noteSeen(L);
      assert.strictEqual(reg.floor(L), true);
      t += 31 * 24 * 3600 * 1000;
      reg = new RosterKeyRegistry({ dir, now: () => t });
      assert.strictEqual(reg.floor(L), true, 'the binding may be gone; the floor is not');
      const reg2 = new RosterKeyRegistry({ maxBindings: 1000, isRouted: (id) => id === L });
      reg2.bind(L, K, 'proven');
      for (let i = 0; i < 1000; i++) reg2.bind(`01a0fd21-0000-7000-8000-${String(i).padStart(12, '0')}`, identity().publicKey, 'proven');
      assert.strictEqual(reg2.floor(L), true);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('interior-probe: the mindId ends nothing, a stale capability on a new connection is refused', async () => {
    const node = mk('ip');
    try {
      const it2 = node.interior();
      const p = await it2.listen();
      const { mindId, capability } = it2.startMind({ id: 'm1', kinds: ['note'] });
      const ask = (obj) => new Promise((res) => { const s = net.createConnection(p, () => s.write(JSON.stringify(obj) + '\n')); let b = ''; s.on('data', (d) => { b += d; if (b.includes('\n')) { s.destroy(); res(JSON.parse(b)); } }); });
      const keep = net.createConnection(p);
      await new Promise((r) => keep.once('connect', r));
      const first = await new Promise((res) => { let b = ''; keep.on('data', (d) => { b += d; if (b.includes('\n')) res(JSON.parse(b)); }); keep.write(JSON.stringify({ id: 1, type: 'mission', capability }) + '\n'); });
      assert.strictEqual(first.type, 'mission');
      assert.strictEqual((await ask({ id: 2, type: 'end', capability: mindId })).reason, 'no-live-capability');
      assert.strictEqual((await ask({ id: 3, type: 'submit', capability, kind: 'note', categories: { focus: 'x' } })).reason, 'capability-bound-to-another-connection');
      keep.destroy();
    } finally { await stopAll(node); }
  });
});
