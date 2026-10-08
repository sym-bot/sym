'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * The 0.14.0 re-review at 72daeb6 (docs/handover/agent-a/sym-0.14.0-rereview-notes.txt in
 * sym-bot/xmesh): each finding as a regression test that fails on 72daeb6 for its own reason.
 *
 *   N1  the forgery penalty is charged only to a session that signed in its own name
 *   N2  a revoke carries a cutoff (retired with the time-replay rule: MMP §6.6)
 *   N3  a verified directed record earns its author a durable binding
 *   N4  no cap refuses a revoke (retired: §6.6 quotas never refuse a revoke a bucket keeps first)
 *   N5  a 0.13 grant store is never rewritten (it is now read only as plain data, never rewritten)
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
const { signAttestation, signCheckpoint, signWitness } = require('../lib/core');
const Auth = require('../lib/core/authority');
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

      assert.strictEqual(sA.closed, false, 'the honest relayer\'s session is not closed');
      assert.strictEqual(b._penalised(A.nodeId), false, 'and the relayer is not refused');
      const kinds = metrics.filter((m) => m.type === 'relayed-signature-unverified' && m.peer === A.nodeId).map((m) => m.kind).sort();
      assert.deepStrictEqual(kinds, ['attestation', 'checkpoint', 'record', 'witness'], 'each relayed statement is dropped and counted');
      assert.ok(!metrics.some((m) => m.type === 'forged-signature'), 'none is called a forgery');
      assert.strictEqual(b._store.allEntries().length, 0, 'the record is not stored');

      // The squatter's session delivering a record in its own name (X) that its proven key did not
      // sign is attributable: it is closed and refused.
      deliver(b, sM, { type: 'cmb', cmb: signedRecord(X, { categories: { focus: 'X said this too' }, room: b._room }) });
      assert.strictEqual(sM.closed, true, 'the session that sent a record in its own name its key did not sign is closed');
      assert.strictEqual(b._penalised(X.nodeId), true);
    } finally { await stopAll(b); }
  });

  it('an authority statement is verified under the key its chain names, never a binding: one that fails is dropped and counted against its session, which is not closed (MMP §6.6.8)', async () => {
    const ANC = identity('anchor-n1b');
    const b = mk('n1b-b', { anchor: { threshold: 1, keys: [{ key: ANC.publicKey }] } });
    try {
      await b.start();
      const metrics = [];
      b.on('metric', (m) => metrics.push(m));
      const G1 = identity('g-k1'); const G2 = { ...identity('g-k2'), nodeId: G1.nodeId };
      const W = identity('w');
      const gG = Auth.signStatement({ kind: 'grant', authorisedBy: 'anchor', subject: { nodeId: G1.nodeId, key: G1.publicKey }, role: 'admin', nonce: Auth.freshNonce(), sigs: [] }, ANC.privateKey, ANC.publicKey);
      assert.strictEqual(b.submitAuthority(gG).status, 'in-force');
      // G's session proves K2; a grant signed with K2 under G's grant (which names K1) is not valid,
      // whoever delivers it: the key is the one the chain names.
      const sG2 = admitAs(b, { nodeId: G2.nodeId, name: 'g-k2', publicKey: G2.publicKey });
      const bad = Auth.signStatement({ kind: 'grant', authorisedBy: Auth.statementId(gG), subject: { nodeId: W.nodeId, key: W.publicKey }, role: 'validator', nonce: Auth.freshNonce(), sigs: [] }, G2.privateKey, G2.publicKey);
      assert.strictEqual(b._ingestAuthority(bad, sG2).result, 'invalid');
      assert.strictEqual(sG2.closed, false, 'rate-limited, not closed');
      assert.ok(!metrics.some((m) => m.type === 'forged-signature'));
      for (let i = 0; i < 20; i++) b._ingestAuthority({ ...bad, nonce: Auth.freshNonce() }, sG2);
      assert.strictEqual(b._relayMuted(G2.nodeId, 'authority-statements'), true, 'past a few failures that peer\'s authority statements are dropped unread (the mute is the session\'s, never a key the sender chose)');
      // Signed with K1, the key the chain names: valid, whichever session delivers it.
      const good = Auth.signStatement({ kind: 'grant', authorisedBy: Auth.statementId(gG), subject: { nodeId: W.nodeId, key: W.publicKey }, role: 'validator', nonce: Auth.freshNonce(), sigs: [] }, G1.privateKey, G1.publicKey);
      assert.strictEqual(b._ingestAuthority(good, admitAs(b, identity('anyone'))).result, 'held');
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
// N2 (cutoffs), N4 (subtree budgets, whole-store sync) and N5 (the 0.13 grant store) tested the
// time-replay grant rule that MMP §6.6 retired. Their successors: authority-vectors (every published
// case, in every order), authority-attacks (bounds, backdating, arrival order), authority-node
// (anti-entropy pulls page by page; persistence re-verified at load; legacyRoleGrants reads 0.13's
// file as plain data and never rewrites it).

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
      assert.throws(() => b.send('hello', { to: id.toUpperCase() }), (e) => e.code === 'EBADTO', 'send refuses it too');
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
