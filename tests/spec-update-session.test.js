'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * sym 0.14.0 aligned with the MMP 2.0 update 1 drafts it implements (the session and sealed-control
 * set: #26, #30, #31, #37, #23), the founder's rulings for that update, and the reviews of each draft
 * against sym 390b4af. Each test here fails on 390b4af.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const crypto = require('crypto');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const { PeerSession } = require('../lib/session');
const { buildControlFrame, openControlSealed } = require('../lib/core/sealed-control');
const { buildEncryptedFrame } = require('../lib/core/cmb-encrypted-frame');
const { signRoomGrant, verifyRoomGrant } = require('../lib/core/room-grant');
const { identity, connectNodes, until, signedRecord, signerOf } = require('./_core-secure');

const uniq = (b) => `${b}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
const made = [];
function node(base, opts = {}) {
  const n = new SymNode({ name: uniq(base), silent: true, discovery: new NullDiscovery(), room: opts.room || 'upd', ...opts });
  made.push(n);
  return n;
}
async function stopAll() {
  for (const n of made.splice(0)) { try { await n.stop(); } catch { /* */ } try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ } }
}
const sessionTo = (n, other) => { const p = n._peers.get(other.nodeId); return p && p.transport; };

describe('S1: the signed room governs the seal point (#26)', () => {
  it('a record signed for another room is never sealed to a session, whichever path offers it', async () => {
    try {
      const A = node('s1-a', { room: 'beta' }); const B = node('s1-b', { room: 'beta' });
      await A.start(); await B.start();
      await connectNodes(B, A);
      // A held this before it moved rooms: its own record, signed for 'alpha'.
      const old = signedRecord(signerOf(A), { categories: { focus: 'said in the alpha room' }, room: 'alpha' });
      const r = sessionTo(A, B).trySend({ type: 'cmb', cmb: old });
      assert.strictEqual(r.ok, false);
      assert.strictEqual(r.reason, 'not-addressed');
      // The same record for this room goes.
      const here = signedRecord(signerOf(A), { categories: { focus: 'said in the beta room' }, room: 'beta' });
      assert.strictEqual(sessionTo(A, B).trySend({ type: 'cmb', cmb: here }).ok, true);
      // A fetch for the old record is answered missing: the store is per node, not per room.
      A._store.receiveFromPeer('self-older', { key: old.metadata.key, content: 'x', source: A.name, cmb: old, _cmbVerified: true });
      const got = await B.fetchCMB(old.metadata.key, { timeoutMs: 1500 });
      assert.strictEqual(got, null, 'never served across rooms');
    } finally { await stopAll(); }
  });
});

describe('S2: a room-join grant is checked against its schema before it is verified (#31)', () => {
  const kp = () => { const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519'); return { pub: publicKey.export({ format: 'jwk' }).x, priv: privateKey.export({ format: 'jwk' }).d }; };
  it('string timestamps (the same signed bytes) are refused; so is any member the schema does not define', () => {
    const owner = kp(); const grantee = kp();
    const ownerId = crypto.randomUUID(); const granteeId = crypto.randomUUID();
    const now = Date.now();
    const g = signRoomGrant({ room: 'team-room', grantee: granteeId, granteeKey: grantee.pub, grantedBy: ownerId, grantedAt: now - 1000, expiresAt: now + 60_000 }, owner.priv);
    const expect = { room: 'team-room', grantee: granteeId, provenKey: grantee.pub, ownerNodeId: ownerId };
    assert.strictEqual(verifyRoomGrant(g, owner.pub, expect).ok, true);
    const strings = { ...g, grantedAt: String(g.grantedAt), expiresAt: String(g.expiresAt) };
    const r = verifyRoomGrant(strings, owner.pub, expect);
    assert.strictEqual(r.ok, false, 'a grant whose timestamps are strings never verifies');
    assert.match(r.reason, /malformed/);
    assert.strictEqual(verifyRoomGrant({ ...g, note: 'x' }, owner.pub, expect).ok, false, 'an extra member: malformed');
    assert.strictEqual(verifyRoomGrant({ ...g, expiresAt: g.expiresAt + 0.5 }, owner.pub, expect).ok, false, 'not an integer');
  });
  it('a node sends the schema\'s grant only, whatever object its host passed', () => {
    const { grantForWire } = require('../lib/core/room-grant');
    const owner = kp();
    const g = signRoomGrant({ room: 'team-room', grantee: crypto.randomUUID(), granteeKey: kp().pub, grantedBy: crypto.randomUUID() }, owner.priv);
    assert.deepStrictEqual(grantForWire({ ...g, note: 'host data', extra: 1 }), g);
  });
  it('the grant a node mints is the schema\'s object only: extra members the caller passed are not kept', () => {
    const owner = kp();
    const g = signRoomGrant({ room: 'team-room', grantee: crypto.randomUUID(), granteeKey: kp().pub, grantedBy: crypto.randomUUID(), note: 'host data' }, owner.priv);
    assert.deepStrictEqual(Object.keys(g).sort(), ['expiresAt', 'grantedAt', 'grantedBy', 'grantee', 'granteeKey', 'room', 'sig', 'sigAlg', 'type'].sort());
  });
});

describe('S4: a sealed frame that opens advances the receive sequence (#26)', () => {
  /** A confirmed pair of PeerSessions over a memory pipe, and a way to inject sealed frames from one to the other. */
  async function pair() {
    const A = node('s4-a'); const B = node('s4-b');
    await A.start(); await B.start();
    await connectNodes(B, A);
    const sA = sessionTo(A, B); const sB = sessionTo(B, A);
    return { A, B, sA, sB };
  }
  it('an authentic control frame whose inner frame is refused changes nothing else: the next frame is taken', async () => {
    try {
      const { sA, sB } = await pair();
      const refused = []; const closed = [];
      sB.on('refused', (type, reason) => refused.push([type, reason]));
      sB.on('closed', (e) => closed.push(e.reason));
      // A sealed frame whose plaintext is not a control frame (a relay frame type inside).
      const pos = sA._mmp.nextSend();
      const bad = buildControlFrame({ frame: { type: 'mood', mood: 'x' }, sessionId: sA.sessionId, direction: pos.direction, sequence: pos.sequence, trafficKey: pos.trafficKey });
      // Re-seal with a forbidden inner type at the same position (bypassing the builder's own refusal).
      const { sealV2 } = require('../lib/core/e2e-v2');
      const { nonceForSequence } = require('../lib/core/cmb-encrypted-frame');
      const { controlAAD } = require('../lib/core/sealed-control');
      bad.sealed = sealV2(pos.trafficKey, nonceForSequence(pos.sequence), controlAAD(bad), Buffer.from(JSON.stringify({ type: 'relay-auth', nodeId: 'x' }))).toString('base64url').replace(/=+$/, '');
      sA._wire(bad);
      await new Promise((r) => setTimeout(r, 30));
      assert.ok(refused.some(([, reason]) => /inner frame refused/.test(reason)), JSON.stringify(refused));
      // The next ordinary frame is taken: no gap, no close.
      const got = [];
      sB.on('frame', (f) => got.push(f.type));
      sA.trySend({ type: 'peer-info', peers: [] });
      await until(() => got.includes('peer-info'), 1000);
      assert.deepStrictEqual(closed, []);
      assert.ok(got.includes('peer-info'));
    } finally { await stopAll(); }
  });
  it('an authentic record whose plaintext is refused changes nothing else either', async () => {
    try {
      const { sA, sB } = await pair();
      const closed = [];
      sB.on('closed', (e) => closed.push(e.reason));
      const pos = sA._mmp.nextSend();
      const rec = signedRecord(identity('x'), { room: sA.room });
      const wire = buildEncryptedFrame({ cmb: rec, applicationBytes: null, sessionId: sA.sessionId, direction: pos.direction, sequence: pos.sequence, trafficKey: pos.trafficKey });
      // The same position, with a plaintext that is not an object.
      const { sealV2 } = require('../lib/core/e2e-v2');
      const { nonceForSequence } = require('../lib/core/cmb-encrypted-frame');
      const { aeadAADv2 } = require('../lib/core/e2e-v2');
      const m = wire.metadata;
      const aad = aeadAADv2({ protocolVersion: '2.0', sessionId: wire.sessionId, direction: wire.direction, sequence: String(wire.sequence), key: m.key, assertionId: m.assertionId, createdByNodeId: m.createdByNodeId, room: m.room, to: m.to });
      wire.sealed = sealV2(pos.trafficKey, nonceForSequence(pos.sequence), aad, Buffer.from('not json at all')).toString('base64url').replace(/=+$/, '');
      sA._wire(wire);
      await new Promise((r) => setTimeout(r, 30));
      const got = [];
      sB.on('frame', (f) => got.push(f.type));
      sA.trySend({ type: 'peer-info', peers: [] });
      await until(() => got.includes('peer-info'), 1000);
      assert.deepStrictEqual(closed, []);
    } finally { await stopAll(); }
  });
});

describe('§7.2: every sealed Close-action error closes the session; a host sends only information (#23)', () => {
  it('a sealed 1008 from a peer closes the session; a sealed 2001 does not', async () => {
    try {
      const A = node('e-a'); const B = node('e-b');
      await A.start(); await B.start();
      await connectNodes(B, A);
      const closed = [];
      sessionTo(B, A).on('closed', (e) => closed.push(e.reason));
      sessionTo(A, B).trySend({ type: 'error', code: 2001, message: 'svaf rejected' });
      await new Promise((r) => setTimeout(r, 30));
      assert.deepStrictEqual(closed, []);
      sessionTo(A, B).trySend({ type: 'error', code: 1008, message: 'replay' });
      await until(() => closed.length > 0, 1000);
      assert.deepStrictEqual(closed, ['peer-closed']);
    } finally { await stopAll(); }
  });
  it('sendError refuses 1009, 1010, 1011, the other Close codes and 4xxx; 1002 and 2xxx go', async () => {
    try {
      const A = node('se-a'); const B = node('se-b');
      await A.start(); await B.start();
      await connectNodes(B, A);
      for (const code of [1001, 1006, 1009, 1010, 1011, 4004, 4007, 999, 'x']) {
        assert.throws(() => A.sendError(B.nodeId, code, 'no'), (e) => e.code === 'EBADERRORCODE', String(code));
      }
      assert.doesNotThrow(() => A.sendError(B.nodeId, 2001, 'svaf rejected'));
      assert.doesNotThrow(() => A.sendError(B.nodeId, 1002, 'frame rejected'));
    } finally { await stopAll(); }
  });
});

void PeerSession; void openControlSealed;
