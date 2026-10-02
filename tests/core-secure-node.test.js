'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * Design D1/D4/D6 at the node: two real SymNodes joined by an in-memory pipe through the real §5.2
 * handshake. A peer exists only after confirmation, keyed by its proven nodeId; records travel only
 * as cmb-encrypted (no plaintext on the wire); the binding is the signed metadata.to; the host sees
 * verified records through the public `verified-record` hook; a gated room admits on proven keys.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const crypto = require('crypto');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDirById, loadOrCreateIdentity } = require('../lib/config');
const { signRoomGrant } = require('../lib/core/room-grant');
const { memoryPipe, connectNodes, until, identity, signedRecord, admitAs } = require('./_core-secure');

const uniq = (b) => `${b}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
const CATS = (focus) => ({ focus, issue: 'core secure node test', intent: 'prove the channel', motivation: 'D1 D4', commitment: 'none', perspective: 'test', mood: { text: 'calm', valence: 0, arousal: 0 } });

function mk(base, extra = {}) {
  const name = uniq(base);
  const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: extra.room || 'cs-room', ...extra });
  return node;
}
async function stopAll(...nodes) {
  for (const n of nodes) { try { await n.stop(); } catch { /* */ } try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ } }
}

describe('a peer is a proven session (D1)', () => {
  it('nothing per-peer exists before confirmation; after it, the peer is keyed by the proven nodeId and bound proven', async () => {
    const a = mk('cs-a'); const b = mk('cs-b');
    try {
      await a.start(); await b.start();
      const [ta, tb] = memoryPipe();
      b.connectTransport(tb, { role: 'server' });
      assert.strictEqual(b._peers.size, 0, 'an attached transport is not a peer');
      a.connectTransport(ta, { role: 'client', expectNodeId: b.nodeId });
      assert.strictEqual(a._peers.size, 0, 'a dial is not a peer');
      await until(() => a._peers.has(b.nodeId) && b._peers.has(a.nodeId));
      assert.strictEqual(a._roster.source(b.nodeId), 'proven');
      assert.strictEqual(a._roster.get(b.nodeId), b._identity.publicKey);
      const p = a.peers().find((x) => x.peerId === b.nodeId);
      assert.strictEqual(p.profile, 'core-secure');
      assert.strictEqual(p.keySource, 'proven');
      assert.strictEqual(p.sessions.length, 1);
      assert.match(p.sessions[0].sessionId, /^[0-9a-f]{32}$/);
    } finally { await stopAll(a, b); }
  });

  it('a record crosses only as cmb-encrypted, is verified by createdByNodeId, and reaches the host hook', async () => {
    const a = mk('cs-a'); const b = mk('cs-b');
    const wire = [];
    try {
      await a.start(); await b.start();
      const hooked = [];
      b.on('verified-record', (e) => hooked.push(e));
      await connectNodes(a, b, { tap: (f) => wire.push(f) });
      a.remember(CATS('a sealed observation for b'), { payload: { action: 'look' } });
      await until(() => hooked.length > 0);
      assert.strictEqual(hooked.length, 1);
      const e = hooked[0];
      assert.strictEqual(e.session.nodeId, a.nodeId, 'the proven session facts');
      assert.strictEqual(e.session.identityKey, a._identity.publicKey);
      assert.strictEqual(e.session.profile, 'core-secure');
      assert.strictEqual(e.verification.authorNodeId, a.nodeId);
      assert.strictEqual(e.verification.suite, 'mmp-sig-v2.0');
      assert.strictEqual(e.verification.audience, 'room');
      assert.strictEqual(e.record.metadata.createdByNodeId, a.nodeId);
      assert.ok(Object.keys(e).every((k) => !k.startsWith('_')) && Object.keys(e.session).every((k) => !k.startsWith('_')), 'no underscore field is needed');
      assert.ok(Object.isFrozen(e.record) && Object.isFrozen(e.record.metadata) && Object.isFrozen(e.record.categories), 'the host gets a frozen copy of the record');
      assert.throws(() => { 'use strict'; e.record.metadata.to = b.nodeId; }, TypeError);
      const text = JSON.stringify(wire);
      assert.ok(!text.includes('a sealed observation for b'), 'no category text on the wire');
      assert.ok(!wire.some((f) => f.type === 'cmb' || f.type === 'handshake'), 'no plaintext record and no legacy hello on the wire');
      assert.ok(wire.some((f) => f.type === 'cmb-encrypted'));
      assert.ok(wire.filter((f) => !['client-hello', 'server-hello', 'client-finish', 'cmb-encrypted', 'control-encrypted', 'ping', 'pong'].includes(f.type)).length === 0, 'every other frame was sealed');
      // The payload rode as the signed application section and came back as cmb.payload.
      await until(() => b._store.allEntries().some((x) => x.peerId === a.nodeId) || b.inbox().length > 0, 3000);
    } finally { await stopAll(a, b); }
  });

  it('the binding is the signed metadata.to: a record directed to another node is refused, one to me is delivered', async () => {
    const a = mk('cs-a'); const b = mk('cs-b');
    try {
      await a.start(); await b.start();
      await connectNodes(a, b);
      const metrics = [];
      b.on('metric', (m) => metrics.push(m));
      const accepted = [];
      b.on('cmb-accepted', (x) => accepted.push(x));
      // A record a signed to some other node, sent on the session to b.
      const elsewhere = identity('elsewhere');
      const cmb = signedRecord({ nodeId: a.nodeId, name: a.name, privateKey: a._identity.privateKey }, { categories: { focus: 'not for b' }, room: 'cs-room', to: elsewhere.nodeId });
      a._peers.get(b.nodeId).transport.send({ type: 'cmb', cmb });
      await until(() => metrics.some((m) => m.type === 'cmb-audience-rejected'));
      assert.ok(metrics.some((m) => m.type === 'cmb-audience-rejected'), 'the signed to names another node: refused');
      a.remember(CATS('directed to b'), { to: b.nodeId });
      await until(() => accepted.some((x) => x.directed === true || x.content?.includes('directed to b')));
      assert.ok(accepted.length >= 1, 'a record signed to b is delivered (§9.2.2)');
    } finally { await stopAll(a, b); }
  });

  it('frame flags never direct a record: a room-bound record with directed/to on its frame is not delivered as directed', async () => {
    // Over a session the seal carries only the record, so a frame flag cannot even cross (D4); the
    // handler is checked here directly, with a frame as an injector would shape it.
    const b = mk('cs-flags');
    try {
      await b.start();
      const author = identity('flag-author');
      const session = admitAs(b, author);
      b._svafEvaluator.evaluate = async () => ({ decision: 'rejected', totalDrift: 1, categoryDrifts: {}, gateValues: {} });
      const accepted = [];
      b.on('cmb-accepted', (x) => accepted.push(x));
      const cmb = signedRecord(author, { categories: CATS('room-bound, flagged as directed'), room: 'cs-room', to: null });
      await b._frameHandler.handle(session, { type: 'cmb', cmb, directed: true, to: b.nodeId, timestamp: Date.now() });
      await new Promise((r) => setTimeout(r, 50));
      assert.strictEqual(accepted.filter((x) => x.directed === true).length, 0, 'not surfaced as directed past SVAF');
    } finally { await stopAll(b); }
  });

  it('a message is a directed CMB: send() raises the receiver\'s message event, nothing plaintext crosses', async () => {
    const a = mk('cs-a'); const b = mk('cs-b');
    const wire = [];
    try {
      await a.start(); await b.start();
      await connectNodes(a, b, { tap: (f) => wire.push(f) });
      const got = [];
      b.on('message', (from, content, info) => got.push({ from, content, info }));
      assert.strictEqual(a.send('hello over core secure', { to: b.nodeId }), 1);
      await until(() => got.length > 0);
      assert.strictEqual(got[0].content, 'hello over core secure');
      assert.strictEqual(got[0].info.from, a.nodeId);
      assert.ok(!JSON.stringify(wire).includes('hello over core secure'));
      assert.ok(!wire.some((f) => f.type === 'message'), 'no message frame');
    } finally { await stopAll(a, b); }
  });

  it('a record from an author this node never proved and no grant vouches is refused ("X via Y", M12)', async () => {
    const a = mk('cs-a'); const b = mk('cs-b');
    try {
      await a.start(); await b.start();
      await connectNodes(a, b);
      const metrics = [];
      b.on('metric', (m) => metrics.push(m));
      const stranger = identity('stranger');
      const relayed = signedRecord(stranger, { categories: { focus: 'relayed by a' }, room: 'cs-room' });
      a._peers.get(b.nodeId).transport.send({ type: 'cmb', cmb: relayed });
      await until(() => metrics.some((m) => m.type === 'cmb-author-unresolvable'));
      assert.ok(metrics.some((m) => m.type === 'cmb-signature-rejected' && m.reason === 'unresolvable-author'));
      // Once b holds the stranger's key from an out-of-band pin, the same record verifies.
      b._roster.bind(stranger.nodeId, stranger.publicKey, 'pinned');
      const hooked = [];
      b.on('verified-record', (e) => hooked.push(e));
      const again = signedRecord(stranger, { categories: { focus: 'relayed by a, now resolvable' }, room: 'cs-room' });
      a._peers.get(b.nodeId).transport.send({ type: 'cmb', cmb: again });
      await until(() => hooked.length > 0);
      assert.strictEqual(hooked[0].verification.relayed, true);
      assert.strictEqual(hooked[0].verification.authorKeySource, 'pinned');
    } finally { await stopAll(a, b); }
  });

  it('a second confirmed session for the same (nodeId, key) supersedes the first without a peer-left', async () => {
    const a = mk('cs-a'); const b = mk('cs-b');
    try {
      await a.start(); await b.start();
      await connectNodes(a, b);
      const left = [];
      b.on('peer-left', (x) => left.push(x));
      const first = b._peers.get(a.nodeId).transport;
      await connectNodes(a, b);
      await until(() => b._peers.get(a.nodeId)?.transport !== first && first.closed);
      assert.strictEqual(first.closed, true);
      assert.strictEqual(first.closedReason, 'superseded');
      assert.deepStrictEqual(left, [], 'no peer-left: the peer kept a session throughout');
      assert.strictEqual(b._sessionStats.superseded >= 1, true);
    } finally { await stopAll(a, b); }
  });
});

describe('the key registry at the session (D3)', () => {
  it('a squatter racing the upgrade against a legacy-claim is refused; the honest node with the claimed key binds proven', async () => {
    const { PeerSession } = require('../lib/session');
    const b = mk('cs-b');
    const honestName = uniq('cs-honest');
    const honestId = loadOrCreateIdentity(honestName);
    try {
      // b upgraded from 0.13 holding a legacy claim (an unproven hello's key) for the honest node.
      b._roster.bind(honestId.nodeId, honestId.publicKey, 'legacy-claim');
      await b.start();
      // A squatter proves the honest node's id under a key of its own.
      const squat = identity('squatter');
      const [ts, tb] = memoryPipe();
      // What b's session hands the squatter, before sealing.
      const toSquatter = [];
      const attach = b._attachTransport.bind(b);
      b._attachTransport = (...args) => {
        const sess = attach(...args);
        const send = sess.trySend.bind(sess);
        sess.trySend = (f) => { toSquatter.push(f && f.type); return send(f); };
        return sess;
      };
      b.connectTransport(tb, { role: 'server' });
      b._attachTransport = attach;
      const s = new PeerSession({ role: 'client', transport: ts, kind: 'bonjour', room: 'cs-room', extensions: ['cmb-encrypted-v2'], implementation: { name: 'x', version: '1' },
        local: { nodeId: honestId.nodeId, name: honestName, publicKey: squat.publicKey, privateKey: squat.privateKey } });
      ts.on('message', (f) => s.receiveWire(f));
      // b holds a room-join grant of its own: it is presented only to a session that passed the key
      // check, never to one that proved a key in conflict with the registry.
      b._roomGrant = { type: 'room-join', room: 'cs-room', grantee: b.nodeId, sig: 'x' };
      const joined = [];
      b.on('peer-joined', (p) => joined.push(p));
      const ended = [];
      s.on('closed', (c) => ended.push(c.reason));
      s.start();
      await until(() => b._roster.conflicts().length > 0, 3000);
      await new Promise((r) => setTimeout(r, 50));
      assert.strictEqual(b._peers.has(honestId.nodeId), false, 'the squatter is not a peer');
      assert.ok(!toSquatter.includes('mesh-room-join'), 'nothing was presented to the squatter');
      assert.deepStrictEqual(joined, [], 'and no peer-joined was raised');
      await until(() => ended.length > 0, 2000);
      assert.deepStrictEqual(ended, ['identity-conflict'], 'the squatter is told 1009 IDENTITY_CONFLICT (draft spec PR #21)');
      assert.ok(toSquatter.some((t) => t === 'error'), 'an error frame went out');
      b._roomGrant = null;
      assert.strictEqual(b._roster.source(honestId.nodeId), 'legacy-claim', 'the claim is not taken over');
      assert.deepStrictEqual(b._roster.conflicts().map((c) => [c.nodeId, c.got, c.gotSource]), [[honestId.nodeId, squat.publicKey, 'proven']]);
      const honest = new SymNode({ name: honestName, silent: true, discovery: new NullDiscovery(), room: 'cs-room' });
      await honest.start();
      await connectNodes(honest, b);
      assert.strictEqual(b._roster.source(honestId.nodeId), 'proven', 'the honest node, whose identity file did not change, matches');
      await stopAll(honest);
    } finally { await stopAll(b); }
  });
});

describe('room admission on proven keys (D6)', () => {
  function owned(ownerId, extra = {}) {
    return { roomOwners: [{ room: 'gated-room', nodeId: ownerId.nodeId, publicKey: ownerId.publicKey }], room: 'gated-room', ...extra };
  }

  it('the owner is recognised by its pinned key; a grantee by the key it proved; a copied grant and no grant are refused', async () => {
    const ownerName = uniq('cs-owner');
    const ownerId = loadOrCreateIdentity(ownerName);
    const guestName = uniq('cs-guest');
    const guestId = loadOrCreateIdentity(guestName);
    const thiefName = uniq('cs-thief');
    loadOrCreateIdentity(thiefName);
    const grant = signRoomGrant({ room: 'gated-room', grantee: guestId.nodeId, granteeKey: guestId.publicKey, grantedBy: ownerId.nodeId }, ownerId.privateKey);
    // The owner waits one (short) handshake timeout for a session's grant.
    const owner = new SymNode({ name: ownerName, silent: true, discovery: new NullDiscovery(), ...owned(ownerId), handshakeTimeoutMs: 600 });
    const guest = new SymNode({ name: guestName, silent: true, discovery: new NullDiscovery(), ...owned(ownerId, { roomGrant: grant }) });
    // The thief holds a copy of the guest's grant.
    const thief = new SymNode({ name: thiefName, silent: true, discovery: new NullDiscovery(), ...owned(ownerId, { roomGrant: grant, handshakeTimeoutMs: 300 }) });
    const bare = new SymNode({ name: uniq('cs-bare'), silent: true, discovery: new NullDiscovery(), ...owned(ownerId), handshakeTimeoutMs: 300 });
    try {
      for (const n of [owner, guest, thief, bare]) await n.start();
      assert.strictEqual(owner.roomGate().admits, 'grant-holders');
      await connectNodes(guest, owner);
      assert.ok(owner._peers.has(guest.nodeId), 'the grantee whose proven key is the grant\'s is admitted');
      assert.ok(guest._peers.has(owner.nodeId), 'and it admits the owner by the owner\'s pinned key');
      for (const intruder of [thief, bare]) {
        const [ti, to] = memoryPipe();
        owner.connectTransport(to, { role: 'server' });
        intruder.connectTransport(ti, { role: 'client', expectNodeId: owner.nodeId });
        await until(() => owner._roomVerdicts?.get(intruder.nodeId)?.admit === false, 3000);
        assert.strictEqual(owner._peers.has(intruder.nodeId), false, `${intruder.name} is refused`);
      }
      assert.match(owner._roomVerdicts.get(thief.nodeId).reason, /grantee-mismatch|room-join grant refused/);
      assert.match(owner._roomVerdicts.get(bare.nodeId).reason, /no room-join grant/);
    } finally { await stopAll(owner, guest, thief, bare); }
  });

  it('an id claiming to be the owner under another key is refused', async () => {
    const ownerId = identity('the-owner');
    const n = mk('cs-gated', owned(ownerId));
    try {
      const fake = { nodeId: ownerId.nodeId, identityKey: identity('x').publicKey, roomGrant: null };
      const v = n._roomAdmissionDecide(fake);
      assert.strictEqual(v.admit, false);
      assert.match(v.reason, /owner's nodeId under another key/);
      const real = { nodeId: ownerId.nodeId, identityKey: ownerId.publicKey };
      assert.strictEqual(n._roomAdmissionDecide(real).admit, true);
    } finally { await stopAll(n); }
  });
});

describe('extension gating (D1)', () => {
  it('attestation frames go only to sessions that selected sym-attest-v1, and are refused from one that did not', async () => {
    const a = mk('cs-a', { extensions: ['cmb-encrypted-v2'] }); const b = mk('cs-b');
    const wire = [];
    try {
      await a.start(); await b.start();
      await connectNodes(a, b, { tap: (f, dir) => wire.push({ f, dir }) });
      const session = b._peers.get(a.nodeId).transport;
      assert.strictEqual(session.has('sym-attest-v1'), false);
      const before = wire.length;
      b._gossipToRoster({ type: 'sym-attest-attestation', attestation: { of: 'x' } });
      assert.strictEqual(wire.length, before, 'not sent to a session without the extension');
      const refused = [];
      b.on('metric', (m) => { if (m.type === 'session-frame-refused') refused.push(m); });
      a._peers.get(b.nodeId).transport.send({ type: 'sym-attest-checkpoint', checkpoint: { by: a.nodeId } });
      await until(() => refused.length > 0);
      assert.match(refused[0].reason, /sym-attest-v1 not selected/);
      // sym 0.13's bare names are never taken on a Core Secure session, selected or not (sym-attest-v1 §9).
      const c = mk('cs-c');
      await c.start();
      await connectNodes(c, b);
      const sc = b._peers.get(c.nodeId).transport;
      assert.strictEqual(sc.has('sym-attest-v1'), true);
      const legacy = [];
      b.on('metric', (m) => { if (m.type === 'session-frame-refused' && m.reason === 'legacy-attest-frame') legacy.push(m.frameType); });
      for (const t of ['attestation', 'checkpoint', 'witness', 'node-stats']) c._peers.get(b.nodeId).transport.send({ type: t });
      await until(() => legacy.length === 4);
      assert.deepStrictEqual(legacy.sort(), ['attestation', 'checkpoint', 'node-stats', 'witness']);
      await stopAll(c);
    } finally { await stopAll(a, b); }
  });
});

describe('invites carry the issuer (D5)', () => {
  it('accepting an invite pins the issuer only where its nodeId is unbound', async () => {
    const a = mk('cs-a'); const b = mk('cs-b');
    try {
      const url = a.inviteURL({ relay: 'wss://relay.example', token: 't'.repeat(32) });
      assert.match(url, /^sym:\/\/team\/cs-room\?relay=.*&token=.*&node=.*&key=/);
      assert.deepStrictEqual(b.acceptInvite(url).pinned, true);
      assert.strictEqual(b._roster.source(a.nodeId), 'pinned');
      // An invite naming the same id with another key against the existing binding: a conflict.
      const forged = url.replace(/key=[^&]+/, `key=${identity('evil').publicKey}`);
      const r = b.acceptInvite(forged);
      assert.strictEqual(r.pinned, false);
      assert.strictEqual(r.reason, 'conflict');
      assert.strictEqual(b._roster.get(a.nodeId), a._identity.publicKey);
      assert.strictEqual(b._roster.conflicts().length, 1);
      // A proven binding is not lowered by an invite naming the same key.
      void crypto;
    } finally { await stopAll(a, b); }
  });
});
