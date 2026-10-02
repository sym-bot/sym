'use strict';

/**
 * Design D2 — the MMP v2.0 §5.2 handshake over a transport, and the sealed channel it opens
 * (lib/session.js). The §17.4 negative cases: a bad proof, a wrong confirmation, an unechoed nonce,
 * a stripped extension, a room mismatch, a data frame before client-finish, a legacy hello on the
 * Core Secure listener, an all-zero shared secret, a fresh X25519 per handshake. Then the channel:
 * records only as cmb-encrypted, control frames sealed, AEAD before sequence, desync closes.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { PeerSession, agreeX25519 } = require('../lib/session');
const { EXT_CMB_ENCRYPTED_V2 } = require('../lib/core/mmp-extensions');
const { buildEncryptedFrame } = require('../lib/core/cmb-encrypted-frame');
const { identity, memoryPipe, until, signedRecord, applicationFor } = require('./_core-secure');

const IMPL = { name: 'sym', version: '0.14.0-test' };
const EXTS = [EXT_CMB_ENCRYPTED_V2, 'sym-attest-v1'];

/** A client and a server session joined by a pipe, with an optional wire tamper per direction. */
function pairOver({ room = 'r', clientRoom = room, clientExts = EXTS, serverExts = EXTS, tamper } = {}) {
  const C = identity('client'), S = identity('server');
  const wire = [];
  const [tc, ts] = memoryPipe({ tap: (f, dir) => wire.push({ dir, f }) });
  const client = new PeerSession({ role: 'client', transport: tc, kind: 'bonjour', local: C, room: clientRoom, extensions: clientExts, implementation: IMPL, expectNodeId: S.nodeId });
  const server = new PeerSession({ role: 'server', transport: ts, kind: 'bonjour', local: S, room, extensions: serverExts, implementation: IMPL });
  const feed = (to, from) => from.on('message', (f) => to.receiveWire(tamper ? tamper(f, to === server ? 'to-server' : 'to-client') : f));
  feed(server, ts);
  feed(client, tc);
  const events = { client: [], server: [] };
  for (const [name, s] of [['client', client], ['server', server]]) {
    s.on('confirmed', () => events[name].push('confirmed'));
    s.on('closed', (c) => events[name].push(`closed:${c.reason}`));
    s.on('frame', (f) => events[name].push(f));
    s.on('refused', (type, reason) => events[name].push(`refused:${type}:${reason}`));
  }
  return { C, S, client, server, tc, ts, wire, events };
}

const settle = () => new Promise((r) => setTimeout(r, 30));

describe('the v2 handshake over a transport (D2)', () => {
  it('confirms both sides with the proven facts and the extension intersection', async () => {
    const p = pairOver({ serverExts: [EXT_CMB_ENCRYPTED_V2, 'sym-attest-v1', 'xmesh-insight-v1'] });
    p.client.start();
    await until(() => p.client.confirmed && p.server.confirmed);
    assert.strictEqual(p.client.nodeId, p.S.nodeId);
    assert.strictEqual(p.client.identityKey, p.S.publicKey);
    assert.strictEqual(p.server.nodeId, p.C.nodeId);
    assert.strictEqual(p.server.identityKey, p.C.publicKey);
    assert.strictEqual(p.client.sessionId, p.server.sessionId);
    assert.deepStrictEqual(p.server.selected, [EXT_CMB_ENCRYPTED_V2, 'sym-attest-v1']);
    assert.deepStrictEqual(p.client.selected, p.server.selected);
    assert.strictEqual(p.client.peerE2EPublicKey, p.server.localE2EPublicKey);
  });

  it('a fresh X25519 key pair per handshake, and none injectable', async () => {
    const a = pairOver(); const b = pairOver();
    assert.notStrictEqual(a.client.localE2EPublicKey, b.client.localE2EPublicKey);
    const C = identity('c');
    const keys = new Set();
    for (let i = 0; i < 5; i++) keys.add(new PeerSession({ role: 'client', transport: memoryPipe()[0], local: C, room: 'r', extensions: EXTS, implementation: IMPL, e2ePrivateKey: 'ignored' }).localE2EPublicKey);
    assert.strictEqual(keys.size, 5, 'one identity, five handshakes, five ephemeral keys');
  });

  it('a bad server proof aborts the client before anything is confirmed', async () => {
    const p = pairOver({ tamper: (f) => (f.type === 'server-hello' ? { ...f, proof: Buffer.alloc(64, 1).toString('base64url') } : f) });
    p.client.start();
    await settle();
    assert.strictEqual(p.client.confirmed, false);
    assert.match(p.events.client.join(), /closed:error/);
    assert.strictEqual(p.client.nodeId, null, 'no peer fact was kept');
  });

  it('a wrong key confirmation aborts (the client side, then the server side)', async () => {
    const flip = (k) => { const b = Buffer.from(k, 'base64url'); b[0] ^= 1; return b.toString('base64url'); };
    const p = pairOver({ tamper: (f) => (f.type === 'server-hello' ? { ...f, keyConfirmation: flip(f.keyConfirmation) } : f) });
    p.client.start();
    await settle();
    assert.strictEqual(p.client.confirmed, false);
    const q = pairOver({ tamper: (f) => (f.type === 'client-finish' ? { ...f, keyConfirmation: flip(f.keyConfirmation) } : f) });
    q.client.start();
    await settle();
    assert.strictEqual(q.server.confirmed, false, 'the server never confirms a client whose confirmation is wrong');
    assert.match(q.events.server.join(), /closed:error/);
  });

  it('an unechoed nonce aborts', async () => {
    const p = pairOver({ tamper: (f) => (f.type === 'server-hello' ? { ...f, clientNonce: crypto.randomBytes(32).toString('base64url') } : f) });
    p.client.start();
    await settle();
    assert.strictEqual(p.client.confirmed, false);
    assert.match(p.events.client.join(), /closed:error/);
  });

  it('a stripped extension aborts as a downgrade, and a session without cmb-encrypted-v2 is never Core Secure', async () => {
    const p = pairOver({ tamper: (f) => (f.type === 'server-hello' ? { ...f, selectedExtensions: f.selectedExtensions.filter((e) => e !== EXT_CMB_ENCRYPTED_V2) } : f) });
    p.client.start();
    await settle();
    assert.strictEqual(p.client.confirmed, false);
    const q = pairOver({ clientExts: ['sym-attest-v1'] });
    q.client.start();
    await settle();
    assert.strictEqual(q.server.confirmed, false);
    assert.match(q.events.server.join(), /closed:no-core-secure/, 'no fallback to a weaker session');
  });

  it('a room mismatch closes before admission', async () => {
    const p = pairOver({ room: 'room-a', clientRoom: 'room-b' });
    p.client.start();
    await settle();
    assert.strictEqual(p.server.confirmed, false);
    assert.match(p.events.server.join(), /closed:room-mismatch/);
    assert.strictEqual(p.wire.filter((w) => w.f.type === 'server-hello').length, 0, 'the server answered nothing');
  });

  it('a data frame before client-finish closes the listener', async () => {
    const p = pairOver({ tamper: (f) => (f.type === 'client-finish' ? { type: 'cmb', cmb: {} } : f) });
    p.client.start();
    await settle();
    assert.strictEqual(p.server.confirmed, false);
    assert.match(p.events.server.join(), /closed:frame-before-finish/);
  });

  it('a legacy hello on the Core Secure listener is refused at once', async () => {
    const S = identity('server');
    const [tc, ts] = memoryPipe();
    const server = new PeerSession({ role: 'server', transport: ts, local: S, room: 'r', extensions: EXTS, implementation: IMPL });
    const closed = [];
    server.on('closed', (c) => closed.push(c.reason));
    server.receiveWire({ type: 'handshake', nodeId: identity().nodeId, name: 'legacy', publicKey: identity().publicKey });
    assert.deepStrictEqual(closed, ['first-frame']);
    assert.strictEqual(server.nodeId, null);
    void tc;
  });

  it('a relay server session is bound to its relay from: a hello naming another nodeId is refused (D2)', async () => {
    const S = identity('server'), C = identity('client'), from = identity('relay-from');
    const [tc, ts] = memoryPipe();
    const server = new PeerSession({ role: 'server', transport: ts, kind: 'relay', relayFrom: from.nodeId, expectNodeId: from.nodeId, local: S, room: 'r', extensions: EXTS, implementation: IMPL });
    const client = new PeerSession({ role: 'client', transport: tc, kind: 'relay', local: C, room: 'r', extensions: EXTS, implementation: IMPL });
    const closed = [];
    server.on('closed', (c) => closed.push(c.reason));
    ts.on('message', (f) => server.receiveWire(f));
    tc.on('message', (f) => client.receiveWire(f));
    client.start();
    await settle();
    assert.deepStrictEqual(closed, ['node-id-mismatch'], 'C proves its own key, but over the relay address of another node');
    assert.strictEqual(server.confirmed, false);
  });

  it('an all-zero shared secret aborts (§5.2.1)', async () => {
    const { privateKey } = crypto.generateKeyPairSync('x25519');
    const peer = crypto.randomBytes(32).toString('base64url');
    assert.throws(() => agreeX25519(privateKey, peer, () => Buffer.alloc(32)), /all-zero/);
    // And on the wire: a client-hello whose X25519 key is a low-order point.
    const S = identity('server');
    const server = new PeerSession({ role: 'server', transport: memoryPipe()[1], local: S, room: 'r', extensions: EXTS, implementation: IMPL });
    const closed = [];
    server.on('closed', (c) => closed.push(`${c.reason}:${c.detail}`));
    const C = identity('client');
    const { clientHello } = require('../lib/core/handshake-v2-flow');
    const { frame } = clientHello({ room: 'r', nodeId: C.nodeId, name: 'c', identityPublicKey: C.publicKey, e2ePublicKey: Buffer.alloc(32).toString('base64url'), implementation: IMPL, extensions: EXTS });
    server.receiveWire(frame);
    assert.match(closed.join(), /error:.*(all-zero|X25519 agreement failed)/);
    assert.strictEqual(server.confirmed, false);
  });

  it('a hello whose fields are not what they must be is refused at the door', async () => {
    const S = identity('server');
    for (const bad of [{ nodeId: 'not-a-uuid' }, { identityPublicKey: { x: 1 } }, { nonce: 'short' }, { extensions: 'cmb-encrypted-v2' }, { implementation: null }, { name: '' }]) {
      const server = new PeerSession({ role: 'server', transport: memoryPipe()[1], local: S, room: 'r', extensions: EXTS, implementation: IMPL });
      const closed = [];
      server.on('closed', (c) => closed.push(c.reason));
      const C = identity('client');
      const { clientHello } = require('../lib/core/handshake-v2-flow');
      const { frame } = clientHello({ room: 'r', nodeId: C.nodeId, name: 'c', identityPublicKey: C.publicKey, e2ePublicKey: crypto.randomBytes(32).toString('base64url'), implementation: IMPL, extensions: EXTS });
      server.receiveWire({ ...frame, ...bad });
      assert.deepStrictEqual(closed, ['error'], JSON.stringify(bad));
    }
  });

  it('times out an unanswered handshake', async () => {
    const C = identity('client');
    const s = new PeerSession({ role: 'client', transport: memoryPipe()[0], local: C, room: 'r', extensions: EXTS, implementation: IMPL, timeoutMs: 20 });
    const closed = [];
    s.on('closed', (c) => closed.push(c.reason));
    s.start();
    await until(() => closed.length > 0, 500);
    assert.deepStrictEqual(closed, ['timeout']);
  });
});

describe('the sealed channel (D1/D4)', () => {
  async function confirmedPair(opts) {
    const p = pairOver(opts);
    p.client.start();
    await until(() => p.client.confirmed && p.server.confirmed);
    return p;
  }

  it('a record travels only as cmb-encrypted, its application sealed, and arrives whole', async () => {
    const p = await confirmedPair();
    const app = applicationFor(Buffer.from(JSON.stringify({ action: 'deploy' })));
    const cmb = signedRecord(p.C, { categories: { focus: 'sealed thought text' }, room: 'r', application: app });
    assert.strictEqual(p.client.trySend({ type: 'cmb', cmb }).ok, true);
    await until(() => p.events.server.some((e) => e && e.type === 'cmb'));
    const got = p.events.server.find((e) => e && e.type === 'cmb').cmb;
    assert.deepStrictEqual(got, cmb, 'the logical record, application data included');
    const onWire = p.wire.filter((w) => w.dir === 'a→b' && w.f.type === 'cmb-encrypted');
    assert.strictEqual(onWire.length, 1);
    const text = JSON.stringify(onWire[0].f);
    assert.ok(!text.includes('sealed thought text'), 'no category text on the wire');
    assert.ok(!text.includes(app.data), 'no application data on the wire');
    assert.strictEqual(onWire[0].f.metadata.application.data, undefined);
  });

  it('a record that is not a signed v2.0 record is not sent at all', async () => {
    const p = await confirmedPair();
    const unsigned = signedRecord(p.C, { room: 'r' });
    delete unsigned.metadata.sig;
    assert.strictEqual(p.client.trySend({ type: 'cmb', cmb: unsigned }).reason, 'unsealable');
    assert.strictEqual(p.client.trySend({ type: 'cmb', cmb: { categories: {}, metadata: { signatureSuite: 'mmp-sig-v2', sig: 'x' } } }).reason, 'unsealable');
    assert.strictEqual(p.wire.filter((w) => w.f.type === 'cmb-encrypted').length, 0);
    // Positions were given back: the next sealed frame is still sequence 0.
    p.client.trySend({ type: 'mood', mood: 'calm' });
    await until(() => p.events.server.some((e) => e && e.type === 'mood'));
    assert.strictEqual(p.wire.find((w) => w.f.type === 'control-encrypted').f.sequence, '0');
  });

  it('control frames are sealed: a mood never crosses in the clear', async () => {
    const p = await confirmedPair();
    p.client.trySend({ type: 'mood', mood: 'tired after a long session' });
    p.client.trySend({ type: 'wake-channel', platform: 'apns', token: 't', environment: 'sandbox' });
    await until(() => p.events.server.filter((e) => e && e.type).length === 2);
    assert.deepStrictEqual(p.events.server.filter((e) => e && e.type).map((e) => e.type), ['mood', 'wake-channel']);
    const sealed = p.wire.filter((w) => w.f.type === 'control-encrypted');
    assert.strictEqual(sealed.length, 2);
    assert.ok(!JSON.stringify(p.wire).includes('tired after'), 'the mood text is not on the wire');
    assert.deepStrictEqual(sealed.map((w) => w.f.sequence), ['0', '1'], 'one ordered sequence for every sealed frame');
  });

  it('plaintext frames after confirmation are refused (legacy cmb, plaintext mood, a late hello)', async () => {
    const p = await confirmedPair();
    for (const f of [{ type: 'cmb', cmb: {} }, { type: 'mood', mood: 'x' }, { type: 'handshake', nodeId: 'x' }, { type: 'state-sync' }, { type: 'client-hello' }]) p.server.receiveWire(f);
    assert.deepStrictEqual(p.events.server.filter((e) => typeof e === 'string' && e.startsWith('refused')),
      ['refused:cmb:not-sealed', 'refused:mood:not-sealed', 'refused:handshake:not-sealed', 'refused:state-sync:not-sealed', 'refused:client-hello:handshake-after-confirm']);
    assert.strictEqual(p.server.confirmed, true, 'refusing a frame does not end the session');
  });

  it('a forged frame with the right sequence does not desynchronise the session', async () => {
    const p = await confirmedPair();
    const cmb = signedRecord(p.C, { room: 'r' });
    const forged = buildEncryptedFrame({ cmb, sessionId: p.server.sessionId, direction: 'client-to-server', sequence: '0', trafficKey: crypto.randomBytes(32) });
    p.server.receiveWire(forged);
    assert.ok(p.events.server.includes('refused:cmb-encrypted:record did not authenticate'));
    assert.strictEqual(p.server.confirmed, true);
    p.client.trySend({ type: 'cmb', cmb });
    await until(() => p.events.server.some((e) => e && e.type === 'cmb'));
    assert.ok(p.events.server.some((e) => e && e.type === 'cmb'), 'the genuine frame 0 still opens');
  });

  it('frame loss is a gap: the session closes as desynchronised (the owner re-handshakes)', async () => {
    let drop = true;
    const p = await confirmedPair({ tamper: (f) => { if (f.type === 'control-encrypted' && f.sequence === '0' && drop) { drop = false; return { type: 'pong' }; } return f; } });
    p.client.trySend({ type: 'mood', mood: 'lost' });
    p.client.trySend({ type: 'mood', mood: 'next' });
    await until(() => p.server.closed);
    assert.match(p.events.server.join(), /closed:desync/);
  });

  it('a frame from another session is refused, not taken', async () => {
    const a = await confirmedPair();
    const b = await confirmedPair();
    const frame = []; const t = b.wire; void t;
    b.client.trySend({ type: 'mood', mood: 'm' });
    await until(() => b.wire.some((w) => w.f.type === 'control-encrypted'));
    a.server.receiveWire(b.wire.find((w) => w.f.type === 'control-encrypted').f);
    assert.ok(a.events.server.includes('refused:control-encrypted:other-session'));
    void frame;
  });
});
