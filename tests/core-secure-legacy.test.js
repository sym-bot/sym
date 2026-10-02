'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * Design D7 — Legacy Import: explicit, outbound, temporary. Against a fake 0.13 endpoint that speaks
 * the one-frame `handshake` (the real 0.13.17 run is tests/integration/legacy-import-013.js):
 *   - a route dials whatever the id order (0.13 dials only when its id is smaller on the loopback);
 *   - the fingerprint is mandatory, and a hello presenting another key is refused;
 *   - records from it are quarantined (verified: false, profile legacy-import), and only those the
 *     routed node signed with the pinned key are taken;
 *   - what this node sends is a legacy cmb under the legacy E2E construction, never plaintext;
 *   - the sticky floor is the registry's proven binding, and it survives a restart;
 *   - a legacy hello on the Core Secure listener is refused, and a record without TXT mmp=2.0 is
 *     never dialled as Core Secure.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const net = require('net');
const crypto = require('crypto');
const { SymNode } = require('../lib/node');
const { NullDiscovery, BonjourDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const { TcpTransport } = require('../lib/transport');
const { checkRoute } = require('../lib/legacy-import');
const { keyFingerprint } = require('../lib/roster-keys');
const { e2eGenerateKeyPair, e2eDeriveSharedSecret, encryptCategories, decryptCategories, createCMB, signCMB } = require('../lib/core');
const { sendFrame } = require('../lib/frame-parser');
const { until, identity } = require('./_core-secure');

const uniq = (b) => `${b}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;

/** A fake 0.13 node's TCP endpoint: answers a legacy hello with its own, and speaks legacy cmb. */
async function fake013({ id = identity('legacy'), room = 'lg-room', presentKey } = {}) {
  const e2e = e2eGenerateKeyPair();
  const seen = { frames: [], records: [], secret: null, peer: null };
  const server = net.createServer((sock) => {
    sock.on('error', () => {});
    const t = new TcpTransport(sock);
    seen.transport = t;
    t.on('message', (f) => {
      seen.frames.push(f);
      if (f.type === 'handshake') {
        seen.peer = f;
        seen.secret = e2eDeriveSharedSecret(e2e.privateKey, Buffer.from(f.e2ePublicKey, 'base64'));
        t.send({ type: 'handshake', nodeId: id.nodeId, name: id.name, version: '0.2.3', extensions: [], room, publicKey: presentKey || id.publicKey, e2ePublicKey: e2e.publicKey.toString('base64'), lifecycleRole: 'participant' });
      } else if (f.type === 'cmb' && f.cmb && typeof f.cmb.categories === 'string') {
        seen.records.push({ frame: f, categories: decryptCategories(f.cmb.categories, f.cmb._e2e.nonce, seen.secret) });
      }
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  /** Send a 0.13-shaped record (internal mmp-sig-v2 suite), legacy-encrypted, directed or not. */
  const sendRecord = ({ focus, to, signer = id }) => {
    const cmb = createCMB({ categories: { focus }, createdBy: id.name, room, to: to ?? null });
    signCMB(cmb, signer.privateKey);
    const { ciphertext, nonce } = encryptCategories(cmb.categories, seen.secret);
    seen.transport.send({ type: 'cmb', timestamp: Date.now(), cmb: { ...cmb, categories: ciphertext, _e2e: { nonce } }, ...(to ? { to, directed: true } : {}) });
  };
  return { id, port: server.address().port, seen, sendRecord, close: () => new Promise((r) => server.close(() => r())) };
}

function routeTo(fake) { return { nodeId: fake.id.nodeId, endpoint: `127.0.0.1:${fake.port}`, key: fake.id.publicKey, name: 'legacy' }; }
async function stopAll(...nodes) {
  for (const n of nodes) { try { await n.stop(); } catch { /* */ } try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ } }
}

describe('Legacy Import routes (D7)', () => {
  it('the identity key fingerprint is mandatory; a route without one is refused', () => {
    const id = identity('x');
    assert.throws(() => checkRoute({ nodeId: id.nodeId, endpoint: '127.0.0.1:1' }), /fingerprint is mandatory/);
    assert.throws(() => checkRoute({ nodeId: id.nodeId, endpoint: 'nowhere', key: id.publicKey }), /endpoint/);
    assert.throws(() => checkRoute({ nodeId: id.nodeId, endpoint: 'relay', key: id.publicKey, fingerprint: keyFingerprint(identity().publicKey) }), /disagree/);
    assert.strictEqual(checkRoute({ nodeId: id.nodeId, endpoint: 'relay', fingerprint: keyFingerprint(id.publicKey) }).fingerprint, keyFingerprint(id.publicKey));
  });

  for (const order of ['smaller', 'larger']) {
    it(`this node dials the route itself when the legacy id is ${order} than its own, and the session is quarantined both ways`, async () => {
      const lid = identity('legacy');
      lid.nodeId = order === 'smaller' ? `00000000-0000-7000-8000-${crypto.randomBytes(6).toString('hex')}` : `ffffffff-ffff-7fff-bfff-${crypto.randomBytes(6).toString('hex')}`;
      const fake = await fake013({ id: lid });
      const node = new SymNode({ name: uniq('lg'), silent: true, discovery: new NullDiscovery(), room: 'lg-room', legacyRoutes: [routeTo(fake)] });
      try {
        await node.start();
        await until(() => node._peers.has(lid.nodeId), 5000);
        const st = node.status().legacyImport;
        assert.strictEqual(st.sessions.length, 1);
        assert.match(st.sessions[0].encryption, /no forward secrecy, no transcript proof/);
        assert.strictEqual(node._roster.source(lid.nodeId), 'pinned', 'the route\'s key is pinned');
        assert.strictEqual(node.peers().find((p) => p.peerId === lid.nodeId).profile, 'legacy-import');
        // In: a directed 0.13 record is delivered, quarantined.
        const got = [];
        node.on('cmb-accepted', (e) => got.push(e));
        fake.sendRecord({ focus: 'from the 0.13 side', to: node.nodeId });
        await until(() => got.length > 0, 5000);
        assert.strictEqual(got[0].verified, false);
        assert.strictEqual(got[0].profile, 'legacy-import');
        assert.strictEqual(got[0].author?.nodeId ?? null, null, 'no verified author');
        // A record signed by another key on the route is refused.
        const metrics = [];
        node.on('metric', (m) => metrics.push(m));
        fake.sendRecord({ focus: 'signed by someone else', to: node.nodeId, signer: identity('other') });
        await until(() => metrics.some((m) => m.type === 'legacy-import-refused'), 3000);
        // Out: this node's record goes as a legacy cmb, encrypted, directed by its signed to.
        node.remember({ focus: 'from the 0.14 side', issue: 'i', intent: 'x', motivation: 'y', commitment: 'z', perspective: 'p', mood: { text: 'calm', valence: 0, arousal: 0 } }, { to: lid.nodeId });
        await until(() => fake.seen.records.length > 0, 5000);
        const out = fake.seen.records[0];
        assert.strictEqual(out.frame.to, lid.nodeId);
        assert.strictEqual(out.categories.focus.text, 'from the 0.14 side');
        assert.ok(!JSON.stringify(fake.seen.frames).includes('from the 0.14 side'), 'never in the clear');
        assert.strictEqual(out.frame.cmb.metadata.signatureSuite, 'mmp-sig-v2.0');
      } finally { await stopAll(node); await fake.close(); }
    });
  }

  it('a hello presenting a key other than the pinned one is refused', async () => {
    const lid = identity('legacy');
    const fake = await fake013({ id: lid, presentKey: identity('squatter').publicKey });
    const node = new SymNode({ name: uniq('lg'), silent: true, discovery: new NullDiscovery(), room: 'lg-room', legacyRoutes: [routeTo(fake)] });
    try {
      await node.start();
      await until(() => node.status().legacyImport.refused.some((r) => /fingerprint-mismatch/.test(r.why)), 5000);
      assert.strictEqual(node._peers.has(lid.nodeId), false);
    } finally { await stopAll(node); await fake.close(); }
  });

  it('the sticky floor is the persisted proven binding: the route is refused, across a restart', async () => {
    const lid = identity('legacy');
    const fake = await fake013({ id: lid });
    const name = uniq('lg-floor');
    let node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: 'lg-room', legacyRoutes: [routeTo(fake)] });
    try {
      node._roster.bind(lid.nodeId, lid.publicKey, 'proven'); // it once proved itself over Core Secure
      await node.start();
      await new Promise((r) => setTimeout(r, 300));
      assert.strictEqual(node._peers.has(lid.nodeId), false);
      assert.match(node.status().legacyImport.refused.find((r) => r.nodeId === lid.nodeId).why, /sticky floor/);
      const id = node.nodeId;
      await node.stop();
      node = new SymNode({ name, nodeId: id, create: false, silent: true, discovery: new NullDiscovery(), room: 'lg-room', legacyRoutes: [routeTo(fake)] });
      await node.start();
      await new Promise((r) => setTimeout(r, 300));
      assert.strictEqual(node._peers.has(lid.nodeId), false, 'still refused after the restart');
      // An operator reset lifts it.
      node._roster.resetFloor(lid.nodeId);
      await node.stop();
      node = new SymNode({ name, nodeId: id, create: false, silent: true, discovery: new NullDiscovery(), room: 'lg-room', legacyRoutes: [routeTo(fake)] });
      await node.start();
      await until(() => node._peers.has(lid.nodeId), 5000);
      assert.ok(node._peers.has(lid.nodeId));
    } finally { await stopAll(node); await fake.close(); }
  });
});

describe('the Core Secure listener and discovery (D2)', () => {
  it('a legacy hello on the listener is refused at once and counted; no route means no peer', async () => {
    const node = new SymNode({ name: uniq('lg-listen'), silent: true, discovery: new BonjourDiscovery({ mdns: false }), room: 'lg-room' });
    try {
      await node.start();
      const sock = net.createConnection({ host: '127.0.0.1', port: node._port });
      await new Promise((r) => sock.once('connect', r));
      const closed = new Promise((r) => sock.once('close', r));
      sock.on('error', () => {});
      const lid = identity('legacy');
      sendFrame(sock, { type: 'handshake', nodeId: lid.nodeId, name: 'legacy-0.13', publicKey: lid.publicKey, room: 'lg-room' });
      await closed;
      await until(() => node._sessionStats.legacyHellosRefused === 1, 2000);
      assert.strictEqual(node._sessionStats.legacyHellosRefused, 1);
      assert.strictEqual(node._peers.size, 0);
      assert.strictEqual(node._roster.has(lid.nodeId), false, 'nothing is pinned from it');
    } finally { await stopAll(node); }
  });

  it('a discovery record is dialled as Core Secure only with TXT mmp=2.0, and only by the smaller nodeId', async () => {
    const { EventEmitter } = require('events');
    const disco = new EventEmitter();
    disco.start = async () => 0; disco.stop = async () => {}; disco.reconnect = () => {};
    const node = new SymNode({ name: uniq('lg-disco'), silent: true, discovery: disco, room: 'default' });
    const dialled = [];
    node._connectToPeer = (address, port, peerId) => dialled.push(peerId);
    try {
      await node.start();
      const larger = `ffffffff-ffff-7fff-bfff-${crypto.randomBytes(6).toString('hex')}`;
      const legacy = `fffffffe-ffff-7fff-bfff-${crypto.randomBytes(6).toString('hex')}`;
      const smaller = `00000000-0000-7000-8000-${crypto.randomBytes(6).toString('hex')}`;
      disco.emit('peer-found', '127.0.0.1', 1, legacy, 'legacy', { mmp: null, room: 'default' });
      disco.emit('peer-found', '127.0.0.1', 4, legacy, 'legacy-old-txt', { mmp: '1.0', room: 'default' });
      disco.emit('peer-found', '127.0.0.1', 2, larger, 'v2', { mmp: '2.0', room: 'default' });
      disco.emit('peer-found', '127.0.0.1', 3, smaller, 'v2-smaller', { mmp: '2.0', room: 'default' });
      assert.deepStrictEqual(dialled, [larger], 'a record without mmp=2.0 is not dialled; the larger v2 one is; the smaller one dials us');
    } finally { await stopAll(node); }
  });

  it('the advertisement carries mmp=2.0 and the room (§5.1)', async () => {
    const d = new BonjourDiscovery({ mdns: false, room: 'lg-room' });
    assert.strictEqual(d._room, 'lg-room');
    // The loopback registration names the profile too.
    const id = identity('adv');
    await d.start({ nodeId: id.nodeId, name: 'adv', publicKey: id.publicKey, hostname: 'h.local' }, () => {});
    try {
      const rec = JSON.parse(fs.readFileSync(d._regFile, 'utf8'));
      assert.strictEqual(rec.mmp, '2.0');
      assert.strictEqual(rec.room, 'lg-room');
    } finally { await d.stop(); }
  });
});
