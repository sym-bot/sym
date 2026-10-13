'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * Two peer-fed stores, bounded without a lockout (0.13.17 re-review; ports of roster-fill.js and
 * announce-cap.js against 0.14's API).
 *   - The key registry. 0.13.17 held at most 16,384 bindings and refused every new one past that,
 *     never evicting: a LAN host filled it with throwaway handshakes in seconds, and no genuine new
 *     peer could be bound after. 0.14 (design D3, binding lifetime): a first-contact binding that
 *     verified nothing expires after 30 days unseen, and when the registry is full the least recently
 *     seen such binding makes room. A flood displaces only its own kind; a binding that protects
 *     history is never displaced; a newcomer is always bound — and if every binding protects history,
 *     its live session still verifies what it signs.
 *   - The relay's announcements name candidates (each costs a handshake): at most 4,096 are held;
 *     past that an announcement for an unknown nodeId is ignored, said once and counted. A peer the
 *     node already knows is unaffected, and one that leaves frees its place.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { WebSocketServer } = require('ws');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const { RosterKeyRegistry } = require('../lib/roster-keys');
const { RelayConnection } = require('../lib/relay');
const { PeerSession } = require('../lib/session');
const { memoryPipe, until, identity, admitAs, deliver, signedRecord } = require('./_core-secure');

const uniq = (base) => `${base}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
const IMPL = { name: 'sym', version: '0.14.0-test' };

/** A bare client session against `node` presenting `local`; resolves when it confirms or ends. */
async function dial(node, local, room) {
  const [tc, ts] = memoryPipe();
  node.connectTransport(ts, { role: 'server' });
  const c = new PeerSession({ role: 'client', transport: tc, kind: 'bonjour', local, room, extensions: ['cmb-encrypted-v2'], implementation: IMPL });
  tc.on('message', (f) => c.receiveWire(f));
  c.start();
  await until(() => c.confirmed || c.closed, 3000);
  return { c, tc };
}

describe('the key registry cannot be locked out by identity churn (roster-fill.js, D3)', () => {
  it('a full registry evicts nothing before it expires: a once-seen honest binding stays, and a squatter of it is a conflict (security review D, p8-evict)', () => {
    let t = 1;
    const r = new RosterKeyRegistry({ now: () => t, maxBindings: 1000 });
    const honest = identity('honest');
    r.bind(honest.nodeId, honest.publicKey, 'proven'); r.noteSeen(honest.nodeId); // seen once, verified nothing
    let full = 0;
    for (let i = 0; i < 5000; i++) { t++; if (r.bind(`fill-${i}`, identity().publicKey, 'proven').reason === 'full') full++; }
    assert.strictEqual(r.size(), 1000, 'bounded');
    assert.strictEqual(full, 4001, 'past the bound a newcomer is refused a durable binding (held for its session only)');
    assert.strictEqual(r.get(honest.nodeId), honest.publicKey, 'the honest binding was never displaced');
    assert.strictEqual(r.bind(honest.nodeId, identity('squatter').publicKey, 'proven').reason, 'conflict', 'and its nodeId cannot be squatted');
    assert.strictEqual(r.evictedCount(), 0, 'nothing is evicted before it expires');
  });

  it('on a node: 300 throwaway identities, each handshaking twice, fill nothing durable; a genuine newcomer runs with its session binding (roster-fill-014)', async () => {
    const node = new SymNode({ name: uniq('roster-fill'), silent: true, discovery: new NullDiscovery(), room: 'g', maxKeyBindings: 100 });
    try {
      await node.start();
      for (let i = 0; i < 300; i++) {
        const id = identity(`throwaway-${i}`);
        for (let k = 0; k < 2; k++) { const { c } = await dial(node, id, 'g'); c.close('done'); }
      }
      await until(() => node._peers.size === 0, 3000);
      assert.strictEqual(node._roster.size(), 0, 'a handshake, or two, earns no durable binding (security review D)');
      const genuine = identity('genuine');
      const { c } = await dial(node, genuine, 'g');
      assert.strictEqual(c.confirmed, true);
      await until(() => node._peers.has(genuine.nodeId), 2000);
      assert.strictEqual(node._keySource(genuine.nodeId), 'session', 'held for its session');
      assert.strictEqual(node._identityKey(genuine.nodeId), genuine.publicKey);
    } finally { await node.stop(); fs.rmSync(nodeDirById(node.nodeId), { recursive: true, force: true }); }
  });

  it('when every binding protects history, a newcomer is not bound but its live session still verifies what it signs', async () => {
    const node = new SymNode({ name: uniq('roster-full'), silent: true, discovery: new NullDiscovery(), room: 'g', maxKeyBindings: 3 });
    try {
      await node.start();
      for (let i = 0; i < 3; i++) { const id = identity(); node._roster.bind(id.nodeId, id.publicKey, 'pinned'); }
      const newcomer = identity('newcomer');
      const s = admitAs(node, newcomer);
      assert.strictEqual(node._roster.has(newcomer.nodeId), false, 'not bound: the registry is full of bindings that protect history');
      const metrics = [];
      node.on('metric', (m) => metrics.push(m));
      await deliver(node, s, { type: 'cmb', cmb: signedRecord(newcomer, { room: 'g', categories: { focus: 'signed by a newcomer to a full registry' } }) });
      assert.ok(!metrics.some((m) => m.type === 'cmb-author-unresolvable'), 'its record verified under the session\'s proven key');
    } finally { await node.stop(); fs.rmSync(nodeDirById(node.nodeId), { recursive: true, force: true }); }
  });

  it('a 0.13 legacy hello on the listener binds nothing at all', async () => {
    const node = new SymNode({ name: uniq('roster-legacy'), silent: true, discovery: new (require('../lib/discovery').BonjourDiscovery)({ mdns: false }), room: 'g' });
    try {
      await node.start();
      const net = require('net');
      const { sendFrame } = require('../lib/frame-parser');
      for (let i = 0; i < 50; i++) {
        await new Promise((resolve) => {
          const sock = net.createConnection({ host: '127.0.0.1', port: node._port }, () => { sendFrame(sock, { type: 'handshake', nodeId: `fill-${i}`, name: 'x', room: 'g', publicKey: identity().publicKey }); setTimeout(() => { sock.destroy(); resolve(); }, 5); });
          sock.on('error', resolve);
        });
      }
      await until(() => node._sessionStats.legacyHellosRefused >= 50, 3000);
      assert.strictEqual(node._roster.size(), 0, 'an unproven hello pins nothing (it was a binding each in 0.13)');
    } finally { await node.stop(); fs.rmSync(nodeDirById(node.nodeId), { recursive: true, force: true }); }
  });
});

describe('peers the relay announces are bounded (announce-cap.js)', () => {
  /** A RelayConnection against a fake relay that sends `messages` after relay-auth. */
  async function withRelay(messages, opts, fn) {
    const wss = new WebSocketServer({ port: 0 });
    const sockets = [];
    wss.on('connection', (ws) => {
      sockets.push(ws);
      ws.once('message', () => { for (const m of messages) ws.send(JSON.stringify(m)); });
    });
    const logs = [];
    const present = new Set();
    let running = true;
    const rc = new RelayConnection({
      relayUrl: `ws://127.0.0.1:${wss.address().port}`, relayToken: 'x'.repeat(40), log: (l) => logs.push(l),
      getIdentity: () => ({ nodeId: 'b'.repeat(64) }), isRunning: () => running, onAuthRefused: () => {},
      onPeerPresent: (id) => present.add(id), onPeerGone: (id) => present.delete(id),
      isKnown: opts.isKnown, nodeName: 'announce-cap',
      ...(opts.max ? { maxAnnouncedPeers: opts.max } : {}),
    });
    try {
      rc.connect();
      await fn({ rc, present, logs, send: (m) => sockets[0].send(JSON.stringify(m)) });
    } finally {
      running = false;
      rc.destroy();
      await new Promise((r) => wss.close(() => r()));
    }
  }

  it('4,100 unknown nodeIds announced (a peer list, then a join each) hold 4,096 candidates; the rest are ignored, said once and counted', async () => {
    const peers = Array.from({ length: 4100 }, (_, i) => ({ nodeId: `ann-${i}`, name: `a${i}` }));
    const list = { type: 'relay-peers', peers };
    const joins = peers.map((p) => ({ type: 'relay-peer-joined', nodeId: p.nodeId, name: p.name }));
    await withRelay([list, ...joins], {}, async ({ rc, present, logs }) => {
      await until(() => rc.state().phase === 'connected' && present.size >= 4096);
      await new Promise((r) => setTimeout(r, 200));
      assert.strictEqual(present.size, 4096);
      assert.strictEqual(rc.state().peers, 4096);
      // The list is read for its first 256 entries (PEER_INFO_MAX); the joins bring the rest.
      assert.ok(logs.some((l) => /peer list of 4100 entries: reading the first 256/.test(l)));
      assert.strictEqual(rc.state().announcementsIgnored, 4, 'the 4 past the bound');
      assert.strictEqual(logs.filter((l) => /announced peers held/.test(l)).length, 1, 'said once');
    });
  });

  it('a peer the node already knows is unaffected at the bound, and relay-peer-left frees a place', async () => {
    const msgs = [
      { type: 'relay-peers', peers: [{ nodeId: 'a1' }, { nodeId: 'a2' }] },
      { type: 'relay-peer-joined', nodeId: 'a3' },          // unknown, at the bound: ignored
      { type: 'relay-peer-joined', nodeId: 'lan-peer' },    // known (a live session): taken
      { type: 'relay-peer-joined', nodeId: 'a1' },          // already held: taken again
    ];
    await withRelay(msgs, { max: 2, isKnown: (id) => id === 'lan-peer' }, async ({ rc, present, send }) => {
      await until(() => present.has('lan-peer'));
      await new Promise((r) => setTimeout(r, 100));
      assert.deepStrictEqual([...present].sort(), ['a1', 'a2', 'lan-peer']);
      assert.strictEqual(rc.state().announcementsIgnored, 1);
      send({ type: 'relay-peer-left', nodeId: 'a2' });
      send({ type: 'relay-peer-left', nodeId: 'lan-peer' });
      await until(() => !present.has('a2'));
      send({ type: 'relay-peer-joined', nodeId: 'a4' });
      await until(() => present.has('a4'));
      assert.strictEqual(present.has('a4'), true, 'room again once one left');
    });
  });
});
