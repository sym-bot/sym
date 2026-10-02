'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * 0.13.17, two more peer-fed stores with no bound, bounded here; sym 0.14.0's proven sessions
 * remove the cause (a peer exists only after a handshake that proves its key).
 *   - The roster key registry added a binding, and a line to its file, for every handshake that
 *     named a new nodeId. It now holds at most 16,384; when full a NEW binding is refused and none
 *     is ever evicted (forgetting one would let its nodeId be pinned again with another key). The
 *     refusal is said once and counted in status().roster.refusedFull, and a record signed by a key
 *     that could not be pinned fails verification.
 *   - The relay's announcements (join notices, peer-list entries) added a peer for every nodeId
 *     they named. At most 4,096 announced peers are held; an announcement for an unknown nodeId
 *     past that is ignored, said once and counted. Known peers are unaffected, and relay-peer-left
 *     still prunes.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { WebSocketServer } = require('ws');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const { RosterKeyRegistry, MAX_BINDINGS } = require('../lib/roster-keys');
const { RelayConnection } = require('../lib/relay');
const { createCMB, signCMB } = require('../lib/core');

const uniq = (base) => `${base}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
const until = async (cond, ms = 5000) => { for (let t = 0; t < ms && !cond(); t += 20) await new Promise((r) => setTimeout(r, 20)); };

describe('the roster key registry is bounded and never evicts', () => {
  it(`holds at most ${MAX_BINDINGS}; a new binding past that is refused, said once and counted`, () => {
    const lines = [];
    const r = new RosterKeyRegistry({ log: (l) => lines.push(l) });
    for (let i = 0; i < MAX_BINDINGS; i++) assert.strictEqual(r.pin(`n${i}`, `k${i}`, 'handshake').pinned, true);
    assert.deepStrictEqual(r.pin('late', 'kl', 'handshake'), { pinned: false, reason: 'full' });
    assert.deepStrictEqual(r.pin('late2', 'kl2', 'grant'), { pinned: false, reason: 'full' });
    assert.strictEqual(r.size(), MAX_BINDINGS);
    assert.strictEqual(r.refusedFull(), 2);
    assert.strictEqual(lines.filter((l) => /registry is full/.test(l)).length, 1, 'said once');
  });

  it('never evicts: a full registry keeps every binding, refuses a rebinding as before, and still takes a stronger source for a held nodeId and the anchor', () => {
    const r = new RosterKeyRegistry({ maxBindings: 3 });
    r.pin('a', 'ka', 'grant');
    r.pin('b', 'kb', 'handshake');
    r.pin('c', 'kc', 'handshake');
    assert.strictEqual(r.pin('d', 'kd', 'handshake').reason, 'full');
    assert.deepStrictEqual(['a', 'b', 'c'].map((n) => r.get(n)), ['ka', 'kb', 'kc'], 'nothing evicted');
    assert.strictEqual(r.pin('b', 'other', 'handshake').reason, 'conflict', 'a held nodeId is not re-pinned with another key');
    assert.strictEqual(r.pin('a', 'ka2', 'handshake').pinned, true, 'a stronger source for a held nodeId does not grow it');
    assert.strictEqual(r.pin('founder', 'kf', 'anchor').pinned, true, 'the anchor is configuration, always pinned');
    assert.strictEqual(r.refusedFull(), 1);
  });

  it('a full registry reloaded from its file keeps what it held and refuses the rest', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'roster-full-'));
    try {
      const r = new RosterKeyRegistry({ dir, maxBindings: 2 });
      r.pin('a', 'ka', 'handshake');
      r.pin('b', 'kb', 'handshake');
      r.pin('c', 'kc', 'handshake');
      fs.appendFileSync(path.join(dir, 'roster-keys.jsonl'), JSON.stringify({ nodeId: 'z', key: 'kz', source: 'handshake' }) + '\n');
      const again = new RosterKeyRegistry({ dir, maxBindings: 2 });
      assert.deepStrictEqual([again.get('a'), again.get('b'), again.get('c'), again.get('z')], ['ka', 'kb', undefined, undefined]);
      assert.strictEqual(again.refusedFull(), 1);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('on a node: a key the full roster refused is not resolvable at all, so what it signs is not verified; status() shows the count', () => {
    const name = uniq('roster-full-node');
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: 'g' });
    const keypair = () => {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
      return { pub: publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('base64url'),
        priv: privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(16).toString('base64url') };
    };
    const signedBy = (k, author) => {
      const cmb = createCMB({ categories: { focus: `work from ${author}`, issue: 'x', intent: 'x', motivation: 'x', commitment: 'x', perspective: author, mood: { text: 'neutral', valence: 0, arousal: 0 } }, createdBy: author });
      signCMB(cmb, k.priv);
      return { type: 'cmb', timestamp: Date.now(), cmb: JSON.parse(JSON.stringify(cmb)) };
    };
    try {
      node._roster._maxBindings = node._roster.size() + 1; // room for exactly one more (keeps this fast)
      const known = keypair(), late = keypair();
      node._receiveFrame('known-peer', 'known', { type: 'handshake', nodeId: 'known-peer', name: 'known', room: 'g', publicKey: known.pub }, 'relay');
      node._receiveFrame('late-peer', 'late', { type: 'handshake', nodeId: 'late-peer', name: 'late', room: 'g', publicKey: late.pub }, 'relay');
      assert.strictEqual(node._roster.get('known-peer'), known.pub);
      assert.strictEqual(node._roster.has('late-peer'), false, 'the full roster refused it');
      assert.strictEqual(node._identityKey('late-peer'), undefined, 'and it is not resolvable through the direct-handshake fallback either');
      assert.deepStrictEqual(node.status().roster, { size: node._roster.size(), refusedFull: 1 });
      const a = signedBy(known, 'known');
      const b = signedBy(late, 'late');
      node._frameHandler._rejectOnBadSignature('known-peer', 'known', a);
      node._frameHandler._rejectOnBadSignature('late-peer', 'late', b);
      assert.strictEqual(a._cmbVerified, true, 'a pinned key verifies');
      assert.strictEqual(b._cmbVerified, false, 'an unpinned key does not: no verified authorship, no elevation');
    } finally { node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });
});

describe('peers the relay announces are bounded', () => {
  /** A RelayConnection against a fake relay that sends `messages` after relay-auth. */
  async function withRelay(messages, opts, fn) {
    const wss = new WebSocketServer({ port: 0 });
    const sockets = [];
    wss.on('connection', (ws) => {
      sockets.push(ws);
      ws.once('message', () => { for (const m of messages) ws.send(JSON.stringify(m)); });
    });
    const peers = opts.peers || new Map();
    const logs = [];
    let running = true;
    const rc = new RelayConnection({
      relayUrl: `ws://127.0.0.1:${wss.address().port}`, relayToken: 'x'.repeat(40), log: (l) => logs.push(l),
      getIdentity: () => ({ nodeId: 'b'.repeat(64) }), isRunning: () => running, getPeers: () => peers, getMeshNode: () => null,
      createPeer: (transport, peerId) => {
        const p = peers.get(peerId) || { peerId, transports: new Map() };
        p.transports.set('relay', transport);
        transport.on('close', () => { p.transports.delete('relay'); if (p.transports.size === 0) peers.delete(peerId); });
        return p;
      },
      addPeer: (p) => peers.set(p.peerId, p),
      handlePeerMessage: () => {}, onPeerLeft: () => {}, onAuthRefused: () => {},
      nodeName: 'announce-cap', peerWakeChannels: new Map(), saveWakeChannels: () => {},
      ...(opts.max ? { maxAnnouncedPeers: opts.max } : {}),
    });
    try {
      rc.connect();
      await fn({ rc, peers, logs, send: (m) => sockets[0].send(JSON.stringify(m)) });
    } finally {
      running = false;
      rc.destroy();
      await new Promise((r) => wss.close(() => r()));
    }
  }

  it('a peer list naming 4,100 unknown nodeIds adds 4,096; the rest are ignored, said once and counted', async () => {
    const list = { type: 'relay-peers', peers: Array.from({ length: 4100 }, (_, i) => ({ nodeId: `ann-${i}`, name: `a${i}` })) };
    await withRelay([list], {}, async ({ rc, peers, logs }) => {
      await until(() => rc.state().phase === 'connected' && peers.size >= 4096);
      await new Promise((r) => setTimeout(r, 100));
      assert.strictEqual(peers.size, 4096);
      assert.strictEqual(rc.state().announcementsIgnored, 4);
      assert.strictEqual(logs.filter((l) => /announced peers held/.test(l)).length, 1, 'said once');
    });
  });

  it('known peers are unaffected at the cap, and relay-peer-left still prunes', async () => {
    const lan = { peerId: 'lan-peer', transports: new Map([['bonjour', { send() { return true; } }]]) };
    const peers = new Map([['lan-peer', lan]]);
    const msgs = [
      { type: 'relay-peers', peers: [{ nodeId: 'a1' }, { nodeId: 'a2' }] },
      { type: 'relay-peer-joined', nodeId: 'a3' },                 // unknown, at the cap: ignored
      { type: 'relay-peer-joined', nodeId: 'lan-peer' },           // known (live LAN transport): taken
      { type: 'relay-peer-joined', nodeId: 'a1' },                 // already announced: taken again
    ];
    await withRelay(msgs, { max: 2, peers }, async ({ rc, logs, send }) => {
      await until(() => lan.transports.has('relay'));
      await new Promise((r) => setTimeout(r, 100));
      assert.deepStrictEqual([...peers.keys()].sort(), ['a1', 'a2', 'lan-peer']);
      assert.strictEqual(lan.transports.has('relay'), true, 'a known peer gets its relay transport at the cap');
      assert.strictEqual(rc.state().announcementsIgnored, 1);
      send({ type: 'relay-peer-left', nodeId: 'a2' });
      await until(() => !peers.has('a2'));
      assert.strictEqual(peers.has('a2'), false, 'pruned as before');
      send({ type: 'relay-peer-joined', nodeId: 'a4' });
      await until(() => peers.has('a4'));
      assert.strictEqual(peers.has('a4'), true, 'room again once one left');
      assert.ok(logs.some((l) => /announced peers held/.test(l)));
    });
  });
});
