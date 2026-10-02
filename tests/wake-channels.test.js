'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * Wake channels: learned from the peer itself, the relay's list, or another peer's `peer-info`
 * gossip, which nothing authenticates. Every peer re-sends its whole list on every connect, so a
 * repeat must change nothing and log nothing; gossip must never repoint a phone's own token; and a
 * channel nobody has seen first-hand ages out however often it is forwarded.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const { WAKE_CHANNEL_TTL_MS } = require('../lib/core/wake');

const DAY = 24 * 60 * 60 * 1000;
const apns = (token) => ({ platform: 'apns', token, environment: 'sandbox' });

function withNode(fn) {
  const name = `wake-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
  const lines = [];
  node._log = (m) => lines.push(m);
  node._wakeManager._log = (m) => lines.push(m);
  let writes = 0;
  const save = node._wakeManager.saveWakeChannels.bind(node._wakeManager);
  node._wakeManager.saveWakeChannels = () => { writes++; save(); };
  try { return fn(node, { lines, writes: () => writes }); } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
}

describe('peer-info gossip', () => {
  it('learns new channels with one line per frame, and a repeat of the same list is silent', () => {
    withNode((node, io) => {
      const now = Date.now();
      const frame = { type: 'peer-info', peers: [
        { nodeId: 'phone-1', name: 'unknown', wakeChannel: apns('t1'), lastSeen: now - 1000 },
        { nodeId: 'phone-2', name: 'unknown', wakeChannel: apns('t2'), lastSeen: now - 2000 },
      ] };
      node._frameHandler._handlePeerInfo('peer-x', 'xmesh', frame);
      assert.deepStrictEqual(io.lines.filter((l) => /Gossip/.test(l)), ['Gossip from xmesh: learned 2 wake channel(s)']);
      assert.strictEqual(io.writes(), 1);
      for (let i = 0; i < 50; i++) node._frameHandler._handlePeerInfo('peer-x', 'xmesh', frame);
      assert.strictEqual(io.lines.filter((l) => /Gossip/.test(l)).length, 1, 'a reconnect storm logs nothing more');
      assert.strictEqual(io.writes(), 1, 'and writes nothing more');
      assert.strictEqual(node._peerWakeChannels.get('phone-1').lastSeen, now - 1000, 'lastSeen is the sighting the frame carried');
    });
  });

  it('never replaces a token the phone gave us itself over a session that proved its key', () => {
    withNode((node) => {
      node._peerKeyProven = (id) => id === 'phone-1';
      node._frameHandler._handleWakeChannel('phone-1', 'melotune', apns('own-token'));
      node._frameHandler._handlePeerInfo('peer-x', 'mallory', { peers: [{ nodeId: 'phone-1', wakeChannel: apns('attacker'), lastSeen: Date.now() }] });
      assert.strictEqual(node._peerWakeChannels.get('phone-1').token, 'own-token');
      assert.strictEqual(node._peerWakeChannels.get('phone-1').source, 'direct');
    });
  });

  it('replaces an older gossiped token only with a newer sighting', () => {
    withNode((node) => {
      const now = Date.now();
      const wm = node._wakeManager;
      assert.strictEqual(wm.learnWakeChannel('phone-1', apns('old'), { source: 'gossip', lastSeen: now - 5000 }), 'added');
      assert.strictEqual(wm.learnWakeChannel('phone-1', apns('stale'), { source: 'gossip', lastSeen: now - 9000 }), 'ignored');
      assert.strictEqual(wm.learnWakeChannel('phone-1', apns('fresh'), { source: 'gossip', lastSeen: now - 100 }), 'updated');
      assert.strictEqual(node._peerWakeChannels.get('phone-1').token, 'fresh');
    });
  });

  it('ignores a sighting older than the TTL and a frame entry with no sighting', () => {
    withNode((node) => {
      const wm = node._wakeManager;
      assert.strictEqual(wm.learnWakeChannel('phone-1', apns('t'), { source: 'gossip', lastSeen: Date.now() - WAKE_CHANNEL_TTL_MS - DAY }), 'ignored');
      assert.strictEqual(wm.learnWakeChannel('phone-2', apns('t'), { source: 'gossip' }), 'ignored', 'no lastSeen means no evidence');
      assert.strictEqual(node._peerWakeChannels.size, 0);
    });
  });
});

describe('refreshes', () => {
  it('a repeat sighting updates memory, and asks for a save only once it is an hour newer', () => {
    withNode((node) => {
      const wm = node._wakeManager;
      let t = 1_000_000_000_000;
      wm._now = () => t;
      assert.strictEqual(wm.learnWakeChannel('phone-1', apns('t'), { source: 'direct' }), 'added');
      t += 5 * 60 * 1000;
      assert.strictEqual(wm.learnWakeChannel('phone-1', apns('t'), { source: 'direct' }), 'unchanged');
      assert.strictEqual(node._peerWakeChannels.get('phone-1').lastSeen, t, 'memory still holds the newest sighting');
      t += 61 * 60 * 1000;
      assert.strictEqual(wm.learnWakeChannel('phone-1', apns('t'), { source: 'direct' }), 'refreshed');
    });
  });
});

describe('gossip sent and expiry', () => {
  it('forwards the lastSeen it holds, not the time of sending, and drops expired channels', () => {
    withNode((node) => {
      const wm = node._wakeManager;
      const now = Date.now();
      wm.learnWakeChannel('phone-1', apns('a'), { source: 'gossip', lastSeen: now - 3 * DAY });
      wm.learnWakeChannel('phone-2', apns('b'), { source: 'gossip', lastSeen: now - 1000 });
      let t = now;
      wm._now = () => t;
      const out = wm.gossipEntries('peer-x');
      assert.deepStrictEqual(out.map((e) => [e.nodeId, e.lastSeen]).sort(), [['phone-1', now - 3 * DAY], ['phone-2', now - 1000]]);
      t = now + WAKE_CHANNEL_TTL_MS - 2 * DAY; // phone-1 is now past the TTL, phone-2 is not
      let saves = 0;
      wm.saveWakeChannels = () => { saves++; };
      assert.deepStrictEqual(wm.gossipEntries('peer-x').map((e) => e.nodeId), ['phone-2']);
      assert.strictEqual(node._peerWakeChannels.has('phone-1'), false, 'the expired channel is gone from memory too');
      assert.strictEqual(saves, 0, 'and nothing is written on the connection path (0.14.0 part A2 review)');
    });
  });

  it('gives a channel saved before lastSeen existed one TTL of grace, once', () => {
    withNode((node) => {
      const wm = node._wakeManager;
      fs.mkdirSync(require('path').dirname(wm._wakeChannelsFile), { recursive: true });
      fs.writeFileSync(wm._wakeChannelsFile, JSON.stringify({ 'old-phone': apns('legacy') }));
      node._peerWakeChannels.clear();
      const loadedAt = Date.now();
      wm._now = () => loadedAt;
      wm.loadWakeChannels();
      assert.strictEqual(node._peerWakeChannels.get('old-phone').lastSeen, loadedAt);
      wm.saveWakeChannels();
      node._peerWakeChannels.clear();
      wm._now = () => loadedAt + WAKE_CHANNEL_TTL_MS + DAY;
      wm.loadWakeChannels();
      assert.strictEqual(node._peerWakeChannels.has('old-phone'), false, 'the grace is not renewed by a later load');
      assert.deepStrictEqual(JSON.parse(fs.readFileSync(wm._wakeChannelsFile, 'utf8')), {}, 'and the file is cleaned');
    });
  });
});

describe('relay peer list', () => {
  it('learns from the relay with one line per list, silent on a repeat', () => {
    withNode((node, io) => {
      const relayLines = [];
      node._relay._log = (m) => relayLines.push(m);
      node._relay._setPhase = () => {};
      const list = { type: 'relay-peers', peers: [
        { nodeId: 'phone-1', name: 'melotune', wakeChannel: apns('r1'), offline: true },
        { nodeId: 'phone-2', name: 'melomove', wakeChannel: apns('r2'), offline: true },
      ] };
      node._relay._handleRelayPeers(list);
      node._relay._handleRelayPeers(list);
      assert.deepStrictEqual(relayLines.filter((l) => /wake channel/.test(l)), ['Relay: learned 2 wake channel(s)']);
      assert.strictEqual(io.writes(), 1, 'one write for the first list, none for the repeat');
      assert.strictEqual(node._peerWakeChannels.get('phone-1').source, 'relay');
    });
  });

  it('a gossiped token cannot repoint a channel the relay holds', () => {
    withNode((node) => {
      node._relay._learnWakeChannel('phone-1', apns('relay-token'), { source: 'relay' });
      node._frameHandler._handlePeerInfo('peer-x', 'mallory', { peers: [{ nodeId: 'phone-1', wakeChannel: apns('attacker'), lastSeen: Date.now() }] });
      assert.strictEqual(node._peerWakeChannels.get('phone-1').token, 'relay-token');
    });
  });
});

describe('0.14.0 review F2/F3', () => {
  it('a channel kept by 0.13.14 (no source) is not repointed by gossip, and the relay or the phone still can', () => {
    withNode((node) => {
      const wm = node._wakeManager;
      fs.mkdirSync(require('path').dirname(wm._wakeChannelsFile), { recursive: true });
      fs.writeFileSync(wm._wakeChannelsFile, JSON.stringify({ 'phone-1': apns('phones-own') }));
      wm.loadWakeChannels();
      // A minute later, so the gossip is strictly newer than the load (the old ranking let it through).
      const later = Date.now() + 60_000;
      wm._now = () => later;
      node._frameHandler.handle('peer-x', 'peer-x', { type: 'peer-info', peers: [{ nodeId: 'phone-1', wakeChannel: apns('ATTACKER'), lastSeen: later }] });
      assert.strictEqual(wm._peerWakeChannels.get('phone-1').token, 'phones-own', 'gossip cannot repoint it');
      assert.strictEqual(wm.learnWakeChannel('phone-1', apns('re-registered'), { source: 'relay' }), 'updated', 'the relay can');
      assert.strictEqual(wm.learnWakeChannel('phone-1', apns('again'), { source: 'direct' }), 'updated', 'the phone can');
    });
  });

  it('fabricated gossip is bounded: one frame reads at most 256 entries, and the map holds at most its cap', () => {
    withNode((node, io) => {
      const wm = node._wakeManager;
      wm._maxChannels = 300;
      wm.learnWakeChannel('real-phone', apns('own'), { source: 'direct' });
      const now = Date.now();
      const flood = (from) => ({ type: 'peer-info', peers: Array.from({ length: 2000 }, (_, i) => ({ nodeId: `fake-${from}-${i}`, wakeChannel: apns(`f${i}`), lastSeen: now })) });
      node._frameHandler.handle('peer-x', 'peer-x', flood('a'));
      assert.strictEqual(wm._peerWakeChannels.size, 1 + 256, 'the first 256 entries of one frame');
      assert.ok(io.lines.some((l) => /2000 entries, reading the first 256/.test(l)));
      node._frameHandler.handle('peer-x', 'peer-x', flood('b'));
      assert.strictEqual(wm._peerWakeChannels.size, 300, 'never past the cap');
      assert.strictEqual(wm._peerWakeChannels.get('real-phone').token, 'own', 'gossip only displaces gossip');
    });
  });

  it('a full map of first-hand channels is not displaced by gossip, and a new first-hand one displaces the oldest weakest', () => {
    withNode(() => {
      const { WakeManager } = require('../lib/core/wake');
      let t = 1_000_000;
      const wm = new WakeManager({ wakeChannelsFile: require('path').join(require('os').tmpdir(), `wc-${process.pid}-${Date.now()}.json`), peerWakeChannels: new Map(), peerLastWake: new Map(), pendingFrames: new Map(), maxWakeChannels: 3, now: () => t, log: () => {} });
      wm.learnWakeChannel('p1', apns('1'), { source: 'direct' }); t += 1000;
      wm.learnWakeChannel('p2', apns('2'), { source: 'relay' }); t += 1000;
      wm.learnWakeChannel('p3', apns('3'), { source: 'direct' }); t += 1000;
      assert.strictEqual(wm.learnWakeChannel('g1', apns('g'), { source: 'gossip', lastSeen: t }), 'ignored');
      assert.strictEqual(wm.learnWakeChannel('p4', apns('4'), { source: 'direct' }), 'added');
      assert.deepStrictEqual([...wm._peerWakeChannels.keys()].sort(), ['p1', 'p3', 'p4'], 'the relay-sourced one went: the weakest');
    });
  });
});

// 0.14.0 release review, part B (F2-F4, F7, F8, F10, F12).
describe('0.14.0 release review B: who may set a wake channel', () => {
  it("a wake-channel frame from a session that proved nothing is trusted as gossip, never over the phone's own (F2)", () => {
    withNode((node) => {
      const wm = node._wakeManager;
      // The phone registered its channel through the relay (its own authenticated session).
      wm.learnWakeChannel('phone-1', apns('phones-own'), { source: 'relay' });
      // Mallory handshakes claiming the phone's nodeId and sends its own token.
      node._frameHandler.handle('phone-1', 'mallory', { type: 'wake-channel', platform: 'apns', token: 'MALLORY', environment: 'sandbox' });
      assert.strictEqual(node._peerWakeChannels.get('phone-1').token, 'phones-own', 'an unproven claim cannot repoint it');
      // A channel only an unproven frame gave is held at the lowest rank: it repoints nothing above it.
      node._frameHandler.handle('phone-2', 'phone-2', { type: 'wake-channel', platform: 'apns', token: 'p2', environment: 'sandbox' });
      assert.strictEqual(node._peerWakeChannels.get('phone-2').source, 'unproven');
      // A session that proved the key is the peer itself: top rank.
      node._peerKeyProven = (id) => id === 'phone-1';
      node._frameHandler.handle('phone-1', 'phone-1', { type: 'wake-channel', platform: 'apns', token: 'rotated', environment: 'sandbox' });
      assert.deepStrictEqual([node._peerWakeChannels.get('phone-1').token, node._peerWakeChannels.get('phone-1').source], ['rotated', 'direct']);
    });
  });

  it('this runtime proves no peer key at handshake, and a handshake cannot claim it did', () => {
    withNode((node) => {
      assert.strictEqual(node._peerKeyProven('anyone'), false);
      const msg = { type: 'handshake', nodeId: 'x', name: 'x', publicKey: 'k', provenPublicKey: 'k' };
      let seen = null;
      node._roomAdmission = (peerId, m) => { seen = { ...m }; return { admit: true }; };
      node._frameHandler.handle('x', 'x', msg);
      assert.ok(seen, 'the admission check ran');
      assert.strictEqual('provenPublicKey' in seen, false, 'a peer-supplied proof claim never reaches it');
    });
  });

  it("a peer turns its own channel off with platform 'none'; gossip cannot turn off anyone's (F3)", () => {
    withNode((node, io) => {
      const wm = node._wakeManager;
      node._frameHandler.handle('phone-1', 'phone-1', { type: 'wake-channel', platform: 'apns', token: 't1', environment: 'sandbox' });
      wm.learnWakeChannel('phone-2', apns('t2'), { source: 'relay' });
      const before = io.writes();
      node._frameHandler.handle('peer-x', 'mallory', { type: 'peer-info', peers: [{ nodeId: 'phone-1', wakeChannel: { platform: 'none' }, lastSeen: Date.now() }] });
      assert.ok(node._peerWakeChannels.has('phone-1'), 'gossip cannot turn it off');
      node._frameHandler.handle('phone-1', 'phone-1', { type: 'wake-channel', platform: 'none' });
      assert.strictEqual(node._peerWakeChannels.has('phone-1'), false, 'the peer turned its own channel off');
      assert.strictEqual(io.writes(), before + 1, 'and it was saved');
      // Not one held at a stronger rank than the frame: that takes the relay or a proven session.
      node._frameHandler.handle('phone-2', 'phone-2', { type: 'wake-channel', platform: 'none' });
      assert.ok(node._peerWakeChannels.has('phone-2'));
      node._relay._setPhase = () => {};
      node._relay._handleRelayPeers({ peers: [{ nodeId: 'phone-2', wakeChannel: { platform: 'none' }, offline: true }] });
      assert.strictEqual(node._peerWakeChannels.has('phone-2'), false, "the relay's registration turned it off");
      wm.loadWakeChannels();
      assert.strictEqual(node._peerWakeChannels.size, 0, 'and neither comes back from the file');
    });
  });
});

describe('0.14.0 release review B: every store and list is bounded', () => {
  const file = (wm, data) => { fs.mkdirSync(require('path').dirname(wm._wakeChannelsFile), { recursive: true }); fs.writeFileSync(wm._wakeChannelsFile, JSON.stringify(data)); };

  it('the cap holds for what is loaded from disk, and invalid entries are not loaded (F4)', () => {
    withNode((node) => {
      const wm = node._wakeManager;
      const data = {};
      for (let i = 0; i < 3000; i++) data[`gossiped-${i}`] = apns(`t${i}`);   // a 0.13.x file: no source, no lastSeen
      data['x'.repeat(5000)] = apns('long-id');
      data['bad-token'] = apns('a/../b?c');
      data['huge-token'] = apns('t'.repeat(5000));
      file(wm, data);
      node._peerWakeChannels.clear();
      wm.loadWakeChannels();
      assert.strictEqual(node._peerWakeChannels.size, 1024, 'at most the cap');
      for (const k of ['x'.repeat(5000), 'bad-token', 'huge-token']) assert.strictEqual(node._peerWakeChannels.has(k), false, `${k.slice(0, 12)} is not a channel`);
      assert.strictEqual(Object.keys(JSON.parse(fs.readFileSync(wm._wakeChannelsFile, 'utf8'))).length, 1024, 'and the file is held to it');
    });
  });

  it('a learned channel is a short, single-segment token too', () => {
    withNode((node) => {
      const wm = node._wakeManager;
      for (const token of ['a/b', 'a?b', '', 't'.repeat(600), 42]) {
        assert.strictEqual(wm.learnWakeChannel('p', { platform: 'apns', token }, { source: 'relay' }), 'ignored', String(token).slice(0, 10));
      }
      assert.strictEqual(wm.learnWakeChannel('n'.repeat(200), apns('t'), { source: 'relay' }), 'ignored');
      assert.strictEqual(node._peerWakeChannels.size, 0);
    });
  });

  it("the one grace given a channel saved before 0.14.0 is written down at once, so a restart does not renew it (F10)", () => {
    withNode((node) => {
      const wm = node._wakeManager;
      file(wm, { 'old-phone': apns('legacy') });
      node._peerWakeChannels.clear();
      const loadedAt = Date.now();
      wm._now = () => loadedAt;
      wm.loadWakeChannels();   // nothing expires: before, nothing was written
      node._peerWakeChannels.clear();
      wm._now = () => loadedAt + WAKE_CHANNEL_TTL_MS + DAY;
      wm.loadWakeChannels();
      assert.strictEqual(node._peerWakeChannels.has('old-phone'), false, 'the grace ended');
    });
  });

  it('a peer-info frame this node sends carries at most what a receiver reads, the most recently seen (F7)', () => {
    withNode((node, io) => {
      const wm = node._wakeManager;
      const now = Date.now();
      for (let i = 0; i < 300; i++) wm.learnWakeChannel(`p${i}`, apns(`t${i}`), { source: 'gossip', lastSeen: now - (300 - i) * 1000 });
      const out = wm.gossipEntries('peer-x');
      assert.strictEqual(out.length, 256);
      assert.ok(out.every((e) => Number(e.nodeId.slice(1)) >= 44), 'the 256 most recently seen');
      // A receiver reading a longer frame (from an older sender) says so once a minute, not per frame.
      const long = { type: 'peer-info', peers: Array.from({ length: 300 }, (_, i) => ({ nodeId: `q${i}`, wakeChannel: apns('t'), lastSeen: now })) };
      for (let i = 0; i < 20; i++) node._frameHandler.handle('peer-y', 'old-sender', long);
      assert.strictEqual(io.lines.filter((l) => /entries, reading the first/.test(l)).length, 1);
    });
  });

  it("the relay's peer list is read for its first 256 entries, and room is made without scanning the map (F12)", () => {
    withNode((node) => {
      const wm = node._wakeManager;
      node._relay._setPhase = () => {};
      node._relay._log = () => {};
      let joined = 0;
      node._relay._handleRelayPeerJoined = () => { joined++; };
      const peers = Array.from({ length: 200000 }, (_, i) => ({ nodeId: `r${i}`, wakeChannel: apns(`t${i}`) }));
      // Count steps over the channel map: making room must not walk it.
      let steps = 0;
      const map = node._peerWakeChannels;
      for (const m of ['entries', 'keys', 'values', Symbol.iterator]) {
        const real = map[m].bind(map);
        map[m] = (...a) => { const it = real(...a); return { next: () => { steps++; return it.next(); }, [Symbol.iterator]() { return this; } }; };
      }
      wm._maxChannels = 100;
      let saves = 0;
      node._relay._saveWakeChannels = () => { saves++; };   // the one save per list serialises the map; counted apart
      node._relay._handleRelayPeers({ peers });
      assert.strictEqual(joined, 256, 'the first 256 entries');
      assert.strictEqual(node._peerWakeChannels.size, 100, 'at the cap');
      assert.strictEqual(steps, 0, 'and making room for 156 of them walked nothing');
      assert.strictEqual(saves, 1);
      assert.ok(node._peerWakeChannels.has('r255') && !node._peerWakeChannels.has('r0'), 'the least recently set went first');
    });
  });

  it('the eviction index holds exactly the channels held, through removals and expiry', () => {
    withNode((node) => {
      const wm = node._wakeManager;
      const indexed = () => [...wm._byRank.values()].reduce((n, m) => n + m.size, 0);
      let t = Date.now();
      wm._now = () => t;
      for (let i = 0; i < 100; i++) wm.learnWakeChannel(`p${i}`, apns(`t${i}`), { source: i % 2 ? 'relay' : 'gossip', lastSeen: t });
      for (let i = 0; i < 10; i++) wm.learnWakeChannel(`p${i}`, { platform: 'none' }, { source: 'relay' });
      assert.strictEqual(indexed(), node._peerWakeChannels.size);
      t += WAKE_CHANNEL_TTL_MS + DAY;
      wm.pruneWakeChannels();
      assert.deepStrictEqual([node._peerWakeChannels.size, indexed()], [0, 0]);
    });
  });

  it('frames waiting for a sleeping peer are bounded, and go with its channel', () => {
    withNode((node) => {
      const wm = node._wakeManager;
      wm.wakeIfNeeded = async () => false;
      wm.learnWakeChannel('sleeper', apns('t'), { source: 'relay' });
      for (let i = 0; i < 500; i++) wm.wakeSleepingPeers('message', { type: 'message', n: i });
      const q = node._pendingFrames.get('sleeper');
      assert.strictEqual(q.length, 64);
      assert.strictEqual(q[0].n, 436, 'the newest are kept');
      wm.learnWakeChannel('sleeper', { platform: 'none' }, { source: 'relay' });
      assert.strictEqual(node._pendingFrames.has('sleeper'), false);
    });
  });

  it('a relay leg built without a wake manager does not throw on a peer list with channels (F8)', () => {
    const { RelayConnection } = require('../lib/relay');
    const relay = new RelayConnection({ relayUrl: 'ws://127.0.0.1:1', token: 'x'.repeat(32), getIdentity: () => ({ nodeId: 'me' }), getPeers: () => new Map(), createPeer: () => ({}), addPeer: () => {}, log: () => {}, nodeName: 'n', peerWakeChannels: new Map(), saveWakeChannels: () => {} });
    relay._setPhase = () => {};
    relay._handleRelayPeerJoined = () => {};
    assert.doesNotThrow(() => relay._handleRelayPeers({ peers: [{ nodeId: 'p', wakeChannel: apns('t'), offline: true }] }));
  });
});
