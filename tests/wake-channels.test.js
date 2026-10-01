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

  it('never replaces a token the phone gave us itself', () => {
    withNode((node) => {
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
      assert.deepStrictEqual(wm.gossipEntries('peer-x').map((e) => e.nodeId), ['phone-2']);
      assert.strictEqual(node._peerWakeChannels.has('phone-1'), false, 'the expired channel is gone from memory too');
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

describe('0.13.15 review F2/F3', () => {
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
