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
