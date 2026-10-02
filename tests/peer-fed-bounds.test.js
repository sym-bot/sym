'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * 0.13.17 review (R4). A room peer could grow what a node keeps without limit:
 *   - wake channels: `peer-info` had no total bound, so 20 frames of 256 fresh nodeIds kept 5,120
 *     channels, and wake-channels.json was rewritten whole on every frame;
 *   - wakes: every message and mood the daemon relays wakes every stored channel; a failed wake
 *     (every one, on a node without APNs keys) had no cooldown, so each message queued a frame and
 *     logged a line per channel, and the queues were unbounded;
 *   - per-peer maps never pruned: room verdicts, anchor debounce, the E2E derived-key cache (one
 *     entry per handshake on one link), declared lifecycle roles (kept as any JSON value), and the
 *     roster's conflict list (one entry per re-sent handshake with a new key).
 * Each peer-fed store now has one bound, and per-peer state goes when the peer does.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const { WakeChannelTable, MAX_WAKE_CHANNELS, MAX_GOSSIPED_PER_ANNOUNCER, MAX_PENDING_FRAMES_PER_PEER } = require('../lib/core/wake');
const { keepPeerState, MAX_PEER_STATE } = require('../lib/peer-state');
const { RosterKeyRegistry, MAX_CONFLICTS } = require('../lib/roster-keys');

const uniq = (base) => `${base}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
const ch = (token) => ({ platform: 'apns', token });
const gossip = (f, n = 256) => ({ type: 'peer-info', peers: Array.from({ length: n }, (_, i) => ({ nodeId: `fake-${f}-${i}`, wakeChannel: ch('t'.repeat(64)) })) });

function boot(name, extra = {}) {
  return new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: 'g', ...extra });
}

describe('wake channels have one bound (R4)', () => {
  it('twenty peer-info frames from one peer keep at most half the table, not 5,120', () => {
    const name = uniq('bound-wake');
    const node = boot(name);
    try {
      for (let f = 0; f < 20; f++) node._receiveFrame('evil', 'evil', gossip(f), 'relay');
      assert.strictEqual(node._peerWakeChannels.size, MAX_GOSSIPED_PER_ANNOUNCER);
      for (const a of ['e2', 'e3', 'e4']) for (let f = 0; f < 4; f++) node._receiveFrame(a, a, gossip(`${a}-${f}`), 'relay');
      assert.strictEqual(node._peerWakeChannels.size, MAX_WAKE_CHANNELS, 'and never more than the table in all');
    } finally { node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  it('a full table still takes a node\'s own channel, displacing the oldest gossiped one', () => {
    const t = new WakeChannelTable({ max: 3, maxPerAnnouncer: 2 });
    t.set('a', ch('1'), 'p');
    t.set('b', ch('2'), 'p');
    t.set('c', ch('3'), 'p');
    assert.deepStrictEqual([...t.keys()], ['a', 'b'], 'one announcer teaches at most its share');
    t.set('c', ch('3'), 'q');
    t.set('d', ch('4'), 'q');
    assert.deepStrictEqual([...t.keys()], ['a', 'b', 'c'], 'gossip finding the table full is not kept');
    t.set('me', ch('5'), 'me');
    assert.deepStrictEqual([...t.keys()], ['b', 'c', 'me'], 'a node\'s own channel displaces the oldest gossiped');
    t.set('me2', ch('6'));
    t.set('me3', ch('7'));
    t.set('me4', ch('8'));
    assert.deepStrictEqual([...t.keys()], ['me', 'me2', 'me3'], 'and when only own channels are left, a new one is not kept');
    t.set('d', ch('4'), 'p');
    assert.strictEqual(t.has('d'), false);
  });

  it('a dropped channel takes its queued frames and its cooldown with it', () => {
    const name = uniq('bound-wake-drop');
    const node = boot(name);
    try {
      node._peerWakeChannels.set('phone', ch('t'), 'gossiper');
      node._pendingFrames.set('phone', [{ type: 'message' }]);
      node._peerLastWake.set('phone', Date.now());
      node._peerWakeChannels.delete('phone');
      assert.strictEqual(node._pendingFrames.has('phone'), false);
      assert.strictEqual(node._peerLastWake.has('phone'), false);
    } finally { node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  it('wake-channels.json is written once for a burst of frames, not once per frame', () => {
    const name = uniq('bound-wake-file');
    const node = boot(name);
    const file = path.join(nodeDir(name), 'wake-channels.json');
    const write = fs.writeFileSync;
    let writes = 0;
    fs.writeFileSync = function (p, ...rest) { if (p === file) writes++; return write.call(this, p, ...rest); };
    try {
      for (let f = 0; f < 20; f++) node._receiveFrame(`p${f}`, `p${f}`, gossip(f, 10), 'relay');
      assert.strictEqual(writes, 0, 'nothing yet: the saves coalesce');
      node.stop();
      assert.strictEqual(writes, 1, 'one write, made when the node stops (or a second after the burst)');
      assert.strictEqual(Object.keys(JSON.parse(fs.readFileSync(file, 'utf8'))).length, 200);
    } finally { fs.writeFileSync = write; node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  it('channels read back from disk are typed and bounded, and give way to a node\'s own', () => {
    const name = uniq('bound-wake-load');
    fs.mkdirSync(nodeDir(name), { recursive: true });
    const data = { bad1: { platform: { toString: 1 }, token: 't' }, bad2: { platform: 'apns', token: 7 } };
    for (let i = 0; i < MAX_WAKE_CHANNELS + 100; i++) data[`n${i}`] = ch(`t${i}`);
    fs.writeFileSync(path.join(nodeDir(name), 'wake-channels.json'), JSON.stringify(data));
    const node = boot(name);
    try {
      assert.strictEqual(node._peerWakeChannels.size, MAX_WAKE_CHANNELS);
      assert.strictEqual(node._peerWakeChannels.has('bad1') || node._peerWakeChannels.has('bad2'), false);
      node._receiveFrame('own-phone', 'own-phone', { type: 'wake-channel', platform: 'apns', token: 'mine' }, 'relay');
      assert.deepStrictEqual(node._peerWakeChannels.get('own-phone'), { platform: 'apns', token: 'mine', environment: undefined });
      assert.strictEqual(node._peerWakeChannels.has('n0'), false, 'the oldest read back made room');
    } finally { node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });
});

describe('wakes have a cooldown on failure and a bounded queue (R4)', () => {
  it('fifty messages to 300 sleeping channels: one failed wake per channel, at most 16 frames queued for each', async () => {
    const name = uniq('bound-wakes');
    const node = boot(name);
    const lines = [];
    node._log = (l) => lines.push(l);
    try {
      for (let i = 0; i < 300; i++) node._peerWakeChannels.set(`phone-${i}`, ch(`t${i}`));
      for (let m = 0; m < 50; m++) node._wakeManager.wakeSleepingPeers('message', { type: 'message', content: `m${m}` });
      await new Promise((r) => setTimeout(r, 300));
      const failed = lines.filter((l) => /^Wake failed/.test(l));
      assert.strictEqual(failed.length, 300, 'one attempt per channel per cooldown, not one per message (no APNs keys here, so each fails)');
      let most = 0;
      for (const [, q] of node._pendingFrames) most = Math.max(most, q.length);
      assert.strictEqual(most, MAX_PENDING_FRAMES_PER_PEER);
      assert.deepStrictEqual(node._pendingFrames.get('phone-0').map((f) => f.content), Array.from({ length: 16 }, (_, i) => `m${34 + i}`), 'the newest are kept');
    } finally { node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });
});

describe('per-peer maps are pruned when the peer leaves and bounded otherwise (R4)', () => {
  const x25519 = () => crypto.generateKeyPairSync('x25519').publicKey.export({ format: 'der', type: 'spki' }).toString('base64'); // as a handshake carries it

  it('one link re-sending its handshake with new keys holds one derived-key entry and a bounded conflict list', () => {
    const name = uniq('bound-handshake');
    const node = boot(name);
    try {
      const P = 'p'.repeat(64);
      for (let i = 0; i < 300; i++) node._receiveFrame(P, 'evil', { type: 'handshake', nodeId: P, name: 'evil', room: 'g', e2ePublicKey: x25519(), publicKey: `k${i}` }, 'relay');
      assert.strictEqual(node._e2eDerivedKeys.size, 1, 'until 0.13.17: 300');
      assert.strictEqual(node._roster.conflicts().length, MAX_CONFLICTS, 'until 0.13.17: 299');
      assert.strictEqual(node.metrics().framesRefused, 0);
    } finally { node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  it('a repeated conflict is kept once', () => {
    const r = new RosterKeyRegistry();
    r.pin('n', 'k1', 'handshake');
    for (let i = 0; i < 10; i++) r.pin('n', 'k2', 'handshake');
    assert.strictEqual(r.conflicts().length, 1);
  });

  it('a peer that leaves takes its lifecycle role, derived-key cache and admit verdict with it; a refusal stays', () => {
    const name = uniq('bound-forget');
    const node = boot(name);
    try {
      const transport = Object.assign(new EventEmitter(), { send() { return true; }, close() { this.emit('close'); } });
      const peer = node._createPeer(transport, 'friend', 'friend', true, 'relay');
      node._addPeer(peer);
      node._receiveFrame('friend', 'friend', { type: 'handshake', nodeId: 'friend', name: 'friend', room: 'g', lifecycleRole: 'validator', e2ePublicKey: x25519() }, 'relay');
      assert.strictEqual(node._peerLifecycleRoles.get('friend'), 'validator');
      assert.strictEqual(node._e2eDerivedKeys.has('friend'), true);
      assert.strictEqual(node._roomVerdicts.get('friend').admit, true);
      node._receiveFrame('liar', 'liar', { type: 'handshake', nodeId: 'liar', name: 'liar', room: 'elsewhere' }, 'relay');
      transport.close();
      assert.strictEqual(node._peers.has('friend'), false);
      assert.strictEqual(node._peerLifecycleRoles.has('friend'), false);
      assert.strictEqual(node._e2eDerivedKeys.has('friend'), false);
      assert.strictEqual(node._roomVerdicts.has('friend'), false);
      assert.strictEqual(node._roomVerdicts.get('liar').admit, false, 'a refused peer stays refused (it can keep speaking over the relay)');
      assert.strictEqual(node._roomDoor('liar').pass, false);
    } finally { node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  it('a declared lifecycle role is one of the named roles or it is not kept', () => {
    const name = uniq('bound-role');
    const node = boot(name);
    try {
      for (const [i, role] of [{ toString: 1 }, 7, ['validator'], 'emperor'].entries()) {
        node._receiveFrame(`r${i}`, `r${i}`, { type: 'handshake', nodeId: `r${i}`, name: 'r', room: 'g', lifecycleRole: role }, 'relay');
      }
      assert.strictEqual(node._peerLifecycleRoles.size, 0);
      node._receiveFrame('ok', 'ok', { type: 'handshake', nodeId: 'ok', name: 'ok', room: 'g', lifecycleRole: 'anchor' }, 'relay');
      assert.strictEqual(node._peerLifecycleRoles.get('ok'), 'anchor');
    } finally { node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  it('room verdicts from peers that never joined are bounded; a connected peer\'s entry is never dropped for room', () => {
    const name = uniq('bound-verdicts');
    const node = boot(name);
    try {
      node._peers.set('connected', { peerId: 'connected', transports: new Map() });
      node._receiveFrame('connected', 'c', { type: 'handshake', nodeId: 'connected', name: 'c', room: 'g' }, 'relay');
      for (let i = 0; i < MAX_PEER_STATE + 50; i++) node._receiveFrame(`ghost-${i}`, 'g', { type: 'handshake', nodeId: `ghost-${i}`, name: 'g', room: 'g' }, 'relay');
      assert.strictEqual(node._roomVerdicts.size, MAX_PEER_STATE);
      assert.strictEqual(node._roomVerdicts.has('connected'), true);
      assert.strictEqual(node._roomVerdicts.has('ghost-0'), false, 'the oldest went first');
    } finally { node._peers.clear(); node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  it('keepPeerState: newest last, oldest non-live dropped first, never the one just set', () => {
    const m = new Map();
    const live = new Set(['a']);
    for (const k of ['a', 'b', 'c', 'd']) keepPeerState(m, k, k, live, 2);
    assert.deepStrictEqual([...m.keys()], ['a', 'd']);
    keepPeerState(m, 'a', 'a2', live, 2);
    assert.deepStrictEqual([...m.entries()], [['d', 'd'], ['a', 'a2']]);
  });
});
