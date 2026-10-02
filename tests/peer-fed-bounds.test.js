'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * Every store a peer feeds has one bound, and per-peer state goes when the peer does (0.13.17 R4,
 * re-review A4; a port of growth.js against 0.14's API). In 0.14 a peer is a proven session (design
 * D1), so the handshake-fed maps of 0.13 (derived keys, declared lifecycle roles) are gone; what a
 * peer can still grow is bounded here:
 *   - wake channels: learned only from a confirmed session's own nodeId (gossip about other nodes
 *     is a hint, never stored); at most WAKE_CHANNELS_MAX, and a new first-hand channel always gets
 *     in, displacing the least recently seen, so many identities cannot lock the table (A4);
 *   - wakes: a cooldown that runs from the attempt, and at most 16 frames queued per sleeping peer;
 *   - per-peer maps: room verdicts and the anchor debounce are bounded and pruned when the peer
 *     leaves; key conflicts are bounded per nodeId and in all; relay handshakes in flight are bounded,
 *     and a relay `from` that never confirms leaves nothing behind.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const { WAKE_CHANNELS_MAX, PENDING_FRAMES_MAX } = require('../lib/core/wake');
const { keepPeerState, MAX_PEER_STATE } = require('../lib/peer-state');
const { RosterKeyRegistry, MAX_CONFLICTS, MAX_CONFLICTS_PER_NODE } = require('../lib/roster-keys');
const { PeerSession } = require('../lib/session');
const { identity, admitAs, deliver, connectNodes, until, memoryPipe } = require('./_core-secure');

const uniq = (base) => `${base}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
const ch = (token) => ({ platform: 'apns', token });
const gossip = (f, n = 256) => ({ type: 'peer-info', peers: Array.from({ length: n }, (_, i) => ({ nodeId: `fake-${f}-${i}`, wakeChannel: ch('t'.repeat(64)), lastSeen: Date.now() })) });

function boot(base, extra = {}) {
  return new SymNode({ name: uniq(base), silent: true, discovery: new NullDiscovery(), room: 'g', ...extra });
}
async function done(node) { try { await node.stop(); } catch { /* */ } fs.rmSync(nodeDirById(node.nodeId), { recursive: true, force: true }); }

describe('wake channels have one bound, and many identities cannot lock it (R4, A4)', () => {
  it('twenty peer-info frames of 256 fresh nodeIds from one session keep none (they name other nodes)', async () => {
    const node = boot('bound-wake');
    try {
      const s = admitAs(node, identity('evil'));
      for (let f = 0; f < 20; f++) deliver(node, s, gossip(f));
      assert.strictEqual(node._peerWakeChannels.size, 0, 'until 0.13.17: 5,120; 0.13.17: 512');
      assert.strictEqual(node.metrics().framesRefused, 0);
    } finally { await done(node); }
  });

  it(`${WAKE_CHANNELS_MAX + 500} identities each giving its own channel: the table holds ${WAKE_CHANNELS_MAX}, and a new phone still gets in`, async () => {
    const node = boot('bound-wake-flood');
    try {
      for (let i = 0; i < WAKE_CHANNELS_MAX + 500; i++) {
        const s = admitAs(node, identity(`flood-${i}`));
        deliver(node, s, { type: 'wake-channel', platform: 'apns', token: `f${i}` });
      }
      assert.strictEqual(node._peerWakeChannels.size, WAKE_CHANNELS_MAX);
      const phone = admitAs(node, identity('honest-phone'));
      deliver(node, phone, { type: 'wake-channel', platform: 'apns', token: 'the-phone' });
      assert.strictEqual(node._peerWakeChannels.get(phone.nodeId)?.token, 'the-phone', 'not locked out (A4)');
      assert.strictEqual(node._peerWakeChannels.size, WAKE_CHANNELS_MAX);
    } finally { await done(node); }
  });

  it('a dropped channel takes its queued frames and its cooldown with it', async () => {
    const node = boot('bound-wake-drop');
    try {
      const s = admitAs(node, identity('phone'));
      deliver(node, s, { type: 'wake-channel', platform: 'apns', token: 't' });
      node._pendingFrames.set(s.nodeId, [{ type: 'message' }]);
      node._peerLastWake.set(s.nodeId, Date.now());
      deliver(node, s, { type: 'wake-channel', platform: 'none' });
      assert.strictEqual(node._peerWakeChannels.has(s.nodeId), false);
      assert.strictEqual(node._pendingFrames.has(s.nodeId), false);
      assert.strictEqual(node._peerLastWake.has(s.nodeId), false);
    } finally { await done(node); }
  });

  it('wake-channels.json is written once for a burst of frames, not once per frame', async () => {
    const node = boot('bound-wake-file');
    const file = path.join(node._dir, 'wake-channels.json');
    const write = fs.writeFileSync;
    let writes = 0;
    fs.writeFileSync = function (p, ...rest) { if (p === file) writes++; return write.call(this, p, ...rest); };
    try {
      for (let i = 0; i < 20; i++) deliver(node, admitAs(node, identity(`p${i}`)), { type: 'wake-channel', platform: 'apns', token: `t${i}` });
      assert.strictEqual(writes, 0, 'nothing yet: the saves coalesce');
      await node.stop();
      assert.strictEqual(writes, 1, 'one write, made when the node stops (or a second after the burst)');
      assert.strictEqual(Object.keys(JSON.parse(fs.readFileSync(file, 'utf8'))).length, 20);
    } finally { fs.writeFileSync = write; await done(node); }
  });

  it('channels read back from disk are typed and bounded, and give way to a node\'s own', async () => {
    const seed = boot('bound-wake-load');
    const dir = seed._dir;
    await seed.stop();
    const data = { bad1: { platform: { toString: 1 }, token: 't' }, bad2: { platform: 'apns', token: 7 } };
    for (let i = 0; i < WAKE_CHANNELS_MAX + 100; i++) data[`n${i}`] = ch(`t${i}`);
    fs.writeFileSync(path.join(dir, 'wake-channels.json'), JSON.stringify(data));
    const node = new SymNode({ name: seed.name, silent: true, discovery: new NullDiscovery(), room: 'g' });
    try {
      assert.strictEqual(node._peerWakeChannels.size, WAKE_CHANNELS_MAX);
      assert.strictEqual(node._peerWakeChannels.has('bad1') || node._peerWakeChannels.has('bad2'), false);
      const own = admitAs(node, identity('own-phone'));
      deliver(node, own, { type: 'wake-channel', platform: 'apns', token: 'mine' });
      assert.strictEqual(node._peerWakeChannels.get(own.nodeId)?.token, 'mine');
      assert.strictEqual(node._peerWakeChannels.size, WAKE_CHANNELS_MAX, 'the oldest read back made room');
    } finally { await done(node); }
  });
});

describe('wakes have a cooldown on failure and a bounded queue (R4)', () => {
  it('fifty messages to 300 sleeping channels: one failed wake per channel, at most 16 frames queued for each', async () => {
    const node = boot('bound-wakes');
    const lines = [];
    node._log = (l) => lines.push(l);
    try {
      for (let i = 0; i < 300; i++) {
        node._wakeManager.learnWakeChannel(`phone-${i}`, ch(`t${i}`), { source: 'direct' });
        node._roster.bind(`phone-${i}`, identity(`phone-${i}`).publicKey, 'pinned'); // a queued frame goes to this key only
      }
      for (let m = 0; m < 50; m++) node._wakeManager.wakeSleepingPeers('mood', { type: 'mood', mood: `m${m}` });
      // The retired `message` frame is never queued (security review): it wakes, and waits for nothing.
      node._wakeManager.wakeSleepingPeers('message', { type: 'message', content: 'retired' });
      await new Promise((r) => setTimeout(r, 300));
      const failed = lines.filter((l) => /^Wake failed/.test(l));
      assert.strictEqual(failed.length, 300, 'one attempt per channel per cooldown, not one per message (no APNs keys here, so each fails)');
      let most = 0;
      for (const [, q] of node._pendingFrames) most = Math.max(most, q.length);
      assert.strictEqual(most, PENDING_FRAMES_MAX);
      assert.strictEqual(PENDING_FRAMES_MAX, 16);
      assert.deepStrictEqual(node._pendingFrames.get('phone-0').map((e) => e.frame.mood), Array.from({ length: 16 }, (_, i) => `m${34 + i}`), 'the newest are kept');
      assert.ok(node._pendingFrames.get('phone-0').every((e) => e.key === node._roster.get('phone-0')), 'each kept with the key it may be delivered to');
      assert.ok(![...node._pendingFrames.values()].some((q) => q.some((e) => e.frame.type === 'message')), 'no message frame queued');
    } finally { await done(node); }
  });
});

describe('per-peer maps are pruned when the peer leaves and bounded otherwise (R4)', () => {
  it('a peer that leaves takes its admit verdict and anchor debounce with it; a refusal stays, bounded', async () => {
    const a = boot('bound-forget-a'); const b = boot('bound-forget-b');
    try {
      await a.start(); await b.start();
      a.remember({ focus: 'something to replay as an anchor', issue: 'i', intent: 'i', motivation: 'm', commitment: 'c', perspective: 'p', mood: { text: 'calm', valence: 0, arousal: 0 } });
      const { tc } = await connectNodes(b, a);
      assert.strictEqual(a._roomVerdicts.get(b.nodeId)?.admit, true);
      tc.close();
      await until(() => !a._peers.has(b.nodeId), 3000);
      assert.strictEqual(a._roomVerdicts.has(b.nodeId), false, 'the admit verdict went with the peer');
      assert.strictEqual(a._lastAnchorSent ? a._lastAnchorSent.has(b.nodeId) : false, false, 'and the anchor debounce');
      const fake = (id) => ({ nodeId: id, name: id, close() {} });
      for (let i = 0; i < MAX_PEER_STATE + 50; i++) a._refuseAdmission(fake(`ghost-${i}`), 'not in this room');
      assert.strictEqual(a._roomVerdicts.size, MAX_PEER_STATE, 'refusals are kept, bounded');
      assert.strictEqual(a._roomVerdicts.has('ghost-0'), false, 'the oldest went first');
      assert.strictEqual(a._roomDoor(`ghost-${MAX_PEER_STATE + 49}`).pass, false, 'a refused peer stays refused');
    } finally { await done(a); await done(b); }
  });

  it('key conflicts are bounded per nodeId and in all; every one is counted', () => {
    const r = new RosterKeyRegistry();
    const P = identity('p');
    r.bind(P.nodeId, P.publicKey, 'proven');
    for (let i = 0; i < 300; i++) r.bind(P.nodeId, identity().publicKey, 'proven');
    assert.strictEqual(r.conflicts().length, MAX_CONFLICTS_PER_NODE, 'until 0.13.17: 299');
    for (let i = 0; i < 3000; i++) { const id = identity(); r.bind(id.nodeId, id.publicKey, 'proven'); r.bind(id.nodeId, identity().publicKey, 'proven'); }
    assert.strictEqual(r.conflicts().length, MAX_CONFLICTS);
    assert.strictEqual(r.conflictCount(), 3300);
  });

  it('relay hellos: at most 256 handshakes in flight; a from that never confirms leaves nothing behind', async () => {
    const node = boot('bound-relay-hellos');
    try {
      await node.start();
      node._relay.transportFor = () => ({ trySend: () => ({ ok: true }), send: () => true, close() {}, destroy() {} });
      const hellos = [];
      for (let i = 0; i < 400; i++) {
        const id = { ...identity(`h${i}`), nodeId: `00000000-0000-7000-8000-${String(i).padStart(12, '0')}` };
        const [tc] = memoryPipe();
        const c = new PeerSession({ role: 'client', transport: { trySend: (f) => { hellos.push({ from: id.nodeId, f }); return { ok: true }; }, send() { return true; }, close() {} }, kind: 'relay', local: id, room: 'g', extensions: ['cmb-encrypted-v2'], implementation: { name: 't', version: '0' } });
        c.start();
        void tc;
      }
      for (const { from, f } of hellos) node._relayEnvelope(from, 'x', f);
      // Unknown froms share RELAY_UNKNOWN_MAX (32) of the 256 slots, the oldest going first for a
      // newer hello (security review D, relay-slots / announce-starve).
      assert.strictEqual(node._relayHandshakesInFlight(), 32, 'unknown froms: bounded at their share');
      assert.ok((node._sessionStats.failedByReason['handshake-evicted'] || 0) >= 368, 'the oldest unknown handshakes made room');
      for (const s of [...node._sessions]) if (s.kind === 'relay') s.close('timeout', { notify: false });
      assert.strictEqual(node._relaySessions.size, 0, 'nothing kept per relay from');
    } finally { await done(node); }
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
