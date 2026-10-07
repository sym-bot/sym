'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * THE 0.13.17 RELAY SCENES, AGAINST CORE SECURE (sym 0.13.17, fix 2cf4dea; found in xmesh-world-room, 7 Oct 2026).
 *
 * In 0.13, a relay re-announcing a peer the node already held closed the held relay transport while it was still registered; its
 * synchronous close handler left the peer in the table with transport null, and every later send and broadcast threw ("Cannot read
 * properties of null (reading 'send')"). And a LAN transport added to a peer first met over the relay never became the active one, so
 * CMBs kept going to the relay. 0.14.0 binds peers to proven sessions (D1): the new session is registered and the active transport
 * recomputed before the old one is superseded, and a session's close removes only itself. These tests hold that to the same scenes,
 * end to end: a re-announced peer, and a restarted one (the cloud peer's reconnect), are still sent to; a peer met over the relay and
 * then on the LAN is sent to over the LAN.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const { fakeRelay } = require('./_fake-relay');
const { until, connectNodes } = require('./_core-secure');

const uniq = (b) => `${b}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
const CATS = (focus) => ({ focus, issue: 'relay scene', intent: '0.13.17 scenes', motivation: 'm', commitment: 'c', perspective: 'p', mood: { text: 'calm', valence: 0, arousal: 0 } });
const TOKEN = 'x'.repeat(40);
const relayNode = (base, relay) => new SymNode({ name: uniq(base), silent: true, relayOnly: true, discovery: new NullDiscovery(), relay: relay.url, relayToken: TOKEN, room: 'relay-room' });
async function stopAll(...nodes) {
  for (const n of nodes) { try { await n.stop(); } catch { /* */ } try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ } }
}
const paired = (a, b) => a._peers.has(b.nodeId) && b._peers.has(a.nodeId);
const relaySession = (n, other) => n._peers.get(other.nodeId)?.transports.get('relay');
/** what `to` verifies from `from`, by focus */
function heard(to) { const got = []; to.on('verified-record', (e) => got.push(e)); return got; }
const focusOf = (e) => e.record.categories.focus.text;

describe('the 0.13.17 relay scenes under Core Secure sessions', () => {
  it('a peer the relay announces again is still sent to: a room broadcast and a directed send both arrive, and nothing throws', async () => {
    const relay = fakeRelay();
    const a = relayNode('ra-a', relay); const b = relayNode('ra-b', relay);
    try {
      await a.start(); await b.start();
      await until(() => paired(a, b), 8000);
      const [lo, hi] = [a, b].sort((x, y) => (x.nodeId < y.nodeId ? -1 : 1));
      const ws = relay.conns.get(lo.nodeId).ws;
      for (let i = 0; i < 5; i++) ws.send(JSON.stringify({ type: 'relay-peer-joined', nodeId: hi.nodeId, name: hi.name }));
      await new Promise((r) => setTimeout(r, 300));
      const peer = lo._peers.get(hi.nodeId);
      assert.ok(peer && peer.transport && !peer.transport.closed, 'the peer is held with a live transport');
      const got = heard(hi);
      assert.doesNotThrow(() => lo.remember(CATS('room, after the re-announce')));
      assert.doesNotThrow(() => lo.remember(CATS('directed, after the re-announce'), { to: hi.nodeId }));
      await until(() => got.length >= 2, 5000);
      assert.deepStrictEqual(got.map(focusOf).sort(), ['directed, after the re-announce', 'room, after the re-announce']);
    } finally { await stopAll(a, b); await relay.close(); }
  });

  it('a peer that restarts under the relay (the cloud reconnect: 4004, a new session) is sent to on its new session', async () => {
    const relay = fakeRelay();
    const a = relayNode('rr-a', relay);
    const bName = uniq('rr-b');
    let b = new SymNode({ name: bName, silent: true, relayOnly: true, discovery: new NullDiscovery(), relay: relay.url, relayToken: TOKEN, room: 'relay-room' });
    try {
      await a.start(); await b.start();
      await until(() => paired(a, b), 8000);
      const old = relaySession(a, b), bId = b.nodeId;
      b._relay._identityCollision = true;
      const b2 = new SymNode({ name: `${bName}-restarted`, nodeId: bId, silent: true, relayOnly: true, discovery: new NullDiscovery(), relay: relay.url, relayToken: TOKEN, room: 'relay-room', create: false });
      await b2.start();
      await until(() => relaySession(a, b2) && relaySession(a, b2) !== old, 10000);
      const peer = a._peers.get(bId);
      assert.strictEqual(peer.transport, relaySession(a, b2), 'the active transport is the new session');
      const got = heard(b2);
      assert.doesNotThrow(() => a.remember(CATS('after the restart')));
      await until(() => got.length >= 1, 5000);
      assert.strictEqual(focusOf(got[0]), 'after the restart');
      await b.stop().catch(() => {});
      b = b2;
    } finally { await stopAll(a, b); await relay.close(); }
  });

  it('a peer met over the relay and then on the LAN is sent to over the LAN (bonjour before relay, MMP 4.6)', async () => {
    const a = new SymNode({ name: uniq('rl-a'), silent: true, discovery: new NullDiscovery(), room: 'lan-room' });
    const b = new SymNode({ name: uniq('rl-b'), silent: true, discovery: new NullDiscovery(), room: 'lan-room' });
    try {
      await a.start(); await b.start();
      const [lo, hi] = [a, b].sort((x, y) => (x.nodeId < y.nodeId ? -1 : 1));
      await connectNodes(lo, hi, { kind: 'relay' });
      await until(() => paired(a, b), 5000);
      assert.strictEqual(a._peers.get(b.nodeId).transport.kind, 'relay', 'first met over the relay');
      await connectNodes(lo, hi, { kind: 'bonjour' });
      await until(() => a._peers.get(b.nodeId).transports.has('bonjour') && b._peers.get(a.nodeId).transports.has('bonjour'), 5000);
      assert.strictEqual(a._peers.get(b.nodeId).transport.kind, 'bonjour', 'then sent to over the LAN');
      assert.strictEqual(b._peers.get(a.nodeId).transport.kind, 'bonjour');
      const got = heard(b);
      a.remember(CATS('over the LAN'));
      await until(() => got.length >= 1, 5000);
      assert.strictEqual(got[0].session.transport, 'lan', 'and it arrived over the LAN');
    } finally { await stopAll(a, b); }
  });
});
