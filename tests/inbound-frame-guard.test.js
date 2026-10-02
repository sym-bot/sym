'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * 0.13.17 security hotfix (G2, C3). In 0.13.16 a frame whose handling threw took the process down
 * when it came over the relay: the relay's dispatch had no guard, so the throw reached
 * uncaughtException, and the daemon exits on that. Two frames any peer could send did it:
 *   - a legacy `mood` frame: _handleMood registered the mood as a peer in the coupling set and the
 *     stock coupler's decisions do not carry the fields the metrics logger read, so it always threw
 *     (and, on LAN where the throw was swallowed, left the phantom peer behind, so the node's own
 *     remember() threw for the next two minutes);
 *   - a `message` frame, on the daemon: its listener called node._xmesh.ingestSignal, and a stock
 *     node has no insight engine.
 * Every inbound frame now goes through one guarded dispatch, whatever carried it: a frame the node
 * cannot handle is refused and counted, never thrown out of the transport.
 *
 * Since 0.14 (Core Secure) a frame reaches that dispatch only from a confirmed session, so these
 * drive real sessions: two nodes over a fake relay, and over a LAN TCP connection. A plaintext frame
 * from an unproven relay `from` is refused before it, and the process survives that too.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { WebSocketServer } = require('ws');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const { sendFrame } = require('../lib/frame-parser');
const { fakeRelay } = require('./_fake-relay');
const { admitAs } = require('./_core-secure');

const uniq = (base) => `${base}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
const until = async (cond, ms = 5000) => { for (let t = 0; t < ms && !cond(); t += 20) await new Promise((r) => setTimeout(r, 20)); };

/** Throws on its first call only: a host listener (like the daemon's) that fails on one frame. */
function throwOnce(seen) {
  let thrown = false;
  return (from, content) => {
    seen.push(content);
    if (!thrown) { thrown = true; throw new Error('host listener failed'); }
  };
}

describe('every inbound frame goes through one guarded dispatch (G2, C3)', () => {
  async function exercise(a, b) {
    const seen = [];
    const moods = [];
    b.on('message', throwOnce(seen));
    b.on('mood-delivered', (d) => moods.push(d));
    b.on('mood-rejected', (d) => moods.push(d));
    a.send('first', { to: b.nodeId });
    a.broadcastMood('exhausted after a long debugging session');
    a.send('second', { to: b.nodeId });
    await until(() => seen.length >= 2 && moods.length >= 1);
    return { seen, moods };
  }

  it('relay: a frame whose handling throws is refused and counted; the process and the relay link survive', async () => {
    const uncaught = [];
    const onUncaught = (err) => uncaught.push(err);
    process.on('uncaughtException', onUncaught);
    const relay = fakeRelay();
    const mk = (n) => new SymNode({ name: uniq(n), silent: true, relayOnly: true, discovery: new NullDiscovery(), relay: relay.url, relayToken: 'x'.repeat(40), room: 'g' });
    const a = mk('guard-relay-a'); const b = mk('guard-relay-b');
    try {
      await a.start(); await b.start();
      await until(() => a._peers.has(b.nodeId) && b._peers.has(a.nodeId), 8000);
      // A plaintext frame from an unproven relay `from` is refused before the dispatch.
      relay.inject('e'.repeat(64), b.nodeId, { type: 'mood', mood: 'evil', fromName: 'evil' });
      const { seen, moods } = await exercise(a, b);
      assert.deepStrictEqual(uncaught, [], 'nothing reached uncaughtException');
      assert.deepStrictEqual(seen, ['first', 'second'], 'the frame after the refused one is still dispatched');
      assert.strictEqual(moods.length, 1, 'the mood frame is evaluated, not thrown');
      const m = b.metrics();
      assert.strictEqual(m.framesRefused, 1);
      assert.deepStrictEqual(m.framesRefusedByType, { cmb: 1 }, 'the directed message record whose listener threw');
      assert.strictEqual(b.status().relayConnected, true, 'the relay link is still up');
      assert.ok(b._sessionStats.refusedByReason['not-core-secure'] >= 1, 'the unproven plaintext frame was refused and counted');
    } finally {
      process.removeListener('uncaughtException', onUncaught);
      await a.stop(); await b.stop();
      await relay.close();
      for (const n of [a, b]) fs.rmSync(nodeDir(n.name), { recursive: true, force: true });
    }
  });

  it('LAN: the same dispatch refuses and counts over a TCP session', async () => {
    const { BonjourDiscovery } = require('../lib/discovery');
    const a = new SymNode({ name: uniq('guard-lan-a'), silent: true, discovery: new NullDiscovery(), room: 'g' });
    const b = new SymNode({ name: uniq('guard-lan-b'), silent: true, discovery: new BonjourDiscovery({ mdns: false }), room: 'g' });
    try {
      await a.start(); await b.start();
      a._pendingBonjour = a._pendingBonjour || new Set();
      a._connectToPeer('127.0.0.1', b._port, b.nodeId, b.name);
      await until(() => a._peers.has(b.nodeId) && b._peers.has(a.nodeId));
      const { seen } = await exercise(a, b);
      assert.deepStrictEqual(seen, ['first', 'second']);
      assert.strictEqual(b.metrics().framesRefused, 1);
      assert.deepStrictEqual(b.metrics().framesRefusedByType, { cmb: 1 });
    } finally {
      await a.stop(); await b.stop();
      for (const n of [a, b]) fs.rmSync(nodeDir(n.name), { recursive: true, force: true });
    }
  });
});

describe('a mood frame on a stock node (G2)', () => {
  it('is evaluated against this node\'s state without touching the coupling set, and the node keeps working', () => {
    const name = uniq('guard-mood');
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    const out = [];
    node.on('mood-delivered', (d) => out.push(['delivered', d]));
    node.on('mood-rejected', (d) => out.push(['rejected', d]));
    try {
      const p = admitAs(node, { nodeId: 'p' });
      node._frameHandler.handle(p, { type: 'mood', mood: 'tired', fromName: 'p' });
      assert.strictEqual(out.length, 1);
      assert.strictEqual(typeof out[0][1].drift, 'number');
      assert.ok(out[0][1].drift >= 0 && out[0][1].drift <= 2, `drift ${out[0][1].drift} is a cosine drift`);
      assert.strictEqual(node._meshNode.activePeerCount, 0, 'no phantom peer is left in the coupling set');
      const entry = node.remember({ focus: 'own work after a mood frame', issue: 'none', intent: 'x', motivation: 'y', commitment: 'z', perspective: 'me', mood: { text: 'calm', valence: 0, arousal: 0 } });
      assert.ok(entry, 'remember() still works (in 0.13.16 it threw for two minutes after one mood frame)');
      assert.ok(Array.isArray(node.peers()));
      for (const mood of [42, { text: 'x' }, null, '']) node._frameHandler.handle(p, { type: 'mood', mood });
      assert.strictEqual(out.length, 1, 'a mood that is not text is not a mood');
    } finally { node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  it('the stock coupler, with a peer in it, does not break coupledState (the metrics logger reads the contract, not extra fields)', () => {
    const { MeshNode } = require('../lib/core');
    const mesh = new MeshNode({ hiddenDim: 4 });
    mesh.updateLocalState([1, 0, 0, 0], [0, 1, 0, 0]);
    mesh.addPeer('some-peer-id', [1, 0, 0, 0], [0, 1, 0, 0], 0.8);
    assert.doesNotThrow(() => mesh.coupledState());
    assert.strictEqual(mesh.metricsCount, 1);
  });
});

describe('the asynchronous half of a frame (SVAF) is refused by the same guard', () => {
  it('a rejection is counted, and a peer name that cannot be printed cannot make the containment throw', async () => {
    const name = uniq('guard-async');
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    const rejections = [];
    const onRejection = (r) => rejections.push(r);
    process.on('unhandledRejection', onRejection);
    try {
      node._frameHandler._processHeuristicSVAF = async () => { throw new Error('engine failed'); };
      node._frameHandler._runHeuristicSVAFContained({ type: 'cmb', cmb: {} }, { toString: 1 }, 'id-a', 0, Date.now(), 1);
      await new Promise((r) => setTimeout(r, 50));
      assert.deepStrictEqual(rejections, [], 'nothing reached unhandledRejection (0.13.16: the catch threw printing the name)');
      assert.strictEqual(node.metrics().framesRefusedByType.cmb, 1);
    } finally {
      process.removeListener('unhandledRejection', onRejection);
      node.stop();
      fs.rmSync(nodeDir(name), { recursive: true, force: true });
    }
  });
});

describe('the daemon survives a peer\'s mood and message frames over the relay (G2, C3)', () => {
  it('stays up, handles both from a Core Secure peer, refuses them in the clear, and answers an insight-engine request it cannot serve', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-daemon-guard-'));
    const sock = path.join(home, 'd.sock');
    const relay = fakeRelay();
    const daemon = spawn(process.execPath, [path.join(__dirname, '..', 'bin', 'sym-daemon.js')], {
      env: { ...process.env, HOME: home, USERPROFILE: home, SYM_STATE_DIR: path.join(home, '.sym'), SYM_SOCKET: sock,
        SYM_NODE_NAME: 'daemon-guard-test', SYM_ROOM: 'daemon-guard-room', SYM_RELAY_ONLY: '1',
        SYM_RELAY_URL: relay.url, SYM_RELAY_TOKEN: 'x'.repeat(32) },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    daemon.stdout.on('data', (b) => { out += b; });
    daemon.stderr.on('data', (b) => { out += b; });
    const peer = new SymNode({ name: uniq('guard-peer'), silent: true, relayOnly: true, discovery: new NullDiscovery(), relay: relay.url, relayToken: 'x'.repeat(32), room: 'daemon-guard-room' });
    try {
      await until(() => /sym-daemon ready/.test(out) || daemon.exitCode !== null, 15000);
      await peer.start();
      await until(() => peer._peers.size === 1, 10000);
      const daemonId = [...peer._peers.keys()][0];
      // In the clear, from an unproven relay `from`: refused, and the daemon survives it.
      relay.inject('e'.repeat(64), daemonId, { type: 'mood', mood: 'unproven', fromName: 'evil' });
      relay.inject('e'.repeat(64), daemonId, { type: 'message', content: 'unproven', fromName: 'evil' });
      // Over the session: handled.
      peer.broadcastMood('exhausted after a long debugging session');
      peer.send('hello daemon', { to: daemonId });
      await until(() => /Message from .*: hello daemon/.test(out) || daemon.exitCode !== null, 15000);
      await new Promise((r) => setTimeout(r, 300));
      assert.strictEqual(daemon.exitCode, null, `the daemon is still running; log:\n${out.slice(-1500)}`);
      assert.doesNotMatch(out, /FATAL/);
      assert.match(out, /Mood from .*: .*(ACCEPTED|IGNORED)/, 'the session\'s mood is handled, not merely survived');
      assert.match(out, /Message from .*: hello daemon/);
      // Named by the relay envelope's label ('injected' in the fake relay), never the frame's own fromName.
      assert.match(out, /Refused a '(mood|message)' frame from injected: not-core-secure/, 'the plaintext ones were refused');
      assert.doesNotMatch(out, /from evil/, 'a frame-supplied name is never printed');
      const reply = await new Promise((resolve, reject) => {
        const c = net.createConnection(sock, () => c.write(JSON.stringify({ type: 'xmesh-context' }) + '\n'));
        let buf = '';
        c.on('data', (d) => { buf += d; const i = buf.indexOf('\n'); if (i >= 0) { c.end(); resolve(JSON.parse(buf.slice(0, i))); } });
        c.on('error', reject);
        setTimeout(() => { c.destroy(); reject(new Error('no IPC reply')); }, 5000);
      });
      assert.strictEqual(reply.action, 'xmesh-context');
      assert.match(String(reply.error), /insight engine/);
      assert.strictEqual(daemon.exitCode, null);
    } finally {
      await peer.stop();
      daemon.kill('SIGTERM');
      await new Promise((r) => (daemon.exitCode !== null ? r() : daemon.once('exit', r)));
      await relay.close();
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});
