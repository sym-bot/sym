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
  it('relay: a frame whose handling throws is refused and counted; the process and the relay link survive', async () => {
    const uncaught = [];
    const onUncaught = (err) => uncaught.push(err);
    process.on('uncaughtException', onUncaught);
    const evil = 'e'.repeat(64);
    const wss = new WebSocketServer({ port: 0 });
    wss.on('connection', (ws) => ws.on('message', (m) => {
      if (JSON.parse(String(m)).type !== 'relay-auth') return;
      const send = (payload) => ws.send(JSON.stringify({ from: evil, fromName: 'evil', payload }));
      send({ type: 'message', content: 'first' });
      send({ type: 'mood', mood: 'exhausted after a long debugging session', fromName: 'evil' });
      send({ type: 'message', content: 'second' });
    }));
    const name = uniq('guard-relay');
    const node = new SymNode({ name, silent: true, relayOnly: true, relay: `ws://127.0.0.1:${wss.address().port}`, relayToken: 'x'.repeat(40), room: 'g' });
    const seen = [];
    const moods = [];
    node.on('message', throwOnce(seen));
    node.on('mood-delivered', (d) => moods.push(d));
    node.on('mood-rejected', (d) => moods.push(d));
    try {
      await node.start();
      await until(() => seen.length >= 2);
      assert.deepStrictEqual(uncaught, [], 'nothing reached uncaughtException');
      assert.deepStrictEqual(seen, ['first', 'second'], 'the frame after the refused one is still dispatched');
      assert.strictEqual(moods.length, 1, 'the mood frame is evaluated, not thrown');
      const m = node.metrics();
      assert.strictEqual(m.framesRefused, 1);
      assert.deepStrictEqual(m.framesRefusedByType, { message: 1 });
      assert.strictEqual(node.status().relayConnected, true, 'the relay link is still up');
    } finally {
      process.removeListener('uncaughtException', onUncaught);
      await node.stop();
      await new Promise((r) => wss.close(() => r()));
      fs.rmSync(nodeDir(name), { recursive: true, force: true });
    }
  });

  it('LAN and loopback: the same dispatch refuses and counts (0.13.16 swallowed it in the transport, uncounted)', async () => {
    const socks = [];
    const server = net.createServer((sock) => {
      socks.push(sock);
      sock.on('error', () => {});
      sendFrame(sock, { type: 'handshake', nodeId: 'lan-peer', name: 'lan-peer' });
      sendFrame(sock, { type: 'message', content: 'first' });
      sendFrame(sock, { type: 'message', content: 'second' });
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const name = uniq('guard-lan');
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: 'g' });
    const seen = [];
    node.on('message', throwOnce(seen));
    try {
      await node.start();
      node._connectToPeer('127.0.0.1', server.address().port, 'lan-peer', 'lan-peer');
      await until(() => seen.length >= 2);
      assert.deepStrictEqual(seen, ['first', 'second']);
      assert.strictEqual(node.metrics().framesRefused, 1);
      assert.deepStrictEqual(node.metrics().framesRefusedByType, { message: 1 });
    } finally {
      await node.stop();
      for (const sock of socks) sock.destroy();
      server.close();
      fs.rmSync(nodeDir(name), { recursive: true, force: true });
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
      node._frameHandler.handle('p', 'p', { type: 'mood', mood: 'tired', fromName: 'p' });
      assert.strictEqual(out.length, 1);
      assert.strictEqual(typeof out[0][1].drift, 'number');
      assert.ok(out[0][1].drift >= 0 && out[0][1].drift <= 2, `drift ${out[0][1].drift} is a cosine drift`);
      assert.strictEqual(node._meshNode.activePeerCount, 0, 'no phantom peer is left in the coupling set');
      const entry = node.remember({ focus: 'own work after a mood frame', issue: 'none', intent: 'x', motivation: 'y', commitment: 'z', perspective: 'me', mood: { text: 'calm', valence: 0, arousal: 0 } });
      assert.ok(entry, 'remember() still works (in 0.13.16 it threw for two minutes after one mood frame)');
      assert.ok(Array.isArray(node.peers()));
      for (const mood of [42, { text: 'x' }, null, '']) node._frameHandler.handle('p', 'p', { type: 'mood', mood });
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
  it('stays up, handles both, and answers an insight-engine request it cannot serve instead of throwing', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-daemon-guard-'));
    const sock = path.join(home, 'd.sock');
    const wss = new WebSocketServer({ port: 0 });
    wss.on('connection', (ws) => ws.on('message', (m) => {
      if (JSON.parse(String(m)).type !== 'relay-auth') return;
      const send = (payload) => ws.send(JSON.stringify({ from: 'e'.repeat(64), fromName: 'evil', payload }));
      send({ type: 'mood', mood: 'exhausted after a long debugging session', fromName: 'evil' });
      send({ type: 'message', content: 'hello daemon', fromName: 'evil' });
    }));
    const daemon = spawn(process.execPath, [path.join(__dirname, '..', 'bin', 'sym-daemon.js')], {
      env: { ...process.env, HOME: home, USERPROFILE: home, SYM_STATE_DIR: path.join(home, '.sym'), SYM_SOCKET: sock,
        SYM_NODE_NAME: 'daemon-guard-test', SYM_ROOM: 'daemon-guard-room', SYM_RELAY_ONLY: '1',
        SYM_RELAY_URL: `ws://127.0.0.1:${wss.address().port}`, SYM_RELAY_TOKEN: 'x'.repeat(32) },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    daemon.stdout.on('data', (b) => { out += b; });
    daemon.stderr.on('data', (b) => { out += b; });
    try {
      await until(() => /Message from evil: hello daemon/.test(out) && /sym-daemon ready/.test(out) || daemon.exitCode !== null, 15000);
      await new Promise((r) => setTimeout(r, 500));
      assert.strictEqual(daemon.exitCode, null, `the daemon is still running; log:\n${out.slice(-1500)}`);
      assert.doesNotMatch(out, /FATAL/);
      assert.match(out, /Mood from evil: .*(ACCEPTED|IGNORED)/);
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
      daemon.kill('SIGTERM');
      await new Promise((r) => (daemon.exitCode !== null ? r() : daemon.once('exit', r)));
      await new Promise((r) => wss.close(() => r()));
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});
