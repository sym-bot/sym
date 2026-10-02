'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * 0.13.17 security hotfix. A peer's nodeId and name arrive as JSON (a LAN handshake; a relay's
 * join notice and peer list, which carry what the joiner put in its relay-auth; a relay envelope),
 * and JSON can carry an object whose toString is not callable, which throws when anything prints
 * it. 0.13.16 kept such values in the peer table and printed them later, in timers and transport
 * callbacks: a peer could crash a node over the relay (a join notice) or the LAN (a handshake) by
 * choosing its own name. They are now taken at the door as what they must be (lib/wire-identity.js).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const net = require('net');
const { WebSocketServer } = require('ws');
const { SymNode } = require('../lib/node');
const { BonjourDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const { sendFrame } = require('../lib/frame-parser');
const { wireNodeId, wireName } = require('../lib/wire-identity');

const BAD = { toString: 1 }; // JSON-expressible; String(BAD) throws
const uniq = (base) => `${base}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
const until = async (cond, ms = 5000) => { for (let t = 0; t < ms && !cond(); t += 20) await new Promise((r) => setTimeout(r, 20)); };

function catchUncaught() {
  const seen = [];
  const on = (err) => seen.push(err);
  process.on('uncaughtException', on);
  return { seen, done: () => process.removeListener('uncaughtException', on) };
}

describe('wire identity', () => {
  it('a nodeId is a bounded non-empty string or nothing; a name is a bounded string or "unknown"', () => {
    assert.strictEqual(wireNodeId('abc'), 'abc');
    for (const x of [BAD, 42, null, undefined, '', 'x'.repeat(257), ['a']]) assert.strictEqual(wireNodeId(x), null);
    assert.strictEqual(wireName('alice'), 'alice');
    for (const x of [BAD, 42, null, undefined, '']) assert.strictEqual(wireName(x), 'unknown');
    assert.strictEqual(wireName('n'.repeat(1000)).length, 256);
  });
});

describe('relay: what the relay forwards from a joiner cannot crash the node', () => {
  it('a join notice and a peer list naming a peer with an unprintable name, or malformed entries, are taken safely', async () => {
    const u = catchUncaught();
    const wss = new WebSocketServer({ port: 0 });
    wss.on('connection', (ws) => ws.on('message', (m) => {
      if (JSON.parse(String(m)).type !== 'relay-auth') return;
      ws.send(JSON.stringify({ type: 'relay-peers', peers: [null, 7, { nodeId: BAD }, { nodeId: 'p'.repeat(64), name: BAD }] }));
      ws.send(JSON.stringify({ type: 'relay-peers', peers: { length: 1 } }));
      ws.send(JSON.stringify({ type: 'relay-peer-joined', nodeId: 'q'.repeat(64), name: BAD }));
      ws.send(JSON.stringify({ type: 'relay-peer-joined', nodeId: 12345, name: 'numeric' }));
      ws.send(JSON.stringify({ type: 'relay-peer-left', nodeId: BAD, name: BAD }));
      ws.send(JSON.stringify({ type: 'relay-error', message: BAD }));
      ws.send(JSON.stringify({ from: 'q'.repeat(64), fromName: BAD, payload: { type: 'message', content: 'hello' } }));
    }));
    const name = uniq('wire-relay');
    const node = new SymNode({ name, silent: true, relayOnly: true, relay: `ws://127.0.0.1:${wss.address().port}`, relayToken: 'x'.repeat(40), room: 'g' });
    const messages = [];
    node.on('message', (from, content) => messages.push([from, content]));
    try {
      await node.start();
      await until(() => messages.length >= 1);
      await new Promise((r) => setTimeout(r, 100));
      assert.deepStrictEqual(u.seen, [], 'nothing reached uncaughtException');
      const peers = node.status().peers;
      assert.deepStrictEqual(peers.map((p) => p.name).sort(), ['unknown', 'unknown'], 'both named peers are in, as "unknown"; the numeric id is not');
      assert.deepStrictEqual(messages, [['unknown', 'hello']]);
      assert.strictEqual(node.status().relayConnected, true);
    } finally {
      u.done();
      await node.stop();
      await new Promise((r) => wss.close(() => r()));
      fs.rmSync(nodeDir(name), { recursive: true, force: true });
    }
  });
});

describe('LAN: the handshake that opens a connection', () => {
  async function lanNode(base, opts = {}) {
    const name = uniq(base);
    const node = new SymNode({ name, silent: true, discovery: new BonjourDiscovery({ mdns: false }), room: 'g', ...opts });
    await node.start();
    return { node, name };
  }
  function dial(port, frame) {
    const s = net.createConnection({ port, host: '127.0.0.1' }, () => sendFrame(s, frame));
    s.gone = false;
    s.on('data', () => {});
    s.on('error', () => {});
    s.on('close', () => { s.gone = true; });
    return s;
  }

  it('a handshake naming the peer with an unprintable name does not crash the node; the peer is "unknown"', async () => {
    const u = catchUncaught();
    const { node, name } = await lanNode('wire-lan-name');
    const s = dial(node._port, { type: 'handshake', nodeId: 'z'.repeat(64), name: BAD });
    try {
      await until(() => node._peers.size === 1);
      await new Promise((r) => setTimeout(r, 200));
      assert.deepStrictEqual(u.seen, []);
      assert.strictEqual(node._peers.get('z'.repeat(64)).name, 'unknown');
      assert.ok(Array.isArray(node.status().peers));
    } finally { u.done(); s.destroy(); await node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  it('a handshake the node cannot take closes the connection and is counted; it is never left open without an owner', async () => {
    const { node, name } = await lanNode('wire-lan-refused');
    node._roomAdmission = () => { throw new Error('admission failed'); };
    const s = dial(node._port, { type: 'handshake', nodeId: 'w'.repeat(64), name: 'w' });
    const t = dial(node._port, { type: 'handshake', nodeId: 42, name: 'n' });
    try {
      await until(() => s.gone && t.gone, 3000);
      assert.strictEqual(s.gone, true, 'the refused connection is closed (0.13.16 left it open, its deadline cleared)');
      assert.strictEqual(t.gone, true, 'a handshake whose nodeId is not one is closed');
      assert.strictEqual(node._peers.size, 0);
      assert.strictEqual(node.metrics().framesRefusedByType.handshake, 1);
    } finally { s.destroy(); t.destroy(); await node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  it('a handshake whose keys are not text pins nothing', async () => {
    const { node, name } = await lanNode('wire-lan-keys');
    const s = dial(node._port, { type: 'handshake', nodeId: 'k'.repeat(64), name: 'k', publicKey: BAD, e2ePublicKey: BAD });
    try {
      await until(() => node._peers.size === 1);
      assert.strictEqual(node._roster.has('k'.repeat(64)), false);
      assert.strictEqual(node._peerSharedSecrets.has('k'.repeat(64)), false);
    } finally { s.destroy(); await node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });
});
