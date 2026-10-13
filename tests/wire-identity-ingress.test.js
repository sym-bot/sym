'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * 0.13.17 security hotfix. A peer's nodeId and name arrive as JSON (a LAN handshake; a relay's
 * join notice and peer list, which carry what the joiner put in its relay-auth; a relay envelope),
 * and JSON can carry an object whose toString is not callable, which throws when anything prints
 * it. 0.13.16 kept such values in the peer table and printed them later, in timers and transport
 * callbacks: a peer could crash a node over the relay (a join notice) or the LAN (a handshake) by
 * choosing its own name. They are now taken at the door as what they must be (lib/wire-identity.js).
 *
 * Since 0.14 (Core Secure) none of these values makes a peer at all: a relay roster entry is a
 * candidate, a hello is checked field by field before the handshake uses it, and a peer exists only
 * after both proofs. The invariant stands on every path: nothing a peer chooses for its id or name
 * reaches uncaughtException, and a connection the node cannot take is closed and counted.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const net = require('net');
const { WebSocketServer } = require('ws');
const { SymNode } = require('../lib/node');
const { BonjourDiscovery, NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const { sendFrame } = require('../lib/frame-parser');
const { wireNodeId, wireName } = require('../lib/wire-identity');
const { admitAs, identity } = require('./_core-secure');
const { clientHello } = require('../lib/core/handshake-v2-flow');

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
    const refused = [];
    node.on('metric', (m) => { if (m.type === 'session-frame-refused') refused.push(m); });
    try {
      await node.start();
      await until(() => refused.length >= 1);
      await new Promise((r) => setTimeout(r, 100));
      assert.deepStrictEqual(u.seen, [], 'nothing reached uncaughtException');
      assert.deepStrictEqual(node.status().peers, [], 'a roster entry is a candidate, never a peer');
      assert.ok(refused.some((m) => m.frameType === 'message'), 'the plaintext frame from an unproven `from` is refused and counted');
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

  /** A client-hello as a real client builds it, with `bad` fields put in. */
  function hello(room, bad = {}) {
    const C = identity('c');
    const { frame } = clientHello({ room, nodeId: C.nodeId, name: 'c', identityPublicKey: C.publicKey, e2ePublicKey: require('crypto').randomBytes(32).toString('base64url'), implementation: { name: 'x', version: '1' }, extensions: ['cmb-encrypted-v2'] });
    return { ...frame, ...bad };
  }

  it('a legacy handshake naming the peer with an unprintable name is refused at once, and nothing crashes', async () => {
    const u = catchUncaught();
    const { node, name } = await lanNode('wire-lan-name');
    const s = dial(node._port, { type: 'handshake', nodeId: 'z'.repeat(64), name: BAD });
    try {
      await until(() => s.gone, 3000);
      await new Promise((r) => setTimeout(r, 100));
      assert.deepStrictEqual(u.seen, []);
      assert.strictEqual(s.gone, true);
      assert.strictEqual(node._peers.size, 0);
      assert.strictEqual(node._sessionStats.legacyHellosRefused, 1);
      assert.ok(Array.isArray(node.status().peers));
    } finally { u.done(); s.destroy(); await node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  it('a client-hello whose fields are not what they must be closes the connection and is counted; it is never left open without an owner', async () => {
    const u = catchUncaught();
    const { node, name } = await lanNode('wire-lan-refused');
    const dials = [
      dial(node._port, hello('g', { name: BAD })),
      dial(node._port, hello('g', { nodeId: 42 })),
      dial(node._port, hello('g', { room: BAD })),
      dial(node._port, hello('g', { identityPublicKey: BAD, e2ePublicKey: BAD })),
    ];
    try {
      await until(() => dials.every((d) => d.gone), 3000);
      assert.ok(dials.every((d) => d.gone), 'every refused connection is closed');
      assert.deepStrictEqual(u.seen, []);
      assert.strictEqual(node._peers.size, 0);
      assert.strictEqual(node._sessionStats.failedByReason.error, 4, 'each counted');
      assert.strictEqual(node._roster.size(), 0, 'and nothing was pinned from any of them');
    } finally { u.done(); for (const d of dials) d.destroy(); await node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });
});

describe('wake channels are taken as text before they are kept', () => {
  it('a wake-channel frame or peer-info entry that is not text is not stored, written or passed on', () => {
    const name = uniq('wire-wake');
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    let writes = 0;
    node._wakeManager.saveWakeChannels = () => { writes++; };
    try {
      const p1 = admitAs(node, { nodeId: 'p1' });
      assert.doesNotThrow(() => node._frameHandler.handle(p1, { type: 'wake-channel', platform: BAD, token: 't' }));
      assert.doesNotThrow(() => node._frameHandler.handle(p1, { type: 'wake-channel', platform: 'apns', token: { t: 1 } }));
      assert.strictEqual(node._peerWakeChannels.has('p1'), false, 'not kept');
      assert.strictEqual(writes, 0, 'and not written (0.13.16 wrote it, then threw printing it)');
      // Since 0.14 a peer-info entry is learned only for the sender itself (design D1).
      node._frameHandler.handle(admitAs(node, { nodeId: 'b' }), { type: 'peer-info', peers: [
        null, 7, { nodeId: BAD, wakeChannel: { platform: 'apns', token: 't' } },
        { nodeId: 'a', wakeChannel: { platform: 'apns', token: BAD } },
        { nodeId: 'b', lastSeen: Date.now(), wakeChannel: { platform: 'apns', token: 't', environment: 'sandbox', extra: 'x'.repeat(10000) } },
      ] });
      assert.deepStrictEqual([...node._peerWakeChannels.keys()], ['b']);
      // 0.14 keeps how the channel was learned (source, lastSeen) beside what a wake uses.
      const { platform, token, environment, ...rest } = node._peerWakeChannels.get('b');
      assert.deepStrictEqual({ platform, token, environment }, { platform: 'apns', token: 't', environment: 'sandbox' }, 'only what a wake uses is kept');
      assert.deepStrictEqual(Object.keys(rest).sort(), ['lastSeen', 'source']);
      assert.strictEqual(writes, 1);
    } finally { node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });
});
