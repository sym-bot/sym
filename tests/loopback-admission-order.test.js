'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * 0.13.17 review (R6), two lower findings.
 *   - The loopback scan, which runs in a timer, did arithmetic and comparisons on the fields of
 *     registry files (`now - ts`, `nodeId < other`) and passed `name` on to be printed, as read: a
 *     file holding an object there threw in the timer, which is uncaught. A registration is now
 *     taken as what it must be, or skipped.
 *   - `_acceptInbound` ran its dedup first, which can close the existing connection for the same
 *     nodeId (as stale, or by the dual-dial tie-break), and decided admission after: a refused
 *     handshake naming a connected peer's nodeId cost that peer its connection. Admission is now
 *     decided first, and a refused handshake leaves nothing behind.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { EventEmitter } = require('events');
const { BonjourDiscovery, NullDiscovery } = require('../lib/discovery');
const { SymNode } = require('../lib/node');
const { nodeDir } = require('../lib/config');

const uniq = (base) => `${base}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
const BAD = { toString: 1, valueOf: 1 };

describe('the loopback scan types what it reads (R6)', () => {
  it('a registration whose fields are not what they must be is skipped, not thrown on; a good one is still found', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-loopback-'));
    try {
      const now = Date.now();
      const write = (f, rec) => fs.writeFileSync(path.join(dir, f), JSON.stringify(rec));
      write('a.json', { nodeId: 'zz-bad-ts', port: 4000, pid: process.pid, ts: BAD });
      write('b.json', { nodeId: BAD, port: 4001, pid: process.pid, ts: now });
      write('c.json', { nodeId: 'zz-bad-name', name: BAD, port: 4002, pid: process.pid, ts: now });
      write('d.json', { nodeId: 'zz-bad-port', port: '4003', pid: process.pid, ts: now });
      write('e.json', [1, 2]);
      write('f.json', { nodeId: 'zz-good', name: 'good', port: 4005, pid: process.pid, ts: now });
      const scanner = Object.assign(new EventEmitter(), {
        _regFile: path.join(dir, 'self.json'), _regDir: dir, _identity: { nodeId: 'aa-self' }, _serviceType: '_sym._tcp',
      });
      const found = [];
      scanner.on('peer-found', (addr, port, id, name) => found.push([port, id, name]));
      assert.doesNotThrow(() => BonjourDiscovery.prototype._scanLoopback.call(scanner));
      assert.deepStrictEqual(found.sort(), [[4002, 'zz-bad-name', 'unknown'], [4005, 'zz-good', 'good']]);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
});

describe('an inbound connection is admitted before it can replace one (R6, Core Secure D1/D3)', () => {
  // 0.14: a session is admitted only after its proofs, its key-registry check and the room door;
  // supersession happens only for a confirmed session of the same (nodeId, key). So a handshake
  // naming a connected peer's nodeId — in another room, or under another key — never costs that peer
  // its session, and nothing is learned from it.
  const { PeerSession } = require('../lib/session');
  const { memoryPipe, connectNodes, until, identity } = require('./_core-secure');
  const IMPL = { name: 'sym', version: '0.14.0-test' };
  /** A bare client session against `node` presenting `local` (any nodeId and key) in `room`. */
  function dialAs(node, local, room) {
    const [tc, ts] = memoryPipe();
    node.connectTransport(ts, { role: 'server' });
    const client = new PeerSession({ role: 'client', transport: tc, kind: 'bonjour', local, room, extensions: ['cmb-encrypted-v2'], implementation: IMPL });
    const ended = [];
    client.on('closed', (c) => ended.push(c.reason));
    tc.on('message', (f) => client.receiveWire(f));
    client.start();
    return { client, ended, tc };
  }

  for (const [label, room, otherKey] of [['in another room', 'elsewhere', false], ['under another key', 'g', true]]) {
    it(`a handshake naming a connected peer's nodeId ${label} leaves that peer's session open and learns nothing`, async () => {
      const node = new SymNode({ name: uniq('accept-order'), silent: true, discovery: new NullDiscovery(), room: 'g' });
      const friend = new SymNode({ name: uniq('friend'), silent: true, discovery: new NullDiscovery(), room: 'g' });
      try {
        await node.start(); await friend.start();
        await connectNodes(friend, node);
        const peer = node._peers.get(friend.nodeId);
        const before = peer.transport;
        const keyBefore = node._roster.get(friend.nodeId);
        const forged = { ...identity('impostor'), nodeId: friend.nodeId, name: friend.name };
        if (!otherKey) { forged.publicKey = friend._identity.publicKey; forged.privateKey = friend._identity.privateKey; }
        const imp = dialAs(node, forged, room);
        await until(() => imp.ended.length > 0 || imp.client.confirmed, 3000);
        await new Promise((r) => setTimeout(r, 50));
        assert.strictEqual(node._peers.get(friend.nodeId).transport, before, 'the connected peer keeps its session');
        assert.strictEqual(before.closed, false);
        assert.strictEqual(node._roster.get(friend.nodeId), keyBefore, 'nothing was learned from the refused handshake');
        assert.strictEqual(node._peers.get(friend.nodeId).transports.size, 1);
      } finally { await node.stop(); await friend.stop(); }
    });
  }
});
