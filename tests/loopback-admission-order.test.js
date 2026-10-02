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

describe('an inbound connection is admitted before it can replace one (R6)', () => {
  it('a refused handshake naming a connected peer leaves that peer\'s connection open and learns nothing', () => {
    const name = uniq('accept-order');
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: 'g' });
    const fake = () => Object.assign(new EventEmitter(), { closed: false, send() { return true; }, close() { this.closed = true; this._closed = true; this.emit('close'); } });
    try {
      const existing = fake();
      node._acceptInbound(existing, 'friend', 'friend', { type: 'handshake', nodeId: 'friend', name: 'friend', room: 'g' });
      assert.strictEqual(node._peers.get('friend').transport, existing);
      node._peers.get('friend').lastSeen = Date.now() - 60_000; // idle: the dedup would take it for stale
      const impostor = fake();
      node._acceptInbound(impostor, 'friend', 'friend', { type: 'handshake', nodeId: 'friend', name: 'friend', room: 'elsewhere', publicKey: 'impostor-key' });
      assert.strictEqual(impostor.closed, true, 'the refused connection is closed');
      assert.strictEqual(existing.closed, false, 'the connected peer keeps its connection (until 0.13.17 it was closed first)');
      assert.strictEqual(node._peers.get('friend').transport, existing);
      assert.strictEqual(node._roster.has('friend'), false, 'and nothing was learned from the refused handshake');
      assert.strictEqual(impostor.listenerCount('message'), 0, 'nor is anything read from its connection');
    } finally { node._peers.clear(); node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });
});
