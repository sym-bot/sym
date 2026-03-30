'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { EventEmitter } = require('events');
const { TcpTransport, RelayPeerTransport } = require('../lib/transport');

class MockSocket extends EventEmitter {
  constructor() { super(); this.destroyed = false; this.chunks = []; }
  write(data) { this.chunks.push(data); }
  destroy() { this.destroyed = true; }
}

describe('TcpTransport', () => {
  it('should emit message events from parsed frames', () => {
    const socket = new MockSocket();
    const transport = new TcpTransport(socket);
    const messages = [];
    transport.on('message', (m) => messages.push(m));

    // Send a valid frame through the socket
    const payload = Buffer.from(JSON.stringify({ type: 'ping' }), 'utf8');
    const header = Buffer.alloc(4);
    header.writeUInt32BE(payload.length, 0);
    socket.emit('data', Buffer.concat([header, payload]));

    assert.strictEqual(messages.length, 1);
    assert.strictEqual(messages[0].type, 'ping');
  });

  it('should send frames via sendFrame', () => {
    const socket = new MockSocket();
    const transport = new TcpTransport(socket);
    transport.send({ type: 'pong' });
    assert.strictEqual(socket.chunks.length, 1);
    assert.ok(socket.chunks[0].length > 4, 'should have length prefix + payload');
  });

  it('should not send after close', () => {
    const socket = new MockSocket();
    const transport = new TcpTransport(socket);
    transport.close();
    transport.send({ type: 'ping' });
    assert.strictEqual(socket.chunks.length, 0);
  });

  it('should destroy socket on close', () => {
    const socket = new MockSocket();
    const transport = new TcpTransport(socket);
    transport.close();
    assert.ok(socket.destroyed);
  });

  it('should be idempotent on double close', () => {
    const socket = new MockSocket();
    const transport = new TcpTransport(socket);
    transport.close();
    transport.close(); // should not throw
    assert.ok(socket.destroyed);
  });

  it('should emit close when socket closes', () => {
    const socket = new MockSocket();
    const transport = new TcpTransport(socket);
    let closed = false;
    transport.on('close', () => { closed = true; });
    socket.emit('close');
    assert.ok(closed);
  });

  it('should propagate socket errors', () => {
    const socket = new MockSocket();
    const transport = new TcpTransport(socket);
    const errors = [];
    transport.on('error', (e) => errors.push(e));
    socket.emit('error', new Error('connection reset'));
    assert.strictEqual(errors.length, 1);
    assert.match(errors[0].message, /connection reset/);
  });

  it('should return pending buffer', () => {
    const socket = new MockSocket();
    const transport = new TcpTransport(socket);
    const buf = transport.pendingBuffer;
    assert.ok(Buffer.isBuffer(buf));
  });
});

describe('RelayPeerTransport', () => {
  it('should send envelope with to field when ws ready', () => {
    const sent = [];
    const mockWs = { readyState: 1, send: (data) => sent.push(data) };
    const transport = new RelayPeerTransport(mockWs, 'peer-123');
    transport.send({ type: 'ping' });
    assert.strictEqual(sent.length, 1);
    const envelope = JSON.parse(sent[0]);
    assert.strictEqual(envelope.to, 'peer-123');
    assert.strictEqual(envelope.payload.type, 'ping');
  });

  it('should not send when ws is not ready', () => {
    const sent = [];
    const mockWs = { readyState: 0, send: (data) => sent.push(data) };
    const transport = new RelayPeerTransport(mockWs, 'peer-123');
    transport.send({ type: 'ping' });
    assert.strictEqual(sent.length, 0);
  });

  it('should not send after close', () => {
    const sent = [];
    const mockWs = { readyState: 1, send: (data) => sent.push(data) };
    const transport = new RelayPeerTransport(mockWs, 'peer-123');
    transport.close();
    transport.send({ type: 'ping' });
    assert.strictEqual(sent.length, 0);
  });

  it('should emit close on close()', () => {
    const mockWs = { readyState: 1, send: () => {} };
    const transport = new RelayPeerTransport(mockWs, 'peer-123');
    let closed = false;
    transport.on('close', () => { closed = true; });
    transport.close();
    assert.ok(closed);
  });

  it('should emit close on destroy()', () => {
    const mockWs = { readyState: 1, send: () => {} };
    const transport = new RelayPeerTransport(mockWs, 'peer-123');
    let closed = false;
    transport.on('close', () => { closed = true; });
    transport.destroy();
    assert.ok(closed);
  });

  it('should not send when ws is null', () => {
    const transport = new RelayPeerTransport(null, 'peer-123');
    assert.doesNotThrow(() => transport.send({ type: 'ping' }));
  });
});
