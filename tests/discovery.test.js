'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { Discovery, BonjourDiscovery, NullDiscovery } = require('../lib/discovery');

describe('NullDiscovery', () => {
  it('should return port 0', async () => {
    const d = new NullDiscovery();
    const port = await d.start({}, () => {});
    assert.strictEqual(port, 0);
  });

  it('should stop without error', async () => {
    const d = new NullDiscovery();
    await d.start({}, () => {});
    await d.stop(); // should not throw
  });

  it('should be an EventEmitter', () => {
    const d = new NullDiscovery();
    assert.ok(typeof d.on === 'function');
    assert.ok(typeof d.emit === 'function');
  });
});

describe('BonjourDiscovery', () => {
  it('should be constructable', () => {
    const d = new BonjourDiscovery({ mdns: false });
    assert.ok(d instanceof Discovery);
  });

  it('should start a TCP server and return a port', async () => {
    const d = new BonjourDiscovery({ mdns: false });
    const identity = { nodeId: 'test-id', name: 'test', publicKey: 'pk', hostname: 'host' };
    const port = await d.start(identity, () => {});
    assert.ok(port > 0, `should get a real port, got ${port}`);
    await d.stop();
  });

  it('should emit inbound-connection on valid handshake', async () => {
    const d = new BonjourDiscovery({ mdns: false });
    const identity = { nodeId: 'test-id', name: 'test', publicKey: 'pk', hostname: 'host' };
    const port = await d.start(identity, () => {});

    const connections = [];
    d.on('inbound-connection', (transport, peerId, peerName) => {
      connections.push({ peerId, peerName });
    });

    // Connect and send handshake
    const net = require('net');
    const { sendFrame } = require('../lib/frame-parser');
    const client = net.createConnection({ host: '127.0.0.1', port }, () => {
      sendFrame(client, { type: 'handshake', nodeId: 'peer-abc', name: 'peer-node' });
    });

    // Wait for the event
    await new Promise(resolve => setTimeout(resolve, 100));

    assert.strictEqual(connections.length, 1);
    assert.strictEqual(connections[0].peerId, 'peer-abc');
    assert.strictEqual(connections[0].peerName, 'peer-node');

    client.destroy();
    await d.stop();
  });

  it('should reject non-handshake first frames', async () => {
    const d = new BonjourDiscovery({ mdns: false });
    const identity = { nodeId: 'test-id', name: 'test', publicKey: 'pk', hostname: 'host' };
    const port = await d.start(identity, () => {});

    const connections = [];
    d.on('inbound-connection', () => connections.push(true));

    const net = require('net');
    const { sendFrame } = require('../lib/frame-parser');
    const client = net.createConnection({ host: '127.0.0.1', port }, () => {
      sendFrame(client, { type: 'ping' }); // not a handshake
    });

    await new Promise(resolve => setTimeout(resolve, 100));
    assert.strictEqual(connections.length, 0, 'should not accept non-handshake');

    client.destroy();
    await d.stop();
  });

  it('should stop cleanly', async () => {
    const d = new BonjourDiscovery({ mdns: false });
    const identity = { nodeId: 'test-id', name: 'test', publicKey: 'pk', hostname: 'host' };
    await d.start(identity, () => {});
    await d.stop();
    await d.stop(); // double stop should not throw
  });
});

describe('Discovery base class', () => {
  it('should have start and stop methods', () => {
    const d = new Discovery();
    assert.ok(typeof d.start === 'function');
    assert.ok(typeof d.stop === 'function');
  });
});
