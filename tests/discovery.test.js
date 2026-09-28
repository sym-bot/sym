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

    // Wait for the EVENT, not for a fixed time: a 100 ms sleep raced the loopback round trip on a
    // loaded host and failed with 0 connections while the handshake was still in flight.
    const deadline = Date.now() + 5000;
    while (connections.length === 0 && Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 10));
    }

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

describe('loopback self-clean on abrupt exit', () => {
  it('removes the endpoint file when the process exits without stop()', () => {
    const { spawnSync } = require('node:child_process');
    const fs = require('node:fs');
    const os = require('node:os');
    const path = require('node:path');

    // Isolated HOME so we touch a temp loopback dir, not the real ~/.sym.
    const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-exit-'));
    const discoveryPath = path.resolve(__dirname, '../lib/discovery.js');
    // Child starts the loopback registry (writes the endpoint), then exits
    // WITHOUT calling stop() — the exit hook must still unlink the file.
    const src = `
      const fs = require('fs');
      const { BonjourDiscovery } = require(${JSON.stringify(discoveryPath)});
      const d = new BonjourDiscovery({ mdns: false });
      d._identity = { nodeId: 'exit-hook-test', name: 'exit-hook-test' };
      d._port = 12345; d._serviceType = '_sym._tcp'; d._log = () => {};
      d._scanLoopback = () => {};
      d._startLoopbackRegistry();
      process.stdout.write(d._regFile);
      process.exit(0);
    `;
    const r = spawnSync(process.execPath, ['-e', src], {
      env: { ...process.env, HOME: tmpHome },
      encoding: 'utf8',
    });

    const regFile = r.stdout.trim();
    assert.ok(regFile.startsWith(tmpHome), `endpoint should write under temp HOME, got ${regFile}`);
    assert.ok(!fs.existsSync(regFile), 'endpoint file must be removed on exit');

    fs.rmSync(tmpHome, { recursive: true, force: true });
  });
});

describe('Discovery base class', () => {
  it('should have start and stop methods', () => {
    const d = new Discovery();
    assert.ok(typeof d.start === 'function');
    assert.ok(typeof d.stop === 'function');
  });
});

describe('loopback GC collects a dead registration in any room', () => {
  // A finished mission's nodes leave registrations in a room no live node shares. The scan used to apply room
  // isolation BEFORE its liveness check, so nobody ever collected them: 492 of 516 on one host (2026-09-28), and every
  // live node re-read all of them every 5 s. Liveness now comes first; room isolation gates dialing only.
  it('removes dead registrations of every room, keeps live ones, and dials only its own room', async () => {
    const fs = require('node:fs');
    const os = require('node:os');
    const path = require('node:path');
    const { spawn } = require('node:child_process');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-gc-'));
    // a pid that is certainly dead: a child that has exited and been reaped
    const child = spawn(process.execPath, ['-e', '0'], { stdio: 'ignore' });
    await new Promise((r) => child.on('exit', r));
    const deadPid = child.pid;
    const write = (name, rec) => fs.writeFileSync(path.join(dir, `${name}.json`), JSON.stringify({ ts: Date.now(), port: 40000, ...rec }));
    write('dead-other-room', { nodeId: 'n-dead-other', pid: deadPid, serviceType: '_mission-abc123._tcp' });
    write('dead-own-room', { nodeId: 'n-dead-own', pid: deadPid, serviceType: '_sym._tcp' });
    write('live-other-room', { nodeId: 'n-live-other', pid: process.pid, serviceType: '_mission-def456._tcp' });
    write('live-own-room', { nodeId: 'n-live-own', pid: process.pid, serviceType: '_sym._tcp' });
    const dialed = [];
    const d = new BonjourDiscovery({ mdns: false });
    d._identity = { nodeId: 'n-aaa-scanner', name: 'scanner' };
    d._serviceType = '_sym._tcp'; d._log = () => {};
    d._regDir = dir; d._regFile = path.join(dir, 'self.json');
    d.emit = (event, _host, _port, nodeId) => { if (event === 'peer-found') dialed.push(nodeId); return true; };
    d._scanLoopback();
    const left = fs.readdirSync(dir).sort();
    assert.deepStrictEqual(left, ['live-other-room.json', 'live-own-room.json'], 'both dead registrations collected, whatever their room');
    assert.deepStrictEqual(dialed, ['n-live-own'], 'room isolation still gates dialing');
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
