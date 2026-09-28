'use strict';

// HOME is redirected BEFORE sym is required: discovery's loopback registry lives under os.homedir(), and these tests
// start real discovery. Without this they registered throwaway nodes ('test-id', on the global service type) in the
// HOST's live registry, where a live node could dial them mid-test, and their scans collected the host's
// registrations (found 2026-09-28: a run of 0.13.10's scan removed 490 dead entries from the real ~/.sym/loopback).
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const realHome = os.homedir();
process.env.HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-discovery-home-'));

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { Discovery, BonjourDiscovery, NullDiscovery, createBonjour } = require('../lib/discovery');

describe('test isolation', () => {
  it('a started discovery registers under the sandbox HOME, never the real one', async () => {
    const d = new BonjourDiscovery({ mdns: false });
    await d.start({ nodeId: 'isolation-probe', name: 'isolation-probe', publicKey: 'pk', hostname: 'host' }, () => {});
    try {
      assert.ok(d._regDir && d._regDir.startsWith(process.env.HOME), `registry dir ${d._regDir} is under the sandbox`);
      assert.ok(!d._regDir.startsWith(path.join(realHome, '.sym')), 'and not in the host registry');
    } finally { await d.stop(); }
  });
});

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

// One 'exit' hook serves every live loopback registration in the process. Each discovery used to add its own, so a
// process hosting many nodes carried one listener per live node (the xmesh runtime logged Node's
// MaxListenersExceededWarning at every boot, 2026-09-28).
describe('exit cleanup', () => {
  it('twelve live discoveries add at most one exit listener between them, and stop() removes each registration', async () => {
    const before = process.listenerCount('exit');
    const ds = [];
    for (let i = 0; i < 12; i++) {
      const d = new BonjourDiscovery({ mdns: false });
      await d.start({ nodeId: `exit-probe-${i}`, name: `exit-probe-${i}`, publicKey: 'pk', hostname: 'host' }, () => {});
      ds.push(d);
    }
    try {
      assert.ok(process.listenerCount('exit') - before <= 1, `exit listeners grew by ${process.listenerCount('exit') - before} for 12 nodes`);
      const files = ds.map((d) => d._regFile);
      assert.ok(files.every((f) => f && fs.existsSync(f)), 'each node is registered');
      for (const d of ds) await d.stop();
      assert.ok(files.every((f) => !fs.existsSync(f)), 'stop() unlinks each registration');
    } finally { for (const d of ds) { try { await d.stop(); } catch {} } }
  });

  it('a process that exits without stopping its nodes leaves no registration behind', () => {
    const { spawnSync } = require('node:child_process');
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-exit-home-'));
    const script = `
      const { BonjourDiscovery } = require(${JSON.stringify(path.join(__dirname, '..', 'lib', 'discovery.js'))});
      (async () => {
        for (let i = 0; i < 3; i++) {
          const d = new BonjourDiscovery({ mdns: false });
          await d.start({ nodeId: 'abrupt-' + i, name: 'abrupt-' + i, publicKey: 'pk', hostname: 'host' }, () => {});
        }
        const fs = require('node:fs'), path = require('node:path'), os = require('node:os');
        const dir = path.join(os.homedir(), '.sym', 'loopback');
        process.stdout.write(String(fs.readdirSync(dir).filter((f) => f.startsWith('abrupt-')).length));
        process.exit(0);
      })();`;
    const r = spawnSync(process.execPath, ['-e', script], { env: { ...process.env, HOME: home }, encoding: 'utf8', timeout: 20000 });
    assert.strictEqual(r.status, 0, r.stderr);
    assert.strictEqual(r.stdout.trim(), '3', 'three registrations while the process ran');
    const dir = path.join(home, '.sym', 'loopback');
    const left = fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.startsWith('abrupt-')) : [];
    assert.deepStrictEqual(left, [], 'and none after it exited');
  });
});

// mDNS failures are reported, never thrown. The sym daemon's room beacon, made without an error callback, died of
// `send EHOSTUNREACH 224.0.0.251:5353` three times in September 2026: bonjour-service answers a query through its
// multicast-dns socket, and a failed send reaches its default error callback, which throws.
describe('mDNS errors', () => {
  const { Bonjour } = require('bonjour-service');
  // publish a service, then hand the server a query it answers, with the socket's send failing as it does when the
  // network drops: the path the daemon died on
  function answerAQueryWhileSendsFail(bonjour) {
    // every send fails, the announcement included, so nothing reaches the real LAN; no probe, so the records are
    // registered at once
    bonjour.server.mdns.respond = (_packet, cb) => cb && cb(new Error('send EHOSTUNREACH 224.0.0.251:5353'));
    bonjour.publish({ name: 'mdns-probe', type: 'symrooms', port: 7777, host: 'probe.local', txt: { room: 'r' }, probe: false });
    bonjour.server.mdns.emit('query', { questions: [{ name: '_symrooms._tcp.local', type: 'PTR' }] }, { address: '192.168.1.9', port: 5353 });
  }

  it('the path the daemon died on: a bonjour made without an error callback throws a failed send', () => {
    const bare = new Bonjour();
    try { assert.throws(() => answerAQueryWhileSendsFail(bare), /EHOSTUNREACH/); }
    finally { try { bare.destroy(); } catch {} }
  });

  it('createBonjour reports a failed send to its callback instead of throwing', () => {
    const seen = [];
    const b = createBonjour((err) => seen.push(err.message));
    try {
      assert.doesNotThrow(() => answerAQueryWhileSendsFail(b));
      assert.deepStrictEqual(seen, ['send EHOSTUNREACH 224.0.0.251:5353']);
    } finally { try { b.destroy(); } catch {} }
  });

  it('createBonjour listens for the socket error multicast-dns emits when it cannot bind', () => {
    const seen = [];
    const b = createBonjour((err) => seen.push(err.code));
    try {
      assert.ok(b.server.mdns.listenerCount('error') >= 1, 'on bonjour.server.mdns, where the socket errors are emitted');
      const bind = Object.assign(new Error('bind EADDRINUSE 0.0.0.0:5353'), { code: 'EADDRINUSE' });
      assert.doesNotThrow(() => b.server.mdns.emit('error', bind));
      assert.deepStrictEqual(seen, ['EADDRINUSE']);
    } finally { try { b.destroy(); } catch {} }
  });

  it('every bonjour sym makes comes from createBonjour', () => {
    const roots = ['lib', 'bin'].map((d) => path.join(__dirname, '..', d));
    for (const dir of roots) {
      for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.js'))) {
        const src = fs.readFileSync(path.join(dir, f), 'utf8');
        const direct = (src.match(/new Bonjour\(/g) || []).length;
        assert.strictEqual(direct, f === 'discovery.js' ? 1 : 0, `${d(dir)}/${f}: ${direct} direct Bonjour construction(s)`);
      }
    }
    function d(p) { return path.basename(p); }
  });
});
