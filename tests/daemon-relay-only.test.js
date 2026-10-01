'use strict';
/**
 * RELAY-ONLY. A host with no usable multicast (Termux on Android, a locked-down container)
 * joins over the relay alone: SYM_RELAY_ONLY=1 makes the daemon skip LAN discovery entirely and
 * still authenticate to the relay. Measured here against a fake relay, with the daemon's own
 * process, its own HOME and its own IPC endpoint so it never touches the real one.
 *
 * The relay leg and the IPC leg are checked separately. The relay connection is started by
 * node.start(), before the IPC server exists, and relay-auth is asserted on its own. The IPC
 * endpoint is asserted after it, by name and by the CLI actually reaching the daemon through
 * it. On Windows the endpoint for SYM_SOCKET=<dir>\d.sock is a named pipe (lib/platform
 * ipcEndpoint): listening on the file path itself failed with EACCES, the daemon exited, and
 * the failure surfaced as a missing relay-auth. An IPC failure is now reported as an IPC failure.
 */
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawn, execFile } = require('node:child_process');
const { WebSocketServer } = require('ws');
const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');
const { ipcEndpoint } = require('../lib/platform');

const BIN = path.join(__dirname, '..', 'bin');

test('SYM_RELAY_ONLY=1: LAN discovery off, relay-auth still sent, CLI reaches the daemon over its IPC endpoint', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-relay-only-'));
  const wss = new WebSocketServer({ port: 0 });
  const auths = [];
  wss.on('connection', (ws) => ws.on('message', (m) => { const f = JSON.parse(String(m)); if (f.type === 'relay-auth') auths.push(f); }));
  const relayUrl = `ws://127.0.0.1:${wss.address().port}`;
  const socket = path.join(home, 'd.sock');
  const endpoint = ipcEndpoint(socket); // what the daemon and every client resolve SYM_SOCKET to
  const env = { ...process.env, HOME: home, USERPROFILE: home, SYM_SOCKET: socket, SYM_NODE_NAME: 'relay-only-test',
    SYM_ROOM: 'relay-only-room', SYM_RELAY_ONLY: '1', SYM_RELAY_URL: relayUrl, SYM_RELAY_TOKEN: 'x'.repeat(32) };
  const daemon = spawn(process.execPath, [path.join(BIN, 'sym-daemon.js')], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  daemon.stdout.on('data', (b) => { out += b; });
  daemon.stderr.on('data', (b) => { out += b; });
  const listening = () => out.includes(`IPC server listening: ${endpoint}`);
  try {
    for (let i = 0; i < 100 && daemon.exitCode === null && !(auths.length && listening()); i++) {
      await new Promise((r) => setTimeout(r, 100));
    }
    assert.doesNotMatch(out, /IPC server error/, `the daemon could not open its IPC endpoint ${endpoint}:\n${out.slice(-800)}`);

    // The relay leg, on its own.
    assert.match(out, /relay-only: LAN discovery off \(SYM_RELAY_ONLY\); joining ws:/, out.slice(-800));
    assert.match(out, /Room beacon: off \(relay-only\)/, 'a relay-only daemon does not announce its room on the LAN');
    assert.doesNotMatch(out, /Room beacon: room=/);
    assert.equal(auths.length >= 1, true, `relay-auth expected; log:\n${out.slice(-800)}`);
    assert.equal(auths[0].name, 'relay-only-test');
    assert.equal(typeof auths[0].engine, 'string');
    assert.ok(out.indexOf('SYM node started') < out.indexOf('IPC server listening'),
      'the relay connection is started before the IPC server exists, so it is not gated on it');

    // The IPC leg: the daemon listens where a client resolves the same SYM_SOCKET, and the CLI
    // gets through. (`sym start` records the daemon pid; on Windows the CLI checks that pid
    // rather than a socket file, so record it here the way `sym start` would.)
    assert.ok(listening(), `IPC server listening on ${endpoint} expected; log:\n${out.slice(-800)}`);
    fs.writeFileSync(path.join(home, '.sym', 'daemon.pid'), String(daemon.pid));
    const status = await new Promise((resolve, reject) => {
      execFile(process.execPath, [path.join(BIN, 'sym.js'), 'status', '--json'], { env, timeout: 15000 }, (err, stdout, stderr) => {
        if (err) reject(new Error(`sym status failed: ${err.message}\n${stderr}\ndaemon log:\n${out.slice(-800)}`));
        else resolve(stdout);
      });
    });
    assert.equal(JSON.parse(status).status.name, 'relay-only-test', 'the CLI reached this daemon');
    assert.equal(daemon.exitCode, null, 'the daemon is still running');
  } finally {
    daemon.kill('SIGTERM');
    await new Promise((r) => wss.close(() => r()));
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('a daemon with SYM_STATE_DIR keeps its own files in that root, not in ~/.sym', async () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-rooted-'));
  const home = path.join(base, 'home'); fs.mkdirSync(home);
  const root = path.join(base, 'root'); fs.mkdirSync(root);
  const wss = new WebSocketServer({ port: 0 });
  const auths = [];
  wss.on('connection', (ws) => ws.on('message', (m) => { const f = JSON.parse(String(m)); if (f.type === 'relay-auth') auths.push(f); }));
  // The relay config and the room live only in the root: a daemon reading ~/.sym finds neither.
  fs.writeFileSync(path.join(root, 'relay.env'), `SYM_RELAY_URL=ws://127.0.0.1:${wss.address().port}\nSYM_RELAY_TOKEN=${'y'.repeat(32)}\n`);
  fs.writeFileSync(path.join(root, 'room'), 'rooted-room');
  fs.writeFileSync(path.join(root, 'tasks.json'), JSON.stringify({ tasks: [{ id: 'task-1', title: 'kept in the root', status: 'backlog' }], nextId: 2 }));
  const socket = path.join(base, 'r.sock');
  const env = { ...process.env, HOME: home, USERPROFILE: home, SYM_STATE_DIR: root, SYM_SOCKET: socket, SYM_NODE_NAME: 'rooted-test', SYM_RELAY_ONLY: '1' };
  delete env.SYM_RELAY_URL; delete env.SYM_RELAY_TOKEN; delete env.SYM_ROOM;
  const daemon = spawn(process.execPath, [path.join(BIN, 'sym-daemon.js')], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  daemon.stdout.on('data', (b) => { out += b; });
  daemon.stderr.on('data', (b) => { out += b; });
  try {
    for (let i = 0; i < 100 && daemon.exitCode === null && !auths.length; i++) await new Promise((r) => setTimeout(r, 100));
    assert.ok(auths.length >= 1, `the relay config was read from the root; log:\n${out.slice(-800)}`);
    assert.match(out, /rooted-room/, 'the room was read from the root');
    const endpoint = ipcEndpoint(socket);
    for (let i = 0; i < 100 && !out.includes(`IPC server listening: ${endpoint}`); i++) await new Promise((r) => setTimeout(r, 100));
    const ipc = (msg) => new Promise((resolve, reject) => {
      const c = net.createConnection(endpoint);
      let buf = '';
      c.on('data', (d) => {
        buf += d;
        for (const line of buf.split('\n').slice(0, -1)) {
          const m = JSON.parse(line);
          if (m.type === 'result' && m.action === msg.type) { c.end(); resolve(m); return; }
        }
      });
      c.on('error', reject);
      c.on('connect', () => c.write(JSON.stringify(msg) + '\n'));
    });
    const listed = await ipc({ type: 'task-list' });
    assert.deepEqual(listed.tasks.map((t) => t.title), ['kept in the root'], 'the task board was read from the root');
    // A refused record answers with the SDK's reason and its code, so a client can say why.
    const big = await ipc({ type: 'remember', categories: { focus: 'x'.repeat(300 * 1024) } });
    assert.match(String(big.error), /at most/);
    assert.equal(big.code, 'ECMBSIZE');
    // A handler that throws answers the request with the error instead of leaving it unanswered.
    assert.ok((await ipc({ type: 'remember', categories: { focus: 'one stored record' } })).key);
    const bad = await ipc({ type: 'recall', query: 123 });
    assert.ok(bad.error, `the throw is reported to the caller: ${JSON.stringify(bad)}`);
    assert.equal(daemon.exitCode, null, 'and the daemon is still running');
    assert.equal(fs.existsSync(path.join(home, '.sym')), false, 'nothing was written to ~/.sym');
  } finally {
    daemon.kill('SIGTERM');
    await new Promise((r) => wss.close(() => r()));
    fs.rmSync(base, { recursive: true, force: true });
  }
});

// A second daemon start removed the socket of the daemon already serving it, which then ran on,
// reachable by no client (every client: "sym-daemon not running"). A served socket is never
// removed, and a daemon whose socket file is removed listens on it again.
test('a second daemon never takes a served socket, and a removed socket is listened on again', { skip: process.platform === 'win32' && 'a socket file' }, async () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-sock-'));
  const socket = path.join(base, 'd.sock');
  const start = (name) => {
    const home = path.join(base, name); fs.mkdirSync(home);
    const env = { ...process.env, HOME: home, USERPROFILE: home, SYM_STATE_DIR: path.join(home, '.sym'), SYM_SOCKET: socket, SYM_NODE_NAME: name, SYM_RELAY_ONLY: '1', SYM_SOCKET_CHECK_MS: '300' };
    delete env.SYM_RELAY_URL; delete env.SYM_RELAY_TOKEN; delete env.SYM_ROOM;
    const d = spawn(process.execPath, [path.join(BIN, 'sym-daemon.js')], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    d.out = '';
    d.stdout.on('data', (b) => { d.out += b; });
    d.stderr.on('data', (b) => { d.out += b; });
    return d;
  };
  const until = async (cond, ms = 15000) => { for (let t = 0; t < ms && !cond(); t += 100) await new Promise((r) => setTimeout(r, 100)); return cond(); };
  const status = () => new Promise((resolve) => {
    const c = net.createConnection(socket);
    let buf = '';
    c.on('data', (d) => { buf += d; if (buf.includes('\n')) { c.end(); resolve(true); } });
    c.on('error', () => resolve(false));
    c.on('connect', () => c.write(JSON.stringify({ type: 'status' }) + '\n'));
    setTimeout(() => resolve(false), 3000);
  });
  const a = start('first');
  let b = null;
  try {
    assert.ok(await until(() => a.out.includes('IPC server listening')), a.out.slice(-600));
    b = start('second');
    assert.ok(await until(() => b.exitCode !== null), `the second daemon exits: ${b.out.slice(-400)}`);
    assert.match(b.out, /Another sym-daemon is serving/);
    assert.equal(await status(), true, 'the first is still reachable on the socket');
    fs.unlinkSync(socket);
    assert.ok(await until(() => fs.existsSync(socket), 5000), 'the first listens again on its removed socket');
    assert.equal(await status(), true);
  } finally {
    a.kill('SIGTERM');
    if (b && b.exitCode === null) b.kill('SIGTERM');
    await new Promise((r) => setTimeout(r, 300));
    fs.rmSync(base, { recursive: true, force: true });
  }
});
