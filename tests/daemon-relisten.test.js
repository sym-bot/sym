'use strict';

/**
 * 0.14.0 release review B-F1: a daemon whose socket file was removed listened again by closing its
 * server and listening in the close callback. close() waits for every connection to end, and IPC
 * clients stay connected for hours, so the daemon accepted nothing while one was attached; each check
 * queued another callback, and when the clients left the second listen() threw and the daemon exited.
 * It now binds a fresh server, without waiting on anyone, and a failure never ends it.
 *
 * Closing a Unix-socket server removes its path, whoever has bound it since; so a daemon shutting
 * down closes its server only while the path is its own, and leaves one another daemon serves.
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const net = require('net');
const fs = require('fs');
const path = require('path');
const { tmpdir } = require('./_tmpdir');

const BIN = path.join(__dirname, '..', 'bin');
const posix = process.platform !== 'win32';

function startDaemon(base, name, socket, checkMs) {
  const home = path.join(base, name);
  fs.mkdirSync(home, { recursive: true });
  const env = { ...process.env, HOME: home, USERPROFILE: home, SYM_SOCKET: socket, SYM_NODE_NAME: name, SYM_RELAY_ONLY: '1', SYM_SOCKET_CHECK_MS: String(checkMs) };
  delete env.SYM_RELAY_URL; delete env.SYM_RELAY_TOKEN; delete env.SYM_ROOM; delete env.SYM_STATE_DIR;
  const d = spawn(process.execPath, [path.join(BIN, 'sym-daemon.js')], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  d.out = '';
  d.stdout.on('data', (b) => { d.out += b; });
  d.stderr.on('data', (b) => { d.out += b; });
  return d;
}
const until = async (cond, ms = 15000) => { for (let t = 0; t < ms && !cond(); t += 50) await new Promise((r) => setTimeout(r, 50)); return cond(); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** A client that stays connected and can ask for status over and over. */
function client(socket) {
  return new Promise((resolve, reject) => {
    const c = net.createConnection(socket);
    let buf = '';
    const waiting = [];
    c.on('data', (d) => {
      buf += d;
      let i;
      while ((i = buf.indexOf('\n')) !== -1) { const line = buf.slice(0, i); buf = buf.slice(i + 1); const w = waiting.shift(); if (w) w(JSON.parse(line)); }
    });
    c.once('error', reject);
    c.once('connect', () => resolve({
      status: () => new Promise((r) => { waiting.push(r); c.write(JSON.stringify({ type: 'status' }) + '\n'); setTimeout(() => r(null), 3000); }),
      end: () => c.end(),
    }));
  });
}
const statusOnce = async (socket) => { try { const c = await client(socket); const s = await c.status(); c.end(); return !!s; } catch { return false; } };

test('a removed socket is listened on again while a client stays connected, and the daemon lives on when it leaves', { skip: !posix && 'Unix socket files only' }, async () => {
  const base = tmpdir('sym-relisten-');
  const socket = path.join(base, 'd.sock');
  const d = startDaemon(base, 'relisten', socket, 200);
  try {
    assert.ok(await until(() => d.out.includes('IPC server listening')), d.out.slice(-600));
    const held = await client(socket);
    assert.ok(await held.status(), 'a client is connected and served');
    for (let round = 1; round <= 2; round++) {
      fs.unlinkSync(socket);
      assert.ok(await until(() => fs.existsSync(socket), 3000), `round ${round}: the socket is back while the client is still connected\n${d.out.slice(-600)}`);
      assert.equal(await statusOnce(socket), true, `round ${round}: a new client reaches the daemon`);
      assert.ok(await held.status(), `round ${round}: and the connected client is still served`);
      await sleep(700);   // several checks pass with the path served: none re-listens
    }
    held.end();
    await sleep(1000);
    assert.equal(d.exitCode, null, `the daemon is still running after its clients left\n${d.out.slice(-600)}`);
    assert.doesNotMatch(d.out, /FATAL|ERR_SERVER_ALREADY_LISTEN/);
    assert.equal(await statusOnce(socket), true);
  } finally {
    d.kill('SIGTERM');
    await until(() => d.exitCode !== null, 5000);
  }
});

test('a daemon shutting down leaves the socket another daemon now serves', { skip: !posix && 'Unix socket files only' }, async () => {
  const base = tmpdir('sym-shutdown-');
  const socket = path.join(base, 'd.sock');
  const a = startDaemon(base, 'first', socket, 600_000);   // never re-listens within the test
  let b = null;
  try {
    assert.ok(await until(() => a.out.includes('IPC server listening')), a.out.slice(-600));
    fs.unlinkSync(socket);
    b = startDaemon(base, 'second', socket, 600_000);
    assert.ok(await until(() => b.out.includes('IPC server listening')), `the second daemon takes the free path\n${b.out.slice(-600)}`);
    a.kill('SIGTERM');
    assert.ok(await until(() => a.exitCode !== null, 10000), 'the first shuts down');
    assert.ok(fs.existsSync(socket), "the second daemon's socket is still there");
    assert.equal(await statusOnce(socket), true, 'and it still answers');
  } finally {
    if (a.exitCode === null) a.kill('SIGTERM');
    if (b && b.exitCode === null) b.kill('SIGTERM');
    await sleep(300);
  }
});
