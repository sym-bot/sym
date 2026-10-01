'use strict';
/**
 * RELAY-ONLY. A host with no usable multicast (Termux on Android, a locked-down container)
 * joins over the relay alone: SYM_RELAY_ONLY=1 makes the daemon skip LAN discovery entirely and
 * still authenticate to the relay. Measured here against a fake relay, with the daemon's own
 * process, its own HOME and its own IPC socket so it never touches the real one.
 */
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { WebSocketServer } = require('ws');
const fs = require('fs');
const os = require('os');
const path = require('path');

test('SYM_RELAY_ONLY=1: LAN discovery off, relay-auth still sent', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-relay-only-'));
  const wss = new WebSocketServer({ port: 0 });
  const auths = [];
  wss.on('connection', (ws) => ws.on('message', (m) => { const f = JSON.parse(String(m)); if (f.type === 'relay-auth') auths.push(f); }));
  const relayUrl = `ws://127.0.0.1:${wss.address().port}`;
  const daemon = spawn(process.execPath, [path.join(__dirname, '..', 'bin', 'sym-daemon.js')], {
    env: { ...process.env, HOME: home, USERPROFILE: home, SYM_SOCKET: path.join(home, 'd.sock'), SYM_NODE_NAME: 'relay-only-test',
      SYM_ROOM: 'relay-only-room', SYM_RELAY_ONLY: '1', SYM_RELAY_URL: relayUrl, SYM_RELAY_TOKEN: 'x'.repeat(32) },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  daemon.stdout.on('data', (b) => { out += b; });
  daemon.stderr.on('data', (b) => { out += b; });
  try {
    for (let i = 0; i < 100 && !(auths.length && /relay-only: LAN discovery off/.test(out)); i++) await new Promise((r) => setTimeout(r, 100));
    assert.match(out, /relay-only: LAN discovery off \(SYM_RELAY_ONLY\); joining ws:/, out.slice(-800));
    assert.equal(auths.length >= 1, true, `relay-auth expected; log:\n${out.slice(-800)}`);
    assert.equal(auths[0].name, 'relay-only-test');
    assert.equal(typeof auths[0].engine, 'string');
    assert.equal(daemon.exitCode, null, 'the daemon is still running');
  } finally {
    daemon.kill('SIGTERM');
    await new Promise((r) => wss.close(() => r()));
    fs.rmSync(home, { recursive: true, force: true });
  }
});
