'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * THE RELAY SETTING NEVER STOPS THE NODE (B1, re-review of release/0.14.3). R3-11 had a relay URL `ws`
 * could not parse throw from start(), after the node had half started; the first fix threw EBADRELAY
 * from the SymNode constructor and refused http:// and https:// (which sym 0.14.2 dialled, ws maps
 * them), so mesh-channel exited at startup and the daemon crash-looped under KeepAlive for anyone
 * whose SYM_RELAY_URL was https://. The relay is an optional transport:
 *
 *   - http:// and https:// are the same relay as ws:// and wss://, and are spelled so wherever a relay
 *     URL comes in (SymNode, RelayConnection, parseInvite);
 *   - a setting that is still no relay URL disables the relay: the constructor and start() never fail
 *     for it, status() says `disabled` with the reason, one loud log line, and a 'relay-disabled'
 *     event at start(); the node runs on the LAN;
 *   - the daemon comes up with either setting.
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { WebSocketServer } = require('ws');
const { RelayConnection, normalizeRelayUrl, relayUrlProblem } = require('../lib/relay');
const { parseInvite } = require('../lib/invite');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { until } = require('./_core-secure');

const BIN = path.join(__dirname, '..', 'bin');
const uniq = (s) => `${s}-${process.pid}-${Math.random().toString(36).slice(2, 8)}`;

test('http:// and https:// are spelled ws:// and wss://; ws:// and wss:// are kept as written; the rest is no relay URL', () => {
  assert.equal(normalizeRelayUrl('https://sym-relay.onrender.com'), 'wss://sym-relay.onrender.com');
  assert.equal(normalizeRelayUrl('HTTP://127.0.0.1:8787/x'), 'ws://127.0.0.1:8787/x');
  assert.equal(normalizeRelayUrl(' wss://relay.example.org '), 'wss://relay.example.org');
  assert.equal(normalizeRelayUrl('ws://127.0.0.1:8787'), 'ws://127.0.0.1:8787');
  for (const bad of ['relay.example.com', 'ftp://relay.example.com', 'https://', '', 'ws://', 42, null, 'w'.repeat(3000)]) {
    assert.equal(normalizeRelayUrl(bad), null, String(bad).slice(0, 40));
  }
  // The reason never repeats the setting: a URL can carry a secret.
  const why = relayUrlProblem('ftp://user:s3cret@relay.example.com');
  assert.match(why, /ftp: URL/);
  assert.ok(!why.includes('s3cret') && !why.includes('relay.example.com'));
  assert.match(relayUrlProblem('relay.example.com'), /not a URL/);
});

test('RelayConnection: a setting that is no relay URL disables the relay; nothing throws and nothing dials', async () => {
  const logs = [];
  const rc = new RelayConnection({ relayUrl: 'relay.example.com', log: (l) => logs.push(l), getIdentity: () => ({ nodeId: '01900000-0000-7000-8000-0000000000f1' }), isRunning: () => true, nodeName: 'off' });
  const s = rc.state();
  assert.equal(s.phase, 'disabled');
  assert.equal(s.url, null);
  assert.match(s.disabled.reason, /not a URL/);
  assert.match(rc.describe(), /^DISABLED: .*runs on the LAN only\. Fix: set SYM_RELAY_URL/);
  rc.connect();
  assert.equal(rc.ws, null, 'nothing dialled');
  assert.equal((await rc.awaitOutcome(10_000)).phase, 'disabled', 'an outcome at once');
  rc.destroy();
  assert.equal(rc.state().phase, 'disabled');
});

test('SymNode: an invalid relay setting never fails the constructor or start(); status says disabled; one event at start', async () => {
  const n = new SymNode({ name: uniq('relay-off'), silent: true, discovery: new NullDiscovery(), relay: 'not a relay url', relayToken: 'x'.repeat(40) });
  const told = [];
  n.on('relay-disabled', (e) => told.push(e));
  try {
    await n.start();
    const st = n.status();
    assert.equal(st.running, true);
    assert.equal(st.relay, null);
    assert.equal(st.relayState.phase, 'disabled');
    assert.match(st.relayState.disabled.reason, /not a URL/);
    assert.match(st.relayStatus, /^DISABLED: /);
    assert.equal(told.length, 1);
    assert.match(told[0].reason, /not a URL/);
    await n.stop();
    await n.start();
    assert.equal(told.length, 1, 'told once per node, not on every start');
  } finally { await n.stop(); }
});

test('SymNode: an http:// relay URL is dialled as ws:// and connects', async () => {
  const wss = new WebSocketServer({ port: 0, host: '127.0.0.1' });
  await new Promise((r) => wss.once('listening', r));
  wss.on('connection', (ws) => ws.on('message', (d) => { if (JSON.parse(String(d)).type === 'relay-auth') ws.send(JSON.stringify({ type: 'relay-peers', peers: [] })); }));
  const port = wss.address().port;
  const n = new SymNode({ name: uniq('relay-http'), silent: true, discovery: new NullDiscovery(), relay: `http://127.0.0.1:${port}`, relayToken: 'x'.repeat(40) });
  try {
    assert.equal(n.status().relay, `ws://127.0.0.1:${port}`);
    await n.start();
    assert.ok(await until(() => n.status().relayConnected, 5000), 'connected over the ws:// spelling');
  } finally { await n.stop(); await new Promise((r) => { for (const c of wss.clients) c.terminate(); wss.close(() => r()); }); }
});

test('parseInvite takes http(s) relays as ws(s) and refuses one that is no URL, with a clear error', () => {
  const ok = parseInvite(`sym://team/r?relay=${encodeURIComponent('https://sym-relay.onrender.com')}&token=t`);
  assert.equal(ok.error, undefined);
  assert.equal(ok.relayUrl, 'wss://sym-relay.onrender.com');
  const bad = parseInvite('sym://team/r?relay=sym-relay.onrender.com&token=t');
  assert.match(bad.error, /is not a ws:\/\/, wss:\/\/, http:\/\/ or https:\/\/ URL/);
});

for (const [label, url, expect] of [
  ['an https:// relay URL', 'https://127.0.0.1:9', /joining wss:\/\/127\.0\.0\.1:9/],
  ['a relay setting that is no URL', 'relay.example.com', /RELAY DISABLED: /],
]) {
  test(`the daemon comes up with ${label} and stays up`, async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-relayurl-'));
    const socket = path.join(home, 'd.sock');
    const env = { PATH: process.env.PATH, HOME: home, USERPROFILE: home, SYM_STATE_DIR: path.join(home, '.sym'), SYM_SOCKET: socket,
      SYM_SEMANTIC_ENCODER: 'off', SYM_NODE_NAME: uniq('relayurl'), SYM_RELAY_ONLY: '1', SYM_RELAY_URL: url, SYM_RELAY_TOKEN: 'x'.repeat(40) };
    const daemon = spawn(process.execPath, [path.join(BIN, 'sym-daemon.js')], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    daemon.stdout.on('data', (b) => { out += b; });
    daemon.stderr.on('data', (b) => { out += b; });
    try {
      assert.ok(await until(() => /IPC server listening/.test(out) || daemon.exitCode !== null, 15000), `the daemon started:\n${out.slice(-800)}`);
      await new Promise((r) => setTimeout(r, 1500));
      assert.equal(daemon.exitCode, null, `the daemon is still running:\n${out.slice(-800)}`);
      assert.match(out, /IPC server listening/);
      assert.match(out, expect, out.slice(-800));
      assert.doesNotMatch(out, /EBADRELAY|Uncaught exception/);
    } finally {
      daemon.kill('SIGTERM');
      await new Promise((r) => { if (daemon.exitCode !== null) r(); else { daemon.once('exit', r); setTimeout(() => { try { daemon.kill('SIGKILL'); } catch { /* gone */ } r(); }, 3000); } });
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
}
