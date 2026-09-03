'use strict';

/**
 * The relay's state must be visible to whoever drives the node — a person at `sym status`
 * or the Claude session behind the plugin — because the alternative is what happened on
 * 2026-09-03: a session knocked on a relay every ~23 s for hours, refused each time, and
 * nothing on the session's side could see it. These tests pin what state() reports at each
 * phase, that describe() carries the fix in the same sentence as the fault, and that
 * awaitOutcome() resolves on the relay's actual answer (admitted / refused / stopped) rather
 * than on a timer, so a join can return that answer instead of "discovering peers".
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { WebSocketServer } = require('ws');
const { RelayConnection } = require('../lib/relay');

function fakeRelay(answer) {
  const wss = new WebSocketServer({ port: 0 });
  const state = { attempts: 0 };
  wss.on('connection', (ws) => {
    ws.on('message', () => { state.attempts++; answer(ws, state.attempts); });
  });
  const url = `ws://127.0.0.1:${wss.address().port}`;
  return { wss, url, state, close: () => new Promise((r) => wss.close(() => r())) };
}

function client(url, opts = {}) {
  const logs = [];
  let running = true;
  const rc = new RelayConnection({
    relayUrl: url,
    relayToken: 'x'.repeat(40),
    log: (line) => logs.push(line),
    getIdentity: () => ({ nodeId: 'b'.repeat(64) }),
    isRunning: () => running,
    getPeers: () => new Map(),
    getMeshNode: () => null,
    createPeer: () => { throw new Error('no peers expected'); },
    addPeer: () => {},
    handlePeerMessage: () => {},
    onPeerLeft: () => {},
    onAuthRefused: () => {},
    nodeName: 'claude-test-state',
    peerWakeChannels: new Map(),
    saveWakeChannels: () => {},
    ...opts,
  });
  return { rc, logs, stop: () => { running = false; rc.destroy(); } };
}

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

test('no relay configured: phase off, describe says LAN only, awaitOutcome resolves at once', async () => {
  const c = client(null);
  const t0 = Date.now();
  const s = await c.rc.awaitOutcome(5000);
  assert.equal(s.phase, 'off');
  assert.equal(s.url, null);
  assert.ok(Date.now() - t0 < 500, 'does not wait for a relay that is not there');
  assert.equal(c.rc.describe(), 'not configured (LAN only)');
  c.stop();
});

test('admitted: awaitOutcome resolves on relay-peers with phase connected and the peer count', async () => {
  const relay = fakeRelay((ws) => ws.send(JSON.stringify({ type: 'relay-peers', peers: [] })));
  const c = client(relay.url);
  try {
    assert.equal(c.rc.state().phase, 'idle');
    assert.match(c.rc.describe(), /^configured: ws:\/\/127\.0\.0\.1:\d+ \(not started\)$/);
    c.rc.connect();
    const s = await c.rc.awaitOutcome(5000);
    assert.equal(s.phase, 'connected');
    assert.equal(s.attempts, 0, 'a successful auth resets the attempt count');
    assert.equal(s.refused, null);
    assert.equal(s.peers, 0);
    assert.match(c.rc.describe(), /^connected to ws:\/\/127\.0\.0\.1:\d+ for \d+s, 0 relay peer\(s\)$/);
  } finally { c.stop(); await relay.close(); }
});

test('refused: awaitOutcome resolves on 4003; describe names code, reason and the fix; the phase survives the slow-cadence retries', async () => {
  const relay = fakeRelay((ws) => {
    ws.send(JSON.stringify({ type: 'relay-error', kind: 'auth', code: 4003, message: 'Token too short — a self-serve channel needs at least 32 characters' }));
    ws.close(4003, 'Token too short — a self-serve channel needs at least 32 characters');
  });
  const c = client(relay.url, { authRefusedRetryMs: 200 });
  try {
    c.rc.connect();
    const s = await c.rc.awaitOutcome(5000);
    assert.equal(s.phase, 'refused');
    assert.equal(s.refused.code, 4003);
    assert.match(s.refused.reason, /at least 32 characters/);
    assert.equal(s.lastClose.code, 4003);
    const line = c.rc.describe();
    assert.match(line, /^REFUSED by ws:\/\/127\.0\.0\.1:\d+ \(4003: Token too short/);
    assert.match(line, /sym_invite_create/, 'the fix is in the same sentence as the fault');
    assert.match(line, /sym_join_room/);
    assert.match(line, /SYM_RELAY_TOKEN/);
    assert.ok(!line.includes('x'.repeat(40)), 'the token itself is never in the line');
    await wait(700);
    assert.ok(relay.state.attempts >= 2, `still knocking at the slow cadence (attempts=${relay.state.attempts})`);
    assert.equal(c.rc.state().phase, 'refused', 'a scheduled retry does not relabel a refusal as reconnecting');
    assert.equal(c.rc.state().refused.reason, s.refused.reason, 'first refusal of the episode is kept');
  } finally { c.stop(); await relay.close(); }
});

test('identity collision: awaitOutcome resolves on 4004 with phase collision; describe says it will not reconnect', async () => {
  const relay = fakeRelay((ws) => ws.close(4004, 'Duplicate identity'));
  const c = client(relay.url);
  try {
    c.rc.connect();
    const s = await c.rc.awaitOutcome(5000);
    assert.equal(s.phase, 'collision');
    assert.equal(s.nextRetryAt, null, 'nothing scheduled');
    assert.match(c.rc.describe(), /^STOPPED: .*\(4004\)\. Not reconnecting/);
    await wait(300);
    assert.equal(relay.state.attempts, 1, 'no second knock');
  } finally { c.stop(); await relay.close(); }
});

test('unreachable: awaitOutcome times out in phase reconnecting; describe gives the last close, the retry and that LAN is unaffected', async () => {
  const relay = fakeRelay(() => {});
  const { url } = relay;
  await relay.close(); // nobody listening on that port any more
  const c = client(url);
  try {
    c.rc.connect();
    const t0 = Date.now();
    const s = await c.rc.awaitOutcome(400);
    assert.ok(Date.now() - t0 >= 380, 'waited for the bound, not for a terminal phase that never came');
    assert.equal(s.phase, 'reconnecting');
    assert.equal(s.attempts, 1);
    assert.ok(s.nextRetryAt > Date.now() - 100, `a retry is scheduled (${s.nextRetryAt})`);
    assert.ok(s.lastClose || s.lastError, 'the failure is recorded');
    const line = c.rc.describe();
    assert.match(line, /^unreachable: ws:\/\/127\.0\.0\.1:\d+ \(last (close|error)/);
    assert.match(line, /retry in \d+s, attempt 1\. LAN peers are unaffected\.$/);
  } finally { c.stop(); }
});

test('destroy() returns the state to idle, never leaves a stale connected/refused phase behind', async () => {
  const relay = fakeRelay((ws) => ws.send(JSON.stringify({ type: 'relay-peers', peers: [] })));
  const c = client(relay.url);
  try {
    c.rc.connect();
    await c.rc.awaitOutcome(5000);
    assert.equal(c.rc.state().phase, 'connected');
    c.rc.destroy();
    assert.equal(c.rc.state().phase, 'idle');
    assert.equal(c.rc.state().nextRetryAt, null);
  } finally { c.stop(); await relay.close(); }
});
