'use strict';

/**
 * A relay's auth refusal (close 4003) is deterministic — the token this process holds is not
 * in the relay's channel table — and retrying it at the reconnect cadence is not persistence,
 * it is noise: one rejection every ~23 s in the relay's log for the life of the process, and
 * nothing in the host's. These tests pin the replacement: the refusal is logged ONCE with the
 * fix, the host is told ONCE, and the node keeps knocking at the slow cadence (default 10 min)
 * instead of the exponential one. A 4001 (auth timeout) is transient and keeps the old backoff.
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { WebSocketServer } = require('ws');
const { RelayConnection } = require('../lib/relay');

/** A relay that answers every auth the same way; counts the attempts. */
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
  const refusals = [];
  let running = true;
  const rc = new RelayConnection({
    relayUrl: url,
    relayToken: 'not-in-any-channel',
    log: (line) => logs.push(line),
    getIdentity: () => ({ nodeId: 'a'.repeat(64) }),
    isRunning: () => running,
    getPeers: () => new Map(),
    getMeshNode: () => null,
    createPeer: () => { throw new Error('no peers expected'); },
    addPeer: () => {},
    handlePeerMessage: () => {},
    onPeerLeft: () => {},
    onAuthRefused: (info) => refusals.push(info),
    nodeName: 'claude-test-refused',
    peerWakeChannels: new Map(),
    saveWakeChannels: () => {},
    ...opts,
  });
  return { rc, logs, refusals, stop: () => { running = false; rc.destroy(); } };
}

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

test('4003: one FATAL line with the fix, one host callback, then the slow cadence', async () => {
  const relay = fakeRelay((ws) => {
    ws.send(JSON.stringify({ type: 'relay-error', kind: 'auth', code: 4003, message: 'Invalid token' }));
    ws.close(4003, 'Invalid token');
  });
  const c = client(relay.url, { authRefusedRetryMs: 250 });
  try {
    c.rc.connect();
    await wait(1200);
    const fatal = c.logs.filter((l) => l.startsWith('FATAL: relay '));
    assert.equal(fatal.length, 1, `the refusal is said once, not per attempt:\n${c.logs.join('\n')}`);
    assert.match(fatal[0], /refused claude-test-refused \(4003: Invalid token\)/);
    assert.match(fatal[0], /SYM_RELAY_TOKEN/, 'the line names what fixes it');
    assert.match(fatal[0], /Retrying every 0 min/, 'the line states the cadence it dropped to');
    assert.equal(c.refusals.length, 1, 'the host is told once per episode');
    assert.deepEqual(Object.keys(c.refusals[0]).sort(), ['code', 'name', 'reason', 'relayUrl']);
    // With the exponential backoff (1 s, 2 s, 4 s…) 1.2 s allows at most 2 attempts; the slow
    // cadence, set to 250 ms here, keeps knocking — and every knock is still refused.
    assert.ok(relay.state.attempts >= 3, `keeps retrying at the fixed cadence (attempts=${relay.state.attempts})`);
    const scheduled = c.logs.filter((l) => l.startsWith('Relay reconnecting in'));
    assert.ok(scheduled.every((l) => l === 'Relay reconnecting in 0s'), `no exponential growth: ${scheduled.join(' | ')}`);
  } finally { c.stop(); await relay.close(); }
});

test('a refusal episode ends on the next successful auth, so a later refusal is said again', async () => {
  // refuse, admit (relay-peers = successful auth), then refuse again
  const relay = fakeRelay((ws, n) => {
    if (n === 2) { ws.send(JSON.stringify({ type: 'relay-peers', peers: [] })); ws.close(1000, 'bye'); return; }
    ws.close(4003, 'Invalid token');
  });
  const c = client(relay.url, { authRefusedRetryMs: 100 });
  try {
    c.rc.connect();
    // attempt 1 refused (FATAL #1) → 100 ms → attempt 2 admitted, closed normally → backoff 1 s →
    // attempt 3 refused (FATAL #2)
    await wait(2500);
    assert.ok(relay.state.attempts >= 3, `attempts=${relay.state.attempts}`);
    assert.equal(c.logs.filter((l) => l.startsWith('FATAL: relay ')).length, 2);
    assert.equal(c.refusals.length, 2);
  } finally { c.stop(); await relay.close(); }
});

test('4001 (auth timeout) is transient: no FATAL, no callback, exponential backoff unchanged', async () => {
  const relay = fakeRelay((ws) => ws.close(4001, 'Auth timeout'));
  const c = client(relay.url, { authRefusedRetryMs: 100 });
  try {
    c.rc.connect();
    await wait(1500);
    assert.equal(c.logs.filter((l) => l.startsWith('FATAL:')).length, 0);
    assert.equal(c.refusals.length, 0);
    const scheduled = c.logs.filter((l) => l.startsWith('Relay reconnecting in'));
    assert.ok(scheduled.length >= 1 && scheduled[0] === 'Relay reconnecting in 1s', scheduled.join(' | '));
  } finally { c.stop(); await relay.close(); }
});
