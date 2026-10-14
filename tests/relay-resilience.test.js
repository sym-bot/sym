'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * The relay client's own failure modes (R3, 0.14.3):
 *   R3-1/R3-2 — the per-message bound was the connection's ws maxPayload, so ONE oversized message
 *               (a re-serialised payload, a roster padded with long names) closed the whole shared
 *               connection, again on every reconnect. Now it is dropped on its own and counted;
 *   R3-10     — the backoff started over when the socket opened, not when the relay took the auth,
 *               so a relay that closed after the open (1013, 4008, 1009) was dialled every second;
 *   R3-3      — 4004 and 4006 stopped the client for good, so any token holder could switch a member
 *               off by claiming its nodeId once. Now a loud retry on a long backoff with a ping-pong
 *               detector (`identityRetry: false` keeps MMP §4.4.7 as written);
 *   R3-15     — the liveness timeout closed politely (ws.close), which waits for a closing handshake a
 *               dead connection never sends; it terminates now;
 *   R3-13     — stop() destroyed the relay before it closed the sessions, so a relay peer was never
 *               sent the sealed 1010 SESSION_CLOSED the session promises; it is now.
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const { WebSocketServer } = require('ws');
const { RelayConnection, IDENTITY_CLOSES } = require('../lib/relay');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const { fakeRelay: meshRelay } = require('./_fake-relay');
const { until } = require('./_core-secure');

const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const ID = '01900000-0000-7000-8000-0000000000b1';
const PEER = '01900000-0000-7000-8000-0000000000c2';

/** A relay that runs `answer(ws, n, msg)` for the n-th auth it receives; records each dial's time. */
function relayAnswering(answer) {
  const wss = new WebSocketServer({ port: 0 });
  const dials = [];
  let auths = 0;
  wss.on('connection', (ws) => {
    dials.push(Date.now());
    ws.on('message', (d) => {
      let m; try { m = JSON.parse(String(d)); } catch { return; }
      if (m.type === 'relay-auth') answer(ws, ++auths, m);
    });
  });
  return { url: `ws://127.0.0.1:${wss.address().port}`, dials, auths: () => auths, close: () => new Promise((r) => { for (const c of wss.clients) c.terminate(); wss.close(() => r()); }) };
}

function client(url, opts = {}) {
  const logs = [];
  let running = true;
  const rc = new RelayConnection({
    relayUrl: url,
    relayToken: 'x'.repeat(40),
    log: (line) => logs.push(line),
    getIdentity: () => ({ nodeId: ID }),
    isRunning: () => running,
    nodeName: 'resilience-test',
    ...opts,
  });
  return { rc, logs, stop: () => { running = false; rc.destroy(); } };
}

const peersFrame = (peers = []) => JSON.stringify({ type: 'relay-peers', peers });

test('R3-1: a message over the frame bound is dropped on its own; the connection stays up and the next message is taken', async () => {
  const relay = relayAnswering((ws) => {
    ws.send(peersFrame());
    setTimeout(() => {
      // An envelope the relay grew past the bound (sym-relay before 0.6.1 re-serialised payloads).
      ws.send(JSON.stringify({ from: PEER, fromName: 'p', payload: { type: 'cmb-encrypted', pad: 'x'.repeat(1024 * 1024 + 8192) } }));
      ws.send(JSON.stringify({ type: 'relay-peer-joined', nodeId: PEER, name: 'after-the-big-one' }));
    }, 50);
  });
  const c = client(relay.url);
  try {
    c.rc.connect();
    assert.ok(await until(() => c.rc.present.has(PEER), 4000), 'the message after the oversized one was taken');
    const s = c.rc.state();
    assert.equal(s.phase, 'connected');
    assert.equal(s.lastClose, null, 'the connection was never closed');
    assert.equal(s.oversizeDropped, 1, 'the oversized message was dropped and counted');
    assert.equal(relay.dials.length, 1, 'no reconnect');
  } finally { c.stop(); await relay.close(); }
});

test('R3-2: a roster over the frame bound (long names) is still read; the node learns its room', async () => {
  const long = 'n'.repeat(600 * 1024);
  const relay = relayAnswering((ws) => ws.send(peersFrame([{ nodeId: PEER, name: long }, { nodeId: '01900000-0000-7000-8000-0000000000c3', name: long }])));
  const c = client(relay.url);
  try {
    c.rc.connect();
    await c.rc.awaitOutcome(5000);
    await wait(50);
    const s = c.rc.state();
    assert.equal(s.phase, 'connected');
    assert.equal(s.peers, 2);
    assert.equal(s.lastClose, null);
  } finally { c.stop(); await relay.close(); }
});

test('R3-10: a relay that takes the socket and then closes (1013) is redialled on a growing backoff, not every second', async () => {
  const relay = relayAnswering((ws) => ws.close(1013, 'Try Again Later'));
  const c = client(relay.url);
  try {
    c.rc.connect();
    await wait(7600);
    const gaps = relay.dials.slice(1).map((t, i) => t - relay.dials[i]);
    assert.ok(relay.dials.length <= 4, `at most 4 dials in 7.6 s (1 s, 2 s, 4 s): ${relay.dials.length}, gaps ${gaps.join(', ')} ms`);
    assert.ok(gaps.length >= 2 && gaps[1] >= 1800, `the second gap doubled (${gaps.join(', ')} ms)`);
  } finally { c.stop(); await relay.close(); }
});

for (const code of [4004, 4006]) {
  test(`R3-3: an identity close (${code}) is retried on the long backoff, said loudly; the member comes back once the claimant has gone`, async () => {
    const relay = relayAnswering((ws, n) => { if (n === 1) ws.close(code, 'claimed'); else ws.send(peersFrame()); });
    const told = [];
    const c = client(relay.url, { identityRetryMs: 300, onIdentityCollision: (i) => told.push(i) });
    try {
      c.rc.connect();
      assert.ok(await until(() => c.rc.state().phase === (code === 4004 ? 'collision' : 'duplicate-rejected'), 3000));
      const s = c.rc.state();
      assert.ok(s.nextRetryAt > Date.now(), 'a retry is scheduled: no permanent stop');
      assert.equal(s.stopped.code, code);
      assert.match(c.rc.describe(), /^IDENTITY CLOSE: .*Retrying in \d+s\.$/);
      assert.ok(c.logs.some((l) => /^IDENTITY CLOSE: /.test(l)), 'said loudly');
      assert.ok(await until(() => c.rc.state().phase === 'connected', 5000), 'back on the relay after the retry');
      assert.equal(relay.dials.length, 2);
      assert.equal(told.length, 1);
      assert.equal(told[0].code, code);
      assert.equal(told[0].pingPong, false, 'one close is no ping-pong');
    } finally { c.stop(); await relay.close(); }
  });
}

test('R3-3: two processes replacing each other are detected as a ping-pong, told to the host, and retried only at the longest backoff', async () => {
  // Every auth is taken and then replaced (4004) shortly after: what a second live process does.
  const relay = relayAnswering((ws) => { ws.send(peersFrame()); setTimeout(() => ws.close(4004, 'Replaced by new connection'), 30); });
  const told = [];
  const c = client(relay.url, { identityRetryMs: 100, onIdentityCollision: (i) => told.push(i) });
  try {
    c.rc.connect();
    assert.ok(await until(() => c.rc.state().stopped && c.rc.state().stopped.pingPong, 5000), 'the ping-pong is detected');
    const s = c.rc.state();
    assert.equal(s.stopped.closes, 3);
    assert.ok(s.nextRetryAt - Date.now() > 29 * 60_000, `retried only at the longest backoff (${Math.round((s.nextRetryAt - Date.now()) / 1000)} s)`);
    assert.match(c.rc.describe(), /^PING-PONG: .*Stop one of them\. Retrying in \d+s\.$/);
    assert.ok(told.some((t) => t.pingPong === true), 'the host is told it is a ping-pong');
    assert.ok(c.logs.some((l) => /PING-PONG/.test(l)));
    const dials = relay.dials.length;
    await wait(500);
    assert.equal(relay.dials.length, dials, 'and not dialled again meanwhile');
    // At the longest backoff a real ping-pong's closes are an hour apart, past the window that found
    // it: it holds anyway, until a connection outlasts the clear time.
    c.rc._identityCloses = [];
    c.rc._identityClosed(4004, IDENTITY_CLOSES[4004], 'Replaced by new connection');
    assert.equal(c.rc.state().stopped.pingPong, true, 'still a ping-pong an hour later');
    assert.ok(c.rc.state().nextRetryAt - Date.now() > 29 * 60_000);
  } finally { c.stop(); await relay.close(); }
});

test('R3-3: identityRetry: false keeps MMP §4.4.7 as written (no reconnect after an identity close)', async () => {
  const relay = relayAnswering((ws) => ws.close(4004, 'claimed'));
  const c = client(relay.url, { identityRetry: false, identityRetryMs: 100 });
  try {
    c.rc.connect();
    assert.ok(await until(() => c.rc.state().phase === 'collision', 3000));
    await wait(600);
    assert.equal(relay.dials.length, 1);
    assert.equal(c.rc.state().nextRetryAt, null);
    assert.match(c.rc.describe(), /Not reconnecting \(identityRetry is off\)/);
  } finally { c.stop(); await relay.close(); }
});

test('R3-15: the liveness timeout terminates the connection (a dead one never answers a polite close)', async () => {
  const relay = relayAnswering((ws) => ws.send(peersFrame()));
  const c = client(relay.url);
  try {
    c.rc.connect();
    await c.rc.awaitOutcome(5000);
    const ws = c.rc.ws;
    const calls = [];
    ws.close = () => calls.push('close');
    const terminate = ws.terminate.bind(ws);
    ws.terminate = () => { calls.push('terminate'); terminate(); };
    c.rc._lastRelayMessage = Date.now() - 61_000; // a minute without a word from the relay
    c.rc._relayPingTimer._onTimeout();             // the keepalive tick
    assert.deepEqual(calls, ['terminate']);
    assert.ok(await until(() => c.rc.state().phase === 'reconnecting', 3000), 'and the close follows at once');
  } finally { c.stop(); await relay.close(); }
});

test('R3-13: records still queued for a relay peer at stop go before the 1010, so the notice is no sequence gap', async () => {
  const relay = meshRelay();
  const mk = (name) => new SymNode({ name: `${name}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`, silent: true, relayOnly: true, discovery: new NullDiscovery(), relay: relay.url, relayToken: 'x'.repeat(40), room: 'r13q' });
  const a = mk('stopq-a'); const b = mk('stopq-b');
  const blog = [];
  b._log = (m) => blog.push(m);
  const got = [];
  b.on('cmb-accepted', (e) => got.push(e));
  try {
    await a.start(); await b.start();
    assert.ok(await until(() => a._peers.has(b.nodeId) && b._peers.has(a.nodeId), 20000));
    await wait(1500); // the pacer's bucket refills
    const cats = (focus) => ({ focus, issue: 'i', intent: 'inform', motivation: 'm', commitment: 'c', perspective: 'p', mood: { text: 'calm' } });
    for (let i = 0; i < 5; i++) a.remember(cats(`queued at stop ${i}`), { to: b.nodeId });
    await a.stop(); // in the same turn: the five are still in a's pacer
    assert.ok(await until(() => blog.some((l) => /^Peer disconnected: /.test(l)), 5000));
    const line = blog.find((l) => /^Peer disconnected: /.test(l));
    assert.match(line, /last: peer-closed\)$/, `b closed on a's notice, not on a gap (${line})`);
    assert.ok(await until(() => got.length === 5, 3000), `and b received the five sent before it (${got.length})`);
  } finally {
    for (const n of [a, b]) { try { await n.stop(); } catch { /* */ } }
    await relay.close();
    for (const n of [a, b]) { try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ } }
  }
});

test('R3-13: a stopped node tells each relay peer its session closed (sealed 1010) before the relay goes', async () => {
  const relay = meshRelay();
  const mk = (name) => new SymNode({ name: `${name}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`, silent: true, relayOnly: true, discovery: new NullDiscovery(), relay: relay.url, relayToken: 'x'.repeat(40), room: 'r13' });
  const a = mk('stop-a'); const b = mk('stop-b');
  const blog = [];
  b._log = (m) => blog.push(m);
  try {
    await a.start(); await b.start();
    assert.ok(await until(() => a._peers.has(b.nodeId) && b._peers.has(a.nodeId), 20000));
    await a.stop();
    assert.ok(await until(() => blog.some((l) => /^Peer disconnected: /.test(l)), 5000));
    const line = blog.find((l) => /^Peer disconnected: /.test(l));
    assert.match(line, /last: peer-closed\)$/, `b heard the session close from a itself, not from the relay (${line})`);
  } finally {
    for (const n of [a, b]) { try { await n.stop(); } catch { /* */ } }
    await relay.close();
    for (const n of [a, b]) { try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ } }
  }
});
