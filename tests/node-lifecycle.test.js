'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * R3-5, R3-9, R3-11 (0.14.3): the node lifecycle is one state machine on one promise chain.
 *
 * At 632b95d start() set `_running = true` before it awaited the store and the listener, and nothing
 * put a stop after the start it raced:
 *   - `start(); await stop()` returned with the TCP listener up, four timers set, the process held
 *     open, and the listener still taking handshakes (R3-5);
 *   - `stop(); start()` let the stop's tail run after the new start and drop its listener, which then
 *     nothing could close (discovery set `_server = null` after its await) (R3-9);
 *   - a start that threw left a half-started node that a second start() took for a running one, and
 *     a node stopped and started again ran without its identity lock and its inbox (R3-11).
 * XMesh calls start() and stop() without awaiting either, so every case here is un-awaited too.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const net = require('net');
const path = require('path');
const { SymNode } = require('../lib/node');
const { BonjourDiscovery, NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const { parseInvite } = require('../lib/invite');
const { connectNodes, until } = require('./_core-secure');

const uniq = (b) => `${b}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
const cats = (focus) => ({ focus, issue: 'i', intent: 'inform', motivation: 'm', commitment: 'c', perspective: 'p', mood: { text: 'calm' } });
const settle = (ms = 100) => new Promise((r) => setTimeout(r, ms));
const mk = (name, opts = {}) => new SymNode({ name: uniq(name), silent: true, discovery: new BonjourDiscovery({ mdns: false }), ...opts });
const timers = (n) => ['_heartbeatTimer', '_encodeTimer', '_statsTimer', '_purgeTimer'].filter((k) => n[k]);
/** Whether a TCP connect to 127.0.0.1:port is accepted. */
const accepts = (port) => new Promise((resolve) => {
  if (!port) { resolve(false); return; }
  const c = net.createConnection({ host: '127.0.0.1', port });
  c.once('connect', () => { c.destroy(); resolve(true); });
  c.once('error', () => resolve(false));
});
async function cleanup(...nodes) {
  for (const n of nodes) { try { await n.stop(); } catch { /* */ } }
  for (const n of nodes) { try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ } }
}

describe('node lifecycle: one state machine on one chain (R3-5, R3-9, R3-11)', () => {
  it('start() un-awaited, then await stop(): no listener, no timers, nothing taking handshakes (R3-5)', async () => {
    const n = mk('race-a');
    try {
      const p = n.start();
      await n.stop();
      await p;
      await settle();
      assert.strictEqual(n._running, false);
      assert.deepStrictEqual(timers(n), [], 'no timer survives the stop');
      const server = n._discovery._server;
      assert.ok(!(server && server.listening), 'the TCP listener is closed');
      assert.strictEqual(await accepts(n._port), false, 'the port takes no connection');
    } finally { await cleanup(n); }
  });

  it('stop(); start() un-awaited on a running node: it ends running, with the listener it started and its listeners; a final stop closes it (R3-9)', async () => {
    const n = mk('race-b');
    try {
      await n.start();
      const s = n.stop();
      const p = n.start();
      await s; await p; await settle();
      assert.strictEqual(n._running, true);
      assert.ok(n._discovery._server && n._discovery._server.listening, 'the discovery holds the listener the restart opened');
      assert.strictEqual(n._discovery.listenerCount('peer-found'), 1);
      assert.strictEqual(n._discovery.listenerCount('inbound-connection'), 1);
      const port = n._port;
      assert.strictEqual(await accepts(port), true);
      await n.stop();
      await settle();
      assert.strictEqual(await accepts(port), false, 'the final stop closed that listener');
      assert.deepStrictEqual(timers(n), []);
    } finally { await cleanup(n); }
  });

  it('start(); stop(); start(), none awaited: steps run in the order called and the node ends running', async () => {
    const n = mk('race-c');
    const servers = () => process.getActiveResourcesInfo().filter((r) => r === 'TCPServerWrap').length;
    const before = servers();
    try {
      const a = n.start(); const b = n.stop(); const c = n.start();
      await Promise.all([a, b, c]);
      await settle();
      assert.strictEqual(servers() - before, 1, 'exactly one listener exists: none started and lost');
      assert.strictEqual(n._running, true);
      assert.ok(n._discovery._server && n._discovery._server.listening, 'the discovery holds a listening server');
      assert.strictEqual(n._discovery.listenerCount('inbound-connection'), 1, 'one set of discovery listeners');
      assert.strictEqual(timers(n).length, 4);
      const port = n._port;
      assert.strictEqual(await accepts(port), true);
      assert.strictEqual(n.lifecycle, 'running');
      // A second start() while running, or while one is queued last, is that start.
      assert.strictEqual(n.start(), n.start());
      await n.stop();
      await settle();
      assert.strictEqual(await accepts(port), false, 'one stop closes it all');
      assert.strictEqual(servers() - before, 0, 'and no listener is left');
      assert.deepStrictEqual(timers(n), []);
    } finally { await cleanup(n); }
  });

  it('a start that fails undoes everything it set up, and a second start() starts again (R3-11)', async () => {
    let fail = true;
    class FailingOnce extends BonjourDiscovery {
      async start(identity, log) {
        const port = await super.start(identity, log); // the listener is up when it fails
        if (fail) { fail = false; throw Object.assign(new Error('injected discovery failure'), { code: 'EINJECTED' }); }
        return port;
      }
    }
    const disc = new FailingOnce({ mdns: false });
    const n = new SymNode({ name: uniq('fail-once'), silent: true, discovery: disc });
    const lock = path.join(nodeDirById(n.nodeId), 'lock.pid');
    try {
      await assert.rejects(n.start(), { code: 'EINJECTED' });
      assert.ok(!(disc._server && disc._server.listening), 'the listener the failed start opened is closed');
      assert.strictEqual(n._running, false);
      assert.deepStrictEqual(timers(n), []);
      assert.strictEqual(n.lifecycle, 'idle');
      assert.strictEqual(n.status().lastStartError.code, 'EINJECTED');
      assert.strictEqual(fs.existsSync(lock), false, 'the failed start gave the identity lock back');
      await n.start();
      assert.strictEqual(n.lifecycle, 'running', 'a second start() starts the node, it is not taken for a running one');
      assert.ok(disc._server && disc._server.listening);
      assert.strictEqual(fs.existsSync(lock), true, 'and holds the lock again');
    } finally { await cleanup(n); }
  });

  it('an un-awaited start that fails is no unhandled rejection', async () => {
    const seen = [];
    const onUnhandled = (e) => seen.push(e);
    process.on('unhandledRejection', onUnhandled);
    class Failing extends NullDiscovery { async start() { throw new Error('injected'); } }
    const n = new SymNode({ name: uniq('fail-quiet'), silent: true, discovery: new Failing() });
    try {
      n.start();
      await settle(200);
      assert.strictEqual(n.lifecycle, 'idle');
      assert.deepStrictEqual(seen, []);
    } finally { process.removeListener('unhandledRejection', onUnhandled); await cleanup(n); }
  });

  it('stop() not awaited does its synchronous part at once: a host that exits in the same turn keeps its inbox', async () => {
    const n = mk('sync-stop');
    try {
      await n.start();
      let wrote = 0;
      const write = n._writeInbox.bind(n);
      n._writeInbox = () => { wrote++; write(); };
      const p = n.stop(); // the daemon's SIGTERM handler calls stop() and process.exit() in one turn
      assert.deepStrictEqual(timers(n), [], 'the timers are cleared before stop() returns');
      assert.ok(wrote >= 1, 'and the inbox is written');
      await p;
    } finally { await cleanup(n); }
  });

  it('a relay setting ws cannot parse never fails the constructor or start(): the relay is disabled (R3-11, B1)', async () => {
    // R3-11 found a URL ws could not parse throwing from start(), after the node had half started. The
    // first fix threw EBADRELAY from the constructor instead, which stopped the daemon and mesh-channel
    // at startup for an https:// URL (B1). The relay is an optional transport: a setting that is not a
    // relay URL disables it, said in status(), and the node starts (tests/relay-url-setting.test.js).
    const n = new SymNode({ name: uniq('bad-url'), silent: true, relay: 'relay.example.com', relayToken: 'x'.repeat(40), discovery: new NullDiscovery() });
    try {
      await n.start();
      assert.strictEqual(n.status().running, true);
      assert.strictEqual(n.status().relayState.phase, 'disabled');
    } finally { await cleanup(n); }
    const https = new SymNode({ name: uniq('https-url'), silent: true, relay: 'https://relay.example.com', discovery: new NullDiscovery() });
    assert.strictEqual(https.status().relay, 'wss://relay.example.com', 'https:// is the same relay as wss://');
    await cleanup(https);
    const bad = parseInvite('sym://team/r?relay=relay.example.com&token=t');
    assert.ok(bad.error && /relay/.test(bad.error), `an invite naming a relay that is not a URL is refused (${bad.error})`);
    const good = parseInvite(`sym://team/r?relay=${encodeURIComponent('wss://relay.example.com')}&token=t`);
    assert.strictEqual(good.error, undefined);
    assert.strictEqual(good.relayUrl, 'wss://relay.example.com');
  });

  it('a node stopped and started again holds its identity lock and its inbox again (R3-11)', async () => {
    const a = new SymNode({ name: uniq('restart-a'), silent: true, discovery: new NullDiscovery(), room: 'r' });
    const b = new SymNode({ name: uniq('restart-b'), silent: true, discovery: new NullDiscovery(), room: 'r' });
    const lock = path.join(nodeDirById(a.nodeId), 'lock.pid');
    try {
      await a.start(); await b.start();
      await connectNodes(a, b);
      b.remember(cats('before the restart'), { to: a.nodeId });
      assert.ok(await until(() => a.inbox({ peek: true }).messages.length === 1, 5000), 'delivered before the restart');
      await a.stop();
      assert.strictEqual(fs.existsSync(lock), false, 'stop() gives the lock up');
      await a.start();
      assert.strictEqual(fs.existsSync(lock), true, 'the restart takes the lock again');
      await connectNodes(a, b);
      const ids = [];
      a.on('cmb-accepted', (e) => ids.push(e.inboxId));
      b.remember(cats('after the restart'), { to: a.nodeId });
      assert.ok(await until(() => ids.length === 1, 5000), 'delivered after the restart');
      assert.ok(typeof ids[0] === 'string' && ids[0], `the delivery got an inbox id (${ids[0]})`);
      assert.deepStrictEqual(a.inbox({ peek: true }).messages.map((m) => m.content.split(';')[0]), ['focus: before the restart', 'focus: after the restart']);
    } finally { await cleanup(a, b); }
  });
});
