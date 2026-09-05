'use strict';
/**
 * The relay-auth frame carries the engine version. Without it, "which engines ever traversed
 * path X through the relay" is unanswerable after the fact (2026-09-05, the plaintext-fallback
 * question). One field, no payload, no confidentiality cost.
 */
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { WebSocketServer } = require('ws');
const { RelayConnection } = require('../lib/relay');
const { version } = require('../package.json');

test('relay-auth names the engine version beside the identity, and never more than that', async () => {
  const wss = new WebSocketServer({ port: 0 });
  const seen = [];
  wss.on('connection', (ws) => ws.on('message', (m) => { seen.push(JSON.parse(String(m))); ws.close(4003, 'done'); }));
  const url = `ws://127.0.0.1:${wss.address().port}`;
  let running = true;
  const rc = new RelayConnection({
    relayUrl: url, relayToken: 'x'.repeat(32), log: () => {}, getIdentity: () => ({ nodeId: 'b'.repeat(64) }),
    isRunning: () => running, getPeers: () => new Map(), getMeshNode: () => null, createPeer: () => {}, addPeer: () => {},
    handlePeerMessage: () => {}, onPeerLeft: () => {}, onAuthRefused: () => {}, nodeName: 'engine-version-test',
    peerWakeChannels: new Map(), saveWakeChannels: () => {}, authRefusedRetryMs: 60000,
  });
  rc.connect();
  for (let i = 0; i < 40 && seen.length === 0; i++) await new Promise((r) => setTimeout(r, 50));
  running = false; rc.destroy(); await new Promise((r) => wss.close(() => r()));
  assert.equal(seen.length, 1);
  const auth = seen[0];
  assert.equal(auth.type, 'relay-auth');
  assert.equal(auth.engine, version);
  assert.deepEqual(Object.keys(auth).sort(), ['engine', 'name', 'nodeId', 'token', 'type']);   // no IP, no keys, nothing else
});
