'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * 0.13.16: peer-info gossip logged one line per entry and rewrote the wake-channel file on every
 * frame, and every peer re-sends its whole list on every connect, so the daemon's log reached 1 GB.
 * Only a channel that changed is set and saved, with one line per frame. (In 0.14.0 only the entry a
 * session's own node gives is learned — design D1 — and the relay's list is a hint: see
 * wake-channels.test.js.)
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');

describe('peer-info gossip is quiet when nothing changed', () => {
  // Core Secure (design D1): only the entry naming the session's own nodeId is learned; entries about
  // other nodes are hints, never stored. The 0.13.16 property still holds for what is learned: a
  // repeat logs nothing and writes nothing.
  it('a repeat of the same list logs nothing and writes nothing; a change logs one line', () => {
    const name = `pinfo-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    const lines = [];
    node._log = (m) => lines.push(m);
    let writes = 0;
    node._wakeManager.saveWakeChannels = () => { writes++; };
    try {
      const seen = Date.now();
      const frame = { type: 'peer-info', peers: [
        { nodeId: 'phone-1', name: 'unknown', wakeChannel: { platform: 'apns', token: 't1', environment: 'sandbox' }, lastSeen: seen },
        { nodeId: 'phone-2', name: 'unknown', wakeChannel: { platform: 'apns', token: 't2', environment: 'sandbox' }, lastSeen: seen },
      ] };
      node._frameHandler._handlePeerInfo('phone-1', 'phone-1', frame);
      assert.deepStrictEqual(lines.filter((l) => /[Ww]ake channel/.test(l)), ['Wake channel from phone-1: apns'], 'its own entry, said once');
      assert.strictEqual(writes, 1);
      assert.strictEqual(node._peerWakeChannels.has('phone-2'), false, 'what it says about another node is not stored');
      for (let i = 0; i < 50; i++) node._frameHandler._handlePeerInfo('phone-1', 'phone-1', frame);
      assert.strictEqual(lines.filter((l) => /[Ww]ake channel/.test(l)).length, 1, 'repeats are silent');
      assert.strictEqual(writes, 1, 'and write nothing');
      const big = { type: 'peer-info', peers: Array.from({ length: 1000 }, (_, i) => ({ nodeId: `n${i}`, wakeChannel: { platform: 'apns', token: `x${i}` }, lastSeen: Date.now() })) };
      node._frameHandler._handlePeerInfo('peer-x', 'peer-x', big);
      assert.strictEqual(node._peerWakeChannels.size, 1, 'a frame of 1,000 entries about others stores nothing');
    } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });
});

describe('0.13.16 review follow-ups', () => {
  const { WebSocketServer } = require('ws');
  const { RelayConnection } = require('../lib/relay');
  const { AttestationStore } = require('../lib/attestation-store');
  const os = require('os');
  const path = require('path');

  it('a changed channel for a peer already held is updated (F4) and an over-long frame is said (F5)', () => {
    const name = `pinfo2-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    const lines = [];
    node._log = (m) => lines.push(m);
    node._wakeManager.saveWakeChannels = () => {};
    try {
      const now = Date.now();
      const at = (token, lastSeen) => ({ type: 'peer-info', peers: [{ nodeId: 'phone-1', wakeChannel: { platform: 'apns', token, environment: 'sandbox' }, lastSeen }] });
      node._frameHandler._handlePeerInfo('phone-1', 'phone-1', at('t1', now - 1000));
      node._frameHandler._handlePeerInfo('phone-1', 'phone-1', at('t2', now));   // the phone's own newer channel
      assert.strictEqual(node._peerWakeChannels.get('phone-1').token, 't2');
      node._frameHandler._handlePeerInfo('p', 'p', { type: 'peer-info', peers: Array.from({ length: 300 }, (_, i) => ({ nodeId: `n${i}`, wakeChannel: { platform: 'apns', token: `x${i}` }, lastSeen: now })) });
      assert.ok(lines.some((l) => /300 entries, reading the first 256/.test(l)));
      node._frameHandler._handlePeerInfo('p', 'p', { type: 'peer-info', peers: Array.from({ length: 300 }, (_, i) => ({ nodeId: `n${i}` })) });
      assert.strictEqual(lines.filter((l) => /300 entries/.test(l)).length, 1, 'said once a minute per peer');
    } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  it('the relay\'s peer list is a hint: it sets, saves and logs no wake channel (F3, Core Secure D1)', async () => {
    const list = (token) => JSON.stringify({ type: 'relay-peers', peers: [{ nodeId: 'phone-1', name: 'phone', offline: true, wakeChannel: { platform: 'apns', token, environment: 'sandbox' } }] });
    const wss = new WebSocketServer({ port: 0 });
    let sent = 0;
    wss.on('connection', (ws) => ws.on('message', () => { ws.send(list('t1')); ws.send(list('t1')); ws.send(list('t2')); sent += 3; }));
    const logs = [];
    let running = true;
    const rc = new RelayConnection({
      relayUrl: `ws://127.0.0.1:${wss.address().port}`, relayToken: 'x'.repeat(40), log: (l) => logs.push(l),
      getIdentity: () => ({ nodeId: 'b'.repeat(64) }), isRunning: () => running, onAuthRefused: () => {}, nodeName: 'quiet-relay',
    });
    try {
      rc.connect();
      for (let i = 0; i < 100 && sent < 3; i++) await new Promise((r) => setTimeout(r, 20));
      await new Promise((r) => setTimeout(r, 100));
      assert.strictEqual(rc.state().phase, 'connected');
      assert.strictEqual(logs.filter((l) => /wake channel/i.test(l)).length, 0, 'nothing learned, nothing said');
      assert.ok(rc.present.has('phone-1') === false, 'an offline entry is not even a candidate');
    } finally { running = false; rc.destroy(); await new Promise((r) => wss.close(() => r())); }
  });

  it('an own witness the position cannot hold is still remembered after a restart (F2)', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'att-full-'));
    try {
      const st = new AttestationStore({ dir, selfId: 'me', maxWitnessesPerPosition: 1 });
      st.recordCheckpoint({ by: 'A', upto_seq: 1, root: 'r', sig: 'c' });
      st.recordWitness({ attester: 'A', upto_seq: 1, root: 'r', by: 'other', sig: 'o' });
      assert.strictEqual(st.recordWitness({ attester: 'A', upto_seq: 1, root: 'r', by: 'me', sig: 'mine' }).reason, 'position-full');
      const again = new AttestationStore({ dir, selfId: 'me', maxWitnessesPerPosition: 1 });
      assert.strictEqual(again.hasWitnessed('A', 1, 'me'), true);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('a dropped position takes its conflict mark, so held positions keep theirs (F6); own-witness memory is bounded in attesters (F7)', () => {
    const st = new AttestationStore({ maxCheckpointsPerAttester: 1, maxAttesters: 2, selfId: 'me' });
    st.recordCheckpoint({ by: 'A', upto_seq: 1, root: 'r', sig: 'c1' });
    st.recordCheckpoint({ by: 'A', upto_seq: 1, root: 'other', sig: 'x1' });
    assert.strictEqual(st.hasConflict('A', 1), true);
    st.recordCheckpoint({ by: 'A', upto_seq: 2, root: 'r2', sig: 'c2' }); // position 1 is dropped
    assert.strictEqual(st.hasConflict('A', 1), false, 'its mark went with it');
    for (const a of ['B', 'C', 'D']) st.recordWitness({ attester: a, upto_seq: 1, root: 'r', by: 'me', sig: a });
    assert.ok(st._ownWitnessed.size <= 2);
  });
});
