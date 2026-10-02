'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * Design D2 over the relay, with a fake relay: the node with the smaller nodeId sends client-hello in
 * an envelope; a session is bound to the relay `from` it was made on and torn down on peer-left; a
 * new confirmed session supersedes the old (a restart under 4004); an unconfirmed hello never tears a
 * confirmed session down; frame loss re-handshakes; a forged sequence frame does not desynchronise;
 * the binding comes from the signed metadata.to; and a broadcast to 30 sessions stays under the
 * relay's 25 frames/s — fan-out when the relay advertises it, paced when it does not.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const crypto = require('crypto');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const { RelayConnection } = require('../lib/relay');
const { buildEncryptedFrame } = require('../lib/core/cmb-encrypted-frame');
const { fakeRelay } = require('./_fake-relay');
const { until, signedRecord, identity } = require('./_core-secure');

const uniq = (b) => `${b}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
const CATS = (focus) => ({ focus, issue: 'relay session test', intent: 'D2', motivation: 'm', commitment: 'c', perspective: 'p', mood: { text: 'calm', valence: 0, arousal: 0 } });
const TOKEN = 'x'.repeat(40);

function relayNode(base, relay, extra = {}) {
  return new SymNode({ name: uniq(base), silent: true, relayOnly: true, discovery: new NullDiscovery(), relay: relay.url, relayToken: TOKEN, room: 'relay-room', ...extra });
}
async function stopAll(...nodes) {
  for (const n of nodes) { try { await n.stop(); } catch { /* */ } try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ } }
}
const paired = (a, b) => a._peers.has(b.nodeId) && b._peers.has(a.nodeId);
const relaySession = (n, other) => n._peers.get(other.nodeId)?.transports.get('relay');

describe('relay sessions (D2)', () => {
  it('the smaller nodeId is the client; the session confirms over envelopes and records cross sealed', async () => {
    const seen = [];
    const relay = fakeRelay({ tap: (e) => { seen.push(e); } });
    const a = relayNode('rs-a', relay); const b = relayNode('rs-b', relay);
    try {
      await a.start(); await b.start();
      await until(() => paired(a, b), 8000);
      assert.ok(paired(a, b));
      const [lo] = [a, b].sort((x, y) => (x.nodeId < y.nodeId ? -1 : 1));
      const hello = seen.find((e) => e.payload.type === 'client-hello');
      assert.strictEqual(hello.from, lo.nodeId, 'the smaller nodeId sent client-hello');
      const got = [];
      b.on('verified-record', (e) => got.push(e));
      a.remember(CATS('over the relay, sealed'));
      await until(() => got.length > 0, 5000);
      assert.strictEqual(got[0].session.transport, 'relay');
      assert.ok(!JSON.stringify(seen).includes('over the relay, sealed'), 'the relay saw no category text');
      assert.ok(!seen.some((e) => e.payload.type === 'cmb' || e.payload.type === 'handshake'));
      assert.strictEqual(relaySession(b, a).relayFrom, a.nodeId, 'bound to the relay from it was made on');
    } finally { await stopAll(a, b); await relay.close(); }
  });

  it('a repeated announcement of a peer with a live relay session reuses it: no new handshake (A2)', async () => {
    const relay = fakeRelay();
    const a = relayNode('rs-a2', relay); const b = relayNode('rs-b2', relay);
    try {
      await a.start(); await b.start();
      await until(() => paired(a, b), 8000);
      const [lo, hi] = [a, b].sort((x, y) => (x.nodeId < y.nodeId ? -1 : 1));
      const before = relaySession(lo, hi);
      const confirmed = lo._sessionStats.confirmed;
      const ws = relay.conns.get(lo.nodeId).ws;
      for (let i = 0; i < 5; i++) ws.send(JSON.stringify({ type: 'relay-peer-joined', nodeId: hi.nodeId, name: hi.name }));
      ws.send(JSON.stringify({ type: 'relay-peers', peers: [{ nodeId: hi.nodeId, name: hi.name }] }));
      await new Promise((r) => setTimeout(r, 300));
      assert.strictEqual(relaySession(lo, hi), before, 'the same session carries the peer');
      assert.strictEqual(lo._sessionStats.confirmed, confirmed, 'no new handshake');
      assert.strictEqual(before.closed, false);
    } finally { await stopAll(a, b); await relay.close(); }
  });

  it('an error 1009 IDENTITY_CONFLICT from the peer ends the session, is said, and is not retried (draft spec PR #21); a clear one is ignored', async () => {
    const relay = fakeRelay();
    const a = relayNode('rs-a3', relay); const b = relayNode('rs-b3', relay);
    try {
      await a.start(); await b.start();
      await until(() => paired(a, b), 8000);
      const [lo, hi] = [a, b].sort((x, y) => (x.nodeId < y.nodeId ? -1 : 1));
      const metrics = [];
      lo.on('metric', (m) => metrics.push(m));
      // A CLEAR error is anyone's to write (security review F): ignored, the session stays.
      const before = relaySession(lo, hi);
      relay.inject(hi.nodeId, lo.nodeId, { type: 'error', code: 1009, message: 'IDENTITY_CONFLICT', detail: `session:${before.sessionId}` });
      relay.inject(hi.nodeId, lo.nodeId, { type: 'error', code: 1010, message: 'session closed' });
      await new Promise((r) => setTimeout(r, 300));
      assert.strictEqual(relaySession(lo, hi), before, 'a clear error is not a command');
      assert.strictEqual(before.closed, false);
      // The peer's own 1009 travels sealed on the session.
      assert.strictEqual(relaySession(hi, lo).trySend({ type: 'error', code: 1009, message: 'IDENTITY_CONFLICT' }).ok, true);
      await until(() => !lo._peers.has(hi.nodeId), 3000);
      await new Promise((r) => setTimeout(r, 1500)); // past the first retry backoff
      assert.strictEqual(lo._peers.has(hi.nodeId), false, 'no re-handshake after an identity conflict');
      assert.ok(metrics.some((m) => m.type === 'identity-conflict-refused-by-peer'));
    } finally { await stopAll(a, b); await relay.close(); }
  });

  it('frame loss leads to a re-handshake, and records flow again', async () => {
    let dropOne = false;
    const relay = fakeRelay({ tap: (e) => { if (dropOne && e.payload.type === 'control-encrypted') { dropOne = false; return false; } return undefined; } });
    const a = relayNode('rs-a', relay); const b = relayNode('rs-b', relay);
    try {
      await a.start(); await b.start();
      await until(() => paired(a, b), 8000);
      const first = relaySession(b, a).sessionId;
      dropOne = true;
      a.broadcastMood('lost on the way');           // sealed control frame: dropped by the relay
      a.broadcastMood('arrives after a gap');        // the gap: the receiver closes, the client re-handshakes
      await until(() => relaySession(b, a) && relaySession(b, a).sessionId !== first && relaySession(a, b)?.sessionId === relaySession(b, a)?.sessionId, 10000);
      assert.notStrictEqual(relaySession(b, a).sessionId, first, 'a new session');
      assert.ok(b._sessionStats.desync >= 1 || a._sessionStats.failedByReason['peer-closed'] >= 0);
      const got = [];
      b.on('verified-record', (e) => got.push(e));
      a.remember(CATS('after the re-handshake'));
      await until(() => got.length > 0, 5000);
      assert.strictEqual(got.length, 1);
    } finally { await stopAll(a, b); await relay.close(); }
  });

  it('a forged frame with the next sequence does not desynchronise the session', async () => {
    const relay = fakeRelay();
    const a = relayNode('rs-a', relay); const b = relayNode('rs-b', relay);
    try {
      await a.start(); await b.start();
      await until(() => paired(a, b), 8000);
      const sb = relaySession(b, a);
      const sessionId = sb.sessionId;
      const direction = sb.role === 'client' ? 'server-to-client' : 'client-to-server';
      const forged = buildEncryptedFrame({ cmb: signedRecord(identity('x'), { room: 'relay-room' }), sessionId, direction, sequence: sb._mmp.nextRecv, trafficKey: crypto.randomBytes(32) });
      relay.inject(a.nodeId, b.nodeId, forged);
      await until(() => b._sessionStats.refusedByReason['record did not authenticate'] >= 1, 3000);
      assert.strictEqual(relaySession(b, a).sessionId, sessionId, 'the same session, not torn down');
      const got = [];
      b.on('verified-record', (e) => got.push(e));
      a.remember(CATS('genuine after a forged one'));
      await until(() => got.length > 0, 5000);
      assert.strictEqual(got.length, 1, 'the genuine frame at that sequence still opens');
    } finally { await stopAll(a, b); await relay.close(); }
  });

  it('a peer restart under 4004 supersedes the old session; an unconfirmed hello never tears the confirmed one down', async () => {
    const relay = fakeRelay();
    const a = relayNode('rs-a', relay);
    const bName = uniq('rs-b');
    let b = new SymNode({ name: bName, silent: true, relayOnly: true, discovery: new NullDiscovery(), relay: relay.url, relayToken: TOKEN, room: 'relay-room' });
    try {
      await a.start(); await b.start();
      await until(() => paired(a, b), 8000);
      const old = relaySession(a, b);
      // An unconfirmed hello under b's id (an injector): the confirmed session stays.
      const { clientHello } = require('../lib/core/handshake-v2-flow');
      const imp = identity('imp');
      const { frame } = clientHello({ room: 'relay-room', nodeId: b.nodeId, name: 'imp', identityPublicKey: imp.publicKey, e2ePublicKey: crypto.randomBytes(32).toString('base64url'), implementation: { name: 'x', version: '1' }, extensions: ['cmb-encrypted-v2'] });
      if (b.nodeId < a.nodeId) relay.inject(b.nodeId, a.nodeId, frame);
      await new Promise((r) => setTimeout(r, 200));
      assert.strictEqual(relaySession(a, b), old, 'still the confirmed session');
      assert.strictEqual(old.closed, false);
      // b restarts with the same identity: the relay replaces its connection (4004, no peer-left).
      const left = [];
      a.on('peer-left', (x) => left.push(x));
      const bId = b.nodeId;
      b._relay._identityCollision = true; // the old process stops reconnecting, as a replaced one would
      const b2 = new SymNode({ name: `${bName}-restarted`, nodeId: bId, silent: true, relayOnly: true, discovery: new NullDiscovery(), relay: relay.url, relayToken: TOKEN, room: 'relay-room', create: false });
      await b2.start();
      await until(() => relaySession(a, b2) && relaySession(a, b2) !== old, 10000);
      assert.notStrictEqual(relaySession(a, b2), old, 'a new confirmed session for the same (nodeId, key)');
      assert.strictEqual(old.closed, true);
      assert.deepStrictEqual(left, [], 'superseded, not left');
      await b.stop().catch(() => {});
      b = b2;
    } finally { await stopAll(a, b); await relay.close(); }
  });

  it('a session ends on relay-peer-left', async () => {
    const relay = fakeRelay();
    const a = relayNode('rs-a', relay); const b = relayNode('rs-b', relay);
    try {
      await a.start(); await b.start();
      await until(() => paired(a, b), 8000);
      const left = [];
      a.on('peer-left', (x) => left.push(x));
      relay.kick(b.nodeId);
      await until(() => left.length > 0, 5000);
      assert.strictEqual(a._peers.has(b.nodeId), false);
    } finally { await stopAll(a, b); await relay.close(); }
  });

  it('the binding is taken from metadata.to, never the envelope: a record signed to another node is refused', async () => {
    const relay = fakeRelay();
    const a = relayNode('rs-a', relay); const b = relayNode('rs-b', relay);
    try {
      await a.start(); await b.start();
      await until(() => paired(a, b), 8000);
      const metrics = [];
      b.on('metric', (m) => metrics.push(m));
      const someone = identity('someone');
      const cmb = signedRecord({ nodeId: a.nodeId, name: a.name, privateKey: a._identity.privateKey }, { room: 'relay-room', to: someone.nodeId, categories: { focus: 'for someone else' } });
      const s = relaySession(a, b);
      // The seal point refuses it (security review A) ...
      assert.strictEqual(s.trySend({ type: 'cmb', cmb }).reason, 'not-addressed');
      // ... and a sender that seals it anyway, in an envelope addressed to b, is refused by b.
      const { signedProjection } = require('../lib/core/record-canonical');
      const rec = signedProjection(cmb);
      const pos = s._mmp.nextSend();
      s._wire(buildEncryptedFrame({ cmb: { categories: rec.categories, metadata: { ...rec.metadata } }, applicationBytes: null, sessionId: s.sessionId, direction: pos.direction, sequence: pos.sequence, trafficKey: pos.trafficKey }));
      await until(() => metrics.some((m) => m.type === 'cmb-audience-rejected'), 5000);
      assert.ok(metrics.some((m) => m.type === 'cmb-audience-rejected'));
    } finally { await stopAll(a, b); await relay.close(); }
  });
});

describe('the relay limit with 30 sessions (D4)', () => {
  /** A RelayConnection on a fake relay, with `n` present peers to address. */
  async function oneConnection(relay, { rate } = {}) {
    const id = identity('sender');
    const conn = new RelayConnection({
      relayUrl: relay.url, relayToken: TOKEN, log: () => {}, getIdentity: () => id, getRoom: () => 'relay-room',
      isRunning: () => true, nodeName: 'sender', rate,
    });
    conn.connect();
    await until(() => conn.state().phase === 'connected', 5000);
    return conn;
  }

  it('paced: 30 recipients x 20 broadcasts stay under the relay\'s token bucket (no 4008)', async () => {
    // The fake relay enforces the 0.5 bucket scaled 10x faster (250/s, burst 300) so the test is short;
    // the client paces at 10x its default (200/s, burst 200): the same ratio as production (20 vs 25).
    const relay = fakeRelay({ ratePerSec: 250, burst: 300 });
    const conn = await oneConnection(relay, { rate: { perSecond: 200, burst: 200 } });
    try {
      const recipients = Array.from({ length: 30 }, () => identity('r').nodeId);
      for (let i = 0; i < 20; i++) for (const to of recipients) assert.strictEqual(conn.sendTo(to, { type: 'control-encrypted', i }).ok, true);
      await until(() => conn.state().queued === 0, 15000);
      // The relay reads them a turn or more later: wait until it has them all (or refused one).
      await until(() => relay.stats.framesIn >= 600 || relay.stats.rateLimited > 0, 5000);
      assert.strictEqual(relay.stats.rateLimited, 0, 'never over the relay\'s limit');
      assert.strictEqual(conn.state().phase, 'connected');
      assert.ok(conn.state().sentFrames >= 600);
    } finally { conn.destroy(); await relay.close(); }
  });

  it('fan-out when the relay lists it in relay-peers.features: one frame for many recipients', async () => {
    const relay = fakeRelay({ fanout: true });
    const conn = await oneConnection(relay);
    try {
      assert.deepStrictEqual(conn.state().fanout, { max: 64 }, 'the draft\'s floor; an unknown token beside it is ignored');
      const recipients = Array.from({ length: 30 }, () => identity('r').nodeId);
      for (const to of recipients) conn.sendTo(to, { type: 'control-encrypted' });
      await until(() => conn.state().queued === 0, 5000);
      await until(() => relay.stats.fanoutIn >= 1, 2000); // the relay reads it a turn later
      assert.strictEqual(relay.stats.fanoutIn, 1, 'thirty sealed frames, one relay frame');
      assert.strictEqual(relay.stats.rateLimited, 0);
    } finally { conn.destroy(); await relay.close(); }
  });

  it('a fan-out never names a recipient twice, and each recipient gets its frames in order', async () => {
    const relay = fakeRelay({ fanout: true });
    const conn = await oneConnection(relay);
    const ids = Array.from({ length: 30 }, () => identity('r'));
    const got = new Map();
    const { WebSocket } = require('ws');
    const sockets = [];
    try {
      for (const r of ids) {
        const ws = new WebSocket(relay.url);
        sockets.push(ws);
        await new Promise((res) => ws.once('open', res));
        ws.send(JSON.stringify({ type: 'relay-auth', nodeId: r.nodeId, name: 'r', token: TOKEN }));
        ws.on('message', (d) => { const m = JSON.parse(String(d)); if (m.payload) { if (!got.has(r.nodeId)) got.set(r.nodeId, []); got.get(r.nodeId).push(m.payload.i); } });
      }
      await until(() => relay.conns.size === 31, 3000);
      // Three broadcasts in one turn: the queue holds each recipient three times.
      for (let i = 0; i < 3; i++) for (const r of ids) conn.sendTo(r.nodeId, { type: 'control-encrypted', i });
      await until(() => [...got.values()].reduce((n, v) => n + v.length, 0) === 90, 5000);
      assert.strictEqual(relay.stats.fanoutRefused, 0, 'no fan-out was malformed');
      assert.strictEqual(relay.stats.fanoutIn, 3, 'one envelope per broadcast');
      for (const r of ids) assert.deepStrictEqual(got.get(r.nodeId), [0, 1, 2], 'per-recipient order');
    } finally { for (const ws of sockets) ws.terminate(); conn.destroy(); await relay.close(); }
  });

  it('a node broadcasting to 30 relay sessions stays under the limit (fan-out on, and off)', async () => {
    for (const fanout of [true, false]) {
      const relay = fakeRelay({ fanout });
      const sender = relayNode('rs-sender', relay);
      const peers = Array.from({ length: 30 }, (_, i) => relayNode(`rs-p${i}`, relay));
      try {
        await sender.start();
        for (const p of peers) await p.start();
        await until(() => peers.every((p) => sender._peers.has(p.nodeId)), 30000);
        assert.strictEqual(sender._peers.size, 30, `fanout ${fanout}: 30 sessions`);
        for (let i = 0; i < 3; i++) sender.remember(CATS(`broadcast ${i} fanout ${fanout}`));
        await until(() => sender._relay.state().queued === 0, 20000);
        assert.strictEqual(relay.stats.rateLimited, 0, `fanout ${fanout}: no 4008`);
        if (fanout) assert.ok(relay.stats.fanoutIn >= 1);
      } finally { await stopAll(sender, ...peers); await relay.close(); }
    }
  });
});
