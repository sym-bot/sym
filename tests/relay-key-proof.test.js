'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * RELAY-AUTH KEY PROOF, the client (core/relay-auth-proof.js; sym-relay 0.8.0 verifies it).
 *
 * Until now a relay keyed this node's slot by a nodeId it only claimed, so any holder of the channel
 * token could claim it and have this node closed (4004) or refused (4006), and a 0.14.3 candidate's
 * answer was to retry those closes with a ping-pong detector: a patch over an identity nobody
 * verified, removed here. These pin the client's half of the design:
 *
 *   - it asks for a challenge (`keyProof`) and signs it with its identity key, over the nonce, the
 *     room, the nodeId and the origin of the URL IT dialed; the vector is shared with sym-relay;
 *   - a relay that never challenges (sym-relay before 0.8.0) takes the first frame as it always did;
 *     the node connects at once and records relayVerifiesKeys: false, said once;
 *   - 4004 and 4006 stop it for good (MMP §4.4.7), said with their cause: on a connection whose key
 *     the relay verified, another process proved this identity's key; otherwise the relay does not
 *     verify keys and any token holder could have done it. The event is { nodeId, name, code, kind,
 *     reason, relayVerifiesKeys };
 *   - directed frames name `toKey` when the relay understands it and lists a slot proven for the key
 *     this node binds to the recipient; roster entries for that key are the peer, an impostor's key
 *     is never a candidate, and its departure ends nothing.
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const { RelayConnection } = require('../lib/relay');
const proof = require('../lib/core/relay-auth-proof');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { identity, until } = require('./_core-secure');

const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const TOKEN = 'p'.repeat(40);

/**
 * A relay for these tests. `verifies`: it answers keyProof with a relay-challenge and checks the
 * proof as sym-relay 0.8.0 does (the origin it was dialled at), listing `key-proof`; otherwise it is a
 * relay before 0.8.0 and takes the first relay-auth. `after(ws, auth, n)` runs once the n-th
 * connection is admitted. Every frame received is kept.
 */
function relay({ verifies = true, after = null, peers = [] } = {}) {
  const wss = new WebSocketServer({ port: 0, host: '127.0.0.1' });
  const port = () => wss.address().port;
  const st = { dials: 0, frames: [], proofs: [], admitted: 0, refused: 0, sockets: [] };
  wss.on('connection', (ws) => {
    st.dials++;
    st.sockets.push(ws);
    let nonce = null; let admitted = false;
    ws.on('message', (d) => {
      const m = JSON.parse(String(d));
      st.frames.push(m);
      if (m.type !== 'relay-auth' || admitted) return;
      if (verifies && m.keyProof === proof.KEY_PROOF && !m.proof) {
        nonce = crypto.randomBytes(32);
        ws.send(JSON.stringify({ type: 'relay-challenge', keyProof: proof.KEY_PROOF, nonce: nonce.toString('base64url') }));
        return;
      }
      if (verifies && m.proof) {
        const origin = `ws://127.0.0.1:${port()}`;
        const ok = !!nonce && proof.verifyProof({ nonce, room: m.room || 'default', nodeId: m.nodeId, origin }, m.publicKey, m.proof);
        st.proofs.push({ ok, origin, publicKey: m.publicKey });
        if (!ok) { st.refused++; ws.close(4002, 'Invalid key proof'); return; }
      }
      admitted = true;
      st.admitted++;
      ws.send(JSON.stringify({ type: 'relay-peers', peers, ...(verifies ? { features: ['fanout', 'key-proof'] } : { features: ['fanout'] }) }));
      if (after) after(ws, m, st.admitted);
    });
  });
  return {
    st, ready: new Promise((r) => wss.once('listening', r)),
    url: () => `ws://127.0.0.1:${port()}`,
    close: () => new Promise((r) => { for (const c of wss.clients) c.terminate(); wss.close(() => r()); }),
  };
}

function client(url, id, opts = {}) {
  const logs = [];
  const told = [];
  const present = [];
  const gone = [];
  let running = true;
  const rc = new RelayConnection({
    relayUrl: url,
    relayToken: TOKEN,
    log: (line) => logs.push(line),
    getIdentity: () => id,
    isRunning: () => running,
    nodeName: 'proof-test',
    onIdentityCollision: (info) => told.push(info),
    onPeerPresent: (nodeId, name) => present.push({ nodeId, name }),
    onPeerGone: (nodeId, name) => gone.push({ nodeId, name }),
    ...opts,
  });
  return { rc, logs, told, present, gone, stop: () => { running = false; rc.destroy(); } };
}

test('the shared vector: the transcript and the proof are what sym-relay verifies (tests/relay-auth-proof-v1.json)', () => {
  const file = path.join(__dirname, 'relay-auth-proof-v1.json');
  const raw = fs.readFileSync(file);
  // The same bytes as sym-relay's test/fixtures/relay-auth-proof-v1.json.
  assert.equal(crypto.createHash('sha256').update(raw).digest('hex'), '2da01ece220d02114b45c21e465176dd3f2069d96fb70b30aec1d592d726c1d5');
  const v = JSON.parse(raw);
  const nonce = Buffer.from(v.nonce, 'base64url');
  const priv = Buffer.from(v.seedHex, 'hex').toString('base64url');
  for (const c of v.cases) {
    assert.equal(proof.originOf(c.dialed), c.origin);
    assert.equal(proof.transcript({ nonce, room: c.room, nodeId: c.nodeId, origin: c.origin }).toString('hex'), c.transcriptHex);
    assert.equal(proof.signProof({ nonce, room: c.room, nodeId: c.nodeId, origin: c.origin }, priv), c.proof);
    assert.equal(proof.verifyProof({ nonce, room: c.room, nodeId: c.nodeId, origin: c.origin }, v.publicKey, c.proof), true);
  }
});

test('a node holding its key asks for a challenge and answers it with a proof for the URL it dialed; the relay verified it', async () => {
  const r = relay();
  await r.ready;
  const id = identity('prover');
  const c = client(r.url(), id, { getRoom: () => 'team-x' });
  try {
    c.rc.connect();
    const s = await c.rc.awaitOutcome(5000);
    assert.equal(s.phase, 'connected');
    assert.equal(s.relayVerifiesKeys, true);
    const [ask, answer] = r.st.frames.filter((f) => f.type === 'relay-auth');
    assert.equal(ask.keyProof, proof.KEY_PROOF);
    assert.equal(ask.proof, undefined, 'the first frame asks; it proves nothing');
    assert.equal(ask.token, TOKEN, 'and is a whole relay-auth, which a relay before 0.8.0 takes as it is');
    assert.equal(answer.publicKey, id.publicKey);
    assert.equal(answer.room, 'team-x');
    assert.deepEqual(r.st.proofs.map((p) => p.ok), [true], 'the proof verifies, over room team-x and the dialed origin');
    assert.match(c.rc.describe(), /the relay verified this node's key$/);
    assert.ok(!c.logs.some((l) => l.includes(TOKEN)), 'the token is never logged');
  } finally { c.stop(); await r.close(); }
});

test('http:// is the same relay as ws://: dialled as ws://, and the proof names that origin', async () => {
  const r = relay();
  await r.ready;
  const c = client(r.url().replace(/^ws:/, 'http:'), identity('http'));
  try {
    assert.equal(c.rc.state().url, r.url());
    c.rc.connect();
    assert.equal((await c.rc.awaitOutcome(5000)).relayVerifiesKeys, true);
  } finally { c.stop(); await r.close(); }
});

test('a relay that never challenges (sym-relay before 0.8.0) takes the first frame: connected at once, relayVerifiesKeys false, said once', async () => {
  const r = relay({ verifies: false });
  await r.ready;
  const c = client(r.url(), identity('old-relay'));
  try {
    const t0 = Date.now();
    c.rc.connect();
    const s = await c.rc.awaitOutcome(5000);
    assert.equal(s.phase, 'connected');
    assert.ok(Date.now() - t0 < 1500, 'no wait for a challenge that never comes');
    assert.equal(s.relayVerifiesKeys, false);
    assert.equal(r.st.frames.filter((f) => f.type === 'relay-auth').length, 1, 'one relay-auth, the one the old relay took');
    assert.match(c.rc.describe(), /this relay does not verify keys/);
    // Reconnect: said once per connection object, not on every connect.
    for (const ws of r.st.sockets) ws.close(1001, 'restart');
    assert.ok(await until(() => r.st.admitted === 2, 5000));
    assert.equal(c.logs.filter((l) => /does not verify keys/.test(l)).length, 1);
  } finally { c.stop(); await r.close(); }
});

test('a relay that does not verify keys may not be sent toKey: a fan-out entry carrying it is malformed there', async () => {
  const peerKey = identity('pk').publicKey;
  const P = '01900000-0000-7000-8000-0000000000e1';
  const r = relay({ verifies: false, peers: [{ nodeId: P, name: 'peer' }] });
  await r.ready;
  const c = client(r.url(), identity('nokey'), { keyOf: () => peerKey });
  try {
    c.rc.connect();
    await c.rc.awaitOutcome(5000);
    c.rc.sendTo(P, { type: 'cmb-encrypted', n: 1 });
    assert.ok(await until(() => r.st.frames.some((f) => f.payload && f.payload.n === 1), 3000));
    assert.equal(r.st.frames.find((f) => f.payload && f.payload.n === 1).toKey, undefined);
  } finally { c.stop(); await r.close(); }
});

for (const [label, verifies, cause] of [
  ['the relay verified this connection\'s key', true, /another process proved this identity's key on this relay; this one stopped/],
  ['the relay does not verify keys', false, /this relay does not verify keys, so any holder of the token can cause this; upgrade the relay/],
]) {
  test(`4004 when ${label}: stopped for good, said once with its cause, told to the host once`, async () => {
    const r = relay({ verifies, after: (ws) => setTimeout(() => ws.close(4004, 'Replaced: this identity\'s key connected again (key proven)'), 30) });
    await r.ready;
    const id = identity('stopped');
    const c = client(r.url(), id);
    try {
      c.rc.connect();
      assert.ok(await until(() => c.rc.state().phase === 'collision', 5000));
      await wait(1500); // past the first ordinary backoff (1 s)
      assert.equal(r.st.dials, 1, 'never redialled');
      const s = c.rc.state();
      assert.equal(s.nextRetryAt, null, 'nothing scheduled');
      assert.equal(s.stopped.code, 4004);
      assert.equal(s.stopped.relayVerifiesKeys, verifies);
      assert.match(c.rc.describe(), /^STOPPED: .*\(4004\): /);
      assert.match(c.rc.describe(), cause);
      assert.equal(c.logs.filter((l) => l.startsWith('FATAL')).length, 1, 'said once, loudly');
      assert.match(c.logs.find((l) => l.startsWith('FATAL')), cause);
      assert.deepEqual(c.told, [{ nodeId: id.nodeId, name: 'proof-test', code: 4004, kind: 'replaced', reason: 'Replaced: this identity\'s key connected again (key proven)', relayVerifiesKeys: verifies }]);
      c.rc.connect();
      await wait(200);
      assert.equal(r.st.dials, 1, 'a later connect() does not dial either');
      c.rc.destroy();
      assert.equal(c.rc.state().phase, 'collision', 'destroy() does not hide the stop');
    } finally { c.stop(); await r.close(); }
  });
}

test('4006 (a relay that does not verify keys) stops the same way', async () => {
  const wss = new WebSocketServer({ port: 0, host: '127.0.0.1' });
  await new Promise((r) => wss.once('listening', r));
  let dials = 0;
  wss.on('connection', (ws) => { dials++; ws.on('message', () => ws.close(4006, 'Existing connection too fresh — duplicate identity rejected')); });
  const c = client(`ws://127.0.0.1:${wss.address().port}`, identity('dup'));
  try {
    c.rc.connect();
    const s = await c.rc.awaitOutcome(5000);
    assert.equal(s.phase, 'duplicate-rejected');
    await wait(1500);
    assert.equal(dials, 1);
    assert.equal(c.told.length, 1);
    assert.equal(c.told[0].code, 4006);
    assert.equal(c.told[0].relayVerifiesKeys, false);
    assert.match(c.rc.describe(), /\(4006\): this relay does not verify keys/);
  } finally { c.stop(); await new Promise((r) => { for (const x of wss.clients) x.terminate(); wss.close(() => r()); }); }
});

test('toKey names the bound key when the relay lists a slot proven for it; fan-out entries carry it too', async () => {
  const P = '01900000-0000-7000-8000-0000000000e2', Q = '01900000-0000-7000-8000-0000000000e3';
  const bound = identity('bound').publicKey, impostor = identity('imp').publicKey;
  const r = relay({ peers: [
    { nodeId: P, name: 'peer', key: bound, proven: true },
    { nodeId: P, name: 'impostor', key: impostor, proven: true },
    { nodeId: Q, name: 'legacy-peer' },
  ] });
  await r.ready;
  const keys = new Map([[P, bound], [Q, identity('q').publicKey]]);
  const c = client(r.url(), identity('sender'), { keyOf: (n) => keys.get(n) });
  try {
    c.rc.connect();
    await c.rc.awaitOutcome(5000);
    c.rc.sendTo(P, { type: 'cmb-encrypted', n: 1 });
    assert.ok(await until(() => r.st.frames.some((f) => f.payload && f.payload.n === 1), 3000));
    assert.equal(r.st.frames.find((f) => f.payload && f.payload.n === 1).toKey, bound, 'the bound key');
    c.rc.sendTo(Q, { type: 'cmb-encrypted', n: 2 });
    assert.ok(await until(() => r.st.frames.some((f) => f.payload && f.payload.n === 2), 3000));
    assert.equal(r.st.frames.find((f) => f.payload && f.payload.n === 2).toKey, undefined, 'a peer listed without a proven slot for its key is reached without toKey');
    // Two in one turn go as one fan-out; each entry names its own key or none.
    c.rc.sendTo(P, { type: 'cmb-encrypted', n: 3 });
    c.rc.sendTo(Q, { type: 'cmb-encrypted', n: 4 });
    assert.ok(await until(() => r.st.frames.some((f) => Array.isArray(f.fanout)), 3000));
    const fan = r.st.frames.find((f) => Array.isArray(f.fanout)).fanout;
    assert.deepEqual(fan.map((e) => [e.to, e.toKey]), [[P, bound], [Q, undefined]]);
  } finally { c.stop(); await r.close(); }
});

test('the bound key\'s slot is the peer: an impostor\'s key is no candidate, and its departure ends nothing', async () => {
  const P = '01900000-0000-7000-8000-0000000000e4';
  const bound = identity('b').publicKey, impostor = identity('i').publicKey;
  let relaySocket = null;
  const r = relay({ after: (ws) => { relaySocket = ws; } });
  await r.ready;
  const c = client(r.url(), identity('watcher'), { keyOf: (n) => (n === P ? bound : undefined) });
  const announce = (type, name, key) => relaySocket.send(JSON.stringify({ type, nodeId: P, name, ...(key ? { key, proven: true } : {}) }));
  try {
    c.rc.connect();
    await c.rc.awaitOutcome(5000);
    announce('relay-peer-joined', 'impostor', impostor);
    await wait(100);
    assert.equal(c.rc.present.has(P), false, 'only a key other than the bound one: not the peer');
    assert.equal(c.present.length, 0);
    announce('relay-peer-joined', 'member', bound);
    assert.ok(await until(() => c.present.length === 1, 2000));
    assert.equal(c.rc.present.get(P), 'member');
    announce('relay-peer-joined', 'impostor-2', identity('i2').publicKey);
    announce('relay-peer-left', 'impostor', impostor);
    await wait(100);
    assert.equal(c.gone.length, 0, 'an impostor leaving ends nothing');
    assert.equal(c.rc.present.get(P), 'member', 'and renames nothing');
    announce('relay-peer-left', 'member', bound);
    assert.ok(await until(() => c.gone.length === 1, 2000), 'the member leaving is the peer gone');
    assert.equal(c.rc.present.has(P), false);
  } finally { c.stop(); await r.close(); }
});

test('with no binding the newest proven slot is the candidate; a legacy claim behind a proven peer takes over when it leaves', async () => {
  const P = '01900000-0000-7000-8000-0000000000e5';
  const k1 = identity('k1').publicKey;
  let sock = null;
  const r = relay({ after: (ws) => { sock = ws; } });
  await r.ready;
  const c = client(r.url(), identity('w2'));
  try {
    c.rc.connect();
    await c.rc.awaitOutcome(5000);
    sock.send(JSON.stringify({ type: 'relay-peer-joined', nodeId: P, name: 'legacy' }));
    sock.send(JSON.stringify({ type: 'relay-peer-joined', nodeId: P, name: 'proven', key: k1, proven: true }));
    assert.ok(await until(() => c.rc.present.get(P) === 'proven', 2000));
    sock.send(JSON.stringify({ type: 'relay-peer-left', nodeId: P, name: 'legacy' }));
    await wait(100);
    assert.equal(c.gone.length, 0, 'the legacy claim leaving ends nothing while the proven one is the peer');
    sock.send(JSON.stringify({ type: 'relay-peer-joined', nodeId: P, name: 'legacy' }));
    sock.send(JSON.stringify({ type: 'relay-peer-left', nodeId: P, name: 'proven', key: k1, proven: true }));
    assert.ok(await until(() => c.gone.length === 1 && c.rc.present.get(P) === 'legacy', 2000), 'the proven peer gone, the legacy claim is the candidate now');
  } finally { c.stop(); await r.close(); }
});

test('a challenge this node did not ask for, or one that is malformed, is ignored', async () => {
  const wss = new WebSocketServer({ port: 0, host: '127.0.0.1' });
  await new Promise((r) => wss.once('listening', r));
  const frames = [];
  wss.on('connection', (ws) => {
    ws.on('message', (d) => {
      frames.push(JSON.parse(String(d)));
      if (frames.length === 1) ws.send(JSON.stringify({ type: 'relay-challenge', keyProof: proof.KEY_PROOF, nonce: 'short' }));
      if (frames.length === 1) setTimeout(() => ws.send(JSON.stringify({ type: 'relay-peers', peers: [] })), 100);
    });
  });
  const unasked = client(`ws://127.0.0.1:${wss.address().port}`, { nodeId: '01900000-0000-7000-8000-0000000000e6' });
  try {
    unasked.rc.connect();
    const s = await unasked.rc.awaitOutcome(5000);
    assert.equal(s.phase, 'connected');
    assert.equal(frames.length, 1, 'no proof sent: a node without its key pair asks for none, and a malformed challenge is not answered');
    assert.equal(frames[0].keyProof, undefined);
    assert.equal(s.relayVerifiesKeys, false);
  } finally { unasked.stop(); await new Promise((r) => { for (const x of wss.clients) x.terminate(); wss.close(() => r()); }); }
});

test('a SymNode proves its key, reports it in status(), and its identity-collision event has the restored shape', async () => {
  const r = relay({ after: (ws, auth, n) => { if (n === 1) setTimeout(() => ws.close(4004, 'Replaced: this identity\'s key connected again (key proven)'), 300); } });
  await r.ready;
  const n = new SymNode({ name: `proof-node-${process.pid}`, silent: true, discovery: new NullDiscovery(), relay: r.url(), relayToken: TOKEN });
  const events = [];
  const metrics = [];
  n.on('identity-collision', (e) => events.push(e));
  n.on('metric', (m) => { if (/^relay-/.test(m.type)) metrics.push(m); });
  try {
    await n.start();
    assert.ok(await until(() => n.status().relayState.phase === 'connected', 5000));
    assert.equal(n.status().relayState.relayVerifiesKeys, true);
    assert.deepEqual(r.st.proofs.map((p) => [p.ok, p.publicKey]), [[true, n._identity.publicKey]]);
    assert.ok(await until(() => events.length === 1, 5000));
    assert.deepEqual(Object.keys(events[0]).sort(), ['code', 'kind', 'name', 'nodeId', 'reason', 'relayVerifiesKeys']);
    assert.equal(events[0].relayVerifiesKeys, true);
    assert.deepEqual(metrics.map((m) => m.type), ['relay-hard-stop']);
    assert.match(n.status().relayStatus, /another process proved this identity's key on this relay; this one stopped/);
  } finally { await n.stop(); await r.close(); }
});
