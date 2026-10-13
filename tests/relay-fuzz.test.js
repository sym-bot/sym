'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * A port of the 0.13.17 review's fuzz-relay.js against 0.14: every frame type, every field set to
 * values that are not what they must be (unprintable, numbers, arrays, objects, null, deep, long),
 * sent two ways —
 *   - in the clear from an unproven relay `from` (refused: not a Core Secure session), and
 *   - from a CONFIRMED session, through the one guarded dispatch (design D1), as a peer that proved
 *     its key could send them sealed.
 * Nothing may reach uncaughtException or unhandledRejection, and the node must keep working.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { WebSocketServer } = require('ws');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const { identity, admitAs, deliver, until } = require('./_core-secure');

const U = { toString: 1 };                 // unprintable
const deepArr = (d) => { let a = []; for (let i = 0; i < d; i++) a = [a]; return a; };
const VALS = { U, num: 42, arr: [1, 2], obj: {}, nul: null, bool: true, deep: deepArr(100), long: 'x'.repeat(5000) };
const TYPES = ['handshake', 'cmb', 'mood', 'wake-channel', 'peer-info', 'attestation', 'cmb-fetch', 'cmb-fetch-result',
  'checkpoint', 'witness', 'role-grant', 'role-revoke', 'role-chain-fetch', 'role-chain', 'role-digest', 'node-stats', 'message',
  'authority-statement', 'authority-digest', 'authority-fetch', 'authority-set',
  'xmesh-insight', 'cmb-anchors', 'mesh-room-join', 'ping', 'pong', 'error', 'state-sync', 'zzz'];
const FIELDS = ['nodeId', 'name', 'publicKey', 'room', 'roomGrant', 'grant', 'cmb', 'content', 'mood', 'fromName', 'platform',
  'token', 'environment', 'peers', 'attestation', 'key', 'keys', 'reqId', 'found', 'notFound', 'grantees', 'grants', 'checkpoint',
  'witness', 'stats', 'trajectory', 'anomaly', 'remixScore', 'coherence', 'timestamp', 'directed', 'to', 'code', 'detail', 'message',
  'statement', 'root', 'count', 'ids', 'after', 'statements', 'missing', 'next'];

function corpus() {
  const out = [];
  for (const type of TYPES) {
    for (const f of FIELDS) for (const v of Object.values(VALS)) out.push({ type, [f]: v });
    for (const v of Object.values(VALS)) {
      out.push({ type, cmb: { categories: v } });
      out.push({ type, cmb: { categories: { focus: v, mood: v } } });
      out.push({ type, cmb: { metadata: v, categories: { focus: { text: 'x' } } } });
      out.push({ type, cmb: { metadata: { createdBy: v, createdByNodeId: v, sig: v, lineage: v, createdTimestamp: v, signatureSuite: 'mmp-sig-v2.0', to: v, room: v }, categories: { focus: { text: 'hello focus' } } } });
      out.push({ type, peers: [v, { nodeId: 'p1', wakeChannel: v }, { nodeId: v, wakeChannel: { platform: 'apns', token: v } }] });
      out.push({ type, grant: { type: 'role-grant', grantee: 'g', grantedBy: 'b', sig: 's', sigAlg: 'ed25519', grantedAt: v, role: v, granteeKey: v } });
      out.push({ type, grants: [v, { type: 'role-grant', grantee: v, grantedBy: v, sig: v }], reqId: 'rc-x' });
      out.push({ type, attestation: { of: v, by: v, sig: v, seq: v, prev: v, verdict: v } });
      out.push({ type, checkpoint: { by: v, at: v, sig: v, root: v }, witness: { by: v, of: v, sig: v } });
      out.push({ type, stats: { name: v, nodeId: v } });
      out.push({ type, keys: [v, v], reqId: v, found: [v], notFound: v });
    }
  }
  return out;
}

function watchProcess() {
  const events = [];
  const onU = (e) => events.push(['uncaught', String(e && e.stack || e).split('\n').slice(0, 3).join(' | ')]);
  const onR = (e) => events.push(['unhandledRejection', String(e && e.stack || e).split('\n').slice(0, 3).join(' | ')]);
  process.on('uncaughtException', onU);
  process.on('unhandledRejection', onR);
  return { events, stop: () => { process.removeListener('uncaughtException', onU); process.removeListener('unhandledRejection', onR); } };
}

describe('fuzz: malformed frames of every type (port of fuzz-relay.js)', () => {
  it('from a confirmed session, through the guarded dispatch: nothing escapes, and the node keeps working', async () => {
    const w = watchProcess();
    const node = new SymNode({ name: `fuzz-session-${Date.now()}`, silent: true, discovery: new NullDiscovery(), room: 'g' });
    try {
      await node.start();
      const s = admitAs(node, identity('fuzzer'));
      const cases = corpus();
      for (const f of cases) {
        const r = deliver(node, s, JSON.parse(JSON.stringify(f, (k, v) => (v === U ? { toString: 1 } : v))));
        if (r && typeof r.then === 'function') await r.catch(() => {});
      }
      for (const f of cases.slice(0, 200)) deliver(node, s, { ...f, cmb: f.cmb, fromName: U });
      await new Promise((r) => setTimeout(r, 300));
      assert.deepStrictEqual(w.events, [], 'nothing reached uncaughtException or unhandledRejection');
      const ok = admitAs(node, identity('after'));
      deliver(node, ok, { type: 'wake-channel', platform: 'apns', token: 'still-working' });
      assert.strictEqual(node._peerWakeChannels.get(ok.nodeId)?.token, 'still-working', 'the node keeps working');
    } finally { w.stop(); await node.stop(); fs.rmSync(nodeDirById(node.nodeId), { recursive: true, force: true }); }
  });

  it('in the clear from an unproven relay from: all refused, nothing escapes, the relay link keeps working', async () => {
    const w = watchProcess();
    const evil = '0'.repeat(8) + '-evil';
    const cases = corpus();
    let sentAll = false;
    const wss = new WebSocketServer({ port: 0 });
    wss.on('connection', (ws) => ws.on('message', (m) => {
      let j; try { j = JSON.parse(String(m)); } catch { return; }
      if (j.type !== 'relay-auth') return;
      ws.send(JSON.stringify({ type: 'relay-peers', peers: [{ nodeId: evil, name: 'evil' }, { nodeId: { toString: 1 }, name: U }, { nodeId: 'w1', name: 'w', wakeChannel: { platform: 'apns', token: null }, offline: true }] }));
      ws.send(JSON.stringify({ type: 'relay-peer-joined', nodeId: 'p2', name: { toString: 1 } }));
      for (const payload of cases) {
        ws.send(JSON.stringify({ from: evil, fromName: 'evil', payload }));
        ws.send(JSON.stringify({ from: evil, fromName: { toString: 1 }, payload }));
        ws.send(JSON.stringify({ from: { toString: 1 }, payload }));
      }
      ws.send(JSON.stringify({ type: 'relay-error', kind: { toString: 1 }, code: 'x', message: { toString: 1 } }));
      ws.send(JSON.stringify({ type: 'relay-peer-joined', nodeId: '0'.repeat(8) + '-sentinel', name: 'after' }));
      sentAll = true;
    }));
    const node = new SymNode({ name: `fuzz-relay-${Date.now()}`, silent: true, relayOnly: true, discovery: new NullDiscovery(), relay: `ws://127.0.0.1:${wss.address().port}`, relayToken: 'x'.repeat(40), room: 'g' });
    try {
      await node.start();
      await until(() => sentAll && node._relay.present.has('0'.repeat(8) + '-sentinel'), 20000);
      await new Promise((r) => setTimeout(r, 300));
      assert.deepStrictEqual(w.events, [], 'nothing reached uncaughtException or unhandledRejection');
      assert.ok(node._relay.present.has('0'.repeat(8) + '-sentinel'), 'the relay link keeps working');
      assert.strictEqual(node._peers.size, 0, 'no peer from anything sent in the clear');
      assert.strictEqual(node._roster.size(), 0, 'and no key bound');
      assert.strictEqual(node._authority.size(), 0);
      assert.strictEqual(node._peerWakeChannels.size, 0);
    } finally { w.stop(); await node.stop(); await new Promise((r) => wss.close(() => r())); fs.rmSync(nodeDirById(node.nodeId), { recursive: true, force: true }); }
  });
});
