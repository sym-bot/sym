'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * The host API mesh-channel 0.11.0 builds to (its DESIGN-0.11.0.md §6, at 8590081), and the rest of
 * the security review's extras that need a node: what an inbox entry, `mood-delivered` and
 * `xmesh-insight` carry; a room-join grant's expiry; the anchor mark; bounded refusal metrics; node
 * names; `sym emit` and a live identity.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const config = require('../lib/config');
const { signRoomGrant } = require('../lib/core/room-grant');
const { memoryPipe, connectNodes, until, identity, signedRecord, admitAs, deliver } = require('./_core-secure');

const uniq = (b) => `${b}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
const CATS = (focus, mood = 'calm') => ({ focus, issue: 'host api', intent: 'inform', motivation: 'm', commitment: 'c', perspective: 'p', mood: { text: mood, valence: 0.4, arousal: 0.1 } });
const ALIGNED = { decision: 'aligned', total_drift: 0.1, category_drifts: { focus: 0.1 }, gate_values: { g: 1 } };
const REJECTED = { decision: 'rejected', total_drift: 9, category_drifts: {}, gate_values: { g: 0 } };
const mk = (base, extra = {}) => new SymNode({ name: uniq(base), silent: true, discovery: new NullDiscovery(), room: extra.room || 'ha', ...extra });
async function stopAll(...nodes) {
  for (const n of nodes) { try { await n.stop(); } catch { /* */ } try { fs.rmSync(config.nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ } }
}

describe('what a host is given (mesh-channel DESIGN-0.11.0 §6)', () => {
  it('1. an inbox entry carries verified, profile, assertionId, verification, session, author.key and the signed record, persisted', async () => {
    const a = mk('in-a'); const b = mk('in-b');
    try {
      await a.start(); await b.start();
      b._svafEvaluator.evaluate = async () => ALIGNED;
      await connectNodes(a, b);
      const accepted = [];
      b.on('cmb-accepted', (e) => accepted.push(e));
      const sent = a.remember(CATS('provenance travels with the delivery'));
      await until(() => accepted.length > 0, 4000);
      const e = accepted[0];
      assert.strictEqual(e.verified, true);
      assert.strictEqual(e.profile, 'core-secure');
      assert.strictEqual(e.assertionId, sent.cmb.metadata.assertionId);
      assert.strictEqual(e.verification.authorNodeId, a.nodeId);
      assert.strictEqual(e.session.nodeId, a.nodeId);
      assert.strictEqual(e.author.key, a.publicKey);
      const item = b.inboxGet(e.inboxId);
      for (const k of ['verified', 'profile', 'assertionId']) assert.strictEqual(item[k], e[k], k);
      assert.deepStrictEqual(item.verification, e.verification);
      assert.strictEqual(item.session.identityKey, a.publicKey);
      assert.strictEqual(item.record.metadata.assertionId, sent.cmb.metadata.assertionId, 'the signed record');
      assert.strictEqual(item.record.categories.mood.valence, undefined, 'its projection: no unsigned members');
      // Persisted with the inbox: a restart reads the same facts back.
      b._writeInbox();
      const persisted = JSON.parse(fs.readFileSync(b._inboxFile, 'utf8')).messages.find((m) => m.id === e.inboxId);
      assert.strictEqual(persisted.assertionId, e.assertionId);
      assert.strictEqual(persisted.verification.authorKey, a.publicKey);
    } finally { await stopAll(a, b); }
  });

  it('2. mood-delivered carries { key, assertionId, authorNodeId, deliveredBy, verified }, and no unsigned valence or arousal', async () => {
    const a = mk('md-a'); const b = mk('md-b');
    try {
      await a.start(); await b.start();
      b._svafEvaluator.evaluate = async () => REJECTED;
      await connectNodes(a, b);
      const moods = [];
      b.on('mood-delivered', (m) => moods.push(m));
      const sent = a.remember(CATS('a rejected focus with a strong mood', 'exhausted'));
      await until(() => moods.length > 0, 4000);
      const m = moods[0];
      assert.strictEqual(m.key, sent.cmb.metadata.key);
      assert.strictEqual(m.assertionId, sent.cmb.metadata.assertionId);
      assert.strictEqual(m.authorNodeId, a.nodeId);
      assert.deepStrictEqual({ ...m.deliveredBy }, { nodeId: a.nodeId, name: a.name });
      assert.strictEqual(m.verified, true);
      assert.ok(!('valence' in m) && !('arousal' in m), 'unsigned affect numbers are not delivered');
      assert.ok(Object.isFrozen(m));
    } finally { await stopAll(a, b); }
  });

  it('4-5. node.publicKey, node.fingerprint and node.keyBindings() — public keys only', async () => {
    const a = mk('kb-a'); const b = mk('kb-b');
    try {
      await a.start(); await b.start();
      assert.strictEqual(a.publicKey, a._identity.publicKey);
      assert.match(a.fingerprint, /^sha256:[0-9a-f]{64}$/);
      await connectNodes(a, b);
      const pinned = identity('pinned-peer');
      a._roster.bind(pinned.nodeId, pinned.publicKey, 'pinned');
      const kb = a.keyBindings();
      assert.ok(kb.some((x) => x.nodeId === b.nodeId && x.key === b.publicKey && x.source === 'session'));
      assert.ok(kb.some((x) => x.nodeId === pinned.nodeId && x.source === 'pinned'));
      assert.ok(kb.every((x) => Object.keys(x).sort().join() === 'key,nodeId,source'), 'nothing but { nodeId, key, source }');
      assert.ok(!JSON.stringify(kb).includes(a._identity.privateKey));
    } finally { await stopAll(a, b); }
  });

  it('xmesh-insight names the proven nodeId it came from', async () => {
    const n = mk('xi');
    try {
      const got = [];
      n.on('xmesh-insight', (i) => got.push(i));
      const P = identity('insight-peer');
      const s = admitAs(n, P);
      deliver(n, s, { type: 'xmesh-insight', fromName: 'a label it chose', anomaly: 0.1, remixScore: 0.2, coherence: 0.3 });
      assert.strictEqual(got[0].fromNodeId, P.nodeId);
      assert.strictEqual(got[0].from, 'a label it chose', 'the label stays a label');
    } finally { await stopAll(n); }
  });
});

describe('the rest of the review\'s extras', () => {
  it('a room-join grant admits until it expires: the session closes when its grant does', async () => {
    const ownerName = uniq('rg-owner'); const ownerId = config.loadOrCreateIdentity(ownerName);
    const guestName = uniq('rg-guest'); const guestId = config.loadOrCreateIdentity(guestName);
    const grant = signRoomGrant({ room: 'gated-expiry', grantee: guestId.nodeId, granteeKey: guestId.publicKey, grantedBy: ownerId.nodeId, expiresAt: Date.now() + 1500 }, ownerId.privateKey);
    const owned = (extra = {}) => ({ roomOwners: [{ room: 'gated-expiry', nodeId: ownerId.nodeId, publicKey: ownerId.publicKey }], room: 'gated-expiry', ...extra });
    const owner = new SymNode({ name: ownerName, silent: true, discovery: new NullDiscovery(), ...owned() });
    const guest = new SymNode({ name: guestName, silent: true, discovery: new NullDiscovery(), ...owned({ roomGrant: grant }) });
    try {
      await owner.start(); await guest.start();
      await connectNodes(guest, owner);
      assert.ok(owner._peers.has(guest.nodeId), 'admitted on its grant');
      await until(() => !owner._peers.has(guest.nodeId), 4000);
      assert.strictEqual(owner._peers.has(guest.nodeId), false, 'gone when the grant expired');
    } finally { await stopAll(owner, guest); }
  });

  it('cmb-anchors marks only a record the session\'s own node authored', async () => {
    const n = mk('anc');
    try {
      n._svafEvaluator.evaluate = async () => ALIGNED;
      const P = identity('anchoring-peer'); const Q = identity('someone-else');
      const s = admitAs(n, P); admitAs(n, Q);
      const hooked = [];
      n.on('verified-record', (e) => hooked.push(e));
      const own = signedRecord(P, { categories: CATS('P\'s own context'), room: 'ha' });
      const other = signedRecord(Q, { categories: CATS('Q\'s record P relays as "context"'), room: 'ha' });
      deliver(n, s, { type: 'cmb-anchors', keys: [own.metadata.key, other.metadata.key] });
      deliver(n, s, { type: 'cmb', cmb: own });
      deliver(n, s, { type: 'cmb', cmb: other });
      await until(() => hooked.length >= 2, 3000);
      assert.strictEqual(hooked.find((e) => e.record.metadata.key === own.metadata.key).verification.anchor, true);
      assert.strictEqual(hooked.find((e) => e.record.metadata.key === other.metadata.key).verification.anchor, false, 'another node\'s record is not P\'s anchor');
    } finally { await stopAll(n); }
  });

  it('refused frames are counted by known type only (a peer\'s own type names do not grow the table)', () => {
    const n = mk('metr');
    try {
      for (let i = 0; i < 50; i++) n._refuseFrame('p', 'p', { type: `made-up-${i}` }, 'lan', new Error('x'));
      n._refuseFrame('p', 'p', { type: '__proto__' }, 'lan', new Error('x'));
      n._refuseFrame('p', 'p', { type: 'cmb' }, 'lan', new Error('x'));
      const byType = n.metrics().framesRefusedByType;
      assert.deepStrictEqual(Object.keys(byType).sort(), ['cmb', 'other']);
      assert.strictEqual(byType.other, 51);
    } finally { n.stop().catch(() => {}); }
  });

  it('a node name is one path component', () => {
    for (const bad of ['../escape', 'a/b', 'a\\b', '.', '..']) assert.throws(() => config.validateName(bad), /path separator|"\."/, bad);
    assert.doesNotThrow(() => config.validateName('claude-sym-agent-a'));
  });

  it('sym emit never reuses a live node\'s identity (its lock is held by another process)', async () => {
    const name = uniq('emit-live');
    const id = config.loadOrCreateIdentity(name);
    const dir = config.nodeDirById(id.nodeId);
    // Another process holds the identity's lock (a running node of that name).
    const child = spawn(process.execPath, ['-e', `
      const c = require(${JSON.stringify(path.join(__dirname, '..', 'lib', 'config'))});
      c.acquireIdentityLock(${JSON.stringify(name)}, { dir: ${JSON.stringify(dir)} });
      process.stdout.write('held\\n');
      setInterval(() => {}, 1000);
    `], { env: process.env, stdio: ['ignore', 'pipe', 'inherit'] });
    try {
      await new Promise((r) => child.stdout.once('data', r));
      const receiver = mk('emit-rx');
      try {
        const { connect } = require('../lib/emit');
        await assert.rejects(() => connect({ server: '127.0.0.1:1', receiver: { nodeId: receiver.nodeId, key: receiver.publicKey }, name }), (e) => e.code === 'EIDENTITYLOCK');
      } finally { await stopAll(receiver); }
    } finally { child.kill('SIGKILL'); }
  });
});

void memoryPipe;
