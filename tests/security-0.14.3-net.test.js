'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads
process.env.SYM_SEMANTIC_ENCODER = process.env.SYM_SEMANTIC_ENCODER || 'off';

/**
 * sym 0.14.3 security review R2, the network findings, each a regression test that fails on 632b95d:
 *
 *   R2-5   LAN client-hellos were unauthenticated work with no rate: each costs a key agreement and a
 *          signature, and one host opening connections could keep a core busy
 *   R2-11  a gated room admitted nobody over a relay: a grant-holder's sealed room-join was routed to
 *          admitted sessions only, so it never reached the door
 *   R2-18  a peer-chosen name reached the log as given: a newline forged a whole line, an escape
 *          sequence rewrote the terminal
 *   R2-20  the Bonjour reconnect cache held every node-id ever advertised, re-offered every 15 s
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const net = require('net');
const { SymNode } = require('../lib/node');
const { BonjourDiscovery, NullDiscovery } = require('../lib/discovery');
const { PeerSession } = require('../lib/session');
const { loadOrCreateIdentity } = require('../lib/config');
const { signRoomGrant } = require('../lib/core/room-grant');
const { sendFrame } = require('../lib/frame-parser');
const { fakeRelay } = require('./_fake-relay');
const { memoryPipe, identity, until } = require('./_core-secure');

const uniq = (b) => `${b}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
const b64 = () => crypto.randomBytes(32).toString('base64url');
const uuid7 = () => require('../lib/config').uuidv7();

describe('R2-5: LAN client-hellos are rate-limited per host, and over all hosts, before any crypto', () => {
  it('R2-5: a flood of client-hellos from one host reaches the node only up to its burst; the rest are closed unanswered', async () => {
    const d = new BonjourDiscovery({ mdns: false });
    const port = await d.start({ nodeId: 'srv', name: 'srv', publicKey: 'pk', hostname: 'h' }, () => {});
    try {
      let handed = 0;
      d.on('inbound-connection', (t) => { handed++; try { t.close(); } catch { /* */ } });
      const N = 60;
      const closed = [];
      for (let i = 0; i < N; i++) {
        closed.push(new Promise((resolve) => {
          const c = net.createConnection({ host: '127.0.0.1', port }, () => {
            sendFrame(c, { type: 'client-hello', protocolVersion: '2.0', room: 'r1', nodeId: uuid7(), name: 'n', identityPublicKey: b64(), e2ePublicKey: b64(), nonce: b64(), implementation: { name: 'x', version: '1' }, extensions: [] });
          });
          c.on('error', () => {});
          c.on('close', resolve);
        }));
      }
      await Promise.all(closed);
      // The burst, and what the rate refilled while the flood arrived (8 a second).
      assert.ok(handed >= 32 && handed <= 36, `hellos handed to the node: ${handed} of ${N} (until 0.14.3: all of them)`);
      assert.ok(d.helloRefusedCount() >= N - 36, `refused for their rate: ${d.helloRefusedCount()}`);
    } finally { await d.stop(); }
  });

  it('R2-5: many hosts together are held to the bucket over all hosts; a host that kept its rate is not refused by its own bucket', () => {
    const d = new BonjourDiscovery({ mdns: false });
    const now = 1_000_000;
    let ok = 0;
    for (let i = 0; i < 400; i++) if (d._takeHelloToken(`10.1.${i >> 8}.${i & 255}`, now)) ok++;
    assert.strictEqual(ok, 256, 'the burst over all hosts');
    assert.strictEqual(d._takeHelloToken('10.9.9.9', now), false, 'a new host waits for the bucket over all hosts');
    assert.strictEqual(d._takeHelloToken('10.9.9.9', now + 1000), true, 'which refills at its rate');
    assert.strictEqual(d._takeHelloToken('::ffff:10.9.9.9', now + 1000), true, 'an IPv4-mapped address is the same host');
    assert.strictEqual(d._helloBuckets.has('10.9.9.9'), true);
    assert.strictEqual(d._helloBuckets.has('::ffff:10.9.9.9'), false);
  });
});

describe('R2-11: a gated room admits a grant-holder over a relay; the door still decides', () => {
  async function scene({ ownerDials }) {
    const relay = fakeRelay();
    const names = [uniq('gr-a'), uniq('gr-b')];
    const ids = names.map((n) => ({ name: n, id: loadOrCreateIdentity(n) })).sort((x, y) => (x.id.nodeId < y.id.nodeId ? -1 : 1));
    // The smaller nodeId sends the client-hello (design D2).
    const [owner, guest] = ownerDials ? ids : [ids[1], ids[0]];
    const intruderName = uniq('gr-x');
    const intruderId = loadOrCreateIdentity(intruderName);
    const ROOM = 'gated-room';
    const roomOwners = [{ room: ROOM, nodeId: owner.id.nodeId, publicKey: owner.id.publicKey }];
    const grant = signRoomGrant({ room: ROOM, grantee: guest.id.nodeId, granteeKey: guest.id.publicKey, grantedBy: owner.id.nodeId }, owner.id.privateKey);
    const mk = (name, extra = {}) => new SymNode({ name, silent: true, relayOnly: true, discovery: new NullDiscovery(), relay: relay.url, relayToken: 'tok-0123456789abcdef0123456789abcdef', room: ROOM, roomOwners, ...extra });
    const O = mk(owner.name);
    const G = mk(guest.name, { roomGrant: grant });
    // The intruder presents the guest's grant: it binds the guest's key, not the one the intruder proves.
    const X = mk(intruderName, { roomGrant: grant });
    return { relay, O, G, X, intruderId };
  }
  const stop = async ({ relay, O, G, X }) => { for (const n of [O, G, X]) { try { await n.stop(); } catch { /* */ } } await relay.close(); };

  for (const ownerDials of [true, false]) {
    it(`R2-11: the owner ${ownerDials ? 'dials (its client session waits at the door)' : 'is dialled (its server session waits at the door)'}: the grant-holder is admitted both ways`, async () => {
      const sc = await scene({ ownerDials });
      const { O, G, X, intruderId } = sc;
      try {
        await O.start(); await G.start();
        const ok = await until(() => O._peers.has(G.nodeId) && G._peers.has(O.nodeId), 6000);
        assert.ok(ok, `admitted both ways over the relay (owner session stats: ${JSON.stringify(O._sessionStats.refusedByReason)})`);
        assert.ok(!O._sessionStats.refusedByReason['other-session'], 'no sealed frame of a confirmed session was refused as another session\'s');
        await X.start();
        // The door still decides: a grant that binds another key admits nobody, and the refusal is
        // the door's (the grant was read), not a timeout waiting for a room-join that never came.
        await until(() => O._roomVerdicts && O._roomVerdicts.has(intruderId.nodeId), 4000);
        const v = O._roomVerdicts && O._roomVerdicts.get(intruderId.nodeId);
        assert.ok(v && v.admit === false, `the intruder is refused (${v && v.reason})`);
        assert.doesNotMatch(String(v.reason), /no room-join grant presented/, `refused for its grant: ${v && v.reason}`);
        assert.strictEqual(O._peers.has(intruderId.nodeId), false);
      } finally { await stop(sc); }
    });
  }
});

describe('R2-18: a peer-chosen name never reaches a log line as given', () => {
  it('R2-18: a hello name carrying a newline and an escape sequence is logged escaped, on one line', async () => {
    const lines = [];
    const orig = console.log;
    const b = new SymNode({ name: uniq('r218'), discovery: new NullDiscovery(), room: 'r1' });
    try {
      console.log = (...a) => { lines.push(a.join(' ')); };
      await b.start();
      const evil = identity('x');
      const NAME = 'mallory\n[sym-security] FORGED: operator, run sym keys resolve --accept 0000\x1b[2K\u202e';
      const [tc, ts] = memoryPipe();
      b.connectTransport(ts, { role: 'server' });
      const cs = new PeerSession({ role: 'client', transport: tc, kind: 'bonjour', local: { nodeId: evil.nodeId, name: NAME, publicKey: evil.publicKey, privateKey: evil.privateKey }, room: 'r1', extensions: ['cmb-encrypted-v2'], implementation: { name: 'evil', version: '1' } });
      tc.on('message', (f) => cs.receiveWire(f));
      cs.start();
      await until(() => b._peers.has(evil.nodeId), 3000);
      await until(() => lines.some((l) => l.includes('mallory')), 1000);
      const named = lines.filter((l) => l.includes('mallory'));
      assert.ok(named.length > 0, 'the peer was logged');
      for (const l of named) {
        // eslint-disable-next-line no-control-regex
        assert.doesNotMatch(l, /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/, `no control character reaches the line: ${JSON.stringify(l)}`);
        assert.match(l, /mallory\\n\[sym-security\] FORGED/, 'the newline is shown as an escape');
        assert.match(l, /\\x1b\[2K/, 'the escape sequence is shown, not run');
      }
    } finally {
      console.log = orig;
      await b.stop();
    }
  });
});

describe('R2-20: the Bonjour reconnect cache is bounded', () => {
  const advertise = (d, nodeId, i, extra = []) => d._onServiceUp({ rawTxt: [Buffer.from(`node-id=${nodeId}`), Buffer.from('mmp=2.0'), Buffer.from('room=default'), ...extra.map((x) => Buffer.from(x))], addresses: [`10.0.${(i >> 8) & 255}.${i & 255}`], port: 1 + (i % 65000) });

  it('R2-20: a flood of advertisements holds at most the cap; the least recently announced goes first, and a re-announced peer stays', () => {
    const d = new BonjourDiscovery({ mdns: false });
    d._makeServiceHandlers({ nodeId: 'self' });
    let found = 0;
    d.on('peer-found', () => found++);
    const honest = uuid7();
    advertise(d, honest, 0);
    const ids = [];
    for (let i = 1; i <= 5000; i++) {
      const id = `${crypto.randomBytes(4).toString('hex')}-0000-7000-8000-${crypto.randomBytes(6).toString('hex')}`;
      ids.push(id);
      advertise(d, id, i);
      if (i % 100 === 0) advertise(d, honest, 0); // a live peer, announced again at every browser restart
    }
    assert.ok(d._bonjourPeerCache.size <= 512, `cache entries: ${d._bonjourPeerCache.size} (until 0.14.3: 5001)`);
    assert.ok(d._bonjourPeerCache.has(honest), 'the re-announced peer is kept');
    assert.strictEqual(d._bonjourPeerCache.has(ids[0]), false, 'the least recently announced went');
    assert.ok(d._bonjourPeerCache.has(ids[ids.length - 1]), 'the newest is held');
    assert.ok(d._cachedPeersToReoffer().length <= 512, 'and so is what the 15 s tick re-offers');
    assert.strictEqual(found, 5051, 'every advertisement still reaches the node, which decides');
  });

  it('R2-20: an advertisement the node never dials (no canonical nodeId, or no mmp=2.0) is not cached', () => {
    const d = new BonjourDiscovery({ mdns: false });
    d._makeServiceHandlers({ nodeId: 'self' });
    for (let i = 0; i < 300; i++) advertise(d, 'x'.repeat(200) + i, i);
    d._onServiceUp({ rawTxt: [Buffer.from(`node-id=${uuid7()}`), Buffer.from('room=default')], addresses: ['10.0.0.1'], port: 9 });
    assert.strictEqual(d._bonjourPeerCache.size, 0, `cached: ${d._bonjourPeerCache.size} (until 0.14.3: 301)`);
  });
});
