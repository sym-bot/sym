'use strict';

// MMP v2.0 Core Secure session discipline: directional key agreement, the per-direction sequence
// rule (start 0, exact-next, refuse replay/rollback/gap), fail-closed gating before key
// confirmation, and paired key confirmation over the shared transcript.

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { MmpSession, C2S, S2C } = require('../lib/core/mmp-session');
const { buildEncryptedFrame, openEncryptedFrame } = require('../lib/core/cmb-encrypted-frame');

// A shared X25519 secret and a §5.2 transcript both sides agree on (contents are opaque here).
const sharedSecret = crypto.randomBytes(32);
const transcript = Buffer.from('mmp-test-transcript::client+server::nonces+keys+room', 'utf8');

function pair() {
  const client = new MmpSession('client', sharedSecret, transcript);
  const server = new MmpSession('server', sharedSecret, transcript);
  return { client, server };
}
function confirm({ client, server }) {
  assert.strictEqual(client.confirmPeer(server.ownKeyConfirmation()), true);
  assert.strictEqual(server.confirmPeer(client.ownKeyConfirmation()), true);
  return { client, server };
}

// A minimal v2.0-shaped record for round-trips (categories + the metadata the AAD binds).
const cmb = {
  categories: { focus: { text: 'session test', meta: { key: 'k', parents: [] } } },
  metadata: {
    key: 'cmb-' + '0'.repeat(64), addressScheme: 'mmp-cmb-merkle-v2', signatureSuite: 'mmp-sig-v2.0',
    assertionId: 'asrt-' + '0'.repeat(64), createdByNodeId: '018f47a0-7b21-7abc-8def-0123456789ab',
    createdBy: 'a', createdTimestamp: 1, room: 'r', to: null, lineage: null, application: null,
    sigAlg: 'ed25519', sig: 'x',
  },
};

describe('MMP v2.0 session discipline', () => {
  it('both sides derive the same sessionId and confirm each other', () => {
    const { client, server } = pair();
    assert.strictEqual(client.sessionId, server.sessionId);
    assert.match(client.sessionId, /^[0-9a-f]{32}$/);
    confirm({ client, server });
    assert.ok(client.confirmed && server.confirmed);
  });

  it('fails closed: no send or receive before confirmation', () => {
    const { client, server } = pair();
    assert.throws(() => client.nextSend(), /unconfirmed/);
    assert.throws(() => server.receive('0', C2S, () => null), /unconfirmed/);
  });

  it('a tampered peer confirmation is rejected and leaves the session closed', () => {
    const { client, server } = pair();
    const bad = server.ownKeyConfirmation(); bad[0] ^= 0x01;
    assert.strictEqual(client.confirmPeer(bad), false);
    assert.strictEqual(client.confirmed, false);
  });

  it('directions and keys agree: client c2s opens on the server, and back', () => {
    const { client, server } = confirm(pair());
    // client → server
    const s = client.nextSend();
    assert.strictEqual(s.direction, C2S);
    const frame = buildEncryptedFrame({ cmb, sessionId: client.sessionId, direction: s.direction, sequence: s.sequence, trafficKey: s.trafficKey });
    const out = server.receive(frame.sequence, frame.direction, (trafficKey) => openEncryptedFrame({ frame, trafficKey }));
    assert.deepStrictEqual(out.cmb.categories, cmb.categories);
    // server → client
    const s2 = server.nextSend();
    assert.strictEqual(s2.direction, S2C);
    const frame2 = buildEncryptedFrame({ cmb, sessionId: server.sessionId, direction: s2.direction, sequence: s2.sequence, trafficKey: s2.trafficKey });
    assert.ok(client.receive(frame2.sequence, frame2.direction, (trafficKey) => openEncryptedFrame({ frame: frame2, trafficKey })));
  });

  it('sequence starts at 0 and advances by exactly one per direction', () => {
    const { client, server } = confirm(pair());
    assert.strictEqual(client.nextSend().sequence, '0');
    assert.strictEqual(client.nextSend().sequence, '1');
    assert.strictEqual(client.nextSend().sequence, '2');
    // server's send counter is independent
    assert.strictEqual(server.nextSend().sequence, '0');
  });

  it('refuses replay, rollback, and gaps on the receive side (authentic frames out of order)', () => {
    const { client, server } = confirm(pair());
    const f = [0, 1, 2].map(() => { const s = client.nextSend(); return buildEncryptedFrame({ cmb, sessionId: client.sessionId, direction: s.direction, sequence: s.sequence, trafficKey: s.trafficKey }); });
    const take = (frame) => server.receive(frame.sequence, frame.direction, (trafficKey) => openEncryptedFrame({ frame, trafficKey }));
    assert.ok(take(f[0]));                                      // exact-next
    assert.throws(() => take(f[0]), (e) => e.name === 'SessionDesyncError' && e.kind === 'replay');
    assert.throws(() => take(f[2]), (e) => e.name === 'SessionDesyncError' && e.kind === 'gap');
    assert.ok(take(f[1]));                                      // 1 is now exact-next
    assert.throws(() => take(f[0]), /replay|rollback/);         // rollback below 2
    assert.strictEqual(server.nextRecv, '2');
  });

  it('a forged frame at the right sequence is refused and does NOT move the counter (design D2)', () => {
    const { client, server } = confirm(pair());
    const s0 = client.nextSend();
    const genuine = buildEncryptedFrame({ cmb, sessionId: client.sessionId, direction: s0.direction, sequence: s0.sequence, trafficKey: s0.trafficKey });
    // An injector knows the next sequence but not the key: it seals under a key of its own.
    const forged = buildEncryptedFrame({ cmb, sessionId: client.sessionId, direction: s0.direction, sequence: '0', trafficKey: crypto.randomBytes(32) });
    const take = (frame) => server.receive(frame.sequence, frame.direction, (trafficKey) => openEncryptedFrame({ frame, trafficKey }));
    assert.throws(() => take(forged), (e) => e.name !== 'SessionDesyncError', 'refused as unauthentic, not as out of order');
    assert.strictEqual(server.nextRecv, '0', 'the counter did not move');
    assert.ok(take(genuine), 'so the genuine frame 0 still opens: the session is not desynchronised');
    // A forged frame claiming a gap sequence cannot tear the session down either.
    const forgedGap = buildEncryptedFrame({ cmb, sessionId: client.sessionId, direction: s0.direction, sequence: '7', trafficKey: crypto.randomBytes(32) });
    assert.throws(() => take(forgedGap), (e) => e.name !== 'SessionDesyncError');
    assert.strictEqual(server.nextRecv, '1');
  });

  it('refuses a frame whose declared direction is not this session\'s receive direction', () => {
    const { client, server } = confirm(pair());
    // The server receives c2s; a frame claiming s2c must be refused before any key use.
    assert.throws(() => server.receive('0', S2C, () => assert.fail('no key is used for the wrong direction')), /receive direction/);
  });
});
