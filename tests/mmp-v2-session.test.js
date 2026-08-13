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
    assert.throws(() => server.acceptRecv('0', C2S), /unconfirmed/);
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
    const r = server.acceptRecv(frame.sequence, frame.direction);
    const out = openEncryptedFrame({ frame, trafficKey: r.trafficKey });
    assert.deepStrictEqual(out.cmb.categories, cmb.categories);
    // server → client
    const s2 = server.nextSend();
    assert.strictEqual(s2.direction, S2C);
    const frame2 = buildEncryptedFrame({ cmb, sessionId: server.sessionId, direction: s2.direction, sequence: s2.sequence, trafficKey: s2.trafficKey });
    const r2 = client.acceptRecv(frame2.sequence, frame2.direction);
    assert.ok(openEncryptedFrame({ frame: frame2, trafficKey: r2.trafficKey }));
  });

  it('sequence starts at 0 and advances by exactly one per direction', () => {
    const { client, server } = confirm(pair());
    assert.strictEqual(client.nextSend().sequence, '0');
    assert.strictEqual(client.nextSend().sequence, '1');
    assert.strictEqual(client.nextSend().sequence, '2');
    // server's send counter is independent
    assert.strictEqual(server.nextSend().sequence, '0');
  });

  it('refuses replay, rollback, and gaps on the receive side', () => {
    const { client, server } = confirm(pair());
    assert.ok(server.acceptRecv('0', C2S));            // exact-next
    assert.throws(() => server.acceptRecv('0', C2S), /replay|rollback/); // replay of 0
    assert.throws(() => server.acceptRecv('2', C2S), /gap/);             // skip 1
    assert.ok(server.acceptRecv('1', C2S));            // 1 is now exact-next
    assert.throws(() => server.acceptRecv('0', C2S), /replay|rollback/); // rollback below 2
  });

  it('refuses a frame whose declared direction is not this session\'s receive direction', () => {
    const { client, server } = confirm(pair());
    // The server receives c2s; a frame claiming s2c must be refused before any key use.
    assert.throws(() => server.acceptRecv('0', S2C), /receive direction/);
  });
});
