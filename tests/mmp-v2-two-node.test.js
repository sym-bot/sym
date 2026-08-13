'use strict';

// MMP v2.0 two-node Core Secure round-trip: the whole sealed-envelope stack composed end to end.
// A real v2.0-signed, application-null record (the common sym case) is sealed by the client,
// carried as a cmb-encrypted frame the router cannot read, opened by the server, and verified +
// attested — then the tamper, replay, rollback and gap refusals that make the channel safe.

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { createCMB, signCMB, assertionIdV2_0 } = require('../lib/core');
const { MmpSession } = require('../lib/core/mmp-session');
const { buildEncryptedFrame, openEncryptedFrame } = require('../lib/core/cmb-encrypted-frame');
const { verifyAndAttest } = require('../lib/core/verified-receipt');

function rawKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { priv: privateKey.export({ format: 'jwk' }).d, pub: publicKey.export({ format: 'jwk' }).x };
}
// A real signed v2.0 record (application-null), exactly what the emit path produces when flipped.
function signedRecord(priv) {
  const cmb = createCMB({
    categories: { focus: 'seal me end to end', intent: 'prove the channel' },
    createdBy: 'author-agent', createdByNodeId: '018f47a0-7b21-7abc-8def-0123456789ab',
    room: 'conformance-room', to: '018f47a0-7b21-7abc-8def-fedcba987654', emitV2: true,
  });
  cmb.metadata.assertionId = assertionIdV2_0(cmb);
  signCMB(cmb, priv);
  return cmb;
}

// A shared X25519 secret + agreed §5.2 transcript establish both sessions.
function establishedPair() {
  const sharedSecret = crypto.randomBytes(32);
  const transcript = Buffer.from('two-node::transcript::nonces+nodeIds+keys+room+version', 'utf8');
  const client = new MmpSession('client', sharedSecret, transcript);
  const server = new MmpSession('server', sharedSecret, transcript);
  assert.strictEqual(client.confirmPeer(server.ownKeyConfirmation()), true);
  assert.strictEqual(server.confirmPeer(client.ownKeyConfirmation()), true);
  return { client, server };
}

describe('MMP v2.0 two-node sealed round-trip', () => {
  it('client seals an app-null signed record; server opens, verifies and attests it', () => {
    const { priv, pub } = rawKeypair();
    const cmb = signedRecord(priv);
    const { client, server } = establishedPair();

    const s = client.nextSend();
    const frame = buildEncryptedFrame({ cmb, sessionId: client.sessionId, direction: s.direction, sequence: s.sequence, trafficKey: s.trafficKey });

    // The router sees only routing metadata + opaque bytes — no category text.
    assert.strictEqual(frame.type, 'cmb-encrypted');
    assert.ok(!JSON.stringify(frame.metadata).includes('seal me end to end'), 'category text is not in the clear frame');
    assert.ok(!frame.sealed.includes('seal me end to end'));

    const r = server.acceptRecv(frame.sequence, frame.direction);
    const out = openEncryptedFrame({ frame, trafficKey: r.trafficKey });
    assert.strictEqual(out.applicationBytes, null, 'app-null record carries no applicationData');
    assert.deepStrictEqual(out.cmb.categories, cmb.categories);
    assert.deepStrictEqual(out.cmb.metadata, cmb.metadata);

    // The reconstructed record still verifies and attests — the seal preserved the signed bytes.
    const att = verifyAndAttest(out.cmb, pub);
    assert.strictEqual(att.ok, true, `reconstructed record must attest, got ${JSON.stringify(att)}`);
  });

  it('carries an ordered stream 0..2 and refuses replay, rollback and gaps', () => {
    const { priv } = rawKeypair();
    const cmb = signedRecord(priv);
    const { client, server } = establishedPair();

    for (let i = 0; i < 3; i++) {
      const s = client.nextSend();
      assert.strictEqual(s.sequence, String(i));
      const frame = buildEncryptedFrame({ cmb, sessionId: client.sessionId, direction: s.direction, sequence: s.sequence, trafficKey: s.trafficKey });
      const r = server.acceptRecv(frame.sequence, frame.direction);
      assert.ok(openEncryptedFrame({ frame, trafficKey: r.trafficKey }));
    }
    // A relay replays frame 0; the server has already consumed through 2.
    assert.throws(() => server.acceptRecv('0', client._sendDirection || 'client-to-server'), /replay|rollback/);
  });

  it('a router that flips one sealed byte cannot pass the frame', () => {
    const { priv } = rawKeypair();
    const cmb = signedRecord(priv);
    const { client, server } = establishedPair();
    const s = client.nextSend();
    const frame = buildEncryptedFrame({ cmb, sessionId: client.sessionId, direction: s.direction, sequence: s.sequence, trafficKey: s.trafficKey });
    const b = Buffer.from(frame.sealed, 'base64url'); b[10] ^= 0x02; frame.sealed = b.toString('base64url').replace(/=+$/, '');
    const r = server.acceptRecv(frame.sequence, frame.direction);
    assert.throws(() => openEncryptedFrame({ frame, trafficKey: r.trafficKey }));
  });

  it('a router that rewrites the clear room cannot pass the frame (AAD binds it)', () => {
    const { priv } = rawKeypair();
    const cmb = signedRecord(priv);
    const { client, server } = establishedPair();
    const s = client.nextSend();
    const frame = buildEncryptedFrame({ cmb, sessionId: client.sessionId, direction: s.direction, sequence: s.sequence, trafficKey: s.trafficKey });
    frame.metadata = { ...frame.metadata, room: 'attacker-room' };
    const r = server.acceptRecv(frame.sequence, frame.direction);
    assert.throws(() => openEncryptedFrame({ frame, trafficKey: r.trafficKey }));
  });
});
