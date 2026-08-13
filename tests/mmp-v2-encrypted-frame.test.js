'use strict';

// MMP v2.0 cmb-encrypted frame codec conformance. Proves the codec reproduces the published
// e2e-v2.json vector byte-for-byte (protected plaintext + sealed frame), round-trips, and refuses
// a frame whose clear metadata or sealed bytes were altered (AEAD-bound), or opened at the wrong
// position (wrong nonce).

const { describe, it } = require('node:test');
const assert = require('node:assert');
const {
  buildEncryptedFrame, openEncryptedFrame, protectedPlaintext, nonceForSequence, FRAME_TYPE, SUITE,
} = require('../lib/core/cmb-encrypted-frame');

const vec = require('./mmp-v2-e2e.vector.json');
// The vector's protected plaintext splits into the record's categories and its application bytes.
const plain = JSON.parse(vec.protectedPlaintextUtf8);
const categories = plain.categories;
const applicationBytes = Buffer.from(plain.applicationData, 'base64url');
const cmb = { categories, metadata: vec.metadata };

describe('MMP v2.0 cmb-encrypted frame codec', () => {
  it('reconstructs the protected plaintext byte-for-byte', () => {
    assert.strictEqual(
      protectedPlaintext(categories, applicationBytes).toString('utf8'),
      vec.protectedPlaintextUtf8,
    );
  });

  it('the 96-bit BE nonce matches the vector for each sequence', () => {
    for (const c of vec.cases) {
      assert.strictEqual(nonceForSequence(c.sequence).toString('hex'), c.nonceHex);
    }
  });

  for (const c of vec.cases) {
    it(`builds a byte-exact cmb-encrypted frame — ${c.direction} seq ${c.sequence}`, () => {
      const frame = buildEncryptedFrame({
        cmb, applicationBytes,
        sessionId: vec.sessionId, direction: c.direction, sequence: c.sequence,
        trafficKey: Buffer.from(c.trafficKeyHex, 'hex'),
      });
      assert.strictEqual(frame.type, FRAME_TYPE);
      assert.strictEqual(frame.suite, SUITE);
      assert.strictEqual(frame.protocolVersion, '2.0');
      assert.strictEqual(frame.sessionId, vec.sessionId);
      assert.strictEqual(frame.sequence, c.sequence);
      assert.strictEqual(frame.direction, c.direction);
      assert.deepStrictEqual(frame.metadata, vec.metadata);
      assert.strictEqual(frame.sealed, c.sealedBase64url, 'sealed bytes must match the published vector');
    });

    it(`opens its own frame back to the record — ${c.direction} seq ${c.sequence}`, () => {
      const trafficKey = Buffer.from(c.trafficKeyHex, 'hex');
      const frame = buildEncryptedFrame({ cmb, applicationBytes, sessionId: vec.sessionId, direction: c.direction, sequence: c.sequence, trafficKey });
      const out = openEncryptedFrame({ frame, trafficKey });
      assert.deepStrictEqual(out.cmb.categories, categories);
      assert.deepStrictEqual(out.cmb.metadata, vec.metadata);
      assert.strictEqual(out.applicationBytes.toString('base64url').replace(/=+$/, ''), plain.applicationData);
    });
  }

  const c0 = vec.cases[0];
  const tkey0 = Buffer.from(c0.trafficKeyHex, 'hex');

  it('refuses a frame whose clear metadata was altered (AAD binds routing identity)', () => {
    const frame = buildEncryptedFrame({ cmb, applicationBytes, sessionId: vec.sessionId, direction: c0.direction, sequence: c0.sequence, trafficKey: tkey0 });
    frame.metadata = { ...frame.metadata, room: 'attacker-room' };
    assert.throws(() => openEncryptedFrame({ frame, trafficKey: tkey0 }));
  });

  it('refuses a frame whose sealed bytes were flipped', () => {
    const frame = buildEncryptedFrame({ cmb, applicationBytes, sessionId: vec.sessionId, direction: c0.direction, sequence: c0.sequence, trafficKey: tkey0 });
    const b = Buffer.from(frame.sealed, 'base64url'); b[0] ^= 0x01;
    frame.sealed = b.toString('base64url').replace(/=+$/, '');
    assert.throws(() => openEncryptedFrame({ frame, trafficKey: tkey0 }));
  });

  it('refuses to open at the wrong position (sequence rebind → wrong nonce/AAD)', () => {
    const frame = buildEncryptedFrame({ cmb, applicationBytes, sessionId: vec.sessionId, direction: c0.direction, sequence: '0', trafficKey: tkey0 });
    frame.sequence = '1'; // a relay trying to replay frame 0 as frame 1
    assert.throws(() => openEncryptedFrame({ frame, trafficKey: tkey0 }));
  });

  it('refuses the wrong directional traffic key (cross-direction)', () => {
    const c2s = vec.cases.find((c) => c.direction === 'client-to-server');
    const s2c = vec.cases.find((c) => c.direction === 'server-to-client');
    const frame = buildEncryptedFrame({ cmb, applicationBytes, sessionId: vec.sessionId, direction: c2s.direction, sequence: c2s.sequence, trafficKey: Buffer.from(c2s.trafficKeyHex, 'hex') });
    assert.throws(() => openEncryptedFrame({ frame, trafficKey: Buffer.from(s2c.trafficKeyHex, 'hex') }));
  });
});
