'use strict';

// MMP v2.0 emitter flip (1a): the reader-first-gated emission path. Proves that when v2.0
// emission is enabled, the encoder + signing layer produce a record that sym itself verifies
// AND attests through the verified-record receipt emitter — i.e. the live emit path can emit
// records xmesh-core will admit. Default (flag off) emission is unchanged: no v2.0 fields.

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { createCMB, signCMB, assertionIdV2_0 } = require('../lib/core');
const { verifyAndAttest } = require('../lib/core/verified-receipt');

// Fresh raw Ed25519 keypair as base64url (seed / public), the shape signCMB/verifyCMB expect.
function rawKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    priv: privateKey.export({ format: 'jwk' }).d,   // 32-byte seed, base64url
    pub: publicKey.export({ format: 'jwk' }).x,      // 32-byte public, base64url
  };
}

// Mirror exactly what lib/emit.js does when MMP_EMIT_V2 is on.
function emitV2Record({ categories, createdBy, createdByNodeId, room, to, priv }) {
  const cmb = createCMB({ categories, createdBy, room: room ?? null, to: to ?? null, emitV2: true, createdByNodeId });
  cmb.metadata.assertionId = assertionIdV2_0(cmb);
  signCMB(cmb, priv);
  return cmb;
}

describe('MMP v2.0 emitter flip', () => {
  it('flag OFF (default): emission carries no v2.0 fields and signs under the internal suite', () => {
    const cmb = createCMB({ categories: { focus: 'ship the reader' }, createdBy: 'agent-a' });
    assert.ok(!('signatureSuite' in cmb.metadata), 'no signatureSuite by default');
    assert.ok(!('addressScheme' in cmb.metadata), 'no addressScheme by default');
    assert.ok(!('createdByNodeId' in cmb.metadata), 'no createdByNodeId by default');
  });

  it('flag ON: the emitted record verifies AND attests through the receipt emitter', () => {
    const { priv, pub } = rawKeypair();
    const cmb = emitV2Record({
      categories: { focus: 'publish v2.0 conformance', intent: 'interoperate' },
      createdBy: 'agent-a',
      createdByNodeId: '018f47a0-7b21-7abc-8def-0123456789ab',
      room: 'conformance-room',
      priv,
    });

    assert.strictEqual(cmb.metadata.signatureSuite, 'mmp-sig-v2.0');
    assert.strictEqual(cmb.metadata.addressScheme, 'mmp-cmb-merkle-v2');
    assert.ok(cmb.metadata.assertionId.startsWith('asrt-'));

    const r = verifyAndAttest(cmb, pub);
    assert.strictEqual(r.ok, true, `live-emitted v2.0 record must attest, got ${JSON.stringify(r)}`);
    assert.strictEqual(r.receipt.assertionId, cmb.metadata.assertionId);
    assert.strictEqual(r.receipt.signatureSuite, 'mmp-sig-v2.0');
  });

  it('flag ON without createdByNodeId fails closed at construction', () => {
    assert.throws(
      () => createCMB({ categories: { focus: 'x' }, createdBy: 'agent-a', emitV2: true }),
      /emitV2 requires createdByNodeId/,
    );
  });

  it('a tampered category on a v2.0-emitted record fails verification (content address bound)', () => {
    const { priv, pub } = rawKeypair();
    const cmb = emitV2Record({
      categories: { focus: 'original claim' }, createdBy: 'agent-a',
      createdByNodeId: '018f47a0-7b21-7abc-8def-0123456789ab', room: 'r', priv,
    });
    cmb.categories.focus.text = 'rewritten in flight';
    const r = verifyAndAttest(cmb, pub);
    assert.strictEqual(r.ok, false, 'a rewritten category must not attest');
  });
});
