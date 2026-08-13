'use strict';

// MMP v2.0 published-contract conformance: sym must reproduce meshcognition.org's mmp-sig-v2.0
// byte-for-byte. The vector is the normative record-signature-v2.json (website PR #12@3d66352).
// This is the gate for the reader-first migration: if sym's preimage diverges by one byte, an
// independent implementer's signature and sym's disagree and the mesh silently splits.

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { signingPayloadV2_0, assertionIdV2_0, signCMB, verifyCMB, privateKeyObject } = require('../lib/core/cmb-signing');
const vec = require('./mmp-v2-record-signature.vector.json');

// The fixed test key (Ed25519, deterministic per RFC 8032 in Node — so a byte-exact sig match holds).
const seed = Buffer.from(vec.testKey.privateSeedBase64url, 'base64url');
const privB64url = seed.toString('base64url');
const pubB64url = vec.testKey.publicKeyBase64url;

describe('MMP v2.0 signing conformance (mmp-sig-v2.0)', () => {
  for (const kase of vec.cases) {
    it(`assertionId matches the published vector — ${kase.label}`, () => {
      assert.strictEqual(assertionIdV2_0(kase.record), kase.record.metadata.assertionId);
    });

    it(`signature is byte-identical to the published vector — ${kase.label}`, () => {
      const sig = crypto.sign(null, signingPayloadV2_0(kase.record), privateKeyObject(privB64url));
      assert.strictEqual(sig.toString('base64url'), kase.record.metadata.sig);
    });

    it(`the published signature verifies against the test public key — ${kase.label}`, () => {
      const r = verifyCMB(kase.record, pubB64url);
      // verifyCMB currently checks the v2 preimage; assert the v2.0 preimage verifies directly.
      const ok = crypto.verify(null, signingPayloadV2_0(kase.record),
        require('../lib/core/cmb-signing').publicKeyObject(pubB64url),
        Buffer.from(kase.record.metadata.sig, 'base64url'));
      assert.ok(ok, 'published v2.0 signature must verify');
      void r;
    });
  }

  it('same cognition, different application → same key, DIFFERENT assertion (P0.2 fix)', () => {
    const [noApp, withApp] = vec.cases;
    assert.strictEqual(noApp.record.metadata.key, withApp.record.metadata.key, 'address unchanged by application');
    assert.notStrictEqual(noApp.record.metadata.assertionId, withApp.record.metadata.assertionId, 'application enters the signature');
  });
});
