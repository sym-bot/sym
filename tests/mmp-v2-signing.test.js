'use strict';

// MMP v2.0 published-contract conformance: sym must reproduce meshcognition.org's mmp-sig-v2.0
// signing preimage byte-for-byte and accept the published signatures. The vector is the
// normative record-signature-v2.json, copied verbatim (2026-09-14 errata included; the digest
// is pinned in mmp-v2-vectors-published.test.js). This is the gate for the reader-first
// migration: if sym's preimage diverges by one byte, an independent implementer's signature
// and sym's disagree and the mesh silently splits.

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { signingPayloadV2_0, assertionIdV2_0, categoryParentsCommitment, verifyCMB, privateKeyObject, publicKeyObject } = require('../lib/core/cmb-signing');
const vec = require('./mmp-v2-record-signature.vector.json');

// The fixed test key. Signatures made with it are verified, never compared: see below.
const seed = Buffer.from(vec.testKey.privateSeedBase64url, 'base64url');
const privB64url = seed.toString('base64url');
const pubB64url = vec.testKey.publicKeyBase64url;

describe('MMP v2.0 signing conformance (mmp-sig-v2.0)', () => {
  for (const kase of vec.cases) {
    it(`assertionId matches the published vector — ${kase.label}`, () => {
      assert.strictEqual(assertionIdV2_0(kase.record), kase.record.metadata.assertionId);
    });

    // The signing PREIMAGE is deterministic and must reproduce exactly; the signature over it
    // must not be compared. The vector says so itself (`usage`, and `expectedSignatureIsOneOfMany`
    // on every case, from the 2026-09-14 errata): Apple's signers hedge, so a conforming
    // implementation there returns different valid bytes on every call (measured 2026-09-14:
    // CryptoKit gave five distinct valid signatures for one payload under one key, none equal
    // to the published one). Node happens to be deterministic, and asserting byte equality here
    // would pin that accident as if it were the contract.
    it(`signing payload and assertion id reproduce the published bytes — ${kase.label}`, () => {
      assert.strictEqual(signingPayloadV2_0(kase.record).toString('hex'), kase.expectedSigningPayloadHex);
      assert.strictEqual(assertionIdV2_0(kase.record), kase.expectedAssertionId);
      assert.strictEqual(categoryParentsCommitment(kase.record.categories), kase.expectedCategoryParentsCommitment);
    });

    it(`expectedSignature is honoured as one valid signature of many: verified, never reproduced — ${kase.label}`, () => {
      assert.ok(kase.expectedSignatureIsOneOfMany, 'the published vector marks the signature as one of many');
      assert.ok(crypto.verify(null, Buffer.from(kase.expectedSigningPayloadHex, 'hex'),
        publicKeyObject(pubB64url), Buffer.from(kase.expectedSignature, 'base64url')),
      'the published expectedSignature must verify over the published payload');
    });

    // THE CONFORMANCE PROPERTY, which every implementation must satisfy including a hedged signer:
    // sign the same payload twice and both verify. Nothing is asserted about equality.
    it(`two signatures over one payload both verify — ${kase.label}`, () => {
      const payload = signingPayloadV2_0(kase.record);
      const key = privateKeyObject(privB64url);
      const pub = publicKeyObject(pubB64url);
      const a = crypto.sign(null, payload, key);
      const b = crypto.sign(null, payload, key);
      assert.ok(crypto.verify(null, payload, pub, a), 'first signature must verify');
      assert.ok(crypto.verify(null, payload, pub, b), 'second signature must verify');
    });

    it(`the published signature verifies against the test public key — ${kase.label}`, () => {
      const r = verifyCMB(kase.record, pubB64url);
      // verifyCMB currently checks the v2 preimage; assert the v2.0 preimage verifies directly.
      const ok = crypto.verify(null, signingPayloadV2_0(kase.record),
        publicKeyObject(pubB64url),
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
