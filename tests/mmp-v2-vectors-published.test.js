'use strict';

// The v2 conformance vectors in this directory are the PUBLISHED files, byte for byte — not
// local edits of them. The SDK's copies of record-signature and handshake once drifted from
// the published ones: they lacked the 2026-09-14 errata fields (`usage`,
// `expectedSignatureIsOneOfMany`) that tell an implementer to verify signatures rather than
// reproduce them, so the SDK's tests went on asserting the opposite of the contract. A digest
// pin makes any such drift fail here instead of silently.
//
// Source: meshcognition.org/spec/mmp/conformance/v2/ (repository meshcognition-website,
// public/spec/mmp/conformance/v2/; mirrored in mesh-memory-protocol/conformance/v2/), whose
// artifact-manifest.json pins these same sha256 digests. To update: copy the published file
// verbatim and replace its digest below from that manifest — never edit a vector by hand.

const { test } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PUBLISHED = {
  'mmp-v2-application.vector.json': ['application-v2.json', '28ef0e7a7a7f2fb1e85a8a35b2f899962a648193e61717165540e5f4b842eb30'],
  'mmp-v2-e2e.vector.json': ['e2e-v2.json', '3e5d4adec0137a01f85c98cacba5c8d65b5d603d02085149f950c3d5ea77dbdc'],
  'mmp-v2-handshake.vector.json': ['handshake-v2.json', 'c93a8440c29b07b08cccd9b0ec51008f98bfd3f631e9a654f631cb391dfe3125'],
  'mmp-v2-record-signature.vector.json': ['record-signature-v2.json', '3725744c2162e3d9f2a6fb9499253057cff018ff1148ea934861826d033018d7'],
};

for (const [local, [published, digest]] of Object.entries(PUBLISHED)) {
  test(`${local} is the published conformance/v2/${published}, byte for byte`, () => {
    const bytes = fs.readFileSync(path.join(__dirname, local));
    assert.strictEqual(crypto.createHash('sha256').update(bytes).digest('hex'), digest);
  });
}
