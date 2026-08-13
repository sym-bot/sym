'use strict';

// MMP v2.0 verification-receipt conformance — the emitting half of xmesh-core's
// verified-record boundary. Two guarantees are proven here:
//
//   1. recordDigest is BYTE-IDENTICAL to @sym-bot/xmesh-core verified-record.recordDigest.
//      The canonical public v2.0 record digests to the SAME hex on both sides; if the
//      canonicalisation drifts by one byte, every honest network record refuses at
//      xmesh-core's digest check. The pinned constant is what xmesh-core's own function
//      produced (verified-record.recordDigest(fixture)).
//
//   2. A receipt is emitted IFF sym itself verified the record, and it is bound to the exact
//      bytes verified. Each of the eight fields the audit names — signature, author nodeId,
//      application digest, room, recipient, timestamp, address, assertion id — when mutated,
//      (a) yields no receipt from verifyAndAttest, and (b) breaks the honest receipt's digest,
//      so a mutated record forwarded with the honest receipt is refused at xmesh-core too.

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { recordDigest, verificationReceipt, verifyAndAttest, canonicalJSON } = require('../lib/core/verified-receipt');

// What xmesh-core/lib/verified-record.recordDigest produces for the canonical public record.
// Recomputed there, pinned here — the cross-package byte-for-byte contract.
const XMESH_CORE_CANONICAL_DIGEST = '7732c274f1ba18beb1227853850cbd0ad2e72f81400aefdb1e0c37f42bc75965';

const publicRecord = require('./mmp-v2-public-record.vector.json');
const sigVec = require('./mmp-v2-record-signature.vector.json');
const PUB = sigVec.testKey.publicKeyBase64url;
const validRecord = sigVec.cases[0].record; // a fully-signed v2.0 record that verifies against PUB

const clone = (o) => JSON.parse(JSON.stringify(o));

describe('MMP v2.0 verification receipt', () => {
  it('recordDigest is byte-identical to xmesh-core on the canonical public record', () => {
    assert.strictEqual(recordDigest(publicRecord), XMESH_CORE_CANONICAL_DIGEST);
  });

  it('canonicalJSON sorts object keys and is stable regardless of input order', () => {
    const a = canonicalJSON({ b: 1, a: { d: 4, c: 3 } });
    const b = canonicalJSON({ a: { c: 3, d: 4 }, b: 1 });
    assert.strictEqual(a, b);
    assert.strictEqual(a, '{"a":{"c":3,"d":4},"b":1}');
  });

  it('emits a well-formed receipt for a record sym itself verified', () => {
    const r = verifyAndAttest(validRecord, PUB);
    assert.strictEqual(r.ok, true, `expected attestation, got ${JSON.stringify(r)}`);
    assert.deepStrictEqual(Object.keys(r.receipt).sort(),
      ['assertionId', 'protocolVersion', 'recordDigest', 'signatureSuite', 'verified'].sort());
    assert.strictEqual(r.receipt.verified, true);
    assert.strictEqual(r.receipt.protocolVersion, '2.0');
    assert.strictEqual(r.receipt.signatureSuite, 'mmp-sig-v2.0');
    assert.strictEqual(r.receipt.assertionId, validRecord.metadata.assertionId);
    assert.strictEqual(r.receipt.recordDigest, recordDigest(validRecord));
  });

  it('refuses to attest a record whose public key does not match', () => {
    const wrongPub = sigVec.testKey.publicKeyBase64url.replace(/^./, (c) => (c === 'A' ? 'B' : 'A'));
    const r = verifyAndAttest(validRecord, wrongPub);
    assert.strictEqual(r.ok, false);
  });

  // The eight audit mutations. Each must (a) produce no receipt and (b) break the honest digest.
  const honestReceipt = verificationReceipt(validRecord);
  const mutations = {
    'signature': (m) => { m.metadata.sig = m.metadata.sig.replace(/^./, (c) => (c === 'a' ? 'b' : 'a')); },
    'author nodeId': (m) => { m.metadata.createdByNodeId = '018f47a0-0000-7abc-8def-000000000000'; },
    'application digest': (m) => { m.metadata.application = { action: 'inject', args: [1, 2, 3] }; },
    'room': (m) => { m.metadata.room = 'attacker-room'; },
    'recipient (to)': (m) => { m.metadata.to = '018f47a0-7b21-7abc-8def-000000000000'; },
    'timestamp': (m) => { m.metadata.createdTimestamp = m.metadata.createdTimestamp + 86_400_000; },
    'address (key)': (m) => { m.metadata.key = 'cmb-' + '0'.repeat(64); },
    'assertion id': (m) => { m.metadata.assertionId = 'asrt-' + '0'.repeat(64); },
  };

  for (const [label, mutate] of Object.entries(mutations)) {
    it(`refuses to attest a ${label} mutation, and the mutation breaks the honest digest`, () => {
      const m = clone(validRecord);
      mutate(m);
      // (a) sym emits no receipt for the mutated record.
      const r = verifyAndAttest(m, PUB);
      assert.strictEqual(r.ok, false, `${label}: expected refusal, got ${JSON.stringify(r)}`);
      // (b) the honest receipt no longer matches the mutated record's digest — xmesh-core refuses.
      assert.notStrictEqual(recordDigest(m), honestReceipt.recordDigest,
        `${label}: mutated record must not share the honest receipt's digest`);
    });
  }

  it('the assertion-id mutation is caught by receipt re-derivation, not by the signature', () => {
    // assertionId is NOT in the v2.0 signing preimage (it is derived FROM it), so a valid
    // signature does NOT fix it. Only the receipt emitter's re-derivation refuses a record whose
    // assertionId was swapped — the boundary's belt-and-braces closing a gap the signature leaves.
    const m = clone(validRecord);
    m.metadata.assertionId = 'asrt-' + 'f'.repeat(64);
    const r = verifyAndAttest(m, PUB);
    assert.strictEqual(r.ok, false);
    assert.strictEqual(r.error, 'assertion-id-mismatch');
  });
});
