'use strict';

// MMP v2.0 application commitment conformance (mmp-app-v1). The application section is the
// one place a record carries opaque, actionable bytes (a deploy instruction, a tool call), and
// the record signature commits to it only through this commitment. So sym must reproduce the
// published commitment exactly for both the absent and the present case, and must refuse a
// section whose bytes no longer match what it declares — otherwise a relay could alter the
// payload under a valid signature. Vector: the published application-v2.json, copied verbatim
// (digest pinned in mmp-v2-vectors-published.test.js).

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { applicationCommitmentV1 } = require('../lib/core/cmb-signing');
const vec = require('./mmp-v2-application.vector.json');
const sigVec = require('./mmp-v2-record-signature.vector.json');

describe('MMP v2.0 application commitment conformance (mmp-app-v1)', () => {
  it('the vector is the mmp-app-v1 construction for protocol 2.0', () => {
    assert.strictEqual(vec.protocolVersion, '2.0');
    assert.strictEqual(vec.construction, 'mmp-app-v1');
  });

  for (const c of vec.cases) {
    it(`commitment reproduces the published bytes — ${c.label}`, () => {
      assert.strictEqual(applicationCommitmentV1(c.application), c.expectedCommitment);
    });
  }

  const present = vec.cases.find((c) => c.application);
  const absent = vec.cases.find((c) => c.application === null);

  it('absent and present are distinct commitments (an absent section is not an empty one)', () => {
    assert.notStrictEqual(absent.expectedCommitment, present.expectedCommitment);
    assert.strictEqual(applicationCommitmentV1(undefined), absent.expectedCommitment, 'undefined is absent too');
  });

  it('the present case carries exactly the bytes it declares', () => {
    const bytes = Buffer.from(present.application.data, 'base64url');
    assert.strictEqual(bytes.toString('utf8'), present.decodedDataUtf8);
    assert.strictEqual(bytes.length, present.application.byteLength);
    assert.strictEqual(`sha256-${crypto.createHash('sha256').update(bytes).digest('hex')}`, present.application.digest);
  });

  it('one changed payload byte is refused, not committed to', () => {
    const bytes = Buffer.from(present.application.data, 'base64url');
    bytes[0] ^= 0x01;
    const tampered = { ...present.application, data: bytes.toString('base64url') };
    assert.throws(() => applicationCommitmentV1(tampered), /digest mismatch/);
  });

  it('a declared length that does not match the bytes is refused', () => {
    assert.throws(() => applicationCommitmentV1({ ...present.application, byteLength: present.application.byteLength + 1 }), /byteLength mismatch/);
  });

  it('padded or non-canonical base64url is refused (one payload, one encoding)', () => {
    assert.throws(() => applicationCommitmentV1({ ...present.application, data: `${present.application.data}=` }), /unpadded base64url/);
  });

  it('the record-signature vector signs this same section (the two vectors agree)', () => {
    const withApp = sigVec.cases.find((k) => k.record.metadata.application);
    assert.deepStrictEqual(withApp.record.metadata.application, present.application);
  });
});
