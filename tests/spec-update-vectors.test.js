'use strict';

/**
 * The MMP 2.0 update 1 artifacts sym vendors (tests/fixtures, from meshcognition-website PR #43,
 * branch spec/mmp-2.0-update-1 at 2660ab9; SOURCES.json records each digest), checked as copies, and
 * the reference construction (scripts/mmp/lib.mjs, vendored as mmp-lib.mjs) run beside sym's own code
 * on the same inputs: what sym builds, the reference builds byte for byte.
 */

const { describe, it, before } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { buildControlFrame, openControlSealed, parseControlPlain, controlAAD, neverInner } = require('../lib/core/sealed-control');
const { canonicalRecordV2_0 } = require('../lib/core/record-canonical');
const { recordBytes, textBytes, MAX_CATEGORY_BYTES, MAX_RECORD_TEXT_BYTES, MAX_RECORD_BYTES, MAX_SEALED_CHARS } = require('../lib/core/cmb-encoder');
const { canonicalJSON } = require('../lib/core/verified-receipt');
const { CAT7_CATEGORIES } = require('../lib/core/cmb');

const FIX = path.join(__dirname, 'fixtures');
const sources = JSON.parse(fs.readFileSync(path.join(FIX, 'SOURCES.json'), 'utf8'));
const vendored = (name) => JSON.parse(fs.readFileSync(path.join(FIX, name), 'utf8'));

describe('the vendored MMP 2.0 update 1 artifacts are the published copies', () => {
  for (const [name, { sha256 }] of Object.entries(sources.files)) {
    it(name, () => {
      const bytes = fs.readFileSync(path.join(FIX, name));
      assert.strictEqual(crypto.createHash('sha256').update(bytes).digest('hex'), sha256);
    });
  }
});

describe('control-encrypted-v2 (§7.1, §18.2.1)', () => {
  const v = vendored('control-encrypted-v2.json');
  for (const c of v.cases) {
    it(`${c.direction} ${c.sequence}: ${c.inner.type} seals to the vector's bytes and opens to its inner frame`, () => {
      const trafficKey = Buffer.from(c.trafficKeyHex, 'hex');
      assert.strictEqual(controlAAD({ sessionId: v.sessionId, direction: c.direction, sequence: c.sequence }).toString('hex'), c.aadHex);
      assert.strictEqual(JSON.stringify(c.inner), c.plaintextUtf8);
      const built = buildControlFrame({ frame: c.inner, sessionId: v.sessionId, direction: c.direction, sequence: c.sequence, trafficKey });
      assert.deepStrictEqual(built, c.frame);
      assert.deepStrictEqual(parseControlPlain(openControlSealed({ frame: c.frame, trafficKey })), c.inner);
    });
  }
  it('an authentic envelope whose inner frame §7.1 forbids opens, and its inner frame is refused', () => {
    const r = v.innerRefused;
    const trafficKey = Buffer.from(r.trafficKeyHex, 'hex');
    assert.strictEqual(r.expected.opens, true);
    const plain = openControlSealed({ frame: r.frame, trafficKey }); // opens: the position is taken
    assert.strictEqual(plain.toString('utf8'), r.plaintextUtf8);
    assert.throws(() => parseControlPlain(plain), /not a control frame/);
    // The session-level half (nextSequence, sessionOpen) is tests/spec-update-session.test.js S4.
  });
});

describe('the reference construction (scripts/mmp/lib.mjs) and sym agree', () => {
  let L;
  before(async () => { L = await import(path.join(FIX, 'mmp-lib.mjs')); });

  it('the size limits', () => {
    assert.strictEqual(L.MAX_CATEGORY_TEXT, MAX_CATEGORY_BYTES);
    assert.strictEqual(L.MAX_RECORD_TEXT, MAX_RECORD_TEXT_BYTES);
    assert.strictEqual(L.MAX_RECORD_BYTES, MAX_RECORD_BYTES);
    assert.strictEqual(L.MAX_SEALED_RECORD_CHARS, MAX_SEALED_CHARS);
  });

  it('the control AAD, and which frames never travel sealed in a control envelope', () => {
    for (const direction of ['client-to-server', 'server-to-client']) {
      for (const sequence of ['0', '1', '4294967296']) {
        const sessionId = crypto.randomBytes(16).toString('hex');
        assert.deepStrictEqual(controlAAD({ sessionId, direction, sequence }), L.controlAADV2({ sessionId, direction, sequence }));
      }
    }
    const registry = vendored('frame-registry.json');
    const types = [...new Set([...registry.frames.map((f) => f.type), 'relay-fanout', 'relay-challenge', 'sym-attest-attestation'])];
    for (const t of types) assert.strictEqual(neverInner(t), L.controlInnerForbidden(t), t);
  });

  it('the record projection, on every accepted record-projection-v2 case', () => {
    const v = vendored('record-projection-v2.json');
    for (const c of v.cases.filter((x) => x.expected.accepted)) {
      const ref = L.recordProjectionV2(c.record);
      assert.strictEqual(ref.ok, true);
      const p = canonicalRecordV2_0(c.record);
      assert.strictEqual(canonicalJSON(p), canonicalJSON(ref.projection), c.label);
    }
  });

  it('the size measures, on every record-size-v2 case', () => {
    const v = vendored('record-size-v2.json');
    for (const c of v.cases) {
      const r = JSON.parse(JSON.stringify(v.base));
      for (const [f, { unit, count }] of Object.entries(c.fill || {})) r.categories[f].text = unit.repeat(count);
      if (c.applicationBytes !== undefined) {
        const bytes = Buffer.alloc(c.applicationBytes, 0x61);
        r.metadata.application = { mediaType: 'application/octet-stream', schema: 'https://meshcognition.org/schema/size-fixture-v1.json', encoding: 'base64url', byteLength: bytes.length, digest: `sha256-${crypto.createHash('sha256').update(bytes).digest('hex')}`, data: bytes.toString('base64url') };
      }
      const ref = L.recordSize(r);
      assert.strictEqual(recordBytes(r), ref.recordBytes, c.label);
      for (const f of CAT7_CATEGORIES) assert.strictEqual(textBytes(r.categories[f].text), ref.categoryTextBytes[f], `${c.label}: ${f}`);
    }
  });
});
