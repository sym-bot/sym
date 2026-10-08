'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * Records as MMP 2.0 update 1 states them (#34 and #37, folded into spec/mmp-2.0-update-1 at
 * 2660ab9): one signed projection per assertion (D2), so every node holds one assertion as the same
 * bytes, and the record size measure. Each case of the record-projection-v2 and record-size-v2
 * vectors runs against sym's own code; the D2 tests fail on 018206d.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { canonicalRecordV2_0, RecordShapeError } = require('../lib/core/record-canonical');
const { verifyCMB } = require('../lib/core/cmb-signing');
const { createCMB, recordBytes, textBytes, MAX_RECORD_BYTES } = require('../lib/core/cmb-encoder');
const { canonicalJSON } = require('../lib/core/verified-receipt');
const { CAT7_CATEGORIES } = require('../lib/core/cmb');

const FIX = path.join(__dirname, 'fixtures');
const sources = JSON.parse(fs.readFileSync(path.join(FIX, 'SOURCES.json'), 'utf8'));
function vendored(name) {
  const bytes = fs.readFileSync(path.join(FIX, name));
  assert.strictEqual(crypto.createHash('sha256').update(bytes).digest('hex'), sources.files[name].sha256, `${name}: the vendored copy is the published one`);
  return JSON.parse(bytes.toString('utf8'));
}

describe('record-projection-v2: the canonical signed projection (#34, D2)', () => {
  const v = vendored('record-projection-v2.json');
  const key = v.testKey.publicKeyBase64url;
  for (const c of v.cases) {
    it(c.label, () => {
      if (c.expected.accepted) {
        const p = canonicalRecordV2_0(c.record);
        assert.deepStrictEqual(p, c.expected.projection);
        assert.strictEqual(crypto.createHash('sha256').update(canonicalJSON(p), 'utf8').digest('hex'), c.expected.projectionSha256, 'the same RFC 8785 bytes');
        assert.strictEqual(verifyCMB(p, key).valid, true, 'the projection verifies');
        assert.strictEqual(verifyCMB(c.record, key).valid, true, 'and so does the record as given');
      } else {
        let err = null;
        try { canonicalRecordV2_0(c.record); } catch (e) { err = e; }
        assert.ok(err instanceof RecordShapeError, `refused (${c.expected.refusedBy})`);
        if (/not NFC/.test(c.expected.refusedBy)) assert.match(err.reason, /not NFC/);
        else if (/meta\.key/.test(c.expected.refusedBy)) assert.strictEqual(err.reason, 'content-mismatch');
        else assert.doesNotMatch(err.reason, /not NFC|content-mismatch/, 'refused by the record schema');
      }
    });
  }

  it('every accepted variant of one assertion is one projection: the same bytes at every node', () => {
    const bySig = new Map();
    for (const c of v.cases.filter((x) => x.expected.accepted)) {
      const sig = c.record.metadata.sig;
      if (!bySig.has(sig)) bySig.set(sig, new Set());
      bySig.get(sig).add(canonicalJSON(canonicalRecordV2_0(c.record)));
    }
    assert.ok(bySig.size >= 2, 'several assertions among the accepted cases');
    assert.ok([...bySig.values()].some((forms) => forms.size === 1) && v.cases.filter((x) => x.expected.accepted).length > bySig.size, 'and some assertion comes in several variants');
    for (const forms of bySig.values()) assert.strictEqual(forms.size, 1);
  });

  it('a 256-character limit counts code points, as JSON Schema counts maxLength', () => {
    const base = v.cases[0].record;
    const astral = '\u{1F600}'.repeat(200); // 200 code points, 400 UTF-16 units
    const r = JSON.parse(JSON.stringify(base));
    r.metadata.createdBy = astral;
    let err = null;
    try { canonicalRecordV2_0(r); } catch (e) { err = e; }
    // Within the cap: it gets past the label check (and is then refused by nothing in step 1).
    assert.strictEqual(err, null, err && err.reason);
    r.metadata.createdBy = '\u{1F600}'.repeat(257);
    assert.throws(() => canonicalRecordV2_0(r), (e) => e.reason === 'createdBy is not a label');
  });
});

describe('rooms, application.schema and the application member on receipt (MMP 2.0 update 1)', () => {
  const v = vendored('record-projection-v2.json');
  // A published record with no application (record-projection-v2's own base case).
  const base = () => JSON.parse(JSON.stringify(v.cases.find((c) => c.label.startsWith('valence, arousal and lineage.method')).record));
  it('a record whose room is not a §5.8 identifier is refused', () => {
    for (const room of ['Conformance-Room', 'cafe\u0301', 'caf\u00e9', 'x'.repeat(65), 'a b']) {
      const r = base(); r.metadata.room = room;
      assert.throws(() => canonicalRecordV2_0(r), (e) => e.reason === 'room is not a §5.8 room identifier', room);
    }
  });
  it('an application whose schema is not NFC is refused; an absent application is held as null', () => {
    const r = base();
    r.metadata.application = { mediaType: 'application/json', schema: 'https://example.org/cafe\u0301', encoding: 'base64url', byteLength: 0, digest: `sha256-${crypto.createHash('sha256').update('').digest('hex')}`, data: '' };
    assert.throws(() => canonicalRecordV2_0(r), (e) => e.reason === 'application schema is not NFC');
    const absent = base(); delete absent.metadata.application;
    assert.strictEqual(canonicalRecordV2_0(absent).metadata.application, null);
  });
  it('a sealed record carries metadata.application, as encrypted-cmb-frame.schema.json requires', () => {
    const { buildEncryptedFrame } = require('../lib/core/cmb-encrypted-frame');
    const p = canonicalRecordV2_0(base());
    const f = buildEncryptedFrame({ cmb: p, applicationBytes: null, sessionId: 'a'.repeat(32), direction: 'client-to-server', sequence: '0', trafficKey: crypto.randomBytes(32) });
    assert.ok(Object.prototype.hasOwnProperty.call(f.metadata, 'application'));
    assert.strictEqual(f.metadata.application, null);
  });
});

describe('a node mints the canonical projection (D2)', () => {
  const cats = (focus) => Object.fromEntries(CAT7_CATEGORIES.map((f) => [f, f === 'focus' ? focus : (f === 'mood' ? { text: 'calm' } : `${f} text`)]));
  const P = (b) => `cmb-${b.repeat(64)}`;
  it('NFC text, createdBy and room; parents a sorted set; no parents is no lineage', () => {
    const nfd = 'café'; // "café" in NFD
    const r = createCMB({ categories: cats(nfd), createdBy: "zoe\u0308", room: "acme.prod", lineage: { parents: [P("f"), P("0"), P("f")], method: "SVAF-v2" }, categoryParents: { issue: ["z", "a", "z"] }, emitV2: true, createdByNodeId: crypto.randomUUID(), application: { mediaType: "application/json", schema: "https://example.org/cafe\u0301", encoding: "base64url", byteLength: 0, digest: `sha256-${crypto.createHash("sha256").update("").digest("hex")}`, data: "" } });
    assert.strictEqual(r.categories.focus.text, nfd.normalize("NFC"));
    assert.strictEqual(r.metadata.createdBy, "zo\u00eb");
    assert.strictEqual(r.metadata.application.schema, "https://example.org/caf\u00e9", "application.schema minted NFC");
    assert.throws(() => createCMB({ categories: cats("x"), createdBy: "a", room: "ro\u0301om" }), /§5\.8 room identifier/, "a room outside §5.8 is never minted");
    assert.deepStrictEqual(r.metadata.lineage.parents, [P('0'), P('f')]);
    assert.deepStrictEqual(r.categories.issue.meta.parents, ['a', 'z']);
    assert.strictEqual(createCMB({ categories: cats('x'), createdBy: 'a', lineage: { parents: [] } }).metadata.lineage, null);
  });

  it('a minted, signed record is its own projection', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const { signCMB, assertionIdV2_0 } = require('../lib/core/cmb-signing');
    const r = createCMB({ categories: cats('café'), createdBy: 'zoë', room: 'r', lineage: { parents: [P('f'), P('0')] }, emitV2: true, createdByNodeId: crypto.randomUUID() });
    r.metadata.assertionId = assertionIdV2_0(r);
    signCMB(r, privateKey.export({ format: 'jwk' }).d);
    const p = canonicalRecordV2_0(r);
    assert.strictEqual(r.metadata.application, null);
    assert.strictEqual(canonicalJSON(p), canonicalJSON({ categories: Object.fromEntries(CAT7_CATEGORIES.map((f) => [f, { text: r.categories[f].text, meta: r.categories[f].meta }])), metadata: { ...r.metadata, lineage: { parents: r.metadata.lineage.parents } } }));
    assert.strictEqual(verifyCMB(p, publicKey.export({ format: 'jwk' }).x).valid, true);
  });
});

describe('record-size-v2: one measure for MAX_RECORD_BYTES (#37)', () => {
  const v = vendored('record-size-v2.json');
  function expand(c) {
    const r = JSON.parse(JSON.stringify(v.base));
    for (const [f, { unit, count }] of Object.entries(c.fill || {})) r.categories[f].text = unit.repeat(count);
    if (c.applicationBytes !== undefined) {
      const bytes = Buffer.alloc(c.applicationBytes, 0x61);
      r.metadata.application = { mediaType: 'application/octet-stream', schema: 'https://meshcognition.org/schema/size-fixture-v1.json', encoding: 'base64url', byteLength: bytes.length, digest: `sha256-${crypto.createHash('sha256').update(bytes).digest('hex')}`, data: bytes.toString('base64url') };
    }
    return r;
  }
  for (const c of v.cases) {
    it(c.label, () => {
      const r = expand(c);
      for (const f of CAT7_CATEGORIES) assert.strictEqual(textBytes(r.categories[f].text), c.expected.categoryTextBytes[f], f);
      assert.strictEqual(recordBytes(r), c.expected.recordBytes);
      let refused = null;
      try { canonicalRecordV2_0(r); } catch (e) { refused = e; }
      const sizeRefused = !!(refused && /too long/.test(refused.reason));
      assert.strictEqual(!sizeRefused, c.expected.within, refused && refused.reason);
    });
  }

  it('a record\'s decoded payload beside it is not counted twice: the measure is the two-section record', () => {
    const r = expand({ fill: { focus: { unit: 'a', count: 95266 } }, applicationBytes: 480000 });
    assert.strictEqual(recordBytes(r), MAX_RECORD_BYTES);
    r.payload = { decoded: 'x'.repeat(1000) }; // what remember() keeps beside its own record
    assert.strictEqual(recordBytes(r), MAX_RECORD_BYTES);
  });
});
