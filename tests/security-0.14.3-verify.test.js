'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * sym 0.14.3 security review (R2): the record verifier's findings, each a regression test that fails on
 * 632b95d for its own reason.
 *
 *   R2-12  the public verifyCMB reported a record carrying unsigned members, a wrong assertionId, or a
 *          0.13-suite record with an attached application, as valid:true
 *   R2-13  a lone surrogate encodes as U+FFFD, so one signature verified two strings (and, review M2,
 *          refusing it dropped a 0.14.2 author's record cut inside a surrogate pair: it is held as U+FFFD)
 *   R2-14  non-canonical base64url spellings of one key or signature were accepted
 *   R2-21  an invite parse error echoed the URL, relay token included
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const pub = require('../lib/public/core');
const core = require('../lib/core');
const { verifyStrict } = require('../lib/core/ed25519');
const { canonicalRecordV2_0 } = require('../lib/core/record-canonical');
const { isIdentityKey } = require('../lib/roster-keys');
const { grantShapeReason } = require('../lib/core/room-grant');
const { parseInvite } = require('../lib/invite');
const { identity, signedRecord, applicationFor } = require('./_core-secure');

const alice = identity('alice');
const copy = (o) => JSON.parse(JSON.stringify(o));
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
/** Every spelling of a base64url string whose last character carries `usedMask` bits, the canonical one first. */
function spellings(s, usedMask) {
  const i = B64.indexOf(s[s.length - 1]);
  const out = [s];
  for (let j = 0; j < 64; j++) if (j !== i && (j & usedMask) === (i & usedMask)) out.push(s.slice(0, -1) + B64[j]);
  return out;
}
/** A 0.13-suite (mmp-sig-v2) record, as a 0.13 node minted and signed it. */
function legacyRecord(author = alice) {
  const r = core.createCMB({ categories: { focus: 'deploy finished', mood: { text: 'calm', valence: 0.2 } }, createdBy: author.name, room: 'default' });
  core.signCMB(r, author.privateKey);
  return r;
}

describe('R2-12: the public verifyCMB checks the record\'s own bytes, and says which suite signed it', () => {
  it('R2-12: a v2.0 record carrying a member its signature does not cover is invalid', () => {
    const base = signedRecord(alice, { categories: { focus: 'v2.0 observation' } });
    assert.strictEqual(pub.verifyCMB(copy(base), alice.publicKey).valid, true, 'the untouched record verifies');
    const cases = {
      'metadata.approved': (r) => { r.metadata.approved = true; },
      'top-level payload': (r) => { r.payload = { action: 'rm -rf' }; },
      'a category member': (r) => { r.categories.focus.weight = 9; },
      'a meta member': (r) => { r.categories.issue.meta.trusted = true; },
      'a lineage member': (r) => { r.metadata.lineage = { parents: [], approvedBy: 'root' }; },
    };
    for (const [what, mutate] of Object.entries(cases)) {
      const r = copy(base); mutate(r);
      const v = pub.verifyCMB(r, alice.publicKey);
      assert.strictEqual(v.valid, false, `${what}: ${JSON.stringify(v)}`);
      assert.strictEqual(v.coreSecure, false, what);
    }
  });

  it('R2-12: a v2.0 record naming another assertionId is invalid, checked before the signature', () => {
    const r = copy(signedRecord(alice, { categories: { focus: 'v2.0 observation' } }));
    r.metadata.assertionId = 'asrt-' + '0'.repeat(64);
    const v = pub.verifyCMB(r, alice.publicKey);
    assert.strictEqual(v.valid, false);
    assert.strictEqual(v.error, 'assertion-id-mismatch');
    // Under the wrong key too: the assertion identity is refused first, never called a forgery.
    assert.strictEqual(pub.verifyCMB(r, identity('other').publicKey).error, 'assertion-id-mismatch');
  });

  it('R2-12: a genuine v2.0 record is valid and Core Secure, with its assertionId and its signed projection', () => {
    const r = signedRecord(alice, { categories: { focus: 'v2.0 observation', mood: { text: 'calm' } } });
    const wire = copy(r);
    wire.categories.mood.valence = -1; // carried, unsigned (§8.8.4): allowed, and not in the projection
    const v = pub.verifyCMB(wire, alice.publicKey);
    assert.strictEqual(v.valid, true, JSON.stringify(v));
    assert.strictEqual(v.signed, true);
    assert.strictEqual(v.suite, 'mmp-sig-v2.0');
    assert.strictEqual(v.coreSecure, true);
    assert.strictEqual(v.assertionId, r.metadata.assertionId);
    assert.ok(Object.isFrozen(v.record) && Object.isFrozen(v.record.metadata), 'the projection is frozen');
    assert.strictEqual(v.record.categories.mood.valence, undefined, 'the projection holds only what is signed');
    assert.strictEqual(pub.verifyCMB(wire, alice.publicKey, { coreSecure: true }).valid, true);
    const forged = copy(r); forged.metadata.createdTimestamp += 1; forged.metadata.assertionId = core.assertionIdV2_0(forged);
    assert.strictEqual(pub.verifyCMB(forged, alice.publicKey).error, 'bad-signature');
  });

  it('R2-12: the payload sym keeps beside a record it minted stays valid; a payload that is not the signed one is refused', () => {
    const payload = { action: 'deploy', build: 42 };
    const r = signedRecord(alice, { categories: { focus: 'with a payload' }, application: applicationFor(Buffer.from(JSON.stringify(payload)), { schema: 'https://sym.bot/schema/payload-v1.json' }) });
    const stored = copy({ ...r, payload });
    assert.strictEqual(pub.verifyCMB(stored, alice.publicKey).valid, true, 'the decoded copy of the signed section is allowed');
    stored.payload.build = 43;
    const v = pub.verifyCMB(stored, alice.publicKey);
    assert.strictEqual(v.valid, false);
    assert.strictEqual(v.error, 'unsigned-member');
  });

  it('R2-12: a genuine 0.13 record stays valid, reported as the 0.13 suite and not Core Secure; { coreSecure: true } refuses it', () => {
    const r = legacyRecord();
    const v = pub.verifyCMB(copy(r), alice.publicKey);
    assert.strictEqual(v.valid, true, JSON.stringify(v));
    assert.strictEqual(v.suite, 'mmp-sig-v2');
    assert.strictEqual(v.coreSecure, false);
    // A 0.13 store kept annotations beside the two sections: still what it was, never flipped.
    const stored = { ...copy(r), payload: { a: 1 }, provenance: { via: 'x' }, tether: { verdict: 'tethered' } };
    assert.strictEqual(pub.verifyCMB(stored, alice.publicKey).valid, true, 'a 0.13 store reads as it did');
    const strict = pub.verifyCMB(copy(r), alice.publicKey, { coreSecure: true });
    assert.strictEqual(strict.valid, false);
    assert.strictEqual(strict.error, 'not-core-secure');
  });

  it('R2-12: a 0.13 record whose sections carry an application, a node id, or a member its suite does not sign is invalid', () => {
    const data = Buffer.from(JSON.stringify({ action: 'transfer', to: 'mallory', amount: 1e6 }));
    const cases = {
      application: (r) => { r.metadata.application = applicationFor(data); },
      createdByNodeId: (r) => { r.metadata.createdByNodeId = alice.nodeId; },
      assertionId: (r) => { r.metadata.assertionId = 'asrt-' + '0'.repeat(64); },
      'an eighth category': (r) => { r.categories.approval = { text: 'granted' }; },
    };
    for (const [what, mutate] of Object.entries(cases)) {
      const r = copy(legacyRecord()); mutate(r);
      const v = pub.verifyCMB(r, alice.publicKey);
      assert.strictEqual(v.valid, false, `${what}: ${JSON.stringify(v)}`);
      assert.strictEqual(v.error, 'unsigned-member', what);
      assert.strictEqual(v.suite, 'mmp-sig-v2', what);
    }
  });

  it('R2-12: an unsigned record says so, with its suite', () => {
    const r = core.createCMB({ categories: { focus: 'unsigned' }, createdBy: 'probe' });
    assert.deepStrictEqual(pub.verifyCMB(r, alice.publicKey), { signed: false, valid: false, suite: 'mmp-sig-v2', coreSecure: false });
  });
});

describe('R2-13 (review M2): one signature, one string; a lone surrogate is held as U+FFFD, never refused', () => {
  // The signed object is UTF-8 bytes, where a lone surrogate can only be U+FFFD: "\ud800" and "\ufffd" are
  // one signed text. 0.14.3 first refused the lone-surrogate spelling, which dropped a 0.14.2 author's
  // record whose text was cut inside a surrogate pair; it now holds it as the U+FFFD spelling, so the
  // record verifies as signed and two different strings are never held under one signature.
  it('R2-13: a text re-spelt with a lone surrogate is the same record: it verifies, and is held as its U+FFFD spelling', () => {
    const rec = signedRecord(alice, { categories: { focus: 'build \ufffd ok' } });
    assert.strictEqual(pub.verifyCMB(copy(rec), alice.publicKey).valid, true);
    const respelt = JSON.parse(JSON.stringify(rec).replace('\ufffd', '\\ud800'));
    assert.notStrictEqual(respelt.categories.focus.text, rec.categories.focus.text, 'the scene: two different strings');
    assert.deepStrictEqual(canonicalRecordV2_0(respelt), canonicalRecordV2_0(copy(rec)), 'one projection: one string');
    const v = pub.verifyCMB(respelt, alice.publicKey);
    assert.strictEqual(v.valid, true, JSON.stringify(v));
    assert.strictEqual(v.record.categories.focus.text, 'build \ufffd ok', 'what verifies is the U+FFFD spelling');
    assert.strictEqual(core.verifyCMB(respelt, alice.publicKey).valid, false, 'core\'s signature step refuses an object no boundary brought to its well-formed spelling (fail closed)');
    assert.strictEqual(core.verifyCMB(canonicalRecordV2_0(respelt), alice.publicKey).valid, true, 'and verifies the projection');
  });

  it('R2-13: a signed label re-spelt with a lone surrogate is the same label, in both suites', () => {
    const rec = signedRecord({ ...alice, name: 'ali\ufffdce' });
    const respelt = JSON.parse(JSON.stringify(rec).replace('\ufffd', '\\udfff'));
    assert.strictEqual(canonicalRecordV2_0(respelt).metadata.createdBy, 'ali\ufffdce');
    assert.strictEqual(core.verifyCMB(respelt, alice.publicKey).valid, false, 'unprojected: refused');
    assert.strictEqual(pub.verifyCMB(respelt, alice.publicKey).valid, true);
    const legacy = legacyRecord({ ...alice, name: 'ali\ufffdce' });
    const legacyRespelt = JSON.parse(JSON.stringify(legacy).replace('\ufffd', '\\udfff'));
    assert.strictEqual(core.verifyCMB(legacyRespelt, alice.publicKey).valid, false, 'the 0.13 suite: core\'s step refuses the unnormalised object');
    assert.strictEqual(pub.verifyCMB(legacyRespelt, alice.publicKey).valid, true, 'the public verifier reads it as its bytes say');
  });

  it('R2-13: a record is minted well formed: a lone surrogate a host passes is minted as U+FFFD, and verifies', () => {
    const r = core.createCMB({ categories: { focus: 'cut inside a pair \ud83d' }, createdBy: 'ag\udc00ent', createdByNodeId: alice.nodeId, emitV2: true, room: 'default' });
    assert.strictEqual(r.categories.focus.text, 'cut inside a pair \ufffd');
    assert.strictEqual(r.metadata.createdBy, 'ag\ufffdent');
    r.metadata.assertionId = core.assertionIdV2_0(r);
    core.signCMB(r, alice.privateKey);
    assert.strictEqual(pub.verifyCMB(copy(r), alice.publicKey).valid, true);
  });
});

describe('R2-14: one key, one spelling; one signature, one spelling', () => {
  it('R2-14: the projection takes only the canonical spelling of a record\'s signature', () => {
    const rec = signedRecord(alice);
    const all = spellings(rec.metadata.sig, 0x30);
    assert.strictEqual(all.length, 16, 'the scene: 16 spellings decode to the same 64 bytes');
    const projected = all.filter((sig) => { try { canonicalRecordV2_0({ ...copy(rec), metadata: { ...copy(rec).metadata, sig } }); return true; } catch { return false; } });
    assert.deepStrictEqual(projected, [rec.metadata.sig]);
  });

  it('R2-14: verifyStrict takes only canonical base64url for keys and signatures', () => {
    const rec = signedRecord(alice);
    const msg = core.signingPayloadV2_0(rec);
    const sig = rec.metadata.sig;
    assert.strictEqual(verifyStrict(msg, alice.publicKey, sig), true);
    for (const bad of [sig + '==', sig.slice(0, 40) + ' \n' + sig.slice(40), sig.replace(/-/g, '+').replace(/_/g, '/'), ...spellings(sig, 0x30).slice(1)]) {
      if (bad === sig) continue;
      assert.strictEqual(verifyStrict(msg, alice.publicKey, bad), false, JSON.stringify(bad));
    }
    for (const k of spellings(alice.publicKey, 0x3c).slice(1)) assert.strictEqual(verifyStrict(msg, k, sig), false, k);
    assert.strictEqual(verifyStrict(msg, Buffer.from(alice.publicKey, 'base64url'), Buffer.from(sig, 'base64url')), true, 'bytes are bytes');
  });

  it('R2-14: the key registry and a room-join grant take one spelling per key and signature', () => {
    const keys = spellings(alice.publicKey, 0x3c);
    assert.strictEqual(keys.length, 4);
    assert.deepStrictEqual(keys.filter(isIdentityKey), [alice.publicKey]);
    const grant = { type: 'room-join', room: 'r1', grantee: alice.nodeId, granteeKey: alice.publicKey, grantedBy: identity('o').nodeId, grantedAt: 1, expiresAt: 2, sigAlg: 'ed25519', sig: signedRecord(alice).metadata.sig };
    assert.strictEqual(grantShapeReason(grant), null);
    assert.strictEqual(grantShapeReason({ ...grant, granteeKey: keys[1] }), 'granteeKey');
    assert.strictEqual(grantShapeReason({ ...grant, sig: spellings(grant.sig, 0x30)[1] }), 'sig');
  });
});

describe('R2-21: an invite error never repeats the invite', () => {
  it('R2-21: a malformed team invite\'s error does not carry its relay token', () => {
    const secret = 'SECRET-RELAY-TOKEN-abcdef0123456789';
    for (const url of [
      `sym://team/room1?relay=wss%3A%2F%2Fr.example&token=${secret}#frag x`,
      `not-a-scheme team/room1?token=${secret}`,
      `sym://team/room1?relay=wss%3A%2F%2Fr.example&token=${secret}&node=bad`,
    ]) {
      const r = parseInvite(url);
      assert.ok(r.error, url);
      assert.ok(!r.error.includes(secret) && !r.error.includes('SECRET'), r.error);
    }
  });
});
