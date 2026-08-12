'use strict';

/**
 * P-6 — a pre-boundary block is UNATTESTED, not FORGED.
 *
 * THE DEFECT THIS FILE EXISTS FOR. `verifyCMB` returns `{valid:false}` for three different
 * situations and sym collapsed all three into the bad-signature arm. A grandfathered v1 record
 * — which is what every node's entire pre-boundary history looks like — was therefore rejected
 * as forged, and logged as `forged/tampered`. Not gated by strict mode either: `_requireSignedCmb`
 * guards only the *unsigned* branch. So on the first packet after the boundary, every node would
 * have refused every peer's whole history and said "forgery" about it in the security log.
 *
 * WHY BOTH ARMS ARE ASSERTED HERE, and this is the point of the file rather than a detail:
 * a test that only checks "a legacy block is admitted" PASSES IF EVERYTHING IS ADMITTED. The fix
 * has to preserve core's split — `unverified-legacy` grandfathers, `legacy-key-rejected` and a
 * genuinely bad signature still reject — so the split is what gets tested, not the half that was
 * broken. This is the same vacuity found in AC-2.4's second test on 2026-08-01: an assertion
 * that cannot fail in the case it exists for.
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { SymNode } = require('../lib/node');
const { BonjourDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const { verifyCMB, signCMB, createCMB } = require('../lib/core');

const ROOM = 'p6group';

async function withNode(name, fn) {
  const node = new SymNode({ name, silent: true, room: ROOM, discovery: new BonjourDiscovery({ mdns: false }) });
  await node.start();
  try { await fn(node); } finally {
    await node.stop();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  }
}

const LEGACY_FIELDS = {
  focus: { text: 'the crosswalk predates the boundary' }, issue: { text: 'no v2 attestation' },
  intent: { text: 'coordinate' }, motivation: { text: 'history must stay readable' },
  commitment: { text: 'grandfather it' }, perspective: { text: 'a peer that has not upgraded' },
  mood: { text: 'steady' },
};

/** A pre-boundary record: address at the TOP level, v1 scheme, signed, and NO `metadata`. */
function legacyBlock({ key, room = ROOM } = {}) {
  return {
    key: key || ('cmb-' + crypto.randomBytes(32).toString('hex')),
    categories: JSON.parse(JSON.stringify(LEGACY_FIELDS)),
    room,
    sig: crypto.randomBytes(64).toString('base64url'),
    sigAlg: 'ed25519',
  };
}

const someKey = () => crypto.generateKeyPairSync('ed25519')
  .publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64url');

test('P-6: core classifies the three populations apart — the premise the fix rests on', () => {
  const grandfathered = verifyCMB(legacyBlock(), someKey());
  assert.equal(grandfathered.error, 'unverified-legacy',
    'a bare cmb-<64hex> v1 key grandfathers');

  // A non-v1 key was refused by the §19.1 membrane BEFORE the boundary and is refused after.
  const refused = verifyCMB({ ...legacyBlock(), key: 'cmb1-' + 'a'.repeat(64) }, someKey());
  assert.equal(refused.error, 'legacy-key-rejected',
    'a transitional/legacy key is a REJECTION, never a grandfathering');

  assert.notEqual(grandfathered.error, refused.error,
    'if these ever collapse to one value the fix below silently widens into "admit everything"');
});

test('P-6: a pre-boundary block is REFUSED — grandfathering is retired', async () => {
  // POLICY CHANGE, recorded rather than silently flipped. This asserted the opposite until the
  // v1 retirement: a pre-boundary block was surfaced, marked unverified, and kept off the forgery
  // counter, so ordinary history did not read as an attack at the cutover.
  //
  // That policy required reading the audience under its retired name, because the companion case
  // below — a pre-boundary block from the WRONG audience — still had to be refused. Surfacing and
  // audience-checking together are only possible while the old name is still read, and the old
  // name is gone (founder ruling 2026-08-09: remove all fallback and dead v1 code).
  //
  // So the audience of such a record can no longer be established, and core refuses it as
  // `unreadable-audience` rather than treating an absent room as a broadcast. Refusing is the
  // honest end state: we cannot say who it was for, so we do not act as though we can.
  //
  // WHAT THIS COSTS, stated plainly: a node holding genuine pre-boundary history will now see it
  // refused rather than surfaced. That is a real behaviour change for existing deployments, and
  // it is the intended consequence of retiring v1 rather than an oversight.
  await withNode('p6-grandfather', async (node) => {
    const fh = node._frameHandler;
    node._identityKey = () => someKey();

    const metrics = [];
    node.on('metric', (m) => metrics.push(m));

    const msg = { cmb: legacyBlock(), source: 'oldpeer' };
    const rejected = fh._rejectOnBadSignature('peer-1', 'oldpeer', msg);

    assert.equal(rejected, true, 'a pre-boundary block is refused: its audience cannot be read');
    // NOT `=== false`: refusal now happens at the audience check, BEFORE verification is
    // attempted, so the flag is never set at all. Asserting `false` would quietly require that
    // the verify step still runs — the opposite of what refusing early means.
    assert.notEqual(msg._cmbVerified, true, 'a refused block is never marked verified');

    // The audit-trail half still holds and is the part worth keeping: an operator watching the
    // forgery counter must not see ordinary history in it. Refused is not the same as forged.
    assert.equal(metrics.filter((m) => m.type === 'cmb-signature-rejected').length, 0,
      'a legacy block MUST NOT increment the forgery counter — refusing it is not accusing it');
  });
});

test('P-6: the OTHER arm — a genuinely bad signature is still rejected as forged', async () => {
  await withNode('p6-forged', async (node) => {
    const fh = node._frameHandler;
    const victim = crypto.generateKeyPairSync('ed25519');
    const victimPub = victim.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64url');
    node._identityKey = () => victimPub;

    // A well-formed v2 record signed by SOMEONE ELSE — the forgery case.
    const cmb = createCMB({ categories: LEGACY_FIELDS, createdBy: 'impostor@p6group', room: ROOM });
    const attacker = crypto.generateKeyPairSync('ed25519');
    const attackerPriv = attacker.privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32).toString('base64url');
    signCMB(cmb, attackerPriv);

    const metrics = [];
    node.on('metric', (m) => metrics.push(m));

    const msg = { cmb, source: 'attacker' };
    const rejected = fh._rejectOnBadSignature('peer-2', 'attacker', msg);

    assert.equal(rejected, true, 'a signature that does not verify against the author key MUST reject');
    assert.equal(metrics.filter((m) => m.type === 'cmb-signature-rejected').length, 1,
      'and it IS a forgery, on the forgery counter');
  });
});

test('P-6: a legacy block with the WRONG AUDIENCE is still rejected', async () => {
  // Grandfathering must not become an early return that skips the audience check. `checkAudience`
  // reads the audience from the top level on a pre-boundary record and applies to exactly these
  // v1 keys, so returning early would admit a cross-room legacy replay — closing one hole by
  // opening another.
  await withNode('p6-audience', async (node) => {
    const fh = node._frameHandler;
    node._identityKey = () => someKey();

    const msg = { cmb: legacyBlock({ room: 'a-different-room' }), source: 'oldpeer' };
    const rejected = fh._rejectOnBadSignature('peer-3', 'oldpeer', msg);

    assert.equal(rejected, true,
      'a grandfathered block from the wrong audience MUST still be refused');
  });
});
