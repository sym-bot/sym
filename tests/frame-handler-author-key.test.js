'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * Regression: a RELAYED CMB must not be reported as forged.
 *
 * `_rejectOnBadSignature` resolves the verifying key from the DELIVERING peer
 * (`_identityKey(peerId)`, and the roster is keyed by nodeId), while
 * `signingPayload` binds the AUTHOR (`cmb.createdBy`). Those coincide only when
 * the author handed the block over directly. For every relayed CMB the check
 * ran against the wrong node's public key, so an untouched, genuinely-signed
 * block failed 100% of the time and was dropped before SVAF with the log text
 * "forged/tampered" — invisible in every drift distribution and admission tally
 * because the drop happens upstream of evaluation.
 *
 * The relaxation is deliberately narrow: only a NAMED author that is not the
 * deliverer is treated as unverifiable. An absent `createdBy`, or an author that
 * IS the deliverer, still hard-rejects — otherwise omitting the category would be a
 * way to dodge signature rejection entirely.
 *
 * This does NOT authenticate relayed CMBs. The author's key is unresolvable from
 * a name (roster is nodeId-keyed), so the honest outcome is "unverified", which
 * is the posture the no-key branch already takes. Authenticating them needs
 * `createdByNodeId` bound into `signingPayload` — an MMP schema change.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { FrameHandler } = require('../lib/frame-handler');
const { createCMB, signCMB } = require('@sym-bot/core');

const GROUP = 'test-group';
const RECEIVER_NODE_ID = 'receiver-node-id';

/** A fresh Ed25519 identity in the raw base64url form sym stores. */
function identity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const rawPriv = privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(16);
  const rawPub = publicKey.export({ type: 'spki', format: 'der' }).subarray(12);
  return { priv: rawPriv.toString('base64url'), pub: rawPub.toString('base64url') };
}

/** A signed CMB as it appears on the wire (emit.js: whole object, then signCMB). */
function signedCMB({ author, signWith }) {
  const cmb = createCMB({ categories: { focus: 'a relayed observation' }, createdBy: author });
  cmb.room = GROUP;
  signCMB(cmb, signWith);
  return cmb;
}

/** Receiver node stub. `keyFor` maps the delivering peerId → the key we hold. */
function harness(keyFor) {
  const logs = [];
  const metrics = [];
  const decisions = [];
  const node = {
    nodeId: RECEIVER_NODE_ID,
    _room: GROUP,
    _requireSignedCmb: false,
    _log: (m) => logs.push(m),
    emit: (type, payload) => { if (type === 'metric') metrics.push(payload); },
    _identityKey: (peerId) => keyFor[peerId],
    _recordDecision: (d) => decisions.push(d),
  };
  return { fh: new FrameHandler(node, {}), logs, metrics, decisions };
}

describe('_rejectOnBadSignature — the verifying key must belong to the author', () => {
  it('does NOT reject a CMB authored by A and relayed by B (the 100%-loss case)', () => {
    const a = identity();
    const b = identity();
    const cmb = signedCMB({ author: 'node-a', signWith: a.priv });
    // C holds B's key for the delivering peer, and has never met A.
    const { fh, logs, metrics, decisions } = harness({ 'peer-b': b.pub });
    const msg = { cmb, source: 'node-a' };

    const rejected = fh._rejectOnBadSignature('peer-b', 'node-b', msg);

    assert.strictEqual(rejected, false, 'a relayed CMB must reach SVAF, not be dropped as forged');
    assert.strictEqual(msg._cmbVerified, false, 'and must be flagged unverified — it is NOT authenticated');
    assert.ok(
      !decisions.some((d) => d.decision === 'rejected-signature'),
      `must never record rejected-signature, got: ${JSON.stringify(decisions)}`,
    );
    assert.ok(
      metrics.some((m) => m.type === 'cmb-signature-unverifiable' && m.author === 'node-a'),
      `the population must stay countable, got: ${JSON.stringify(metrics)}`,
    );
    assert.ok(
      !logs.some((m) => m.includes('forged/tampered')),
      `must not be logged as forgery, got: ${logs.join(' | ')}`,
    );
  });

  it('still rejects a forgery from the peer that claims to have authored it', () => {
    const a = identity();
    const b = identity();
    // B names itself the author but the bytes were signed by A: B's own key is
    // the right key to check, and it fails. That is a real forgery.
    const cmb = signedCMB({ author: 'node-b', signWith: a.priv });
    const { fh, logs, decisions } = harness({ 'peer-b': b.pub });
    const msg = { cmb, source: 'node-b' };

    const rejected = fh._rejectOnBadSignature('peer-b', 'node-b', msg);

    assert.strictEqual(rejected, true, 'author === deliverer means the verdict is meaningful');
    assert.ok(decisions.some((d) => d.decision === 'rejected-signature'));
    assert.ok(logs.some((m) => m.includes('forged/tampered')));
  });

  it('still rejects when createdBy is absent — omitting it cannot dodge rejection', () => {
    const a = identity();
    const b = identity();
    const cmb = signedCMB({ author: 'node-a', signWith: a.priv });
    delete cmb.createdBy;
    if (cmb.metadata) delete cmb.metadata.createdBy; // absent means absent on the two-section record too
    const { fh, decisions } = harness({ 'peer-b': b.pub });
    const msg = { cmb, source: 'node-a' };

    const rejected = fh._rejectOnBadSignature('peer-b', 'node-b', msg);

    assert.strictEqual(rejected, true, 'an unnamed author must not buy a pass');
    assert.ok(decisions.some((d) => d.decision === 'rejected-signature'));
  });

  it('verifies normally when the author delivers its own CMB', () => {
    const a = identity();
    const cmb = signedCMB({ author: 'node-a', signWith: a.priv });
    const { fh, decisions } = harness({ 'peer-a': a.pub });
    const msg = { cmb, source: 'node-a' };

    const rejected = fh._rejectOnBadSignature('peer-a', 'node-a', msg);

    assert.strictEqual(rejected, false);
    assert.strictEqual(msg._cmbVerified, true, 'the direct path must still authenticate');
    assert.strictEqual(decisions.length, 0);
  });

  it('leaves the unresolvable-key path untouched (unverified, not rejected)', () => {
    const a = identity();
    const cmb = signedCMB({ author: 'node-a', signWith: a.priv });
    const { fh, decisions } = harness({}); // no key for anyone
    const msg = { cmb, source: 'node-a' };

    const rejected = fh._rejectOnBadSignature('peer-b', 'node-b', msg);

    assert.strictEqual(rejected, false);
    assert.strictEqual(msg._cmbVerified, false);
    assert.strictEqual(decisions.length, 0);
  });
});
