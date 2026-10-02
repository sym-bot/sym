'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * The verifying key belongs to the AUTHOR, resolved by the signed `createdByNodeId` — never the peer
 * that delivered the record (sym 0.14, design D4; MMP §8.8.5).
 *
 * History: 0.13 resolved the key from the DELIVERING peer, so a relayed record failed against the
 * relayer's key; the fix then let a record whose author was named but unresolvable through as
 * "unverified". Core Secure removes both: the author's key is looked up by the nodeId the signature
 * binds, a relayed record verifies against its author, and a record whose author has no proven,
 * pinned or vouched key here is refused (counted `cmb-author-unresolvable`), never delivered
 * unverified. A legacy-suite (pre-v2.0) record, an unsigned one and one without an author nodeId are
 * refused.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { FrameHandler } = require('../lib/frame-handler');
const { createCMB, signCMB } = require('../lib/core');
const { identity, signedRecord } = require('./_core-secure');

const GROUP = 'test-group';

/** Receiver node stub. `keys` maps an AUTHOR nodeId → the key this node holds for it. */
function harness(keys) {
  const logs = [];
  const metrics = [];
  const decisions = [];
  const asked = [];
  const node = {
    nodeId: 'receiver-node-id',
    _room: GROUP,
    _log: (m) => logs.push(m),
    emit: (type, payload) => { if (type === 'metric') metrics.push(payload); },
    _identityKey: (nodeId) => { asked.push(nodeId); return keys[nodeId] || null; },
    _recordDecision: (d) => decisions.push(d),
  };
  return { fh: new FrameHandler(node, {}), logs, metrics, decisions, asked };
}

describe('_rejectOnBadSignature — the verifying key is the author\'s, by createdByNodeId', () => {
  it('a record authored by A and relayed by B verifies against A\'s key (the 0.13 100%-loss case)', () => {
    const A = identity('node-a'), B = identity('node-b');
    const cmb = signedRecord(A, { room: GROUP });
    const { fh, decisions, asked } = harness({ [A.nodeId]: A.publicKey, [B.nodeId]: B.publicKey });
    const msg = { cmb };
    assert.strictEqual(fh._rejectOnBadSignature(B.nodeId, 'node-b', msg), false);
    assert.strictEqual(msg._cmbVerified, true, 'authenticated, not merely let through');
    assert.strictEqual(msg._verifiedAuthorNodeId, A.nodeId);
    assert.deepStrictEqual(asked, [A.nodeId], 'only the author\'s key is looked up, never the deliverer\'s');
    assert.strictEqual(decisions.length, 0);
  });

  it('a relayed record whose author has no key here is refused, not delivered unverified', () => {
    const A = identity('node-a'), B = identity('node-b');
    const cmb = signedRecord(A, { room: GROUP });
    const { fh, metrics, decisions } = harness({ [B.nodeId]: B.publicKey });
    const msg = { cmb };
    assert.strictEqual(fh._rejectOnBadSignature(B.nodeId, 'node-b', msg), true);
    assert.strictEqual(msg._cmbVerified, false);
    assert.ok(metrics.some((m) => m.type === 'cmb-author-unresolvable' && m.author === A.nodeId), 'counted by author');
    assert.ok(decisions.some((d) => d.decision === 'rejected-signature' && /unresolvable|no proven/.test(d.focusLabel)));
  });

  it('a record whose signature was made by another key is refused (B claims A\'s nodeId)', () => {
    const A = identity('node-a'), B = identity('node-b');
    const cmb = signedRecord({ ...A, privateKey: B.privateKey }, { room: GROUP });
    const { fh, logs, decisions } = harness({ [A.nodeId]: A.publicKey, [B.nodeId]: B.publicKey });
    assert.strictEqual(fh._rejectOnBadSignature(B.nodeId, 'node-b', { cmb }), true);
    assert.ok(decisions.some((d) => d.decision === 'rejected-signature'));
    assert.ok(logs.some((m) => /refused/.test(m)));
  });

  it('a record with no createdByNodeId is refused — omitting it cannot dodge the check', () => {
    const A = identity('node-a');
    const cmb = signedRecord(A, { room: GROUP });
    delete cmb.metadata.createdByNodeId;
    const { fh, decisions } = harness({ [A.nodeId]: A.publicKey });
    assert.strictEqual(fh._rejectOnBadSignature(A.nodeId, 'node-a', { cmb }), true);
    assert.ok(decisions.some((d) => d.focusLabel === 'no-author-node-id'));
  });

  it('a legacy-suite record (pre-v2.0 signature) is refused even when its signature is genuine', () => {
    const A = identity('node-a');
    const cmb = createCMB({ categories: { focus: 'an old record' }, createdBy: 'node-a', room: GROUP });
    signCMB(cmb, A.privateKey);
    const { fh, decisions, metrics } = harness({ [A.nodeId]: A.publicKey });
    assert.strictEqual(fh._rejectOnBadSignature(A.nodeId, 'node-a', { cmb }), true);
    assert.ok(metrics.some((m) => m.type === 'cmb-legacy-suite-refused'), 'counted on its own metric');
    assert.strictEqual(decisions.length, 0, 'and not recorded as a rejected signature: old history is not a forgery');
  });

  it('a record its author delivers directly verifies normally', () => {
    const A = identity('node-a');
    const cmb = signedRecord(A, { room: GROUP });
    const { fh, decisions } = harness({ [A.nodeId]: A.publicKey });
    const msg = { cmb };
    assert.strictEqual(fh._rejectOnBadSignature(A.nodeId, 'node-a', msg), false);
    assert.strictEqual(msg._cmbVerified, true);
    assert.strictEqual(decisions.length, 0);
  });
});
