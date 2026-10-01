'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * Receipt of published v2.0 records (mmp-sig-v2.0), which sign the author's node id:
 * - B-R4 (§8.8.4, §18.3.1): the verifying key is the one held for `createdByNodeId`, never the
 *   key of whichever peer delivered the frame, so a peer cannot vouch for a record by signing it
 *   itself under someone else's id, and a genuine relay verifies against the author.
 * - B-R6 (§8.8.5 step 5): a carried `assertionId` must be the one the preimage yields; on records
 *   of the older suite, where no signature covers it, a carried `assertionId` is dropped.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const { createCMB, signCMB, assertionIdV2_0 } = require('../lib/core');
const { settle } = require('./_settle'); // waits for every in-flight frame, not a fixed guess

function kp() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' }, privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  return { pub: publicKey.slice(-32).toString('base64url'), priv: privateKey.slice(-32).toString('base64url') };
}
const ALICE = kp(), MALLORY = kp(), RELAY = kp();

function v2Record({ nodeId, createdBy, signWith, focus = 'v2 observation' }) {
  const cmb = createCMB({ categories: { focus }, createdBy, emitV2: true, createdByNodeId: nodeId, room: 'default' });
  cmb.metadata.assertionId = assertionIdV2_0(cmb);
  signCMB(cmb, signWith.priv);
  return cmb;
}

function withNode(fn) {
  const name = `v2bind-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
  node._pinPeerKey('node-alice', ALICE.pub);
  node._pinPeerKey('node-mallory', MALLORY.pub);
  node._pinPeerKey('node-relay', RELAY.pub);
  try { return fn(node); } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
}

describe('v2.0 author binding (B-R4)', () => {
  it('a v2.0 record relayed by another peer verifies against its author\'s key', () => {
    withNode((node) => {
      const msg = { cmb: v2Record({ nodeId: 'node-alice', createdBy: 'alice', signWith: ALICE }) };
      assert.strictEqual(node._frameHandler._rejectOnBadSignature('node-relay', 'relay', msg), false);
      assert.strictEqual(msg._cmbVerified, true);
    });
  });

  it('a peer that signs a record under another node\'s id is refused, even delivering it itself', () => {
    withNode((node) => {
      const msg = { cmb: v2Record({ nodeId: 'node-alice', createdBy: 'alice', signWith: MALLORY }) };
      assert.strictEqual(node._frameHandler._rejectOnBadSignature('node-mallory', 'mallory', msg), true);
    });
  });

  it('an author whose key this node does not hold yet is unverified, not refused', () => {
    withNode((node) => {
      const stranger = kp();
      const msg = { cmb: v2Record({ nodeId: 'node-stranger', createdBy: 'stranger', signWith: stranger }) };
      assert.strictEqual(node._frameHandler._rejectOnBadSignature('node-relay', 'relay', msg), false);
      assert.strictEqual(msg._cmbVerified, false);
    });
  });
});

describe('assertionId (B-R6)', () => {
  it('a v2.0 record whose carried assertionId is not the preimage\'s is refused', () => {
    withNode((node) => {
      const cmb = v2Record({ nodeId: 'node-alice', createdBy: 'alice', signWith: ALICE });
      cmb.metadata.assertionId = 'asrt-' + '0'.repeat(64);
      assert.strictEqual(node._frameHandler._rejectOnBadSignature('node-alice', 'alice', { cmb }), true);
    });
  });

  it('on an older-suite record, a carried assertionId (which nothing signs) is dropped', () => {
    withNode((node) => {
      const cmb = createCMB({ categories: { focus: 'old suite' }, createdBy: 'alice', room: 'default' });
      signCMB(cmb, ALICE.priv);
      cmb.metadata.assertionId = 'asrt-' + '1'.repeat(64);
      const msg = { cmb };
      assert.strictEqual(node._frameHandler._rejectOnBadSignature('node-alice', 'alice', msg), false);
      assert.strictEqual(msg._cmbVerified, true);
      assert.strictEqual('assertionId' in msg.cmb.metadata, false);
    });
  });
});

describe('the inbox names a proven author (K5)', () => {
  it('a relayed v2.0 record verified against its signed node id is from its author, not the relay', async () => {
    const name = `v2inbox-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    await node.start();
    try {
      node._pinPeerKey('node-alice', ALICE.pub);
      node._pinPeerKey('node-relay', RELAY.pub);
      node._svafEvaluator.evaluate = async () => ({ decision: 'aligned', total_drift: 0.1, category_drifts: { focus: 0.1 }, gate_values: { g: 1 } });
      const got = [];
      node.on('cmb-accepted', (e) => got.push(e));
      node._frameHandler.handle('node-relay', 'relay', { type: 'cmb', timestamp: Date.now(), cmb: v2Record({ nodeId: 'node-alice', createdBy: 'alice', signWith: ALICE, focus: 'relayed but proven' }) });
      await settle();
      assert.strictEqual(got.length, 1);
      assert.strictEqual(got[0].author.nodeId, 'node-alice');
      assert.strictEqual(node.inboxGet(got[0].inboxId).from, 'alice');
    } finally { await node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });
});

describe('a malformed v2.0 frame is refused, never thrown (0.14.0 review F1)', () => {
  // Declares the v2.0 suite but carries no room and no signature: it has no preimage, and building
  // one throws. On the relay path that throw reached the process and ended the daemon.
  function malformed() {
    const cmb = createCMB({ categories: { focus: 'x' }, createdBy: 'alice', emitV2: true, createdByNodeId: 'node-alice', room: 'default' });
    cmb.metadata.assertionId = 'asrt-0';
    delete cmb.metadata.room;
    return cmb;
  }

  it('the signature check rejects it as a mismatch', () => {
    withNode((node) => {
      const metrics = [];
      node.on('metric', (m) => metrics.push(m));
      const msg = { cmb: malformed() };
      assert.doesNotThrow(() => assert.strictEqual(node._frameHandler._rejectOnBadSignature('node-alice', 'alice', msg), true));
      assert.ok(metrics.some((m) => m.type === 'cmb-signature-rejected'), 'rejected through the ordinary path, with its metric');
    });
  });

  it('a frame that throws anywhere in handling is dropped and counted, and the node goes on', () => {
    withNode((node) => {
      node._roomDoor = () => ({ pass: true });
      const metrics = [];
      node.on('metric', (m) => metrics.push(m));
      assert.doesNotThrow(() => node._frameHandler.handle('node-alice', 'alice', { type: 'cmb', cmb: malformed() }));
      const original = node._frameHandler._handleMemoryShare;
      node._frameHandler._handleMemoryShare = () => { throw new Error('boom'); };
      assert.doesNotThrow(() => node._frameHandler.handle('node-alice', 'alice', { type: 'cmb', cmb: malformed() }));
      node._frameHandler._handleMemoryShare = original;
      assert.ok(metrics.some((m) => m.type === 'frame-handler-error' && /boom/.test(m.error)));
    });
  });
});
