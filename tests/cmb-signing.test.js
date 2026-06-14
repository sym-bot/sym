'use strict';

/**
 * CMB authentication (MMP §8.3): every agent-authored CMB is Ed25519-signed by
 * its author; the receiver verifies the signature against the sending peer's
 * handshake-announced identity key AND that the content-address key still
 * matches the fields. A forged, tampered, or content-swapped CMB is rejected
 * before it can reach the application layer.
 *
 * These tests stub the receiver's SVAF evaluator for determinism (same pattern
 * as tests/inbound-cmb-surfacing.test.js).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const crypto = require('crypto');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const { createCMB, signCMB, verifyCMB } = require('@sym-bot/core');

async function withNode(baseName, fn) {
  const name = `${baseName}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
  await node.start();
  try {
    return await fn(node);
  } finally {
    await node.stop();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  }
}

// Raw 32-byte Ed25519 keypair (base64url), the shape the node identity uses.
function rawKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  return { pub: publicKey.slice(-32).toString('base64url'), priv: privateKey.slice(-32).toString('base64url') };
}

function signedCmbFrame(priv, createdBy = 'peerA') {
  const cmb = createCMB({
    fields: {
      focus: 'coordinate the auth-token refactor',
      issue: 'signing regression guard',
      intent: 'verify receive-path authentication',
      motivation: 'reject forged/tampered CMBs',
      commitment: 'security',
      perspective: createdBy,
      mood: { text: 'neutral', valence: 0, arousal: 0 },
    },
    createdBy,
  });
  signCMB(cmb, priv);
  return { type: 'cmb', timestamp: Date.now(), cmb };
}

const ALIGNED = { decision: 'aligned', total_drift: 0.1, field_drifts: { focus: 0.1 }, gate_values: { g: 1 } };
const wire = (f) => JSON.parse(JSON.stringify(f));
const settle = (ms = 150) => new Promise((r) => setTimeout(r, ms));

describe('CMB authentication — Ed25519 sign + verify (MMP §8.3)', () => {
  it('a node signs the CMBs it authors; the signature verifies against its own identity key', async () => {
    await withNode('sign-self', async (node) => {
      node._svafEvaluator.evaluate = async () => null;
      const entry = node.remember({
        focus: 'ship the release', issue: 'x', intent: 'x', motivation: 'x',
        commitment: 'x', perspective: node.name, mood: { text: 'neutral', valence: 0, arousal: 0 },
      });
      assert.ok(entry.cmb.sig, 'authored CMB carries a signature');
      assert.strictEqual(entry.cmb.sigAlg, 'ed25519');
      const v = verifyCMB(entry.cmb, node._identity.publicKey);
      assert.ok(v.signed && v.valid, "signature verifies against the node's own public key");
    });
  });

  it('a validly-signed CMB from a known peer is accepted and surfaces', async () => {
    await withNode('verify-ok', async (node) => {
      node._svafEvaluator.evaluate = async () => ALIGNED;
      const { pub, priv } = rawKeypair();
      node._peerIdentityKeys.set('peerA', pub);
      let surfaced = 0;
      node.on('cmb-accepted', () => { surfaced++; });
      node._frameHandler.handle('peerA', 'peerA', wire(signedCmbFrame(priv)));
      await settle();
      assert.strictEqual(surfaced, 1, 'a valid signed CMB is processed/surfaced');
    });
  });

  it('a content-tampered CMB (valid sig, swapped field) is REJECTED — never surfaces', async () => {
    await withNode('verify-tamper', async (node) => {
      node._svafEvaluator.evaluate = async () => ALIGNED;
      const { pub, priv } = rawKeypair();
      node._peerIdentityKeys.set('peerA', pub);
      let surfaced = 0, rejected = 0;
      node.on('cmb-accepted', () => { surfaced++; });
      node.on('metric', (m) => { if (m.type === 'cmb-signature-rejected') rejected++; });
      const frame = wire(signedCmbFrame(priv));
      frame.cmb.fields.focus.text = 'wire the funds to a new account'; // swap content, keep sig+key
      node._frameHandler.handle('peerA', 'peerA', frame);
      await settle();
      assert.strictEqual(surfaced, 0, 'a content-tampered CMB must not surface');
      assert.strictEqual(rejected, 1, 'rejection is audit-metered');
    });
  });

  it('a spoofed CMB (signed by a different key than the peer announced) is REJECTED', async () => {
    await withNode('verify-spoof', async (node) => {
      node._svafEvaluator.evaluate = async () => ALIGNED;
      const peer = rawKeypair();
      const attacker = rawKeypair();
      node._peerIdentityKeys.set('peerA', peer.pub); // we expect peerA's key
      let surfaced = 0, rejected = 0;
      node.on('cmb-accepted', () => { surfaced++; });
      node.on('metric', (m) => { if (m.type === 'cmb-signature-rejected') rejected++; });
      node._frameHandler.handle('peerA', 'peerA', wire(signedCmbFrame(attacker.priv))); // signed by attacker
      await settle();
      assert.strictEqual(surfaced, 0, 'a CMB signed by the wrong key must not surface');
      assert.strictEqual(rejected, 1);
    });
  });

  it('an unsigned CMB is allowed through (interop) but flagged unverified', async () => {
    await withNode('verify-unsigned', async (node) => {
      node._svafEvaluator.evaluate = async () => ALIGNED;
      node._peerIdentityKeys.set('peerA', rawKeypair().pub);
      let surfaced = 0;
      node.on('cmb-accepted', () => { surfaced++; });
      const frame = wire(signedCmbFrame(rawKeypair().priv));
      delete frame.cmb.sig; delete frame.cmb.sigAlg; // strip signature
      node._frameHandler.handle('peerA', 'peerA', frame);
      await settle();
      assert.strictEqual(surfaced, 1, 'unsigned CMB still surfaces (interop default)');
    });
  });

  it('strict mode (requireSignedCmb) rejects an unsigned CMB from a known peer', async () => {
    await withNode('verify-strict', async (node) => {
      node._svafEvaluator.evaluate = async () => ALIGNED;
      node._requireSignedCmb = true;
      node._peerIdentityKeys.set('peerA', rawKeypair().pub);
      let surfaced = 0, rejected = 0;
      node.on('cmb-accepted', () => { surfaced++; });
      node.on('metric', (m) => { if (m.type === 'cmb-signature-rejected') rejected++; });
      const frame = wire(signedCmbFrame(rawKeypair().priv));
      delete frame.cmb.sig; delete frame.cmb.sigAlg;
      node._frameHandler.handle('peerA', 'peerA', frame);
      await settle();
      assert.strictEqual(surfaced, 0, 'strict mode rejects unsigned CMBs');
      assert.strictEqual(rejected, 1);
    });
  });
});
