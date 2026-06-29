'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * EA2/EA3 — node earned-authority wiring. The node holds the role-grant chain, stamps
 * its RESOLVED role into attestations, can grant/revoke, and resolves any node's role.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const crypto = require('crypto');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir, loadOrCreateIdentity } = require('../lib/config');
const { verifyAttestationRole, signAttestation } = require('@sym-bot/core');

function kp(nodeId) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    nodeId,
    priv: privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(16).toString('base64url'),
    pub: publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('base64url'),
  };
}
function att(by, role, verdict, fields, priv) {
  const a = { of: 'cmb-agg', by, at: Date.now(), roster: 'g', method: 'heuristic', verdict, fields, role, seq: 1, prev: null };
  return signAttestation(a, priv);
}

// A node configured as its OWN anchor (the founder-anchor case): pre-create the
// identity so we can pin it as the anchor before constructing the node.
function anchorNode(base) {
  const name = `${base}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const id = loadOrCreateIdentity(name);
  const node = new SymNode({
    name, silent: true, discovery: new NullDiscovery(), group: 'g',
    anchor: { nodeId: id.nodeId, publicKey: id.publicKey },
  });
  return { node, name };
}

describe('node earned-authority wiring (EA2/EA3)', () => {
  it('a node pinned as the anchor resolves to anchor and can grant validator', () => {
    const { node, name } = anchorNode('ea-anchor');
    try {
      assert.strictEqual(node._resolvedRole(), 'anchor');
      const peer = 'node-peer-xyz';
      const g = node.grantRole(peer, 'validator');
      assert.ok(g && g.sig, 'grant is signed');
      assert.strictEqual(node.resolveRole(peer), 'validator', 'grantee resolves to validator');
      const revoke = node.revokeRole(peer);
      assert.ok(revoke && revoke.type === 'role-revoke');
      assert.strictEqual(node.resolveRole(peer), 'participant', 'revoked → participant');
    } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  it('attestations stamp the RESOLVED role, matching the chain', () => {
    const { node, name } = anchorNode('ea-att-role');
    try {
      const att = node._buildAdmissionAttestation('cmb-1', 'aligned', { focus: 'admit' }, 'heuristic');
      assert.strictEqual(att.role, 'anchor', 'stamps the resolved anchor role, not a static default');
      const r = verifyAttestationRole(att, node._roleGrants.resolver());
      assert.strictEqual(r.resolved, 'anchor');
      assert.strictEqual(r.matches, true, 'claimed role matches the chain-resolved role');
    } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  it('a node with an anchor but no grants resolves itself to participant', () => {
    const name = `ea-plain-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), group: 'g', anchor: { nodeId: 'someone-else', publicKey: 'AAAA' } });
    try {
      assert.strictEqual(node._resolvedRole(), 'participant', 'no grant → participant, not self-asserted');
    } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  it('falls back to the static lifecycleRole when no anchor is configured (legacy)', () => {
    const name = `ea-legacy-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), lifecycleRole: 'validator' });
    try {
      assert.strictEqual(node._resolvedRole(), 'validator', 'no anchor → static role (backward compatible)');
    } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });
});

describe('§6.5 enforcement — validate/canonize gated on earned authority (EA4)', () => {
  // Seed a CMB straight into the store so we have a key to act on.
  function seed(node) {
    const key = 'cmb-to-validate';
    node._store._cache.set(key, { key, lifecycle: 'remixed', anchorWeight: 1.0 });
    return key;
  }

  it('a participant cannot validate or canonize — the CMB is left untouched', () => {
    const name = `ea65-part-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), group: 'g', anchor: { nodeId: 'someone-else', publicKey: 'AAAA' } });
    try {
      const key = seed(node);
      assert.strictEqual(node._resolvedRole(), 'participant');
      const v = node.validateCMB(key);
      assert.deepStrictEqual(v, { ok: false, reason: 'insufficient-authority' });
      assert.strictEqual(node._store.getLifecycle(key), 'remixed', 'lifecycle unchanged');
      const c = node.canonizeCMB(key);
      assert.deepStrictEqual(c, { ok: false, reason: 'insufficient-authority' });
    } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  it('an anchor can validate AND canonize', () => {
    const { node, name } = anchorNode('ea65-anchor');
    try {
      const key = seed(node);
      assert.strictEqual(node.validateCMB(key).ok, true);
      assert.strictEqual(node._store.getLifecycle(key), 'validated');
      assert.strictEqual(node.canonizeCMB(key).ok, true);
      assert.strictEqual(node._store.getLifecycle(key), 'canonical');
    } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  it('validator rank can validate but NOT canonize (canonization is anchor-only)', () => {
    const { node, name } = anchorNode('ea65-rank');
    try {
      const key = seed(node);
      // exercise the store gate at validator rank directly — validate passes, canonize blocked
      assert.strictEqual(node._store.validateCMB(key, { byRole: 'validator' }).ok, true);
      assert.strictEqual(node._store.getLifecycle(key), 'validated');
      assert.strictEqual(node._store.canonizeCMB(key, { byRole: 'validator' }).reason, 'insufficient-authority');
      assert.strictEqual(node._store.getLifecycle(key), 'validated', 'canonize blocked — stays validated');
    } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });
});

describe('aggregateAttestations — weighted by earned authority (EA6)', () => {
  it('weights verdicts by resolved rank, excludes unverifiable, flags over-claims', () => {
    const { node, name } = anchorNode('ea-agg');
    try {
      const V = kp('val'), P = kp('part'), O = kp('overclaim'), U = kp('unknown');
      // teach the node every attester's key, then grant V validator (so V resolves up)
      for (const x of [V, P, O]) node._roster.pin(x.nodeId, x.pub, 'handshake');
      node.grantRole(V.nodeId, 'validator');

      // anchor (self, weight 4) + validator (weight 2) admit; participant (weight 1) rejects;
      // an over-claimer asserts anchor but resolves participant (weight 1, mismatch); and an
      // attestation whose key we don't have (excluded entirely).
      node._attestations.record(att(node.nodeId, 'anchor', 'aligned', { focus: 'admit' }, node._identity.privateKey));
      node._attestations.record(att(V.nodeId, 'validator', 'aligned', { focus: 'admit' }, V.priv));
      node._attestations.record(att(P.nodeId, 'participant', 'rejected', { focus: 'reject' }, P.priv));
      node._attestations.record(att(O.nodeId, 'anchor', 'rejected', { focus: 'reject' }, O.priv));
      node._attestations.record(att(U.nodeId, 'participant', 'aligned', { focus: 'admit' }, U.priv));

      const agg = node.aggregateAttestations('cmb-agg');
      assert.strictEqual(agg.total, 4, 'four verifiable attestations');
      assert.strictEqual(agg.weight, 8, '4 + 2 + 1 + 1');
      assert.deepStrictEqual(agg.byRole, { participant: 2, validator: 1, anchor: 1 });
      assert.strictEqual(agg.overall.dominant, 'aligned');
      assert.strictEqual(agg.overall.tally.aligned, 6);
      assert.strictEqual(agg.overall.tally.rejected, 2);
      assert.strictEqual(agg.overall.confidence, 0.75, '6/8');
      assert.strictEqual(agg.fields.focus.dominant, 'admit');
      assert.strictEqual(agg.fields.focus.tally.admit, 6);
      // the over-claimer is down-weighted to participant AND surfaced as evidence
      assert.strictEqual(agg.mismatches.length, 1);
      assert.strictEqual(agg.mismatches[0].by, O.nodeId);
      assert.deepStrictEqual({ claimed: agg.mismatches[0].claimed, resolved: agg.mismatches[0].resolved }, { claimed: 'anchor', resolved: 'participant' });
      // the unverifiable attestation never votes
      assert.strictEqual(agg.excluded.length, 1);
      assert.strictEqual(agg.excluded[0].by, U.nodeId);
      assert.strictEqual(agg.excluded[0].reason, 'unknown-key');
    } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  it('a tampered attestation is excluded as bad-signature, not weighted', () => {
    const { node, name } = anchorNode('ea-agg-tamper');
    try {
      const P = kp('p');
      node._roster.pin(P.nodeId, P.pub, 'handshake');
      const a = att(P.nodeId, 'participant', 'aligned', { focus: 'admit' }, P.priv);
      a.verdict = 'rejected'; // tamper after signing
      node._attestations.record(a);
      const agg = node.aggregateAttestations('cmb-agg');
      assert.strictEqual(agg.total, 0);
      assert.strictEqual(agg.excluded.length, 1);
      assert.strictEqual(agg.excluded[0].reason, 'bad-signature');
    } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });
});
