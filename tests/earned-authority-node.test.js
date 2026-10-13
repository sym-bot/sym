'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * A node's use of authority (MMP §6.5, §6.6.9, §6.6.10): the roles it resolves for itself and for
 * others from its in-force set, the role its attestations carry, the lifecycle transitions it may make
 * on a CMB (judged on that CMB's own fields, a scoped grant only inside its scope), and the weight an
 * attestation counts with, judged against the in-force set when the weight is applied.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const crypto = require('crypto');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir, loadOrCreateIdentity, uuidv7 } = require('../lib/config');
const { verifyAttestationRole, signAttestation } = require('../lib/core');
const { statementId } = require('../lib/core/authority');

function kp() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    nodeId: uuidv7(),
    priv: privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(16).toString('base64url'),
    pub: publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('base64url'),
  };
}
function att(by, role, verdict, categories, priv) {
  const a = { of: 'cmb-agg', by, at: Date.now(), roster: 'g', method: 'heuristic', verdict, categories, role, seq: 1, prev: null };
  return signAttestation(a, priv);
}
const uniq = (b) => `${b}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;

/** A node pinned as its own 1-of-1 anchor (the founder case): its identity made first, then pinned. */
function anchorNode(base, opts = {}) {
  const name = uniq(base);
  const id = loadOrCreateIdentity(name);
  const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: 'g', anchor: { nodeId: id.nodeId, publicKey: id.publicKey }, ...opts });
  return { node, name, pin: { nodeId: id.nodeId, publicKey: id.publicKey } };
}
function cleanup(...names) { for (const n of names) fs.rmSync(nodeDir(n), { recursive: true, force: true }); }

describe('roles from the in-force set (MMP §6.6.9)', () => {
  it('a node pinned as the anchor resolves to anchor, grants a role to a proven key, and a revoke ends it', () => {
    const { node, name } = anchorNode('ea-anchor');
    try {
      assert.strictEqual(node.resolveRole(node.nodeId), 'anchor');
      const peer = kp();
      assert.strictEqual(node.grantRole(peer.nodeId, 'validator'), null, 'no grant to an id whose key nothing proved');
      node._roster.bind(peer.nodeId, peer.pub, 'proven');
      const g = node.grantRole(peer.nodeId, 'validator');
      assert.ok(g && g.kind === 'grant' && g.authorisedBy === 'anchor', 'an anchor-level grant');
      assert.deepStrictEqual(g.subject, { nodeId: peer.nodeId, key: peer.pub }, 'it names the nodeId and the key');
      assert.strictEqual(node.resolveRole(peer.nodeId), 'validator');
      const r = node.revokeRole(peer.nodeId);
      assert.ok(r && r.kind === 'revoke');
      assert.strictEqual(node.resolveRole(peer.nodeId), 'participant', 'revoked: participant');
      assert.strictEqual(node.revokeRole(peer.nodeId), null, 'nothing left in force to revoke');
    } finally { cleanup(name); }
  });

  it('roles follow the key: the same nodeId holding another key has none of them', () => {
    const { node, name } = anchorNode('ea-key');
    try {
      const peer = kp(); const other = kp();
      node.grant({ nodeId: peer.nodeId, key: peer.pub }, 'admin');
      assert.strictEqual(node.resolveRole(peer.nodeId, { key: peer.pub }), 'admin');
      assert.strictEqual(node.resolveRole(peer.nodeId, { key: other.pub }), 'participant');
    } finally { cleanup(name); }
  });

  it('attestations stamp the resolved role, which matches the in-force set', () => {
    const { node, name } = anchorNode('ea-att-role');
    try {
      const a = node._buildAdmissionAttestation('cmb-1', 'aligned', { focus: 'admit' }, 'heuristic');
      assert.strictEqual(a.role, 'anchor');
      const r = verifyAttestationRole(a, (by) => node.resolveRole(by));
      assert.strictEqual(r.resolved, 'anchor');
      assert.strictEqual(r.matches, true);
    } finally { cleanup(name); }
  });

  it('an anchored node holding no grant is a participant; with no anchor pinned, the configured lifecycleRole stands', () => {
    const someone = kp();
    const n1 = uniq('ea-plain');
    const plain = new SymNode({ name: n1, silent: true, discovery: new NullDiscovery(), room: 'g', anchor: { nodeId: someone.nodeId, publicKey: someone.pub } });
    const n2 = uniq('ea-legacy');
    const legacy = new SymNode({ name: n2, silent: true, discovery: new NullDiscovery(), lifecycleRole: 'validator' });
    try {
      assert.strictEqual(plain._resolvedRole(), 'participant', 'no grant: participant, never self-asserted');
      assert.strictEqual(legacy._resolvedRole(), 'validator', 'no anchor: a closed development mode');
      assert.strictEqual(legacy.resolveRole(someone.nodeId), 'participant', 'and nobody else holds anything');
      assert.strictEqual(legacy.authorityRoot(), null, 'no anchor, no root');
    } finally { cleanup(n1, n2); }
  });

  it('a pin that is not a valid key set stops the node instead of running without the root it asked for', () => {
    assert.throws(() => new SymNode({ name: uniq('ea-badpin'), silent: true, discovery: new NullDiscovery(), anchor: { nodeId: 'someone-else', publicKey: 'AAAA' } }));
  });
});

describe('§6.5 lifecycle gating: the node\'s authority over THAT CMB', () => {
  function seed(node, cmb = null, key = 'cmb-to-validate') {
    node._store._cache.set(key, { key, lifecycle: 'remixed', anchorWeight: 1.0, cmb });
    return key;
  }

  it('a participant cannot validate or canonize: the CMB is left untouched', () => {
    const someone = kp();
    const name = uniq('ea65-part');
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: 'g', anchor: { nodeId: someone.nodeId, publicKey: someone.pub } });
    try {
      const key = seed(node);
      assert.deepStrictEqual(node.validateCMB(key), { ok: false, reason: 'insufficient-authority' });
      assert.strictEqual(node._store.getLifecycle(key), 'remixed');
      assert.deepStrictEqual(node.canonizeCMB(key), { ok: false, reason: 'insufficient-authority' });
    } finally { cleanup(name); }
  });

  it('the anchor can validate and canonize', () => {
    const { node, name } = anchorNode('ea65-anchor');
    try {
      const key = seed(node);
      assert.strictEqual(node.validateCMB(key).ok, true);
      assert.strictEqual(node._store.getLifecycle(key), 'validated');
      assert.strictEqual(node.canonizeCMB(key).ok, true);
      assert.strictEqual(node._store.getLifecycle(key), 'canonical');
    } finally { cleanup(name); }
  });

  it('the store gate: validated authority validates and cannot canonize; a role name is not authority', () => {
    const { node, name } = anchorNode('ea65-rank');
    try {
      const key = seed(node);
      assert.strictEqual(node._store.validateCMB(key, { lifecycle: 'validated' }).ok, true);
      assert.strictEqual(node._store.canonizeCMB(key, { lifecycle: 'validated' }).reason, 'insufficient-authority');
      assert.strictEqual(node._store.getLifecycle(key), 'validated');
      assert.strictEqual(node._store.validateCMB(seed(node, null, 'k2'), { byRole: 'anchor' }).reason, 'insufficient-authority');
    } finally { cleanup(name); }
  });

  it('a scoped validator validates only CMBs inside its scope, judged on each CMB\'s own fields, and only where the namespace is implemented', () => {
    const { node: AN, name: an, pin } = anchorNode('ea65-scope-anchor');
    const world = (p, cmb) => !!(cmb && typeof cmb.world === 'string' && (cmb.world === p || cmb.world.startsWith(`${p}/`)));
    const nx = uniq('ea65-scoped');
    const X = new SymNode({ name: nx, silent: true, discovery: new NullDiscovery(), room: 'g', anchor: pin, authorityScopes: { 'test-world': world } });
    const ny = uniq('ea65-unscoped');
    const Y = new SymNode({ name: ny, silent: true, discovery: new NullDiscovery(), room: 'g', anchor: pin });
    try {
      const g = AN.grant({ nodeId: X.nodeId, key: X._identity.publicKey }, 'validator', { scope: 'test-world:w1' });
      assert.strictEqual(X.submitAuthority(g.statement).status, 'in-force');
      assert.strictEqual(Y.submitAuthority(g.statement).status, 'in-force');
      assert.strictEqual(X.resolveRole(X.nodeId), 'participant', 'a scoped role is not an unscoped one');
      assert.strictEqual(X.validateCMB(seed(X, { world: 'w1/room-3' }, 'in')).ok, true);
      assert.strictEqual(X.validateCMB(seed(X, { world: 'w10' }, 'out')).ok, false);
      assert.strictEqual(X.validateCMB(seed(X, null, 'none')).ok, false);
      assert.strictEqual(X.lifecycleAuthority(X.nodeId, X._identity.publicKey, { world: 'w1' }), 'validated');
      // Y holds the same grant but does not implement the namespace: X's scoped role gives nothing there.
      assert.strictEqual(Y.lifecycleAuthority(X.nodeId, X._identity.publicKey, { world: 'w1' }), 'none');
    } finally { cleanup(an, nx, ny); }
  });
});

describe('aggregateAttestations: weights judged against the in-force set when applied (§6.6.10)', () => {
  it('weights verdicts by resolved rank, excludes the unverifiable, flags over-claims; a revoke changes the weight at once', () => {
    const { node, name } = anchorNode('ea-agg');
    try {
      const V = kp(), P = kp(), O = kp(), U = kp();
      for (const x of [V, P, O]) node._roster.bind(x.nodeId, x.pub, 'proven');
      const gV = node.grantRole(V.nodeId, 'validator');
      node._attestations.record(att(node.nodeId, 'anchor', 'aligned', { focus: 'admit' }, node._identity.privateKey));
      node._attestations.record(att(V.nodeId, 'validator', 'aligned', { focus: 'admit' }, V.priv));
      node._attestations.record(att(P.nodeId, 'participant', 'rejected', { focus: 'reject' }, P.priv));
      node._attestations.record(att(O.nodeId, 'anchor', 'rejected', { focus: 'reject' }, O.priv));
      node._attestations.record(att(U.nodeId, 'participant', 'aligned', { focus: 'admit' }, U.priv));

      const agg = node.aggregateAttestations('cmb-agg');
      assert.strictEqual(agg.total, 4);
      assert.strictEqual(agg.weight, 8, '4 + 2 + 1 + 1');
      assert.deepStrictEqual(agg.byRole, { participant: 2, issuer: 0, validator: 1, admin: 0, anchor: 1 });
      assert.strictEqual(agg.overall.dominant, 'aligned');
      assert.strictEqual(agg.overall.tally.aligned, 6);
      assert.strictEqual(agg.overall.confidence, 0.75);
      assert.deepStrictEqual(agg.mismatches, [{ by: O.nodeId, claimed: 'anchor', resolved: 'participant' }]);
      assert.deepStrictEqual(agg.excluded, [{ by: U.nodeId, reason: 'unknown-key' }]);

      // The validator's grant revoked: the same attestations weigh as the set stands now.
      node.revoke([statementId(gV)]);
      const after = node.aggregateAttestations('cmb-agg');
      assert.strictEqual(after.weight, 7, '4 + 1 + 1 + 1: no role "at the time" is kept');
      assert.strictEqual(after.mismatches.length, 2, 'the validator\'s stamp is now an over-claim');
    } finally { cleanup(name); }
  });

  it('a tampered attestation is excluded as bad-signature, not weighted', () => {
    const { node, name } = anchorNode('ea-agg-tamper');
    try {
      const P = kp();
      node._roster.bind(P.nodeId, P.pub, 'proven');
      const a = att(P.nodeId, 'participant', 'aligned', { focus: 'admit' }, P.priv);
      a.verdict = 'rejected';
      node._attestations.record(a);
      const agg = node.aggregateAttestations('cmb-agg');
      assert.strictEqual(agg.total, 0);
      assert.deepStrictEqual(agg.excluded, [{ by: P.nodeId, reason: 'bad-signature' }]);
    } finally { cleanup(name); }
  });
});
