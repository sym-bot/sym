'use strict';

/**
 * Earned-authority role-grant chain (MMP §6.5). Authority flows ONLY along signed
 * grant chains that terminate at the non-earnable anchor (the founder). The tests
 * pin down the Sybil-resistant resolution: over-reaching grants, unrooted chains,
 * and cycles confer nothing; only anchor-rooted, rank-respecting chains do.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { RoleGrantStore } = require('../lib/role-grant-store');
const { signGrant } = require('@sym-bot/core');

function kp(nodeId) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    nodeId,
    priv: privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(16).toString('base64url'),
    pub: publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('base64url'),
  };
}

const T = 1_000_000;
function grant(type, grantee, role, grantor, at) {
  return signGrant({ type, grantee: grantee.nodeId, role, grantedBy: grantor.nodeId, grantedAt: at }, grantor.priv);
}

/** A store whose keys map is pre-populated with every party's pubkey + anchor pinned. */
function storeWith(anchor, parties, opts = {}) {
  const keys = new Map();
  for (const p of [anchor, ...parties]) keys.set(p.nodeId, p.pub);
  return new RoleGrantStore({ anchor: { nodeId: anchor.nodeId, publicKey: anchor.pub }, keys, ...opts });
}

describe('RoleGrantStore.resolveRole — anchor-rooted, Sybil-resistant', () => {
  it('the anchor is anchor; an unknown node is participant', () => {
    const A = kp('A');
    const st = storeWith(A, []);
    assert.strictEqual(st.resolveRole(A.nodeId, T), 'anchor');
    assert.strictEqual(st.resolveRole('nobody', T), 'participant');
  });

  it('the anchor can grant validator + anchor', () => {
    const A = kp('A'), V = kp('V'), N = kp('N');
    const st = storeWith(A, [V, N]);
    assert.strictEqual(st.record(grant('role-grant', V, 'validator', A, T)).stored, true);
    assert.strictEqual(st.record(grant('role-grant', N, 'anchor', A, T)).stored, true);
    assert.strictEqual(st.resolveRole(V.nodeId, T + 1), 'validator');
    assert.strictEqual(st.resolveRole(N.nodeId, T + 1), 'anchor');
  });

  it('a validator can confer validator (delegation), rooted via the anchor', () => {
    const A = kp('A'), V = kp('V'), V2 = kp('V2');
    const st = storeWith(A, [V, V2]);
    st.record(grant('role-grant', V, 'validator', A, T));     // anchor → V validator
    st.record(grant('role-grant', V2, 'validator', V, T + 5)); // V → V2 validator (V is validator at T+5)
    assert.strictEqual(st.resolveRole(V2.nodeId, T + 6), 'validator');
  });

  it('over-reach confers nothing: a validator cannot grant anchor', () => {
    const A = kp('A'), V = kp('V'), X = kp('X');
    const st = storeWith(A, [V, X]);
    st.record(grant('role-grant', V, 'validator', A, T));
    st.record(grant('role-grant', X, 'anchor', V, T + 5)); // validator cannot confer anchor
    assert.strictEqual(st.resolveRole(X.nodeId, T + 6), 'participant');
  });

  it('an unrooted grant confers nothing (grantor has no anchor-rooted authority)', () => {
    const A = kp('A'), X = kp('X'), Y = kp('Y');
    const st = storeWith(A, [X, Y]);
    st.record(grant('role-grant', Y, 'validator', X, T)); // X is a participant — confers nothing
    assert.strictEqual(st.resolveRole(Y.nodeId, T + 1), 'participant');
  });

  it('a cycle confers nothing (Sybil ring cannot bootstrap authority)', () => {
    const A = kp('A'), P = kp('P'), Q = kp('Q');
    const st = storeWith(A, [P, Q]);
    st.record(grant('role-grant', P, 'validator', Q, T));
    st.record(grant('role-grant', Q, 'validator', P, T));
    assert.strictEqual(st.resolveRole(P.nodeId, T + 1), 'participant');
    assert.strictEqual(st.resolveRole(Q.nodeId, T + 1), 'participant');
  });

  it('role-at-time: a grant made before the grantor had rank confers nothing', () => {
    const A = kp('A'), V = kp('V'), V2 = kp('V2');
    const st = storeWith(A, [V, V2]);
    st.record(grant('role-grant', V2, 'validator', V, T));      // V grants V2 at T (V not yet validator)
    st.record(grant('role-grant', V, 'validator', A, T + 100)); // V becomes validator only at T+100
    assert.strictEqual(st.resolveRole(V2.nodeId, T + 200), 'participant', 'grant predates the grantor\'s authority');
  });

  it('revocation: an anchor revoke clears the role; before the revoke it still holds', () => {
    const A = kp('A'), V = kp('V');
    const st = storeWith(A, [V]);
    st.record(grant('role-grant', V, 'validator', A, T));
    st.record(grant('role-revoke', V, undefined, A, T + 100));
    assert.strictEqual(st.resolveRole(V.nodeId, T + 50), 'validator', 'held before the revoke');
    assert.strictEqual(st.resolveRole(V.nodeId, T + 200), 'participant', 'cleared after the revoke');
  });
});

describe('RoleGrantStore — signature gate + persistence', () => {
  it('rejects a forged grant and an unknown grantor', () => {
    const A = kp('A'), V = kp('V'), imposter = kp('imp');
    const st = storeWith(A, [V]); // imposter key NOT pinned
    const forged = grant('role-grant', V, 'anchor', A, T);
    forged.role = 'validator'; // tamper after signing
    assert.strictEqual(st.record(forged).reason, 'bad-signature');
    // a grant from a node whose key we don't have
    assert.strictEqual(st.record(grant('role-grant', V, 'validator', imposter, T)).reason, 'unknown-grantor-key');
  });

  it('persists grants append-only and reloads resolution across a restart', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rg-'));
    try {
      const A = kp('A'), V = kp('V');
      const s1 = storeWith(A, [V], { dir });
      s1.record(grant('role-grant', V, 'validator', A, T));
      // a fresh store over the same dir reloads + resolves the same
      const s2 = storeWith(A, [V], { dir });
      assert.strictEqual(s2.resolveRole(V.nodeId, T + 1), 'validator', 'reloaded grant still confers');
      assert.strictEqual(s2.size(), 1);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
});
