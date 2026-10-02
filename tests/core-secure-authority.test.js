'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * Design D3 — authority follows the key.
 *   - resolveRole(nodeId, key, at): a grant confers its role only when its granteeKey is the key the
 *     subject holds, so an id claimed under another key is a participant.
 *   - Grant chains are verified top-down with the key each verified grant vouches, never with the key
 *     the registry holds for the grantor: a grantor bound to an impostor keeps exactly the authority
 *     of its vouched key, and the impostor gets none.
 *   - Every role-grant carries granteeKey; grantRole refuses without a proven key for the grantee.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const { RoleGrantStore } = require('../lib/role-grant-store');
const { RosterKeyRegistry } = require('../lib/roster-keys');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir, loadOrCreateIdentity } = require('../lib/config');
const { signGrant } = require('../lib/core');

function kp(nodeId) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    // nodeIds are canonical lowercase at every door, a grant's included (security review B).
    nodeId: nodeId.toLowerCase(),
    priv: privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(16).toString('base64url'),
    pub: publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('base64url'),
  };
}
const T = 1_000_000;
const grant = (grantee, granteeKey, role, grantor, at) =>
  signGrant({ type: 'role-grant', grantee: grantee.nodeId, granteeKey, role, grantedBy: grantor.nodeId, grantedAt: at }, grantor.priv);

describe('authority follows the key (D3)', () => {
  it('a grant confers its role only on the key it names', () => {
    const A = kp('A'), V = kp('V'), impostor = kp('V');
    const st = new RoleGrantStore({ anchor: { nodeId: A.nodeId, publicKey: A.pub } });
    assert.strictEqual(st.record(grant(V, V.pub, 'validator', A, T)).stored, true);
    assert.strictEqual(st.resolveRole(V.nodeId, V.pub, T + 1), 'validator');
    assert.strictEqual(st.resolveRole(V.nodeId, impostor.pub, T + 1), 'participant', 'the same id under another key holds nothing');
    assert.strictEqual(st.resolveRole(A.nodeId, impostor.pub, T + 1), 'participant', 'not even the anchor id');
    assert.strictEqual(st.resolveRole(A.nodeId, A.pub, T + 1), 'anchor');
  });

  it('a grantor bound to an impostor: its chain is verified with the vouched key, and the impostor gets nothing', () => {
    const A = kp('A'), G = kp('G'), impG = kp('G'), X = kp('X'), Y = kp('Y');
    const reg = new RosterKeyRegistry({ anchor: { nodeId: A.nodeId, publicKey: A.pub } });
    // The impostor proved first contact under G's id; the registry holds the impostor's key for G.
    reg.bind(G.nodeId, impG.pub, 'proven');
    const st = new RoleGrantStore({ anchor: { nodeId: A.nodeId, publicKey: A.pub }, keys: reg });
    // The anchor vouches G's real key.
    assert.strictEqual(st.record(grant(G, G.pub, 'validator', A, T)).stored, true);
    assert.strictEqual(reg.get(G.nodeId), impG.pub, 'the registry binding is not repointed');
    assert.strictEqual(reg.conflicts().length, 1, 'the vouch against it is a recorded conflict');
    // A grant the real G signs verifies against its vouched key and confers.
    assert.strictEqual(st.record(grant(X, X.pub, 'validator', G, T + 10)).stored, true);
    assert.strictEqual(st.resolveRole(X.nodeId, X.pub, T + 20), 'validator');
    // A grant the impostor signs as G is checked against the vouched key, not the registry's: refused.
    assert.strictEqual(st.record(grant(Y, Y.pub, 'validator', impG, T + 10)).reason, 'bad-signature');
    assert.strictEqual(st.resolveRole(Y.nodeId, Y.pub, T + 20), 'participant');
    // And the impostor itself, holding the id under its own key, is a participant.
    assert.strictEqual(st.resolveRole(G.nodeId, impG.pub, T + 20), 'participant');
    assert.strictEqual(st.resolver()(G.nodeId, T + 20), 'participant', 'the registry-bound key resolves to nothing');
  });

  it('a grant chain is verified with vouched keys, hop by hop, in any file order', () => {
    const dir = fs.mkdtempSync(require('path').join(require('os').tmpdir(), 'rg-chain-'));
    try {
      const A = kp('A'), B = kp('B'), C = kp('C'), D = kp('D');
      const recs = [
        grant(D, D.pub, 'validator', C, T + 30),
        grant(C, C.pub, 'validator', B, T + 20),
        grant(B, B.pub, 'validator', A, T + 10),
      ];
      fs.writeFileSync(require('path').join(dir, 'role-grants.jsonl'), recs.map((r) => JSON.stringify(r)).join('\n') + '\n');
      // The registry knows none of B, C, D: nothing but the anchor and the chain itself verifies.
      const st = new RoleGrantStore({ anchor: { nodeId: A.nodeId, publicKey: A.pub }, dir, keys: new RosterKeyRegistry() });
      assert.strictEqual(st.loadReport().loaded, 3);
      assert.strictEqual(st.resolveRole(D.nodeId, D.pub, T + 40), 'validator');
      // A link whose vouched key is not the one that signed the next hop breaks the chain below it.
      const E = kp('E'), Cfake = kp('C');
      const st2 = new RoleGrantStore({ anchor: { nodeId: A.nodeId, publicKey: A.pub } });
      st2.record(grant(B, B.pub, 'validator', A, T + 10));
      st2.record(grant(C, C.pub, 'validator', B, T + 20));
      assert.strictEqual(st2.record(grant(E, E.pub, 'validator', Cfake, T + 30)).reason, 'bad-signature');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('a role-grant without granteeKey is malformed, on the wire and on disk', () => {
    const A = kp('A'), V = kp('V');
    const st = new RoleGrantStore({ anchor: { nodeId: A.nodeId, publicKey: A.pub } });
    const bare = signGrant({ type: 'role-grant', grantee: V.nodeId, role: 'validator', grantedBy: A.nodeId, grantedAt: T }, A.priv);
    assert.strictEqual(st.record(bare).reason, 'malformed');
    const revoke = signGrant({ type: 'role-revoke', grantee: V.nodeId, grantedBy: A.nodeId, grantedAt: T }, A.priv);
    assert.strictEqual(st.record(revoke).stored, true, 'a revoke names no key: it clears the id whatever key it holds');
  });
});

describe('grantRole names a proven key (D3)', () => {
  function anchorNode() {
    const name = `d3-anchor-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const id = loadOrCreateIdentity(name);
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: 'g', anchor: { nodeId: id.nodeId, publicKey: id.publicKey } });
    return { node, name };
  }

  it('refuses a grantee with no key, a legacy claim or a grant-vouched key; takes a proven or pinned one', () => {
    const { node, name } = anchorNode();
    try {
      const sent = [];
      node._gossipToRoster = (f) => sent.push(f);
      const [P, L, G, Q] = ['p', 'l', 'g', 'q'].map(kp);
      assert.strictEqual(node.grantRole(P.nodeId, 'validator'), null, 'no key at all');
      node._roster.bind(L.nodeId, L.pub, 'legacy-claim');
      assert.strictEqual(node.grantRole(L.nodeId, 'validator'), null, 'an unproven hello is not a proof');
      node._roster.bind(G.nodeId, G.pub, 'grant');
      assert.strictEqual(node.grantRole(G.nodeId, 'validator'), null, 'a vouched key is not this node\'s proof');
      assert.deepStrictEqual(sent, [], 'nothing was sent for any of them');
      node._roster.bind(P.nodeId, P.pub, 'proven');
      const g = node.grantRole(P.nodeId, 'validator');
      assert.strictEqual(g.granteeKey, P.pub);
      node._roster.bind(Q.nodeId, Q.pub, 'pinned');
      assert.strictEqual(node.grantRole(Q.nodeId, 'validator').granteeKey, Q.pub);
      assert.strictEqual(node.grantRole(L.nodeId, 'validator', { granteeKey: L.pub }).granteeKey, L.pub, 'or the operator names the key');
      assert.strictEqual(node.resolveRole(P.nodeId), 'validator');
    } finally { node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });
});
