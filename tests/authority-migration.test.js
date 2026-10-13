'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * MMP §6.6.1 and §6.6.11 on a node: an anchor-level statement under a threshold above 1, signed by
 * one key holder and co-signed by another, and the migration from the time-replay rule — the old
 * grants confer nothing, and the operator reads them as plain data to re-issue what should stand.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDirById, loadOrCreateIdentity } = require('../lib/config');
const A = require('../lib/core/authority');
const { identity } = require('./_core-secure');

const uniq = (b) => `${b}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
const made = [];
function node(name, opts) {
  const n = new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: 'mig', ...opts });
  made.push(n);
  return n;
}
async function stopAll() {
  for (const n of made.splice(0)) { try { await n.stop(); } catch { /* */ } try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ } }
}

describe('§6.6.1: a threshold anchor on nodes', () => {
  it('2 of 3: one holder signs, a second co-signs, and only then is the statement valid; no holder alone is the anchor', async () => {
    try {
      const names = [uniq('k1'), uniq('k2'), uniq('k3')];
      const ids = names.map((n) => loadOrCreateIdentity(n));
      const pin = { threshold: 2, keys: ids.map((i) => ({ key: i.publicKey, nodeId: i.nodeId })) };
      const [K1, K2] = names.slice(0, 2).map((n) => node(n, { anchor: pin }));
      const other = node(uniq('obs'), { anchor: pin });
      assert.strictEqual(K1.resolveRole(K1.nodeId), 'participant', 'under a threshold above 1 no holder alone is the anchor');
      const subject = identity('s');
      const half = K1.authorityStatement({ kind: 'grant', subject: { nodeId: subject.nodeId, key: subject.publicKey }, role: 'admin' }, { asAnchor: true });
      assert.strictEqual(half.authorisedBy, 'anchor');
      assert.strictEqual(other.submitAuthority(half).result, 'invalid', 'one of the two signatures it needs');
      const whole = K2.cosignAuthority(half);
      assert.strictEqual(whole.sigs.length, 2);
      assert.strictEqual(A.statementId(whole), A.statementId(half), 'the same statement, more signatures');
      const r = other.submitAuthority(whole);
      assert.strictEqual(r.result, 'held');
      assert.strictEqual(r.status, 'in-force');
      assert.strictEqual(other.resolveRole(subject.nodeId, { key: subject.publicKey }), 'admin');
      assert.throws(() => other.cosignAuthority(half), (e) => e.code === 'ENOAUTHORITY', 'a node whose key is not pinned cannot co-sign');
    } finally { await stopAll(); }
  });
});

describe('§6.6.11: migration from the time-replay rule', () => {
  it('a 0.13 grant store confers nothing; legacyRoleGrants lists it as plain data, the anchor role read as admin; re-issued, it stands', async () => {
    try {
      const name = uniq('mig-anchor');
      const id = loadOrCreateIdentity(name);
      const dir = nodeDirById(id.nodeId);
      const V = identity('v'); const W = identity('w');
      fs.mkdirSync(path.join(dir, 'role-grants'), { recursive: true });
      const old = [
        { type: 'role-grant', grantee: V.nodeId, granteeKey: V.publicKey, role: 'validator', grantedBy: id.nodeId, grantedAt: 1, sig: 'x', sigAlg: 'ed25519' },
        { grant: { type: 'role-grant', grantee: W.nodeId, granteeKey: W.publicKey, role: 'anchor', grantedBy: id.nodeId, grantedAt: 2, sig: 'y', sigAlg: 'ed25519' } },
        { type: 'role-revoke', grantee: V.nodeId, grantedBy: id.nodeId, grantedAt: 3, sig: 'z', sigAlg: 'ed25519' },
      ];
      fs.writeFileSync(path.join(dir, 'role-grants', 'role-grants.jsonl'), old.map((o) => JSON.stringify(o)).join('\n') + '\n{not json\n');
      const before = fs.readFileSync(path.join(dir, 'role-grants', 'role-grants.jsonl'), 'utf8');
      const N = node(name, { anchor: { nodeId: id.nodeId, publicKey: id.publicKey } });
      assert.strictEqual(N.resolveRole(V.nodeId), 'participant', 'the old grants confer nothing');
      assert.strictEqual(N.resolveRole(W.nodeId), 'participant');
      const legacy = N.legacyRoleGrants();
      assert.deepStrictEqual(legacy, [
        { grantee: V.nodeId, granteeKey: V.publicKey, role: 'validator', grantedBy: id.nodeId },
        { grantee: W.nodeId, granteeKey: W.publicKey, role: 'admin', grantedBy: id.nodeId },
      ]);
      assert.strictEqual(fs.readFileSync(path.join(dir, 'role-grants', 'role-grants.jsonl'), 'utf8'), before, 'the old file is never rewritten');
      // The anchor's holder re-issues what should stand, one for one (§6.6.11).
      for (const g of legacy) N.grant({ nodeId: g.grantee, key: g.granteeKey }, g.role);
      assert.strictEqual(N.resolveRole(V.nodeId), 'validator');
      assert.strictEqual(N.resolveRole(W.nodeId), 'admin');
    } finally { await stopAll(); }
  });
});
