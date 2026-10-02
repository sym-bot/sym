'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * 0.13.17 review (R1). The hotfix keeps a role-grant only when it is rooted at the anchor, and
 * refused the rest at receipt. Rooted is a property of the chain, not of arrival order: gossip can
 * bring a grant, or a revoke, before the grant that roots its grantor, refused records were not
 * relayed and there is no grant sync, so such a record was lost for good, and the node resolved
 * different roles from 0.13.16 (which kept everything). A record refused for a curable reason
 * (`unknown-grantor-key`, `unrooted`) now waits in a bounded in-memory pending set, never written
 * and never relayed, and is stored, persisted and relayed once a stored record roots it.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { RoleGrantStore } = require('../lib/role-grant-store');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const { signGrant } = require('../lib/core');

function kp(nodeId) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    nodeId,
    priv: privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(16).toString('base64url'),
    pub: publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('base64url'),
  };
}
const grant = (type, grantee, role, grantor, at, extra = {}) =>
  signGrant({ type, grantee: grantee.nodeId, role, grantedBy: grantor.nodeId, grantedAt: at, ...extra }, grantor.priv);
const uniq = (base) => `${base}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
const grantsFile = (name) => path.join(nodeDir(name), 'role-grants', 'role-grants.jsonl');
const lines = (file) => (fs.existsSync(file) ? fs.readFileSync(file, 'utf8').split('\n').filter(Boolean) : []);

describe('a grant or revoke that arrives before its root is not lost (R1)', () => {
  const A = kp('anchor'), V = kp('val'), X = kp('x');
  const t = Date.now();
  const gAV = grant('role-grant', V, 'validator', A, t - 3000, { granteeKey: V.pub });
  const gVX = grant('role-grant', X, 'validator', V, t - 2000, { granteeKey: X.pub });
  const rVX = grant('role-revoke', X, undefined, V, t - 1000);
  const store = (keys = new Map()) => new RoleGrantStore({ anchor: { nodeId: A.nodeId, publicKey: A.pub }, keys });

  // The roles 0.13.16 resolved for each order (it kept every record, rooted or not).
  for (const [order, role] of [
    [['AV', 'VX'], 'validator'],
    [['VX', 'AV'], 'validator'],          // the grant arrives first (grantor key unknown)
    [['AV', 'VX', 'rVX'], 'participant'],
    [['AV', 'rVX', 'VX'], 'participant'],
    [['rVX', 'VX', 'AV'], 'participant'], // both before their root
    [['VX', 'rVX', 'AV'], 'participant'],
  ]) {
    it(`grant case ${order.join(' → ')}: X ends ${role}, as in 0.13.16`, () => {
      const s = store();
      const recs = { AV: gAV, VX: gVX, rVX };
      for (const k of order) s.record(recs[k]);
      assert.strictEqual(s.resolveRole(X.nodeId, Date.now()), role);
      assert.strictEqual(s.pendingSize(), 0, 'nothing is left waiting once the root is in');
    });
  }

  it('revoke case: a revoke that arrives before the grant rooting its revoker still revokes', () => {
    const gAX = grant('role-grant', X, 'validator', A, t - 5000);
    const gAV2 = grant('role-grant', V, 'validator', A, t - 4000);
    const s = store(new Map([[V.nodeId, V.pub]]));
    assert.strictEqual(s.record(gAX).stored, true);
    assert.deepStrictEqual(s.record(rVX), { stored: false, reason: 'unrooted' }, 'refused at receipt, as before');
    assert.strictEqual(s.resolveRole(X.nodeId, Date.now()), 'validator', 'and no effect while it waits');
    const r = s.record(gAV2);
    assert.strictEqual(r.stored, true);
    assert.deepStrictEqual(r.released, [rVX], 'the stored grant releases the revoke it roots');
    assert.strictEqual(s.resolveRole(X.nodeId, Date.now()), 'participant', 'as 0.13.16 resolved it');
  });

  it('the pending set is bounded: the oldest is dropped first', () => {
    const s = new RoleGrantStore({ anchor: { nodeId: A.nodeId, publicKey: A.pub }, keys: new Map(), maxPending: 3 });
    const Ys = [0, 1, 2, 3, 4].map((i) => kp(`y${i}`));
    const waiting = Ys.map((Y, i) => grant('role-grant', Y, 'validator', V, t - 2000 + i));
    for (const g of waiting) assert.strictEqual(s.record(g).stored, false);
    for (const g of waiting) s.record(g); // re-sending them changes nothing
    const r = s.record(gAV);
    assert.deepStrictEqual(Ys.map((Y) => s.resolveRole(Y.nodeId, Date.now())),
      ['participant', 'participant', 'validator', 'validator', 'validator'], 'the newest three waited; the oldest two were dropped');
    assert.deepStrictEqual(r.released.map((g) => g.grantee), ['y2', 'y3', 'y4']);
    assert.strictEqual(s.pendingSize(), 0);
  });

  it('the default bound is 1024', () => {
    const s = store();
    for (let i = 0; i < 1100; i++) s.record({ type: 'role-grant', grantee: `g${i}`, role: 'validator', grantedBy: 'nobody', grantedAt: t, sig: `s${i}`, sigAlg: 'ed25519' });
    assert.strictEqual(s.pendingSize(), 1024);
  });

  it('a forged copy sent ahead of the genuine record cannot displace it, and is dropped when its grantor is rooted', () => {
    const s = store();
    const forged = { ...gVX, granteeKey: kp('other').pub }; // same sig, a different signed field
    s.record(forged);
    s.record(gVX);
    const r = s.record(gAV);
    assert.strictEqual(s.resolveRole(X.nodeId, Date.now()), 'validator');
    assert.deepStrictEqual(r.released, [gVX]);
    assert.strictEqual(s.pendingSize(), 0, 'the forgery failed its signature check and is gone');
  });
});

describe('nothing pending is written or relayed; a released record is persisted and relayed once (R1)', () => {
  it('a node holds an early grant in memory, then writes and relays it when its root arrives', () => {
    const name = uniq('rg-pending');
    const A = kp('anchor'), V = kp('val'), X = kp('x'), relayer = kp('relayer');
    const t = Date.now();
    const gAV = grant('role-grant', V, 'validator', A, t - 3000, { granteeKey: V.pub });
    const gVX = grant('role-grant', X, 'validator', V, t - 2000, { granteeKey: X.pub });
    const boot = () => new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: 'g', anchor: { nodeId: A.nodeId, publicKey: A.pub } });
    let node = boot();
    try {
      const relayed = [];
      node._gossipToRoster = (frame, except) => relayed.push({ sig: frame.grant.sig, except });
      node._frameHandler.handle(relayer.nodeId, 'relayer', { type: 'handshake', nodeId: relayer.nodeId, name: 'relayer', publicKey: relayer.pub });
      node._frameHandler.handle(relayer.nodeId, 'relayer', { type: 'role-grant', grant: gVX });
      assert.deepStrictEqual(lines(grantsFile(name)), [], 'not written while it waits');
      assert.deepStrictEqual(relayed, [], 'not relayed while it waits');
      assert.strictEqual(node.resolveRole(X.nodeId), 'participant', 'and no effect');

      node._frameHandler.handle(relayer.nodeId, 'relayer', { type: 'role-grant', grant: gAV });
      assert.deepStrictEqual(relayed, [
        { sig: gAV.sig, except: relayer.nodeId },
        { sig: gVX.sig, except: undefined },
      ], 'the root is relayed, then the record it released');
      assert.deepStrictEqual(lines(grantsFile(name)).map((l) => JSON.parse(l).sig), [gAV.sig, gVX.sig], 'both persisted, root first');
      assert.strictEqual(node.resolveRole(X.nodeId), 'validator');
      assert.strictEqual(node._roleGrants.pendingSize(), 0);
      node.stop();
      node = boot();
      assert.strictEqual(node.resolveRole(X.nodeId), 'validator', 'and both survive a restart');
    } finally { node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  it('a record a 0.13.16 file left unrooted waits too, and is not written again when it is rooted', () => {
    const name = uniq('rg-pending-file');
    const A = kp('anchor'), V = kp('val'), X = kp('x');
    const t = Date.now();
    const gAV = grant('role-grant', V, 'validator', A, t - 3000, { granteeKey: V.pub });
    const gVX = grant('role-grant', X, 'validator', V, t - 2000, { granteeKey: X.pub });
    fs.mkdirSync(path.dirname(grantsFile(name)), { recursive: true });
    fs.writeFileSync(grantsFile(name), JSON.stringify(gVX) + '\n');
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: 'g', anchor: { nodeId: A.nodeId, publicKey: A.pub } });
    try {
      assert.deepStrictEqual(node._roleGrants.loadReport().skipped, { 'unknown-grantor-key': 1 });
      const relayed = [];
      node._gossipToRoster = (frame) => relayed.push(frame.grant.sig);
      node._frameHandler.handle('relayer', 'relayer', { type: 'role-grant', grant: gAV });
      assert.strictEqual(node.resolveRole(X.nodeId), 'validator');
      assert.deepStrictEqual(relayed, [gAV.sig, gVX.sig]);
      assert.deepStrictEqual(lines(grantsFile(name)).map((l) => JSON.parse(l).sig), [gVX.sig, gAV.sig], 'the file already held it: only the root is appended');
    } finally { node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });
});
