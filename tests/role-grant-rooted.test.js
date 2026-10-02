'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * 0.13.17 security hotfix (F3). In 0.13.16 one self-signed role-grant from any connected peer was
 * verified against that peer's own first-use key, written to role-grants.jsonl and relayed to the
 * roster; and reading any non-empty role-grants.jsonl threw ("object is not iterable"), so every
 * node that had received it could never start again.
 *
 * Authority flows only along chains rooted at the pinned anchor, so a grant that is not rooted there
 * has no effect: it is not stored, not relayed, and costs nothing. A record on disk that cannot be
 * verified is skipped and counted, and a store that cannot be read leaves the node starting with no
 * grants.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir, loadOrCreateIdentity } = require('../lib/config');
const { signGrant } = require('../lib/core');
const { admitAs, deliver } = require('./_core-secure');

function kp(nodeId) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    nodeId,
    priv: privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(16).toString('base64url'),
    pub: publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('base64url'),
  };
}
// Since 0.14 every role-grant names the key it confers authority on (design D3): the fixtures carry
// granteeKey, so each record exercises the check the 0.13.17 test meant it to.
const grant = (type, grantee, role, grantor, at, extra = {}) =>
  signGrant({ type, grantee: grantee.nodeId, role, grantedBy: grantor.nodeId, grantedAt: at, ...(type === 'role-grant' ? { granteeKey: grantee.pub } : {}), ...extra }, grantor.priv);

const uniq = (base) => `${base}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
const grantsFile = (name) => path.join(nodeDir(name), 'role-grants', 'role-grants.jsonl');

function boot(name, founder, extra = {}) {
  return new SymNode({
    name, silent: true, discovery: new NullDiscovery(), room: 'g',
    ...(founder ? { anchor: { nodeId: founder.nodeId, publicKey: founder.pub } } : {}),
    ...extra,
  });
}
// A peer connects: its session proves its key (design D1/D3), the strongest binding a self-signed
// grant could ever be checked against. Frames then reach the node through the one guarded dispatch.
function handshake(node, peer) {
  return admitAs(node, { nodeId: peer.nodeId, name: peer.nodeId, publicKey: peer.pub });
}

describe('a role-grant that is not rooted at the anchor is not stored (F3)', () => {
  for (const anchored of [true, false]) {
    it(`a connected peer's self-signed grant is not persisted, not relayed, and the node restarts (${anchored ? 'anchored' : 'no anchor, as the daemon runs'})`, () => {
      const name = uniq('rg-self');
      const founder = kp('founder');
      const evil = kp('evil-peer');
      let node = boot(name, anchored ? founder : null);
      try {
        const relayed = [];
        node._gossipToRoster = (frame) => relayed.push(frame);
        const session = handshake(node, evil);
        const self = grant('role-grant', evil, 'anchor', evil, Date.now());
        deliver(node, session, { type: 'role-grant', grant: self });
        assert.strictEqual(node._roleGrants.has(self.sig), false, 'the unrooted grant is not held');
        assert.strictEqual(fs.existsSync(grantsFile(name)), false, 'and nothing was written');
        assert.deepStrictEqual(relayed, [], 'and nothing was relayed');
        assert.strictEqual(node.resolveRole(evil.nodeId), 'participant');
        node.stop();
        node = boot(name, anchored ? founder : null);
        assert.strictEqual(node.resolveRole(evil.nodeId), 'participant');
      } finally { node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
    });
  }

  it('an anchor-rooted grant relayed by a peer still persists, is relayed once, and resolves after a restart', () => {
    const name = uniq('rg-rooted');
    const founder = kp('founder'), relayer = kp('relayer'), V = kp('validator-v');
    let node = boot(name, founder);
    try {
      const relayed = [];
      node._gossipToRoster = (frame, except) => relayed.push({ frame, except });
      const session = handshake(node, relayer);
      const g = grant('role-grant', V, 'validator', founder, Date.now() - 1000, { granteeKey: V.pub });
      deliver(node, session, { type: 'role-grant', grant: g });
      assert.strictEqual(node._roleGrants.has(g.sig), true);
      assert.strictEqual(relayed.length, 1, 'relayed once');
      assert.strictEqual(relayed[0].except, relayer.nodeId, 'not back to the peer it came from');
      assert.strictEqual(node.resolveRole(V.nodeId), 'validator');
      node.stop();
      node = boot(name, founder);
      assert.strictEqual(node.resolveRole(V.nodeId), 'validator', 'the rooted grant survives the restart');
      assert.strictEqual(node._roster.get(V.nodeId), V.pub, 'and the key it vouched for is resolvable');
    } finally { node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  it('the anchor node\'s own grant persists and the node restarts (it could not in 0.13.16)', () => {
    const name = uniq('rg-own');
    const id = loadOrCreateIdentity(name);
    const self = { nodeId: id.nodeId, pub: id.publicKey };
    let node = boot(name, self);
    try {
      const peer = kp('node-peer-xyz');
      node._roster.bind(peer.nodeId, peer.pub, 'proven'); // a grant names a proven key (design D3)
      assert.ok(node.grantRole(peer.nodeId, 'validator'));
      node.stop();
      node = boot(name, self);
      assert.strictEqual(node.resolveRole(peer.nodeId), 'validator');
    } finally { node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  it('a node with no rooted authority makes no grant and sends nothing', () => {
    const name = uniq('rg-noauth');
    const founder = kp('founder');
    const node = boot(name, founder);
    try {
      const sent = [];
      node._gossipToRoster = (frame) => sent.push(frame);
      node._roster.bind('someone', kp('someone').pub, 'proven');
      assert.strictEqual(node.grantRole('someone', 'validator'), null);
      assert.deepStrictEqual(sent, []);
      assert.strictEqual(fs.existsSync(grantsFile(name)), false);
    } finally { node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });
});

describe('reading role-grants.jsonl never stops a node from starting (F3)', () => {
  it('junk, non-JSON, malformed, forged and unrooted records are skipped and counted; rooted ones load in any order', () => {
    const name = uniq('rg-junk');
    const founder = kp('founder'), evil = kp('evil-peer'), V = kp('v'), W = kp('w');
    let node = boot(name, founder);
    handshake(node, evil); // binds evil's key (proven): a self-signed grant still confers nothing
    node.stop();
    const now = Date.now();
    const forged = { ...grant('role-grant', evil, 'anchor', founder, now), sig: Buffer.alloc(64, 7).toString('base64url') };
    const lines = [
      'not json at all {',
      'null',
      '42',
      '[]',
      JSON.stringify({ type: 'role-grant' }),
      JSON.stringify({ type: 'role-grant', grantee: { x: 1 }, grantedBy: founder.nodeId, grantedAt: now, role: 'validator', sig: 'abc' }),
      JSON.stringify(grant('role-grant', evil, 'anchor', evil, now)),                          // what 0.13.16 stored from one frame
      JSON.stringify(forged),
      JSON.stringify(grant('role-grant', W, 'validator', V, now - 500)),                       // V→W, before V's own grant in the file
      JSON.stringify(grant('role-grant', V, 'validator', founder, now - 1000, { granteeKey: V.pub })),
    ];
    fs.mkdirSync(path.dirname(grantsFile(name)), { recursive: true });
    fs.writeFileSync(grantsFile(name), lines.join('\n') + '\n');
    const said = [];
    const log = console.log;
    console.log = (line) => said.push(String(line));
    try { node = boot(name, founder, { silent: false }); } finally { console.log = log; }
    try {
      const about = said.filter((l) => /Role grants/.test(l));
      assert.strictEqual(about.length, 1, 'said once');
      // 0.14 (design D3): a grant is checked against the keys the chain vouches for its grantor, never
      // the registry's, so the self-signed grant is skipped as from a grantor no chain reaches.
      assert.match(about[0], /loaded 2, skipped 8 that could not be verified \(not-json 1, malformed 5, unknown-grantor-key 1, bad-signature 1\)/);
      assert.strictEqual(node.resolveRole(V.nodeId), 'validator');
      assert.strictEqual(node.resolveRole(W.nodeId), 'validator', 'a two-hop chain loads whatever the line order');
      assert.strictEqual(node.resolveRole(evil.nodeId), 'participant');
      const rep = node._roleGrants.loadReport();
      assert.strictEqual(rep.loaded, 2);
      assert.strictEqual(rep.unreadable, null);
      assert.deepStrictEqual(rep.skipped, { 'not-json': 1, malformed: 5, 'unknown-grantor-key': 1, 'bad-signature': 1 });
    } finally { node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  it('a store that cannot be read leaves the node starting with no grants, and says why', () => {
    const name = uniq('rg-unreadable');
    const founder = kp('founder');
    fs.mkdirSync(grantsFile(name), { recursive: true }); // a directory where the file should be: EISDIR
    const node = boot(name, founder);
    try {
      assert.strictEqual(node._roleGrants.size(), 0);
      assert.match(String(node._roleGrants.loadReport().unreadable), /EISDIR/);
      assert.strictEqual(node._resolvedRole(), 'participant');
    } finally { node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  it('an empty grants file starts', () => {
    const name = uniq('rg-empty');
    fs.mkdirSync(path.dirname(grantsFile(name)), { recursive: true });
    fs.writeFileSync(grantsFile(name), '');
    const node = boot(name, kp('founder'));
    try { assert.strictEqual(node._roleGrants.size(), 0); }
    finally { node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });
});
