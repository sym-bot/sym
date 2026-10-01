'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * §18.3.1: every Core Secure CMB MUST be signed. A node that cannot sign used to log the failure and
 * then store and broadcast the record unsigned; now remember() throws ESIGN before anything is
 * stored or dispatched.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');

function withNode(fn) {
  const name = `signfail-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
  try { return fn(node); } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
}

describe('a record that cannot be signed', () => {
  it('throws ESIGN, and nothing is stored or sent', () => {
    withNode((node) => {
      const sent = [];
      node._peers.set('peer-1', { peerId: 'peer-1', name: 'peer', transport: { send: (f) => { sent.push(f); return true; } } });
      const metrics = [];
      node.on('metric', (m) => metrics.push(m));
      const before = node._store.count ? node._store.count() : node.recall('').length;
      node._identity.privateKey = 'not-a-key';
      assert.throws(() => node.remember({ focus: 'unsignable' }), (e) => e.code === 'ESIGN');
      const after = node._store.count ? node._store.count() : node.recall('').length;
      assert.strictEqual(after, before, 'nothing stored');
      assert.strictEqual(sent.filter((f) => f.type === 'cmb').length, 0, 'nothing sent');
      assert.ok(metrics.some((m) => m.type === 'cmb-signing-failed'));
    });
  });

  it('a node with a working key still signs and sends', () => {
    withNode((node) => {
      const sent = [];
      node._peers.set('peer-1', { peerId: 'peer-1', name: 'peer', transport: { send: (f) => { sent.push(f); return true; } } });
      const entry = node.remember({ focus: 'signable' });
      assert.ok(entry?.cmb?.metadata?.sig, 'signed');
      assert.strictEqual(sent.filter((f) => f.type === 'cmb').length, 1);
    });
  });
});
