'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * The version a node names is package.json's, in every place it is named: the §5.2 hello's
 * `implementation`, `node.version`, `status().version` and the module's `version`. None is a literal
 * that a release could leave behind.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const sym = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const { connectNodes } = require('./_core-secure');

const VERSION = require('../package.json').version;

describe('the version is package.json\'s', () => {
  it('the hello, node.version, status() and the module name it', async () => {
    const mk = (b) => new SymNode({ name: `${b}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`, silent: true, discovery: new NullDiscovery(), room: 'ver' });
    const a = mk('ver-a'); const b = mk('ver-b');
    try {
      await a.start(); await b.start();
      await connectNodes(b, a);
      assert.strictEqual(a.version, VERSION);
      assert.strictEqual(sym.version, VERSION);
      assert.strictEqual(a.status().version, VERSION);
      const seenByB = b._peers.get(a.nodeId).transport.peerImplementation;
      assert.deepStrictEqual(seenByB, { name: 'sym', version: VERSION }, 'what the peer\'s hello said');
      assert.deepStrictEqual(a._implementation, { name: 'sym', version: VERSION });
    } finally {
      for (const n of [a, b]) { try { await n.stop(); } catch { /* */ } try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ } }
    }
  });
});
