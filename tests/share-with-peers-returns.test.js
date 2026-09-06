'use strict';
require('./_isolate-home');
// shareWithPeers returned `timestamp: frame.timestamp` with no `frame` in scope — a ReferenceError
// on every call, after the frames had already gone out. Found by the wire-alignment review
// (mission-b28f10) reading the code; confirmed by running it. Pinned so it cannot come back.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const { createCMB } = require('../lib/core');

test('shareWithPeers returns the send it made instead of throwing', async () => {
  const name = `share-return-${Date.now()}`;
  const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
  await node.start();
  try {
    const sent = [];
    const transport = { send: (f) => sent.push(f), close: () => {} };
    node._peers.set('q'.repeat(32), { peerId: 'q'.repeat(32), name: 'lan-peer', transport, transports: new Map([['bonjour', transport]]), source: 'bonjour', lastSeen: Date.now() });
    const cmb = createCMB({ categories: { focus: 'shared on purpose' }, createdBy: name });
    const r = node.shareWithPeers('shared on purpose', { cmb });
    assert.equal(typeof r.timestamp, 'number');
    assert.equal(r.cmb, cmb);
    assert.equal(sent.filter((f) => f.type === 'cmb').length, 1);
  } finally { await node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
});
