'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * Node self-reported memory stats. A node is sovereign over its store, so it EMITS its
 * own {emitted, admitted, memory} tally to the roster (a `node-stats` frame, not a CMB),
 * letting any observer show real counts for it even across machines.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');

function makeNode(base) {
  const name = `${base}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: 'g' });
  return { node, name };
}

describe('node-stats — self-reported store tally', () => {
  it('_nodeStats maps store.stats() local→emitted, peer→admitted, total→memory', () => {
    const { node, name } = makeNode('ns-map');
    try {
      node._store.stats = () => ({ total: 5, local: 3, peer: 2, hot: 5, cold: 0 });
      const s = node._nodeStats();
      assert.strictEqual(s.name, node.name);
      assert.strictEqual(s.nodeId, node.nodeId);
      assert.strictEqual(s.emitted, 3);
      assert.strictEqual(s.admitted, 2);
      assert.strictEqual(s.memory, 5);
      assert.ok(typeof s.at === 'number');
    } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  it('_emitNodeStats gossips a node-stats frame to the roster', () => {
    const { node, name } = makeNode('ns-emit');
    try {
      const frames = [];
      node._gossipToRoster = (frame) => frames.push(frame);
      node._store.stats = () => ({ total: 7, local: 4, peer: 3, hot: 7, cold: 0 });
      node._emitNodeStats();
      assert.strictEqual(frames.length, 1);
      assert.strictEqual(frames[0].type, 'sym-attest-node-stats');
      assert.deepStrictEqual(
        { e: frames[0].stats.emitted, a: frames[0].stats.admitted, m: frames[0].stats.memory },
        { e: 4, a: 3, m: 7 },
      );
      assert.deepStrictEqual(Object.keys(frames[0].stats).sort(), ['admitted', 'at', 'emitted', 'memory'], 'no self-asserted name or nodeId (sym-attest-v1 §5.4)');
    } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  it('a sym-attest-node-stats frame is attributed to the session\'s proven peer; a malformed one is refused', () => {
    const { node, name } = makeNode('ns-ingest');
    const { admitAs, identity, deliver } = require('./_core-secure');
    try {
      const seen = [];
      node.on('node-stats', s => seen.push(s));
      const peer = admitAs(node, identity('research'));
      // A self-asserted name and nodeId in the frame are not read: the session says who it is.
      deliver(node, peer, { type: 'sym-attest-node-stats', stats: { name: 'liar', nodeId: 'someone-else', emitted: 7, admitted: 65, memory: 158, at: 1 } });
      deliver(node, peer, { type: 'sym-attest-node-stats', stats: { emitted: -1, admitted: 1, memory: 2, at: 1 } }); // malformed
      deliver(node, peer, { type: 'sym-attest-node-stats', stats: null });
      assert.strictEqual(seen.length, 1, 'only the well-formed stats surfaced');
      assert.strictEqual(seen[0].nodeId, peer.nodeId);
      assert.strictEqual(seen[0].name, 'research');
      assert.strictEqual(seen[0].admitted, 65);
    } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });
});
