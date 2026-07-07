'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * MMP §7 cmb-fetch — content-addressed retrieval, the §15.8 re-verification
 * path. Serving is discretionary and self-verifying: the requester accepts a
 * response only when the recomputed content address equals the requested key,
 * so a forged or tampered response is discarded regardless of who served it.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');

async function withNode(baseName, fn) {
  const name = `${baseName}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
  await node.start();
  try {
    return await fn(node);
  } finally {
    await node.stop();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  }
}

function cat7(t) {
  return {
    focus: t, issue: t, intent: t, motivation: t, commitment: t,
    perspective: 'peerA', mood: { text: 'neutral', valence: 0, arousal: 0 },
  };
}

function fakePeer(node, peerId) {
  const sent = [];
  node._peers.set(peerId, { transport: { send: (f) => sent.push(f), close: () => {} } });
  return sent;
}

describe('MMP §7 cmb-fetch — content-addressed retrieval', () => {
  it('serves a held root text-only, keyed exactly', async () => {
    await withNode('cfetch-serve', async (node) => {
      const root = node.remember(cat7('mountain trail conditions report for the north ridge'));
      const sent = fakePeer(node, 'peerX');
      node._frameHandler.handle('peerX', 'peerX', { type: 'cmb-fetch', key: root.key, reqId: 'r1' });
      const res = sent.find((f) => f.type === 'cmb-fetch-result');
      assert.ok(res, 'responds');
      assert.strictEqual(res.found, true);
      assert.strictEqual(res.cmb.key, root.key);
      assert.ok(res.cmb.fields.focus.text.length > 0, 'text served');
      assert.strictEqual(res.cmb.fields.focus.vector, undefined, 'vectors stripped — re-verifiers re-encode');
    });
  });

  it('answers found:false for an unknown key', async () => {
    await withNode('cfetch-miss', async (node) => {
      const sent = fakePeer(node, 'peerX');
      node._frameHandler.handle('peerX', 'peerX', { type: 'cmb-fetch', key: 'cmb1-doesnotexist', reqId: 'r2' });
      const res = sent.find((f) => f.type === 'cmb-fetch-result');
      assert.strictEqual(res.found, false);
      assert.strictEqual(res.cmb, null);
    });
  });

  it('fetchCMB resolves on a verified response and rejects a forged one', async () => {
    await withNode('cfetch-verify', async (nodeA) => {
      // nodeA holds the root; grab the exact wire form it would serve.
      const root = nodeA.remember(cat7('fresh snowfall reported on the upper mountain trail sections'));
      const sentByA = fakePeer(nodeA, 'peerB');
      nodeA._frameHandler.handle('peerB', 'peerB', { type: 'cmb-fetch', key: root.key, reqId: 'wire' });
      const served = sentByA.find((f) => f.type === 'cmb-fetch-result').cmb;

      await withNode('cfetch-req', async (nodeB) => {
        fakePeer(nodeB, 'peerA'); // captures the outgoing cmb-fetch
        const p = nodeB.fetchCMB(root.key, { timeoutMs: 2000 });
        const reqId = [...nodeB._cmbFetchPending.keys()][0];

        // Forged response first: same key, tampered text → recomputed address
        // mismatches → discarded (counted as a miss, does not resolve).
        const forged = JSON.parse(JSON.stringify(served));
        forged.fields.focus.text = 'entirely different content under the same key';
        nodeB._frameHandler.handle('peerEvil', 'peerEvil',
          { type: 'cmb-fetch-result', reqId, key: root.key, found: true, cmb: forged });

        // Genuine response second: verifies and resolves.
        nodeB._frameHandler.handle('peerA', 'peerA',
          { type: 'cmb-fetch-result', reqId, key: root.key, found: true, cmb: served });

        const hit = await p;
        assert.ok(hit, 'verified response resolves');
        assert.strictEqual(hit.from, 'peerA', 'the forged response did not win');
        assert.strictEqual(hit.cmb.key, root.key);
      });
    });
  });

  it('fetchCMB returns the local copy without asking the mesh', async () => {
    await withNode('cfetch-local', async (node) => {
      const root = node.remember(cat7('trailhead parking permits and the shuttle bus timetable'));
      const sent = fakePeer(node, 'peerX');
      const hit = await node.fetchCMB(root.key);
      assert.ok(hit && hit.from === node.name);
      assert.strictEqual(sent.length, 0, 'no wire traffic for a locally held key');
    });
  });

  it('fetchCMB times out to null when every peer misses', async () => {
    await withNode('cfetch-timeout', async (node) => {
      fakePeer(node, 'peerX');
      const p = node.fetchCMB('cmb1-nowhere', { timeoutMs: 300 });
      const reqId = [...node._cmbFetchPending.keys()][0];
      node._frameHandler.handle('peerX', 'peerX',
        { type: 'cmb-fetch-result', reqId, key: 'cmb1-nowhere', found: false, cmb: null });
      assert.strictEqual(await p, null);
    });
  });
});
