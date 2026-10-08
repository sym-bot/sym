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

// A peer as a confirmed session leaves it (Core Secure, 0.14): `sent` is what the node sends it,
// before sealing. A fetch is answered by each record in its own sealed record frame, then a sealed
// cmb-fetch-result carrying only the correlation id and the returned / missing key lists (design D1).
const { admitAs } = require('./_core-secure');
/** A cognition key no node holds. */
const NOWHERE = `cmb-${'ab'.repeat(32)}`;
function fakePeer(node, peerId) {
  return admitAs(node, { nodeId: peerId, name: peerId });
}
/** Deliver a fetch answer on `session` as the server sends it: the record (if any), then the result. */
function answer(node, session, reqId, key, cmb) {
  if (cmb) node._frameHandler.handle(session, { type: 'cmb', cmb });
  node._frameHandler.handle(session, { type: 'cmb-fetch-result', reqId, returned: cmb ? [key] : [], missing: cmb ? [] : [key] });
}

describe('MMP §7 cmb-fetch — content-addressed retrieval', () => {
  it('serves a held record as signed: the record in its own sealed frame, then the key lists', async () => {
    await withNode('cfetch-serve', async (node) => {
      const root = node.remember(cat7('mountain trail conditions report for the north ridge'));
      const peer = fakePeer(node, 'peerX');
      node._frameHandler.handle(peer, { type: 'cmb-fetch', key: root.key, reqId: 'r1' });
      const res = peer.sent.find((f) => f.type === 'cmb-fetch-result');
      assert.ok(res, 'responds');
      assert.deepStrictEqual(Object.keys(res).sort(), ['missing', 'reqId', 'returned', 'type'], 'the id and the key lists, never the record (it was plaintext; §18.2.1), and no timestamp (cmb-fetch-result.schema.json)');
      assert.deepStrictEqual([res.reqId, res.returned, res.missing], ['r1', [root.key], []]);
      assert.ok(peer.sent.findIndex((f) => f.type === 'cmb') < peer.sent.indexOf(res), 'the record goes first');
      const rec = peer.sent.find((f) => f.type === 'cmb');
      assert.strictEqual(rec.cmb.metadata.key, root.key);
      assert.ok(rec.cmb.categories.focus.text.length > 0, 'text served');
      assert.strictEqual(rec.cmb.categories.focus.vector, undefined, 'vectors stripped — re-verifiers re-encode');
      assert.deepStrictEqual(Object.keys(rec.cmb).sort(), ['categories', 'metadata'], 'exactly as signed');
    });
  });

  it('lists an unknown key as missing, and sends no record', async () => {
    await withNode('cfetch-miss', async (node) => {
      const peer = fakePeer(node, 'peerX');
      node._frameHandler.handle(peer, { type: 'cmb-fetch', key: NOWHERE, reqId: 'r2' });
      const res = peer.sent.find((f) => f.type === 'cmb-fetch-result');
      assert.deepStrictEqual([res.returned, res.missing], [[], [NOWHERE]]);
      assert.strictEqual(peer.sent.filter((f) => f.type === 'cmb').length, 0);
    });
  });

  it('fetchCMB resolves on a verified response and rejects a forged one', async () => {
    await withNode('cfetch-verify', async (nodeA) => {
      // nodeA holds the root; grab the exact record it would serve.
      const root = nodeA.remember(cat7('fresh snowfall reported on the upper mountain trail sections'));
      const toB = fakePeer(nodeA, 'peerB');
      nodeA._frameHandler.handle(toB, { type: 'cmb-fetch', key: root.key, reqId: 'wire' });
      const served = toB.sent.find((f) => f.type === 'cmb').cmb;

      await withNode('cfetch-req', async (nodeB) => {
        // nodeB has proven nodeA's key (D4: a fetched record is attributed only after §8.8.5).
        nodeB._roster.bind(nodeA.nodeId, nodeA._identity.publicKey, 'proven');
        const a = fakePeer(nodeB, 'peerA');
        const evil = fakePeer(nodeB, 'peerEvil');
        const p = nodeB.fetchCMB(root.key, { timeoutMs: 2000 });
        const reqId = [...nodeB._cmbFetchPending.keys()][0];
        assert.ok(a.sent.some((f) => f.type === 'cmb-fetch' && f.reqId === reqId), 'asked over the session (sealed)');

        // Forged response first: same key, tampered text → recomputed address mismatches → discarded.
        const forged = JSON.parse(JSON.stringify(served));
        forged.categories.focus.text = 'entirely different content under the same key';
        answer(nodeB, evil, reqId, root.key, forged);

        // Genuine response second: verifies and resolves.
        answer(nodeB, a, reqId, root.key, JSON.parse(JSON.stringify(served)));

        const hit = await p;
        assert.ok(hit, 'verified response resolves');
        assert.strictEqual(hit.from, 'peerA', 'the forged response did not win');
        assert.strictEqual(hit.verified, true);
        assert.strictEqual(hit.authorNodeId, nodeA.nodeId);
        assert.strictEqual(hit.cmb.metadata.key, root.key);
      });
    });
  });

  it('a record that is not a signed v2.0 record answers nothing: Core Secure serves only those (MMP 2.0 update 1, D4)', async () => {
    // Until the update this took a pre-boundary record (no metadata, a flat key) on its address
    // alone. Over Core Secure a server sends only signed v2.0 records, and a fetched record passes
    // the whole of §8.8.5 before it is attributed; one that has no v2.0 metadata cannot.
    const { cmbKeyV1 } = require('../lib/core');
    await withNode('cfetch-legacy', async (nodeB) => {
      const a = fakePeer(nodeB, 'peerA');
      const categories = cat7('a pre-boundary block minted before the merkle cutover');
      const legacy = { categories, key: cmbKeyV1(categories) };
      const p = nodeB.fetchCMB(NOWHERE, { timeoutMs: 2000 });
      const reqId = [...nodeB._cmbFetchPending.keys()][0];
      answer(nodeB, a, reqId, NOWHERE, legacy);
      assert.strictEqual(await p, null);
    });
  });

  it('a response that does not match its key is told apart from one that is malformed, in telemetry', async () => {
    // The classes must not merge: a record whose content does not match its key is an attack; a
    // record that is not a record is a compatibility problem. Both are discarded.
    await withNode('cfetch-classes', async (nodeA) => {
      const root = nodeA.remember(cat7('content served twice, once altered and once broken'));
      const toB = fakePeer(nodeA, 'peerB');
      nodeA._frameHandler.handle(toB, { type: 'cmb-fetch', key: root.key, reqId: 'wire' });
      const served = toB.sent.find((f) => f.type === 'cmb').cmb;
      await withNode('cfetch-classes-b', async (nodeB) => {
        const a = fakePeer(nodeB, 'peerA');
        const c = fakePeer(nodeB, 'peerC');
        const metrics = [];
        nodeB.on('metric', (m) => { if (m.type === 'cmb-fetch-forged') metrics.push(m); });
        const p = nodeB.fetchCMB(root.key, { timeoutMs: 600 });
        const reqId = [...nodeB._cmbFetchPending.keys()][0];
        const altered = JSON.parse(JSON.stringify(served)); altered.categories.focus.text = 'other words under the same key';
        const broken = JSON.parse(JSON.stringify(served)); delete broken.categories;
        answer(nodeB, a, reqId, root.key, altered);
        answer(nodeB, c, reqId, root.key, broken);
        await p;
        assert.deepStrictEqual(metrics.map((m) => m.verdict), ['mismatch', 'malformed']);
      });
    });
  });

  it('a request names one key: a keys array is refused, not served', async () => {
    await withNode('cfetch-multi', async (node) => {
      const r1 = node.remember(cat7('the first record of a multi-key fetch about avalanche risk'));
      const peer = fakePeer(node, 'peerX');
      node._receiveSessionFrame(peer, { type: 'cmb-fetch', key: r1.key, keys: [r1.key], reqId: 'm1' });
      assert.deepStrictEqual(peer.sent, []);
      assert.strictEqual(node._metrics.framesRefusedByType['cmb-fetch'], 1);
    });
  });

  it('a result that lists the key as returned closes the request for that peer when no verifying record came first', async () => {
    await withNode('cfetch-found-nothing', async (node) => {
      const a = fakePeer(node, 'peerA');
      const p = node.fetchCMB(NOWHERE, { timeoutMs: 3000 });
      const reqId = [...node._cmbFetchPending.keys()][0];
      const t0 = Date.now();
      node._frameHandler.handle(a, { type: 'cmb-fetch-result', reqId, returned: [NOWHERE], missing: [] });
      assert.strictEqual(await p, null);
      assert.ok(Date.now() - t0 < 1000, 'closed by the result, not by the timeout');
      assert.strictEqual(a._fetchExpect.size, 0, 'the expectation is let go');
    });
  });

  it('fetchCMB returns the local copy without asking the mesh', async () => {
    await withNode('cfetch-local', async (node) => {
      const root = node.remember(cat7('trailhead parking permits and the shuttle bus timetable'));
      const peer = fakePeer(node, 'peerX');
      const hit = await node.fetchCMB(root.key);
      assert.ok(hit && hit.from === node.name);
      assert.strictEqual(peer.sent.length, 0, 'no wire traffic for a locally held key');
    });
  });

  it('fetchCMB times out to null when every peer misses', async () => {
    await withNode('cfetch-timeout', async (node) => {
      const peer = fakePeer(node, 'peerX');
      const p = node.fetchCMB(NOWHERE, { timeoutMs: 300 });
      const reqId = [...node._cmbFetchPending.keys()][0];
      answer(node, peer, reqId, NOWHERE, null);
      assert.strictEqual(await p, null);
    });
  });
});
