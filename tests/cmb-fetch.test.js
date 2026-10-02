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
// cmb-fetch-result carrying only the correlation id and the found / not-found key lists (design D1).
const { admitAs } = require('./_core-secure');
function fakePeer(node, peerId) {
  return admitAs(node, { nodeId: peerId, name: peerId });
}
/** Deliver a fetch answer on `session` as the server sends it: the record (if any), then the result. */
function answer(node, session, reqId, key, cmb) {
  if (cmb) node._frameHandler.handle(session, { type: 'cmb', cmb });
  node._frameHandler.handle(session, { type: 'cmb-fetch-result', reqId, found: cmb ? [key] : [], notFound: cmb ? [] : [key] });
}

describe('MMP §7 cmb-fetch — content-addressed retrieval', () => {
  it('serves a held record as signed: the record in its own sealed frame, then the key lists', async () => {
    await withNode('cfetch-serve', async (node) => {
      const root = node.remember(cat7('mountain trail conditions report for the north ridge'));
      const peer = fakePeer(node, 'peerX');
      node._frameHandler.handle(peer, { type: 'cmb-fetch', key: root.key, reqId: 'r1' });
      const res = peer.sent.find((f) => f.type === 'cmb-fetch-result');
      assert.ok(res, 'responds');
      assert.deepStrictEqual(Object.keys(res).sort(), ['found', 'notFound', 'reqId', 'timestamp', 'type'], 'the id and the key lists, never the record (it was plaintext; §18.2.1)');
      assert.deepStrictEqual([res.reqId, res.found, res.notFound], ['r1', [root.key], []]);
      assert.ok(peer.sent.findIndex((f) => f.type === 'cmb') < peer.sent.indexOf(res), 'the record goes first');
      const rec = peer.sent.find((f) => f.type === 'cmb');
      assert.strictEqual(rec.cmb.metadata.key, root.key);
      assert.ok(rec.cmb.categories.focus.text.length > 0, 'text served');
      assert.strictEqual(rec.cmb.categories.focus.vector, undefined, 'vectors stripped — re-verifiers re-encode');
      assert.deepStrictEqual(Object.keys(rec.cmb).sort(), ['categories', 'metadata'], 'exactly as signed');
    });
  });

  it('lists an unknown key as notFound, and sends no record', async () => {
    await withNode('cfetch-miss', async (node) => {
      const peer = fakePeer(node, 'peerX');
      node._frameHandler.handle(peer, { type: 'cmb-fetch', key: 'cmb1-doesnotexist', reqId: 'r2' });
      const res = peer.sent.find((f) => f.type === 'cmb-fetch-result');
      assert.deepStrictEqual([res.found, res.notFound], [[], ['cmb1-doesnotexist']]);
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
        assert.strictEqual(hit.cmb.metadata.key, root.key);
      });
    });
  });

  it('a PRE-BOUNDARY record is accepted, not discarded as forged (core 0.8.1 regression guard)', async () => {
    // THE REGRESSION THIS EXISTS TO CATCH, measured before it shipped:
    //
    // This call site used to dispatch on `cmb.metadata` and call core's `recomputeKey` for
    // records without it — a workaround for recomputeKey being broken (it read `cmb.key`, absent
    // on v2 records, and derived roots with the FLAT scheme while createCMB minted MERKLE).
    // core 0.8.1 fixed recomputeKey, and the workaround became a regression the instant it did:
    // a pre-boundary record with a flat root key recomputed to the MERKLE address, mismatched,
    // and was DISCARDED AS FORGED. The whole legacy DAG would have been dropped on fetch.
    //
    // sym's suite was 309/309 green through all of that, because no test served a record of this
    // shape. That is the point of this one: the fix is not "bump the dependency", it is "check
    // what the dependency now returns for the records you actually hold".
    const { cmbKeyV1 } = require('../lib/core');
    await withNode('cfetch-legacy', async (nodeB) => {
      const a = fakePeer(nodeB, 'peerA');
      const categories = cat7('a pre-boundary block minted before the merkle cutover');
      // Pre-boundary wire shape: NO `metadata`, address at the top level, FLAT root derivation.
      const legacy = { categories, key: cmbKeyV1(categories) };

      const p = nodeB.fetchCMB(legacy.key, { timeoutMs: 2000 });
      const reqId = [...nodeB._cmbFetchPending.keys()][0];
      // (Over Core Secure a server sends only a v2.0 record; the requester's address check, the one
      // under test, still takes a pre-boundary one.)
      answer(nodeB, a, reqId, legacy.key, legacy);

      const hit = await p;
      assert.ok(hit, 'a legitimate pre-boundary record must VERIFY, not be discarded as forged');
      assert.strictEqual(hit.cmb.key, legacy.key);
    });
  });

  it('an UNVERIFIABLE response is distinguished from a FORGED one in telemetry', async () => {
    // The three classes must not merge here either. A record we cannot read is a compatibility
    // problem; a record whose content does not match its key is an attack. Both are discarded —
    // and both used to arrive as a bare `null` that this call site reported as a mismatch,
    // accusing a record it had merely failed to read.
    await withNode('cfetch-classes', async (nodeB) => {
      const a = fakePeer(nodeB, 'peerA');
      const metrics = [];
      nodeB.on('metric', (m) => { if (m.type === 'cmb-fetch-forged') metrics.push(m); });

      const categories = cat7('content that will be served without any container at all');
      const { cmbKeyV1 } = require('../lib/core');
      const key = cmbKeyV1(categories);

      const p = nodeB.fetchCMB(key, { timeoutMs: 600 });
      const reqId = [...nodeB._cmbFetchPending.keys()][0];
      // Same key, NO container — unreadable rather than altered.
      answer(nodeB, a, reqId, key, { key });
      await p;

      assert.strictEqual(metrics.length, 1);
      assert.strictEqual(metrics[0].verdict, 'cannot-verify',
        'an unreadable record must not be reported as a content mismatch');
    });
  });

  it('serves several keys in one request: each found record in its own frame, then one result', async () => {
    await withNode('cfetch-multi', async (node) => {
      const r1 = node.remember(cat7('the first record of a multi-key fetch about avalanche risk'));
      const r2 = node.remember(cat7('the second record of a multi-key fetch about lift closures'));
      const peer = fakePeer(node, 'peerX');
      node._frameHandler.handle(peer, { type: 'cmb-fetch', keys: [r1.key, 'cmb1-missing', r2.key, r1.key], reqId: 'm1' });
      assert.deepStrictEqual(peer.sent.map((f) => f.type), ['cmb', 'cmb', 'cmb-fetch-result']);
      const res = peer.sent[2];
      assert.deepStrictEqual([res.found, res.notFound], [[r1.key, r2.key], ['cmb1-missing']], 'each key once');
    });
  });

  it('a result that lists the key as found closes the request for that peer when no verifying record came first', async () => {
    await withNode('cfetch-found-nothing', async (node) => {
      const a = fakePeer(node, 'peerA');
      const p = node.fetchCMB('cmb1-claimed', { timeoutMs: 3000 });
      const reqId = [...node._cmbFetchPending.keys()][0];
      const t0 = Date.now();
      node._frameHandler.handle(a, { type: 'cmb-fetch-result', reqId, found: ['cmb1-claimed'], notFound: [] });
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
      const p = node.fetchCMB('cmb1-nowhere', { timeoutMs: 300 });
      const reqId = [...node._cmbFetchPending.keys()][0];
      answer(node, peer, reqId, 'cmb1-nowhere', null);
      assert.strictEqual(await p, null);
    });
  });
});
