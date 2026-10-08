'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * §15.8 on the remix path (founder ruling, 0.14.0): remix() is asynchronous and evaluates what it
 * produces against its nearest verified lineage root before it is minted. A faithful remix keeps its
 * lineage, a remix drifted past the reject floor is minted as a fresh root, and one with no verified
 * root in reach keeps its lineage, unverified; each verdict is signed as an mmp-tether-v1 attestation.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const { createCMB, verifyTetherAttestation } = require('../lib/core');
const { awaitSemantic } = require('./_semantic');

const cat7 = (t) => ({ focus: t, issue: t, intent: t, motivation: t, commitment: t, perspective: 'peerA', mood: { text: 'neutral' } });
const TOPIC_A = 'quarterly financial audit of the accounting ledger and tax filings';
const TOPIC_A_REMIX = 'the second quarter financial audit of the accounting ledger and tax filings';
const TOPIC_B = 'fresh snowfall reported on the upper mountain trail sections';

async function withNode(fn) {
  const n = new SymNode({ name: `remix-tether-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`, silent: true, discovery: new NullDiscovery() });
  await n.start();
  try { return await fn(n); } finally { await n.stop(); fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); }
}
/** A verified peer record about `text`, held as an admitted peer record. */
function peerRoot(node, text) {
  const cmb = createCMB({ categories: cat7(text), createdBy: 'peerR' });
  node._store.receiveFromPeer('peerR', { key: cmb.metadata.key, content: text, source: 'peerR', cmb, _cmbVerified: true });
  return cmb;
}

describe('remix() evaluates the §15.8 tether on what it produces', () => {
  it('drifted past the floor: minted as a fresh root, the departed source kept, a severed attestation signed', async () => {
    await awaitSemantic();
    await withNode(async (node) => {
      const root = peerRoot(node, TOPIC_A);
      node.remember(cat7('new domain data of this node'));
      const p = node.remix(cat7(TOPIC_B), { parents: [root] });
      assert.ok(p instanceof Promise, 'remix() is asynchronous');
      const e = await p;
      assert.ok(e && e.key && !e.refused);
      const stored = node._store.get(e.key);
      assert.strictEqual(stored.cmb.metadata.lineage, null, 'no parent from the severed chain');
      assert.strictEqual(stored.provenance.tether.severed, true);
      assert.strictEqual(stored.provenance.tether.departedFrom, root.metadata.key);
      assert.strictEqual(stored.tether.verdict, 'severed');
      assert.strictEqual(stored.tether.of, e.key);
      assert.strictEqual(stored.tether.anchor, root.metadata.key);
      assert.strictEqual(verifyTetherAttestation(stored.tether, node._identity.publicKey).valid, true);
      assert.strictEqual(node.canRemix(), false, 'the flag is consumed');
    });
  });

  it('faithful: minted with its lineage, and a tethered attestation', async () => {
    await awaitSemantic();
    await withNode(async (node) => {
      const root = peerRoot(node, TOPIC_A);
      node.remember(cat7('new domain data of this node'));
      const e = await node.remix(cat7(TOPIC_A_REMIX), { parents: [root] });
      const stored = node._store.get(e.key);
      assert.deepStrictEqual(stored.cmb.metadata.lineage.parents, [root.metadata.key]);
      assert.strictEqual(stored.provenance.tether.severed, false);
      assert.strictEqual(stored.tether.verdict, 'tethered');
      assert.strictEqual(verifyTetherAttestation(stored.tether, node._identity.publicKey).valid, true);
    });
  });

  it('no verified root in reach: minted with its lineage, the tether unverified (a trust state), nothing signed', async () => {
    await withNode(async (node) => {
      node.remember(cat7('new domain data of this node'));
      const missing = `cmb-${'e'.repeat(64)}`;
      const e = await node.remix(cat7(TOPIC_B), { parents: [{ key: missing }] });
      const stored = node._store.get(e.key);
      assert.deepStrictEqual(stored.cmb.metadata.lineage.parents, [missing]);
      assert.strictEqual(stored.tether, undefined);
      assert.strictEqual(stored.provenance?.tether, undefined);
    });
  });

  it('a remix that mints nothing gives the flag back; a second remix started meanwhile is refused', async () => {
    await withNode(async (node) => {
      const root = peerRoot(node, TOPIC_A);
      node.remember(cat7('new domain data of this node'));
      const [a, b] = await Promise.all([node.remix(cat7(TOPIC_A_REMIX), { parents: [root] }), node.remix(cat7(TOPIC_A), { parents: [root] })]);
      assert.ok(a.key && !a.refused);
      assert.deepStrictEqual(b, { refused: 'remix-without-new-domain-data' }, 'the flag was consumed when the first began');
      node.remember(cat7('more domain data'));
      const dup = await node.remix(cat7(TOPIC_A), { parents: [root] }); // the parent's own words: nothing new is minted
      assert.ok(dup.duplicate || dup.collapsed);
      assert.strictEqual(node.canRemix(), true, 'nothing minted, so the flag is given back');
    });
  });
});
