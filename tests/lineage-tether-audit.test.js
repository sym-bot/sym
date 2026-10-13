'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * MMP §15.8 retroactive lineage-tether audit — chains of records this node minted itself get the
 * same treatment the invariant gives a remix: re-evaluate against the resolvable root in the current
 * kernel, annotate + attest, and (opt-in) sever what fails the floor.
 *
 * A peer's record this node holds is a collapsed integration, kept exactly as its author signed it:
 * the §15.8 tether does not apply to it (§15.5, MMP 2.0 update 1, #17), and the audit leaves it alone.
 * Until the update the audit judged peers' records too; these fixtures were peer records then.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const { createCMB, verifyTetherAttestation } = require('../lib/core');

const { awaitSemantic } = require('./_semantic');

function cat7(t) {
  return {
    focus: t, issue: t, intent: t, motivation: t, commitment: t,
    perspective: 'peerA', mood: { text: 'neutral', valence: 0, arousal: 0 },
  };
}

/** A record this node mints citing `rootKey`, with `topicText` content (before the tether ran on it).
 *  NOTE: keys are content-only, so fixtures use distinct texts — identical texts collide and dedup. */
function storeOwnRemix(node, rootKey, topicText) {
  const entry = node.remember(cat7(topicText), { parents: [{ key: rootKey }] });
  return { key: entry.key, entry };
}

const TOPIC_A = 'quarterly financial audit of the accounting ledger and tax filings';
const TOPIC_B_ROOT = 'overall report on snowy mountain hiking trail conditions this weekend';
const TOPIC_B = 'fresh snowfall reported on the upper mountain trail sections';
const TOPIC_B2 = 'deep snow drifts covering the mountain hiking path near the summit ridge';

describe('MMP §15.8 retroactive tether audit', () => {
  it('a peer\'s record is a collapsed integration: the audit leaves it alone (MMP 2.0 update 1)', async () => {
    const name = `audit-peer-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    await node.start();
    try {
      await awaitSemantic();
      const rootA = node.remember(cat7(TOPIC_A));
      const cmb = createCMB({ categories: cat7(TOPIC_B2), createdBy: 'peer', lineage: { parents: [rootA.key], method: 'SVAF-v2' } });
      node._store.receiveFromPeer('peer', { key: cmb.metadata.key, content: TOPIC_B2, source: 'peer', cmb, _cmbVerified: true });
      const r = await node.auditLineageTethers({ sever: true });
      assert.strictEqual(r.audited, 0);
      const e = node._store.get(cmb.metadata.key);
      assert.strictEqual(e.tether, undefined);
      assert.deepStrictEqual(node._store.parents(cmb.metadata.key), [rootA.key], 'its lineage is its author\'s');
    } finally {
      await node.stop();
      fs.rmSync(nodeDir(name), { recursive: true, force: true });
    }
  });

  it('annotate-only pass: failed-floor chains are attested but keep lineage; sever pass strips them', async () => {
    const name = `audit-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    await node.start();
    try {
      await awaitSemantic();
      const rootA = node.remember(cat7(TOPIC_A));
      const rootB = node.remember(cat7(TOPIC_B_ROOT));
      const laundered = storeOwnRemix(node, rootA.key, TOPIC_B2); // topic-B content citing topic-A root
      const faithful = storeOwnRemix(node, rootB.key, TOPIC_B);   // topic-B content citing topic-B root

      // Pass 1: annotate + attest only (default).
      const r1 = await node.auditLineageTethers();
      assert.strictEqual(r1.audited, 2);
      assert.strictEqual(r1.tethered, 1);
      assert.strictEqual(r1.failedFloor, 1);
      assert.strictEqual(r1.severed, 0, 'severance is opt-in');

      const l1 = node._store.get(laundered.key);
      assert.ok(l1.cmb.metadata.lineage && (l1.cmb.metadata.lineage.parents || []).length === 1, 'lineage kept in annotate-only mode');
      assert.strictEqual(l1.provenance.tether.audited, true);
      assert.ok(l1.provenance.tether.drift > 0.5);
      const att = l1.tether;
      assert.strictEqual(att.verdict, 'severed', 'attestation records the evaluation outcome');
      assert.strictEqual(verifyTetherAttestation(att, node._identity.publicKey).valid, true);

      // Pass 2: sever.
      const r2 = await node.auditLineageTethers({ sever: true });
      assert.strictEqual(r2.severed, 1);
      const l2 = node._store.get(laundered.key);
      // Severed on the entry and in the index; the stored record is never edited.
      assert.strictEqual(l2.lineage.severed, true, 'laundered chain severed');
      assert.deepStrictEqual(node._store.parents(laundered.key), [], 'the store walks no parents from it');
      assert.deepStrictEqual(l2.cmb.metadata.lineage.parents, [rootA.key], 'the record\'s own lineage is untouched');
      assert.strictEqual(l2.provenance.tether.departedFrom, rootA.key);
      assert.ok(![...node._store._index.byAncestor.get(rootA.key) ?? []].includes(laundered.key),
        'ancestor index no longer lists the severed remix');

      const f2 = node._store.get(faithful.key);
      assert.deepStrictEqual(f2.cmb.metadata.lineage.parents, [rootB.key], 'faithful chain untouched');
      assert.strictEqual(f2.tether.verdict, 'tethered');
    } finally {
      await node.stop();
      fs.rmSync(nodeDir(name), { recursive: true, force: true });
    }
  });

  it('fetch: a parent held locally but unverified does not come back as the anchor', async () => {
    // fetchCMB answers from the local store before asking any peer, so the fetch fallback handed
    // the audit the very record the verified walk had just refused, and the audit attested a tether
    // to it. §15.8 anchors on records reached by VERIFYING parents; a local copy is not a second
    // opinion about its own author.
    const name = `audit-unv-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    await node.start();
    try {
      await awaitSemantic();
      const parent = createCMB({ categories: cat7(TOPIC_B_ROOT), createdBy: 'unverifiable-peer' });
      // A peer admission with no verified signature verdict, stored the way receiveFromPeer stores one.
      node._store.receiveFromPeer('unverifiable-peer', {
        key: parent.metadata.key, content: TOPIC_B_ROOT, source: 'unverifiable-peer', cmb: parent, storedAt: Date.now(),
      });
      const remix = storeOwnRemix(node, parent.metadata.key, TOPIC_B);
      const r = await node.auditLineageTethers({ fetch: true, timeoutMs: 50 });
      assert.strictEqual(r.audited, 1);
      assert.strictEqual(r.fetched, 0, 'the local unverified copy is not a fetch');
      assert.strictEqual(r.unchecked, 1, 'the tether is unverified');
      const e = node._store.get(remix.key);
      assert.strictEqual(e.tether, undefined, 'no tether attestation names the unverified record');
      assert.strictEqual(e.provenance?.tether, undefined);
    } finally {
      await node.stop();
      fs.rmSync(nodeDir(name), { recursive: true, force: true });
    }
  });

  it('unresolvable roots are unchecked, never severed', async () => {
    const name = `audit-un-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    await node.start();
    try {
      await awaitSemantic();
      const orphan = storeOwnRemix(node, `cmb-${'f'.repeat(64)}`, TOPIC_B);
      const r = await node.auditLineageTethers({ sever: true });
      assert.strictEqual(r.unchecked, 1);
      assert.strictEqual(r.severed, 0);
      const e = node._store.get(orphan.key);
      assert.ok(e.cmb.metadata.lineage && (e.cmb.metadata.lineage.parents || []).length === 1, 'orphan chain untouched');
    } finally {
      await node.stop();
      fs.rmSync(nodeDir(name), { recursive: true, force: true });
    }
  });

  // The audit's knowledge of a remix's ancestry is the store's own closure, held on the entry and in
  // its index. It used to read the closure off the RECORD, which held it only because the store
  // stapled a copy there. On a two-section record the read found metadata.lineage instead, which
  // carries direct parents only, or, from a non-conformant sender, an `ancestors` list the sender
  // chose (§7.5: never carried, never trusted).
  it('sever: the remix is unhooked from every ancestor the store indexed it under', async () => {
    const name = `audit-unhook-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    await node.start();
    try {
      await awaitSemantic();
      const root = node.remember(cat7(TOPIC_A));
      // A faithful hop, admitted from a verified peer, then this node's laundered record citing it.
      const hop = createCMB({ categories: cat7(`${TOPIC_A} for the second quarter`), createdBy: 'peer', lineage: { parents: [root.key], method: 'SVAF-v2' } });
      node._store.receiveFromPeer('peer', { key: hop.metadata.key, content: 'hop', source: 'peer', cmb: hop, _cmbVerified: true });
      const laundered = node.remember(cat7(TOPIC_B2), { parents: [{ key: hop.metadata.key }] }).cmb;
      assert.ok(node._store.descendants(root.key).includes(laundered.metadata.key), 'precondition: indexed under the root through the hop');

      const r = await node.auditLineageTethers({ sever: true });
      assert.strictEqual(r.severed, 1, 'the laundered hop is severed');
      for (const [label, k] of [['the hop', hop.metadata.key], ['the root', root.key]]) {
        assert.ok(!node._store.descendants(k).includes(laundered.metadata.key), `no longer a descendant of ${label}`);
      }
      assert.deepStrictEqual(node._store.ancestors(laundered.metadata.key), [], 'a severed remix is a root in the index');
      assert.deepStrictEqual(node._store.parents(laundered.metadata.key), []);
    } finally {
      await node.stop();
      fs.rmSync(nodeDir(name), { recursive: true, force: true });
    }
  });

  it('fetch: the candidates are the store\'s closure (the parents it indexed)', async () => {
    const name = `audit-anc-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    await node.start();
    try {
      const parent = 'cmb-' + 'a'.repeat(64);
      node.remember(cat7(TOPIC_B), { parents: [{ key: parent }] });
      const asked = [];
      node.fetchCMB = async (k) => { asked.push(k); return null; };
      await node.auditLineageTethers({ fetch: true, timeoutMs: 50 });
      assert.deepStrictEqual(asked, [parent], 'only the parent the store derived its closure from is fetched');
    } finally {
      await node.stop();
      fs.rmSync(nodeDir(name), { recursive: true, force: true });
    }
  });
});
