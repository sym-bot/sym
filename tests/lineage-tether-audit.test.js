'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * MMP §15.8 retroactive lineage-tether audit — chains stored before the
 * invariant (or received from pre-tether peers) get the same treatment:
 * re-evaluate against the resolvable root in the current kernel, annotate +
 * attest, and (opt-in) sever what fails the floor.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const { createCMB, isSemanticReady, verifyTetherAttestation } = require('../lib/core');

async function awaitSemantic(timeoutMs = 30000) {
  const t0 = Date.now();
  while (!isSemanticReady()) {
    if (Date.now() - t0 > timeoutMs) throw new Error('semantic encoder did not become ready');
    await new Promise((r) => setTimeout(r, 200));
  }
}

function cat7(t) {
  return {
    focus: t, issue: t, intent: t, motivation: t, commitment: t,
    perspective: 'peerA', mood: { text: 'neutral', valence: 0, arousal: 0 },
  };
}

/** Store a pre-tether chain entry: a remix citing `rootKey` with `topicText`
 *  content, injected the way a legacy receiver would have stored it. */
function storeLegacyRemix(node, rootKey, topicText) {
  // NOTE: createCMB mints content-only keys, so fixtures must use distinct
  // texts — two identical texts collide on one key and dedup.
  const cmb = createCMB({ categories: cat7(topicText), createdBy: 'legacy-peer' });
  // Lineage goes in the section this record ACTUALLY carries. The fixture used to staple a flat
  // `cmb.lineage` onto a record createCMB had already built with metadata — a hybrid that is
  // neither generation, whose key read back undefined and whose lineage nothing walked.
  cmb.metadata.lineage = { parents: [rootKey], ancestors: [rootKey], method: 'SVAF-v2' };
  const key = cmb.metadata.key;
  const entry = node._store.receiveFromPeer('legacy-peer', {
    key, content: topicText, source: 'legacy-peer', cmb, storedAt: Date.now(),
  });
  return { key, entry };
}

const TOPIC_A = 'quarterly financial audit of the accounting ledger and tax filings';
const TOPIC_B_ROOT = 'overall report on snowy mountain hiking trail conditions this weekend';
const TOPIC_B = 'fresh snowfall reported on the upper mountain trail sections';
const TOPIC_B2 = 'deep snow drifts covering the mountain hiking path near the summit ridge';

describe('MMP §15.8 retroactive tether audit', () => {
  it('annotate-only pass: failed-floor chains are attested but keep lineage; sever pass strips them', async () => {
    const name = `audit-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    await node.start();
    try {
      await awaitSemantic();
      const rootA = node.remember(cat7(TOPIC_A));
      const rootB = node.remember(cat7(TOPIC_B_ROOT));
      const laundered = storeLegacyRemix(node, rootA.key, TOPIC_B2); // topic-B content citing topic-A root
      const faithful = storeLegacyRemix(node, rootB.key, TOPIC_B);   // topic-B content citing topic-B root

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
      assert.ok(!l2.cmb.metadata.lineage || (l2.cmb.metadata.lineage.parents || []).length === 0, 'laundered chain severed');
      assert.strictEqual(l2.provenance.tether.departedFrom, rootA.key);
      assert.ok(![...node._store._index.byAncestor.get(rootA.key) ?? []].includes(laundered.key),
        'ancestor index no longer lists the severed remix');

      const f2 = node._store.get(faithful.key);
      assert.ok(f2.cmb.metadata.lineage && f2.cmb.metadata.lineage.ancestors.includes(rootB.key), 'faithful chain untouched');
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
      const remix = storeLegacyRemix(node, parent.metadata.key, TOPIC_B);
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
      const orphan = storeLegacyRemix(node, 'cmb1-purged-root-nowhere', TOPIC_B);
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
      // A faithful hop, admitted from a verified peer, then a laundered hop citing it.
      const hop = createCMB({ categories: cat7(`${TOPIC_A} for the second quarter`), createdBy: 'peer', lineage: { parents: [root.key], method: 'SVAF-v2' } });
      node._store.receiveFromPeer('peer', { key: hop.metadata.key, content: 'hop', source: 'peer', cmb: hop, _cmbVerified: true });
      const laundered = createCMB({ categories: cat7(TOPIC_B2), createdBy: 'peer', lineage: { parents: [hop.metadata.key], method: 'SVAF-v2' } });
      node._store.receiveFromPeer('peer', { key: laundered.metadata.key, content: 'laundered', source: 'peer', cmb: laundered, _cmbVerified: true });
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

  it('fetch: the candidates are the store\'s closure, never an ancestors list the record carries', async () => {
    const name = `audit-anc-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    await node.start();
    try {
      const parent = 'cmb-' + 'a'.repeat(64);
      const chosen = 'cmb-' + 'b'.repeat(64);
      const cmb = createCMB({ categories: cat7(TOPIC_B), createdBy: 'peer' });
      cmb.metadata.lineage = { parents: [parent], ancestors: [chosen], method: 'SVAF-v2' };
      node._store.receiveFromPeer('peer', { key: cmb.metadata.key, content: TOPIC_B, source: 'peer', cmb });
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
