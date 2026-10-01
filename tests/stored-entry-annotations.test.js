'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * What a node records ABOUT an admitted record lives on the store entry, beside the record.
 *
 * A two-section record has exactly `categories` and `metadata` (§8.8.1). The receive path added
 * four more members to the stored record: `admission` (the admission attestation), `tether` (the
 * §15.8 attestation), `provenance` (fusion evidence and the tether annotation) and `collapsed`. None
 * is the author's, none is signed, and each made the stored record a shape no reader of the record
 * format expects. They are entry members now, and files written before keep reading.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const { tmpdir } = require('./_tmpdir');
const { MemoryStore } = require('../lib/memory-store');
const { createCMB, signCMB, verifyCMB, verifyAttestation, verifyTetherAttestation } = require('../lib/core');

const ALIGNED = { decision: 'aligned', total_drift: 0.1, category_drifts: { focus: 0.1 }, gate_values: { focus: 1 } };

function rawKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  return { pub: publicKey.slice(-32).toString('base64url'), priv: privateKey.slice(-32).toString('base64url') };
}
const AUTHOR = rawKeypair();

function cat7(t) {
  return {
    focus: t, issue: t, intent: t, motivation: t, commitment: t,
    perspective: 'peerA', mood: { text: 'neutral', valence: 0, arousal: 0 },
  };
}

async function withNode(opts, fn) {
  const name = `annotations-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), ...opts });
  await node.start();
  try {
    return await fn(node);
  } finally {
    await node.stop();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  }
}

describe('admission annotations live on the store entry', () => {
  for (const path_ of ['heuristic', 'neural']) {
    it(`${path_} path: the stored record is exactly {categories, metadata}; the entry carries the rest`, async () => {
      const opts = path_ === 'neural' ? { svafEvaluator: { evaluate: async () => ALIGNED } } : {};
      await withNode(opts, async (node) => {
        node._pinPeerKey('peerA', AUTHOR.pub);
        const record = createCMB({ categories: cat7(`an observation admitted through the ${path_} path`), createdBy: 'peerA' });
        signCMB(record, AUTHOR.priv);
        // A frame that also tries to supply the node's own annotations.
        const frame = {
          type: 'cmb', timestamp: Date.now(), cmb: JSON.parse(JSON.stringify(record)),
          admission: { forged: true }, provenance: { forged: true }, tether: { forged: true }, collapsed: 'forged', svaf: { forged: true },
        };
        await node._frameHandler._handleMemoryShare('peerA', 'peerA', frame);

        const entry = node._store.get(record.metadata.key);
        assert.ok(entry, 'admitted and stored');
        assert.strictEqual(entry.svaf?.method === 'neural', path_ === 'neural', 'precondition: the intended path stored it');
        assert.deepStrictEqual(Object.keys(entry.cmb).sort(), ['categories', 'metadata'], 'the record has exactly its two sections');
        assert.strictEqual(verifyCMB(entry.cmb, AUTHOR.pub).valid, true, 'and still verifies under its author\'s key');
        const onDisk = JSON.parse(fs.readFileSync(path.join(node._store._dir, `${entry.key}.json`), 'utf8'));
        assert.deepStrictEqual(Object.keys(onDisk.cmb).sort(), ['categories', 'metadata'], 'on disk too');

        assert.strictEqual(entry.admission?.of, record.metadata.key, 'the admission attestation is on the entry');
        assert.strictEqual(entry.admission.by, node.nodeId);
        assert.deepStrictEqual(verifyAttestation(entry.admission, node._identity.publicKey), { signed: true, valid: true });
        assert.strictEqual(entry.tether?.anchor, record.metadata.key, 'the tether attestation is on the entry (a root is its own anchor)');
        assert.strictEqual(verifyTetherAttestation(entry.tether, node._identity.publicKey).valid, true);
        assert.strictEqual(entry.provenance?.tether?.severed, false, 'the provenance is on the entry');
        assert.strictEqual(entry.provenance.forged, undefined, 'nothing the frame supplied reached it');
        assert.strictEqual(entry.collapsed, true, 'the record is the incoming block itself');
        if (path_ === 'heuristic') {
          assert.strictEqual(typeof entry.provenance.totalDrift, 'number', 'the gate\'s evidence');
          assert.strictEqual(entry.svaf, undefined, 'no neural evidence a frame supplied');
        }
      });
    });
  }

  it('a store file written before reads back with its annotations on the entry', async () => {
    const dir = tmpdir('sym-annotations-legacy-');
    const record = createCMB({ categories: cat7('a record stored by an earlier version'), createdBy: 'peerA' });
    signCMB(record, AUTHOR.priv);
    const admission = { of: record.metadata.key, by: 'n1', verdict: 'aligned' };
    const tether = { of: record.metadata.key, anchor: record.metadata.key, verdict: 'tethered', by: 'n1' };
    const provenance = { totalDrift: 0.1, tether: { severed: false } };
    // The shape the receive path used to persist.
    const stale = {
      key: record.metadata.key, content: 'x', peerId: 'peer', storedAt: Date.now(), lineage: { parents: [], ancestors: [], method: null },
      cmb: { ...record, admission, tether, provenance, collapsed: true },
    };
    fs.writeFileSync(path.join(dir, `${stale.key}.json`), JSON.stringify(stale, null, 2));

    const syncStore = new MemoryStore(dir, 'receiver');
    const asyncStore = new MemoryStore(dir, 'receiver');
    await asyncStore.load();
    for (const [label, store] of [['first touch', syncStore], ['load()', asyncStore]]) {
      const entry = store.get(stale.key);
      assert.deepStrictEqual(Object.keys(entry.cmb).sort(), ['categories', 'metadata'], `${label}: the record has exactly its two sections`);
      assert.strictEqual(verifyCMB(entry.cmb, AUTHOR.pub).valid, true, `${label}: and verifies`);
      assert.deepStrictEqual(
        { admission: entry.admission, tether: entry.tether, provenance: entry.provenance, collapsed: entry.collapsed },
        { admission, tether, provenance, collapsed: true },
        `${label}: every annotation is still there, on the entry`);
    }
  });
});
