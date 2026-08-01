'use strict';
require('./_isolate-home');

// Regression: remember() with parents must mint the REMIX-scheme v1 key.
// recomputeKey dispatches by role (lineage present → remix), so a root-keyed
// block carrying parents fails content verification at every peer and is
// hard-rejected as forged — i.e., authored grounding CMBs silently never
// landed cross-node. Found 2026-07-07 while building sym/emit.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');

const { SymNode } = require('../lib/node');
const { BonjourDiscovery } = require('../lib/discovery');
const { blockKeyV2 } = require('@sym-bot/core');
const { nodeDir } = require('../lib/config');

const ALIGNED = { decision: 'aligned', total_drift: 0.1, field_drifts: { focus: 0.1 }, gate_values: { g: 1 } };

function mkNode(name) {
  const n = new SymNode({ name, silent: true, group: 'g', discovery: new BonjourDiscovery({ mdns: false }) });
  n._svafEvaluator.evaluate = async () => ALIGNED;
  return n;
}

describe('remember() with parents — remix-scheme keying (§8.2.1 role dispatch)', () => {
  it('a lineage-bearing block is addressed CONTENT-ONLY — no remix re-key', async () => {
    // This asserted a self-consistent REMIX key under §8.2.1 role dispatch: a block carrying
    // parents was re-keyed under a derivation that bound the parents and the author's NAME.
    // That derivation is retired. The v2 address is the Merkle root over the seven fieldKeys
    // and is content-only, so a lineage-bearing block is addressed exactly like any other block
    // with the same content — which IS the collapse property, and it is the condition Rule A's
    // soundness depends on (a self-re-assertion cites rather than minting key K with parent K).
    const node = mkNode('rmx-key');
    await node.start();
    try {
      node._hasNewDomainData = true;
      const parent = { metadata: { key: 'cmb-' + 'a'.repeat(64) } };
      const res = node.remember(
        { focus: 'outcome', intent: 'ground', commitment: 'verified: it held' },
        { parents: [parent] },
      );
      const cmb = res.cmb || res;
      assert.ok(cmb.metadata.lineage?.parents.length === 1, 'lineage present');
      assert.ok(!('ancestors' in cmb.metadata.lineage), 'ancestors is retired, not carried');
      assert.equal(cmb.metadata.key, blockKeyV2(cmb.fields), 'address is the content root, unchanged by lineage');
    } finally {
      await node.stop();
      fs.rmSync(nodeDir('rmx-key'), { recursive: true, force: true });
    }
  });

  it('a peer ACCEPTS an authored grounding CMB (was: signature-rejected as forged)', async () => {
    const A = mkNode('rmx-a');
    const B = mkNode('rmx-b');
    await A.start();
    await B.start();
    try {
      let rejected = 0;
      const acceptedKeys = [];
      B.on('metric', (m) => { if (m.type === 'cmb-signature-rejected') rejected++; });
      B.on('cmb-accepted', (s) => acceptedKeys.push((s.cmb || s).metadata?.key ?? (s.cmb || s).key));

      A._connectToPeer('127.0.0.1', B._port, 'rmx-b-id', 'rmx-b');
      const until = async (cond, ms = 5000) => {
        const deadline = Date.now() + ms;
        while (!cond() && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
      };
      await until(() => A._peers.size > 0);

      A._hasNewDomainData = true;
      const parent = { key: 'cmb1-' + 'b'.repeat(64), lineage: { ancestors: [] } };
      const res = A.remember(
        { focus: 'grounding outcome', intent: 'ground', commitment: 'failed: regression seen' },
        { parents: [parent] },
      );
      const emittedKey = (res.cmb || res).key;

      await until(() => acceptedKeys.length > 0 || rejected > 0);
      assert.equal(rejected, 0, 'no signature rejection for the authored grounding');
      assert.equal(acceptedKeys.length > 0, true, 'the grounding CMB landed on the peer');
      // Scheme, not spelling — v1 keys carry a 64-hex digest under either prefix.
      assert.match(emittedKey, /^cmb1?-[0-9a-f]{64}$/);
    } finally {
      await A.stop();
      await B.stop();
      for (const n of ['rmx-a', 'rmx-b']) fs.rmSync(nodeDir(n), { recursive: true, force: true });
    }
  });
});
