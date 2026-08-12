'use strict';

/**
 * B-2 / AC-2.4 — Rule A and the collapse property.
 *
 * Rule A: every block parents from its author's own HEAD, so an agent has one continuous line
 * rather than a scatter of unrooted blocks.
 *
 * THE INVARIANT THIS FILE EXISTS FOR (§7.5, Unit A's novel find): under content-only addressing,
 * re-asserting content identical to your own HEAD produces THE SAME ADDRESS as your HEAD.
 * Parenting that on [own HEAD] writes the edge K -> K, and a reachability walk never leaves it.
 * Rule A is sound under content-only addressing IFF the collapse property holds.
 *
 * The old scheme made this impossible by accident: a remix key was minted over categories + parents
 * + the receiver's NAME, so remixKey != parentKey by construction. Removing the name term
 * removed that guarantee without removing the code that relied on it.
 *
 * AND THE ASSERTION IS "HEAD DOES NOT ADVANCE", not "no block was stored". Those come apart
 * exactly when collapse is implemented as a STORE-LEVEL DEDUP rather than a MINT-LEVEL REFUSAL:
 * a dedup writes nothing while HEAD has already moved — the block was minted and then discarded,
 * so the store looks correct and the agent's timeline is wrong. Only the second assertion
 * distinguishes them, so the second assertion is the one that matters.
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { SymNode } = require('../lib/node');
const { BonjourDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');

const ALIGNED = { decision: 'aligned', total_drift: 0.1, gate_values: {} };

async function withNode(name, fn) {
  const node = new SymNode({ name, silent: true, room: 'g', discovery: new BonjourDiscovery({ mdns: false }) });
  node._svafEvaluator.evaluate = async () => ALIGNED;
  await node.start();
  try { await fn(node); } finally {
    await node.stop();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  }
}

const FIELDS = {
  focus: 'the crosswalk for status is unagreed',
  issue: 'no counterpart category in the target',
  intent: 'coordinate',
  motivation: 'unblock the mapping',
  commitment: 'agree it with the category owner',
  perspective: 'dev seat',
  mood: { text: 'steady', valence: 0, arousal: 0 },
};

test('AC-2.4: re-asserting your own HEAD mints NOTHING and HEAD does not advance', async () => {
  await withNode('rule-a-collapse', async (node) => {
    const first = node.remember({ ...FIELDS });
    assert.ok(first, 'the first assertion mints');
    const head = node._head;
    assert.equal(head, first.key, 'HEAD is what was just minted');

    // Say exactly the same thing again.
    const again = node.remember({ ...FIELDS });

    assert.ok(again?.collapsed, 'the re-assertion collapses');
    assert.equal(again.key, head, 'and cites the address that already says it');
    // THE assertion. A store-level dedup would also return nothing new here while having
    // already advanced HEAD — this is what tells the two apart.
    assert.equal(node._head, head, 'HEAD MUST NOT advance: nothing new was said');
  });
});

test('AC-2.4: the collapse is a MINT-level refusal — no self-edge is ever written', async () => {
  await withNode('rule-a-no-self-edge', async (node) => {
    const first = node.remember({ ...FIELDS });
    const again = node.remember({ ...FIELDS }, { parents: [first.cmb] });

    // Whatever else happens, the one thing that must never exist is K -> K.
    const lineage = again?.cmb?.metadata?.lineage;
    if (lineage?.parents?.length) {
      assert.ok(!lineage.parents.includes(again.key),
        'a block must never claim descent from itself — that edge is a walk that does not terminate');
    }
    assert.equal(node._head, first.key, 'HEAD still has not advanced');
  });
});

test('saying something NEW after a collapse still mints, and advances HEAD', async () => {
  // The collapse must not wedge the agent: a genuine new assertion has to proceed normally.
  await withNode('rule-a-recovers', async (node) => {
    const first = node.remember({ ...FIELDS });
    node.remember({ ...FIELDS });                       // collapses
    const next = node.remember({ ...FIELDS, focus: 'the crosswalk was agreed with the owner' });

    assert.ok(next && !next.collapsed, 'new content mints');
    assert.notEqual(next.key, first.key, 'different content, different address');
    assert.equal(node._head, next.key, 'HEAD advances to it');
  });
});

test('B-2: parenting to your OWN head does not trip or consume the anti-paraphrase flag', async () => {
  // The guard exists to stop agents paraphrasing EACH OTHER. Continuing your own line is not
  // paraphrase, and conflating the two enforced a strict alternation — root, parented, root —
  // which made Rule A unimplementable, since it requires every block to be parented.
  await withNode('rule-a-selfparent', async (node) => {
    const root = node.remember({ ...FIELDS });
    node._hasNewDomainData = false;                     // no fresh domain data at all

    const child = node.remember(
      { ...FIELDS, focus: 'continuing my own line' },
      { parents: [root.cmb] },
    );
    assert.ok(child, 'a self-parented block is NOT rejected by the anti-paraphrase guard');

    const grandchild = node.remember(
      { ...FIELDS, focus: 'and continuing it again' },
      { parents: [child.cmb] },
    );
    assert.ok(grandchild, 'two self-parented blocks in a row — the alternation is gone');
    assert.equal(node._hasNewDomainData, false, 'and self-parenting never consumed the flag');
  });
});

test('B-2: parenting to a PEER still requires new domain data', async () => {
  // The half of the guard that was right, kept intact.
  await withNode('rule-a-peerparent', async (node) => {
    node._hasNewDomainData = false;
    const peerBlock = { metadata: { key: 'cmb-' + 'f'.repeat(64) } };   // not ours
    const res = node.remember({ ...FIELDS }, { parents: [peerBlock] });
    assert.equal(res, null, 'remixing a peer without new domain data is still refused');
  });
});
