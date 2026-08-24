'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * Regression: local state moves when a CMB is admitted — on EITHER gate path.
 *
 * The neural and heuristic gates are two implementations of one admission decision, but only the
 * neural one called updateLocalState. The heuristic gate is the PRODUCTION DEFAULT — this package
 * ships no svaf_v2.pt, and the neural path additionally spawns a Python subprocess — so in
 * production a node's state never moved when it admitted a peer's cognition. It moved only on
 * init, broadcast and remember. A node that had admitted five hundred peer blocks carried the
 * same local state as one that had admitted none.
 *
 * Identified 2026-07-05 as bug-grade and independent of any learning work; still present in
 * published 0.12.1 when re-checked 2026-08-24, which is why the third test here is structural.
 * A behavioural test on one path would not have caught this: each path worked as written, and the
 * defect was the DIFFERENCE between them.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { FrameHandler } = require('../lib/frame-handler');

describe('_reencodeLocalStateAfterAdmit', () => {
  it('re-encodes the node context into local state', () => {
    const calls = [];
    const node = {
      _buildContext: () => 'the context after admitting a peer block',
      _meshNode: { updateLocalState: (h1, h2, c) => calls.push({ h1, h2, c }) },
      _log: () => {},
    };
    new FrameHandler(node, {})._reencodeLocalStateAfterAdmit();

    assert.strictEqual(calls.length, 1, 'state is updated exactly once per admit');
    assert.ok(Array.isArray(calls[0].h1) && calls[0].h1.length > 0, 'h1 is an encoded vector');
    assert.strictEqual(calls[0].c, 0.8, 'admitted cognition carries the admit confidence');
  });

  it('never discards an admission that already succeeded', () => {
    // The block is stored by the time this runs. Losing a re-encode is recoverable; throwing
    // here would unwind an admission the gate already granted.
    const logged = [];
    const node = {
      _buildContext: () => { throw new Error('context unavailable'); },
      _meshNode: { updateLocalState: () => {} },
      _log: (m) => logged.push(m),
    };
    assert.doesNotThrow(() => new FrameHandler(node, {})._reencodeLocalStateAfterAdmit());
    assert.match(logged.join(' '), /local state re-encode failed/, 'and it is not silent');
  });

  it('BOTH gate paths take the step — the asymmetry cannot silently return', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'lib', 'frame-handler.js'), 'utf8');
    const lines = src.split('\n');
    const stores = lines
      .map((l, i) => ({ l, i }))
      .filter(({ l }) => /_store\.receiveFromPeer\(/.test(l));

    assert.ok(stores.length >= 2, 'both the neural and heuristic paths store an admitted remix');
    for (const { i } of stores) {
      const after = lines.slice(i, i + 6).join('\n');
      assert.match(after, /_reencodeLocalStateAfterAdmit\(\)/,
        `the admit at line ${i + 1} stores a remix without moving local state — that is the 0.12.1 defect`);
    }
  });
});
