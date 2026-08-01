'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * The redundancy floor is settable on the node — and defaults in exactly one place.
 *
 * Every other SVAF threshold has been an `opts.svaf*` for a long time. This one was not
 * settable at all: it lived as a constant inside core's svaf-heuristic, read from a config
 * key no caller populated. It is also the whole of the binary redundancy cut, so the number
 * that decides "already in memory" was the number an operator could neither move nor
 * attribute to a sample.
 *
 * The second test is the one that matters. A `?? 0.10` here would pass the first test and
 * quietly create a second copy of the threshold in a different package — free to drift from
 * core's the day either moves.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');

function withNode(baseName, opts, fn) {
  const name = `${baseName}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), ...opts });
  try { return fn(node); } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
}

describe('svafRedundancyThreshold', () => {
  it('an operator-set floor reaches the node', () => {
    withNode('floor-set', { svafRedundancyThreshold: 0.42 }, (node) => {
      assert.strictEqual(node._svafRedundancyThreshold, 0.42);
    });
  });

  it('UNSET stays undefined — the default belongs to core, not to a copy here', () => {
    withNode('floor-unset', {}, (node) => {
      assert.strictEqual(node._svafRedundancyThreshold, undefined,
        'a `?? 0.10` here would be a second home for one threshold, in a different package');
    });
  });

  it('it sits beside the thresholds that were already settable, not apart from them', () => {
    withNode('floor-siblings', { svafStableThreshold: 0.3, svafGuardedThreshold: 0.7 }, (node) => {
      assert.strictEqual(node._svafStableThreshold, 0.3);
      assert.strictEqual(node._svafGuardedThreshold, 0.7);
      assert.ok('_svafRedundancyThreshold' in node,
        'the floor must exist on the node even when unset, or the pass-through reads a missing field');
    });
  });
});
