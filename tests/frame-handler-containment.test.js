'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * Regression: a frame must never be able to kill the host process.
 *
 * sym 0.7.30's grounding waiver called `this._node._store.has(p)` on the
 * receive path. On a node whose store does not implement `has` (host apps
 * embed nodes whose store surface varies), the first grounding CMB gossiped
 * from any peer threw inside async `_processHeuristicSVAF` — and because the
 * neural-fallback chain never awaited or caught that promise, the rejection
 * escaped to the global handler and took the whole host process down, on
 * every restart, for as long as peers kept re-gossiping the frame.
 *
 * Two rails guard this now: the waiver feature-detects `_store.has`, and
 * `_runHeuristicSVAFContained` contains ANY heuristic-path rejection to a
 * log line + dropped frame.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { FrameHandler } = require('../lib/frame-handler');

describe('_runHeuristicSVAFContained — heuristic SVAF rejection cannot escape', () => {
  it('contains an async rejection to a log line instead of an unhandled rejection', async () => {
    const logs = [];
    const fh = new FrameHandler({ _log: (m) => logs.push(m) }, {});
    fh._processHeuristicSVAF = async () => { throw new Error('store surface mismatch'); };

    fh._runHeuristicSVAFContained({ cmb: {} }, 'peer-a', 'id-a', 0, Date.now(), 1);
    await new Promise((r) => setImmediate(r));

    assert.ok(
      logs.some((m) => m.includes('SVAF heuristic error') && m.includes('store surface mismatch')),
      `containment log expected, got: ${logs.join(' | ')}`,
    );
  });

  it('contains a synchronous throw from the heuristic path the same way', async () => {
    const logs = [];
    const fh = new FrameHandler({ _log: (m) => logs.push(m) }, {});
    fh._processHeuristicSVAF = () => { throw new TypeError('this._node._store.has is not a function'); };

    assert.doesNotThrow(() => fh._runHeuristicSVAFContained({ cmb: {} }, 'peer-a', 'id-a', 0, Date.now(), 1));
    await new Promise((r) => setImmediate(r));

    assert.ok(logs.some((m) => m.includes('SVAF heuristic error')), 'sync throw is contained too');
  });
});
