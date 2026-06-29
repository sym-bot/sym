'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * Regression: opaque payload survives the SVAF FUSION path, not just the inbox.
 *
 * The payload sits at cmb.payload (sibling of cmb.fields) and is never part of
 * the cmbKey hash. inbox.test.js guards _pushInbox (the pull surface). This
 * guards the layer ABOVE it: when SVAF ADMITS an incoming CMB, the fused remix
 * is rebuilt from CAT7 fields (the heuristic path returns a fresh fusedEntry.cmb
 * with no payload), so the payload was dropped BEFORE it ever reached the inbox.
 * The effect was verdict-dependent and invisible: an admitted directed CMB lost
 * its payload while the same CMB rejected-but-directed (surfaced from the raw
 * msg) kept it — so cross-device payload delivery silently depended on the
 * receiver's per-node SVAF drift. `_preserveIncomingPayload` re-attaches it onto
 * the fused remix on both store paths.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { FrameHandler } = require('../lib/frame-handler');

// Minimal fake node — _preserveIncomingPayload only reads msg + mutates fusedEntry.
const fh = new FrameHandler({}, {});

describe('_preserveIncomingPayload — payload rides the admitted SVAF remix', () => {
  it('re-attaches the incoming payload onto a fused remix whose cmb was rebuilt without it', () => {
    const payload = { type: 'llm-request', request_id: 'r1', nested: { sequence: 42 } };
    const msg = { cmb: { key: 'parent', fields: { focus: { text: 'q' } }, payload } };
    // Simulate the heuristic fusion result: a fresh cmb rebuilt from fields only.
    const fusedEntry = { cmb: { key: 'remix', fields: { focus: { text: 'q' } } } };

    fh._preserveIncomingPayload(fusedEntry, msg);

    assert.deepStrictEqual(fusedEntry.cmb.payload, payload, 'admitted remix carries the parent payload');
  });

  it('is a no-op when the incoming CMB has no payload (back-compat, CAT7-only)', () => {
    const msg = { cmb: { key: 'parent', fields: { focus: { text: 'q' } } } };
    const fusedEntry = { cmb: { key: 'remix', fields: { focus: { text: 'q' } } } };

    fh._preserveIncomingPayload(fusedEntry, msg);

    assert.strictEqual('payload' in fusedEntry.cmb, false, 'no payload key added when none was sent');
  });

  it('does not throw when the fused entry has no cmb', () => {
    const msg = { cmb: { payload: { a: 1 } } };
    assert.doesNotThrow(() => fh._preserveIncomingPayload({}, msg));
    assert.doesNotThrow(() => fh._preserveIncomingPayload(null, msg));
  });

  it('ignores a null/undefined payload rather than overwriting with it', () => {
    const fusedEntry = { cmb: { key: 'remix', fields: {} } };
    fh._preserveIncomingPayload(fusedEntry, { cmb: { payload: null } });
    assert.strictEqual('payload' in fusedEntry.cmb, false, 'null payload is not attached');
  });
});
