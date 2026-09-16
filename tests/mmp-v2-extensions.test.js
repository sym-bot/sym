'use strict';

// MMP v2.0 cmb-encrypted-v2 extension negotiation (codex migration ruling, Option C). The five
// downgrade-resistance cases the ruling names, at the negotiation layer.

const { describe, it } = require('node:test');
const assert = require('node:assert');
const {
  EXT_CMB_ENCRYPTED_V2, selectExtensions, assertNoDowngrade, connectionPosture, StickyFloor,
} = require('../lib/core/mmp-extensions');

const NODE = '018f47a0-7b21-7abc-8def-0123456789ab';

describe('MMP v2.0 cmb-encrypted-v2 extension negotiation', () => {
  it('both peers offer → server MUST select it, and the session is Core Secure v2', () => {
    const { selected, v2 } = selectExtensions([EXT_CMB_ENCRYPTED_V2], [EXT_CMB_ENCRYPTED_V2, 'other']);
    assert.deepStrictEqual(selected, [EXT_CMB_ENCRYPTED_V2]);
    assert.strictEqual(v2, true);
    const posture = connectionPosture({ v2Selected: v2, peerNodeId: NODE });
    assert.deepStrictEqual(posture, { transport: EXT_CMB_ENCRYPTED_V2, coreSecure: true });
  });

  it('both offered but selection omits it → aborts as a downgrade', () => {
    assert.throws(
      () => assertNoDowngrade([EXT_CMB_ENCRYPTED_V2], [EXT_CMB_ENCRYPTED_V2], /* selected */ []),
      /downgrade/,
    );
  });

  it('selected v2 posture is v2-only — legacy is not an allowed transport on that session', () => {
    const posture = connectionPosture({ v2Selected: true, peerNodeId: NODE });
    assert.strictEqual(posture.transport, EXT_CMB_ENCRYPTED_V2);
    assert.notStrictEqual(posture.transport, 'legacy');
    // (The transport layer rejects any legacy frame once this posture holds; enforced there.)
  });

  it('neither side has it, and the peer is not a configured legacy peer → refuse (no auto fallback)', () => {
    assert.throws(
      () => connectionPosture({ v2Selected: false, peerNodeId: NODE, config: {} }),
      /refusing non-Core-Secure/,
    );
  });

  it('sticky floor: a nodeId that spoke v2 cannot later be walked down to no-v2', () => {
    const floor = new StickyFloor();
    floor.recordV2(NODE);
    assert.throws(() => floor.enforce(NODE, /* v2Selected */ false), /sticky-floor downgrade/);
    // only an explicit operator reset clears it
    floor.reset(NODE);
    assert.doesNotThrow(() => floor.enforce(NODE, false));
  });

  it('an explicitly configured Legacy Import peer stays deliverable, marked non-Core-Secure', () => {
    const posture = connectionPosture({ v2Selected: false, peerNodeId: NODE, config: { legacyImportNodeIds: [NODE] } });
    assert.deepStrictEqual(posture, { transport: 'legacy', coreSecure: false });
  });

  it('a non-v2 handshake for an unseen identity is unaffected by the floor', () => {
    const floor = new StickyFloor();
    assert.doesNotThrow(() => floor.enforce('unseen-node', false));
  });
});

describe('downgrade protection covers a REGISTRY, not one hard-coded name', () => {
  const { assertNoDowngrade, DOWNGRADE_CRITICAL } = require('../lib/core/mmp-extensions');

  it('exposes the set it protects, so a new extension has to make a decision', () => {
    // The check was named for a property and implemented for one extension. Anyone adding an
    // extension would reasonably assume a function called assertNoDowngrade covered theirs.
    assert.ok(Array.isArray(DOWNGRADE_CRITICAL) && DOWNGRADE_CRITICAL.length >= 1);
    assert.ok(Object.isFrozen(DOWNGRADE_CRITICAL), 'the registry must not be mutable at runtime');
  });

  it('aborts for EVERY registered extension both peers offered, not just the first', () => {
    for (const ext of DOWNGRADE_CRITICAL) {
      assert.throws(() => assertNoDowngrade([ext], [ext], []), /downgrade/,
        `${ext} is registered as downgrade-critical but stripping it did not abort`);
    }
  });

  it('does NOT abort for an unregistered extension — the omission is deliberate and visible', () => {
    // An extension outside the registry is negotiable: either side may decline it. This test
    // exists so that adding one and expecting protection fails HERE rather than in the field.
    assert.doesNotThrow(() => assertNoDowngrade(['x-not-registered'], ['x-not-registered'], []));
  });

  it('still reports v2 posture correctly when other extensions are in play', () => {
    const { EXT_CMB_ENCRYPTED_V2 } = require('../lib/core/mmp-extensions');
    assert.equal(assertNoDowngrade([EXT_CMB_ENCRYPTED_V2, 'x-other'], [EXT_CMB_ENCRYPTED_V2],
      [EXT_CMB_ENCRYPTED_V2]).v2, true);
    assert.equal(assertNoDowngrade(['x-other'], ['x-other'], ['x-other']).v2, false);
  });
});
