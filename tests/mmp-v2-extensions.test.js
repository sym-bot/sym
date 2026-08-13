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
