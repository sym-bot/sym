'use strict';

// Ingress admission policy (codex transport ruling: clean separation). The five gates the ruling
// names, plus the fail-closed pre-confirmation rule. The point of every one of these: before
// authentication the frame type is attacker-controlled, so it must never select security policy.

const { describe, it } = require('node:test');
const assert = require('node:assert');
const {
  admitCoreSecureFirstFrame, admitCoreSecureFrame, admitLegacyImport,
  refuseFallbackAfterV2Failure, assertNoPromotion,
} = require('../lib/core/mmp-ingress');
const { StickyFloor } = require('../lib/core/mmp-extensions');

const NODE = '018f47a0-7b21-7abc-8def-111111111111';
const ROUTES = [{ endpoint: 'tcp://10.0.0.9:52781', nodeId: NODE }];

describe('MMP v2.0 ingress admission (clean separation)', () => {
  it('gate 1: a legacy handshake frame on the Core Secure listener is refused', () => {
    assert.throws(() => admitCoreSecureFirstFrame({ type: 'handshake', nodeId: NODE }),
      /accepts only client-hello/);
  });

  it('a v2 client-hello is the only admissible first frame', () => {
    assert.ok(admitCoreSecureFirstFrame({ type: 'client-hello' }));
    for (const t of ['cmb', 'cmb-encrypted', 'server-hello', 'client-finish', undefined]) {
      assert.throws(() => admitCoreSecureFirstFrame({ type: t }), /accepts only client-hello/);
    }
  });

  it('fail-closed: no data frame is processed before the handshake is confirmed', () => {
    assert.throws(() => admitCoreSecureFrame({ type: 'cmb-encrypted' }, { confirmed: false }),
      /before the §5.2 handshake is confirmed/);
    assert.ok(admitCoreSecureFrame({ type: 'cmb-encrypted' }, { confirmed: true }));
  });

  it('a cleartext cmb frame on a Core Secure session is refused (v2-only)', () => {
    assert.throws(() => admitCoreSecureFrame({ type: 'cmb' }, { confirmed: true }), /v2-only/);
  });

  it('gate 2: a v2 negotiation failure never falls back to legacy', () => {
    assert.throws(() => refuseFallbackAfterV2Failure('server proof did not verify'),
      /never falls back/);
  });

  it('gate 3: unconfigured legacy ingress is refused (no ambient legacy route)', () => {
    assert.throws(() => admitLegacyImport({ endpoint: 'tcp://10.0.0.9:52781', peerNodeId: NODE, routes: [] }),
      /not configured/);
  });

  it('gate 4: a configured endpoint/nodeId mismatch is refused', () => {
    // right endpoint, wrong nodeId
    assert.throws(() => admitLegacyImport({ endpoint: 'tcp://10.0.0.9:52781', peerNodeId: 'other-node', routes: ROUTES }),
      /no configured Legacy Import route/);
    // right nodeId, wrong endpoint
    assert.throws(() => admitLegacyImport({ endpoint: 'tcp://evil:52781', peerNodeId: NODE, routes: ROUTES }),
      /no configured Legacy Import route/);
    // fingerprint mismatch
    assert.throws(() => admitLegacyImport({
      endpoint: 'tcp://10.0.0.9:52781', peerNodeId: NODE, identityFingerprint: 'bb',
      routes: [{ ...ROUTES[0], identityFingerprint: 'aa' }],
    }), /fingerprint mismatch/);
  });

  it('a correctly configured Legacy Import peer is admitted, labelled non-Core-Secure', () => {
    const posture = admitLegacyImport({ endpoint: 'tcp://10.0.0.9:52781', peerNodeId: NODE, routes: ROUTES });
    assert.strictEqual(posture.transport, 'legacy');
    assert.strictEqual(posture.coreSecure, false);
  });

  it('gate 5: a legacy session cannot enter Core Secure state', () => {
    assert.throws(() => assertNoPromotion({ transport: 'legacy', coreSecure: true }),
      /cannot be promoted/);
    assert.ok(assertNoPromotion({ transport: 'legacy', coreSecure: false }));
  });

  it('sticky floor removes the legacy route once a nodeId has negotiated v2', () => {
    const floor = new StickyFloor();
    floor.recordV2(NODE);
    assert.throws(() => admitLegacyImport({ endpoint: 'tcp://10.0.0.9:52781', peerNodeId: NODE, routes: ROUTES, stickyFloor: floor }),
      /legacy route is disabled until operator reset/);
    floor.reset(NODE);
    assert.ok(admitLegacyImport({ endpoint: 'tcp://10.0.0.9:52781', peerNodeId: NODE, routes: ROUTES, stickyFloor: floor }));
  });
});
