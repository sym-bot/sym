'use strict';

const { describe, it, after } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { nodeDir } = require('../lib/config');
const { NullDiscovery } = require('../lib/discovery');

// Use unique names to avoid state conflicts
const nodeName = `test-node-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;

describe('SymNode', () => {
  let SymNode;

  it('should load SymNode', () => {
    SymNode = require('../lib/node').SymNode;
    assert.ok(SymNode, 'SymNode should be exported');
  });

  it('should require a name', () => {
    assert.throws(() => new SymNode({}), /requires a name/);
  });

  it('should set name and nodeId in constructor', () => {
    const node = new SymNode({ name: nodeName, silent: true });
    assert.strictEqual(node.name, nodeName);
    assert.ok(node.nodeId, 'nodeId should be set');
    assert.strictEqual(node.nodeId.length, 36, 'nodeId should be full UUID');
  });

  // Lifecycle tests inject NullDiscovery — no TCP server, no Bonjour, no child processes.
  // This tests the node's business logic in isolation from networking.
  // Bonjour integration is validated in local dev and e2e tests.

  it('should return full nodeId in status()', async () => {
    const node = new SymNode({ name: nodeName, silent: true, discovery: new NullDiscovery() });
    await node.start();
    const s = node.status();
    assert.strictEqual(s.nodeId, node.nodeId);
    assert.strictEqual(s.nodeId.length, 36);
    assert.strictEqual(s.name, nodeName);
    assert.strictEqual(s.running, true);
    assert.strictEqual(s.peerCount, 0);
    await node.stop();
  });

  it('should start and stop without error', async () => {
    const name = `test-lifecycle-${Date.now()}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    await node.start();
    assert.strictEqual(node.status().running, true);
    await node.stop();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  });

  it('should use NullDiscovery when relayOnly is true', () => {
    const node = new SymNode({ name: nodeName, silent: true, relayOnly: true });
    // relayOnly creates NullDiscovery internally — no server, no discovery
    assert.ok(node._discovery instanceof NullDiscovery);
  });

  it('should return empty peers when no connections', () => {
    const node = new SymNode({ name: nodeName, silent: true });
    const peers = node.peers();
    assert.ok(Array.isArray(peers));
    assert.strictEqual(peers.length, 0);
  });

  it('should return null coherence when no peers', () => {
    const node = new SymNode({ name: nodeName, silent: true });
    const c = node.coherence();
    assert.strictEqual(c, null);
  });

  it('should remember and recall', async () => {
    const name = `test-memory-${Date.now()}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    await node.start();

    const entry = node.remember({
      focus: 'testing memory',
      issue: 'none',
      intent: 'verify remember/recall',
      motivation: 'test coverage',
      commitment: 'test suite',
      perspective: 'developer',
      mood: { text: 'focused', valence: 0.5, arousal: 0.3 },
    });
    assert.ok(entry, 'remember should return entry');
    assert.ok(entry.key, 'entry should have key');

    const results = node.recall('testing memory');
    assert.ok(results.length >= 1, 'should find the memory');

    const count = node.memories();
    assert.ok(count >= 1, 'should have at least 1 memory');

    await node.stop();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  });

  it('should build a startup primer from remix memory', async () => {
    const name = `test-primer-${Date.now()}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    await node.start();

    // Empty store → empty primer.
    const empty = node.buildStartupPrimer();
    assert.strictEqual(empty.text, '', 'empty store yields empty primer text');
    assert.strictEqual(empty.count, 0);
    assert.strictEqual(empty.totalInStore, 0);

    // Seed 3 CMBs.
    for (let i = 0; i < 3; i++) {
      node.remember({
        focus: `primer test ${i}`,
        issue: 'none',
        intent: 'verify primer shape',
        motivation: 'test',
        commitment: 'test suite',
        perspective: 'developer',
        mood: { text: 'focused', valence: 0.5, arousal: 0.3 },
      });
    }

    const primer = node.buildStartupPrimer();
    assert.strictEqual(primer.count, 3, 'primer includes all 3 entries');
    assert.strictEqual(primer.totalInStore, 3);
    assert.strictEqual(primer.dropped, 0);
    assert.ok(primer.text.includes('Mesh memory primer'), 'primer has header');
    assert.ok(primer.text.includes(name), 'primer names the agent');
    assert.ok(primer.text.includes('primer test 0'), 'primer includes CMB focus text');

    // Count cap — maxCount=2 should drop one.
    const capped = node.buildStartupPrimer({ maxCount: 2 });
    assert.strictEqual(capped.count, 2, 'cap enforced');
    assert.strictEqual(capped.dropped, 1, 'one entry elided by cap');
    assert.ok(capped.text.includes('1 older entries elided'), 'primer reports dropped count');

    // Recency cap — maxAgeMs=1ms should elide everything.
    const stale = node.buildStartupPrimer({ maxAgeMs: 1 });
    assert.strictEqual(stale.count, 0, 'recency cap elides all entries');
    assert.strictEqual(stale.dropped, 3);

    await node.stop();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  });

  it('should track protocol metrics', async () => {
    const name = `test-metrics-${Date.now()}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    await node.start();

    const m0 = node.metrics();
    assert.strictEqual(m0.cmbProduced, 0);
    assert.strictEqual(m0.recalls, 0);
    assert.ok(m0.startedAt > 0);
    assert.ok(m0.uptimeMs >= 0);

    // remember() increments cmbProduced
    node.remember({
      focus: 'test', issue: 'none', intent: 'test',
      motivation: 'test', commitment: 'test', perspective: 'test',
      mood: { text: 'neutral', valence: 0, arousal: 0 },
    });
    assert.strictEqual(node.metrics().cmbProduced, 1);

    // recall() increments recalls
    node.recall('test');
    assert.strictEqual(node.metrics().recalls, 1);

    // metric event emitted
    let metricEvent = null;
    node.on('metric', (m) => { metricEvent = m; });
    node.remember({
      focus: 'test2', issue: 'none', intent: 'test',
      motivation: 'test', commitment: 'test', perspective: 'test',
      mood: { text: 'neutral', valence: 0, arousal: 0 },
    });
    assert.ok(metricEvent, 'should emit metric event');
    assert.strictEqual(metricEvent.type, 'cmb-produced');
    assert.strictEqual(node.metrics().cmbProduced, 2);

    // reportLLMUsage() tracks LLM costs
    node.reportLLMUsage(1000, 200, 'gpt-4o-mini');
    const m = node.metrics();
    assert.strictEqual(m.llmCalls, 1);
    assert.strictEqual(m.llmTokensIn, 1000);
    assert.strictEqual(m.llmTokensOut, 200);
    assert.strictEqual(m.llmModel, 'gpt-4o-mini');
    assert.ok(m.llmCostUSD > 0, 'should compute cost');
    // gpt-4o-mini: 1000 * 0.15/1M + 200 * 0.60/1M = 0.00015 + 0.00012 = 0.00027
    assert.ok(Math.abs(m.llmCostUSD - 0.00027) < 0.00001, `cost should be ~0.00027, got ${m.llmCostUSD}`);

    await node.stop();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  });

  it('should track new domain data for remix guard', async () => {
    const name = `test-remix-guard-${Date.now()}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    await node.start();

    // Initially no new domain data
    assert.strictEqual(node.canRemix(), false, 'should not have new data initially');

    // remember() sets the flag
    node.remember({
      focus: 'domain observation',
      issue: 'none',
      intent: 'test',
      motivation: 'test',
      commitment: 'test',
      perspective: 'test',
      mood: { text: 'neutral', valence: 0, arousal: 0 },
    });
    assert.strictEqual(node.canRemix(), true, 'should have new data after remember()');

    // markRemixed() resets
    node.markRemixed();
    assert.strictEqual(node.canRemix(), false, 'should be false after markRemixed()');

    // remember() again sets it back
    node.remember({
      focus: 'another observation',
      issue: 'none',
      intent: 'test',
      motivation: 'test',
      commitment: 'test',
      perspective: 'test',
      mood: { text: 'neutral', valence: 0, arousal: 0 },
    });
    assert.strictEqual(node.canRemix(), true, 'should be true again after second remember()');

    await node.stop();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  });

  it('should reject remix when no new domain data (MMP Section 14.7)', async () => {
    const name = `test-remix-enforce-${Date.now()}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    await node.start();

    // No domain data yet — remix should be rejected
    const rejected = node.remember(
      { focus: 'remix attempt', issue: 'none', intent: 'test', motivation: 'test',
        commitment: 'test', perspective: 'test', mood: { text: 'neutral', valence: 0, arousal: 0 } },
      { parents: [{ key: 'cmb-fake-parent', lineage: { ancestors: [] } }] }
    );
    assert.strictEqual(rejected, null, 'remix without domain data should return null');

    // Produce domain observation — this sets canRemix = true
    node.remember({
      focus: 'domain observation', issue: 'none', intent: 'test', motivation: 'test',
      commitment: 'test', perspective: 'test', mood: { text: 'neutral', valence: 0, arousal: 0 },
    });
    assert.strictEqual(node.canRemix(), true);

    // Now remix should succeed
    const accepted = node.remember(
      { focus: 'valid remix', issue: 'none', intent: 'test', motivation: 'test',
        commitment: 'test', perspective: 'test', mood: { text: 'neutral', valence: 0, arousal: 0 } },
      { parents: [{ key: 'cmb-fake-parent', lineage: { ancestors: [] } }] }
    );
    assert.ok(accepted, 'remix with domain data should succeed');
    assert.ok(accepted.key, 'remix should have key');

    await node.stop();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  });

  it('should emit cmb-accepted when receiveFromPeer stores a CMB', async () => {
    const name = `test-cmb-accepted-${Date.now()}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    await node.start();

    // Track emitted events
    const accepted = [];
    node.on('cmb-accepted', (entry) => accepted.push(entry));

    // Simulate a peer CMB being accepted via the store proxy
    // (In production, frame-handler.js calls this after SVAF accepts)
    const peerEntry = {
      content: 'test signal from peer agent',
      source: 'test-peer',
      timestamp: Date.now(),
      cmb: {
        key: `cmb-test-${Date.now()}`,
        fields: {
          focus: { text: 'test signal' },
          mood: { text: 'neutral', valence: 0, arousal: 0 },
        },
      },
    };

    const stored = node._store.receiveFromPeer('peer-123', peerEntry);
    assert.ok(stored, 'receiveFromPeer should return stored entry');
    assert.strictEqual(accepted.length, 1, 'should emit exactly one cmb-accepted event');
    assert.strictEqual(accepted[0].content, 'test signal from peer agent');
    assert.strictEqual(accepted[0].peerId, 'peer-123');
    assert.ok(accepted[0].key, 'accepted entry should have key');

    // Duplicate should NOT emit
    const dup = node._store.receiveFromPeer('peer-456', peerEntry);
    assert.strictEqual(dup, null, 'duplicate should return null');
    assert.strictEqual(accepted.length, 1, 'should NOT emit for duplicate');

    await node.stop();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  });

  it('should reset hasNewDomainData after remix (MMP Section 14.7)', async () => {
    const name = `test-remix-reset-${Date.now()}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    await node.start();

    const fields = {
      focus: 'observation', issue: 'none', intent: 'test', motivation: 'test',
      commitment: 'test', perspective: 'test', mood: { text: 'neutral', valence: 0, arousal: 0 },
    };

    // Domain observation sets canRemix = true
    node.remember(fields);
    assert.strictEqual(node.canRemix(), true, 'domain observation should enable remix');

    // Remix should succeed and RESET canRemix
    const remix = node.remember(
      { ...fields, focus: 'remix of peer signal' },
      { parents: [{ key: 'cmb-parent-123', lineage: { ancestors: [] } }] }
    );
    assert.ok(remix, 'remix should succeed');
    assert.strictEqual(node.canRemix(), false, 'remix should reset hasNewDomainData');

    // Second remix without new domain data should be rejected
    const rejected = node.remember(
      { ...fields, focus: 'second remix attempt' },
      { parents: [{ key: 'cmb-parent-456', lineage: { ancestors: [] } }] }
    );
    assert.strictEqual(rejected, null, 'second remix without new domain data should be rejected');

    // New domain observation re-enables remix
    node.remember({ ...fields, focus: 'fresh observation' });
    assert.strictEqual(node.canRemix(), true, 'new observation should re-enable remix');

    await node.stop();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  });

  it('should support multi-transport per peer (MMP Section 4.6)', async () => {
    const name = `test-multi-transport-${Date.now()}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    await node.start();

    const events = [];
    node.on('peer-joined', (e) => events.push({ type: 'joined', ...e }));
    node.on('peer-left', (e) => events.push({ type: 'left', ...e }));

    // Mock transports with close event support
    function mockTransport() {
      const listeners = {};
      return {
        on: (event, fn) => { listeners[event] = fn; },
        send: () => {},
        close: () => { if (listeners.close) listeners.close(); },
        _triggerClose: () => { if (listeners.close) listeners.close(); },
      };
    }

    // First transport: relay
    const relayTransport = mockTransport();
    const peer = node._createPeer(relayTransport, 'peer-abc', 'test-peer', true, 'relay');
    node._addPeer(peer);

    assert.ok(node._peers.has('peer-abc'), 'peer should exist');
    assert.strictEqual(peer.transports.size, 1, 'should have 1 transport');

    // Second transport: bonjour (same peer, different transport type)
    const bonjourTransport = mockTransport();
    const peer2 = node._createPeer(bonjourTransport, 'peer-abc', 'test-peer', false, 'bonjour');
    // _createPeer returns existing peer when peer already exists
    assert.strictEqual(peer2, peer, 'should return existing peer');
    assert.strictEqual(peer.transports.size, 2, 'should have 2 transports');

    // Active transport should be bonjour (higher priority)
    assert.strictEqual(node._bestTransport(peer), bonjourTransport, 'bonjour should be preferred');

    // Close relay — peer should NOT be removed (bonjour still active)
    relayTransport._triggerClose();
    assert.ok(node._peers.has('peer-abc'), 'peer should still exist after relay close');
    assert.strictEqual(peer.transports.size, 1, 'should have 1 transport remaining');
    assert.strictEqual(events.filter(e => e.type === 'left').length, 0, 'should NOT emit peer-left');

    // Close bonjour — peer SHOULD be removed (all transports closed)
    bonjourTransport._triggerClose();
    assert.ok(!node._peers.has('peer-abc'), 'peer should be removed after all transports close');
    assert.strictEqual(events.filter(e => e.type === 'left').length, 1, 'should emit peer-left');

    await node.stop();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  });

  it('should prefer LAN transport over relay (MMP Section 4.6 priority)', async () => {
    const name = `test-transport-priority-${Date.now()}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    await node.start();

    function mockTransport() {
      const listeners = {};
      return {
        on: (event, fn) => { listeners[event] = fn; },
        send: () => {},
        close: () => { if (listeners.close) listeners.close(); },
      };
    }

    // Connect via relay first
    const relay = mockTransport();
    const peer = node._createPeer(relay, 'peer-xyz', 'priority-test', true, 'relay');
    node._addPeer(peer);
    assert.strictEqual(peer.transport, relay, 'initial transport should be relay');

    // Add bonjour — should become preferred
    const bonjour = mockTransport();
    node._createPeer(bonjour, 'peer-xyz', 'priority-test', false, 'bonjour');
    assert.strictEqual(node._bestTransport(peer), bonjour, 'bonjour should be preferred over relay');

    await node.stop();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  });

  after(() => {
    fs.rmSync(nodeDir(nodeName), { recursive: true, force: true });
  });
});
