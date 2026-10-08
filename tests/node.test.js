'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

const { describe, it, after, afterEach } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { nodeDir } = require('../lib/config');
const { NullDiscovery } = require('../lib/discovery');

// Use unique names to avoid state conflicts
const nodeName = `test-node-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;

describe('SymNode', () => {
  let SymNode;

  // TEARDOWN MUST SURVIVE A FAILING ASSERTION.
  //
  // Every lifecycle test here ended with `await node.stop()` as its last statement, so any
  // assertion that threw skipped it. SymNode.start() installs four intervals (heartbeat,
  // re-encode, stats, retention purge) and stop() is the only thing that clears them — and
  // stop() early-returns on `!this._running`, so nothing else can. One failed assertion
  // therefore left four live timers and the process never exited.
  //
  // That is what the "intermittent hang in node.test.js" was: NOT a separate flake living
  // alongside a failing test, but the SAME EVENT. The failure and the hang are one defect,
  // and the hang is what hid the failure — a suite that hangs reports nothing, so the
  // assertion underneath it went unread. Diagnosed by tracing every setInterval to its
  // creation site and listing which were still live at exit: four, all from start(), all
  // from the node created at the primer test.
  //
  // Registering on start (rather than at construction) is deliberate: an unstarted node holds
  // no timers, and the tests that assert on constructor behaviour must not be forced to stop
  // something that never ran.
  const liveNodes = new Set();

  afterEach(async () => {
    for (const n of liveNodes) {
      try { await n.stop(); } catch { /* teardown is best-effort; never mask the real failure */ }
    }
    liveNodes.clear();
  });

  it('should load SymNode', () => {
    const Base = require('../lib/node').SymNode;
    // One wrapper instead of a registration call at each of the 16 construction sites: a fix
    // that has to be remembered at every call site is one the next test will forget.
    SymNode = class extends Base {
      async start(...a) { liveNodes.add(this); return super.start(...a); }
      async stop(...a) { liveNodes.delete(this); return super.stop(...a); }
    };
    assert.ok(Base, 'SymNode should be exported');
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
    //
    // The cutoff is `Date.now() - maxAgeMs` and entries are kept when `storedAt >= cutoff`, so
    // an entry written in the SAME MILLISECOND as the query survives a 1ms window. The three
    // writes above are seeded immediately before this call, so on a fast machine the last one
    // is not yet stale and `count` is 1 rather than 0 — a race against clock granularity, not
    // a defect in the recency cap. Wait past one whole millisecond so the assertion tests the
    // cap rather than the machine.
    await new Promise((r) => setTimeout(r, 5));
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

    // No domain data yet — the REMIX PATH is refused, and says so (draft spec PR #35: §15.7 gates
    // only the node's integration of a peer record, never remember()).
    const rejected = await node.remix(
      { focus: 'remix attempt', issue: 'none', intent: 'test', motivation: 'test',
        commitment: 'test', perspective: 'test', mood: { text: 'neutral', valence: 0, arousal: 0 } },
      { parents: [{ key: 'cmb-fake-parent', lineage: { ancestors: [] } }] }
    );
    assert.deepStrictEqual(rejected, { refused: 'remix-without-new-domain-data' }, 'a remix without domain data is refused, by name');

    // Produce domain observation — this sets canRemix = true
    node.remember({
      focus: 'domain observation', issue: 'none', intent: 'test', motivation: 'test',
      commitment: 'test', perspective: 'test', mood: { text: 'neutral', valence: 0, arousal: 0 },
    });
    assert.strictEqual(node.canRemix(), true);

    // Now remix should succeed
    const accepted = await node.remix(
      { focus: 'valid remix', issue: 'none', intent: 'test', motivation: 'test',
        commitment: 'test', perspective: 'test', mood: { text: 'neutral', valence: 0, arousal: 0 } },
      { parents: [{ key: 'cmb-fake-parent', lineage: { ancestors: [] } }] }
    );
    assert.ok(accepted, 'remix with domain data should succeed');
    assert.ok(accepted.key, 'remix should have key');

    await node.stop();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  });

  it('remember(fields, parents) is never gated (draft spec PR #35): two cited replies in a row both mint; a duplicate says so', async () => {
    const name = `test-cited-${Date.now()}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    await node.start();
    try {
      const cats = (focus) => ({ focus, issue: 'none', intent: 'reply', motivation: 'm', commitment: 'c', perspective: 'p', mood: { text: 'neutral' } });
      node._hasNewDomainData = false;
      const peer = { key: 'cmb-' + 'a'.repeat(64) };
      const r1 = node.remember(cats('a cited reply'), { parents: [peer] });
      const r2 = node.remember(cats('a second cited reply'), { parents: [peer] });
      assert.ok(r1 && r1.key && !r1.refused, 'the first cited reply mints');
      assert.ok(r2 && r2.key && !r2.refused, 'and so does the second: a reply is not a remix');
      assert.strictEqual(node.canRemix(), true, 'an authored record is new domain data, with or without parents');
      const dup = node.remember(cats('a second cited reply'), { parents: [peer] });
      assert.deepStrictEqual({ key: dup.key, duplicate: dup.duplicate }, { key: r2.key, duplicate: true }, 'a re-assertion of HEAD is told apart from a refusal');
      node.remember(cats('something else'));
      const again = node.remember(cats('a cited reply'), { parents: [peer] });
      assert.deepStrictEqual(again, { key: r1.key, duplicate: true }, 'and so is a record already stored');
    } finally {
      await node.stop();
      fs.rmSync(nodeDir(name), { recursive: true, force: true });
    }
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
        categories: {
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

    const categories = {
      focus: 'observation', issue: 'none', intent: 'test', motivation: 'test',
      commitment: 'test', perspective: 'test', mood: { text: 'neutral', valence: 0, arousal: 0 },
    };

    // Domain observation sets canRemix = true
    node.remember(categories);
    assert.strictEqual(node.canRemix(), true, 'domain observation should enable remix');

    // Remix should succeed and RESET canRemix
    const remix = await node.remix(
      { ...categories, focus: 'remix of peer signal' },
      { parents: [{ key: 'cmb-parent-123', lineage: { ancestors: [] } }] }
    );
    assert.ok(remix && remix.key, 'remix should succeed');
    assert.strictEqual(node.canRemix(), false, 'remix should reset hasNewDomainData');

    // Second remix without new domain data should be rejected
    const rejected = await node.remix(
      { ...categories, focus: 'second remix attempt' },
      { parents: [{ key: 'cmb-parent-456', lineage: { ancestors: [] } }] }
    );
    assert.deepStrictEqual(rejected, { refused: 'remix-without-new-domain-data' }, 'second remix without new domain data should be rejected');

    // New domain observation re-enables remix
    node.remember({ ...categories, focus: 'fresh observation' });
    assert.strictEqual(node.canRemix(), true, 'new observation should re-enable remix');

    await node.stop();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  });

  it('should support multi-transport per peer (MMP Section 4.6): one proven peer, two sessions', async () => {
    const { connectNodes, until } = require('./_core-secure');
    const a = new SymNode({ name: `test-multi-a-${Date.now()}`, silent: true, discovery: new NullDiscovery() });
    const b = new SymNode({ name: `test-multi-b-${Date.now()}`, silent: true, discovery: new NullDiscovery() });
    await a.start(); await b.start();
    try {
      const events = [];
      a.on('peer-joined', (e) => events.push({ type: 'joined', ...e }));
      a.on('peer-left', (e) => events.push({ type: 'left', ...e }));
      const relayPipe = await connectNodes(a, b, { kind: 'relay' });
      const peer = a._peers.get(b.nodeId);
      assert.ok(peer, 'peer should exist');
      assert.strictEqual(peer.transports.size, 1, 'should have 1 session');
      const lanPipe = await connectNodes(a, b, { kind: 'bonjour' });
      await until(() => peer.transports.size === 2);
      assert.strictEqual(a._peers.get(b.nodeId), peer, 'the same peer: a second transport is a secondary path');
      assert.strictEqual(peer.transports.size, 2, 'should have 2 sessions');
      assert.strictEqual(a._bestTransport(peer), peer.transports.get('bonjour'), 'LAN should be preferred');
      // Close the relay path — the peer stays (the LAN session is still live).
      relayPipe.tc.close();
      await until(() => peer.transports.size === 1);
      assert.ok(a._peers.has(b.nodeId), 'peer should still exist after the relay session closes');
      assert.strictEqual(events.filter((e) => e.type === 'left').length, 0, 'should NOT emit peer-left');
      // Close the LAN path — now the peer is gone.
      lanPipe.tc.close();
      await until(() => !a._peers.has(b.nodeId));
      assert.ok(!a._peers.has(b.nodeId), 'peer should be removed after all sessions close');
      assert.strictEqual(events.filter((e) => e.type === 'left').length, 1, 'should emit peer-left');
    } finally {
      await a.stop(); await b.stop();
    }
  });

  it('should prefer LAN transport over relay (MMP Section 4.6 priority)', async () => {
    const { connectNodes } = require('./_core-secure');
    const a = new SymNode({ name: `test-prio-a-${Date.now()}`, silent: true, discovery: new NullDiscovery() });
    const b = new SymNode({ name: `test-prio-b-${Date.now()}`, silent: true, discovery: new NullDiscovery() });
    await a.start(); await b.start();
    try {
      await connectNodes(a, b, { kind: 'relay' });
      const peer = a._peers.get(b.nodeId);
      assert.strictEqual(peer.transport.kind, 'relay', 'initial session is the relay one');
      await connectNodes(a, b, { kind: 'bonjour' });
      assert.strictEqual(a._bestTransport(peer).kind, 'bonjour', 'LAN should be preferred over relay');
    } finally {
      await a.stop(); await b.stop();
    }
  });

  after(() => {
    fs.rmSync(nodeDir(nodeName), { recursive: true, force: true });
  });
});
