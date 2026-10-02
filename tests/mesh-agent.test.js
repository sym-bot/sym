'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

const { describe, it } = require('node:test');
const assert = require('node:assert');

describe('MeshAgent', () => {
  let MeshAgent;

  it('should load MeshAgent', () => {
    MeshAgent = require('../lib/mesh-agent').MeshAgent;
    assert.ok(MeshAgent, 'MeshAgent should be exported');
  });

  it('should require a name', () => {
    assert.throws(
      () => new MeshAgent({
        fetchDomain: async () => null,
        reason: async () => null,
        remix: async () => null,
      }),
      /requires a name/
    );
  });

  it('should require fetchDomain', () => {
    assert.throws(
      () => new MeshAgent({
        name: 'test-agent',
        reason: async () => null,
        remix: async () => null,
      }),
      /requires fetchDomain/
    );
  });

  it('should require reason', () => {
    assert.throws(
      () => new MeshAgent({
        name: 'test-agent',
        fetchDomain: async () => null,
        remix: async () => null,
      }),
      /requires reason/
    );
  });

  it('should require remix', () => {
    assert.throws(
      () => new MeshAgent({
        name: 'test-agent',
        fetchDomain: async () => null,
        reason: async () => null,
      }),
      /requires remix/
    );
  });

  it('should construct with valid options', () => {
    const agent = new MeshAgent({
      name: 'test-agent',
      fetchDomain: async () => null,
      reason: async () => null,
      remix: async () => null,
    });
    // MMP v0.2.1: every agent is a full peer node — created in constructor
    assert.ok(agent.node !== null, 'node created in constructor');
    assert.strictEqual(agent.node.name, 'test-agent');
  });

  it('should store name and options', () => {
    const agent = new MeshAgent({
      name: 'my-agent',
      fetchDomain: async () => null,
      reason: async () => null,
      remix: async () => null,
    });
    assert.strictEqual(agent._name, 'my-agent');
  });

  it('should accept custom pollInterval', () => {
    const agent = new MeshAgent({
      name: 'poll-test',
      pollInterval: 60000,
      fetchDomain: async () => null,
      reason: async () => null,
      remix: async () => null,
    });
    assert.strictEqual(agent._pollInterval, 60000);
  });

  it('should load state as empty object for fresh agent', () => {
    const agent = new MeshAgent({
      name: 'state-test',
      fetchDomain: async () => null,
      reason: async () => null,
      remix: async () => null,
    });
    assert.ok(typeof agent.state === 'object', 'state should be an object');
    assert.strictEqual(agent.state._lastFingerprint, '', 'fingerprint should default to empty string');
  });

  it('should use default shouldRemix that filters self', () => {
    const agent = new MeshAgent({
      name: 'filter-test',
      fetchDomain: async () => null,
      reason: async () => null,
      remix: async () => null,
    });
    // Default shouldRemix rejects entries from self
    assert.strictEqual(agent._shouldRemix({ source: 'filter-test' }), false);
    assert.strictEqual(agent._shouldRemix({ source: 'other-agent' }), true);
  });

  it('should accept custom shouldRemix', () => {
    const agent = new MeshAgent({
      name: 'custom-filter',
      fetchDomain: async () => null,
      reason: async () => null,
      remix: async () => null,
      shouldRemix: (entry) => entry.source === 'special',
    });
    assert.strictEqual(agent._shouldRemix({ source: 'special' }), true);
    assert.strictEqual(agent._shouldRemix({ source: 'other' }), false);
  });

  // §15.8 severance lives on the store entry: the record keeps the parents its author signed, but
  // this node stored it as a root. Remix-of-remix suppression must read the entry, or a severed
  // block is never remixed, though to this node it is an original observation.
  it('remixes a block whose lineage this node severed, as it does any root', async () => {
    const remixed = [];
    const agent = new MeshAgent({
      name: 'sever-aware',
      fetchDomain: async () => null,
      reason: async () => null,
      remix: async (incoming) => { remixed.push(incoming.key); return null; },
    });
    agent._node._hasNewDomainData = true;
    const { createCMB } = require('../lib/core');
    const cmb = createCMB({
      categories: { focus: 'a block whose chain was severed', issue: 'i', intent: 'n', motivation: 'm', commitment: 'c', perspective: 'p', mood: 'neutral' },
      createdBy: 'other-agent', lineage: { parents: ['cmb-' + 'a'.repeat(64)], method: 'SVAF-v2' },
    });
    const severed = { key: cmb.metadata.key, source: 'other-agent', cmb, lineage: { parents: [], ancestors: [], method: null, severed: true } };
    const kept = { ...severed, key: 'kept', lineage: { parents: ['cmb-' + 'a'.repeat(64)], ancestors: [], method: 'SVAF-v2' } };
    await agent._onCMBAccepted(kept);
    await agent._onCMBAccepted(severed);
    assert.deepStrictEqual(remixed, [cmb.metadata.key], 'the kept remix is not re-remixed; the severed one is a root');
  });
});

// 0.14.0 review F8: remember() throws ESIGN when the node cannot sign. The agent says so once and
// stops, instead of an error for every admitted record and a model call it could never use.
describe('MeshAgent when its node cannot sign', () => {
  const { MeshAgent } = require('../lib/mesh-agent');
  it('halts once on ESIGN and stops remixing and observing', async () => {
    let remixCalls = 0;
    const agent = new MeshAgent({
      name: `esign-${Date.now()}`,
      fetchDomain: async () => ({ data: 'd', fingerprint: String(Math.random()) }),
      reason: async () => ({ focus: 'an observation' }),
      remix: async () => { remixCalls++; return { focus: 'a remix' }; },
      shouldRemix: () => true,
    });
    agent.node.canRemix = () => true;
    agent.node._hasNewDomainData = true; // the remix path is gated on it (§15.7)
    agent.node.remember = () => { const e = new Error('CMB signing failed: key unreadable'); e.code = 'ESIGN'; throw e; };
    const errors = [];
    const origError = console.error, origLog = console.log;
    console.error = (...a) => errors.push(a.join(' '));
    console.log = () => {};
    try {
      const entry = () => ({ key: 'k-' + Math.random(), source: 'peer', cmb: { categories: { focus: { text: 'x' } } } });
      await agent._onCMBAccepted(entry());
      await agent._onCMBAccepted(entry());
      await agent._checkDomain();
    } finally { console.error = origError; console.log = origLog; }
    assert.strictEqual(errors.filter((l) => /HALTED: this node cannot sign/.test(l)).length, 1, 'said once');
    assert.strictEqual(remixCalls, 1, 'no model call after the halt');
    assert.strictEqual(agent._signingHalted, true);
  });
});
