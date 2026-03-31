'use strict';

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
    assert.ok(agent.node, 'should expose underlying SymNode');
    assert.strictEqual(agent.node.name, 'test-agent');
  });

  it('should create node with cognitiveProfile default', () => {
    const agent = new MeshAgent({
      name: 'my-agent',
      fetchDomain: async () => null,
      reason: async () => null,
      remix: async () => null,
    });
    // Default cognitiveProfile is "<name> mesh agent"
    assert.ok(agent.node, 'node should exist');
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
});
