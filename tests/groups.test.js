'use strict';

// Mesh groups (MMP §5.8) — the group<->serviceType mapping is the contract
// every runtime (CLI, MCP node, sym-swift) must agree on, or peers in the
// "same" group never discover each other. These lock that contract.

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { isValidGroup, groupServiceType, serviceTypeToGroup } = require('../lib/groups');

describe('mesh groups', () => {
  describe('groupServiceType', () => {
    it('maps default to the global _sym._tcp', () => {
      assert.strictEqual(groupServiceType('default'), '_sym._tcp');
      assert.strictEqual(groupServiceType(''), '_sym._tcp');
      assert.strictEqual(groupServiceType(undefined), '_sym._tcp');
    });
    it('maps a named group to _<group>._tcp (matches MCP node + sym-swift)', () => {
      assert.strictEqual(groupServiceType('backend-team'), '_backend-team._tcp');
      assert.strictEqual(groupServiceType('acme'), '_acme._tcp');
    });
  });

  describe('serviceTypeToGroup (inverse)', () => {
    it('round-trips', () => {
      for (const g of ['default', 'acme', 'backend-team']) {
        assert.strictEqual(serviceTypeToGroup(groupServiceType(g)), g);
      }
    });
    it('treats _sym._tcp as default', () => {
      assert.strictEqual(serviceTypeToGroup('_sym._tcp'), 'default');
    });
  });

  describe('isValidGroup', () => {
    it('accepts "default" and kebab-case', () => {
      for (const g of ['default', 'acme', 'backend-team', 'a1', 'home-office-2']) {
        assert.ok(isValidGroup(g), `${g} should be valid`);
      }
    });
    it('rejects non-kebab / unsafe names', () => {
      for (const g of ['Backend_Team', 'has space', 'UPPER', '-leading', 'trailing-', 'a--b', '', null, undefined]) {
        assert.strictEqual(isValidGroup(g), false, `${g} should be invalid`);
      }
    });
  });
});
