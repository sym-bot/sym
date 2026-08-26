'use strict';

// Mesh rooms (MMP §5.8) — the room<->serviceType mapping is the contract
// every runtime (CLI, MCP node, sym-swift) must agree on, or peers in the
// "same" room never discover each other. These lock that contract.

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { isValidRoom, roomServiceType, serviceTypeToRoom } = require('../lib/rooms');

describe('mesh rooms', () => {
  describe('roomServiceType', () => {
    it('maps default to the global _sym._tcp', () => {
      assert.strictEqual(roomServiceType('default'), '_sym._tcp');
      assert.strictEqual(roomServiceType(''), '_sym._tcp');
      assert.strictEqual(roomServiceType(undefined), '_sym._tcp');
    });
    it('maps a named room to _<room>._tcp (matches MCP node + sym-swift)', () => {
      assert.strictEqual(roomServiceType('backend-team'), '_backend-team._tcp');
      assert.strictEqual(roomServiceType('acme'), '_acme._tcp');
    });
  });

  describe('serviceTypeToRoom (inverse)', () => {
    it('round-trips', () => {
      for (const g of ['default', 'acme', 'backend-team']) {
        assert.strictEqual(serviceTypeToRoom(roomServiceType(g)), g);
      }
    });
    it('treats _sym._tcp as default', () => {
      assert.strictEqual(serviceTypeToRoom('_sym._tcp'), 'default');
    });
  });

  describe('isValidRoom', () => {
    it('accepts "default" and kebab-case', () => {
      for (const g of ['default', 'acme', 'backend-team', 'a1', 'home-office-2']) {
        assert.ok(isValidRoom(g), `${g} should be valid`);
      }
    });
    it('rejects non-kebab / unsafe names', () => {
      for (const g of ['Backend_Team', 'has space', 'UPPER', '-leading', 'trailing-', 'a---b', 'a--', '--b', '', null, undefined]) {
        assert.strictEqual(isValidRoom(g), false, `${g} should be invalid`);
      }
    });
  });

  it('tenant-suffixed rooms are valid — the grammar xMesh scopes recipe rooms with (ruling 2026-08-26)', () => {
    for (const g of ['a--b', 'x-review--team-02779b950c3d8d7378fd11d6', 'eng-northbank--team-0123456789abcdef01234567']) {
      assert.strictEqual(isValidRoom(g), true, g);
      assert.strictEqual(serviceTypeToRoom(roomServiceType(g)), g, `string round-trip only (not mDNS registration) ${g}`);
    }
  });
});
