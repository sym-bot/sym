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

  describe('isValidRoom: the §5.8 room identifier (MMP 2.0 update 1)', () => {
    it('accepts "default" and every [a-z0-9._-] name of 1 to 64 characters, dotted and underscored included', () => {
      for (const g of ['default', 'acme', 'backend-team', 'a1', 'home-office-2', 'acme.prod', 'research.lab', 'backend_team', '-leading', 'trailing-', 'a---b', 'x'.repeat(64)]) {
        assert.ok(isValidRoom(g), `${g} should be valid`);
      }
    });
    it('rejects anything else, and sym (it aliases default on a per-room service type)', () => {
      for (const g of ['Backend_Team', 'has space', 'UPPER', 'café', 'x'.repeat(65), '', null, undefined, 'sym']) {
        assert.strictEqual(isValidRoom(g), false, `${g} should be invalid`);
      }
    });
    it('a legacy per-room service type exists only where it is a valid RFC 6335 service name', () => {
      const { legacyServiceType } = require('../lib/core/room-id');
      assert.strictEqual(legacyServiceType('backend-team'), '_backend-team._tcp');
      for (const g of ['default', 'acme.prod', 'backend_team', 'a--b', '-lead', 'trail-', '1234', 'sixteen-chars-xx']) assert.strictEqual(legacyServiceType(g), null, g);
    });
  });

  it('tenant-suffixed rooms are valid — the grammar xMesh scopes recipe rooms with (ruling 2026-08-26)', () => {
    for (const g of ['a--b', 'x-review--team-02779b950c3d8d7378fd11d6', 'eng-northbank--team-0123456789abcdef01234567']) {
      assert.strictEqual(isValidRoom(g), true, g);
      assert.strictEqual(serviceTypeToRoom(roomServiceType(g)), g, `string round-trip only (not mDNS registration) ${g}`);
    }
  });
});
