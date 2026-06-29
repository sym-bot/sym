'use strict';

/**
 * Roster key registry — authenticated nodeId→key bindings with source precedence
 * (anchor > handshake > grant-vouched). The relayer never vouches: a weaker-or-equal
 * source can never repoint a stronger binding, so gossip cannot poison a key learnt
 * from a direct handshake or the pinned anchor.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { RosterKeyRegistry } = require('../lib/roster-keys');

describe('RosterKeyRegistry — source precedence', () => {
  it('pins the anchor at construction and reads it back', () => {
    const r = new RosterKeyRegistry({ anchor: { nodeId: 'A', publicKey: 'KA' } });
    assert.strictEqual(r.get('A'), 'KA');
    assert.strictEqual(r.source('A'), 'anchor');
  });

  it('a stronger source overrides a weaker binding; weaker cannot override stronger', () => {
    const r = new RosterKeyRegistry();
    assert.strictEqual(r.pin('N', 'K-grant', 'grant').pinned, true);
    // handshake (stronger) corrects a grant-vouched key
    assert.strictEqual(r.pin('N', 'K-handshake', 'handshake').pinned, true);
    assert.strictEqual(r.get('N'), 'K-handshake');
    // a later grant gossip cannot repoint the handshake binding
    const res = r.pin('N', 'K-evil', 'grant');
    assert.strictEqual(res.pinned, false);
    assert.strictEqual(res.reason, 'conflict');
    assert.strictEqual(r.get('N'), 'K-handshake');
    assert.strictEqual(r.conflicts().length, 1);
  });

  it('an equal-source key conflict is refused (first binding holds)', () => {
    const r = new RosterKeyRegistry();
    r.pin('N', 'K1', 'handshake');
    assert.strictEqual(r.pin('N', 'K2', 'handshake').reason, 'conflict');
    assert.strictEqual(r.get('N'), 'K1');
  });

  it('re-affirming the same key is idempotent and can upgrade the recorded source', () => {
    const r = new RosterKeyRegistry();
    r.pin('N', 'K', 'grant');
    assert.strictEqual(r.pin('N', 'K', 'handshake').pinned, true);
    assert.strictEqual(r.source('N'), 'handshake', 'same key, stronger source upgrades');
  });

  it('the anchor binding cannot be overridden by handshake or grant', () => {
    const r = new RosterKeyRegistry({ anchor: { nodeId: 'A', publicKey: 'KA' } });
    assert.strictEqual(r.pin('A', 'K-evil', 'handshake').reason, 'conflict');
    assert.strictEqual(r.pin('A', 'K-evil', 'grant').reason, 'conflict');
    assert.strictEqual(r.get('A'), 'KA');
  });

  it('is Map-compatible (get/set drop-in)', () => {
    const r = new RosterKeyRegistry();
    r.set('N', 'K');
    assert.strictEqual(r.get('N'), 'K');
    assert.strictEqual(r.has('N'), true);
    assert.strictEqual(r.size(), 1);
  });

  it('persists bindings append-only and reloads across a restart', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rk-'));
    try {
      const r1 = new RosterKeyRegistry({ anchor: { nodeId: 'A', publicKey: 'KA' }, dir });
      r1.pin('N', 'KN', 'handshake');
      const r2 = new RosterKeyRegistry({ anchor: { nodeId: 'A', publicKey: 'KA' }, dir });
      assert.strictEqual(r2.get('N'), 'KN');
      assert.strictEqual(r2.source('N'), 'handshake', 'reloaded at full strength');
      assert.strictEqual(r2.get('A'), 'KA');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
});
