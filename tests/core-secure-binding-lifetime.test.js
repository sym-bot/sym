'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * Design D3, binding lifetime (0.13.17 re-review): new keypairs are free, so a key registry that only
 * grows can be filled by identity churn — 0.13.17's cap of 16,384 never-evicted bindings was a
 * lockout anyone on the LAN could fill in seconds. A first-contact `proven` binding that verified
 * nothing since (no record, grant, attestation or later session) and was not seen for 30 days
 * expires; one that ever verified something, or is pinned, grant-vouched, anchored or a legacy
 * claim, never does. The facts are persisted with the binding.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { RosterKeyRegistry, BINDING_TTL_MS, KEYS_FILE } = require('../lib/roster-keys');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { identity, admitAs, deliver, signedRecord } = require('./_core-secure');

const DAY = 24 * 60 * 60 * 1000;
const key = (i) => crypto.createHash('sha256').update(`k${i}`).digest().toString('base64url').slice(0, 43);

describe('binding lifetime (D3)', () => {
  it('a flood of 20,000 one-shot identities ages out; an honest long-lived peer\'s binding survives', () => {
    let t = 1_000_000;
    const r = new RosterKeyRegistry({ now: () => t });
    const honest = 'honest-peer';
    r.bind(honest, key('honest'), 'proven');
    t += DAY;
    r.bind(honest, key('honest'), 'proven'); r.noteVerified(honest); // a later session re-proved it
    for (let i = 0; i < 20_000; i++) assert.strictEqual(r.bind(`churn-${i}`, key(i), 'proven').created, true);
    assert.strictEqual(r.size(), 20_001);
    t += BINDING_TTL_MS - DAY;
    assert.strictEqual(r.expire(), 0, 'nothing expires before 30 days unseen');
    t += 2 * DAY;
    assert.strictEqual(r.expire(), 20_000, 'every one-shot identity expired');
    assert.strictEqual(r.size(), 1);
    assert.strictEqual(r.get(honest), key('honest'), 'the honest peer is still bound');
    t += 365 * DAY;
    assert.strictEqual(r.expire(), 0, 'and never expires: it verified something');
    assert.strictEqual(r.expiredCount(), 20_000);
  });

  it('pinned, grant-vouched, grant, legacy-claim and live bindings never expire; one seen recently does not', () => {
    let t = 0;
    const live = new Set(['live']);
    const r = new RosterKeyRegistry({ now: () => t, isLive: (id) => live.has(id) });
    r.bind('pinned', key(1), 'pinned');
    r.bind('grant', key(2), 'grant');
    r.bind('claim', key(3), 'legacy-claim');
    r.bind('vouched', key(4), 'proven'); r.bind('vouched', key(4), 'grant');
    r.bind('live', key(5), 'proven');
    r.bind('seen', key(6), 'proven');
    r.bind('record', key(7), 'proven');
    r.bind('gone', key(8), 'proven');
    t += 20 * DAY; r.noteSeen('seen');
    t += 11 * DAY;
    r.noteVerified('record');
    assert.strictEqual(r.expire(), 1);
    assert.deepStrictEqual(r.entries().map((e) => e.nodeId).sort(), ['claim', 'grant', 'live', 'pinned', 'record', 'seen', 'vouched']);
    assert.strictEqual(r.expected('gone'), undefined, 'the expired id is unbound: a later session binds it afresh');
    assert.strictEqual(r.bind('gone', key(9), 'proven').created, true);
  });

  it('the facts persist: after a restart 31 days on, the flood expires at load and the file is compacted', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-binding-life-'));
    try {
      let t = 5_000_000;
      const r = new RosterKeyRegistry({ dir, now: () => t });
      r.bind('honest', key('h'), 'proven');
      for (let i = 0; i < 2000; i++) r.bind(`churn-${i}`, key(i), 'proven');
      // A record verified under the honest binding (frame-handler calls this on §8.8.5 success).
      t += 1000; r.noteVerified('honest');
      t += 31 * DAY;
      const again = new RosterKeyRegistry({ dir, now: () => t });
      assert.strictEqual(again.size(), 1, 'the flood expired at load');
      assert.strictEqual(again.get('honest'), key('h'));
      assert.ok(again.entries()[0].verified, 'the verified fact survived the restart');
      const lines = fs.readFileSync(path.join(dir, KEYS_FILE), 'utf8').trim().split('\n');
      assert.strictEqual(lines.length, 2, 'compacted: the marker and the one binding');
      t += 365 * DAY;
      assert.strictEqual(new RosterKeyRegistry({ dir, now: () => t }).size(), 1, 'and it never expires');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('at the node: a verified record, or a second session, makes a binding permanent', async () => {
    const node = new SymNode({ name: `life-${Date.now()}`, silent: true, discovery: new NullDiscovery(), room: 'life' });
    try {
      const author = identity('author');
      const session = admitAs(node, author);
      const entry = () => node._roster.entries().find((e) => e.nodeId === author.nodeId);
      assert.strictEqual(entry().verified, null, 'first contact: proven, nothing verified yet');
      await deliver(node, session, { type: 'cmb', cmb: signedRecord(author, { room: 'life', categories: { focus: 'a record that verifies' } }) });
      assert.ok(entry().verified, 'a record verified under it');
    } finally { await node.stop(); }
  });
});
