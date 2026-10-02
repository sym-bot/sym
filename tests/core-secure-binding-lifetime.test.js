'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * Design D3, binding lifetime (0.13.17 re-review), as the security review changed it: new keypairs
 * are free, so a key registry that only grows can be filled by identity churn. A confirmed session
 * runs with a SESSION-SCOPED binding; the durable registry takes a binding only when it is EARNED —
 * an admitted verified record, a pin, or a grant in effect (a view) — and a re-handshake earns
 * nothing. A `proven` binding that verified nothing (one made by a path that binds without earning)
 * expires after 30 days unseen; nothing is ever evicted before it expires. The facts are persisted.
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

  it('pinned, grant-vouched (a view), grant, legacy-claim and live bindings never expire; one seen recently does not', () => {
    let t = 0;
    const live = new Set(['live']);
    const view = new Map([['grant', key(2)], ['vouched', key(4)]]); // the grants in effect now
    const r = new RosterKeyRegistry({ now: () => t, isLive: (id) => live.has(id), grantView: (id) => view.get(id) });
    r.bind('pinned', key(1), 'pinned');
    assert.strictEqual(r.bind('grant', key(2), 'grant').bound, true, 'a grant in effect binds as a view');
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
    assert.deepStrictEqual(r.entries().map((e) => e.nodeId).sort(), ['claim', 'live', 'pinned', 'record', 'seen', 'vouched'], 'a grant binding is never stored');
    assert.strictEqual(r.get('grant'), key(2), 'it verifies while the grant is in effect');
    assert.strictEqual(r.source('grant'), 'grant');
    view.delete('grant');
    assert.strictEqual(r.get('grant'), undefined, 'and the binding ends with the grant (security review C)');
    assert.strictEqual(r.expected('gone'), undefined, 'the expired id is unbound: a later session binds it afresh');
    assert.strictEqual(r.bind('gone', key(9), 'proven').created, true);
    // The vouch ends: the proven binding it kept alive is expirable again.
    view.delete('vouched');
    t += 31 * DAY;
    r.expire();
    assert.strictEqual(r.get('vouched'), undefined, 'no grant in effect keeps it any more');
  });

  it('a full registry evicts nothing before it expires: a newcomer is refused a durable binding, and re-handshakes earn nothing', () => {
    let t = 0;
    const r = new RosterKeyRegistry({ now: () => t, maxBindings: 4 });
    const H = 'honest-once-seen';
    r.bind(H, key('h'), 'proven');
    for (let i = 0; i < 3; i++) r.bind(`fill-${i}`, key(i), 'proven');
    // p8-evict: fresh identities used to evict the honest binding and let a squatter take its id.
    for (let i = 0; i < 100; i++) assert.strictEqual(r.bind(`churn-${i}`, key(100 + i), 'proven').reason, 'full');
    assert.strictEqual(r.get(H), key('h'), 'the honest binding is still there');
    assert.strictEqual(r.bind(H, key('squatter'), 'proven').reason, 'conflict', 'a squatter is a conflict, not a newcomer');
    assert.strictEqual(r.evictedCount(), 0);
    assert.strictEqual(r.refusedFullCount(), 100);
    // Expiry is what frees room: 30 days unseen.
    t += 31 * DAY;
    assert.ok(r.expire() >= 1);
    assert.strictEqual(r.bind('newcomer', key('n'), 'proven').created, true);
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

  it('at the node: only an ADMITTED verified record earns a durable binding; one refused for its room, or a second session, earns nothing', async () => {
    const node = new SymNode({ name: `life-${Date.now()}`, silent: true, discovery: new NullDiscovery(), room: 'life' });
    try {
      const author = identity('author');
      const session = admitAs(node, author);
      const entry = () => node._roster.entries().find((e) => e.nodeId === author.nodeId);
      assert.strictEqual(entry(), undefined, 'first contact: a session-scoped binding, nothing durable');
      assert.strictEqual(node._identityKey(author.nodeId), author.publicKey, 'the session still verifies under its proven key');
      // binding-squat (1): a signed record refused for its room earns nothing.
      await deliver(node, session, { type: 'cmb', cmb: signedRecord(author, { room: 'some-other-room', categories: { focus: 'refused for its room' } }) });
      assert.strictEqual(entry(), undefined, 'a record refused for its room protects no history');
      // An admitted one earns it.
      node._svafEvaluator.evaluate = async () => ({ decision: 'aligned', total_drift: 0.1, category_drifts: { focus: 0.1 }, gate_values: { g: 1 } });
      await deliver(node, session, { type: 'cmb', cmb: signedRecord(author, { room: 'life', categories: { focus: 'a record that is admitted' } }) });
      const { until } = require('./_core-secure');
      await until(() => entry() && entry().verified, 3000);
      assert.strictEqual(entry().source, 'proven');
      assert.ok(entry().verified, 'an admitted record verified under it');
    } finally { await node.stop(); }
  });

  it('at the node: a second key for a nodeId with a live session-scoped binding is a 1009 conflict, even with the registry full', async () => {
    const node = new SymNode({ name: `life-full-${Date.now()}`, silent: true, discovery: new NullDiscovery(), room: 'life', maxKeyBindings: 1 });
    try {
      await node.start();
      node._roster.bind(identity('filler').nodeId, identity('filler').publicKey, 'pinned');
      const { memoryPipe, until } = require('./_core-secure');
      const { PeerSession } = require('../lib/session');
      const sessionAs = async (id) => {
        const [tc, ts] = memoryPipe();
        node.connectTransport(ts, { role: 'server' });
        const s = new PeerSession({ role: 'client', transport: tc, local: id, room: 'life', extensions: ['cmb-encrypted-v2'], implementation: { name: 'x', version: '1' }, expectNodeId: node.nodeId });
        tc.on('message', (f) => s.receiveWire(f));
        s.start();
        await until(() => s.closed || (s.confirmed && node._peers.has(id.nodeId)), 3000);
        return s;
      };
      const honest = identity('honest');
      const h = await sessionAs(honest);
      assert.ok(node._peers.has(honest.nodeId), 'the honest newcomer is admitted with a session-scoped binding');
      const squat = { ...identity('squatter'), nodeId: honest.nodeId };
      const sq = await sessionAs(squat);
      await until(() => sq.closed, 3000);
      assert.strictEqual(sq.closedReason, 'identity-conflict', 'the squatter is refused with 1009');
      assert.strictEqual(node._peers.get(honest.nodeId).identityKey, honest.publicKey);
      assert.ok(node._roster.conflicts().some((c) => c.nodeId === honest.nodeId && c.hadSource === 'session'), 'recorded');
      h.close('done');
    } finally { await node.stop(); }
  });
});
