'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * - K4: inbox()'s limit counts unread deliveries; an item already acked (read in full by id) comes
 *   back marked but does not take a new delivery's place.
 * - K6: record timestamps are strictly increasing across restarts (the ratchet starts from the newest
 *   of this node's own stored records), and after the clock steps back by more than a minute they
 *   follow the clock again instead of running ahead of it indefinitely.
 * - 0.14.0 part A2 F3: "the newest stored record" was read from the 20 most recently stored, so on a
 *   node that had admitted 20 peer records since its own last one the ratchet started from zero.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');

const mkNode = (name) => new SymNode({ name, silent: true, discovery: new NullDiscovery() });
const uniq = (p) => `${p}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;

describe('inbox limit (K4)', () => {
  it('acked items do not use up the limit', () => {
    const name = uniq('inbox');
    const node = mkNode(name);
    try {
      for (let i = 0; i < 6; i++) node._pushInbox({ cmb: { categories: { focus: { text: `m${i}` } } }, content: `m${i}`, source: 'peer' });
      const ids = node._inbox.map((m) => m.id);
      node.inboxAck(ids[0]); node.inboxAck(ids[1]); node.inboxAck(ids[2]);
      const r = node.inbox({ limit: 2 });
      const unread = r.messages.filter((m) => !m.acked).map((m) => m.id);
      assert.deepStrictEqual(unread, [ids[3], ids[4]], 'two unread deliveries, as asked');
      assert.deepStrictEqual(r.messages.filter((m) => m.acked).map((m) => m.id), [ids[0], ids[1]], 'acked ones come back marked, up to the same limit');
      assert.strictEqual(r.remaining, 1);
    } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  // 0.14.0 review F6: counting only unread items let the reply grow to the whole ring.
  it('the limit still bounds the reply when most of the ring is acked', () => {
    const name = uniq('inbox-bound');
    const node = mkNode(name);
    try {
      for (let i = 0; i < 300; i++) node._pushInbox({ cmb: { categories: { focus: { text: `m${i}` } } }, content: `m${i}`, source: 'peer' });
      for (const m of node._inbox.slice(0, 299)) node.inboxAck(m.id);
      const r = node.inbox({ limit: 1 });
      assert.ok(r.messages.length <= 2, `one unread and at most one acked, not ${r.messages.length}`);
      assert.deepStrictEqual(r.messages.filter((m) => !m.acked).map((m) => m.id), [node._inbox[299].id], 'the unread delivery is not starved by acked ones');
      assert.strictEqual(r.remaining, 0, 'acked items passed over are behind the cursor');
      assert.strictEqual(node.inbox({ limit: 1 }).messages.length, 0, 'and are not handed back next time');
    } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });
});

describe('record timestamps (K6)', () => {
  it('stay strictly increasing across a restart', () => {
    const name = uniq('clock');
    try {
      const a = mkNode(name);
      const realNow = Date.now;
      const future = realNow() + 30 * 1000; // records written 30 s "ahead", as after a small clock step
      Date.now = () => future;
      const first = a.remember({ focus: 'before the restart' });
      Date.now = realNow;
      a._identityLock?.release?.();
      const b = mkNode(name); // a new process on the same store
      const second = b.remember({ focus: 'after the restart' });
      assert.ok(second.cmb.metadata.createdTimestamp > first.cmb.metadata.createdTimestamp);
    } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  it('stay strictly increasing across a restart after 20 or more peer records were stored since', () => {
    const name = uniq('clock-busy');
    const peerName = uniq('clock-peer');
    const realNow = Date.now;
    try {
      const a = mkNode(name);
      const peer = mkNode(peerName);
      const t0 = realNow();
      Date.now = () => t0 + 30 * 1000;   // written 30 s "ahead", as after a small clock step
      const own = a.remember({ focus: 'before the restart' });
      // 25 peer records, minted further ahead still and stored after this node's own.
      for (let i = 0; i < 25; i++) {
        Date.now = () => t0 + 50 * 1000 + i;
        const r = peer.remember({ focus: `peer record ${i}` });
        Date.now = () => t0 + 31 * 1000 + i;
        assert.ok(a._store.receiveFromPeer(peer.nodeId, { cmb: r.cmb, content: r.content, source: peerName }), `peer record ${i} stored`);
      }
      assert.ok(a._store.allEntries().every((e) => e.peerId != null), 'none of the 20 most recent is its own');
      Date.now = realNow;
      a._identityLock?.release?.();
      a._releaseIdentityLock?.();
      const b = mkNode(name); // a new process on the same store, the clock 30 s behind the last record
      const after = b.remember({ focus: 'after the restart' });
      const ts = after.cmb.metadata.createdTimestamp;
      assert.ok(ts > own.cmb.metadata.createdTimestamp, `${ts} after ${own.cmb.metadata.createdTimestamp}`);
      assert.ok(ts < t0 + 50 * 1000, "and it starts from this node's own, not a peer's");
      b._releaseIdentityLock?.();
      peer._releaseIdentityLock?.();
    } finally {
      Date.now = realNow;
      fs.rmSync(nodeDir(name), { recursive: true, force: true });
      fs.rmSync(nodeDir(peerName), { recursive: true, force: true });
    }
  });

  it('follow the clock again after it steps back by more than a minute', () => {
    const name = uniq('clockstep');
    const node = mkNode(name);
    const metrics = [];
    node.on('metric', (m) => metrics.push(m));
    const realNow = Date.now;
    try {
      const t0 = realNow();
      Date.now = () => t0 + 60 * 60 * 1000; // an hour ahead, then the clock is corrected
      node.remember({ focus: 'written while the clock was an hour fast' });
      Date.now = () => t0;
      const after = node.remember({ focus: 'written after the correction' });
      assert.ok(Math.abs(after.cmb.metadata.createdTimestamp - t0) < 1000, 'the timestamp is the clock again');
      assert.ok(metrics.some((m) => m.type === 'clock-stepped-back'));
    } finally { Date.now = realNow; fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });
});
