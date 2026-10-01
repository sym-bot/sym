'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * - K4: inbox()'s limit counts unread deliveries; an item already acked (read in full by id) comes
 *   back marked but does not take a new delivery's place.
 * - K6: record timestamps are strictly increasing across restarts (the ratchet starts from the newest
 *   stored record), and after the clock steps back by more than a minute they follow the clock again
 *   instead of running ahead of it indefinitely.
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
      assert.ok(r.messages.slice(0, 3).every((m) => m.acked), 'the acked ones come back marked');
      assert.strictEqual(r.remaining, 1);
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
