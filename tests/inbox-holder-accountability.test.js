'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * Regression guard for the RECEIVER half of directed delivery (bl-a6e63608c8c).
 *
 * A node that nothing pulls from is a TERMINUS, and that state was invisible:
 * the delivery inbox accumulated with no counter, no log, and no way to ask.
 *
 * Measured live 2026-08-09 — sym-daemon-mac: seq=96, cursor=0. Ninety-six
 * messages, never drained once, span 08-06 → 08-09 and still accumulating.
 * Five of them were CMBs addressed directly to the dev seat, two carrying
 * founder words. Every seat node beside it drained normally, so the condition
 * was specific and detectable — nobody could detect it.
 *
 * Worse, the ring silently shredded its own backlog. _inbox.shift() evicted
 * oldest-first without asking whether the message had ever been read, so a
 * node in exactly this state discards DIRECTED CMBs, oldest first, in silence
 * once it passes _inboxMax. Eviction is free for a drained message (the
 * session already has it) and is data loss for an undrained one (nobody has
 * ever read it, and nothing will hand it over again). Those two cases were
 * indistinguishable in the code.
 *
 * These tests drive the ring directly through the real push path rather than
 * reaching into internals, so they bind to the behaviour a peer would produce.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');

async function withNode(baseName, fn, opts = {}) {
  const name = `${baseName}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), ...opts });
  await node.start();
  try {
    return await fn(node);
  } finally {
    await node.stop();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  }
}

// Shaped like what frame-handler emits as 'cmb-accepted' on the CLI-host path.
function arrival(focusText, { directed = false, from = 'peer-x' } = {}) {
  return {
    source: from,
    content: focusText,
    directed,
    remixed: false,
    cmb: { fields: { focus: { text: focusText } } },
  };
}

describe('inbox holder accountability (bl-a6e63608c8c, receiver half)', () => {
  it('reports a node that has NEVER been drained, and counts directed mail separately', async () => {
    await withNode('holder-never', async (node) => {
      node.emit('cmb-accepted', arrival('a broadcast nobody pulled'));
      node.emit('cmb-accepted', arrival('addressed to this node', { directed: true }));
      node.emit('cmb-accepted', arrival('also addressed here', { directed: true }));

      const s = node.inboxStatus();
      assert.strictEqual(s.seq, 3);
      assert.strictEqual(s.cursor, 0);
      assert.strictEqual(s.undrained, 3);
      assert.strictEqual(
        s.undrainedDirected, 2,
        'directed mail is the number that matters — somebody is entitled to believe it arrived',
      );
      assert.strictEqual(
        s.neverDrained, true,
        'never-drained is not "behind", it is UNATTENDED — the condition that hid five CMBs for three days',
      );
      assert.ok(s.oldestUndrainedAt, 'the age of the backlog must be answerable');
    });
  });

  it('stops reporting neverDrained once something actually pulls', async () => {
    await withNode('holder-drained', async (node) => {
      node.emit('cmb-accepted', arrival('first', { directed: true }));
      node.emit('cmb-accepted', arrival('second'));

      const pulled = node.inbox();
      assert.strictEqual(pulled.drained, 2);

      const s = node.inboxStatus();
      assert.strictEqual(s.neverDrained, false);
      assert.strictEqual(s.undrained, 0);
      assert.strictEqual(s.undrainedDirected, 0);
    });
  });

  it('NEVER discards an undrained message silently when the ring overflows', async () => {
    // A tiny ring makes the overflow reachable in a test; the semantics under
    // test are the same ones that apply at the shipped _inboxMax.
    await withNode('holder-overflow', async (node) => {
      const dropped = [];
      node.on('metric', (m) => { if (m.type === 'inbox-overflow-dropped') dropped.push(m); });

      // Fill past the ring with nothing draining — the live sym-daemon-mac shape.
      for (let i = 0; i < 5; i++) {
        node.emit('cmb-accepted', arrival(`undrained ${i}`, { directed: i < 2 }));
      }

      assert.ok(dropped.length >= 1, 'discarding unread mail must not be silent');
      assert.strictEqual(
        dropped[0].directed, true,
        'the first casualties are the oldest, which here are the DIRECTED ones',
      );
      assert.strictEqual(node.inboxStatus().dropped, dropped.length,
        'the count must be answerable after the fact, not only observable live');
    }, { inboxMax: 3 });
  });

  it('discards DRAINED messages without crying wolf', async () => {
    // Recycling a message the session already has is not loss. If this fired
    // too, operators would learn to ignore the signal that means real loss —
    // the same inversion that makes an over-eager quarantine worse than none.
    await withNode('holder-recycle', async (node) => {
      const dropped = [];
      node.on('metric', (m) => { if (m.type === 'inbox-overflow-dropped') dropped.push(m); });

      node.emit('cmb-accepted', arrival('read me 1'));
      node.emit('cmb-accepted', arrival('read me 2'));
      node.emit('cmb-accepted', arrival('read me 3'));
      assert.strictEqual(node.inbox().drained, 3, 'precondition: all three are drained');

      node.emit('cmb-accepted', arrival('the one that pushes the ring over'));

      assert.strictEqual(dropped.length, 0, 'evicting an already-read message is free, not loss');
      assert.strictEqual(node.inboxStatus().dropped, 0);
    }, { inboxMax: 3 });
  });
});
