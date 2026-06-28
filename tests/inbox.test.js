'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * Delivery inbox (pull-based receive) — the SDK-level counterpart to remember()
 * (send). The node buffers every delivered CMB (each 'cmb-accepted') so any
 * consumer can pull received CMBs via node.inbox() without subscribing to the
 * event. FIFO drain with a cursor: no message is skipped past `limit`, `peek`
 * is non-destructive.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');

async function withNode(baseName, fn) {
  const name = `${baseName}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
  await node.start();
  try {
    return await fn(node);
  } finally {
    await node.stop();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  }
}

// A delivery lands in the inbox via the node's own 'cmb-accepted' emit.
const deliver = (node, focus, extra = {}) =>
  node.emit('cmb-accepted', { source: 'peerA', content: `focus: ${focus}`, cmb: { key: `cmb-${focus}`, fields: { focus: { text: focus } } }, ...extra });

describe('node.inbox() — pull-based receive', () => {
  it('drains delivered CMBs FIFO and advances the cursor', async () => {
    await withNode('inbox-drain', async (node) => {
      deliver(node, 'one');
      deliver(node, 'two');
      const r1 = node.inbox();
      assert.strictEqual(r1.messages.length, 2, 'both deliveries drain');
      assert.deepStrictEqual(r1.messages.map((m) => m.fields.focus.text), ['one', 'two'], 'FIFO order');
      const r2 = node.inbox();
      assert.strictEqual(r2.messages.length, 0, 'second drain is empty — cursor advanced');
    });
  });

  it('peek is non-destructive', async () => {
    await withNode('inbox-peek', async (node) => {
      deliver(node, 'a');
      assert.strictEqual(node.inbox({ peek: true }).messages.length, 1, 'peek returns the message');
      assert.strictEqual(node.inbox({ peek: true }).messages.length, 1, 'peek again still returns it');
      assert.strictEqual(node.inbox().messages.length, 1, 'drain returns it');
      assert.strictEqual(node.inbox().messages.length, 0, 'now drained');
    });
  });

  it('limit pages without skipping (no loss past the page)', async () => {
    await withNode('inbox-limit', async (node) => {
      deliver(node, 'x1'); deliver(node, 'x2'); deliver(node, 'x3');
      const r1 = node.inbox({ limit: 2 });
      assert.strictEqual(r1.messages.length, 2, 'first page is 2');
      assert.strictEqual(r1.remaining, 1, 'reports 1 remaining');
      const r2 = node.inbox({ limit: 2 });
      assert.strictEqual(r2.messages.length, 1, 'second page is the remaining 1 — not skipped');
      assert.strictEqual(r2.messages[0].fields.focus.text, 'x3');
    });
  });

  it('inboxGet fetches one message by id', async () => {
    await withNode('inbox-get', async (node) => {
      deliver(node, 'findme');
      const { messages } = node.inbox({ peek: true });
      const got = node.inboxGet(messages[0].id);
      assert.ok(got && got.fields.focus.text === 'findme', 'inboxGet returns the buffered message');
      assert.strictEqual(node.inboxGet('in9999'), null, 'unknown id → null');
    });
  });

  it('preserves the opaque payload on the pulled message', async () => {
    // Regression: the payload sits at cmb.payload (sibling of cmb.fields), and
    // _pushInbox used to copy only fields — so structured agent-to-agent data
    // silently vanished on the pull (sym_receive/sym_fetch) path while surviving
    // the channel-push path. It must reach the inbox message intact.
    await withNode('inbox-payload', async (node) => {
      const payload = { request_id: 'r1', prompt: 'beyond CAT7', nested: { n: 42 } };
      node.emit('cmb-accepted', {
        source: 'peerA',
        content: 'focus: with-payload',
        cmb: { key: 'cmb-pl', fields: { focus: { text: 'with-payload' } }, payload },
      });
      const { messages } = node.inbox();
      assert.strictEqual(messages.length, 1);
      assert.deepStrictEqual(messages[0].payload, payload, 'payload survives the inbox pull path');

      node.emit('cmb-accepted', {
        source: 'peerA',
        content: 'focus: no-payload',
        cmb: { key: 'cmb-np', fields: { focus: { text: 'no-payload' } } },
      });
      assert.strictEqual(node.inbox().messages[0].payload, null, 'no payload → null, not undefined');
    });
  });
});
