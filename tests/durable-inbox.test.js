'use strict';

/**
 * Durable delivery inbox (founder ruling 2026-08-04): communication is
 * addressed to the NODE, and a new session RELINKS to it — including what
 * was delivered while no session was attached. Before this, the inbox was
 * process memory only: a restart wiped the delivery feed while every sender
 * believed it had delivered (four gate requests vanished into a restarted
 * peer that showed live on bonjour throughout).
 *
 * The three properties, each of which failed silently before:
 *   1. survives  — a new session (same node) drains what arrived earlier
 *   2. no replay — the CURSOR persists with the ring, so a third session
 *                  does not re-deliver what the second already drained
 *   3. fresh     — a corrupt inbox file starts empty, never throws
 */

require('./_isolate-home');
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { SymNode } = require('../lib/node');
const { nodeDir } = require('../lib/config');

const NAME = 'durable-inbox-test';

function mk() {
  return new SymNode({ name: NAME, autoStart: false, silent: true });
}

function push(node, text, key) {
  node._pushInbox({
    source: 'peer',
    content: text,
    cmb: { fields: { focus: { text } }, metadata: { key } },
  });
}

/** The persist is throttled (1/s trailing) — flush by waiting past it. */
function flushed() {
  return new Promise((resolve) => setTimeout(resolve, 1300));
}

test('a restarted session drains what was delivered to the node before it', async () => {
  const a = mk();
  push(a, 'gate request 1', 'cmb-aaaa');
  push(a, 'gate request 2', 'cmb-bbbb');
  await flushed();

  // "Restart": a NEW instance holding the same node identity.
  const b = mk();
  const got = b.inbox();
  assert.strictEqual(got.drained, 2,
    'the delivery feed must survive the process — this is the vanished-gate-requests bug');
  assert.deepStrictEqual(got.messages.map((m) => m.content),
    ['gate request 1', 'gate request 2'], 'order preserved, oldest first');
});

test('the cursor persists with the ring — a later session does not replay a drained feed', async () => {
  // The previous test drained both messages as session b; its cursor write
  // is throttled, so wait for it, then a third session must see NOTHING.
  await flushed();
  const c = mk();
  assert.strictEqual(c.inbox().drained, 0,
    'replaying drained messages would double-deliver every gate request after every restart');
});

test('a corrupt inbox file starts fresh instead of throwing', async () => {
  fs.writeFileSync(path.join(nodeDir(NAME), 'inbox.json'), '{not json');
  const d = mk(); // must not throw
  assert.strictEqual(d.inbox().drained, 0, 'corrupt file → empty feed, old behavior');
  // …and the node still works forward from there.
  push(d, 'after corruption', 'cmb-cccc');
  await flushed();
  const e = mk();
  assert.strictEqual(e.inbox().drained, 1, 'persistence resumes after a fresh start');
});
