'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * Regression guard for the PUBLIC "directed delivery" claim (MMP §4.4.4):
 * a caller that addresses a CMB to a specific peer MUST be able to tell
 * whether it was actually delivered.
 *
 * Background — the defect this guards against (bl-a6e63608c8c, measured
 * 2026-08-09 across three days of live traffic):
 *
 *   remember({ to }) resolves the addressee in this._peers. When the peer is
 *   not connected the fan-out loop has zero targets, the CMB is written to the
 *   local store, ONE log line is emitted ("peer not connected; CMB stored
 *   locally only") — and the entry is returned exactly as if it had been
 *   delivered. Nothing in the return value distinguishes "the addressee has
 *   it" from "nobody has it". Every layer above (sym_send, the MCP surface,
 *   the seat) therefore reported success for sends that reached no one.
 *
 *   Live consequence: five directed CMBs addressed to the dev seat — including
 *   a founder authorization and a founder question — sat undelivered for three
 *   days while every sender believed it had delivered. Two seats independently
 *   built prose workarounds ("RELAY FOR DEV") around a channel that was
 *   reporting success.
 *
 * The fix makes the delivery outcome part of what the caller is handed:
 * `entry.delivery` carries { directed, targets, dispatched, undelivered }.
 * `dispatched` counts frames handed to a transport — NOT frames received; the
 * word `delivered` stays reserved until an ack earns it.
 * It is defined NON-ENUMERABLE on purpose — the store persists entries with
 * JSON.stringify, and a delivery outcome is a fact about one send, not part of
 * the durable record. Persisting it would be its own defect class (a stored
 * record asserting something it cannot know at read time).
 *
 * These tests use NullDiscovery and never open a transport, so an addressed
 * peer is genuinely absent — which is exactly the live condition.
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

// remember(fields, opts) — the CAT7 fields are the FIRST argument and the
// addressee rides in opts. Passing a single object silently produces a
// broadcast with `to` undefined, which is its own instance of the class under
// test here: a call that looks addressed and is not.
function fieldsOf(focusText) {
  return {
    focus: focusText,
    issue: 'directed delivery accountability',
    intent: 'test',
    mood: { text: 'neutral', valence: 0, arousal: 0 },
  };
}

const ABSENT_PEER = 'peer-that-is-not-here-0000000000000000';

describe('directed delivery accountability (bl-a6e63608c8c)', () => {
  it('reports a directed send to an absent peer as UNDELIVERED', async () => {
    await withNode('acct-absent', async (node) => {
      const entry = await node.remember(
        fieldsOf('directed at a peer that is not connected'),
        { to: ABSENT_PEER },
      );

      assert.ok(entry, 'the CMB is still stored locally — that part was never in doubt');
      assert.ok(entry.delivery, 'the caller must be handed a delivery outcome');
      assert.strictEqual(entry.delivery.directed, true);
      assert.strictEqual(entry.delivery.targets, 0, 'the addressee was not connected');
      assert.strictEqual(entry.delivery.dispatched, 0, 'no frame was even handed to a transport');
      assert.strictEqual(
        entry.delivery.undelivered, true,
        'THE WHOLE POINT: zero peers reached must not be indistinguishable from delivered',
      );
    });
  });

  it('does not persist the delivery outcome into the durable record', async () => {
    await withNode('acct-nonpersist', async (node) => {
      const entry = await node.remember(
        fieldsOf('delivery outcome must not enter the store'),
        { to: ABSENT_PEER },
      );

      // Assert the property EXISTS before asserting how it is defined —
      // otherwise this test passes on a build that has no delivery outcome at
      // all, which is the very defect it exists to catch. (It did, once.)
      assert.ok(entry.delivery, 'precondition: the outcome must be present to be non-enumerable');

      // The store persists with JSON.stringify. A delivery outcome is a fact
      // about one send at one moment, not a property of the record — a stored
      // record must never assert something it cannot know when it is read back.
      assert.strictEqual(
        Object.prototype.propertyIsEnumerable.call(entry, 'delivery'), false,
        'delivery must be non-enumerable so it never reaches the persisted record',
      );
      assert.strictEqual(
        JSON.parse(JSON.stringify(entry)).delivery, undefined,
        'the serialized record must carry no delivery claim',
      );
    });
  });

  it('marks a group broadcast as not-directed rather than undelivered', async () => {
    await withNode('acct-broadcast', async (node) => {
      // A broadcast to an empty mesh reached nobody, but it made no addressed
      // promise — receiver-autonomous attention means no one is obliged to be
      // there. Only a DIRECTED send carries a promise that can be broken, and
      // conflating the two would train operators to ignore the signal.
      const entry = await node.remember(fieldsOf('broadcast into an empty mesh'));

      assert.ok(entry.delivery, 'every send reports an outcome');
      assert.strictEqual(entry.delivery.directed, false);
      assert.strictEqual(
        entry.delivery.undelivered, false,
        'a broadcast that reached nobody is not a broken promise',
      );
    });
  });
});
