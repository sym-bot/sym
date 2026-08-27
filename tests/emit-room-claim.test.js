'use strict';

/**
 * emit(): silence is not a claim.
 *
 * connect() defaulted `room` to 'default' and always sent the field, so a caller
 * who named no room made a POSITIVE claim of the public square — the one value a
 * receiver in any named room is required to close on (§5.8). The documented
 * default of a first-class API was therefore refused by every named room, and the
 * caller saw only "closed before handshake" with no mention of rooms: the node
 * logged the reason, the client did not.
 */

require('./_isolate-home');

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { SymNode } = require('../lib/node');
const { connect } = require('../lib/emit');

describe('emit room claims', () => {
  it('makes NO claim when the caller names no room, and is admitted by a named room', async () => {
    const node = new SymNode({ name: 'acme-node', room: 'acme', silent: true });
    await node.start();
    try {
      const e = await connect({ server: `127.0.0.1:${node._port}`, timeoutMs: 4000 });
      assert.ok(e, 'an emitter naming no room must be admitted into a named room');
      if (e.close) e.close();
    } finally {
      await node.stop();
    }
  });

  it('still CLAIMS default when the caller asks for it, and a named room refuses that', async () => {
    const node = new SymNode({ name: 'acme-node2', room: 'acme', silent: true });
    await node.start();
    try {
      await assert.rejects(
        () => connect({ server: `127.0.0.1:${node._port}`, room: 'default', timeoutMs: 4000 }),
        /closed before handshake|handshake/i,
        'an explicit `default` is a claim, and it mismatches a node in `acme`'
      );
    } finally {
      await node.stop();
    }
  });

  it('a matching claim connects', async () => {
    const node = new SymNode({ name: 'acme-node3', room: 'acme', silent: true });
    await node.start();
    try {
      const e = await connect({ server: `127.0.0.1:${node._port}`, room: 'acme', timeoutMs: 4000 });
      assert.ok(e);
      if (e.close) e.close();
    } finally {
      await node.stop();
    }
  });
});
