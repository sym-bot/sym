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
 *
 * Admitted is not heard (0.14.0 review C-F2): the emitter then minted its records
 * with no room, a record with no room is in 'default' (B-R10), and the node that
 * had admitted it refused every block. It now authors for the room it was
 * admitted into.
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

  it('and the node that admitted it hears what it sends', async () => {
    const node = new SymNode({ name: 'acme-node4', room: 'acme', silent: true });
    await node.start();
    const refused = [];
    node.on('metric', (m) => { if (m.type === 'cmb-audience-rejected') refused.push(m); });
    try {
      const accepted = new Promise((resolve) => node.once('cmb-accepted', resolve));
      const e = await connect({ server: `127.0.0.1:${node._port}`, timeoutMs: 4000 });
      const { cmb } = e.emit({ focus: 'a block from an emitter that named no room' });
      assert.strictEqual(cmb.metadata.room, 'acme', 'it authors for the room it was admitted into');
      const entry = await Promise.race([accepted, new Promise((_, reject) => setTimeout(() => reject(new Error(`not heard; refused: ${JSON.stringify(refused)}`)), 8000))]);
      assert.strictEqual(entry.cmb.metadata.key, cmb.metadata.key);
      assert.strictEqual(refused.length, 0);
      await e.close();
    } finally {
      await node.stop();
    }
  });

  it('a record that names no room is still refused outside "default", even from its own author', () => {
    // As a 0.13.x emitter mints it. The emitter fix is on the minting side: a receiver cannot tell a
    // room-less record its author just sent from one replayed out of another room (B-R10).
    const crypto = require('crypto');
    const { createCMB, signCMB } = require('../lib/core');
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', { publicKeyEncoding: { type: 'spki', format: 'der' }, privateKeyEncoding: { type: 'pkcs8', format: 'der' } });
    const node = new SymNode({ name: 'acme-node5', room: 'acme', silent: true });
    node._pinPeerKey('emitter-0133', publicKey.slice(-32).toString('base64url'));
    const cmb = createCMB({ categories: { focus: 'room-less, from an older emitter' }, createdBy: 'emitter' });
    cmb.metadata.room = null;
    signCMB(cmb, privateKey.slice(-32).toString('base64url'));
    const metrics = [];
    node.on('metric', (m) => metrics.push(m));
    assert.strictEqual(node._frameHandler._rejectOnBadSignature('emitter-0133', 'emitter', { cmb }), true);
    assert.ok(metrics.some((m) => m.type === 'cmb-audience-rejected' && m.reason === 'wrong-audience'));
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
