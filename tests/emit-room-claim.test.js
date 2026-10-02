'use strict';

/**
 * emit(): the room is explicit (Core Secure, sym 0.14; MMP §5.8: "absence is invalid in Core
 * Secure"). The room is inside the §5.2 transcript both sides sign, so an emitter that names none is
 * in the literal room 'default', and a node in another room refuses it at the handshake (room
 * mismatch) — before 0.14 an emitter could make no claim and be admitted into a named room. A
 * matching claim connects, and the node hears what the emitter sends: its records name the room the
 * handshake proved.
 */

require('./_isolate-home');

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { SymNode } = require('../lib/node');
const { BonjourDiscovery } = require('../lib/discovery');
const { connect } = require('../lib/emit');
const { identity, signedRecord, admitAs } = require('./_core-secure');

const lanNode = (name, room) => new SymNode({ name, room, silent: true, discovery: new BonjourDiscovery({ mdns: false }) });

describe('emit room claims (Core Secure)', () => {
  it('an emitter that names no room is in "default", and a named room refuses it at the handshake', async () => {
    const node = lanNode('acme-node', 'acme');
    await node.start();
    try {
      await assert.rejects(
        () => connect({ server: `127.0.0.1:${node._port}`, receiver: { nodeId: node.nodeId, key: node.publicKey }, timeoutMs: 4000 }),
        /did not complete the Core Secure handshake/i,
      );
      assert.ok((node._sessionStats.failedByReason['room-mismatch'] || 0) >= 1, 'refused as a room mismatch');
    } finally {
      await node.stop();
    }
  });

  it('an explicit claim of the node\'s room connects, and the node hears what it sends', async () => {
    const node = lanNode('acme-node4', 'acme');
    await node.start();
    const refused = [];
    node.on('metric', (m) => { if (m.type === 'cmb-audience-rejected' || m.type === 'cmb-signature-rejected') refused.push(m); });
    try {
      const accepted = new Promise((resolve) => node.once('verified-record', resolve));
      const e = await connect({ server: `127.0.0.1:${node._port}`, receiver: { nodeId: node.nodeId, key: node.publicKey }, room: 'acme', timeoutMs: 4000 });
      assert.strictEqual(e.peer.nodeId, node.nodeId, 'the handshake proved the node');
      const { cmb } = e.emit({ focus: 'a block from an emitter in acme' });
      assert.strictEqual(cmb.metadata.room, 'acme', 'it authors for the room the handshake proved');
      const ev = await Promise.race([accepted, new Promise((_, reject) => setTimeout(() => reject(new Error(`not heard; refused: ${JSON.stringify(refused)}`)), 8000))]);
      assert.strictEqual(ev.record.metadata.key, cmb.metadata.key);
      assert.strictEqual(ev.session.nodeId, e.nodeId);
      assert.strictEqual(refused.length, 0);
      await e.close();
    } finally {
      await node.stop();
    }
  });

  it('a record signed for another room is refused, even from its own author over its own session', () => {
    const node = lanNode('acme-node5', 'acme');
    const author = identity('emitter');
    const session = admitAs(node, author);
    const cmb = signedRecord(author, { categories: { focus: 'signed for the public square' }, room: 'default' });
    const metrics = [];
    node.on('metric', (m) => metrics.push(m));
    node._frameHandler.handle(session, { type: 'cmb', cmb });
    assert.ok(metrics.some((m) => m.type === 'cmb-audience-rejected' && m.reason === 'wrong-audience'));
  });

  it('a matching explicit claim of "default" connects to a node in "default"', async () => {
    const node = lanNode('default-node', 'default');
    await node.start();
    try {
      const e = await connect({ server: `127.0.0.1:${node._port}`, receiver: { nodeId: node.nodeId, key: node.publicKey }, room: 'default', timeoutMs: 4000 });
      assert.ok(e);
      await e.close();
    } finally {
      await node.stop();
    }
  });
});
