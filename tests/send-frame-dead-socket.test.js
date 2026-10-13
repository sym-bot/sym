'use strict';

/**
 * B-D6 (residual): a frame handed to a socket that is destroyed, or no longer writable, was counted
 * as sent until 'close' fired, so a send in that window reported delivery.dispatched for nothing.
 *
 * 0.14.0 review B-F6: a frame over MAX_FRAME_SIZE, a closed socket and a failed write were all one
 * `false`, and a directed send that was too large was reported as "not connected". The transports
 * say which, and remember()'s delivery result and log carry it.
 */

require('./_isolate-home');

const { describe, it } = require('node:test');
const assert = require('node:assert');
const net = require('node:net');
const fs = require('node:fs');
const { sendFrame, writeFrame, SEND_FAILURE, MAX_FRAME_SIZE } = require('../lib/frame-parser');
const { TcpTransport, RelayPeerTransport } = require('../lib/transport');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');

describe('sendFrame', () => {
  it('refuses a destroyed socket, a non-writable one, and none at all', () => {
    const destroyed = new net.Socket();
    destroyed.destroy();
    assert.strictEqual(sendFrame(destroyed, { type: 'cmb' }), false);
    const ended = { destroyed: false, writable: false, write: () => true };
    assert.strictEqual(sendFrame(ended, { type: 'cmb' }), false);
    assert.strictEqual(sendFrame(null, { type: 'cmb' }), false);
  });

  it('still sends on a writable socket', () => {
    const writes = [];
    const live = { destroyed: false, writable: true, write: (b) => { writes.push(b); return true; } };
    assert.strictEqual(sendFrame(live, { type: 'cmb', n: 1 }), true);
    assert.strictEqual(writes.length, 1);
  });
});

describe('a send that is not made says why (0.14.0 review B-F6)', () => {
  const live = () => ({ destroyed: false, writable: true, write: () => true, on: () => {}, setKeepAlive: () => {} });
  const huge = { type: 'cmb', blob: 'x'.repeat(MAX_FRAME_SIZE) };

  it('writeFrame names the reason: too large, not connected, write failed', () => {
    assert.deepStrictEqual(writeFrame(live(), huge).reason, SEND_FAILURE.TOO_LARGE);
    assert.ok(writeFrame(live(), huge).bytes > MAX_FRAME_SIZE);
    assert.strictEqual(writeFrame(null, { type: 'cmb' }).reason, SEND_FAILURE.NOT_CONNECTED);
    assert.strictEqual(writeFrame({ destroyed: true }, { type: 'cmb' }).reason, SEND_FAILURE.NOT_CONNECTED);
    assert.strictEqual(writeFrame({ ...live(), write: () => { throw new Error('EPIPE'); } }, { type: 'cmb' }).reason, SEND_FAILURE.WRITE_FAILED);
    assert.strictEqual(writeFrame(live(), { type: 'cmb' }).ok, true);
  });

  it('both transports say it, and send() still answers only whether', () => {
    const tcp = new TcpTransport(Object.assign(new net.Socket(), { write: () => true }));
    assert.strictEqual(tcp.trySend(huge).reason, SEND_FAILURE.TOO_LARGE);
    assert.strictEqual(tcp.send(huge), false);
    tcp.close();
    assert.strictEqual(tcp.trySend({ type: 'cmb' }).reason, SEND_FAILURE.NOT_CONNECTED);

    const sent = [];
    const ws = { readyState: 1, send: (d) => sent.push(d) };
    const relay = new RelayPeerTransport(ws, 'peer-r');
    assert.strictEqual(relay.trySend(huge).reason, SEND_FAILURE.TOO_LARGE);
    assert.strictEqual(relay.trySend({ type: 'cmb' }).ok, true);
    assert.strictEqual(relay.send({ type: 'cmb' }), true);
    ws.send = () => { throw new Error('closed under it'); };
    assert.strictEqual(relay.trySend({ type: 'cmb' }).reason, SEND_FAILURE.WRITE_FAILED);
    ws.readyState = 3;
    assert.strictEqual(relay.trySend({ type: 'cmb' }).reason, SEND_FAILURE.NOT_CONNECTED);
    assert.strictEqual(relay.send({ type: 'cmb' }), false);
  });

  it('a directed send whose frame no transport takes reports why, not "not connected"', async () => {
    const name = `send-reason-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    await node.start();
    try {
      const lines = [];
      const metrics = [];
      node._log = (m) => lines.push(m);
      node.on('metric', (m) => metrics.push(m));
      // A connected peer whose transport refuses the frame as too large (a frame from a record the
      // bounds did not see, or a long relay envelope), and one whose transport only says whether.
      // (Admitted sessions, as a confirmed handshake leaves them; their sends are made to fail.)
      const { admitAs } = require('./_core-secure');
      // nodeIds are lowercase UUIDs (§3.1.1): remember() refuses a `to` spelled otherwise.
      const LARGE = '0190aaaa-0000-7000-8000-000000000001', OPAQUE = '0190bbbb-0000-7000-8000-000000000002', ABSENT = '0190cccc-0000-7000-8000-000000000003';
      const tooLarge = admitAs(node, { nodeId: LARGE, name: 'peer-large' });
      tooLarge.trySend = () => ({ ok: false, reason: SEND_FAILURE.TOO_LARGE, bytes: MAX_FRAME_SIZE + 1 });
      const opaque = admitAs(node, { nodeId: OPAQUE, name: 'peer-opaque' });
      delete opaque.trySend;
      opaque.send = () => false;

      const a = node.remember({ focus: 'a directed send the transport refuses as too large' }, { to: LARGE });
      assert.strictEqual(a.delivery.undelivered, true);
      assert.strictEqual(a.delivery.reason, SEND_FAILURE.TOO_LARGE);
      assert.ok(lines.some((l) => /UNDELIVERED \(directed\): 0190aaaa frame too large/.test(l)), lines.join('\n'));
      assert.ok(!lines.some((l) => /UNDELIVERED.*not connected/.test(l)), 'not reported as not connected');
      assert.ok(metrics.some((m) => m.type === 'cmb-frame-too-large' && m.to === LARGE));
      assert.ok(metrics.some((m) => m.type === 'cmb-undelivered' && m.reason === SEND_FAILURE.TOO_LARGE));

      const b = node.remember({ focus: 'a directed send to a transport that says only whether' }, { to: OPAQUE });
      assert.strictEqual(b.delivery.reason, 'send-failed');

      const c = node.remember({ focus: 'a directed send to nobody connected' }, { to: ABSENT });
      assert.strictEqual(c.delivery.reason, SEND_FAILURE.NOT_CONNECTED);
      assert.ok(lines.some((l) => /UNDELIVERED \(directed\): 0190cccc not connected/.test(l)));
    } finally { await node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });
});
