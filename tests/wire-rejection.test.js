'use strict';

// MMP §4.1 frame rejection and the §19.1 inbound identification deadline.
// Found in the 2026-10-01 MMP 2.0 audit (B-T1, B-T2, B-T3, B-T10): a bad length
// prefix desynchronised the stream instead of closing it, any parse error cancelled
// the 10 s handshake deadline, and a relay message `null` crashed the process.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
process.env.HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-wire-rejection-home-'));
process.env.USERPROFILE = process.env.HOME; // os.homedir() reads USERPROFILE on Windows

const { describe, it } = require('node:test');
const assert = require('node:assert');
const net = require('node:net');
const { WebSocketServer } = require('ws');
const { FrameParser, sendFrame, MAX_FRAME_SIZE } = require('../lib/frame-parser');
const { TcpTransport, RelayPeerTransport } = require('../lib/transport');
const { BonjourDiscovery } = require('../lib/discovery');
const { RelayConnection } = require('../lib/relay');

const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const frame = (bytes) => {
  const header = Buffer.alloc(4);
  header.writeUInt32BE(bytes.length, 0);
  return Buffer.concat([header, bytes]);
};

describe('FrameParser rejection', () => {
  it('stops for good after a bad length instead of reading payload bytes as the next length', () => {
    const parser = new FrameParser();
    const errors = [];
    const messages = [];
    parser.on('error', (e) => errors.push(e));
    parser.on('message', (m) => messages.push(m));
    const bad = Buffer.from([0x00, 0x10, 0x00, 0x01]); // 1 MiB + 1
    parser.feed(Buffer.concat([bad, frame(Buffer.from('{"type":"ping"}'))]));
    parser.feed(frame(Buffer.from('{"type":"ping"}')));
    assert.strictEqual(errors.length, 1);
    assert.strictEqual(errors[0].fatal, true);
    assert.strictEqual(messages.length, 0, 'nothing after a bad length is parsed');
  });

  it('treats a zero-length frame as fatal, not as a frame to skip', () => {
    const parser = new FrameParser();
    const messages = [];
    const errors = [];
    parser.on('error', (e) => errors.push(e));
    parser.on('message', (m) => messages.push(m));
    parser.feed(Buffer.concat([Buffer.alloc(4), frame(Buffer.from('{"type":"ping"}'))]));
    assert.strictEqual(errors[0].fatal, true);
    assert.strictEqual(messages.length, 0);
  });

  it('silently discards null, non-object and type-less frames', () => {
    const parser = new FrameParser();
    const messages = [];
    const errors = [];
    parser.on('error', (e) => errors.push(e));
    parser.on('message', (m) => messages.push(m));
    for (const p of ['null', '5', '"x"', '[]', '{}', '{"type":7}']) parser.feed(frame(Buffer.from(p)));
    parser.feed(frame(Buffer.from('{"type":"ping"}')));
    assert.deepStrictEqual(messages, [{ type: 'ping' }]);
    assert.strictEqual(errors.length, 0);
  });

  it('rejects invalid UTF-8 instead of substituting replacement characters', () => {
    const parser = new FrameParser();
    const messages = [];
    const errors = [];
    parser.on('error', (e) => errors.push(e));
    parser.on('message', (m) => messages.push(m));
    parser.feed(frame(Buffer.concat([Buffer.from('{"type":"'), Buffer.from([0xff, 0xfe]), Buffer.from('"}')])));
    assert.strictEqual(messages.length, 0);
    assert.strictEqual(errors.length, 1);
    assert.ok(!errors[0].fatal, 'a bad payload is discarded, the stream stays usable');
  });

  it('reports a handler exception as a handler failure, not as invalid JSON', () => {
    const parser = new FrameParser();
    const errors = [];
    parser.on('error', (e) => errors.push(e));
    parser.on('message', () => { throw new Error('boom'); });
    parser.feed(frame(Buffer.from('{"type":"ping"}')));
    assert.match(errors[0].message, /Frame handler failed for 'ping': boom/);
  });
});

describe('TcpTransport rejection', () => {
  it('closes the connection on a bad length (MMP §4.1)', async () => {
    const server = net.createServer();
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const accepted = new Promise((r) => server.once('connection', r));
    const client = net.createConnection(server.address().port, '127.0.0.1');
    const socket = await accepted;
    const transport = new TcpTransport(socket);
    transport.on('error', () => {});
    const closed = new Promise((r) => transport.once('close', r));
    client.write(Buffer.alloc(4));
    await closed;
    assert.strictEqual(transport.send({ type: 'ping' }), false, 'send reports a closed transport');
    client.destroy();
    server.close();
  });
});

describe('RelayPeerTransport send result', () => {
  it('refuses a frame over MAX_FRAME_SIZE and reports it', () => {
    const sent = [];
    const ws = { readyState: 1, send: (d) => sent.push(d) };
    const t = new RelayPeerTransport(ws, 'peer');
    assert.strictEqual(t.send({ type: 'cmb', blob: 'x'.repeat(MAX_FRAME_SIZE) }), false);
    assert.strictEqual(t.send({ type: 'ping' }), true);
    assert.strictEqual(sent.length, 1);
  });

  it('reports a relay socket that is not open', () => {
    const t = new RelayPeerTransport({ readyState: 3, send: () => assert.fail('must not send') }, 'peer');
    assert.strictEqual(t.send({ type: 'ping' }), false);
  });
});

describe('inbound identification deadline (MMP §19.1)', () => {
  async function probe(firstBytes) {
    const d = new BonjourDiscovery({ mdns: false, handshakeTimeoutMs: 200 });
    const port = await d.start({ nodeId: 'deadline-probe', name: 'deadline-probe', publicKey: 'pk', hostname: 'host' }, () => {});
    const client = net.createConnection({ host: '127.0.0.1', port }, () => client.write(firstBytes));
    client.on('error', () => {});
    const closedAt = await Promise.race([
      new Promise((r) => client.once('close', () => r(Date.now()))),
      wait(2000).then(() => null),
    ]);
    client.destroy();
    await d.stop();
    return closedAt;
  }

  it('still fires after an invalid-JSON first frame', async () => {
    assert.ok(await probe(frame(Buffer.from('not json'))), 'connection closed by the deadline');
  });

  it('still fires after a null first frame', async () => {
    assert.ok(await probe(frame(Buffer.from('null'))), 'connection closed by the deadline');
  });

  it('closes at once on a zero-length first frame', async () => {
    const t0 = Date.now();
    const closedAt = await probe(Buffer.alloc(4));
    assert.ok(closedAt && closedAt - t0 < 150, 'closed before the deadline, by the length rejection');
  });
});

describe('relay message validation', () => {
  it('survives a relay that sends null, a bare number, a type-less envelope and an oversize frame', async () => {
    const wss = new WebSocketServer({ port: 0 });
    wss.on('connection', (ws) => {
      ws.once('message', () => {
        ws.send('null');
        ws.send('5');
        ws.send(JSON.stringify({ from: 'x', payload: null }));
        ws.send(JSON.stringify({ from: 'x', payload: { no: 'type' } }));
        ws.send(JSON.stringify({ from: 'x', payload: { type: 'cmb', blob: 'x'.repeat(MAX_FRAME_SIZE) } })); // over §4.1's bound
        ws.send(JSON.stringify({ type: 'relay-peers', peers: [] }));
      });
    });
    const handled = [];
    let running = true;
    const rc = new RelayConnection({
      relayUrl: `ws://127.0.0.1:${wss.address().port}`,
      relayToken: 'x'.repeat(40),
      log: () => {},
      getIdentity: () => ({ nodeId: 'b'.repeat(64) }),
      isRunning: () => running,
      getPeers: () => new Map(),
      getMeshNode: () => null,
      createPeer: () => { throw new Error('no peers expected'); },
      addPeer: () => {},
      handlePeerMessage: (...a) => handled.push(a),
      onPeerLeft: () => {},
      onAuthRefused: () => {},
      nodeName: 'claude-test-wire',
      peerWakeChannels: new Map(),
      saveWakeChannels: () => {},
    });
    try {
      rc.connect();
      const s = await rc.awaitOutcome(5000);
      assert.strictEqual(s.phase, 'connected', 'the process is alive and reached relay-peers');
      assert.strictEqual(handled.length, 0, 'malformed envelopes never reach the peer handler');
    } finally {
      running = false;
      rc.destroy();
      await new Promise((r) => wss.close(() => r()));
    }
  });
});

it('sendFrame still refuses oversize frames', () => {
  const mock = { write: () => assert.fail('must not write') };
  assert.strictEqual(sendFrame(mock, { type: 'cmb', blob: 'x'.repeat(MAX_FRAME_SIZE) }), false);
});
