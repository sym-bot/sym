'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { EventEmitter } = require('events');
const { FrameParser, sendFrame } = require('../lib/frame-parser');

function encodeFrame(msg) {
  const payload = Buffer.from(JSON.stringify(msg), 'utf8');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length, 0);
  return Buffer.concat([header, payload]);
}

describe('FrameParser', () => {
  it('should parse a single frame', () => {
    const parser = new FrameParser();
    const messages = [];
    parser.on('message', (m) => messages.push(m));

    parser.feed(encodeFrame({ type: 'ping' }));
    assert.strictEqual(messages.length, 1);
    assert.strictEqual(messages[0].type, 'ping');
  });

  it('should parse multiple frames in one chunk', () => {
    const parser = new FrameParser();
    const messages = [];
    parser.on('message', (m) => messages.push(m));

    const buf = Buffer.concat([
      encodeFrame({ type: 'ping' }),
      encodeFrame({ type: 'pong' }),
      encodeFrame({ type: 'handshake', nodeId: 'abc' }),
    ]);
    parser.feed(buf);
    assert.strictEqual(messages.length, 3);
    assert.strictEqual(messages[0].type, 'ping');
    assert.strictEqual(messages[1].type, 'pong');
    assert.strictEqual(messages[2].nodeId, 'abc');
  });

  it('should handle partial frames across chunks', () => {
    const parser = new FrameParser();
    const messages = [];
    parser.on('message', (m) => messages.push(m));

    const full = encodeFrame({ type: 'state-sync', h1: [1, 2, 3] });
    // Split in the middle
    const mid = Math.floor(full.length / 2);
    parser.feed(full.subarray(0, mid));
    assert.strictEqual(messages.length, 0, 'should not emit on partial data');
    parser.feed(full.subarray(mid));
    assert.strictEqual(messages.length, 1);
    assert.deepStrictEqual(messages[0].h1, [1, 2, 3]);
  });

  it('should emit error for zero-length frame', () => {
    const parser = new FrameParser();
    const errors = [];
    parser.on('error', (e) => errors.push(e));

    const header = Buffer.alloc(4);
    header.writeUInt32BE(0, 0);
    parser.feed(header);
    assert.strictEqual(errors.length, 1);
    assert.match(errors[0].message, /Invalid frame length/);
  });

  it('should emit error for oversized frame', () => {
    const parser = new FrameParser();
    const errors = [];
    parser.on('error', (e) => errors.push(e));

    const header = Buffer.alloc(4);
    header.writeUInt32BE(2 * 1024 * 1024, 0); // 2 MiB > 1 MiB limit
    parser.feed(header);
    assert.strictEqual(errors.length, 1);
    assert.match(errors[0].message, /Invalid frame length/);
  });

  it('should emit error for invalid JSON', () => {
    const parser = new FrameParser();
    const errors = [];
    parser.on('error', (e) => errors.push(e));

    const payload = Buffer.from('not json{{{', 'utf8');
    const header = Buffer.alloc(4);
    header.writeUInt32BE(payload.length, 0);
    parser.feed(Buffer.concat([header, payload]));
    assert.strictEqual(errors.length, 1);
    assert.match(errors[0].message, /Invalid JSON/);
  });
});

describe('sendFrame', () => {
  it('should write length-prefixed frame to socket', () => {
    const chunks = [];
    const mockSocket = { write: (data) => chunks.push(data) };
    const result = sendFrame(mockSocket, { type: 'ping' });
    assert.strictEqual(result, true);
    assert.strictEqual(chunks.length, 1);

    // Parse it back
    const parser = new FrameParser();
    const messages = [];
    parser.on('message', (m) => messages.push(m));
    parser.feed(chunks[0]);
    assert.strictEqual(messages.length, 1);
    assert.strictEqual(messages[0].type, 'ping');
  });

  it('should reject oversized payloads', () => {
    const mockSocket = { write: () => {} };
    const bigContent = 'x'.repeat(1024 * 1024 + 1);
    const result = sendFrame(mockSocket, { data: bigContent });
    assert.strictEqual(result, false);
  });

  it('should return false if socket.write throws', () => {
    const mockSocket = { write: () => { throw new Error('broken pipe'); } };
    const result = sendFrame(mockSocket, { type: 'ping' });
    assert.strictEqual(result, false);
  });
});
