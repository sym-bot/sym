'use strict';

/**
 * R3-12 (0.14.3): FrameParser.feed() concatenated the whole buffer with every chunk, so a frame near
 * MAX_FRAME_SIZE fed in small reads cost O(n²) copying on the event loop (67 ms for one 1 MiB frame in
 * 1 KiB reads), before the peer had authenticated anything on a LAN listener. A frame's bytes are
 * copied once now. Measured in bytes copied, not in milliseconds, so a busy machine cannot flake it.
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { FrameParser, MAX_FRAME_SIZE } = require('../lib/frame-parser');

test('a frame near MAX_FRAME_SIZE fed in 1 KiB chunks is copied about once, not once per chunk', () => {
  const body = Buffer.from(JSON.stringify({ type: 'client-hello', pad: 'x'.repeat(MAX_FRAME_SIZE - 64) }));
  const hdr = Buffer.alloc(4);
  hdr.writeUInt32BE(body.length, 0);
  const all = Buffer.concat([hdr, body]);
  let copied = 0;
  const concat = Buffer.concat;
  const copy = Buffer.prototype.copy;
  Buffer.concat = function (list, total) { const b = concat.call(Buffer, list, total); copied += b.length; return b; };
  Buffer.prototype.copy = function (target, ts, ss = 0, se = this.length) { copied += Math.max(0, Math.min(se, this.length) - ss); return copy.call(this, target, ts, ss, se); };
  const p = new FrameParser();
  const frames = [];
  p.on('message', (m) => frames.push(m.type));
  p.on('error', (e) => { throw e; });
  try {
    for (let i = 0; i < all.length; i += 1024) p.feed(all.subarray(i, i + 1024));
  } finally {
    Buffer.concat = concat;
    Buffer.prototype.copy = copy;
  }
  assert.deepEqual(frames, ['client-hello']);
  assert.ok(copied < 3 * all.length, `copied ${copied} bytes for a ${all.length}-byte frame`);
});

test('frames split across chunks at every boundary still parse, in order', () => {
  const frames = [{ type: 'a', n: 1 }, { type: 'b', s: 'é✓' }, { type: 'c' }].map((m) => {
    const b = Buffer.from(JSON.stringify(m)); const h = Buffer.alloc(4); h.writeUInt32BE(b.length, 0); return Buffer.concat([h, b]);
  });
  const all = Buffer.concat(frames);
  for (let size = 1; size <= all.length; size++) {
    const p = new FrameParser();
    const got = [];
    p.on('message', (m) => got.push(m.type));
    for (let i = 0; i < all.length; i += size) p.feed(all.subarray(i, i + size));
    assert.deepEqual(got, ['a', 'b', 'c'], `chunks of ${size}`);
    assert.equal(p.buffer.length, 0);
  }
});
