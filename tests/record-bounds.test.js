'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * What a record may carry, on the emitting side and the receiving side alike:
 * - B-R10: a record names its room; one that names none is in the literal room 'default' (§7),
 *   not "every room", and a v2.0 record without a room is not signed.
 * - B-R11: mood valence and arousal are measurements in [-1, 1]: absent ones are omitted, not
 *   invented as 0, out-of-range ones are refused, and numbers given without text are kept.
 * - B-R13: a category is at most 256 KiB, the seven together at most 960 KiB, an agent id at most
 *   64 bytes (§3.1.2), so every record fits a 1 MiB frame. Receivers refuse what emitters may not mint.
 * - B-R3 (interim): an unsigned record is accepted as unverified, counted, and named once per peer.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { createCMB, checkAudience, signCMB } = require('../lib/core');
const { MAX_CATEGORY_BYTES, MAX_RECORD_TEXT_BYTES } = require('../lib/core/cmb-encoder');
const { signingPayloadV2_0 } = require('../lib/core/cmb-signing');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');

describe('room (B-R10)', () => {
  it('a record minted without a room is in the room "default"', () => {
    const cmb = createCMB({ categories: { focus: 'x' }, createdBy: 'a' });
    assert.strictEqual(cmb.metadata.room, 'default');
  });

  it('a record with no room is refused outside "default", accepted inside it', () => {
    const cmb = createCMB({ categories: { focus: 'x' }, createdBy: 'a' });
    cmb.metadata.room = null; // as an older emitter minted it
    assert.deepStrictEqual(checkAudience(cmb, 'xmesh-world-room', 'me'), { ok: false, reason: 'wrong-audience' });
    assert.deepStrictEqual(checkAudience(cmb, 'default', 'me'), { ok: true });
  });

  it('the v2.0 preimage refuses a record without a room instead of signing "null"', () => {
    const cmb = createCMB({ categories: { focus: 'x' }, createdBy: 'a', emitV2: true, createdByNodeId: 'node-a' });
    cmb.metadata.room = null;
    assert.throws(() => signingPayloadV2_0(cmb), /requires metadata.room/);
  });
});

describe('mood (B-R11)', () => {
  const mood = (m) => createCMB({ categories: { focus: 'x', mood: m }, createdBy: 'a' }).categories.mood;
  it('keeps measured values, and omits the ones not given', () => {
    assert.deepStrictEqual({ ...mood({ text: 'calm', valence: 0.4, arousal: -0.2 }), meta: undefined }, { text: 'calm', valence: 0.4, arousal: -0.2, meta: undefined });
    const m = mood({ text: 'calm' });
    assert.strictEqual('valence' in m, false, 'no invented 0');
    assert.strictEqual('arousal' in m, false);
  });
  it('keeps numbers given without text', () => {
    const m = mood({ valence: -0.8 });
    assert.strictEqual(m.text, 'neutral');
    assert.strictEqual(m.valence, -0.8);
  });
  it('refuses values outside [-1, 1] or not numbers', () => {
    for (const bad of [7, -1.01, Number.NaN, '0.5']) {
      assert.throws(() => mood({ text: 'x', valence: bad }), RangeError);
      assert.throws(() => mood({ text: 'x', arousal: bad }), RangeError);
    }
  });
});

describe('size (B-R13)', () => {
  const big = (n) => 'a'.repeat(n);
  it('refuses a category over 256 KiB and a record whose text is over 960 KiB', () => {
    assert.throws(() => createCMB({ categories: { focus: big(MAX_CATEGORY_BYTES + 1) }, createdBy: 'a' }), (e) => e.code === 'ECMBSIZE');
    const near = big(MAX_CATEGORY_BYTES);
    assert.throws(() => createCMB({ categories: { focus: near, issue: near, intent: near, motivation: near }, createdBy: 'a' }), (e) => e.code === 'ECMBSIZE' && /total/.test(e.message));
    assert.ok(MAX_RECORD_TEXT_BYTES < 1024 * 1024);
  });
  it('counts bytes, not characters', () => {
    const emoji = '😀'.repeat(MAX_CATEGORY_BYTES / 4 + 1); // 4 bytes each
    assert.throws(() => createCMB({ categories: { focus: emoji }, createdBy: 'a' }), (e) => e.code === 'ECMBSIZE');
  });
  it('refuses an agent id over 64 bytes', () => {
    assert.throws(() => createCMB({ categories: { focus: 'x' }, createdBy: 'n'.repeat(65) }), (e) => e.code === 'ECMBSIZE');
    assert.ok(createCMB({ categories: { focus: 'x' }, createdBy: 'n'.repeat(64) }));
  });
});

describe('on receipt', () => {
  function withNode(fn) {
    const name = `bounds-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    const metrics = [];
    const lines = [];
    node.on('metric', (m) => metrics.push(m));
    node._log = (m) => lines.push(m);
    try { return fn(node, metrics, lines); } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  }

  it('refuses an oversized record before it is verified, stored or surfaced', () => {
    withNode((node, metrics) => {
      const cmb = createCMB({ categories: { focus: 'fine' }, createdBy: 'peer-a' });
      cmb.categories.focus.text = 'a'.repeat(MAX_CATEGORY_BYTES + 1); // a peer that skipped the bound
      let surfaced = 0;
      node.on('cmb-accepted', () => surfaced++);
      node._frameHandler.handle('peer-a', 'peer-a', { type: 'cmb', cmb, timestamp: Date.now() });
      assert.ok(metrics.some((m) => m.type === 'cmb-oversize-rejected'));
      assert.strictEqual(surfaced, 0);
    });
  });

  it('counts every unsigned record and names the peer once', () => {
    withNode((node, metrics, lines) => {
      for (let i = 0; i < 3; i++) {
        const cmb = createCMB({ categories: { focus: `unsigned ${i}` }, createdBy: 'old-peer' });
        node._frameHandler.handle('peer-old', 'old-peer', { type: 'cmb', cmb, timestamp: Date.now() });
      }
      assert.strictEqual(metrics.filter((m) => m.type === 'cmb-unsigned-received').length, 3);
      assert.strictEqual(lines.filter((l) => /UNSIGNED CMB from old-peer/.test(l)).length, 1);
    });
  });

  it('a signed record is not counted as unsigned', () => {
    withNode((node, metrics) => {
      const cmb = createCMB({ categories: { focus: 'signed' }, createdBy: node.name });
      signCMB(cmb, node._identity.privateKey);
      node._frameHandler.handle('peer-x', 'peer-x', { type: 'cmb', cmb, timestamp: Date.now() });
      assert.strictEqual(metrics.filter((m) => m.type === 'cmb-unsigned-received').length, 0);
    });
  });
});
