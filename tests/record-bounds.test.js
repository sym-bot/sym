'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * What a record may carry when it is minted, and what a receiver accepts:
 * - B-R10: a record names its room; one that names none is in the literal room 'default' (§7),
 *   not "every room", and a v2.0 record without a room is not signed.
 * - B-R11: mood valence and arousal are measurements in [-1, 1]: absent ones are omitted, not
 *   invented as 0, out-of-range ones are refused, and numbers given without text are kept.
 * - B-R13: a category is at most 256 KiB, the seven together at most 960 KiB, an agent id at most
 *   64 bytes (§3.1.2), when a record is minted.
 * - 0.14.0 review C-F3: text bytes are not frame bytes (JSON escaping, and the E2E seal's base64), so
 *   a record is minted only when the frame it travels in, sealed, fits MAX_FRAME_SIZE.
 * - 0.14.0 review C-F4: the record bounds are minting rules. A record an earlier release minted
 *   with a longer agent id or a larger category is not refused on receipt: the frame bounds it.
 * - B-R3 (interim): an unsigned record is accepted as unverified, counted, and named once per peer.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const crypto = require('crypto');
const { createCMB, checkAudience, signCMB, encryptCategories, assertionIdV2_0 } = require('../lib/core');
const { MAX_CATEGORY_BYTES, MAX_RECORD_TEXT_BYTES, recordFrameBytes, categoryKeyV1, blockKeyV2, CAT7_CATEGORIES } = require('../lib/core/cmb-encoder');
const { MAX_FRAME_SIZE, writeFrame } = require('../lib/frame-parser');
const { signingPayloadV2_0 } = require('../lib/core/cmb-signing');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const { settle } = require('./_settle'); // waits for every in-flight frame, not a fixed guess

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
    assert.ok(MAX_RECORD_TEXT_BYTES < MAX_FRAME_SIZE);
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

describe('a record is minted only if its frame can be sent (0.14.0 review C-F3)', () => {
  const ID = 'n'.repeat(64); // a 64-byte node id, the longest `to` a frame names
  const cats4 = (t) => ({ focus: t, issue: t, intent: t, motivation: t });
  /** The frames a record travels in: plain over TCP, and sealed for a peer inside the relay envelope. */
  function frames(record) {
    const plain = { type: 'cmb', timestamp: Date.now(), cmb: record, to: ID, directed: true, _anchor: true };
    const { ciphertext, nonce } = encryptCategories(record.categories, crypto.randomBytes(32));
    const sealed = { type: 'cmb', timestamp: Date.now(), cmb: { ...record, categories: ciphertext, _e2e: { nonce } }, to: ID, directed: true, _anchor: true };
    return { plain, relayed: { to: ID, payload: sealed } };
  }
  const live = { destroyed: false, writable: true, write: () => true };
  // The longest metadata a record of this node's carries: a 64-byte author, node id, addressee and
  // room, under the v2.0 suite (its extra fields, and an assertionId once signed).
  const mint = (t) => createCMB({ categories: cats4(t), createdBy: 'a'.repeat(64), to: ID, room: 'r'.repeat(64), emitV2: true, createdByNodeId: ID });
  /** The longest run of `ch` per category (four categories) that still mints, by bisection. */
  function largestMintable(ch) {
    let lo = 0, hi = MAX_CATEGORY_BYTES;
    while (lo < hi) {
      const mid = Math.ceil((lo + hi) / 2);
      try { mint(ch.repeat(mid)); lo = mid; } catch (e) {
        if (e.code !== 'ECMBSIZE') throw e;
        hi = mid - 1;
      }
    }
    return lo;
  }

  it('text that JSON escapes is bounded by the frame, not by its text bytes', () => {
    // 500 KiB of `"`, well inside the text bounds, is a 1 MB frame once each one is written `\"`.
    const quotes = '"'.repeat(250 * 1024);
    assert.throws(() => createCMB({ categories: { focus: quotes, issue: quotes }, createdBy: 'a' }), (e) => e.code === 'ECMBSIZE' && /frame/.test(e.message));
  });

  it('a record sealed for a peer is bounded with the seal\'s base64 counted', () => {
    // 900 KiB of plain text is inside the 960 KiB text bound, and about 1.2 MB once sealed.
    assert.throws(() => createCMB({ categories: cats4('a'.repeat(225 * 1024)), createdBy: 'a' }), (e) => e.code === 'ECMBSIZE' && /frame/.test(e.message));
  });

  for (const [label, ch] of [['plain text', 'a'], ['text JSON escapes', '"'], ['control characters', '\u0001']]) {
    it(`the largest record that mints is sendable on every transport (${label})`, () => {
      const n = largestMintable(ch);
      assert.ok(n > 0 && n < MAX_CATEGORY_BYTES, `bisection found ${n}`);
      const record = mint(ch.repeat(n));
      record.metadata.assertionId = assertionIdV2_0(record);
      signCMB(record, crypto.randomBytes(32).toString('base64url'));
      const { plain, relayed } = frames(record);
      assert.strictEqual(writeFrame(live, plain).ok, true, 'over TCP in the clear');
      assert.ok(Buffer.byteLength(JSON.stringify(relayed), 'utf8') <= MAX_FRAME_SIZE, 'sealed, inside the relay envelope');
      assert.ok(recordFrameBytes(record) <= MAX_FRAME_SIZE);
    });
  }

  it('remember() refuses a payload that would make the frame too large, before storing it', async () => {
    const name = `bounds-payload-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    await node.start();
    try {
      assert.throws(() => node.remember({ focus: 'a small record with a large payload' }, { payload: 'x'.repeat(MAX_FRAME_SIZE) }), (e) => e.code === 'ECMBSIZE');
      assert.strictEqual(node._store.allEntries().length, 0, 'nothing stored');
      assert.ok(node.remember({ focus: 'the same record with a payload that fits' }, { payload: 'x'.repeat(1024) }));
    } finally { await node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
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

  // Records are minted under bounds (cmb-encoder) but none is applied on receipt beyond the frame the
  // record arrived in: an earlier release minted larger categories and longer agent ids. Since 0.14 a
  // received record must be a signed v2.0 record (Core Secure), so these are shaped as an
  // implementation without the minting bound would sign them under mmp-sig-v2.0.
  const { admitAs, identity } = require('./_core-secure');
  function v2Record(peer, categories, createdBy, room) {
    const cmb = { categories, metadata: {
      key: blockKeyV2(categories), addressScheme: 'mmp-cmb-merkle-v2', signatureSuite: 'mmp-sig-v2.0',
      createdByNodeId: peer.nodeId, createdBy, createdTimestamp: Date.now(), room, to: null, lineage: null, application: null,
    } };
    cmb.metadata.assertionId = assertionIdV2_0(cmb);
    signCMB(cmb, peer.privateKey);
    return cmb;
  }

  it('refuses a record with a category over 256 KiB, which this release would not mint, before anything encodes it (security review D, record-flood; reverses C-F4)', async () => {
    const name = `bounds-bigcat-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    await node.start();
    try {
      const peer = identity('peer-old');
      const session = admitAs(node, peer);
      const texts = { focus: 'b'.repeat(MAX_CATEGORY_BYTES + 40 * 1024), issue: 'a large category from another implementation' };
      const categories = {};
      for (const f of CAT7_CATEGORIES) {
        const text = texts[f] || 'neutral';
        categories[f] = { text, meta: { key: categoryKeyV1(f, text), parents: [] } };
      }
      const cmb = v2Record(peer, categories, 'peer-old', node._room);
      assert.throws(() => createCMB({ categories: texts, createdBy: 'peer-old' }), (e) => e.code === 'ECMBSIZE', 'this release does not mint it');

      const accepted = [];
      const metrics = [];
      node.on('cmb-accepted', (e) => accepted.push(e));
      node.on('metric', (m) => metrics.push(m));
      let encoded = 0;
      node._svafEvaluator.evaluate = async () => { encoded++; return null; };
      await node._frameHandler.handle(session, { type: 'cmb', timestamp: Date.now(), cmb });
      await settle();
      assert.strictEqual(accepted.length, 0, 'refused');
      assert.strictEqual(encoded, 0, 'before SVAF encoded anything');
      assert.ok(metrics.some((m) => m.type === 'cmb-signature-rejected' && /too long/.test(m.error)), 'refused as malformed (too long)');
      assert.strictEqual(node._store.get(cmb.metadata.key), null, 'not stored');
    } finally { await node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  it('accepts a record with an agent id over 64 bytes, which this release would not mint (0.14.0 review C-F4)', async () => {
    const name = `bounds-longid-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    await node.start();
    try {
      const peer = identity('peer-long');
      const session = admitAs(node, peer);
      const longId = 'claude-' + 'host-qualified-session-label-'.repeat(4); // 123 bytes
      const base = createCMB({ categories: { focus: 'a record from a peer with a long agent id' }, createdBy: 'short', room: node._room });
      const cmb = v2Record(peer, base.categories, longId, node._room);
      assert.throws(() => createCMB({ categories: { focus: 'x' }, createdBy: longId }), (e) => e.code === 'ECMBSIZE', 'this release does not mint one');

      const accepted = [];
      node.on('cmb-accepted', (e) => accepted.push(e));
      await node._frameHandler.handle(session, { type: 'cmb', timestamp: Date.now(), cmb });
      await settle();
      assert.strictEqual(accepted.length, 1, 'admitted');
      assert.strictEqual(accepted[0].author.name, longId);
      assert.strictEqual(accepted[0]._cmbVerified, true, 'and verified');
    } finally { await node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  it('refuses and counts every unsigned record (Core Secure: §18.3.1)', () => {
    withNode((node, metrics) => {
      const peer = identity('old-peer');
      const session = admitAs(node, peer);
      for (let i = 0; i < 3; i++) {
        const cmb = createCMB({ categories: { focus: `unsigned ${i}` }, createdBy: 'old-peer', emitV2: true, createdByNodeId: peer.nodeId, room: node._room });
        cmb.metadata.assertionId = assertionIdV2_0(cmb);
        node._frameHandler.handle(session, { type: 'cmb', cmb, timestamp: Date.now() });
      }
      assert.strictEqual(metrics.filter((m) => m.type === 'cmb-signature-rejected' && m.reason === 'unsigned').length, 3);
      assert.strictEqual(node._store.allEntries().length, 0, 'none stored');
    });
  });

  it('a signed record is not refused as unsigned', () => {
    withNode((node, metrics) => {
      const self = { nodeId: node.nodeId, name: node.name, publicKey: node._identity.publicKey, privateKey: node._identity.privateKey };
      const peer = identity('peer-x');
      const session = admitAs(node, peer);
      const cmb = createCMB({ categories: { focus: 'signed' }, createdBy: peer.name, emitV2: true, createdByNodeId: peer.nodeId, room: node._room });
      cmb.metadata.assertionId = assertionIdV2_0(cmb);
      signCMB(cmb, peer.privateKey);
      node._frameHandler.handle(session, { type: 'cmb', cmb, timestamp: Date.now() });
      assert.strictEqual(metrics.filter((m) => m.type === 'cmb-signature-rejected').length, 0);
      void self;
    });
  });
});
