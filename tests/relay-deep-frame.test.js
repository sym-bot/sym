'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * 0.13.17 review (R2). The relay measured a peer's payload by serialising it again,
 * JSON.stringify(msg.payload), before the frame reached the inbound guard; serialising recurses once
 * per level, so a payload some 10,000 levels deep (24 KB, under every size bound) threw a RangeError
 * out of the socket callback: uncaughtException, and the daemon exits on that. A relay-error's
 * `message` was serialised the same way. Now nesting has its own bound, checked on the text before
 * parsing wherever peer JSON is parsed, so whatever parses can be serialised again (measured,
 * relayed, persisted); a relay-error is printed field by field; and every message off the relay
 * socket, the relay's own frames included, is taken inside the guard.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const { WebSocketServer } = require('ws');
const { SymNode } = require('../lib/node');
const { nodeDir } = require('../lib/config');
const { FrameParser } = require('../lib/frame-parser');
const { nestedTooDeep, MAX_FRAME_DEPTH } = require('../lib/core/json-depth');
const { encryptCategories, decryptCategories } = require('../lib/core/e2e-crypto');

const uniq = (base) => `${base}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
const until = async (cond, ms = 5000) => { for (let t = 0; t < ms && !cond(); t += 20) await new Promise((r) => setTimeout(r, 20)); };
const deep = (d) => '['.repeat(d) + ']'.repeat(d);

/** A relay that answers relay-auth with `messages` (raw strings), then a plain message frame. */
async function withRelay(messages, fn) {
  const uncaught = [];
  const onUncaught = (err) => uncaught.push(String(err && err.message));
  process.on('uncaughtException', onUncaught);
  const wss = new WebSocketServer({ port: 0 });
  wss.on('connection', (ws) => ws.on('message', (m) => {
    if (JSON.parse(String(m)).type !== 'relay-auth') return;
    for (const raw of messages) ws.send(raw);
    ws.send(JSON.stringify({ from: 'e'.repeat(64), fromName: 'evil', payload: { type: 'message', content: 'after' } }));
  }));
  const name = uniq('deep-relay');
  const lines = [];
  const node = new SymNode({ name, silent: true, relayOnly: true, relay: `ws://127.0.0.1:${wss.address().port}`, relayToken: 'x'.repeat(40), room: 'g' });
  const origLog = node._log.bind(node);
  node._log = (l) => { lines.push(l); origLog(l); };
  const seen = [];
  node.on('message', (from, content) => seen.push(content));
  try {
    await node.start();
    await until(() => seen.length >= 1);
    await fn({ node, uncaught, seen, lines });
  } finally {
    process.removeListener('uncaughtException', onUncaught);
    await node.stop();
    await new Promise((r) => wss.close(() => r()));
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  }
}

describe('a deeply nested message off the relay cannot throw out of the socket (R2)', () => {
  it('a peer payload 12,000 levels deep (24 KB) is dropped; nothing is uncaught and the next frame is delivered', async () => {
    const raw = `{"from":"${'e'.repeat(64)}","fromName":"evil","payload":{"type":"message","content":"deep","a":${deep(12000)}}}`;
    assert.ok(raw.length < 32 * 1024, 'well under every size bound');
    await withRelay([raw], async ({ uncaught, seen, node }) => {
      assert.deepStrictEqual(uncaught, [], 'nothing reached uncaughtException (0.13.16/17: RangeError from JSON.stringify)');
      assert.deepStrictEqual(seen, ['after']);
      assert.strictEqual(node.status().relayConnected, true);
    });
  });

  it('a relay-error whose message is deep, an object or unprintable is said without it', async () => {
    const msgs = [
      `{"type":"relay-error","message":${deep(12000)}}`,
      JSON.stringify({ type: 'relay-error', message: { toString: 1 } }),
      JSON.stringify({ type: 'relay-error', kind: 'auth', code: 4003, message: 'Invalid token' }),
    ];
    await withRelay(msgs, async ({ uncaught, lines }) => {
      assert.deepStrictEqual(uncaught, []);
      const said = lines.filter((l) => /^Relay error/.test(l));
      assert.deepStrictEqual(said, ['Relay error: (no message)', 'Relay error auth 4003: Invalid token']);
    });
  });
});

describe('the relay\'s own frames go through the guard (R2)', () => {
  it('a host listener that throws on a relay join notice is refused and counted, not thrown out of the socket', async () => {
    const uncaught = [];
    const onUncaught = (err) => uncaught.push(String(err && err.message));
    process.on('uncaughtException', onUncaught);
    const wss = new WebSocketServer({ port: 0 });
    wss.on('connection', (ws) => ws.on('message', (m) => {
      if (JSON.parse(String(m)).type !== 'relay-auth') return;
      ws.send(JSON.stringify({ type: 'relay-peer-joined', nodeId: 'j'.repeat(64), name: 'joiner' }));
      ws.send(JSON.stringify({ from: 'e'.repeat(64), fromName: 'evil', payload: { type: 'message', content: 'after' } }));
    }));
    const name = uniq('deep-relay-join');
    const node = new SymNode({ name, silent: true, relayOnly: true, relay: `ws://127.0.0.1:${wss.address().port}`, relayToken: 'x'.repeat(40), room: 'g' });
    const seen = [];
    node.on('peer-joined', () => { throw new Error('host listener failed'); });
    node.on('message', (from, content) => seen.push(content));
    try {
      await node.start();
      await until(() => seen.length >= 1);
      assert.deepStrictEqual(uncaught, [], 'nothing reached uncaughtException');
      assert.deepStrictEqual(seen, ['after'], 'the relay link keeps working');
      assert.strictEqual(node.metrics().framesRefusedByType['relay-peer-joined'], 1);
    } finally {
      process.removeListener('uncaughtException', onUncaught);
      await node.stop();
      await new Promise((r) => wss.close(() => r()));
      fs.rmSync(nodeDir(name), { recursive: true, force: true });
    }
  });
});

describe('nesting is bounded wherever peer JSON is parsed (R2)', () => {
  it('the text scan counts brackets outside strings only', () => {
    assert.strictEqual(nestedTooDeep(deep(MAX_FRAME_DEPTH)), false);
    assert.strictEqual(nestedTooDeep(deep(MAX_FRAME_DEPTH + 1)), true);
    assert.strictEqual(nestedTooDeep(JSON.stringify({ a: '['.repeat(1000), b: '\\"{{{{' + '{'.repeat(500) })), false);
  });

  it('LAN: the frame parser drops a frame nested too deep, unparsed, and reads the next one', () => {
    const p = new FrameParser();
    const got = [];
    const errors = [];
    p.on('message', (m) => got.push(m.type));
    p.on('error', (e) => errors.push(e.message));
    const frame = (text) => { const b = Buffer.from(text); const h = Buffer.alloc(4); h.writeUInt32BE(b.length); return Buffer.concat([h, b]); };
    p.feed(Buffer.concat([frame(`{"type":"message","a":${deep(12000)}}`), frame('{"type":"ping"}')]));
    assert.deepStrictEqual(got, ['ping']);
    assert.match(errors[0], /nested deeper than 128/);
  });

  it('an encrypted CMB whose plaintext nests too deep is refused by decryption, as a bad one is', () => {
    const secret = crypto.randomBytes(32);
    let v = []; for (let i = 0; i < 200; i++) v = [v];
    const { ciphertext, nonce } = encryptCategories({ focus: { text: 'x', v } }, secret);
    assert.throws(() => decryptCategories(ciphertext, nonce, secret), /deeper than 128/);
    const ok = encryptCategories({ focus: { text: 'x' } }, secret);
    assert.deepStrictEqual(decryptCategories(ok.ciphertext, ok.nonce, secret), { focus: { text: 'x' } });
  });
});
