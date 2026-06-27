'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');

function capturingTransport() {
  const listeners = {};
  const frames = [];
  return {
    on: (event, fn) => { listeners[event] = fn; },
    send: (frame) => { frames.push(frame); },
    close: () => { if (listeners.close) listeners.close(); },
    frames,
  };
}

async function withNode(baseName, fn) {
  const name = `${baseName}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
  await node.start();
  try {
    return await fn(node);
  } finally {
    await node.stop();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  }
}

describe('remember({payload}) — opaque payload riding CMBs alongside CAT7', () => {
  it('attaches opts.payload to the stored CMB', async () => {
    await withNode('payload-store', async (node) => {
      const entry = node.remember({
        focus: 'llm-request:test-r1',
        issue: 'verify payload survives store',
        intent: 'llm-call',
        motivation: 'substrate primitive smoke',
        commitment: 'awaiting-response',
        perspective: 'test-sender',
        mood: { text: 'procedural', valence: 0, arousal: 0 },
      }, {
        payload: {
          request_id: 'r1',
          system_prompt: 'You are a test responder.',
          user_message: 'echo back hello',
          max_tokens: 100,
        },
      });

      assert.ok(entry, 'payload-bearing remember should return an entry');
      assert.ok(entry.cmb, 'entry should carry the CMB');
      assert.deepStrictEqual(entry.cmb.payload, {
        request_id: 'r1',
        system_prompt: 'You are a test responder.',
        user_message: 'echo back hello',
        max_tokens: 100,
      }, 'cmb.payload should match opts.payload exactly');
    });
  });

  it('payload rides the wire frame to connected peers', async () => {
    await withNode('payload-wire', async (node) => {
      const tA = capturingTransport();
      node._addPeer(node._createPeer(tA, 'peer-AAAAAAAA', 'peer-a', false, 'bonjour'));

      node.remember({
        focus: 'llm-request:test-r2',
        issue: 'wire propagation',
        intent: 'llm-call',
        motivation: 'verify transport',
        commitment: 'awaiting',
        perspective: 'test-sender',
        mood: { text: 'procedural', valence: 0, arousal: 0 },
      }, {
        to: 'peer-AAAAAAAA',
        payload: { request_id: 'r2', user_message: 'check the wire' },
      });

      const cmbFrames = tA.frames.filter(f => f.type === 'cmb');
      assert.strictEqual(cmbFrames.length, 1, 'peer should receive one CMB frame');
      assert.deepStrictEqual(cmbFrames[0].cmb.payload, {
        request_id: 'r2',
        user_message: 'check the wire',
      }, 'wire frame should carry the payload through');
    });
  });

  it('omitting opts.payload leaves the CMB unchanged (back-compat)', async () => {
    await withNode('payload-omitted', async (node) => {
      const entry = node.remember({
        focus: 'plain CAT7-only CMB',
        issue: 'no payload supplied',
        intent: 'observation',
        motivation: 'regression for v0.5.7 callers',
        commitment: 'shipped',
        perspective: 'test-sender',
        mood: { text: 'procedural', valence: 0, arousal: 0 },
      });

      assert.ok(entry, 'CAT7-only remember should return an entry');
      assert.strictEqual('payload' in entry.cmb, false, 'cmb should NOT have payload key when opts.payload omitted');
    });
  });

  it('payload does not affect cmbKey — same CAT7 + different payloads dedupe', async () => {
    await withNode('payload-not-in-key', async (node) => {
      const entry1 = node.remember({
        focus: 'identical-cat7',
        issue: 'same fields',
        intent: 'observation',
        motivation: 'cmbKey stability',
        commitment: 'shipped',
        perspective: 'test-sender',
        mood: { text: 'procedural', valence: 0, arousal: 0 },
      }, { payload: { v: 1 } });

      const entry2 = node.remember({
        focus: 'identical-cat7',
        issue: 'same fields',
        intent: 'observation',
        motivation: 'cmbKey stability',
        commitment: 'shipped',
        perspective: 'test-sender',
        mood: { text: 'procedural', valence: 0, arousal: 0 },
      }, { payload: { v: 2 } });

      assert.ok(entry1, 'first emit should land');
      assert.strictEqual(entry2, null, 'second emit with identical CAT7 should dedupe (cmbKey unchanged by payload)');
    });
  });
});
