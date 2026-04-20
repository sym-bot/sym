'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');

// Captures peer.transport.send(frame) calls so tests can assert what was
// placed on the wire for each peer. Same surface shape as the mockTransport
// used in node.test.js — extended with a frames[] buffer.
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

describe('remember({to}) — MMP §4.4.4 targeted CMB send', () => {
  it('broadcasts to all peers when opts.to is omitted (regression)', async () => {
    await withNode('targeted-broadcast', async (node) => {
      const tA = capturingTransport();
      const tB = capturingTransport();
      const tC = capturingTransport();
      node._addPeer(node._createPeer(tA, 'peer-AAAAAAAA', 'peer-a', false, 'bonjour'));
      node._addPeer(node._createPeer(tB, 'peer-BBBBBBBB', 'peer-b', false, 'bonjour'));
      node._addPeer(node._createPeer(tC, 'peer-CCCCCCCC', 'peer-c', false, 'bonjour'));

      const entry = node.remember({
        focus: 'broadcast fan-out regression check',
        issue: 'ensure default behaviour unchanged',
        intent: 'verify all peers receive the frame',
        motivation: 'paper §4.1 CMB-path invariants',
        commitment: 'no silent fan-out drop',
        perspective: 'SDK regression',
        mood: { text: 'procedural', valence: 0, arousal: 0 },
      });

      assert.ok(entry, 'broadcast remember should return an entry');
      const cmbFrames = [tA, tB, tC].map(t => t.frames.filter(f => f.type === 'cmb'));
      assert.strictEqual(cmbFrames[0].length, 1, 'peer A should receive exactly one CMB frame');
      assert.strictEqual(cmbFrames[1].length, 1, 'peer B should receive exactly one CMB frame');
      assert.strictEqual(cmbFrames[2].length, 1, 'peer C should receive exactly one CMB frame');
      for (const frames of cmbFrames) {
        assert.strictEqual(frames[0].cmb.key, entry.key, 'broadcast frame should carry the stored CMB key');
      }
    });
  });

  it('emits only to the single target when opts.to names a connected peer', async () => {
    await withNode('targeted-single', async (node) => {
      const tA = capturingTransport();
      const tB = capturingTransport();
      const tC = capturingTransport();
      node._addPeer(node._createPeer(tA, 'peer-AAAAAAAA', 'peer-a', false, 'bonjour'));
      node._addPeer(node._createPeer(tB, 'peer-BBBBBBBB', 'peer-b', false, 'bonjour'));
      node._addPeer(node._createPeer(tC, 'peer-CCCCCCCC', 'peer-c', false, 'bonjour'));

      const entry = node.remember({
        focus: 'targeted send to peer B',
        issue: 'verify fan-out filter',
        intent: 'direct peer-review gate request',
        motivation: 'targeted coordination per MMP §4.4.4',
        commitment: 'frame reaches only the named peer',
        perspective: 'sender role',
        mood: { text: 'procedural', valence: 0, arousal: 0 },
      }, { to: 'peer-BBBBBBBB' });

      assert.ok(entry, 'targeted remember should return an entry');
      assert.strictEqual(tA.frames.filter(f => f.type === 'cmb').length, 0, 'peer A should receive NO CMB');
      const bFrames = tB.frames.filter(f => f.type === 'cmb');
      assert.strictEqual(bFrames.length, 1, 'peer B should receive exactly one CMB');
      assert.strictEqual(bFrames[0].cmb.key, entry.key, 'targeted frame should carry the stored CMB key');
      assert.strictEqual(tC.frames.filter(f => f.type === 'cmb').length, 0, 'peer C should receive NO CMB');
    });
  });

  it('still writes locally when opts.to names a disconnected peer', async () => {
    await withNode('targeted-disconnected', async (node) => {
      const tA = capturingTransport();
      node._addPeer(node._createPeer(tA, 'peer-AAAAAAAA', 'peer-a', false, 'bonjour'));

      const entry = node.remember({
        focus: 'targeted send to absent peer',
        issue: 'peer not in _peers map',
        intent: 'verify local write happens regardless',
        motivation: 'lineage must survive temporary partitions',
        commitment: 'no fan-out but store intact',
        perspective: 'sender role',
        mood: { text: 'procedural', valence: 0, arousal: 0 },
      }, { to: 'peer-ZZZZZZZZ-absent' });

      assert.ok(entry, 'disconnected-target remember should still return an entry');
      assert.strictEqual(tA.frames.filter(f => f.type === 'cmb').length, 0, 'connected peer A should receive nothing');
      const recalled = node.recall('targeted send to absent peer');
      assert.ok(recalled.length >= 1, 'CMB should be recallable from local store');
    });
  });

  it('peers() exposes full peerId alongside truncated id', async () => {
    await withNode('peers-peerid', async (node) => {
      node._addPeer(node._createPeer(capturingTransport(), 'peer-AAAAAAAA-bcd-1234', 'peer-a', false, 'bonjour'));
      const list = node.peers();
      assert.strictEqual(list.length, 1);
      assert.strictEqual(list[0].id, 'peer-AAA', 'id is the truncated display form');
      assert.strictEqual(list[0].peerId, 'peer-AAAAAAAA-bcd-1234', 'peerId is the full nodeId');
      assert.strictEqual(list[0].name, 'peer-a');
    });
  });
});
