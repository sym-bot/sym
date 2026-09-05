'use strict';
require('./_isolate-home');
/**
 * NEVER IN THE CLEAR THROUGH THE RELAY. A peer reached only over the relay whose handshake
 * carried no E2E key used to receive CMB categories in plaintext, through a server that promises
 * it cannot read them. The sender now refuses: nothing is sent to that peer over the relay, the
 * refusal is logged once, and peers() says so. A LAN peer without a key still receives (the frame
 * never leaves the local network), and a relay peer WITH a key receives ciphertext.
 */
const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const crypto = require('crypto');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');

async function withNode(fn) {
  const name = `clear-refusal-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const logs = [];
  const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
  node._log = (m) => logs.push(String(m));
  await node.start();
  try { return await fn(node, logs); } finally { await node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
}
function plant(node, peerId, source, name) {
  const sent = [];
  const transport = { send: (f) => sent.push(f), close: () => {} };
  const transports = new Map([[source, transport]]);
  node._peers.set(peerId, { peerId, name, transport, transports, source, lastSeen: Date.now() });
  return sent;
}

describe('never in the clear through the relay', () => {
  it('a relay-only peer with no key gets nothing; a LAN peer without a key still gets the frame; a keyed relay peer gets ciphertext', async () => {
    await withNode(async (node, logs) => {
      const relayNoKey = plant(node, 'r'.repeat(32), 'relay', 'stranger-old-engine');
      const lanNoKey = plant(node, 'l'.repeat(32), 'bonjour', 'lan-old-engine');
      const relayKeyed = plant(node, 'k'.repeat(32), 'relay', 'relay-current');
      node._peerSharedSecrets.set('k'.repeat(32), crypto.randomBytes(32));

      node.remember({ focus: 'the content the relay must never see' });

      assert.strictEqual(relayNoKey.filter((f) => f.type === 'cmb').length, 0, 'relay peer without a key must receive no CMB');
      assert.strictEqual(lanNoKey.filter((f) => f.type === 'cmb').length, 1, 'LAN peer without a key still receives (never leaves the LAN)');
      const keyed = relayKeyed.filter((f) => f.type === 'cmb');
      assert.strictEqual(keyed.length, 1);
      assert.strictEqual(typeof keyed[0].cmb.categories, 'string', 'relay peer with a key receives ciphertext, not an object');
      assert.ok(keyed[0].cmb._e2e && keyed[0].cmb._e2e.nonce, 'ciphertext carries its nonce');

      // Said once, with the peer named, and visible in peers().
      const refusals = logs.filter((m) => m.includes('Refused to send in the clear through the relay'));
      assert.strictEqual(refusals.length, 1);
      assert.ok(refusals[0].includes('stranger-old-engine'));
      node.remember({ focus: 'a second share' });
      assert.strictEqual(logs.filter((m) => m.includes('Refused to send in the clear')).length, 1, 'logged once per peer, not per frame');
      const byName = Object.fromEntries(node.peers().map((p) => [p.name, p]));
      assert.deepStrictEqual([byName['stranger-old-engine'].e2e, byName['stranger-old-engine'].clearRefused], [false, true]);
      assert.deepStrictEqual([byName['relay-current'].e2e, byName['relay-current'].clearRefused], [true, false]);
      assert.deepStrictEqual([byName['lan-old-engine'].e2e, byName['lan-old-engine'].clearRefused], [false, false]);
    });
  });
});
