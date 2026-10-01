'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * 0.13.16: peer-info gossip logged one line per entry and rewrote the wake-channel file on every
 * frame, and every peer re-sends its whole list on every connect, so the daemon's log reached 1 GB.
 * Only a channel that changed is set and saved, with one line per frame.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');

describe('peer-info gossip is quiet when nothing changed', () => {
  it('a repeat of the same list logs nothing and writes nothing; a change logs one line', () => {
    const name = `pinfo-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    const lines = [];
    node._log = (m) => lines.push(m);
    let writes = 0;
    node._wakeManager.saveWakeChannels = () => { writes++; };
    try {
      const frame = { type: 'peer-info', peers: [
        { nodeId: 'phone-1', name: 'unknown', wakeChannel: { platform: 'apns', token: 't1', environment: 'sandbox' } },
        { nodeId: 'phone-2', name: 'unknown', wakeChannel: { platform: 'apns', token: 't2', environment: 'sandbox' } },
      ] };
      node._frameHandler._handlePeerInfo('peer-x', 'peer-x', frame);
      assert.deepStrictEqual(lines.filter((l) => /wake channel/.test(l)), ['Gossip from peer-x: learned 2 wake channel(s)']);
      assert.strictEqual(writes, 1);
      for (let i = 0; i < 50; i++) node._frameHandler._handlePeerInfo('peer-x', 'peer-x', frame);
      assert.strictEqual(lines.filter((l) => /wake channel/.test(l)).length, 1, 'repeats are silent');
      assert.strictEqual(writes, 1, 'and write nothing');
      const big = { type: 'peer-info', peers: Array.from({ length: 1000 }, (_, i) => ({ nodeId: `n${i}`, wakeChannel: { platform: 'apns', token: `x${i}` } })) };
      node._frameHandler._handlePeerInfo('peer-x', 'peer-x', big);
      assert.strictEqual(node._peerWakeChannels.size, 2 + 256, 'one frame is read for its first 256 entries');
    } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });
});
