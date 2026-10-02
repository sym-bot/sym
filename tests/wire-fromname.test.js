'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * 0.13.17 review (R5). The hotfix took a peer's name as text where the transport carries it, but
 * the `message`, `mood` and `xmesh-insight` handlers still preferred the frame's own `fromName`,
 * as given: printed in their log line and passed on to listeners (the daemon forwards it to every
 * client). One whose `fromName` cannot be turned into text was refused (the log line threw), and
 * any other JSON value reached the listeners as the sender's name. Now `fromName` is taken through
 * wireName, falling back to the name the transport took.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');

const uniq = (base) => `${base}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
const BAD = { toString: 1 };

describe('a frame\'s fromName is taken as text (R5)', () => {
  for (const [type, frame, event, fromOf] of [
    ['message', { type: 'message', content: 'hello' }, 'message', (args) => args[0]],
    ['mood', { type: 'mood', mood: 'calm and focused' }, ['mood-delivered', 'mood-rejected'], (args) => args[0].from],
    ['xmesh-insight', { type: 'xmesh-insight', anomaly: 0.1, remixScore: 0.2, coherence: 0.3 }, 'xmesh-insight', (args) => args[0].from],
  ]) {
    it(`${type}: a fromName that is not text is not printed or passed on; the transport's name is used`, () => {
      const name = uniq(`fromname-${type}`);
      const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: 'g' });
      const froms = [];
      for (const e of [].concat(event)) node.on(e, (...args) => froms.push(fromOf(args)));
      try {
        for (const fromName of [BAD, 42, ['x'], { a: 1 }, null]) {
          assert.strictEqual(node._receiveFrame('p', 'peer-p', { ...frame, fromName }, 'relay'), true, 'handled, not refused');
        }
        node._receiveFrame('p', 'peer-p', { ...frame, fromName: 'its own label' }, 'relay');
        assert.deepStrictEqual(froms, ['peer-p', 'peer-p', 'peer-p', 'peer-p', 'peer-p', 'its own label']);
        assert.strictEqual(node.metrics().framesRefused, 0);
      } finally { node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
    });
  }
});
