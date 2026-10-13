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

const { admitAs, deliver, identity } = require('./_core-secure');

describe('a frame\'s fromName is taken as text (R5)', () => {
  // 0.14: frames arrive on a confirmed session (design D1); the session's proven name is the fallback.
  // MMP 2.0 update 1 (founder ruling): the mood frame names no sender. A mood frame carrying any
  // fromName is not that frame and is refused; the event is labelled with the session's proven name.
  it('mood: a frame naming a sender is refused, whatever its fromName; the session\'s name labels the rest', () => {
    const name = uniq('fromname-mood');
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: 'g' });
    const froms = [];
    for (const e of ['mood-delivered', 'mood-rejected']) node.on(e, (d) => froms.push(d.from));
    try {
      const session = admitAs(node, identity('peer-p'));
      for (const fromName of [BAD, 42, ['x'], { a: 1 }, null, 'its own label']) {
        assert.strictEqual(deliver(node, session, { type: 'mood', mood: 'calm and focused', fromName }), false, 'refused');
      }
      assert.deepStrictEqual(froms, []);
      assert.strictEqual(deliver(node, session, { type: 'mood', mood: 'calm and focused' }), true);
      assert.deepStrictEqual(froms, ['peer-p']);
    } finally { node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  for (const [type, frame, event, fromOf] of [
    ['xmesh-insight', { type: 'xmesh-insight', anomaly: 0.1, remixScore: 0.2, coherence: 0.3 }, 'xmesh-insight', (args) => args[0].from],
  ]) {
    it(`${type}: a fromName that is not text is not printed or passed on; the session's name is used`, () => {
      const name = uniq(`fromname-${type}`);
      const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: 'g' });
      const froms = [];
      for (const e of [].concat(event)) node.on(e, (...args) => froms.push(fromOf(args)));
      try {
        const session = admitAs(node, identity('peer-p'));
        for (const fromName of [BAD, 42, ['x'], { a: 1 }, null]) {
          assert.strictEqual(deliver(node, session, { ...frame, fromName }), true, 'handled, not refused');
        }
        deliver(node, session, { ...frame, fromName: 'its own label' });
        assert.deepStrictEqual(froms, ['peer-p', 'peer-p', 'peer-p', 'peer-p', 'peer-p', 'its own label']);
        assert.strictEqual(node.metrics().framesRefused, 0);
      } finally { node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
    });
  }

  it('message: the frame is retired in Core Secure; it is refused and raises nothing, whatever its fromName', () => {
    const name = uniq('fromname-message');
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: 'g' });
    const raised = [];
    node.on('message', (...a) => raised.push(a));
    try {
      const session = admitAs(node, identity('peer-p'));
      for (const fromName of [BAD, 'label']) deliver(node, session, { type: 'message', content: 'hello', fromName });
      assert.deepStrictEqual(raised, []);
      assert.ok(node._sessionStats.refusedByReason && Object.keys(node._sessionStats.refusedByReason).length > 0, 'counted as refused');
    } finally { node.stop(); fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });
});
