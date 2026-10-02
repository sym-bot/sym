'use strict';
require('./_isolate-home');
/**
 * NEVER IN THE CLEAR, ON ANY TRANSPORT (Core Secure, sym 0.14). Until 0.14 a relay peer whose
 * handshake carried no E2E key was refused records (0.13.7), while a LAN peer without one still got
 * them in plaintext. A peer is now a confirmed §5.2 session, and a session seals every record
 * (cmb-encrypted) and every other frame (control-encrypted): there is no keyless peer, and the LAN
 * exception is gone. Checked on the wire of a LAN session and a relay session.
 */
const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const { connectNodes, until } = require('./_core-secure');

const SEALED_OR_HANDSHAKE = new Set(['client-hello', 'server-hello', 'client-finish', 'cmb-encrypted', 'control-encrypted', 'ping', 'pong']);

describe('never in the clear, on any transport', () => {
  for (const kind of ['bonjour', 'relay']) {
    it(`a ${kind} session carries no plaintext record and no category text`, async () => {
      const a = new SymNode({ name: `clear-a-${kind}-${Date.now()}`, silent: true, discovery: new NullDiscovery() });
      const b = new SymNode({ name: `clear-b-${kind}-${Date.now()}`, silent: true, discovery: new NullDiscovery() });
      const wire = [];
      await a.start(); await b.start();
      try {
        await connectNodes(a, b, { kind, tap: (f) => wire.push(f) });
        const heard = [];
        b.on('verified-record', (e) => heard.push(e));
        a.remember({ focus: 'the content no transport may carry in the clear' });
        a.broadcastMood('a mood is content too');
        await until(() => heard.length > 0);
        assert.strictEqual(heard.length, 1, 'the record arrived');
        assert.deepStrictEqual(wire.filter((f) => !SEALED_OR_HANDSHAKE.has(f.type)).map((f) => f.type), [], 'every frame after the handshake was sealed');
        const text = JSON.stringify(wire);
        assert.ok(!text.includes('the content no transport may carry'), 'no category text on the wire');
        assert.ok(!text.includes('a mood is content too'), 'no mood text on the wire');
        assert.strictEqual(a.peers().find((p) => p.peerId === b.nodeId).e2e, true);
      } finally {
        await a.stop(); await b.stop();
        for (const n of [a, b]) fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true });
      }
    });
  }
});
