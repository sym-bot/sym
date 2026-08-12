'use strict';
require('./_isolate-home');

// sym/emit — the Class 1 emitter (§17.1) against a REAL node over REAL TCP:
// connect → §5.2 handshake → signed v1 `cmb` frame → SVAF admission on the
// receiver. This is the wire-compat proof for the thin emitter: nothing is
// injected into the frame handler; every byte crosses a socket.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');

const { SymNode } = require('../lib/node');
const { BonjourDiscovery } = require('../lib/discovery');
const { connect, emitOnce, parseServer } = require('../lib/emit');
const { verifyCMB } = require('../lib/core');
const { nodeDir } = require('../lib/config');

const ALIGNED = { decision: 'aligned', total_drift: 0.1, category_drifts: { focus: 0.1 }, gate_values: { g: 1 } };

/** A listening node with no mDNS (server-only discovery) on an ephemeral port. */
async function withReceiver(name, fn) {
  const node = new SymNode({
    name,
    silent: true,
    room: 'emit-g',
    discovery: new BonjourDiscovery({ mdns: false }),
  });
  node._svafEvaluator.evaluate = async () => ALIGNED; // deterministic admission
  await node.start();
  try {
    return await fn(node, node._port);
  } finally {
    await node.stop();
    fs.rmSync(nodeDir(name), { recursive: true, force: true });
  }
}

const once = (emitter, event, ms = 5000) => new Promise((resolve, reject) => {
  const t = setTimeout(() => reject(new Error(`timeout waiting for ${event}`)), ms);
  emitter.once(event, (v) => { clearTimeout(t); resolve(v); });
});

describe('sym/emit — MMP Class 1 emitter over real TCP', () => {
  it('parseServer accepts host:port and tcp://, rejects garbage', () => {
    assert.deepEqual(parseServer('127.0.0.1:52781'), { host: '127.0.0.1', port: 52781 });
    assert.deepEqual(parseServer('tcp://mesh.local:9'), { host: 'mesh.local', port: 9 });
    assert.throws(() => parseServer('no-port'));
    assert.throws(() => parseServer(':443'));
    assert.throws(() => parseServer('h:0'));
  });

  it('emitOnce delivers a signed v1 block the receiver admits', async () => {
    await withReceiver('emit-rx', async (node, port) => {
      const accepted = once(node, 'cmb-accepted');
      const { key, cmb } = await emitOnce(
        { server: `127.0.0.1:${port}`, room: 'emit-g', name: 'ci-emitter' },
        { focus: 'build 4821 green', intent: 'ground', commitment: 'verified: test suite passed' },
      );

      // v1 is identified by its 64-hex digest, not by which prefix it wears: the
      // cmb1- -> cmb- migration moves the spelling while the scheme is unchanged.
      assert.match(key, /^cmb1?-[0-9a-f]{64}$/, 'v1 content address (either prefix)');
      assert.equal(cmb.metadata.createdBy, 'ci-emitter');
      // `room` became `room` and moved into metadata in the same signing-scheme change — the
      // audience is signature-bound, so it belongs in the section the signature covers.
      assert.equal(cmb.metadata.room, 'emit-g', 'audience-bound to the authoring room');
      assert.equal(cmb.metadata.sigAlg, 'ed25519');

      const stored = await accepted;
      assert.equal((stored.cmb?.metadata ?? stored.cmb ?? stored).createdBy, 'ci-emitter', 'provenance is the emitter, not a resident node');
      assert.equal(stored.remixed, true, 'admitted into the receiver store as a remix');
    });
  });

  it('the emitted signature verifies against the emitter identity key (Class 1 §17.1)', async () => {
    await withReceiver('emit-rx2', async (node, port) => {
      const emitter = await connect({ server: `127.0.0.1:${port}`, room: 'emit-g', name: 'sensor-a' });
      try {
        assert.ok(emitter.peer && emitter.peer.nodeId, 'receiver handshake surfaced');
        const { cmb } = emitter.emit({ focus: 'temperature nominal' });
        const identity = JSON.parse(fs.readFileSync(`${nodeDir('sensor-a')}/identity.json`, 'utf8'));
        const v = verifyCMB(cmb, identity.publicKey);
        assert.deepEqual({ signed: v.signed, valid: v.valid }, { signed: true, valid: true });
      } finally {
        await emitter.close();
      }
    });
  });

  it('a session emits multiple blocks, including lineage-bearing grounding', async () => {
    await withReceiver('emit-rx3', async (node, port) => {
      const seen = [];
      node.on('cmb-accepted', (s) => seen.push(s));
      const emitter = await connect({ server: `127.0.0.1:${port}`, room: 'emit-g', name: 'ci-emitter' });
      try {
        const first = emitter.emit({ focus: 'deploy started' });
        const second = emitter.emit(
          { focus: 'deploy outcome', intent: 'ground', commitment: 'verified: deploy healthy' },
          { parents: [first.key] },
        );
        assert.notEqual(first.key, second.key);
        assert.deepEqual(second.cmb.metadata.lineage.parents, [first.key], 'grounding cites its parent');
        const deadline = Date.now() + 5000;
        while (seen.length < 2 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
        assert.equal(seen.length >= 2, true, `receiver admitted both (got ${seen.length})`);
      } finally {
        await emitter.close();
      }
    });
  });
});
