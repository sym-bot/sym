'use strict';

require('../_isolate-home'); // sandbox HOME: node state must never land in the real ~/.sym

/**
 * Design D7 against a REAL 0.13.17 node (the release this one replaces), over the LAN and over the
 * relay. The 0.13.17 node runs in a child process from a 0.13.17 checkout (SYM_013_DIR, default
 * ~/code/wt/sym-0.13.17) with its own sandboxed HOME and SYM_STATE_DIR, so neither node touches
 * ~/.sym. The 0.14 node reaches it only through a configured Legacy Import route:
 *   - the 0.14 node dials the route (LAN) or sends its legacy hello (relay); it never accepts one;
 *   - a directed 0.13.17 record is delivered here, quarantined (verified: false, legacy-import);
 *   - a directed 0.14 record reaches 0.13.17 as a legacy E2E cmb, and 0.13.17 verifies and delivers it;
 *   - a 0.13.17 node with no route that dials this node is refused.
 *
 *   npm run test:integration   (skipped when no 0.13.17 checkout is present)
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { SymNode } = require('../../lib/node');
const { NullDiscovery } = require('../../lib/discovery');
const { nodeDirById } = require('../../lib/config');
const { fakeRelay } = require('../_fake-relay');
const { until } = require('../_core-secure');

// The 0.13.17 checkout: SYM_013_DIR, or the sibling worktree of this one (…/wt/sym-0.13.17).
const DIR = process.env.SYM_013_DIR || path.resolve(__dirname, '..', '..', '..', 'sym-0.13.17');
const PRESENT = fs.existsSync(path.join(DIR, 'lib', 'node.js'));
const CATS = (focus) => ({ focus, issue: 'legacy import interop', intent: 'reach a 0.13.17 node', motivation: 'D7', commitment: 'none', perspective: 'test', mood: { text: 'calm', valence: 0, arousal: 0 } });

/** Start a 0.13.17 node in a child, sandboxed; it reports itself and every delivery as JSON lines. */
function start013({ relay, token, room = 'lg-room' } = {}) {
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-013-home-'));
  const script = path.join(sandbox, 'run-013.js');
  fs.writeFileSync(script, `
    'use strict';
    const DIR = ${JSON.stringify(DIR)};
    const { SymNode } = require(DIR + '/lib/node');
    const { BonjourDiscovery, NullDiscovery } = require(DIR + '/lib/discovery');
    const relay = ${JSON.stringify(relay || null)};
    const node = new SymNode({ name: 'legacy-013-' + process.pid, silent: true, room: ${JSON.stringify(room)},
      discovery: relay ? new NullDiscovery() : new BonjourDiscovery({ mdns: false }),
      ...(relay ? { relay, relayToken: ${JSON.stringify(token || '')}, relayOnly: true } : {}) });
    const out = (o) => process.stdout.write(JSON.stringify(o) + '\\n');
    node.on('cmb-accepted', (e) => out({ event: 'accepted', content: e.content, directed: !!e.directed }));
    node.on('metric', (m) => { if (/signature|legacy/.test(m.type)) out({ event: 'metric', m }); });
    node.start().then(() => out({ event: 'ready', nodeId: node.nodeId, publicKey: node._identity.publicKey, e2ePublicKey: node._e2eKeyPair.publicKey.toString('base64'), port: node._port, version: require(DIR + '/package.json').version }));
    let buf = '';
    process.stdin.on('data', (d) => {
      buf += d; let i;
      while ((i = buf.indexOf('\\n')) !== -1) {
        const cmd = JSON.parse(buf.slice(0, i)); buf = buf.slice(i + 1);
        if (cmd.cmd === 'remember') { const e = node.remember(cmd.categories, { to: cmd.to }); out({ event: 'remembered', key: e && e.key }); }
        if (cmd.cmd === 'dial') node._connectToPeer('127.0.0.1', cmd.port, cmd.peerId, 'core-secure');
        if (cmd.cmd === 'stop') node.stop().then(() => process.exit(0));
      }
    });
  `);
  const child = spawn(process.execPath, [script], {
    env: { ...process.env, HOME: sandbox, USERPROFILE: sandbox, SYM_STATE_DIR: path.join(sandbox, '.sym'), NODE_TEST_CONTEXT: '' },
    stdio: ['pipe', 'pipe', 'inherit'],
  });
  const events = [];
  let buf = '';
  child.stdout.on('data', (d) => {
    buf += d; let i;
    while ((i = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, i); buf = buf.slice(i + 1);
      try { events.push(JSON.parse(line)); } catch { /* not ours */ }
    }
  });
  const send = (o) => child.stdin.write(JSON.stringify(o) + '\n');
  return {
    events, send, child,
    ready: async () => { await until(() => events.some((e) => e.event === 'ready'), 15000); return events.find((e) => e.event === 'ready'); },
    stop: async () => { try { send({ cmd: 'stop' }); } catch { /* */ } await new Promise((r) => { child.once('exit', r); setTimeout(() => { child.kill('SIGKILL'); r(); }, 4000); }); fs.rmSync(sandbox, { recursive: true, force: true }); },
  };
}

async function stop14(n) { try { await n.stop(); } catch { /* */ } try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ } }

describe('Legacy Import against a real 0.13.17 node', { skip: PRESENT ? false : `no 0.13.17 checkout at ${DIR}` }, () => {
  it('over the LAN: an outbound route, records both ways, quarantined here; no route means refused', async () => {
    const legacy = start013();
    const ready = await legacy.ready();
    assert.match(ready.version, /^0\.13\./);
    const node = new SymNode({
      name: `core-secure-${process.pid}`, silent: true, room: 'lg-room',
      discovery: new (require('../../lib/discovery').BonjourDiscovery)({ mdns: false }),
      // The route pins the 0.13.17 node's identity key and its persistent X25519 key (security review E).
      legacyRoutes: [{ nodeId: ready.nodeId, endpoint: `127.0.0.1:${ready.port}`, key: ready.publicKey, e2eKey: ready.e2ePublicKey }],
    });
    try {
      await node.start();
      await until(() => node._peers.has(ready.nodeId), 15000);
      assert.strictEqual(node.status().legacyImport.sessions.length, 1, 'a Legacy Import session over the route');
      // 0.13.17 → 0.14, directed: delivered here, quarantined.
      const got = [];
      node.on('legacy-record', (e) => got.push(e)); // quarantined: never a Core Secure delivery
      legacy.send({ cmd: 'remember', categories: CATS('from 0.13.17 to core secure'), to: node.nodeId });
      await until(() => got.length > 0, 15000);
      assert.strictEqual(got[0].verified, false);
      assert.strictEqual(got[0].profile, 'legacy-import');
      // 0.14 → 0.13.17, directed: 0.13.17 verifies the v2.0 record against this node's key and delivers it.
      node.remember(CATS('from core secure to 0.13.17'), { to: ready.nodeId });
      await until(() => legacy.events.some((e) => e.event === 'accepted' && /from core secure/.test(e.content)), 15000);
      assert.ok(legacy.events.some((e) => e.event === 'accepted' && /from core secure/.test(e.content)), '0.13.17 delivered it');
      assert.ok(!legacy.events.some((e) => e.event === 'metric' && e.m.type === 'cmb-signature-rejected'), '0.13.17 did not refuse its signature');
      // A 0.13.17 node with no route that dials this node is refused at the listener.
      const before = node._sessionStats.legacyHellosRefused;
      const other = start013();
      const r2 = await other.ready();
      other.send({ cmd: 'dial', port: node._port, peerId: node.nodeId });
      await until(() => node._sessionStats.legacyHellosRefused > before, 10000);
      assert.ok(node._sessionStats.legacyHellosRefused > before);
      assert.strictEqual(node._peers.has(r2.nodeId), false);
      await other.stop();
    } finally { await stop14(node); await legacy.stop(); }
  });

  it('over the relay: this node sends its legacy hello to the routed node; records both ways', async () => {
    const relay = fakeRelay();
    const token = 't'.repeat(40);
    const legacy = start013({ relay: relay.url, token });
    const ready = await legacy.ready();
    const node = new SymNode({
      name: `core-secure-relay-${process.pid}`, silent: true, room: 'lg-room', relayOnly: true, discovery: new NullDiscovery(),
      relay: relay.url, relayToken: token,
      legacyRoutes: [{ nodeId: ready.nodeId, endpoint: 'relay', key: ready.publicKey, e2eKey: ready.e2ePublicKey }],
    });
    try {
      await node.start();
      await until(() => node._peers.has(ready.nodeId), 15000);
      assert.strictEqual(node.status().legacyImport.sessions[0].transport, 'relay');
      const got = [];
      node.on('legacy-record', (e) => got.push(e)); // quarantined: never a Core Secure delivery
      legacy.send({ cmd: 'remember', categories: CATS('over the relay from 0.13.17'), to: node.nodeId });
      await until(() => got.length > 0, 15000);
      assert.strictEqual(got[0].profile, 'legacy-import');
      node.remember(CATS('over the relay from core secure'), { to: ready.nodeId });
      await until(() => legacy.events.some((e) => e.event === 'accepted' && /from core secure/.test(e.content)), 15000);
      assert.ok(legacy.events.some((e) => e.event === 'accepted' && /from core secure/.test(e.content)));
    } finally { await stop14(node); await legacy.stop(); await relay.close(); }
  });
});
