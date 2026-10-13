'use strict';

/**
 * 0.14.0 release review B-F11: the daemon and the CLI keep their room, pid file, relay.env and node
 * directory under the state root (SYM_STATE_DIR), but MeshAgent and llm-reason still read
 * ~/.sym/relay.env and LAN discovery still kept its loopback registry in ~/.sym/loopback. A rooted
 * deployment read another tenant's relay credentials and met other roots' nodes over 127.0.0.1.
 *
 * Run in a child process with HOME and SYM_STATE_DIR pointing at two different places, each holding
 * its own relay.env, so a reader that still derives its path from the home is caught by what it reads.
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('fs');
const path = require('path');
const { tmpdir } = require('./_tmpdir');

const LIB = path.join(__dirname, '..', 'lib');

test('relay.env and the loopback registry are read under the state root, not the home', () => {
  const base = tmpdir('sym-state-readers-');
  fs.mkdirSync(path.join(base, 'agent'));
  const home = path.join(base, 'home');
  const root = path.join(base, 'root');
  fs.mkdirSync(path.join(home, '.sym'), { recursive: true });
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(home, '.sym', 'relay.env'), 'SYM_RELAY_URL=ws://the-home\nSYM_LLM_API_KEY=from-the-home\n');
  fs.writeFileSync(path.join(root, 'relay.env'), 'SYM_RELAY_URL=ws://the-root\nSYM_LLM_API_KEY=from-the-root\n');
  const env = { ...process.env, HOME: home, USERPROFILE: home, SYM_STATE_DIR: root };
  for (const k of ['SYM_RELAY_URL', 'SYM_RELAY_TOKEN', 'SYM_LLM_API_KEY', 'NODE_TEST_CONTEXT']) delete env[k];
  const probe = `
    const lib = ${JSON.stringify(LIB)};
    const { MeshAgent } = require(lib + '/mesh-agent');
    const relay = process.env.SYM_RELAY_URL;           // read when the module loads
    delete process.env.SYM_RELAY_URL;
    const agent = new MeshAgent({ name: 'probe', agentDir: ${JSON.stringify(path.join(base, 'agent'))}, fetchDomain: async () => [], reason: async () => null, remix: async () => null });
    const relayAtStart = process.env.SYM_RELAY_URL;    // and again when an agent is built
    try { agent.node._releaseIdentityLock?.(); } catch {}
    delete process.env.SYM_LLM_API_KEY;
    try { require(lib + '/llm-reason').getProviderConfig({}); } catch {}
    const llm = process.env.SYM_LLM_API_KEY;
    const { BonjourDiscovery } = require(lib + '/discovery');
    const loopback = BonjourDiscovery.prototype._loopbackDir.call({});
    process.stdout.write('RESULT ' + JSON.stringify({ relay, relayAtStart, llm, loopback }) + String.fromCharCode(10));
    process.exit(0);
  `;
  const stdout = execFileSync(process.execPath, ['-e', probe], { env, encoding: 'utf8' });
  const out = JSON.parse(stdout.split('\n').find((l) => l.startsWith('RESULT ')).slice(7));
  assert.equal(out.relay, 'ws://the-root', "MeshAgent reads the root's relay.env when it loads");
  assert.equal(out.relayAtStart, 'ws://the-root', 'and when an agent is built');
  assert.equal(out.llm, 'from-the-root', "llm-reason reads the root's relay.env");
  assert.equal(out.loopback, path.join(root, 'loopback'), 'the loopback registry is under the root');
});
