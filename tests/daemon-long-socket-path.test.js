'use strict';

/**
 * R3-6 (0.14.3): a daemon whose socket path is longer than a Unix socket address holds (104 bytes
 * with its NUL on macOS, 108 on Linux) was bound at a TRUNCATED path: its own checks (chmod, the
 * socket's identity, the stale-socket removal) looked at the full path and found nothing, so the
 * truncated socket outlived it and the next start of the same daemon could not listen. Such a path is
 * now mapped — the same way in the daemon and in every client — to a private directory of this user's
 * under /tmp (lib/platform.js unixEndpoint).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (cond, ms = 5000) => { for (let t = 0; t < ms && !cond(); t += 25) await sleep(25); return cond(); };

function startDaemon(home) {
  const env = { ...process.env, HOME: home, USERPROFILE: home, SYM_STATE_DIR: path.join(home, '.sym'), SYM_NODE_NAME: 'daemon-longpath-test',
    SYM_ROOM: 'longpath-room', SYM_RELAY_ONLY: '1', SYM_RELAY_URL: '', SYM_RELAY_TOKEN: '', SYM_SEMANTIC_ENCODER: 'off', SYM_SOCKET_CHECK_MS: '600000' };
  delete env.SYM_SOCKET;
  const d = spawn(process.execPath, [path.join(__dirname, '..', 'bin', 'sym-daemon.js')], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  const run = { d, out: '' };
  d.stdout.on('data', (b) => { run.out += b; });
  d.stderr.on('data', (b) => { run.out += b; });
  return run;
}
async function stopDaemon(run) {
  if (run.d.exitCode === null && run.d.signalCode === null) run.d.kill('SIGTERM');
  await new Promise((r) => (run.d.exitCode !== null || run.d.signalCode !== null ? r() : run.d.once('exit', r)));
}
const answers = (p) => new Promise((resolve) => {
  const c = net.createConnection(p);
  c.once('connect', () => { c.destroy(); resolve(true); });
  c.once('error', () => resolve(false));
});

describe('a socket path too long for a Unix socket (R3-6)', { skip: process.platform === 'win32' && 'named pipes have no path limit' }, () => {
  it('the daemon listens at the mapped path, and starts again after it stops', async () => {
    const { ipcEndpoint } = require('../lib/platform');
    const max = (process.platform === 'linux' ? 108 : 104) - 1; // sun_path, without its NUL
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-longpath-'));
    const home = path.join(base, 'x'.repeat(Math.max(1, max + 10 - base.length)));
    fs.mkdirSync(home, { recursive: true });
    const configured = path.join(home, '.sym', 'daemon.sock');
    assert.ok(Buffer.byteLength(configured) > max, `the path is too long (${Buffer.byteLength(configured)} bytes)`);
    const endpoint = ipcEndpoint(configured); // what the daemon and every client dial
    // Where a bind truncates it: sun_path with or without room for the NUL.
    const truncations = [max, max + 1].map((n) => Buffer.from(configured).subarray(0, n).toString());
    const runs = [];
    try {
      for (const label of ['first start', 'second start']) {
        const run = startDaemon(home);
        runs.push(run);
        const ready = await until(() => /sym-daemon ready/.test(run.out) || run.d.exitCode !== null, 20000);
        assert.ok(ready && run.d.exitCode === null, `${label}: the daemon is ready; log:\n${run.out.slice(-1500)}`);
        assert.strictEqual(await answers(endpoint), true, `${label}: it answers at the mapped path`);
        assert.deepStrictEqual(truncations.filter((t) => fs.existsSync(t)), [], `${label}: nothing was bound at a truncated path`);
        const dir = fs.statSync(path.dirname(endpoint));
        assert.strictEqual(dir.mode & 0o077, 0, 'the mapped directory is this user\'s alone');
        await stopDaemon(run);
        assert.strictEqual(fs.existsSync(endpoint), false, `${label}: its socket is gone after it stopped`);
      }
      assert.ok(Buffer.byteLength(endpoint) <= max && require('../lib/platform').isMappedIpcEndpoint(endpoint), `the endpoint is the mapped one (${endpoint})`);
    } finally {
      for (const r of runs) await stopDaemon(r);
      for (const t of truncations) { try { if (fs.lstatSync(t).isSocket()) fs.unlinkSync(t); } catch { /* none */ } }
      try { if (fs.lstatSync(endpoint).isSocket()) fs.unlinkSync(endpoint); } catch { /* none */ }
      fs.rmSync(base, { recursive: true, force: true });
    }
  });
});
