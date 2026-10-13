'use strict';

/**
 * 0.13.17 review (R3), a regression in the hotfix itself. The hotfix made the daemon's IPC catch
 * name the failing message by printing `msg.type` in a template, unchecked; an IPC line whose type
 * is an object that cannot be turned into text ({"type":{"toString":1}}) made the catch throw,
 * which is uncaught, and the daemon exited (FATAL). An IPC message is now typed at the door as a
 * wire frame is: a JSON object with a string `type`, or it is refused with an error reply.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const until = async (cond, ms = 5000) => { for (let t = 0; t < ms && !cond(); t += 20) await new Promise((r) => setTimeout(r, 20)); };

/** Send IPC lines on one connection and collect the reply lines until `want` have arrived. */
function ipc(sock, lines, want) {
  return new Promise((resolve, reject) => {
    const replies = [];
    let buf = '';
    const c = net.createConnection(sock, () => { for (const l of lines) c.write(l + '\n'); });
    c.on('data', (d) => {
      buf += d;
      let i;
      while ((i = buf.indexOf('\n')) >= 0) { replies.push(JSON.parse(buf.slice(0, i))); buf = buf.slice(i + 1); }
      if (replies.length >= want) { c.end(); resolve(replies); }
    });
    c.on('error', reject);
    setTimeout(() => { c.destroy(); resolve(replies); }, 5000);
  });
}

describe('an IPC message is typed at the door (R3)', () => {
  it('a line whose type is not a string is refused with an error reply; the daemon stays up and answers the next one', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-daemon-ipc-'));
    const sock = path.join(home, 'd.sock');
    const daemon = spawn(process.execPath, [path.join(__dirname, '..', 'bin', 'sym-daemon.js')], {
      env: { ...process.env, HOME: home, USERPROFILE: home, SYM_STATE_DIR: path.join(home, '.sym'), SYM_SOCKET: sock,
        SYM_NODE_NAME: 'daemon-ipc-test', SYM_ROOM: 'daemon-ipc-room', SYM_RELAY_ONLY: '1', SYM_RELAY_URL: '', SYM_RELAY_TOKEN: '' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    daemon.stdout.on('data', (b) => { out += b; });
    daemon.stderr.on('data', (b) => { out += b; });
    try {
      await until(() => /sym-daemon ready/.test(out) || daemon.exitCode !== null, 15000);
      assert.strictEqual(daemon.exitCode, null, `the daemon started; log:\n${out.slice(-1500)}`);
      const replies = await ipc(sock, [
        JSON.stringify({ type: { toString: 1 } }),
        JSON.stringify({ type: 5 }),
        JSON.stringify(['type']),
        'not json',
        JSON.stringify({ type: 'xmesh-context' }),
      ], 5);
      await new Promise((r) => setTimeout(r, 300));
      assert.strictEqual(daemon.exitCode, null, `the daemon is still running; log:\n${out.slice(-1500)}`);
      assert.doesNotMatch(out, /FATAL/);
      assert.strictEqual(replies.length, 5, 'every line is answered');
      for (const r of replies.slice(0, 3)) assert.match(String(r.error), /JSON object with a string type/);
      assert.strictEqual(replies[3].error, 'not JSON');
      assert.strictEqual(replies[4].action, 'xmesh-context', 'and a well-typed request after them is served');
    } finally {
      daemon.kill('SIGTERM');
      await new Promise((r) => (daemon.exitCode !== null ? r() : daemon.once('exit', r)));
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});
