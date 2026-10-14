'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * R3-7 (0.14.3): every line reader did `buf += chunk.toString()`, decoding each chunk on its own, so a
 * multi-byte character split across two reads became U+FFFD — and the interior SIGNED the damaged
 * text and published it, and the daemon stored a task title the same way. Lines are now cut on bytes
 * and decoded whole (lib/line-reader.js), bounded in bytes, and a line that is not UTF-8 is refused
 * where the text would be signed or stored.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (cond, ms = 5000) => { for (let t = 0; t < ms && !cond(); t += 20) await sleep(20); return cond(); };
/** `line` (a string) as UTF-8 bytes cut inside the first occurrence of `ch`. */
function cutInside(line, ch, at = 1) {
  const bytes = Buffer.from(line, 'utf8');
  const i = bytes.indexOf(Buffer.from(ch, 'utf8')) + at;
  return [bytes.subarray(0, i), bytes.subarray(i)];
}
/** A client that writes `parts` 100 ms apart and collects JSON reply lines. */
function client(sockPath) {
  const replies = [];
  const c = net.createConnection(sockPath);
  let buf = '';
  c.setEncoding('utf8');
  c.on('data', (d) => { buf += d; let i; while ((i = buf.indexOf('\n')) !== -1) { replies.push(JSON.parse(buf.slice(0, i))); buf = buf.slice(i + 1); } });
  return {
    replies,
    ready: new Promise((r) => c.once('connect', r)),
    async send(parts) { for (const p of parts) { c.write(p); await sleep(100); } },
    end() { c.destroy(); },
  };
}

describe('lines are decoded whole: a character split across reads stays one character (R3-7)', () => {
  it('the line reader cuts on bytes, refuses invalid UTF-8 when strict, and bounds a line in bytes', () => {
    const { LineReader } = require('../lib/line-reader');
    const lines = [];
    const invalid = [];
    let overflow = null;
    const r = new LineReader({ strict: true, maxLineBytes: 12, onLine: (l) => lines.push(l), onInvalid: (b) => invalid.push(b.length), onOverflow: (n) => { overflow = n; } });
    const [a, b] = cutInside('会议\n', '议', 2);
    r.push(a); r.push(b);
    r.push(Buffer.from([0xff, 0xfe, 0x0a]));
    assert.deepStrictEqual(lines, ['会议']);
    assert.deepStrictEqual(invalid, [2]);
    r.push(Buffer.from('五个汉字五', 'utf8')); // 15 bytes, 5 characters: over a 12-byte bound
    assert.strictEqual(overflow, 15, 'the bound is in bytes, not characters');
    r.push(Buffer.from('more\n'));
    assert.deepStrictEqual(lines, ['会议'], 'and the reader takes nothing after an overflow');
  });

  it('the interior signs the text it was sent, not a damaged copy', async () => {
    const n = new SymNode({ name: `interior-utf8-${Date.now()}`, silent: true, discovery: new NullDiscovery() });
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-isock-'));
    let c = null;
    try {
      await n.start();
      const p = await n.interior().listen(path.join(dir, 'i.sock'));
      const { capability } = n.interior().startMind({ kinds: ['note'] });
      c = client(p);
      await c.ready;
      const focus = '决定：周五发布 0.14.3';
      await c.send(cutInside(JSON.stringify({ id: 1, type: 'submit', capability, kind: 'note', categories: { focus } }) + '\n', '周', 2));
      assert.ok(await until(() => c.replies.length > 0, 3000), 'answered');
      assert.strictEqual(c.replies[0].type, 'submitted', JSON.stringify(c.replies[0]));
      const e = n._store.get(c.replies[0].key);
      assert.strictEqual(e.cmb.categories.focus.text, focus, 'the signed focus is the submitted one');
      assert.ok(e.cmb.metadata.sig, 'and it is signed');
    } finally {
      if (c) c.end();
      await n.stop();
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true });
    }
  });

  it('the daemon stores the task title it was sent, not a damaged copy', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-d8-'));
    const sock = path.join(home, 'd.sock');
    const daemon = spawn(process.execPath, [path.join(__dirname, '..', 'bin', 'sym-daemon.js')], {
      env: { ...process.env, HOME: home, USERPROFILE: home, SYM_STATE_DIR: path.join(home, '.sym'), SYM_SOCKET: sock,
        SYM_NODE_NAME: 'daemon-utf8-test', SYM_ROOM: 'daemon-utf8-room', SYM_RELAY_ONLY: '1', SYM_RELAY_URL: '', SYM_RELAY_TOKEN: '', SYM_SEMANTIC_ENCODER: 'off' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    daemon.stdout.on('data', (b) => { out += b; });
    daemon.stderr.on('data', (b) => { out += b; });
    let c = null;
    try {
      assert.ok(await until(() => /sym-daemon ready/.test(out) || daemon.exitCode !== null, 20000) && daemon.exitCode === null, `the daemon started; log:\n${out.slice(-1500)}`);
      c = client(sock);
      await c.ready;
      const title = '会议纪要 — café ✓';
      await c.send(cutInside(JSON.stringify({ type: 'task-create', title }) + '\n', '议', 1));
      assert.ok(await until(() => c.replies.some((r) => r.action === 'task-create'), 3000), `answered: ${JSON.stringify(c.replies)}`);
      const got = c.replies.find((r) => r.action === 'task-create').task.title;
      assert.strictEqual(got, title);
      const onDisk = JSON.parse(fs.readFileSync(path.join(home, '.sym', 'tasks.json'), 'utf8')).tasks[0].title;
      assert.strictEqual(onDisk, title, 'and on disk');
    } finally {
      if (c) c.end();
      daemon.kill('SIGTERM');
      await new Promise((r) => (daemon.exitCode !== null || daemon.signalCode !== null ? r() : daemon.once('exit', r)));
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});
