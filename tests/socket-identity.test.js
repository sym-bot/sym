'use strict';

/**
 * R3-14 (0.14.3): a socket file's identity was its inode, device and `birthtimeMs`; a file system that
 * records no creation time (Linux without statx btime) reports 0 there, so two different files at a
 * reused inode compared equal — the old inode-reuse bug, back. A creation time of 0 is unknown now, and
 * the identity also holds the inode's change time and a token the daemon writes into the socket's times.
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const platform = require('../lib/platform');

/** fs.statSync answering for one path as a file system without birth times would, the inode reused. */
function withStat(fake, fn) {
  const real = fs.statSync;
  fs.statSync = function (p, opts) {
    if (p !== fake.path) return real.apply(fs, arguments);
    const f = fake.now();
    if (opts && opts.bigint) return { ino: BigInt(f.ino), dev: BigInt(f.dev), birthtimeNs: 0n, ctimeNs: BigInt(f.ctime) * 1000000n, mtimeNs: BigInt(f.mtime) * 1000000n };
    return { ino: f.ino, dev: f.dev, birthtimeMs: 0, ctimeMs: f.ctime, mtimeMs: f.mtime };
  };
  try { return fn(); } finally { fs.statSync = real; }
}

test('without birth times, another file at the same inode is not taken for the one a server made', () => {
  let file = { ino: 4242, dev: 7, ctime: 1000, mtime: 1000 };
  const fake = { path: '/no/such/dir/d.sock', now: () => file };
  withStat(fake, () => {
    const mine = platform.socketIdentity(fake.path);
    assert.equal(platform.socketIsStill(fake.path, mine), true, 'the same file is still the same file');
    file = { ino: 4242, dev: 7, ctime: 2000, mtime: 2000 }; // removed, and a new socket got the inode
    assert.equal(platform.socketIsStill(fake.path, mine), false, 'a new file at a reused inode is another file');
  });
});

test('stampSocket gives a socket file a token in its times that a later file at the path does not have', { skip: process.platform === 'win32' && 'no socket files' }, async () => {
  const net = require('net');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-stamp-'));
  const p = path.join(dir, 's.sock');
  const listen = () => new Promise((r) => { const s = net.createServer(); s.listen(p, () => r(s)); });
  try {
    const a = await listen();
    platform.stampSocket(p);
    const mine = platform.socketIdentity(p);
    assert.equal(platform.socketIsStill(p, mine), true);
    await new Promise((r) => a.close(r));
    const b = await listen(); // the next server at the same path, perhaps at the same inode
    assert.equal(platform.socketIsStill(p, mine), false);
    await new Promise((r) => b.close(r));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
