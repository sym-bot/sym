'use strict';

/**
 * 0.14.0 release review B-F9: the daemon probed the socket path and then removed whatever file was
 * there, so two daemons starting together could each take the path from the other. It now binds
 * first, probes only a path that is taken, and removes a stale file holding a start lock, so the
 * starters decide one at a time (lib/platform listenExclusive).
 *
 * 0.14.1: the removal was first guarded by comparing the file's inode number with the one probed. Linux
 * gives a removed file's inode number to the next file at once, so the guard passed for a socket another
 * server had just bound, and CI (Linux) failed where a Mac (APFS) did not. The lock does not rest on it.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const net = require('net');
const fs = require('fs');
const path = require('path');
const { tmpdir } = require('./_tmpdir');
const { listenExclusive, socketAnswers } = require('../lib/platform');

const posix = process.platform !== 'win32';
const listen = (server, p) => new Promise((resolve, reject) => { server.once('error', reject); server.listen(p, resolve); });
const closeAll = (...servers) => Promise.all(servers.map((s) => new Promise((r) => (s.listening ? s.close(() => r()) : r()))));

describe('listening on an IPC path without taking it from another server', { skip: !posix && 'Unix socket paths only' }, () => {
  it('a free path is listened on', async () => {
    const p = path.join(tmpdir('ipc-ex-'), 's.sock');
    const s = net.createServer();
    assert.equal(await listenExclusive(s, p), 'listening');
    assert.equal(await socketAnswers(p), true);
    await closeAll(s);
  });

  it('a stale file nobody answers on is replaced', async () => {
    const p = path.join(tmpdir('ipc-ex-'), 's.sock');
    fs.writeFileSync(p, '');   // what a crashed daemon leaves
    const s = net.createServer();
    assert.equal(await listenExclusive(s, p), 'listening');
    assert.equal(await socketAnswers(p), true);
    await closeAll(s);
  });

  it('a path another server answers on is left to it', async () => {
    const p = path.join(tmpdir('ipc-ex-'), 's.sock');
    const other = net.createServer();
    await listen(other, p);
    const ino = fs.statSync(p).ino;
    const s = net.createServer();
    assert.equal(await listenExclusive(s, p), 'served');
    assert.equal(s.listening, false);
    assert.equal(fs.statSync(p).ino, ino, 'its socket file is untouched');
    assert.equal(await socketAnswers(p), true);
    await closeAll(other);
  });

  it('starters that meet a stale file decide one at a time: one binds, the rest serve it', async () => {
    const p = path.join(tmpdir('ipc-ex-'), 's.sock');
    fs.writeFileSync(p, '');   // stale
    let inFlight = 0;
    let maxInFlight = 0;
    const probe = async (addr) => {
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((r) => setTimeout(r, 20));   // the window another starter could use
      try { return await socketAnswers(addr); } finally { inFlight--; }
    };
    const servers = Array.from({ length: 8 }, () => net.createServer());
    const outcomes = await Promise.all(servers.map((s) => listenExclusive(s, p, { probe })));
    assert.equal(outcomes.filter((o) => o === 'listening').length, 1, 'exactly one starter binds');
    assert.equal(outcomes.filter((o) => o === 'served').length, 7, 'the rest find it answering and serve it');
    assert.equal(maxInFlight, 1, 'no two starters decide about the stale file at once');
    assert.equal(await socketAnswers(p), true, 'the path answers');
    assert.equal(fs.existsSync(`${p}.lock`), false, 'the lock is released');
    await closeAll(...servers);
  });

  it('a file is not removed while a live starter holds the lock', async () => {
    const p = path.join(tmpdir('ipc-ex-'), 's.sock');
    fs.writeFileSync(p, '');
    fs.mkdirSync(`${p}.lock`);
    fs.writeFileSync(path.join(`${p}.lock`, 'pid'), String(process.pid));   // alive: this process
    const s = net.createServer();
    await assert.rejects(listenExclusive(s, p, { lockWaitMs: 80, tries: 2 }), (e) => e.code === 'EADDRINUSE');
    assert.equal(fs.existsSync(p), true, 'the file stays: the lock was not ours to pass');
    assert.equal(fs.existsSync(`${p}.lock`), true, 'and the other starter keeps its lock');
  });

  it('a lock whose owner is gone is broken', async () => {
    const p = path.join(tmpdir('ipc-ex-'), 's.sock');
    fs.writeFileSync(p, '');
    const dead = require('child_process').spawnSync(process.execPath, ['-e', '0']).pid;   // exited: not a process now
    fs.mkdirSync(`${p}.lock`);
    fs.writeFileSync(path.join(`${p}.lock`, 'pid'), String(dead));
    const s = net.createServer();
    assert.equal(await listenExclusive(s, p, { lockWaitMs: 2000 }), 'listening');
    assert.equal(await socketAnswers(p), true);
    assert.equal(fs.existsSync(`${p}.lock`), false);
    await closeAll(s);
  });

  it('a lock that is old is broken even if its pid is a live process', async () => {
    const p = path.join(tmpdir('ipc-ex-'), 's.sock');
    fs.writeFileSync(p, '');
    fs.mkdirSync(`${p}.lock`);
    fs.writeFileSync(path.join(`${p}.lock`, 'pid'), String(process.pid));   // a pid that was reused
    const old = new Date(Date.now() - 60000);
    fs.utimesSync(`${p}.lock`, old, old);
    const s = net.createServer();
    assert.equal(await listenExclusive(s, p, { lockWaitMs: 2000 }), 'listening');
    assert.equal(fs.existsSync(`${p}.lock`), false);
    await closeAll(s);
  });

  it('a socket that answers is never removed, whoever asks', async () => {
    const p = path.join(tmpdir('ipc-ex-'), 's.sock');
    const other = net.createServer();
    await listen(other, p);
    const ino = fs.statSync(p).ino;
    const starters = Array.from({ length: 4 }, () => net.createServer());
    const outcomes = await Promise.all(starters.map((s) => listenExclusive(s, p)));
    assert.deepEqual(outcomes, ['served', 'served', 'served', 'served']);
    assert.equal(fs.statSync(p).ino, ino, 'its socket file is untouched');
    assert.equal(fs.existsSync(`${p}.lock`), false);
    await closeAll(other);
  });
});
