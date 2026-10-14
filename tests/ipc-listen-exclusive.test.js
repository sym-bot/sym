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
 *
 * 0.14.2: a review of the 0.14.1 lock (an XMesh review mission) found its holes, and they are held here:
 * the lock is a symbolic link carrying its owner (atomic, never half written); a holder checks it still
 * holds the lock, and probes again, right before it removes anything; a break that cannot succeed does not
 * spin; and the daemon's own check that a socket is still its own no longer rests on the inode number.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const net = require('net');
const fs = require('fs');
const path = require('path');
const { tmpdir } = require('./_tmpdir');
const { listenExclusive, socketAnswers, socketIdentity, socketIsStill } = require('../lib/platform');

const posix = process.platform !== 'win32';
const listen = (server, p) => new Promise((resolve, reject) => { server.once('error', reject); server.listen(p, resolve); });
// A start lock as a live starter leaves it: a link whose target is `<pid>:<token>`. (Not existsSync: a link whose
// target is no path is a dangling link, which existsSync reports as absent even while it is there.)
const lockAs = (p, owner) => fs.symlinkSync(owner, `${p}.lock`);
const lockOwner = (p) => { try { return fs.readlinkSync(`${p}.lock`); } catch { return null; } };
const old = (p) => { const t = new Date(Date.now() - 120000); fs.lutimesSync(`${p}.lock`, t, t); };
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
    assert.equal(lockOwner(p), null, 'the lock is released');
    await closeAll(...servers);
  });

  it('a file is not removed while a live starter holds the lock', async () => {
    const p = path.join(tmpdir('ipc-ex-'), 's.sock');
    fs.writeFileSync(p, '');
    lockAs(p, `${process.pid}:other`);   // alive: this process
    const s = net.createServer();
    await assert.rejects(listenExclusive(s, p, { lockWaitMs: 80, tries: 2 }), (e) => e.code === 'EADDRINUSE');
    assert.equal(fs.existsSync(p), true, 'the file stays: the lock was not ours to pass');
    assert.equal(lockOwner(p), `${process.pid}:other`, 'and the other starter keeps its lock');
  });

  it('a lock whose owner is gone is broken, and leaves no grave', async () => {
    const dir = tmpdir('ipc-ex-');
    const p = path.join(dir, 's.sock');
    fs.writeFileSync(p, '');
    const dead = require('child_process').spawnSync(process.execPath, ['-e', '0']).pid;   // exited
    assert.throws(() => process.kill(dead, 0), (e) => e.code === 'ESRCH', 'the pid was not reused before the test used it');
    lockAs(p, `${dead}:gone`);
    const s = net.createServer();
    assert.equal(await listenExclusive(s, p, { lockWaitMs: 2000 }), 'listening');
    assert.equal(await socketAnswers(p), true);
    assert.equal(lockOwner(p), null, 'the lock is released');
    assert.deepEqual(fs.readdirSync(dir).filter((f) => f.includes('.broken-')), [], 'and no grave is left beside it');
    await closeAll(s);
  });

  it('a lock that is old is broken even if its pid is a live process', async () => {
    const p = path.join(tmpdir('ipc-ex-'), 's.sock');
    fs.writeFileSync(p, '');
    lockAs(p, `${process.pid}:reused`);   // a pid that was reused
    old(p);
    const s = net.createServer();
    assert.equal(await listenExclusive(s, p, { lockWaitMs: 2000 }), 'listening');
    assert.equal(lockOwner(p), null);
    await closeAll(s);
  });

  it('the lock 0.14.1 made (a directory) is broken once it is old', async () => {
    const p = path.join(tmpdir('ipc-ex-'), 's.sock');
    fs.writeFileSync(p, '');
    fs.mkdirSync(`${p}.lock`);
    fs.writeFileSync(path.join(`${p}.lock`, 'pid'), String(process.pid));
    const t = new Date(Date.now() - 120000);
    fs.utimesSync(`${p}.lock`, t, t);
    const s = net.createServer();
    assert.equal(await listenExclusive(s, p, { lockWaitMs: 2000 }), 'listening');
    assert.equal(fs.existsSync(`${p}.lock`), false);
    await closeAll(s);
  });

  it('a break that cannot succeed gives up at the deadline and does not spin', async () => {
    const p = path.join(tmpdir('ipc-ex-'), 's.sock');
    fs.writeFileSync(p, '');
    lockAs(p, `${process.pid}:stuck`);
    old(p);   // stale, so every attempt tries to break it...
    const real = fs.renameSync;
    let renames = 0;
    fs.renameSync = () => { renames++; throw Object.assign(new Error('not permitted'), { code: 'EPERM' }); };   // ...and cannot (a sticky directory)
    let ticks = 0;
    const timer = setInterval(() => { ticks++; }, 10);
    try {
      const s = net.createServer();
      const t0 = Date.now();
      await assert.rejects(listenExclusive(s, p, { lockWaitMs: 150, tries: 1 }), (e) => e.code === 'EADDRINUSE');
      assert.ok(Date.now() - t0 < 2000, 'it gave up');
      assert.ok(ticks > 3, 'and the event loop kept running while it waited');
      assert.ok(renames < 100, `the break was tried at a wait's pace, not in a loop (${renames} tries)`);
    } finally { clearInterval(timer); fs.renameSync = real; }
    assert.equal(fs.existsSync(p), true, 'nothing was removed');
  });

  it('a start whose lock was taken from it removes nothing and does not remove the new lock', async () => {
    const p = path.join(tmpdir('ipc-ex-'), 's.sock');
    fs.writeFileSync(p, '');
    let calls = 0;
    const probe = async () => {
      calls++;
      if (calls === 1) {   // while this start decides, its lock is taken away and another start takes it
        fs.unlinkSync(`${p}.lock`);
        lockAs(p, `${process.pid}:thief`);
      }
      return false;
    };
    const s = net.createServer();
    await assert.rejects(listenExclusive(s, p, { probe, lockWaitMs: 80, tries: 1 }), (e) => e.code === 'EADDRINUSE');
    assert.equal(fs.existsSync(p), true, 'it did not remove the file on a lock it no longer held');
    assert.equal(lockOwner(p), `${process.pid}:thief`, 'and it did not remove the lock that is now another start\'s');
  });

  it('a socket bound by a start that takes no lock, between the probe and the removal, is not removed', async () => {
    const p = path.join(tmpdir('ipc-ex-'), 's.sock');
    fs.writeFileSync(p, '');   // stale when probed...
    const other = net.createServer();
    let probes = 0;
    const probe = async (addr) => {
      probes++;
      if (probes === 1) {   // ...and in the window after the probe, a daemon that predates the lock removes it and binds
        fs.unlinkSync(addr);
        await listen(other, addr);
        return false;
      }
      return socketAnswers(addr);
    };
    const s = net.createServer();
    assert.equal(await listenExclusive(s, p, { probe }), 'served', 'the other server keeps the path');
    assert.equal(s.listening, false);
    assert.equal(await socketAnswers(p), true, 'and still answers on it');
    await closeAll(other);
  });

  it('a socket that answers is never removed, whoever asks', async () => {
    const p = path.join(tmpdir('ipc-ex-'), 's.sock');
    const other = net.createServer();
    await listen(other, p);
    const identity = socketIdentity(p);
    let sawLock = 0;
    const probe = async (addr) => { if (lockOwner(p) !== null) sawLock++; return socketAnswers(addr); };
    const starters = Array.from({ length: 4 }, () => net.createServer());
    const outcomes = await Promise.all(starters.map((s) => listenExclusive(s, p, { probe })));
    assert.deepEqual(outcomes, ['served', 'served', 'served', 'served']);
    assert.equal(socketIsStill(p, identity), true, 'its socket file is untouched');
    assert.equal(sawLock, 4, 'each start probed holding the lock');
    assert.equal(lockOwner(p), null, 'and released it');
    await closeAll(other);
  });
});

describe('knowing whether a socket file is still the one a server made', { skip: !posix && 'Unix socket paths only' }, () => {
  it('a file made in place of a removed one is not the same, even if the file system reuses the inode number', async () => {
    const p = path.join(tmpdir('ipc-id-'), 's.sock');
    const first = net.createServer();
    await listen(first, p);
    const identity = socketIdentity(p);
    assert.equal(socketIsStill(p, identity), true);
    await closeAll(first);   // closing removes the path
    await new Promise((r) => setTimeout(r, 25));   // two files made apart in time, as a restart makes them
    const second = net.createServer();
    await listen(second, p);
    assert.equal(socketIsStill(p, identity), false, 'the file at the path is another server\'s');
    await closeAll(second);
  });

  it('no file is no identity, and an identity of nothing is never still', () => {
    const p = path.join(tmpdir('ipc-id-'), 'absent.sock');
    assert.equal(socketIdentity(p), null);
    assert.equal(socketIsStill(p, null), false);
  });
});
