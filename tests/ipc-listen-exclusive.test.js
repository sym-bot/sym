'use strict';

/**
 * 0.14.0 release review B-F9: the daemon probed the socket path and then removed whatever file was
 * there, so two daemons starting together could each take the path from the other. It now binds
 * first, probes only a path that is taken, and removes a stale file only while it is still the file
 * it probed (lib/platform listenExclusive).
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

  it('a socket another server binds between the probe and the removal is never removed', async () => {
    const p = path.join(tmpdir('ipc-ex-'), 's.sock');
    fs.writeFileSync(p, '');   // stale when probed...
    const other = net.createServer();
    let probes = 0;
    const probe = async (addr) => {
      probes++;
      if (probes === 1) {
        // ...and in the window after the probe, another daemon removes it and binds the path.
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
});
