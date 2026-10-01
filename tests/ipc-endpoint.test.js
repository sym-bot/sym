'use strict';

require('./_isolate-home'); // sandbox HOME/USERPROFILE before anything reads os.homedir()

/**
 * The daemon's IPC endpoint, as the daemon and its clients resolve it.
 *
 * Windows has no Unix domain sockets at a filesystem path: a daemon told SYM_SOCKET=C:\...\d.sock
 * failed to listen (EACCES) and exited. On Windows a path must become a named pipe, and the
 * server and every client must turn the same path into the same pipe, or the CLI dials an
 * address nobody listens on. The mapping is a pure function of the path, so its Windows
 * behaviour is checked here on any platform; only the listen itself needs Windows.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { ipcEndpoint, isWindowsPipe, resolveSocketPath, getSocketPath } = require('../lib/platform');

const PIPE = /^\\\\\.\\pipe\\sym-[a-z0-9._-]+-[0-9a-f]{16}$/;

describe('ipcEndpoint', () => {
  it('on POSIX a socket path is used as given', () => {
    for (const platform of ['darwin', 'linux']) {
      assert.equal(ipcEndpoint('/tmp/x/d.sock', platform), '/tmp/x/d.sock');
    }
  });

  it('on Windows a filesystem path becomes a named pipe', () => {
    const pipe = ipcEndpoint('C:\\Users\\agent\\AppData\\Local\\Temp\\sym-relay-only-1\\d.sock', 'win32');
    assert.match(pipe, PIPE);
    assert.ok(isWindowsPipe(pipe));
  });

  it('the mapping is stable, and two spellings of one path reach one pipe', () => {
    const a = ipcEndpoint('C:\\Users\\Agent\\d.sock', 'win32');
    assert.equal(ipcEndpoint('C:\\Users\\Agent\\d.sock', 'win32'), a, 'same input, same pipe');
    assert.equal(ipcEndpoint('c:/users/agent/D.SOCK', 'win32'), a, 'case and slash direction do not matter on Windows');
    assert.equal(ipcEndpoint('C:\\Users\\Agent\\sub\\..\\d.sock', 'win32'), a, 'the path is resolved first');
  });

  it('two different paths never share a pipe', () => {
    assert.notEqual(ipcEndpoint('C:\\a\\d.sock', 'win32'), ipcEndpoint('C:\\b\\d.sock', 'win32'));
  });

  it('a name already in the pipe namespace is used as given', () => {
    for (const p of ['\\\\.\\pipe\\sym-daemon', '\\\\?\\pipe\\custom', '//./pipe/fwd']) {
      assert.ok(isWindowsPipe(p), p);
      assert.equal(ipcEndpoint(p, 'win32'), p);
    }
    assert.ok(!isWindowsPipe('C:\\pipe\\not-a-pipe'));
    assert.ok(!isWindowsPipe('\\\\.\\pipe\\'), 'the namespace alone names no pipe');
  });
});

describe('resolveSocketPath', () => {
  it('SYM_SOCKET goes through the mapping on every platform', () => {
    assert.equal(resolveSocketPath({ configured: '/s/d.sock', symDir: '/r', rooted: false, platform: 'linux' }), '/s/d.sock');
    assert.equal(resolveSocketPath({ configured: 'C:\\s\\d.sock', symDir: 'C:\\r', rooted: false, platform: 'win32' }),
      ipcEndpoint('C:\\s\\d.sock', 'win32'));
  });

  it('unset, POSIX uses <state root>/daemon.sock', () => {
    assert.equal(resolveSocketPath({ symDir: '/home/a/.sym', rooted: false, platform: 'darwin' }), '/home/a/.sym/daemon.sock');
  });

  it('unset and unrooted, Windows keeps its long-standing pipe', () => {
    assert.equal(resolveSocketPath({ symDir: 'C:\\Users\\a\\.sym', rooted: false, platform: 'win32' }), '\\\\.\\pipe\\sym-daemon');
  });

  it('unset and rooted, Windows gets a pipe of its own root, not the host-global one', () => {
    const a = resolveSocketPath({ symDir: 'D:\\tenant-a', rooted: true, platform: 'win32' });
    const b = resolveSocketPath({ symDir: 'D:\\tenant-b', rooted: true, platform: 'win32' });
    assert.match(a, PIPE);
    assert.notEqual(a, b);
    assert.notEqual(a, '\\\\.\\pipe\\sym-daemon');
  });
});

describe('the daemon and its clients agree on the endpoint', () => {
  it('SymDaemonClient dials the endpoint the daemon listens on, by default', () => {
    const { SymDaemonClient } = require('../lib/ipc-client');
    assert.equal(new SymDaemonClient()._socketPath, getSocketPath());
  });

  it('an explicit socketPath is resolved the way the daemon resolves SYM_SOCKET', () => {
    const { SymDaemonClient } = require('../lib/ipc-client');
    const p = path.join(__dirname, 'nowhere', 'd.sock');
    assert.equal(new SymDaemonClient({ socketPath: p })._socketPath, ipcEndpoint(p));
  });

  it('with SYM_SOCKET set, the daemon\'s resolution and the client\'s are the same endpoint', () => {
    const p = path.join(__dirname, 'nowhere', 'd.sock');
    const out = execFileSync(process.execPath, ['-e', `
      const { getSocketPath } = require(${JSON.stringify(require.resolve('../lib/platform'))});
      const { SymDaemonClient } = require(${JSON.stringify(require.resolve('../lib/ipc-client'))});
      console.log(JSON.stringify([getSocketPath(), new SymDaemonClient()._socketPath]));`],
    { env: { ...process.env, SYM_SOCKET: p }, encoding: 'utf8' });
    const [server, client] = JSON.parse(out);
    assert.equal(server, ipcEndpoint(p));
    assert.equal(client, server);
  });
});
