'use strict';

require('./_isolate-home'); // sandbox HOME/USERPROFILE before anything reads os.homedir()

/**
 * ETESTHOME — under Node's test runner a node will not start with its state outside a temp dir.
 *
 * A test file that forgot to sandbox HOME used to write identities, keys and stores into the
 * developer's real ~/.sym, silently. The runner sets NODE_TEST_CONTEXT in every test process
 * (children inherit it), so SymNode and the daemon now refuse that state root, and say how to
 * sandbox it; SYM_TEST_REAL_HOME=1 is the explicit way out.
 *
 * The "outside a temp dir" home used here is a scratch dir inside this checkout, created by no
 * one: the guard must throw before anything is written there, and the test checks that nothing
 * was. (If the checkout itself sits under the temp dir, there is no such place to point at and
 * those cases are skipped.)
 */

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');
const { assertTestSandbox } = require('../lib/core/state-root');
const { sandbox } = require('./_isolate-home');

const NODE = require.resolve('../lib/node');
const DAEMON = path.join(__dirname, '..', 'bin', 'sym-daemon.js');
const REAL_TMP = fs.realpathSync(os.tmpdir());
const outsideTmp = path.join(__dirname, '..', `.test-home-guard-${process.pid}`);
const checkoutInTmp = !path.relative(REAL_TMP, fs.realpathSync(path.join(__dirname, '..'))).startsWith('..');
const needsOutside = { skip: checkoutInTmp && 'this checkout is itself under the temp dir, so there is no non-temp path to test with' };

after(() => fs.rmSync(outsideTmp, { recursive: true, force: true }));

/** Construct a SymNode in a fresh process under `env`; report whether it threw, and with what. */
function constructIn(env) {
  const r = spawnSync(process.execPath, ['-e', `
    try {
      const n = new (require(${JSON.stringify(NODE)}).SymNode)({ name: 'guard-probe', silent: true });
      console.log(JSON.stringify({ ok: true, dir: n._dir }));
    } catch (e) { console.log(JSON.stringify({ ok: false, code: e.code, message: e.message })); }
    process.exit(0);`], { env, encoding: 'utf8', timeout: 30000 });
  const line = String(r.stdout).trim().split('\n').pop();
  assert.ok(line, `child produced no result: ${r.stderr}`);
  return JSON.parse(line);
}

const underTest = (over) => {
  const env = { ...process.env, NODE_TEST_CONTEXT: process.env.NODE_TEST_CONTEXT || 'child', ...over };
  delete env.SYM_TEST_REAL_HOME;
  if (!('SYM_STATE_DIR' in over)) delete env.SYM_STATE_DIR;
  if (!('SYM_IDENTITY_DIR' in over)) delete env.SYM_IDENTITY_DIR;
  return env;
};

describe('assertTestSandbox', () => {
  it('this test process is under the runner, and its sandboxed home passes', () => {
    assert.ok(process.env.NODE_TEST_CONTEXT, 'node --test sets NODE_TEST_CONTEXT');
    assert.doesNotThrow(() => assertTestSandbox());
  });

  it('a home outside the temp dir throws ETESTHOME, naming it and the way out', needsOutside, () => {
    const prev = { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE };
    process.env.HOME = outsideTmp;
    process.env.USERPROFILE = outsideTmp;
    try {
      assert.throws(() => assertTestSandbox(), (e) => {
        assert.equal(e.code, 'ETESTHOME');
        assert.ok(e.message.includes(outsideTmp), 'names the offending directory');
        assert.match(e.message, /HOME and USERPROFILE/);
        assert.match(e.message, /SYM_TEST_REAL_HOME=1/);
        return true;
      });
      process.env.SYM_TEST_REAL_HOME = '1';
      assert.doesNotThrow(() => assertTestSandbox(), 'the explicit opt-out');
    } finally {
      delete process.env.SYM_TEST_REAL_HOME;
      process.env.HOME = prev.HOME;
      process.env.USERPROFILE = prev.USERPROFILE;
    }
  });

  it('SYM_IDENTITY_DIR outside the temp dir is refused too: that is where the keypair goes', needsOutside, () => {
    process.env.SYM_IDENTITY_DIR = outsideTmp;
    try {
      assert.throws(() => assertTestSandbox(), (e) => e.code === 'ETESTHOME' && e.message.includes('SYM_IDENTITY_DIR'));
    } finally { delete process.env.SYM_IDENTITY_DIR; }
  });

  it('a temp dir reached through a symlink counts as the temp dir (macOS /var -> /private/var)', () => {
    const prev = process.env.HOME;
    try {
      for (const home of [sandbox, fs.realpathSync(sandbox), path.join(sandbox, 'not', 'made', 'yet')]) {
        process.env.HOME = home;
        if (process.platform === 'win32') process.env.USERPROFILE = home;
        assert.doesNotThrow(() => assertTestSandbox(), home);
      }
    } finally {
      process.env.HOME = prev;
      process.env.USERPROFILE = prev;
    }
  });

  it('outside the test runner nothing is checked', needsOutside, () => {
    const out = execFileSync(process.execPath, ['-e',
      `require(${JSON.stringify(require.resolve('../lib/core/state-root'))}).assertTestSandbox(); console.log('ok')`],
    { env: (() => { const e = { ...process.env, HOME: outsideTmp, USERPROFILE: outsideTmp }; delete e.NODE_TEST_CONTEXT; return e; })(), encoding: 'utf8' });
    assert.equal(out.trim(), 'ok');
  });
});

describe('SymNode construction', () => {
  it('throws ETESTHOME when HOME is not sandboxed — and writes nothing there', needsOutside, () => {
    const r = constructIn(underTest({ HOME: outsideTmp, USERPROFILE: outsideTmp }));
    assert.equal(r.ok, false, 'construction must be refused');
    assert.equal(r.code, 'ETESTHOME', r.message);
    assert.equal(fs.existsSync(outsideTmp), false, 'nothing was written to the unsandboxed home');
  });

  it('throws ETESTHOME when SYM_STATE_DIR is outside the temp dir, even with HOME sandboxed', needsOutside, () => {
    const r = constructIn(underTest({ SYM_STATE_DIR: path.join(outsideTmp, 'state') }));
    assert.equal(r.code, 'ETESTHOME', r.message);
    assert.ok(r.message.includes('state root'));
    assert.equal(fs.existsSync(outsideTmp), false);
  });

  it('constructs normally in a sandbox', () => {
    const r = constructIn(underTest({}));
    assert.equal(r.ok, true, r.message);
    assert.ok(r.dir.startsWith(sandbox), `the node lives in the sandbox: ${r.dir}`);
  });

  it('SYM_TEST_REAL_HOME=1 opts out deliberately', needsOutside, () => {
    const r = constructIn({ ...underTest({ HOME: outsideTmp, USERPROFILE: outsideTmp }), SYM_TEST_REAL_HOME: '1' });
    assert.equal(r.ok, true, r.message);
    assert.ok(fs.existsSync(path.join(outsideTmp, '.sym', 'nodes', 'guard-probe', 'identity.json')), 'and then it writes where it was told');
    fs.rmSync(outsideTmp, { recursive: true, force: true });
  });
});

describe('daemon start', () => {
  it('refuses to start with an unsandboxed home, and writes nothing there', needsOutside, () => {
    const r = spawnSync(process.execPath, [DAEMON], {
      env: underTest({ HOME: outsideTmp, USERPROFILE: outsideTmp, SYM_RELAY_ONLY: '1', SYM_NODE_NAME: 'guard-daemon',
        SYM_SOCKET: path.join(sandbox, 'guard.sock') }),
      encoding: 'utf8', timeout: 20000,
    });
    assert.notEqual(r.status, 0, `the daemon must not run; stdout:\n${r.stdout}`);
    assert.match(String(r.stderr), /ETESTHOME/);
    assert.equal(fs.existsSync(outsideTmp), false, 'nothing was written to the unsandboxed home');
  });
});
