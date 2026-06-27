'use strict';

/**
 * Test isolation: redirect $HOME to a throwaway temp dir BEFORE any
 * `lib/config` load, so node data lands under a per-run sandbox instead of
 * the developer's real ~/.sym/nodes/. lib/config computes SYM_DIR from
 * process.env.HOME at module-load time, so this MUST be required first —
 * before `require('../lib/config')`, `../lib/node`, `../lib/memory-store`,
 * etc. Add `require('./_isolate-home');` as the first require in any test
 * file that constructs a SymNode or otherwise writes node state.
 *
 * Without this, every `npm test` leaked `test-*`/fixture node dirs into the
 * real mesh store, which then surfaced as phantom "agents" in mesh-edge.
 *
 * The sandbox is removed on process exit (node:test runs each file in its
 * own process, so one temp HOME per test file, cleaned when that file's
 * process exits).
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-test-home-'));
process.env.HOME = sandbox;

process.once('exit', () => {
  try {
    fs.rmSync(sandbox, { recursive: true, force: true });
  } catch {
    // best-effort cleanup; temp dir is reaped by the OS regardless
  }
});

module.exports = { sandbox };
