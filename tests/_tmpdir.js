'use strict';

/**
 * A temp directory that does not outlive the test process.
 *
 * `fs.mkdtempSync` alone leaks: nothing reaps $TMPDIR on macOS between reboots, and a suite
 * that makes a handful of scratch dirs per run left six figures of them on a developer
 * machine that runs `npm test` on every change — enough to fill the disk (ENOSPC, 2026-09-03).
 *
 * `tmpdir(prefix)` creates the dir and removes it when the process exits. node:test runs
 * each file in its own process, so every scratch dir a file makes is gone when that file
 * finishes — pass or fail. Use this instead of `fs.mkdtempSync(path.join(os.tmpdir(), …))`
 * in tests; `_isolate-home.js` covers $HOME the same way.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const made = [];

process.once('exit', () => {
  for (const dir of made) {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

function tmpdir(prefix) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  made.push(dir);
  return dir;
}

module.exports = { tmpdir };
