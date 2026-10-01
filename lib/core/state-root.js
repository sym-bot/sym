'use strict';
/**
 * @module sym/core/state-root
 * @description The ONE place this engine decides where its state lives.
 *
 * WHY THIS EXISTS (measured, 2026-08-06): core derived FOUR store locations directly from
 * os.homedir() — ~/.sym/xmesh, ~/.sym/wake-keys, ~/.claude/projects — and
 * read no state-root variable anywhere. It was not that a store had been missed: the engine
 * had NO ROOT CONCEPT AT ALL, so there was nothing for a store to be missed *from*.
 *
 * The consequence was concrete. A test process that had carefully redirected every store in
 * the consuming repo still wrote engine telemetry into the operator's real home, because the
 * engine ships from a dependency and the consumer's structural guard scans its own repo, not
 * node_modules. A leak one layer below the scanned layer is invisible by construction.
 *
 * The memory path is rooted TOO, and that is a deliberate reversal of the implementer's
 * first instinct. Memory is MIND-STATE, and fresh-mind is registered discipline: a rooted run
 * that keeps the real memory directory hands run 1's memory to run 2 — the state-carry the
 * method forbids. It also closes a live write channel, since the memory bridge WRITES peer
 * memories into that directory; rooting it enforces "no rooted run writes real agent memory"
 * BY CONSTRUCTION rather than by a guard someone must remember to keep.
 *
 * Nothing moves for anyone who sets nothing: with SYM_STATE_DIR unset every path resolves
 * exactly where it did before, byte for byte.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');

/** The engine's state root. Everything under ~/.sym derives from here. */
const SYM_STATE_DIR = process.env.SYM_STATE_DIR || path.join(os.homedir(), '.sym');

/** True when a caller has deliberately re-rooted this process (i.e. an isolated run). */
const IS_ROOTED = Boolean(process.env.SYM_STATE_DIR);

/** Resolve a path inside the engine's state root. */
function symPath(...segments) {
  return path.join(SYM_STATE_DIR, ...segments);
}

/**
 * The agent-memory projects directory.
 *
 * It does NOT live under ~/.sym, so its derivation is stated explicitly rather than implied:
 * when the process is rooted, memory follows the root (as `<root>/claude-projects`) so an
 * isolated run gets a fresh mind and cannot write the operator's durable memory; when it is
 * not rooted, it is the real ~/.claude/projects, unchanged.
 */
function claudeProjectsDir() {
  return IS_ROOTED ? path.join(SYM_STATE_DIR, 'claude-projects') : path.join(os.homedir(), '.claude', 'projects');
}

/**
 * Under Node's test runner, refuse to start a node whose state would land outside a temp dir.
 *
 * WHY: a test that constructs a SymNode without first sandboxing HOME writes identities, private
 * keys, stores and locks into the developer's real ~/.sym — where they surface afterwards as
 * phantom agents in the operator's mesh, and where a test can read the real relay.env and its
 * API key. A per-file convention (require tests/_isolate-home.js first) cannot hold that line:
 * the file that forgets it is exactly the file that leaks, and nothing says so. Node's runner
 * sets NODE_TEST_CONTEXT in every test process (and its children inherit it), so the engine can
 * tell it is under test and check the one thing that matters: where it is about to write.
 *
 * Checked: the home directory (os.homedir() — HOME, USERPROFILE on Windows), because several
 * paths still derive from it directly (relay.env, the daemon's room and task files, agent
 * memory); the state root actually in effect, captured when this module loaded, so a test
 * that sandboxed HOME too late is caught; and SYM_IDENTITY_DIR when set, since that is where
 * the keypair goes. Each must resolve inside fs.realpathSync(os.tmpdir()) — through symlinks,
 * because macOS's /var/folders temp dir is a link to /private/var/folders.
 *
 * SYM_TEST_REAL_HOME=1 opts out, for a test that means to use the real home and says so.
 *
 * @throws {Error} code 'ETESTHOME'
 */
function assertTestSandbox() {
  if (!process.env.NODE_TEST_CONTEXT || process.env.SYM_TEST_REAL_HOME === '1') return;
  const tmp = realpathOfPath(os.tmpdir());
  const roots = [
    ['home directory (HOME / USERPROFILE)', os.homedir()],
    ['state root', SYM_STATE_DIR],
  ];
  if (process.env.SYM_IDENTITY_DIR) roots.push(['SYM_IDENTITY_DIR', process.env.SYM_IDENTITY_DIR]);
  const outside = roots.filter(([, dir]) => !isWithin(realpathOfPath(dir), tmp));
  if (!outside.length) return;
  const err = new Error(
    '[SYM] ETESTHOME: refusing to start a node under the Node test runner with its state outside a temp dir.\n' +
    outside.map(([what, dir]) => `  ${what}: ${dir}\n`).join('') +
    `  temp dir: ${tmp}\n\n` +
    '  Sandbox HOME and USERPROFILE to a temp dir before any lib module loads ' +
    "(require('./_isolate-home') as the first line of the test file), or this run writes " +
    'identities, keys and stores into the real ~/.sym. Set SYM_TEST_REAL_HOME=1 to opt out deliberately.'
  );
  err.code = 'ETESTHOME';
  throw err;
}

/** The real path of `p`, resolving through symlinks even when `p` itself does not exist yet. */
function realpathOfPath(p) {
  let head = path.resolve(p);
  const tail = [];
  for (;;) {
    try { return path.join(fs.realpathSync(head), ...tail); } catch { /* not there yet */ }
    const parent = path.dirname(head);
    if (parent === head) return path.resolve(p);
    tail.unshift(path.basename(head));
    head = parent;
  }
}

function isWithin(child, parent) {
  const fold = (s) => (process.platform === 'win32' ? s.toLowerCase() : s);
  const rel = path.relative(fold(parent), fold(child));
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

module.exports = { SYM_STATE_DIR, IS_ROOTED, symPath, claudeProjectsDir, assertTestSandbox };
