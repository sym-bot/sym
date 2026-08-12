'use strict';
/**
 * @module @sym-bot/core/state-root
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

module.exports = { SYM_STATE_DIR, IS_ROOTED, symPath, claudeProjectsDir };
