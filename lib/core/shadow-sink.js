'use strict';

/**
 * @module @sym-bot/core/shadow-sink
 * @description Append-only sink for design C's shadow samples — the thing that makes a shadow
 * window measurable instead of merely computed.
 *
 * WHY THIS EXISTS. `computeShadowSample` produced a complete per-category record — δ^near, the floor
 * in effect, and `exactHeld` on declines — and the only consumer reduced it to five integers in a
 * log line before anything could read it. Every sample was computed and thrown away. Measured
 * against the registered analysis that left two of three predictions uncomputable:
 *
 *   P1 (novel_fraction)      counts were enough — this one survived the log line
 *   P2 (floor sensitivity)   needs per-category δ^near on ACCEPTED categories — discarded
 *   §5b.2 (source-controlled) needs the RECEIVING node — the log named only the sender
 *
 * The third is the one that matters most: a pooled estimate across nodes of unequal anchor
 * density is exactly the artefact that produced +0.220 pooled against −0.007 source-controlled
 * in an earlier study. Without the receiver on each row that correction cannot be applied at all.
 *
 * WHAT IT WRITES. One JSON object per admission, one per line, under ~/.sym/shadow/<node>.jsonl.
 * Numbers, booleans and node names only — never category text. A gating record must not become a
 * second copy of the mesh's content.
 *
 * IT MUST NEVER BREAK ADMISSION. This is instrumentation on the receive path. A full disk, a
 * read-only home or a permissions change must cost a sample, never a CMB — so every failure is
 * swallowed and counted rather than thrown. `droppedWrites()` exposes the count, because an
 * instrument that fails silently is the defect this whole exercise keeps finding.
 */
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const { symPath } = require('./state-root');
const SHADOW_DIR = symPath('shadow');

let dropped = 0;

/** Node names carry `@` and `-`; only separators are unsafe as a filename. */
const safeName = (name) => String(name || 'unknown').replace(/[/\\]/g, '_');

/**
 * Append one shadow sample.
 *
 * @param {object} opts
 * @param {string} opts.node    - the RECEIVING node — the stratification key, and the one the
 *                                log line never carried
 * @param {string} opts.from    - the sending peer
 * @param {string} opts.decision- what the ACTING gate (B) decided, so C can be compared against
 *                                the decision that was actually taken rather than to itself
 * @param {{floor:number, categories:object}} opts.sample - from `computeShadowSample`
 * @param {number} opts.at      - epoch ms
 * @returns {boolean} true if the row was written
 */
function appendShadowSample({ node, from, decision, sample, at }) {
  if (!sample || !sample.categories || Object.keys(sample.categories).length === 0) return false;
  try {
    fs.mkdirSync(SHADOW_DIR, { recursive: true });
    const row = {
      at: at ?? Date.now(),
      node,                       // receiver — §5b.2 source control depends on this being present
      from,
      decision,                   // B's verdict, the one that was acted on
      floor: sample.floor,
      categories: sample.categories,      // { category: { bit, dNear, exactHeld? } }
    };
    fs.appendFileSync(path.join(SHADOW_DIR, `${safeName(node)}.jsonl`), `${JSON.stringify(row)}\n`);
    return true;
  } catch {
    // A sample is worth less than a CMB. Count it and carry on.
    dropped += 1;
    return false;
  }
}

/** How many samples this process failed to persist. Reported, never inferred from silence. */
function droppedWrites() { return dropped; }

module.exports = { appendShadowSample, droppedWrites, SHADOW_DIR };
