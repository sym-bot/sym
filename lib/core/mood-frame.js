'use strict';

/**
 * @module sym/core/mood-frame
 * @description The `mood` control frame (MMP §9.3; control-frame.schema.json, MMP 2.0 update 1 by the
 * founder's ruling): `{ type, mood, context, timestamp }`, sealed on a confirmed Core Secure session.
 *
 *   mood       1 to 1,024 characters
 *   context    at most 4,096 characters, or null
 *   timestamp  the sender's clock, an integer, information only
 *
 * It names no sender: a receiver attributes it to the session's proven nodeId and name, so a frame
 * carrying `from` or `fromName` (the 0.13 shape, where a payload name labelled the event) is not this
 * frame. It carries no valence or arousal, and it is never stored, relayed or remixed. Characters are
 * counted as JSON Schema's maxLength counts them, in code points.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const { codePoints } = require('./record-canonical');

const MOOD_MAX = 1024;
const CONTEXT_MAX = 4096;
const MEMBERS = new Set(['type', 'mood', 'context', 'timestamp']);

/** Why `f` is not a mood frame, or null when it is one. */
function moodFrameReason(f) {
  if (!f || typeof f !== 'object' || Array.isArray(f) || f.type !== 'mood') return 'not a mood frame';
  for (const k of Object.keys(f)) if (!MEMBERS.has(k)) return `carries ${JSON.stringify(k.slice(0, 32))}, which the frame does not define`;
  if (typeof f.mood !== 'string' || f.mood.length === 0) return 'mood is not text';
  if (codePoints(f.mood) > MOOD_MAX) return `mood is over ${MOOD_MAX} characters`;
  if (!(f.context === undefined || f.context === null || typeof f.context === 'string')) return 'context is not text or null';
  if (typeof f.context === 'string' && codePoints(f.context) > CONTEXT_MAX) return `context is over ${CONTEXT_MAX} characters`;
  if (!(f.timestamp === undefined || (Number.isSafeInteger(f.timestamp) && f.timestamp >= 0))) return 'timestamp is not an integer';
  return null;
}

/**
 * The frame a node sends for `mood` and `context`, or a RangeError (`code` EMOODFRAME) naming what is
 * out of bounds: a node never sends a frame its peers refuse.
 */
function buildMoodFrame(mood, context, now = Date.now()) {
  const f = { type: 'mood', mood, context: context === undefined || context === '' ? null : context, timestamp: now };
  const why = moodFrameReason(f);
  if (why) { const e = new RangeError(`mood: ${why}`); e.code = 'EMOODFRAME'; throw e; }
  return f;
}

module.exports = { moodFrameReason, buildMoodFrame, MOOD_MAX, CONTEXT_MAX };
