'use strict';

/**
 * @module @sym-bot/core/liquid-timescale
 * @description Adaptive integration timescale for SVAF temporal decay.
 *
 * The SVAF memory readout weights past anchors by exp(-elapsedAge / tau). With a
 * FIXED tau that is a fixed-gain integrator, which is strictly suboptimal for a
 * latent that changes (the adaptive-timescale necessity: a fixed-gain filter is
 * strictly suboptimal, so an input-dependent timescale is required). The elapsed
 * age is already REAL time (gap-aware, never a step count), so what is missing is
 * only the adaptive timescale.
 *
 * This module makes tau ADAPTIVE: it shortens when the gate has lately been
 * GUARDING/REJECTING (the latent moved -> trust fresh input -> reactive) and
 * lengthens when admissions are ALIGNED/REDUNDANT (stable -> lean on history ->
 * smooth). The change detector is the gate's own decision stream, so the Level-1
 * content gate drives the Level-2 temporal timescale: the two levels couple
 * rather than collapse into one fixed knob. The decision is scale-normalized by
 * the gate's own thresholds, so the signal is path-robust across neural and
 * heuristic SVAF (raw drift magnitudes are not comparable across paths).
 *
 * Pure functions, no state.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

/**
 * Default change weights: only the gate's drift-flagged classes move the dial.
 * aligned = admitted on-topic, redundant = already known — neither is a shift;
 * guarded = the gate uneasy, rejected = foreign — both signal the latent moved.
 */
const DEFAULT_CHANGE_WEIGHTS = { aligned: 0, redundant: 0, guarded: 1, rejected: 1 };

/**
 * Change signal in [0, 1] from recent admission VERDICTS (the gate's
 * scale-normalized change measurement). 0 = stable (lean on history);
 * 1 = the latent just moved (lean on fresh input). Order-independent.
 *
 * @param {string[]} decisions  Recent SVAF decisions (any order).
 * @param {Object<string,number>} [weights=DEFAULT_CHANGE_WEIGHTS]
 * @returns {number}
 */
function changeSignalFromDecisions(decisions, weights = DEFAULT_CHANGE_WEIGHTS) {
  if (!decisions || decisions.length === 0) return 0;
  let sum = 0;
  for (const d of decisions) sum += weights[d] ?? 0;
  return Math.max(0, Math.min(1, sum / decisions.length));
}

/**
 * Adaptive integration timescale (seconds): the e-folding constant of the SVAF
 * decay, shrunk toward `minTau` as the change signal rises (high trust in the
 * latest input = short timescale = reactive). `reactivity` in [0, 1] — at 1 a
 * saturated change collapses tau toward `minTau`. With `changeSignal == 0` it
 * returns `baseTau` exactly, so a stable stream reproduces the fixed-tau path.
 *
 * @param {number} baseTau       Stable-regime e-folding constant (seconds).
 * @param {number} minTau        Floor — the most reactive the dial may go.
 * @param {number} changeSignal  In [0, 1].
 * @param {number} [reactivity=0.9]
 * @returns {number}
 */
function adaptiveTau(baseTau, minTau, changeSignal, reactivity = 0.9) {
  if (!(baseTau > 0)) return baseTau;
  const c = Math.max(0, Math.min(1, changeSignal));
  const shortened = baseTau * (1 - reactivity * c);
  return Math.max(minTau ?? baseTau, shortened);
}

/**
 * Graded decay in (0, 1] over REAL elapsed seconds (e-folding form, matching the
 * SVAF heuristic): exp(-elapsedSeconds / tau). An anchor at or after `now` keeps
 * full weight.
 *
 * @param {number} elapsedSeconds  Real elapsed time (now - anchor time), seconds.
 * @param {number} tau             e-folding constant (seconds).
 * @returns {number}
 */
function timeDecay(elapsedSeconds, tau) {
  if (!(tau > 0)) return elapsedSeconds <= 0 ? 1 : 0;
  if (elapsedSeconds <= 0) return 1;
  return Math.exp(-elapsedSeconds / tau);
}

module.exports = { DEFAULT_CHANGE_WEIGHTS, changeSignalFromDecisions, adaptiveTau, timeDecay };
