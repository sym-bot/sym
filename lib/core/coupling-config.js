"use strict";
/**
 * @module @sym-bot/core/coupling-config
 * @description Configuration for autonomous drift-bounded coupling.
 *
 * Default thresholds are derived from SVAF semantic drift research.
 * Tune empirically for your model's hidden state distribution.
 *
 * See MMP v0.2.0 Section 18: Configuration.
 * See MMP v0.2.0 Section 9: Coupling & SVAF.
 *
 * @license Apache-2.0
 * @copyright 2026 SYM.BOT Ltd
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEFAULT_CONFIG = void 0;

/**
 * Default coupling configuration.
 *
 * @type {{ driftThresholdAligned: number, driftThresholdGuarded: number, alphaAligned: number, alphaGuarded: number, temporalDecay: number, peerRetentionSeconds: number }}
 */
exports.DEFAULT_CONFIG = {
    driftThresholdAligned: 0.25,
    driftThresholdGuarded: 0.5,
    alphaAligned: 0.4,
    alphaGuarded: 0.15,
    temporalDecay: 0.05,
    peerRetentionSeconds: 300,
};
