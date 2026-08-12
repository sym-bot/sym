"use strict";
/**
 * @module sym/core/metrics
 * @description Kuramoto Metrics Logger — Synchronization validation.
 *
 * Records per-coupling-step metrics: peer count, L2 distances,
 * order parameter, effective alpha, and per-peer decisions.
 * Exports as newline-delimited JSON for analysis.
 *
 * See MMP v0.2.0 Section 9: Coupling & SVAF.
 *
 * @license Apache-2.0
 * @copyright 2026 SYM.BOT Ltd
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.KuramotoMetricsLogger = void 0;

/**
 * Logs coupling metrics for synchronization analysis.
 */
class KuramotoMetricsLogger {
    entries = [];
    maxEntries;
    /**
     * @param {number} [maxEntries=10000] - Maximum number of entries to retain.
     */
    constructor(maxEntries = 10_000) {
        this.maxEntries = maxEntries;
    }
    /**
     * Log a coupling step's metrics.
     *
     * @param {number} peerCount - Number of active peers.
     * @param {[number, number]|null} l2Distances - [h1Distance, h2Distance] or null.
     * @param {number|null} orderParameter - Coherence metric (cosine or Kuramoto r(t)).
     * @param {number} effectiveAlpha - Weighted average coupling strength.
     * @param {Map<string, object>} decisions - Per-peer coupling decisions.
     * @returns {void}
     */
    log(peerCount, l2Distances, orderParameter, effectiveAlpha, decisions) {
        const entry = {
            timestamp: Date.now() / 1000,
            peerCount,
            h1L2Distance: l2Distances?.[0] ?? 0,
            h2L2Distance: l2Distances?.[1] ?? 0,
            orderParameter: orderParameter ?? 0,
            effectiveAlpha,
            decisions: [...decisions.values()].map(d => ({
                agentId: d.agentId.slice(0, 8),
                drift: d.drift,
                decision: d.decision,
                alpha: d.alpha,
                weight: d.weight,
            })),
        };
        this.entries.push(entry);
        if (this.entries.length > this.maxEntries) {
            this.entries = this.entries.slice(-this.maxEntries);
        }
    }
    /**
     * Export all entries as newline-delimited JSON.
     *
     * @returns {string} JSONL-formatted metrics.
     */
    exportJsonl() {
        return this.entries.map(e => JSON.stringify(e)).join('\n');
    }
    /** @returns {number} Number of logged entries. */
    get entryCount() {
        return this.entries.length;
    }
    /**
     * Get the most recent metrics entry.
     *
     * @returns {object|undefined} Latest entry, or undefined if empty.
     */
    get latest() {
        return this.entries[this.entries.length - 1];
    }
    /**
     * Clear all stored entries.
     *
     * @returns {void}
     */
    clear() {
        this.entries = [];
    }
}
exports.KuramotoMetricsLogger = KuramotoMetricsLogger;
