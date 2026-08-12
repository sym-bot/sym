"use strict";
/**
 * @module sym/core/mesh-node
 * @description MeshNode — Domain-agnostic mesh cognition node.
 *
 * Holds the local hidden state and delegates peer-state blending to a coupling
 * engine. The engine is INJECTED: any object honouring the nine-member contract
 * below may serve. Stock nodes run the open DefaultCoupler (§10 State Blending);
 * a consumer may wire in its own engine without this module naming it.
 *
 * The coupler contract, measured from the call sites in this file:
 *   couple, coherence, l2Distance, lastDecisions,
 *   updatePeer, removePeer, removeAllPeers, hasActivePeers, activePeerCount
 *
 * See MMP v0.2.0 Section 9: Coupling & SVAF.
 * See MMP v0.2.0 Section 10: State Blending.
 *
 * @license Apache-2.0
 * @copyright 2026 SYM.BOT Ltd
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.MeshNode = void 0;
const default_coupler_1 = require("./default-coupler");
const metrics_1 = require("./metrics");
class MeshNode {
    hiddenDim;
    config;
    coupler;
    metrics;
    localH1;
    localH2;
    /**
     * @param {object} [opts]
     * @param {number} [opts.hiddenDim=64] - Hidden state dimension.
     * @param {object} [opts.config] - Configuration passed to the default coupler.
     * @param {object} [opts.coupler] - Injected coupling engine (nine-member contract).
     *   When absent the open DefaultCoupler is used.
     */
    constructor(opts = {}) {
        this.hiddenDim = opts.hiddenDim ?? 64;
        this.config = { ...opts.config };
        this.coupler = opts.coupler ?? new default_coupler_1.DefaultCoupler(this.config);
        this.metrics = new metrics_1.KuramotoMetricsLogger();
        this.localH1 = new Array(this.hiddenDim).fill(0);
        this.localH2 = new Array(this.hiddenDim).fill(0);
    }
    /**
     * Update this node's local hidden state vectors.
     *
     * @param {number[]} h1 - First hidden state vector (must match hiddenDim).
     * @param {number[]} h2 - Second hidden state vector (must match hiddenDim).
     * @param {number} [confidence=0.5] - Confidence in the local state.
     * @returns {void}
     */
    updateLocalState(h1, h2, confidence = 0.5) {
        if (h1.length !== this.hiddenDim)
            throw new Error(`h1 dim mismatch: ${h1.length} != ${this.hiddenDim}`);
        if (h2.length !== this.hiddenDim)
            throw new Error(`h2 dim mismatch: ${h2.length} != ${this.hiddenDim}`);
        this.localH1 = [...h1];
        this.localH2 = [...h2];
    }
    /**
     * Compute coupled state by blending local state with accepted peers.
     *
     * See MMP v0.2.0 Section 10: State Blending.
     *
     * @returns {[number[], number[]]} Coupled [h1, h2] vectors.
     */
    coupledState() {
        const [h1, h2] = this.coupler.couple(this.localH1, this.localH2);
        if (this.coupler.hasActivePeers) {
            const distances = this.coupler.l2Distance(this.localH1, this.localH2);
            const r = this.coupler.coherence(this.localH1, this.localH2);
            const decisions = this.coupler.lastDecisions;
            const accepted = [...decisions.values()].filter(d => d.decision !== 'rejected');
            const effAlpha = accepted.length > 0
                ? accepted.reduce((s, d) => s + d.alpha, 0) / accepted.length
                : 0;
            this.metrics.log(this.coupler.activePeerCount, distances, r, effAlpha, decisions);
        }
        return [h1, h2];
    }
    /**
     * Register or update a peer's hidden state.
     *
     * @param {string} agentId - Unique peer identifier.
     * @param {number[]} h1 - Peer's first hidden state vector.
     * @param {number[]} h2 - Peer's second hidden state vector.
     * @param {number} confidence - Peer's state confidence.
     * @returns {void}
     */
    addPeer(agentId, h1, h2, confidence) {
        this.coupler.updatePeer(agentId, h1, h2, confidence);
    }
    /**
     * Remove a peer from the coupling set.
     *
     * @param {string} agentId - Peer identifier to remove.
     * @returns {void}
     */
    removePeer(agentId) {
        this.coupler.removePeer(agentId);
    }
    /**
     * Remove all peers from the coupling set.
     *
     * @returns {void}
     */
    removeAllPeers() {
        this.coupler.removeAllPeers();
    }
    /** @returns {number} Number of active (non-expired) peers. */
    get activePeerCount() { return this.coupler.activePeerCount; }
    /** @returns {boolean} Whether any active peers exist. */
    get hasActivePeers() { return this.coupler.hasActivePeers; }
    /** @returns {Map<string, object>} Latest coupling decisions per peer. */
    get couplingDecisions() { return this.coupler.lastDecisions; }
    /**
     * Mesh coherence, as reported by the coupling engine.
     * @returns {number|null}
     */
    get coherence() {
        return this.coupler.coherence(this.localH1, this.localH2);
    }
    /**
     * L2 distance between local state and weighted mesh aggregate.
     * @returns {[number, number]|null} [h1Distance, h2Distance] or null if no peers.
     */
    get l2Distance() {
        return this.coupler.l2Distance(this.localH1, this.localH2);
    }
    /**
     * Export all metrics entries as newline-delimited JSON.
     * @returns {string}
     */
    exportMetrics() {
        return this.metrics.exportJsonl();
    }
    /** @returns {number} Number of logged metrics entries. */
    get metricsCount() { return this.metrics.entryCount; }
}
exports.MeshNode = MeshNode;
