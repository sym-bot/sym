"use strict";
/**
 * @module @sym-bot/core/neural-coupler
 * @description Neural Coupler — CfC per-neuron tau-modulated coupling with real Kuramoto r(t).
 *
 * Designed for applications running trained CfC (Closed-form Continuous-time)
 * neural networks on-device. Each neuron's coupling rate is modulated by its
 * learned time constant tau — fast neurons (small tau) couple readily, slow neurons
 * (large tau) couple conservatively.
 *
 * Coherence is measured using the true Kuramoto order parameter:
 *   r(t) = |<e^{i*theta}>| where theta = atan2(h2, h1) per neuron
 *
 * See MMP v0.2.0 Section 9: Coupling & SVAF.
 * See MMP v0.2.0 Section 10: State Blending.
 *
 * @license Apache-2.0
 * @copyright 2026 SYM.BOT Ltd
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.NeuralCoupler = void 0;
const config_1 = require("./coupling-config");
const coupler_1 = require("./coupler");
/**
 * Neural coupler with per-neuron tau-modulated coupling strength.
 *
 * Implements the same drift-bounded coupling as SemanticCoupler, but
 * modulates per-neuron alpha by K * sim / tau[i].
 */
class NeuralCoupler {
    config;
    tau;
    K;
    peers = new Map();
    _lastDecisions = new Map();
    /**
     * @param {object} config - Coupling configuration. Must include tau array.
     * @param {number[]} config.tau - Per-neuron time constants (length must match hiddenDim).
     * @param {number} [config.couplingRate=1.0] - Global coupling rate K.
     */
    constructor(config) {
        this.config = { ...config_1.DEFAULT_CONFIG, ...config, tau: [...config.tau] };
        this.tau = this.config.tau;
        this.K = config.couplingRate ?? 1.0;
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
    updatePeer(agentId, h1, h2, confidence) {
        this.peers.set(agentId, {
            h1: [...h1],
            h2: [...h2],
            confidence: Math.max(confidence, 0.01),
            timestamp: Date.now(),
        });
    }
    /**
     * Remove a peer from the coupling set.
     * @param {string} agentId
     * @returns {void}
     */
    removePeer(agentId) {
        this.peers.delete(agentId);
        this._lastDecisions.delete(agentId);
    }
    /**
     * Remove all peers from the coupling set.
     * @returns {void}
     */
    removeAllPeers() {
        this.peers.clear();
        this._lastDecisions.clear();
    }
    /** @returns {number} Number of active (non-expired) peers. */
    get activePeerCount() {
        this.pruneExpired();
        return this.peers.size;
    }
    /** @returns {boolean} Whether any active peers exist. */
    get hasActivePeers() {
        this.pruneExpired();
        return this.peers.size > 0;
    }
    /** @returns {Map<string, object>} Copy of latest coupling decisions. */
    get lastDecisions() {
        return new Map(this._lastDecisions);
    }
    /**
     * Compute tau-modulated coupled state.
     *
     * Per-neuron coupling: alpha_i = effectiveAlpha * K * sim_i / tau[i].
     * Fast neurons (small tau) couple readily; slow neurons (large tau) resist.
     *
     * See MMP v0.2.0 Section 10: State Blending.
     *
     * @param {number[]} localH1 - Local first hidden state vector.
     * @param {number[]} localH2 - Local second hidden state vector.
     * @returns {[number[], number[]]} Coupled [h1, h2] vectors.
     */
    couple(localH1, localH2) {
        this.pruneExpired();
        if (this.peers.size === 0)
            return [[...localH1], [...localH2]];
        const dim = localH1.length;
        if (this.tau.length !== dim) {
            throw new Error(`Tau dimension mismatch: tau[${this.tau.length}] vs hiddenDim[${dim}]`);
        }
        const decisions = new Map();
        const accepted = [];
        // Drift evaluation (same as semantic)
        for (const [agentId, peer] of this.peers) {
            if (peer.h1.length !== dim || peer.h2.length !== dim)
                continue;
            const driftH1 = 1.0 - (0, coupler_1.cosineSimilarity)(localH1, peer.h1);
            const driftH2 = 1.0 - (0, coupler_1.cosineSimilarity)(localH2, peer.h2);
            const drift = (driftH1 + driftH2) / 2.0;
            let decision;
            let alpha;
            if (drift <= this.config.driftThresholdAligned) {
                decision = 'aligned';
                alpha = this.config.alphaAligned;
            }
            else if (drift <= this.config.driftThresholdGuarded) {
                decision = 'guarded';
                alpha = this.config.alphaGuarded;
            }
            else {
                decision = 'rejected';
                alpha = 0;
            }
            const age = (Date.now() - peer.timestamp) / 1000;
            const recency = Math.exp(-this.config.temporalDecay * age);
            const weight = peer.confidence * (1.0 - drift) * recency;
            decisions.set(agentId, { agentId, drift, decision, alpha, weight, timestamp: Date.now() });
            if (decision !== 'rejected') {
                accepted.push({ peer, weight, alpha });
            }
        }
        this._lastDecisions = decisions;
        if (accepted.length === 0)
            return [[...localH1], [...localH2]];
        // Weighted mesh aggregate
        const meshH1 = new Array(dim).fill(0);
        const meshH2 = new Array(dim).fill(0);
        let totalWeight = 0;
        for (const { peer, weight } of accepted) {
            for (let i = 0; i < dim; i++) {
                meshH1[i] += peer.h1[i] * weight;
                meshH2[i] += peer.h2[i] * weight;
            }
            totalWeight += weight;
        }
        if (totalWeight <= 0)
            return [[...localH1], [...localH2]];
        for (let i = 0; i < dim; i++) {
            meshH1[i] /= totalWeight;
            meshH2[i] /= totalWeight;
        }
        // Effective alpha
        const alphaSum = accepted.reduce((s, a) => s + a.alpha * a.weight, 0);
        const weightSum = accepted.reduce((s, a) => s + a.weight, 0);
        const effectiveAlpha = weightSum > 0 ? alphaSum / weightSum : 0;
        // Per-neuron TAU-MODULATED coupling
        const coupledH1 = new Array(dim);
        const coupledH2 = new Array(dim);
        for (let i = 0; i < dim; i++) {
            const simH1 = Math.abs(localH1[i]) > 1e-8 && Math.abs(meshH1[i]) > 1e-8
                ? 1.0 - Math.abs(localH1[i] - meshH1[i]) / Math.max(Math.abs(localH1[i]), Math.abs(meshH1[i]))
                : 0;
            const simH2 = Math.abs(localH2[i]) > 1e-8 && Math.abs(meshH2[i]) > 1e-8
                ? 1.0 - Math.abs(localH2[i] - meshH2[i]) / Math.max(Math.abs(localH2[i]), Math.abs(meshH2[i]))
                : 0;
            const tauI = Math.max(this.tau[i], 0.01); // Prevent division by zero
            const a1 = Math.min(effectiveAlpha * this.K * Math.max(simH1, 0) / tauI, 1.0);
            const a2 = Math.min(effectiveAlpha * this.K * Math.max(simH2, 0) / tauI, 1.0);
            coupledH1[i] = (1.0 - a1) * localH1[i] + a1 * meshH1[i];
            coupledH2[i] = (1.0 - a2) * localH2[i] + a2 * meshH2[i];
        }
        return [coupledH1, coupledH2];
    }
    /**
     * Compute L2 distance between local state and weighted mesh aggregate.
     *
     * @param {number[]} localH1 - Local first hidden state vector.
     * @param {number[]} localH2 - Local second hidden state vector.
     * @returns {[number, number]|null} [h1Distance, h2Distance] or null if no peers.
     */
    l2Distance(localH1, localH2) {
        this.pruneExpired();
        if (this.peers.size === 0)
            return null;
        const dim = localH1.length;
        const meshH1 = new Array(dim).fill(0);
        const meshH2 = new Array(dim).fill(0);
        let totalW = 0;
        for (const peer of this.peers.values()) {
            if (peer.h1.length !== dim)
                continue;
            for (let i = 0; i < dim; i++) {
                meshH1[i] += peer.h1[i] * peer.confidence;
                meshH2[i] += peer.h2[i] * peer.confidence;
            }
            totalW += peer.confidence;
        }
        if (totalW <= 0)
            return null;
        for (let i = 0; i < dim; i++) {
            meshH1[i] /= totalW;
            meshH2[i] /= totalW;
        }
        let d1 = 0, d2 = 0;
        for (let i = 0; i < dim; i++) {
            d1 += (localH1[i] - meshH1[i]) ** 2;
            d2 += (localH2[i] - meshH2[i]) ** 2;
        }
        return [Math.sqrt(d1), Math.sqrt(d2)];
    }
    /**
     * Real Kuramoto order parameter: r(t) = |<e^{i*theta}>|.
     *
     * Extracts phase theta[i] = atan2(h2[i], h1[i]) per neuron for each oscillator
     * (local + all peers). Computes per-neuron phase coherence, then averages
     * across all neurons.
     *
     * r(t) = 1.0 means all oscillators are phase-locked.
     * r(t) approaching 0 means random phases (desynchronized).
     *
     * @param {number[]} localH1 - Local first hidden state vector.
     * @param {number[]} localH2 - Local second hidden state vector.
     * @returns {number|null} Kuramoto order parameter, or null if insufficient oscillators.
     */
    coherence(localH1, localH2) {
        this.pruneExpired();
        if (this.peers.size === 0)
            return null;
        const dim = localH1.length;
        const oscillators = [
            { h1: localH1, h2: localH2 },
        ];
        for (const peer of this.peers.values()) {
            if (peer.h1.length === dim && peer.h2.length === dim) {
                oscillators.push({ h1: peer.h1, h2: peer.h2 });
            }
        }
        if (oscillators.length < 2)
            return null;
        const N = oscillators.length;
        let rSum = 0;
        for (let i = 0; i < dim; i++) {
            let realSum = 0;
            let imagSum = 0;
            for (const osc of oscillators) {
                const theta = Math.atan2(osc.h2[i], osc.h1[i]);
                realSum += Math.cos(theta);
                imagSum += Math.sin(theta);
            }
            const rI = Math.sqrt((realSum / N) ** 2 + (imagSum / N) ** 2);
            rSum += rI;
        }
        return rSum / dim;
    }
    /**
     * Remove peers whose state has expired beyond peerRetentionSeconds.
     * @private
     */
    pruneExpired() {
        const now = Date.now();
        const maxAge = this.config.peerRetentionSeconds * 1000;
        for (const [id, peer] of this.peers) {
            if (now - peer.timestamp > maxAge) {
                this.peers.delete(id);
                this._lastDecisions.delete(id);
            }
        }
    }
}
exports.NeuralCoupler = NeuralCoupler;
