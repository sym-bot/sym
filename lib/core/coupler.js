"use strict";
/**
 * @module @sym-bot/core/coupler
 * @description Mesh Coupler — Autonomous drift-bounded coupling engine.
 *
 * Provides the SemanticCoupler implementation for cosine-drift-based
 * state blending (shared memory, LLM agents).
 *
 * For CfC neural coupling with per-neuron time constants, see NeuralCoupler.
 *
 * See MMP v0.2.0 Section 9: Coupling & SVAF.
 * See MMP v0.2.0 Section 10: State Blending.
 * See MMP v0.2.0 Section 18: Configuration.
 *
 * @license Apache-2.0
 * @copyright 2026 SYM.BOT Ltd
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.SemanticCoupler = void 0;
exports.cosineSimilarity = cosineSimilarity;
const config_1 = require("./coupling-config");
/**
 * Semantic Coupler — cosine-drift-based state blending.
 *
 * Designed for embedding-based agents, shared memory, and LLM applications.
 * Uses uniform alpha across all neurons, modulated by per-neuron similarity.
 * Coherence metric is average pairwise cosine similarity (not Kuramoto r(t)).
 *
 * See MMP v0.2.0 Section 10: State Blending.
 */
class SemanticCoupler {
    config;
    peers = new Map();
    _lastDecisions = new Map();
    /**
     * @param {object} [config] - Coupling configuration (merged with DEFAULT_CONFIG).
     */
    constructor(config = {}) {
        this.config = { ...config_1.DEFAULT_CONFIG, ...config };
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
     * Compute coupled state by blending local state with accepted peers.
     *
     * Evaluates drift per peer, classifies as aligned/guarded/rejected,
     * then blends accepted peers using per-neuron similarity modulation.
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
        const decisions = new Map();
        const accepted = [];
        for (const [agentId, peer] of this.peers) {
            if (peer.h1.length !== dim || peer.h2.length !== dim)
                continue;
            const driftH1 = 1.0 - cosineSimilarity(localH1, peer.h1);
            const driftH2 = 1.0 - cosineSimilarity(localH2, peer.h2);
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
        // Per-neuron coupling
        const coupledH1 = new Array(dim);
        const coupledH2 = new Array(dim);
        for (let i = 0; i < dim; i++) {
            const simH1 = Math.abs(localH1[i]) > 1e-8 && Math.abs(meshH1[i]) > 1e-8
                ? 1.0 - Math.abs(localH1[i] - meshH1[i]) / Math.max(Math.abs(localH1[i]), Math.abs(meshH1[i]))
                : 0;
            const simH2 = Math.abs(localH2[i]) > 1e-8 && Math.abs(meshH2[i]) > 1e-8
                ? 1.0 - Math.abs(localH2[i] - meshH2[i]) / Math.max(Math.abs(localH2[i]), Math.abs(meshH2[i]))
                : 0;
            const a1 = effectiveAlpha * Math.max(simH1, 0);
            const a2 = effectiveAlpha * Math.max(simH2, 0);
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
     * Cosine coherence: average pairwise cosine similarity (not Kuramoto r(t)).
     *
     * @param {number[]} localH1 - Local first hidden state vector.
     * @param {number[]} localH2 - Local second hidden state vector.
     * @returns {number|null} Average cosine similarity, or null if no peers.
     */
    coherence(localH1, localH2) {
        this.pruneExpired();
        if (this.peers.size === 0)
            return null;
        const localVec = [...localH1, ...localH2];
        const localNorm = Math.sqrt(localVec.reduce((s, x) => s + x * x, 0));
        if (localNorm < 1e-8)
            return null;
        let totalR = 0;
        let count = 0;
        for (const peer of this.peers.values()) {
            if (peer.h1.length !== localH1.length)
                continue;
            const peerVec = [...peer.h1, ...peer.h2];
            const peerNorm = Math.sqrt(peerVec.reduce((s, x) => s + x * x, 0));
            if (peerNorm < 1e-8)
                continue;
            let dot = 0;
            for (let i = 0; i < localVec.length; i++)
                dot += localVec[i] * peerVec[i];
            totalR += dot / (localNorm * peerNorm);
            count++;
        }
        return count > 0 ? totalR / count : null;
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
exports.SemanticCoupler = SemanticCoupler;

/**
 * Compute cosine similarity between two vectors.
 *
 * @param {number[]} a - First vector.
 * @param {number[]} b - Second vector.
 * @returns {number} Cosine similarity in [-1, 1], or 0 if inputs are invalid.
 */
function cosineSimilarity(a, b) {
    if (a.length !== b.length || a.length === 0)
        return 0;
    let dot = 0, normA = 0, normB = 0;
    for (let i = 0; i < a.length; i++) {
        dot += a[i] * b[i];
        normA += a[i] * a[i];
        normB += b[i] * b[i];
    }
    const denom = Math.sqrt(normA) * Math.sqrt(normB);
    return denom > 1e-8 ? dot / denom : 0;
}
