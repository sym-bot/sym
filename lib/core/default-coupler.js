'use strict';

/**
 * @module sym/core/default-coupler
 * @description DefaultCoupler — the open reference coupling engine.
 *
 * Implements MMP v0.2.0 Section 10 (State Blending) with confidence-weighted
 * averaging: the coupled state blends the local hidden state with the
 * confidence-weighted mean of active peer states. Coherence is the mean cosine
 * similarity between the local state and each active peer.
 *
 * This is the engine a stock node runs. A consumer may inject any object
 * honouring the same nine-member contract (see mesh-node.js) to substitute its
 * own coupling engine; this module neither knows nor needs to know what such an
 * engine does.
 *
 * @copyright 2026 SYM.BOT Ltd
 * @license Apache-2.0
 */

const { cosineSimilarity } = require('./cmb-encoder');

/** Peers older than this contribute nothing — a silent peer is not a coupled peer. */
const DEFAULT_PEER_TTL_MS = 120_000;

class DefaultCoupler {
  /**
   * @param {object} [config]
   * @param {number} [config.peerTtlMs=120000] - Age beyond which a peer state expires.
   * @param {number} [config.blendCap=0.5] - Maximum fraction of the coupled state
   *   contributed by peers, however many there are. The local state always keeps at
   *   least 1 − blendCap: a node's own cognition is never fully displaced (§10).
   */
  constructor(config = {}) {
    this._ttl = config.peerTtlMs ?? DEFAULT_PEER_TTL_MS;
    this._blendCap = config.blendCap ?? 0.5;
    this._peers = new Map(); // agentId -> { h1, h2, confidence, at }
    this._lastDecisions = new Map();
  }

  _active(now = Date.now()) {
    const out = [];
    for (const [id, p] of this._peers) {
      if (now - p.at <= this._ttl) out.push([id, p]);
    }
    return out;
  }

  updatePeer(agentId, h1, h2, confidence) {
    this._peers.set(agentId, {
      h1: [...h1],
      h2: [...h2],
      confidence: typeof confidence === 'number' ? Math.min(Math.max(confidence, 0), 1) : 1.0,
      at: Date.now(),
    });
  }

  removePeer(agentId) { this._peers.delete(agentId); this._lastDecisions.delete(agentId); }
  removeAllPeers() { this._peers.clear(); this._lastDecisions.clear(); }
  get activePeerCount() { return this._active().length; }
  get hasActivePeers() { return this.activePeerCount > 0; }
  get lastDecisions() { return this._lastDecisions; }

  /** Confidence-weighted mean of active peer states, or null with no peers. */
  _peerMean(now = Date.now()) {
    const active = this._active(now);
    if (active.length === 0) return null;
    const dim1 = active[0][1].h1.length;
    const dim2 = active[0][1].h2.length;
    const m1 = new Array(dim1).fill(0);
    const m2 = new Array(dim2).fill(0);
    let total = 0;
    for (const [, p] of active) {
      const w = p.confidence;
      if (p.h1.length !== dim1 || p.h2.length !== dim2) continue;
      for (let i = 0; i < dim1; i++) m1[i] += w * p.h1[i];
      for (let i = 0; i < dim2; i++) m2[i] += w * p.h2[i];
      total += w;
    }
    if (total <= 0) return null;
    return { h1: m1.map(x => x / total), h2: m2.map(x => x / total), total, active };
  }

  /**
   * Blend local state with the peer mean. The peer share grows with total peer
   * confidence but never exceeds blendCap.
   * @returns {[number[], number[]]}
   */
  couple(localH1, localH2) {
    const mean = this._peerMean();
    this._lastDecisions = new Map();
    if (!mean) return [[...localH1], [...localH2]];
    const alpha = Math.min(mean.total / (mean.total + 1), this._blendCap);
    for (const [id, p] of mean.active) {
      this._lastDecisions.set(id, { decision: 'accepted', alpha: alpha * (p.confidence / mean.total) });
    }
    const h1 = localH1.map((x, i) => (1 - alpha) * x + alpha * (mean.h1[i] ?? 0));
    const h2 = localH2.map((x, i) => (1 - alpha) * x + alpha * (mean.h2[i] ?? 0));
    return [h1, h2];
  }

  /** Mean cosine similarity between local state and each active peer, or null. */
  coherence(localH1, localH2) {
    const active = this._active();
    if (active.length === 0) return null;
    let sum = 0, n = 0;
    for (const [, p] of active) {
      if (p.h1.length !== localH1.length) continue;
      sum += cosineSimilarity(localH1, p.h1);
      n++;
    }
    return n > 0 ? sum / n : null;
  }

  /** L2 distance between local state and the peer mean, per hidden vector, or null. */
  l2Distance(localH1, localH2) {
    const mean = this._peerMean();
    if (!mean) return null;
    const l2 = (a, b) => Math.sqrt(a.reduce((s, x, i) => s + (x - (b[i] ?? 0)) ** 2, 0));
    return [l2(localH1, mean.h1), l2(localH2, mean.h2)];
  }
}

module.exports = { DefaultCoupler, DEFAULT_PEER_TTL_MS };
