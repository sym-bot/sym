'use strict';

/**
 * @module @sym-bot/sym/attestation-store
 * @description Per-node Admission Attestation index (MMP admission-attestation layer).
 *
 * Holds the signed gating attestations this node has produced and (in the gossip
 * phase) received from roster peers. Two indexes:
 *   - by `of` (gated CMB key) → the audit trail for that CMB: every receiver's
 *     per-category verdict about it.
 *   - by `by` (attester nodeId) → that attester's hash-chain, keyed by `seq`, so a
 *     dropped attestation is a detectable gap (omission-evidence, LOCAL half;
 *     anchored checkpoints add the cross-node half in a later step).
 * Deduplicated by signature (idempotent record / relay-once). Bounded by count.
 *
 * Checkpoints and witnesses are deduplicated by WHAT they assert, not by signature: one checkpoint
 * per (attester, position) and one witness per (attester, position, witness). A node that witnessed
 * a checkpoint again after a restart signed a second copy of the same statement; keeping only the
 * latest copy made the two copies new to each other forever, so every node stored and relayed each
 * one again whenever the other arrived (the witness storm). A later copy of a held statement is a
 * duplicate; one asserting a different root for a held position is a conflict, not stored (the first
 * copy stays the one relayed), and the position is remembered as conflicted. Positions are integers:
 * the signed payload spells a position as text, so `8` and `"8"` verify alike and must not be two.
 * A witness is stored only for a checkpoint this node holds (one that arrives first waits in a small
 * in-memory set until its checkpoint does), so the witness log cannot grow on positions nobody
 * committed. A node remembers the checkpoints it has witnessed itself, so it signs a witness once even
 * after its witness index has dropped it. Checkpoints and witnesses are bounded, and each log is read
 * at start up to a budget that covers what its cap holds.
 *
 * This store does NOT verify signatures or roster membership — the caller verifies
 * before recording (a recorded attestation is assumed already verified). It only
 * indexes, dedups, reports chain integrity, and bounds memory.
 *
 * @copyright 2026 SYM.BOT. Apache 2.0 License.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const ATT_FILE = 'attestations.jsonl';
const CP_FILE = 'checkpoints.jsonl';
const WIT_FILE = 'witnesses.jsonl';

/** A checkpoint position: a non-negative integer, never its text spelling. */
const isPosition = (n) => Number.isSafeInteger(n) && n >= 0;

/** sha256 hex of a signature — the per-attester chain link (`prev`). */
function chainHash(sig) {
  return crypto.createHash('sha256').update(String(sig)).digest('hex');
}

class AttestationStore {
  /**
   * @param {object} [opts]
   * @param {number} [opts.max=50000] cap on distinct attestations (in-memory).
   * @param {number} [opts.rateWindowMs=60000] ingest rate-limit window per (of,by).
   * @param {number} [opts.ratePerWindow=30] max INGESTED attestations per (of,by) per window.
   * @param {string} [opts.selfId] this node's id: the witnesses it signs are remembered apart.
   * @param {number} [opts.maxReadBytes] one budget for every log at start (tests); otherwise each log
   *   has its own, sized to what its cap holds.
   * @param {string} [opts.dir] when set, the store persists records as append-only
   *   JSONL under this dir and reloads them on construction — so the audit trail
   *   (attestations + checkpoints + witnesses) survives a node restart.
   */
  constructor(opts = {}) {
    this._byCmb = new Map();       // of  -> Map(sig -> att)
    this._byAttester = new Map();  // by  -> Map(seq -> att)
    this._seen = new Set();        // sig -> dedup / relay-once
    this._order = new Map();       // sig -> { of, by, seq }, insertion order, for O(1) eviction
    this._max = opts.max || 50000;
    // Per-(of,by) ingest rate-limit — bounds a Sybil/flood of attestations about a
    // single CMB on the immutable log (research's DoS-at-ingest finding). Applies
    // only to GOSSIPED-IN attestations, never to this node's own gating output.
    this._rateWindowMs = opts.rateWindowMs || 60000;
    this._ratePerWindow = opts.ratePerWindow || 30;
    this._rate = new Map();        // `${of}|${by}` -> [timestamps within window]
    this._selfId = opts.selfId || null;
    this._checkpoints = new Map(); // by -> Map(upto_seq -> checkpoint); least recently updated attester first
    this._maxCheckpointsPerAttester = opts.maxCheckpointsPerAttester || 32;
    this._maxAttesters = opts.maxAttesters || 1024;
    this._conflicted = new Map();  // by -> Set(upto_seq) where a second root was refused
    this._conflictOrder = [];      // [by, upto_seq] in the order seen, bounded
    this._witnesses = new Map();   // attester -> Map(upto_seq -> Map(witnessBy -> witness))
    this._positions = [];          // [attester, upto_seq] in the order a position got its first witness
    this._witnessCount = 0;
    this._maxWitnesses = opts.maxWitnesses || 50000;
    this._maxWitnessesPerPosition = opts.maxWitnessesPerPosition || 256;
    this._pending = new Set();     // witnesses whose checkpoint has not arrived yet (memory only)
    this._maxPending = opts.maxPending || 2048;
    this._ownWitnessed = new Map(); // attester -> Set(upto_seq) this node has witnessed itself
    this._witnessConflicts = new Set(); // JSON [attester, upto_seq, by] already reported, bounded
    // At start, each log is read up to a budget that covers what its cap holds (an attestation is
    // ~400-700 bytes and 50,000 are kept), and of a larger log only its newest part.
    const readAll = opts.maxReadBytes;
    this._readBudget = {
      [ATT_FILE]: readAll || 64 * 1024 * 1024,
      [CP_FILE]: readAll || 8 * 1024 * 1024,
      [WIT_FILE]: readAll || 32 * 1024 * 1024,
    };
    this._rateCalls = 0;
    // Durable, append-only persistence (compliance: never rewrite, only append).
    this._dir = opts.dir || null;
    this._loading = false;
    if (this._dir) {
      try { fs.mkdirSync(this._dir, { recursive: true }); } catch { /* best effort */ }
      this._load();
    }
  }

  /**
   * Record an (already signature-verified) attestation. Idempotent — a sig already
   * seen is a no-op, so relay/replay converge rather than duplicate.
   * @param {object} att
   * @param {object} [opts]
   * @param {boolean} [opts.ingested=false] true when received from a peer (gossip) —
   *   subject to the per-(of,by) rate-limit. Own gating output is never rate-limited.
   * @param {number} [opts.now=Date.now()] injectable clock for the rate window.
   * @returns {{ stored: boolean, reason?: string }}
   */
  record(att, opts = {}) {
    if (!att || !att.sig || !att.of || !att.by || att.seq === undefined) {
      return { stored: false, reason: 'malformed' };
    }
    if (this._seen.has(att.sig)) return { stored: false, reason: 'duplicate' };
    if (opts.ingested && !this._allowIngest(att.of, att.by, opts.now ?? Date.now())) {
      return { stored: false, reason: 'rate-limited' };
    }

    this._seen.add(att.sig);
    this._order.set(att.sig, { of: att.of, by: att.by, seq: att.seq });

    let cmbIdx = this._byCmb.get(att.of);
    if (!cmbIdx) { cmbIdx = new Map(); this._byCmb.set(att.of, cmbIdx); }
    cmbIdx.set(att.sig, att);

    let chain = this._byAttester.get(att.by);
    if (!chain) { chain = new Map(); this._byAttester.set(att.by, chain); }
    chain.set(att.seq, att);

    this._append(ATT_FILE, att);
    this._evict();
    return { stored: true };
  }

  /** Audit trail for a gated CMB: every recorded attestation about it. */
  byCmb(of) {
    const m = this._byCmb.get(of);
    return m ? [...m.values()] : [];
  }

  /** An attester's chain, ordered by seq. */
  chainOf(by) {
    const chain = this._byAttester.get(by);
    return chain ? [...chain.values()].sort((a, b) => a.seq - b.seq) : [];
  }

  has(sig) { return this._seen.has(sig); }
  size() { return this._seen.size; }

  /**
   * Chain-integrity check for one attester — the local half of omission-evidence.
   * Walks the attester's recorded chain and reports:
   *   - `gaps`: missing `seq` values between the lowest and highest seen (a
   *     suppressed/dropped attestation leaves a hole),
   *   - `breaks`: positions where `att.prev !== sha256(previous att.sig)` (a forged
   *     or re-linked chain).
   * Only links recomputable within the held window are checked. Cross-node head
   * reconciliation against anchored checkpoints is a separate (later) step.
   * @returns {{ ok: boolean, gaps: number[], breaks: number[] }}
   */
  verifyChain(by) {
    const chain = this.chainOf(by);
    const gaps = [], breaks = [];
    if (chain.length === 0) return { ok: true, gaps, breaks };
    const bySeq = new Map(chain.map(a => [a.seq, a]));
    const lo = chain[0].seq, hi = chain[chain.length - 1].seq;
    for (let s = lo; s <= hi; s++) {
      const cur = bySeq.get(s);
      if (!cur) { gaps.push(s); continue; }
      const prevAtt = bySeq.get(s - 1);
      if (prevAtt && cur.prev !== chainHash(prevAtt.sig)) breaks.push(s);
    }
    return { ok: gaps.length === 0 && breaks.length === 0, gaps, breaks };
  }

  // ── Checkpoints + witnesses (omission-evidence) ──────────────────────────────

  /**
   * Record an (already-verified) checkpoint, keyed by attester + position. A later copy of a held
   * checkpoint is a duplicate; one with a different root is a conflict: not stored as the position's
   * checkpoint, appended once as evidence (so a restart re-derives it), and the position is remembered
   * as conflicted. At most `maxCheckpointsPerAttester` are kept per attester (dropping the oldest
   * position and its witnesses), for at most `maxAttesters` attesters.
   */
  recordCheckpoint(cp) {
    if (!cp || !cp.by || !isPosition(cp.upto_seq) || !cp.root || !cp.sig) return { stored: false, reason: 'malformed' };
    let m = this._checkpoints.get(cp.by);
    const existing = m && m.get(cp.upto_seq);
    if (existing) {
      if (existing.root === cp.root) return { stored: false, reason: 'duplicate' };
      const first = this._markConflict(cp.by, cp.upto_seq);
      if (first) this._append(CP_FILE, cp);
      return { stored: false, reason: 'conflict', keptRoot: existing.root, first };
    }
    if (m && m.size >= this._maxCheckpointsPerAttester) {
      let oldest = Infinity;
      for (const k of m.keys()) if (k < oldest) oldest = k;
      if (cp.upto_seq < oldest) return { stored: false, reason: 'stale' };
      m.delete(oldest);
      this._dropWitnessesOf(cp.by, oldest);
    }
    if (!m) {
      m = new Map();
      if (this._checkpoints.size >= this._maxAttesters) {
        const [victim] = this._checkpoints.keys();   // the attester updated least recently
        for (const seq of [...this._checkpoints.get(victim).keys()]) this._dropWitnessesOf(victim, seq);
        this._checkpoints.delete(victim);
      }
    }
    m.set(cp.upto_seq, cp);
    this._checkpoints.delete(cp.by);
    this._checkpoints.set(cp.by, m);
    this._append(CP_FILE, cp);
    for (const w of [...this._pending]) {
      if (w.attester === cp.by && w.upto_seq === cp.upto_seq) { this._pending.delete(w); this.recordWitness(w); }
    }
    return { stored: true };
  }

  /**
   * Record an (already-verified) witness countersignature, keyed by (attester, position, witness).
   * A later copy of a held witness is a duplicate; one with a different root is a conflict, not
   * stored (`first` says whether it is newly seen). A witness for a position whose checkpoint is not
   * held waits in memory (`pending`, bounded) until it is. At most `maxWitnessesPerPosition` are kept
   * per position and `maxWitnesses` in all, the oldest positions dropped first.
   */
  recordWitness(w) {
    if (!w || !w.attester || !isPosition(w.upto_seq) || !w.root || !w.by || !w.sig) return { stored: false, reason: 'malformed' };
    const existing = this.witnessAt(w.attester, w.upto_seq, w.by);
    if (existing) {
      if (existing.root === w.root) return { stored: false, reason: 'duplicate' };
      const k = JSON.stringify([w.attester, w.upto_seq, w.by]);
      const first = !this._witnessConflicts.has(k);
      if (first) {
        this._witnessConflicts.add(k);
        if (this._witnessConflicts.size > 1024) this._witnessConflicts.delete(this._witnessConflicts.values().next().value);
      }
      return { stored: false, reason: 'conflict', keptRoot: existing.root, first };
    }
    if (!this.checkpointAt(w.attester, w.upto_seq)) {
      for (const p of this._pending) if (p.attester === w.attester && p.upto_seq === w.upto_seq && p.by === w.by) return { stored: false, reason: 'duplicate' };
      this._pending.add(w);
      if (this._pending.size > this._maxPending) this._pending.delete(this._pending.values().next().value);
      return { stored: false, reason: 'pending' };
    }
    let byPos = this._witnesses.get(w.attester);
    if (!byPos) { byPos = new Map(); this._witnesses.set(w.attester, byPos); }
    let m = byPos.get(w.upto_seq);
    if (!m) { m = new Map(); byPos.set(w.upto_seq, m); this._positions.push([w.attester, w.upto_seq]); }
    if (m.size >= this._maxWitnessesPerPosition) return { stored: false, reason: 'position-full' };
    m.set(w.by, w);
    this._witnessCount++;
    if (this._selfId && w.by === this._selfId) this._markOwnWitness(w.attester, w.upto_seq);
    while (this._witnessCount > this._maxWitnesses && this._positions.length) {
      const [a, seq] = this._positions.shift();
      this._dropWitnessesOf(a, seq, false);
    }
    this._append(WIT_FILE, w);
    return { stored: true };
  }

  /** @private Drop the witnesses of a position (its checkpoint dropped, or the oldest under the cap). */
  _dropWitnessesOf(attester, upto_seq, unlist = true) {
    const byPos = this._witnesses.get(attester);
    const m = byPos && byPos.get(upto_seq);
    if (!m) return;
    this._witnessCount -= m.size;
    byPos.delete(upto_seq);
    if (byPos.size === 0) this._witnesses.delete(attester);
    if (unlist) {
      const i = this._positions.findIndex(([a, s]) => a === attester && s === upto_seq);
      if (i >= 0) this._positions.splice(i, 1);
    }
  }

  /** @private Remember a checkpoint this node witnessed itself; kept per attester, newest 256. */
  _markOwnWitness(attester, upto_seq) {
    let set = this._ownWitnessed.get(attester);
    if (!set) { set = new Set(); this._ownWitnessed.set(attester, set); }
    set.add(upto_seq);
    if (set.size > 256) {
      let oldest = Infinity;
      for (const k of set) if (k < oldest) oldest = k;
      set.delete(oldest);
    }
  }

  /** @private Remember that a second root was refused for (by, upto_seq); bounded.
   *  @returns {boolean} whether this position is newly conflicted */
  _markConflict(by, upto_seq) {
    let set = this._conflicted.get(by);
    if (!set) { set = new Set(); this._conflicted.set(by, set); }
    if (set.has(upto_seq)) return false;
    set.add(upto_seq);
    this._conflictOrder.push([by, upto_seq]);
    if (this._conflictOrder.length > 1024) {
      const [oby, oseq] = this._conflictOrder.shift();
      const os = this._conflicted.get(oby);
      if (os) { os.delete(oseq); if (os.size === 0) this._conflicted.delete(oby); }
    }
    return true;
  }

  /** Whether a second, different root was refused for (by, upto_seq). */
  hasConflict(by, upto_seq) { return !!this._conflicted.get(by)?.has(upto_seq); }

  /** The checkpoint held for (by, upto_seq), or null. */
  checkpointAt(by, upto_seq) { return this._checkpoints.get(by)?.get(upto_seq) || null; }

  /** The witness `by` holds for (attester, upto_seq), or null. */
  witnessAt(attester, upto_seq, by) { return this._witnesses.get(attester)?.get(upto_seq)?.get(by) || null; }

  /** Whether `by` has witnessed (attester, upto_seq) already, in any copy. For this node itself it
   *  also counts a witness its index has since dropped. */
  hasWitnessed(attester, upto_seq, by) {
    if (this._selfId && by === this._selfId && this._ownWitnessed.get(attester)?.has(upto_seq)) return true;
    if (this.witnessAt(attester, upto_seq, by) !== null) return true;
    for (const p of this._pending) if (p.attester === attester && p.upto_seq === upto_seq && p.by === by) return true;
    return false;
  }

  /** An attester's checkpoints, ordered by upto_seq. */
  checkpointsOf(by) {
    const m = this._checkpoints.get(by);
    return m ? [...m.values()].sort((a, b) => a.upto_seq - b.upto_seq) : [];
  }

  /** The highest-seq checkpoint an attester has committed (the freshest commitment). */
  latestCheckpoint(by) {
    const cps = this.checkpointsOf(by);
    return cps.length ? cps[cps.length - 1] : null;
  }

  /** Witnesses countersigning a specific (attester, upto_seq, root) checkpoint. */
  witnessesFor(attester, upto_seq, root) {
    const m = this._witnesses.get(attester)?.get(upto_seq);
    if (!m) return [];
    const all = [...m.values()];
    return root ? all.filter(w => w.root === root) : all;
  }

  // ── Durable persistence (append-only JSONL) ──────────────────────────────────

  /** Append one record to its JSONL file. No-op without a dir or while replaying. */
  _append(file, obj) {
    if (!this._dir || this._loading) return;
    try { fs.appendFileSync(path.join(this._dir, file), JSON.stringify(obj) + '\n'); }
    catch { /* best effort — never let persistence break gating */ }
  }

  /** Replay persisted records into the in-memory index on construction. Reuses the
   *  normal record paths (which dedup), with `_loading` suppressing re-writes. A
   *  malformed line is skipped, never fatal. */
  _load() {
    this._loading = true;
    this._replay(ATT_FILE, (o) => this.record(o));
    this._replay(CP_FILE, (o) => this.recordCheckpoint(o));
    this._replay(WIT_FILE, (o) => this.recordWitness(o));
    this._loading = false;
  }

  _replay(file, fn) {
    const p = path.join(this._dir, file);
    const budget = this._readBudget[file];
    let text;
    try {
      const size = fs.statSync(p).size;
      if (size <= budget) text = fs.readFileSync(p, 'utf8');
      else {
        // The newest part only: what a bounded store keeps. Reading a whole oversized log (one was
        // 257 MB of storm) held a node's thread for minutes at every start. The log itself is never
        // rewritten.
        const fd = fs.openSync(p, 'r');
        try {
          const buf = Buffer.alloc(budget);
          const n = fs.readSync(fd, buf, 0, buf.length, size - buf.length);
          text = buf.subarray(buf.indexOf(0x0a) + 1, n).toString('utf8'); // the cut first line is skipped
        } finally { fs.closeSync(fd); }
      }
    } catch { return; } // no file yet
    for (const line of text.split('\n')) {
      if (!line.trim()) continue;
      try { fn(JSON.parse(line)); } catch { /* skip a corrupt line */ }
    }
  }

  /** Sliding-window rate gate for ingested attestations, per (of, by). */
  _allowIngest(of, by, now) {
    const key = `${of}|${by}`;
    if (++this._rateCalls % 1000 === 0) {
      // One entry per (of, by) ever ingested grew for the life of the process; closed windows go.
      for (const [k, ts] of this._rate) if (!ts.length || ts[ts.length - 1] < now - this._rateWindowMs) this._rate.delete(k);
    }
    let arr = this._rate.get(key);
    if (!arr) { arr = []; this._rate.set(key, arr); }
    const cutoff = now - this._rateWindowMs;
    while (arr.length && arr[0] < cutoff) arr.shift();
    if (arr.length >= this._ratePerWindow) return false;
    arr.push(now);
    return true;
  }

  _evict() {
    while (this._seen.size > this._max && this._order.size) {
      const [sig, { of, by, seq }] = this._order.entries().next().value;
      this._order.delete(sig);
      if (!this._seen.delete(sig)) continue;
      const cmbIdx = this._byCmb.get(of);
      if (cmbIdx) { cmbIdx.delete(sig); if (cmbIdx.size === 0) this._byCmb.delete(of); }
      const chain = this._byAttester.get(by);
      if (chain) { chain.delete(seq); if (chain.size === 0) this._byAttester.delete(by); }
    }
  }
}

module.exports = { AttestationStore, chainHash, isPosition };
