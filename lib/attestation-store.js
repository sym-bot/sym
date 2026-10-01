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
 * Checkpoints and witnesses are bounded, and the logs are read at start from their newest part only.
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
    this._checkpoints = new Map(); // by -> Map(upto_seq -> checkpoint); least recently updated attester first
    this._maxCheckpointsPerAttester = opts.maxCheckpointsPerAttester || 32;
    this._maxAttesters = opts.maxAttesters || 1024;
    this._conflicted = new Map();  // by -> Set(upto_seq) where a second root was refused
    this._conflictOrder = [];      // [by, upto_seq] in the order seen, bounded
    this._witnesses = new Map();   // attester -> Map(upto_seq -> Map(witnessBy -> witness))
    this._witnessOrder = new Set(); // every held witness object, oldest first
    this._witnessesBy = new Map(); // witnessBy -> Set(witness), oldest first
    this._maxWitnesses = opts.maxWitnesses || 20000;
    this._maxWitnessesPerWitness = opts.maxWitnessesPerWitness || 1024;
    // Of a log larger than this, only the newest part is read at start.
    this._maxReadBytes = opts.maxReadBytes || 8 * 1024 * 1024;
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
   * checkpoint is a duplicate; one with a different root is a conflict: not stored, and the position
   * is remembered as conflicted. At most `maxCheckpointsPerAttester` are kept per attester (dropping
   * the oldest position and its witnesses), for at most `maxAttesters` attesters.
   */
  recordCheckpoint(cp) {
    if (!cp || !cp.by || !isPosition(cp.upto_seq) || !cp.root || !cp.sig) return { stored: false, reason: 'malformed' };
    let m = this._checkpoints.get(cp.by);
    const existing = m && m.get(cp.upto_seq);
    if (existing) {
      if (existing.root === cp.root) return { stored: false, reason: 'duplicate' };
      const first = this._markConflict(cp.by, cp.upto_seq);
      return { stored: false, reason: 'conflict', keptRoot: existing.root, first };
    }
    if (m && m.size >= this._maxCheckpointsPerAttester) {
      const oldest = Math.min(...m.keys());
      if (cp.upto_seq < oldest) return { stored: false, reason: 'stale' };
      m.delete(oldest);
      this._dropWitnessesOf(cp.by, oldest);
    }
    if (!m) {
      m = new Map();
      if (this._checkpoints.size >= this._maxAttesters) {
        const [victim] = this._checkpoints.keys();   // the attester updated least recently
        this._checkpoints.delete(victim);
        for (const w of [...this._witnessOrder]) if (w.attester === victim) this._dropWitness(w);
      }
    }
    m.set(cp.upto_seq, cp);
    this._checkpoints.delete(cp.by);
    this._checkpoints.set(cp.by, m);
    this._append(CP_FILE, cp);
    return { stored: true };
  }

  /**
   * Record an (already-verified) witness countersignature, keyed by (attester, position, witness).
   * A later copy of a held witness is a duplicate; one with a different root is a conflict, not
   * stored. At most `maxWitnessesPerWitness` are kept per witnessing node, so one cannot crowd out
   * another, and `maxWitnesses` in all, the oldest dropped first.
   */
  recordWitness(w) {
    if (!w || !w.attester || !isPosition(w.upto_seq) || !w.root || !w.by || !w.sig) return { stored: false, reason: 'malformed' };
    const existing = this.witnessAt(w.attester, w.upto_seq, w.by);
    if (existing) return existing.root === w.root ? { stored: false, reason: 'duplicate' } : { stored: false, reason: 'conflict', keptRoot: existing.root };
    let byPos = this._witnesses.get(w.attester);
    if (!byPos) { byPos = new Map(); this._witnesses.set(w.attester, byPos); }
    let m = byPos.get(w.upto_seq);
    if (!m) { m = new Map(); byPos.set(w.upto_seq, m); }
    m.set(w.by, w);
    this._witnessOrder.add(w);
    let mine = this._witnessesBy.get(w.by);
    if (!mine) { mine = new Set(); this._witnessesBy.set(w.by, mine); }
    mine.add(w);
    if (mine.size > this._maxWitnessesPerWitness) this._dropWitness(mine.values().next().value);
    while (this._witnessOrder.size > this._maxWitnesses) this._dropWitness(this._witnessOrder.values().next().value);
    this._append(WIT_FILE, w);
    return { stored: true };
  }

  /** @private Remove one held witness from every index. */
  _dropWitness(w) {
    this._witnessOrder.delete(w);
    const mine = this._witnessesBy.get(w.by);
    if (mine) { mine.delete(w); if (mine.size === 0) this._witnessesBy.delete(w.by); }
    const byPos = this._witnesses.get(w.attester);
    const m = byPos && byPos.get(w.upto_seq);
    if (m && m.get(w.by) === w) {
      m.delete(w.by);
      if (m.size === 0) byPos.delete(w.upto_seq);
      if (byPos.size === 0) this._witnesses.delete(w.attester);
    }
  }

  /** @private Drop the witnesses of a checkpoint position no longer held. */
  _dropWitnessesOf(attester, upto_seq) {
    const m = this._witnesses.get(attester)?.get(upto_seq);
    if (m) for (const w of [...m.values()]) this._dropWitness(w);
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

  /** Whether `by` has witnessed (attester, upto_seq) already, in any copy. */
  hasWitnessed(attester, upto_seq, by) { return this.witnessAt(attester, upto_seq, by) !== null; }

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
    let text;
    try {
      const size = fs.statSync(p).size;
      if (size <= this._maxReadBytes) text = fs.readFileSync(p, 'utf8');
      else {
        // The newest part only: what a bounded store keeps. Reading a whole oversized log (one was
        // 257 MB of storm) held a node's thread for minutes at every start. The log itself is never
        // rewritten.
        const fd = fs.openSync(p, 'r');
        try {
          const buf = Buffer.alloc(this._maxReadBytes);
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

module.exports = { AttestationStore, chainHash };
