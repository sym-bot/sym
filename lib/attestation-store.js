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
 * per (attester, upto_seq) and one witness per (attester, upto_seq, witness). A node that witnesses
 * a checkpoint again after a restart signs a second, different-looking copy of the same statement;
 * keeping only the latest copy made the two copies new to each other forever, so every node stored
 * and relayed each one again whenever the other arrived. A later copy of a held statement is a
 * duplicate; one asserting a different root for the same position is a conflict, kept out.
 *
 * Persistence is append-only, and bounded: a log that outgrows its limit is moved, whole and
 * unchanged, into `archive/`, and a new log starts from the records still held. A node reads only
 * the live logs at start, and of an oversized one only its tail.
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
    this._maxCheckpointsPerAttester = opts.maxCheckpointsPerAttester || 32;
    this._maxWitnesses = opts.maxWitnesses || 20000;
    this._maxLiveBytes = opts.maxLiveBytes || 8 * 1024 * 1024;
    this._witnessOrder = new Map(); // `${attester}|${upto_seq}|${by}` -> true, insertion order
    this._bytes = new Map();        // live file -> bytes written to it
    // Per-(of,by) ingest rate-limit — bounds a Sybil/flood of attestations about a
    // single CMB on the immutable log (research's DoS-at-ingest finding). Applies
    // only to GOSSIPED-IN attestations, never to this node's own gating output.
    this._rateWindowMs = opts.rateWindowMs || 60000;
    this._ratePerWindow = opts.ratePerWindow || 30;
    this._rate = new Map();        // `${of}|${by}` -> [timestamps within window]
    this._checkpoints = new Map(); // by -> Map(upto_seq -> checkpoint)
    this._witnesses = new Map();   // `${attester}|${upto_seq}` -> Map(witnessBy -> witness)
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

  /** Record an (already-verified) checkpoint, keyed by attester + upto_seq. Idempotent: a later
   *  copy of a held checkpoint is a duplicate, one with a different root is a conflict (both kept
   *  out, so neither is relayed again). At most `maxCheckpointsPerAttester` are kept per attester. */
  recordCheckpoint(cp) {
    if (!cp || !cp.by || cp.upto_seq === undefined || !cp.root || !cp.sig) return { stored: false, reason: 'malformed' };
    let m = this._checkpoints.get(cp.by);
    if (!m) { m = new Map(); this._checkpoints.set(cp.by, m); }
    const existing = m.get(cp.upto_seq);
    if (existing) return { stored: false, reason: existing.root === cp.root ? 'duplicate' : 'conflict' };
    if (m.size >= this._maxCheckpointsPerAttester) {
      const oldest = Math.min(...m.keys());
      if (cp.upto_seq < oldest) return { stored: false, reason: 'stale' };
      m.delete(oldest);
      this._dropWitnessesOf(cp.by, oldest);
    }
    m.set(cp.upto_seq, cp);
    this._append(CP_FILE, cp);
    return { stored: true };
  }

  /** Record an (already-verified) witness countersignature, keyed by (attester, upto_seq, witness).
   *  Idempotent on what it asserts (see the module note); at most `maxWitnesses` are kept. */
  recordWitness(w) {
    if (!w || !w.attester || w.upto_seq === undefined || !w.root || !w.by || !w.sig) return { stored: false, reason: 'malformed' };
    const key = `${w.attester}|${w.upto_seq}`;
    let m = this._witnesses.get(key);
    const existing = m && m.get(w.by);
    if (existing) return { stored: false, reason: existing.root === w.root ? 'duplicate' : 'conflict' };
    if (!m) { m = new Map(); this._witnesses.set(key, m); }
    m.set(w.by, w);
    this._witnessOrder.set(`${key}|${w.by}`, true);
    while (this._witnessOrder.size > this._maxWitnesses) {
      const first = this._witnessOrder.keys().next().value;
      this._witnessOrder.delete(first);
      const cut = first.lastIndexOf('|');
      const k = first.slice(0, cut), by = first.slice(cut + 1);
      const wm = this._witnesses.get(k);
      if (wm) { wm.delete(by); if (wm.size === 0) this._witnesses.delete(k); }
    }
    this._append(WIT_FILE, w);
    return { stored: true };
  }

  /** Whether a checkpoint for (by, upto_seq) is held, in any copy. */
  hasCheckpoint(by, upto_seq) {
    const m = this._checkpoints.get(by);
    return !!(m && m.has(upto_seq));
  }

  /** Whether `by` has witnessed (attester, upto_seq) already, in any copy. */
  hasWitnessed(attester, upto_seq, by) {
    const m = this._witnesses.get(`${attester}|${upto_seq}`);
    return !!(m && m.has(by));
  }

  /** @private Drop the witnesses of a checkpoint no longer held. */
  _dropWitnessesOf(attester, upto_seq) {
    const key = `${attester}|${upto_seq}`;
    const m = this._witnesses.get(key);
    if (!m) return;
    for (const by of m.keys()) this._witnessOrder.delete(`${key}|${by}`);
    this._witnesses.delete(key);
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
    const m = this._witnesses.get(`${attester}|${upto_seq}`);
    if (!m) return [];
    const all = [...m.values()];
    return root ? all.filter(w => w.root === root) : all;
  }

  // ── Durable persistence (append-only JSONL) ──────────────────────────────────

  /** Append one record to its JSONL file. No-op without a dir or while replaying. A log past
   *  `maxLiveBytes` is archived and restarted from what is held (_rotate). */
  _append(file, obj) {
    if (!this._dir || this._loading) return;
    try {
      const line = JSON.stringify(obj) + '\n';
      fs.appendFileSync(path.join(this._dir, file), line);
      const bytes = (this._bytes.get(file) || 0) + Buffer.byteLength(line);
      this._bytes.set(file, bytes);
      if (bytes > this._maxLiveBytes) this._rotate(file);
    } catch { /* best effort — never let persistence break gating */ }
  }

  /** The records of one log this store still holds, in the order they were recorded. @private */
  _held(file) {
    if (file === ATT_FILE) {
      const out = [];
      for (const [sig, { of }] of this._order) { const a = this._byCmb.get(of)?.get(sig); if (a) out.push(a); }
      return out;
    }
    if (file === CP_FILE) return [...this._checkpoints.values()].flatMap((m) => [...m.values()]);
    const out = [];
    for (const k of this._witnessOrder.keys()) {
      const cut = k.lastIndexOf('|');
      const w = this._witnesses.get(k.slice(0, cut))?.get(k.slice(cut + 1));
      if (w) out.push(w);
    }
    return out;
  }

  /** Move a log, whole and unchanged, into archive/ and start a new one from the records held.
   *  Nothing is rewritten: the archived file keeps every line ever appended. @private */
  _rotate(file) {
    const live = path.join(this._dir, file);
    const archiveDir = path.join(this._dir, 'archive');
    fs.mkdirSync(archiveDir, { recursive: true });
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    fs.renameSync(live, path.join(archiveDir, `${file.replace(/\.jsonl$/, '')}.${stamp}.jsonl`));
    const text = this._held(file).map((o) => JSON.stringify(o) + '\n').join('');
    fs.writeFileSync(live, text);
    this._bytes.set(file, Buffer.byteLength(text));
  }

  /** Replay persisted records into the in-memory index on construction. Reuses the
   *  normal record paths (which dedup), with `_loading` suppressing re-writes. A
   *  malformed line is skipped, never fatal. */
  _load() {
    this._loading = true;
    const oversized = [];
    if (this._replay(ATT_FILE, (o) => this.record(o))) oversized.push(ATT_FILE);
    if (this._replay(CP_FILE, (o) => this.recordCheckpoint(o))) oversized.push(CP_FILE);
    if (this._replay(WIT_FILE, (o) => this.recordWitness(o))) oversized.push(WIT_FILE);
    this._loading = false;
    for (const file of oversized) { try { this._rotate(file); } catch { /* best effort */ } }
  }

  /** Replay one log. Of a log larger than `maxLiveBytes` only the last `maxLiveBytes` are read:
   *  the newest records, which are all a bounded store keeps anyway. Reading a whole oversized log
   *  at start held a node's thread for minutes. @returns {boolean} whether the log was oversized */
  _replay(file, fn) {
    const p = path.join(this._dir, file);
    let size;
    try { size = fs.statSync(p).size; } catch { return false; } // no file yet
    let text;
    const oversized = size > this._maxLiveBytes;
    try {
      if (!oversized) text = fs.readFileSync(p, 'utf8');
      else {
        const fd = fs.openSync(p, 'r');
        try {
          const buf = Buffer.alloc(this._maxLiveBytes);
          const n = fs.readSync(fd, buf, 0, buf.length, size - buf.length);
          text = buf.subarray(0, n).toString('utf8');
          text = text.slice(text.indexOf('\n') + 1); // the first line is cut
        } finally { fs.closeSync(fd); }
      }
    } catch { return false; }
    for (const line of text.split('\n')) {
      if (!line.trim()) continue;
      try { fn(JSON.parse(line)); } catch { /* skip a corrupt line */ }
    }
    if (!oversized) this._bytes.set(file, size);
    return oversized;
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
