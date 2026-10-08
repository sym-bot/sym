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
 * Deduplicated by signature (idempotent record / relay-once). Bounded by count, shared out by
 * attester: when full, the attester holding the most loses its oldest.
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
 * Each log is rotated once the bytes in it beyond the records the store holds (appended since the
 * last rotation and since dropped: evicted, superseded) exceed the larger of `rotateBytes` and the
 * bytes of the records it holds. The rule is the same at start as at run time, so a start rotates a
 * log only when it is over budget, and a rotation is never followed by another until that much more
 * has been appended and dropped. A rotation writes the records held to a temp file (fully, then
 * fsynced), links the old log into `archive/` under a name no other rotation can take, and renames
 * the temp file over the live log: the live path holds a complete log at every instant, and a failure
 * at any step leaves it as it was. A log is never edited in place, and a log that could not be read
 * at start is never rotated. A rotation writes back the witnesses read from the log that still wait
 * for their checkpoint.
 *
 * Retention, plainly: rotation keeps each live log bounded; the archives hold the older history. They
 * are pruned oldest first once a log's archives exceed `archiveMaxBytes` (128 MiB by default, the
 * newest archive included, so an archive larger than the bound on its own is deleted too), and never
 * when it is 0. Whoever needs the whole audit trail sets 0 (or SYM_ATTESTATION_ARCHIVE_MAX_BYTES=0)
 * and owns the disk it takes.
 *
 * One writer per directory is the contract, by construction: the store lives in its node's directory
 * (`<node>/attestations`), and the node's identity lock admits one process per node. The start-up
 * tidy tolerates a second live process on the same directory only defensively; nothing else does.
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
const LOGS = [ATT_FILE, CP_FILE, WIT_FILE];
const ARCHIVE_DIR = 'archive';
/** An archived log: `<log>.<sequence, 12 digits>.<UTC time to the ms>.<pid>.jsonl`. The sequence orders them. */
const ARCHIVE_NAME = /^(attestations|checkpoints|witnesses)\.(\d{12})\.(\d{8}T\d{9}Z)\.(\d+)\.jsonl$/;
/** A rotation's temp file: left behind only by a crash part way through one. The fields are the
 *  writing process's pid and a counter. */
const ROTATING_NAME = /^(attestations|checkpoints|witnesses)\.jsonl\.(\d+)\.\d+\.rotating$/;
/** Names the archive a rotation is copying the old log into (where there are no hard links), until the
 *  rotation has replaced the live log: a crash in between leaves a copy of the live log in archive/. */
const ARCHIVING_NAME = /^(attestations|checkpoints|witnesses)\.jsonl\.(\d+)\.\d+\.archiving$/;
/** The line a rotated witness log keeps this node's own-witness memory in, one per attester. */
const OWN_WITNESSED = 'own-witnessed';
/** A link error that means the filesystem has no hard links: the old log is copied instead. */
const NO_LINK = new Set(['EPERM', 'ENOTSUP', 'EOPNOTSUPP', 'ENOSYS', 'EXDEV', 'EMLINK']);
/** Bytes a read budget allows for one record's line. Measured (36-character node ids, a 16-character
 *  room): an attestation ~520, a checkpoint ~315, a witness ~380; and per attester, this node's
 *  own-witness line (up to 256 positions). */
const ATT_LINE = 720;
const CP_LINE = 448;
const WIT_LINE = 448;
const OWN_LINE = 2560;
/** archive/ keeps at most this many bytes per log unless configured (0 keeps every archive). */
const ARCHIVE_MAX_DEFAULT = 128 * 1024 * 1024;
/** A rotation writes the held records in chunks of about this many characters. */
const WRITE_CHUNK = 1 << 20;

/** A checkpoint position: a non-negative integer, never its text spelling. */
const isPosition = (n) => Number.isSafeInteger(n) && n >= 0;
const { checkpointConflict, checkpointLinkValid } = require('./core/attestation');
/** A checkpoint of the chained construction (sym-attest-v1 §5.2, MMP 2.0 update 1): it names its range
 *  and the root it follows. One without `from_seq` is from a log written before the update. */
const isChained = (cp) => !!cp && cp.from_seq !== undefined;
/** The same checkpoint: the same range, prev and root (§6 step 4, duplicates by content). */
const sameCheckpoint = (a, b) => a.from_seq === b.from_seq && a.upto_seq === b.upto_seq && a.prev === b.prev && a.root === b.root;

/** The key a witness is held or waits under: (attester, position, witness), unambiguous for any ids. */
const witnessKey = (attester, upto_seq, by) => JSON.stringify([attester, upto_seq, by]);
/** The key of a witnessed position: (attester, position). */
const positionKey = (attester, upto_seq) => JSON.stringify([attester, upto_seq]);

/** An Ed25519 signature as its signer writes it: 64 bytes in unpadded base64url (86 characters, the
 *  last one carrying two bits). */
const CANONICAL_SIG = /^[A-Za-z0-9_-]{85}[AQgw]$/;

/** The key an attestation is de-duplicated by: its signature's bytes, not its spelling. Base64url
 *  decoding ignores padding, whitespace and stray characters, so one signature can be spelled any
 *  number of ways that all verify; each spelling was a new attestation, stored and relayed. A string
 *  that is not a 64-byte signature is its own key. */
function sigKey(sig) {
  if (typeof sig !== 'string' || sig.length < 86 || CANONICAL_SIG.test(sig)) return sig;
  const bytes = Buffer.from(sig, 'base64url');
  return bytes.length === 64 ? bytes.toString('base64url') : sig;
}

/** Whether a signature is spelled as an Ed25519 signer writes it: 64 bytes, unpadded base64url. */
const isCanonicalSig = (sig) => typeof sig === 'string' && CANONICAL_SIG.test(sig);

/** Write a whole buffer to a file descriptor: a write may be short. @returns {number} bytes written */
function writeAll(fd, buf) {
  let off = 0;
  while (off < buf.length) {
    const n = fs.writeSync(fd, buf, off, buf.length - off);
    if (!(n > 0)) throw Object.assign(new Error(`write returned ${n}`), { code: 'ESHORTWRITE' });
    off += n;
  }
  return off;
}

/** Whether `pid` is a running process other than this one (one that may be mid-rotation on the same
 *  directory). A pid that has been reused errs toward leaving a leftover for a later start. */
function otherLiveProcess(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0 || pid === process.pid) return false;
  try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; }
}

/** Whether two files hold the same bytes, read in chunks. */
function sameBytes(a, b) {
  const fa = fs.openSync(a, 'r');
  try {
    const fb = fs.openSync(b, 'r');
    try {
      if (fs.fstatSync(fa).size !== fs.fstatSync(fb).size) return false;
      const ba = Buffer.alloc(1 << 20);
      const bb = Buffer.alloc(1 << 20);
      for (let pos = 0; ;) {
        const na = fs.readSync(fa, ba, 0, ba.length, pos);
        const nb = fs.readSync(fb, bb, 0, bb.length, pos);
        if (na !== nb) return false;
        if (na === 0) return true;
        if (!ba.subarray(0, na).equals(bb.subarray(0, nb))) return false;
        pos += na;
      }
    } finally { fs.closeSync(fb); }
  } finally { fs.closeSync(fa); }
}

/**
 * The per-attester chain link (`prev`): the sha256 hex of a signature's BYTES (sym-attest-v1 §5.1).
 * sym 0.13 hashed the base64url text instead; a chain written then keeps those links, and
 * `verifyChain` accepts either for a link whose earlier attestation predates 0.14.
 */
function chainHash(sig) {
  return crypto.createHash('sha256').update(Buffer.from(String(sig), 'base64url')).digest('hex');
}

/** The 0.13 link (sha256 of the signature's base64url text), read only for a chain written then. */
function chainHash013(sig) {
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
   * @param {number} [opts.rotateBytes=8 MiB] a log is rotated once the bytes in it beyond the records
   *   held exceed the larger of this and the bytes of the records held.
   * @param {number} [opts.archiveMaxBytes=128 MiB] `archive/` keeps at most this much per log, the
   *   newest archive included, the oldest pruned first; 0 keeps every archive. When not given,
   *   SYM_ATTESTATION_ARCHIVE_MAX_BYTES is read; a value that is not a number of bytes ≥ 0 falls back
   *   to the default, which is said once.
   * @param {function(string):void} [opts.log] where a rotation failure is said (once per distinct error).
   * @param {string} [opts.dir] when set, the store persists records as append-only
   *   JSONL under this dir and reloads them on construction — so the audit trail
   *   (attestations + checkpoints + witnesses) survives a node restart.
   */
  constructor(opts = {}) {
    this._byCmb = new Map();       // of  -> Map(sigKey -> att)
    this._byAttester = new Map();  // by  -> Map(seq -> att)
    this._seen = new Set();        // sigKey -> dedup / relay-once
    this._order = new Map();       // sigKey -> { of, by, seq }, insertion order (the order a rotation writes)
    this._max = opts.max || 50000;
    // The cap is shared out by attester, so one attester cannot flush another's chain: when the store
    // is full, the attester holding the most loses its oldest. Each attester therefore keeps its newest
    // up to its share, max / attesters held, and at least max / maxAttesters (48 at the defaults).
    this._heldBy = new Map();      // by -> Set(sigKey) oldest first; attesters least recently updated first
    this._byCount = new Map();     // n -> Set(by) of the attesters holding n attestations
    this._maxCount = 0;            // the most any attester holds
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
    // by -> Map(upto_seq -> the copy with the other root), for held positions only: a position that
    // is dropped takes its conflict with it, so this is bounded by the checkpoint caps.
    this._conflicted = new Map();
    this._witnesses = new Map();   // attester -> Map(upto_seq -> Map(witnessBy -> witness))
    // positionKey -> [attester, upto_seq], in the order a position got its first witness: the global
    // cap drops the oldest (its head) and a dropped checkpoint unlists its own, both in O(1).
    this._positions = new Map();
    this._witnessCount = 0;
    this._maxWitnesses = opts.maxWitnesses || 50000;
    this._maxWitnessesPerPosition = opts.maxWitnessesPerPosition || 256;
    this._pending = new Map();     // witnessKey -> witness whose checkpoint has not arrived yet (memory only)
    this._maxPending = opts.maxPending || 2048;
    this._ownWitnessed = new Map(); // attester -> Set(upto_seq) this node has witnessed itself
    this._witnessConflicts = new Map(); // witnessKey -> the other root, already reported; bounded
    this._fromLog = new WeakSet();  // waiting witnesses read from the live log (already in it)
    this._rateCalls = 0;
    // Durable, append-only persistence (compliance: a log is never edited, only appended to; a
    // rotation archives it whole and starts a new one from the records held).
    this._dir = opts.dir || null;
    this._loading = false;
    this._rotateBytes = opts.rotateBytes || 8 * 1024 * 1024;
    this._logFn = typeof opts.log === 'function' ? opts.log : (m) => console.error(`[SYM] attestations: ${m}`);
    const perLog = (v) => ({ [ATT_FILE]: v, [CP_FILE]: v, [WIT_FILE]: v });
    this._held = perLog(0);        // bytes of the records held, as the lines a rotation writes
    this._logBytes = perLog(0);    // bytes in each live log
    this._retryAt = perLog(0);     // after a failed rotation, the log size it waits for
    this._rotations = perLog(0);
    this._recBytes = new WeakMap(); // record -> bytes of its log line
    this._replayBytes = 0;         // bytes of the line being replayed
    this._archiveSeq = 0;
    this._tmpSeq = 0;
    this._said = new Set();        // rotation errors already said
    this._unread = new Set();      // logs that could not be read at start: never rotated or rewritten
    this._respelled = 0;           // attestations read from a log with a signature not spelled canonically
    this._maxArchiveBytes = this._archiveBound(opts.archiveMaxBytes, process.env.SYM_ATTESTATION_ARCHIVE_MAX_BYTES);
    // At start, each log is read up to a budget that covers what its caps hold, and of a larger log
    // only its newest part. A record can stay held while newer ones churn past it (a quiet attester's
    // attestations or checkpoints, a quiet position's witnesses), so each log is read whole: what the
    // caps hold, plus what a log may hold beyond that before it is rotated.
    const readAll = opts.maxReadBytes;
    const capBytes = {
      [ATT_FILE]: this._max * ATT_LINE,
      // Each held position may also hold the copy that conflicted with it.
      [CP_FILE]: this._maxCheckpointsPerAttester * this._maxAttesters * CP_LINE * 2,
      [WIT_FILE]: this._maxWitnesses * WIT_LINE + this._maxAttesters * OWN_LINE,
    };
    const wholeLog = (f) => capBytes[f] + Math.max(this._rotateBytes, capBytes[f]);
    this._readBudget = {
      [ATT_FILE]: readAll || wholeLog(ATT_FILE),
      [CP_FILE]: readAll || wholeLog(CP_FILE),
      [WIT_FILE]: readAll || wholeLog(WIT_FILE),
    };
    if (this._dir) {
      try { fs.mkdirSync(this._dir, { recursive: true }); } catch { /* best effort */ }
      this._load();
    }
  }

  /**
   * Record an (already signature-verified) attestation. Idempotent — a signature already
   * seen, however it is spelled, is a no-op, so relay/replay converge rather than duplicate.
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
    const key = sigKey(att.sig);
    if (this._seen.has(key)) return { stored: false, reason: 'duplicate' };
    // One form for everything: the signature is stored as its signer wrote it, so the chain link
    // (`prev` is the hash of the previous signature as written) and the checkpoint's Merkle root
    // are computed over that, as dedup is. Gossip refuses another spelling; a log written before
    // 0.14.0 may hold one, which is read as the canonical spelling, and counted.
    if (key !== att.sig) {
      att = { ...att, sig: key };
      if (this._loading) this._respelled++;
    }
    if (opts.ingested && !this._allowIngest(att.of, att.by, opts.now ?? Date.now())) {
      return { stored: false, reason: 'rate-limited' };
    }
    // No receipt time is kept: an attestation counts by its signer's role in the in-force set when the
    // weight is applied (MMP §6.6.10), so neither its signed time nor when this node received it plays
    // a part.

    let mine = this._heldBy.get(att.by);
    if (mine) this._heldBy.delete(att.by);
    else {
      mine = new Set();
      // At most maxAttesters chains: a new attester takes the place of the one updated least recently
      // (never this node's own, which restores its chain cursor at start).
      if (this._heldBy.size >= this._maxAttesters) this._dropAttester(this._leastRecentAttester());
    }
    this._heldBy.set(att.by, mine);   // most recently updated last
    mine.add(key);
    this._recount(att.by, mine.size - 1, mine.size);
    this._seen.add(key);
    this._order.set(key, { of: att.of, by: att.by, seq: att.seq });

    let cmbIdx = this._byCmb.get(att.of);
    if (!cmbIdx) { cmbIdx = new Map(); this._byCmb.set(att.of, cmbIdx); }
    cmbIdx.set(key, att);

    let chain = this._byAttester.get(att.by);
    if (!chain) { chain = new Map(); this._byAttester.set(att.by, chain); }
    chain.set(att.seq, att);

    this._keep(ATT_FILE, att);
    this._evict();
    this._maybeRotate(ATT_FILE);
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

  /** Whether an attestation with this signature is held, however the signature is spelled. */
  has(sig) { return this._seen.has(sigKey(sig)); }
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
      if (prevAtt && cur.prev !== chainHash(prevAtt.sig) && !(prevAtt.assertionId === undefined && cur.prev === chainHash013(prevAtt.sig))) breaks.push(s);
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
    if (isChained(cp)) {
      // sym-attest-v1 §5.2 as MMP 2.0 update 1 revises it: chained checkpoints (fromSeq, prev).
      if (!(isPosition(cp.from_seq) && cp.from_seq >= 1 && cp.upto_seq >= cp.from_seq && typeof cp.prev === 'string')) return { stored: false, reason: 'malformed' };
      if (!this.linkValid(cp)) return { stored: false, reason: 'malformed-link' };
      if (existing && sameCheckpoint(existing, cp)) return { stored: false, reason: 'duplicate' };
      const ev = this._conflicted.get(cp.by);
      if (ev && [...ev.values()].some((c) => sameCheckpoint(c, cp))) return { stored: false, reason: 'duplicate' };
      // After a conflict this attester's further checkpoints are dropped (which bounds the evidence).
      if (ev) return { stored: false, reason: 'attester-equivocated' };
      // Two checkpoints from one attester whose ranges overlap, or that name the same prev, prove two
      // histories, whatever boundaries each was cut at. The first held stays; this one is the evidence.
      if (m) {
        for (const held of m.values()) {
          if (!isChained(held)) continue;
          const because = checkpointConflict(held, cp);
          if (because.length === 0) continue;
          const first = this._markConflict(cp.by, cp.upto_seq, cp);
          if (first) { this._keep(CP_FILE, cp); this._maybeRotate(CP_FILE); }
          return { stored: false, reason: 'conflict', keptRoot: held.root, kept: held, because, first };
        }
      }
    } else if (existing) {
      // An unchained checkpoint (a log written before update 1): one per position, as it was.
      if (existing.root === cp.root) return { stored: false, reason: 'duplicate' };
      const first = this._markConflict(cp.by, cp.upto_seq, cp);
      if (first) { this._keep(CP_FILE, cp); this._maybeRotate(CP_FILE); }
      return { stored: false, reason: 'conflict', keptRoot: existing.root, first };
    }
    let dropped = false;
    if (m && m.size >= this._maxCheckpointsPerAttester) {
      let oldest = Infinity;
      for (const k of m.keys()) if (k < oldest) oldest = k;
      if (cp.upto_seq < oldest) return { stored: false, reason: 'stale' };
      this._unkeep(CP_FILE, m.get(oldest));
      m.delete(oldest);
      this._dropWitnessesOf(cp.by, oldest);
      this._dropConflict(cp.by, oldest);   // a conflict is kept while its position is
      dropped = true;
    }
    if (!m) {
      m = new Map();
      if (this._checkpoints.size >= this._maxAttesters) {
        const [victim, held] = this._checkpoints.entries().next().value;   // the attester updated least recently
        for (const [seq, old] of held) { this._unkeep(CP_FILE, old); this._dropWitnessesOf(victim, seq); }
        this._checkpoints.delete(victim);
        for (const seq of [...(this._conflicted.get(victim)?.keys() || [])]) this._dropConflict(victim, seq);
        this._ownWitnessed.delete(victim);
        dropped = true;
      }
    }
    m.set(cp.upto_seq, cp);
    this._checkpoints.delete(cp.by);
    this._checkpoints.set(cp.by, m);
    this._keep(CP_FILE, cp);
    for (const [k, w] of [...this._pending]) {
      if (w.attester === cp.by && w.upto_seq === cp.upto_seq) { this._unpend(k); this.recordWitness(w); }
    }
    this._maybeRotate(CP_FILE);
    if (dropped) this._maybeRotate(WIT_FILE);   // witnesses went with the dropped positions
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
    if (w.from_seq !== undefined && !(isPosition(w.from_seq) && w.from_seq >= 1 && w.upto_seq >= w.from_seq)) return { stored: false, reason: 'malformed' };
    // This node's own witness is remembered before anything else is decided, so one that waits or
    // is refused still counts as signed (witness once, across restarts).
    const own = !!this._selfId && w.by === this._selfId;
    const ownKnown = own && !!this._ownWitnessed.get(w.attester)?.has(w.upto_seq);
    if (own) this._markOwnWitness(w.attester, w.upto_seq);
    const existing = this.witnessAt(w.attester, w.upto_seq, w.by);
    if (existing) {
      if (existing.root === w.root) return { stored: false, reason: 'duplicate' };
      return { stored: false, reason: 'conflict', keptRoot: existing.root, first: this._noteWitnessConflict(w) };
    }
    // A witness carries its checkpoint's range (update 1, sym-attest-v1 §5.3). It is not attester-signed,
    // so it is never equivocation evidence against the attester. Naming the range of an attester-signed
    // checkpoint held with another root, it is evidence against the witness (`disagrees`: refused, and
    // the node may mute the witness). Overlapping a held checkpoint without matching it, it is a lead
    // (`lead`: refused, and said), not proof of anything.
    if (w.from_seq !== undefined) {
      const a = this.witnessAssessment(w);
      if (a.evidenceAgainstWitness) return { stored: false, reason: 'disagrees', keptRoot: a.kept.root, first: this._noteWitnessConflict(w) };
      if (a.lead) return { stored: false, reason: 'lead', first: this._noteWitnessConflict(w) };
    }
    const cpHeld = this.checkpointAt(w.attester, w.upto_seq);
    if (!cpHeld) {
      const k = witnessKey(w.attester, w.upto_seq, w.by);
      const p = this._pending.get(k);
      if (p) {
        if (p.root === w.root) return { stored: false, reason: 'duplicate' };
        return { stored: false, reason: 'conflict', keptRoot: p.root, first: this._noteWitnessConflict(w) };
      }
      if (this._loading) {
        // Read from the live log: it stays there (a rotation writes it again) until it is promoted
        // or the waiting set lets it go. One heard on the network waits in memory only.
        this._fromLog.add(w);
        this._recBytes.set(w, this._replayBytes);
        if (this._dir) this._held[WIT_FILE] += this._replayBytes;
      }
      this._pending.set(k, w);
      if (this._pending.size > this._maxPending) this._unpend(this._pending.keys().next().value);
      return { stored: false, reason: 'pending' };
    }
    let byPos = this._witnesses.get(w.attester);
    if (!byPos) { byPos = new Map(); this._witnesses.set(w.attester, byPos); }
    let m = byPos.get(w.upto_seq);
    if (!m) { m = new Map(); byPos.set(w.upto_seq, m); this._positions.set(positionKey(w.attester, w.upto_seq), [w.attester, w.upto_seq]); }
    if (m.size >= this._maxWitnessesPerPosition) {
      // This node's own witness is written even when the position cannot hold it, so a restart still
      // knows it was signed; it is read back as remembered, not stored (and a rotation keeps it in
      // this node's own-witness line). Once: a later copy of a statement already remembered adds
      // nothing to the log, and what was written counts toward the next rotation like any waste.
      if (own && !ownKnown && !this._fromLog.has(w)) {
        this._appendLine(WIT_FILE, JSON.stringify(w) + '\n');
        this._maybeRotate(WIT_FILE);
      }
      return { stored: false, reason: 'position-full' };
    }
    m.set(w.by, w);
    this._witnessCount++;
    // One read from the live log and kept waiting is already in it: promoting it must not append it again.
    this._keep(WIT_FILE, w, !this._fromLog.has(w));
    while (this._witnessCount > this._maxWitnesses && this._positions.size) {
      const [a, seq] = this._positions.values().next().value;   // the oldest position, unlisted as it goes
      this._dropWitnessesOf(a, seq);
    }
    this._maybeRotate(WIT_FILE);
    return { stored: true };
  }

  /** @private Let a waiting witness go (promoted, or out of the bounded set). One read from the live
   *  log stops counting as held there. */
  _unpend(k) {
    const w = this._pending.get(k);
    if (!w) return;
    this._pending.delete(k);
    if (this._dir && this._fromLog.has(w)) this._held[WIT_FILE] -= this._recBytes.get(w) || 0;
  }

  /** @private Remember a witness conflict, and the root it asserted, once; bounded.
   *  @returns {boolean} whether it is newly seen */
  _noteWitnessConflict(w) {
    const k = witnessKey(w.attester, w.upto_seq, w.by);
    if (this._witnessConflicts.has(k)) return false;
    this._witnessConflicts.set(k, w.root);
    if (this._witnessConflicts.size > 1024) this._witnessConflicts.delete(this._witnessConflicts.keys().next().value);
    return true;
  }

  /** @private Drop the witnesses of a position (its checkpoint dropped, or the oldest under the cap).
   *  O(witnesses at the position): the position is unlisted by key, never searched for. */
  _dropWitnessesOf(attester, upto_seq) {
    this._positions.delete(positionKey(attester, upto_seq));
    const byPos = this._witnesses.get(attester);
    const m = byPos && byPos.get(upto_seq);
    if (!m) return;
    this._witnessCount -= m.size;
    for (const w of m.values()) this._unkeep(WIT_FILE, w);
    byPos.delete(upto_seq);
    if (byPos.size === 0) this._witnesses.delete(attester);
  }

  /** @private Remember a checkpoint this node witnessed itself; kept per attester, newest 256. */
  _markOwnWitness(attester, upto_seq) {
    let set = this._ownWitnessed.get(attester);
    if (!set) {
      set = new Set();
      if (this._ownWitnessed.size >= this._maxAttesters) this._ownWitnessed.delete(this._ownWitnessed.keys().next().value);
    }
    this._ownWitnessed.delete(attester);
    this._ownWitnessed.set(attester, set);   // most recently marked last
    set.add(upto_seq);
    if (set.size > 256) {
      let oldest = Infinity;
      for (const k of set) if (k < oldest) oldest = k;
      set.delete(oldest);
    }
  }

  /** @private Remember that a second root was refused for a held position (by, upto_seq), with the
   *  copy that asserted it (a rotation writes it after the kept one, so a restart re-derives the
   *  conflict). Bounded by the held positions: a dropped position drops its conflict.
   *  @returns {boolean} whether this position is newly conflicted */
  _markConflict(by, upto_seq, copy) {
    let m = this._conflicted.get(by);
    if (m && m.has(upto_seq)) return false;
    if (!m) { m = new Map(); this._conflicted.set(by, m); }
    m.set(upto_seq, copy);
    return true;
  }

  /** @private Forget the conflict of a dropped position. */
  _dropConflict(by, upto_seq) {
    const m = this._conflicted.get(by);
    const copy = m && m.get(upto_seq);
    if (!copy) return;
    this._unkeep(CP_FILE, copy);
    m.delete(upto_seq);
    if (m.size === 0) this._conflicted.delete(by);
  }

  /** Whether a second, different root was refused for (by, upto_seq). */
  hasConflict(by, upto_seq) { return !!this._conflicted.get(by)?.has(upto_seq); }

  /** Whether this node holds evidence that `by` signed two histories (sym-attest-v1 §5.2): it then
   *  witnesses none of its checkpoints and drops its further ones unverified. */
  attesterEquivocated(by) { return this._conflicted.has(by); }

  /** The link checks of a chained checkpoint (§5.2) against what is held: not reversed, prev genesis
   *  exactly when fromSeq is 1, and when the checkpoint its prev names is held, starting right after
   *  it. A failure is malformed, never evidence. */
  linkValid(cp) {
    if (!isChained(cp)) return true;
    const m = this._checkpoints.get(cp.by);
    let prevCp = null;
    if (m && cp.prev !== 'genesis') for (const h of m.values()) if (isChained(h) && h.root === cp.prev) { prevCp = h; break; }
    return checkpointLinkValid(cp, prevCp);
  }

  /**
   * What a chained witness shows against the attester's checkpoints held (sym-attest-v1 §5.3): never
   * equivocation evidence; a lead when it overlaps one without being its range and root; evidence
   * against the witness when it names one's range with another root (`kept` is that checkpoint).
   */
  witnessAssessment(w) {
    const m = this._checkpoints.get(w.attester);
    let lead = false; let kept = null;
    if (m) {
      for (const cp of m.values()) {
        if (!isChained(cp)) continue;
        const sameRange = cp.from_seq === w.from_seq && cp.upto_seq === w.upto_seq;
        if (cp.from_seq <= w.upto_seq && w.from_seq <= cp.upto_seq && !(sameRange && cp.root === w.root)) lead = true;
        if (sameRange && cp.root !== w.root) kept = cp;
      }
    }
    return { equivocationEvidence: false, lead, evidenceAgainstWitness: !!kept, kept };
  }

  /** The newest chained checkpoint an attester has committed, or null. */
  latestChainedCheckpoint(by) {
    const m = this._checkpoints.get(by);
    let best = null;
    if (m) for (const h of m.values()) if (isChained(h) && (!best || h.upto_seq > best.upto_seq)) best = h;
    return best;
  }

  /** The refused copy with the other root for a held (by, upto_seq), or null. */
  conflictAt(by, upto_seq) { return this._conflicted.get(by)?.get(upto_seq) || null; }

  /** The checkpoint held for (by, upto_seq), or null. */
  checkpointAt(by, upto_seq) { return this._checkpoints.get(by)?.get(upto_seq) || null; }

  /** Whether a checkpoint for (by, upto_seq) would be refused as older than every position held. O(32). */
  isStale(by, upto_seq) {
    const m = this._checkpoints.get(by);
    if (!m || m.size < this._maxCheckpointsPerAttester || m.has(upto_seq)) return false;
    for (const k of m.keys()) if (k < upto_seq) return false;
    return true;
  }

  /** The witness `by` holds for (attester, upto_seq), or null. */
  witnessAt(attester, upto_seq, by) { return this._witnesses.get(attester)?.get(upto_seq)?.get(by) || null; }

  /** The witness `by` holds or has waiting for (attester, upto_seq), or null. O(1). */
  witnessSeen(attester, upto_seq, by) {
    return this.witnessAt(attester, upto_seq, by) || this._pending.get(witnessKey(attester, upto_seq, by)) || null;
  }

  /** The other root `by` was refused for, for (attester, upto_seq), while that is remembered; or null. */
  witnessConflictRoot(attester, upto_seq, by) { return this._witnessConflicts.get(witnessKey(attester, upto_seq, by)) ?? null; }

  /** Whether `by` has witnessed (attester, upto_seq) already, in any copy. For this node itself it
   *  also counts a witness its index has since dropped. */
  hasWitnessed(attester, upto_seq, by) {
    if (this._selfId && by === this._selfId && this._ownWitnessed.get(attester)?.has(upto_seq)) return true;
    return this.witnessSeen(attester, upto_seq, by) !== null;
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

  // ── Durable persistence (append-only JSONL, rotated) ─────────────────────────

  /** @private A record is now held: its line's bytes count as held, and it is appended to its log
   *  (unless it is being replayed from it, or `append` is false because it is already in it). */
  _keep(file, rec, append = true) {
    if (!this._dir) return;
    let bytes = this._recBytes.get(rec);
    let line = null;
    if (bytes === undefined) {
      if (this._loading) bytes = this._replayBytes;
      else { line = JSON.stringify(rec) + '\n'; bytes = Buffer.byteLength(line); }
      this._recBytes.set(rec, bytes);
    }
    this._held[file] += bytes;
    if (append && !this._loading) this._appendLine(file, line || JSON.stringify(rec) + '\n');
  }

  /** @private A record is no longer held: its line is now waste in the log until the next rotation. */
  _unkeep(file, rec) {
    if (!this._dir || !rec) return;
    this._held[file] -= this._recBytes.get(rec) || 0;
  }

  /** @private Append one line to a live log. Best effort: a failed append is never fatal (the record
   *  is held, and the next rotation writes it). No-op without a dir or while replaying. */
  _appendLine(file, line) {
    if (!this._dir || this._loading) return;
    try {
      fs.appendFileSync(path.join(this._dir, file), line);
      this._logBytes[file] += Buffer.byteLength(line);
    } catch { /* best effort — never let persistence break gating */ }
  }

  /** Replay persisted records into the in-memory index on construction. Reuses the
   *  normal record paths (which dedup), with `_loading` suppressing re-writes. A
   *  malformed line is skipped, never fatal. Then a crashed rotation is tidied up, and a log that is
   *  over budget (by the same rule as at run time) is rotated. */
  _load() {
    this._loading = true;
    this._replay(ATT_FILE, (o) => this.record(o));
    this._replay(CP_FILE, (o) => this.recordCheckpoint(o));
    this._replay(WIT_FILE, (o) => (o && o.type === OWN_WITNESSED ? this._restoreOwn(o) : this.recordWitness(o)));
    this._loading = false;
    if (this._respelled > 0) {
      this._say('respelled', `${this._respelled} attestation(s) in ${ATT_FILE} carried a signature not spelled as its signer wrote it (stored before 0.14.0); each was read as the canonical spelling`);
    }
    this._tidy();
    for (const file of LOGS) this._maybeRotate(file);
  }

  /** @private This node's own-witness line, as a rotation writes it: the positions it signed for one
   *  attester. Read for this node's id only; the line counts as held. Like every line replayed it is
   *  not verified, and a forged one can only stop this node from signing a witness. */
  _restoreOwn(o) {
    if (!this._selfId || o.by !== this._selfId || !o.attester || !Array.isArray(o.positions)) return;
    for (const p of o.positions.slice(-256)) if (isPosition(p)) this._markOwnWitness(o.attester, p);
    this._held[WIT_FILE] += this._replayBytes;
  }

  _replay(file, fn) {
    const p = path.join(this._dir, file);
    const budget = this._readBudget[file];
    let size;
    try { size = fs.statSync(p).size; } catch (e) {
      if (e.code === 'ENOENT') return; // no log yet
      return this._cannotRead(file, e);
    }
    let text;
    try {
      if (size <= budget) text = fs.readFileSync(p, 'utf8');
      else {
        // The newest part only: what a bounded store keeps. Reading a whole oversized log (one was
        // 257 MB of storm) held a node's thread for minutes at every start. What is not read counts
        // as waste, so such a log is rotated once it is loaded.
        const fd = fs.openSync(p, 'r');
        try {
          const buf = Buffer.alloc(budget);
          // A read may return short (a network or FUSE filesystem): it is completed, and a log that
          // cannot be read in full is not taken as read.
          let n = 0;
          while (n < buf.length) {
            const r = fs.readSync(fd, buf, n, buf.length - n, size - buf.length + n);
            if (!(r > 0)) break;
            n += r;
          }
          if (n < buf.length) throw Object.assign(new Error(`read ${n} of ${buf.length} bytes`), { code: 'ESHORTREAD' });
          text = buf.subarray(buf.indexOf(0x0a) + 1, n).toString('utf8'); // the cut first line is skipped
        } finally { fs.closeSync(fd); }
      }
    } catch (e) {
      return this._cannotRead(file, e);
    }
    // Only a log that was read counts its bytes: what was read and not held is waste a rotation may
    // reclaim, and an unread log has nothing known to be waste.
    this._logBytes[file] = size;
    for (const line of text.split('\n')) {
      if (!line.trim()) continue;
      let o;
      try { o = JSON.parse(line); } catch { continue; } // skip a corrupt line
      this._replayBytes = Buffer.byteLength(line) + 1;
      try { fn(o); } catch { /* skip a record that does not fit */ }
    }
    this._replayBytes = 0;
  }

  /** @private A log that exists but could not be read at start (too large for memory, an I/O
   *  error): nothing in it is known, so it is never rotated or rewritten by this process, only
   *  appended to. Said once. */
  _cannotRead(file, err) {
    this._unread.add(file);
    const code = (err && (err.code || err.message)) || String(err);
    this._say(`unread|${file}|${code}`, `${file} could not be read at start (${code}); it is kept as it is, appended to, and not rotated until a start reads it`);
  }

  // ── Rotation ─────────────────────────────────────────────────────────────────

  /**
   * @private Rotate a log once the bytes in it beyond the records held exceed the larger of
   * `rotateBytes` and the bytes of the records held. Every rotation therefore reclaims more than it
   * writes, a rotation is never followed by another until that much more has been appended and
   * dropped, and a start (which applies the same rule to the log as it finds it) rotates only a log
   * that is over budget. After a failed rotation it is retried only after another such budget.
   * O(1): two comparisons per record stored.
   */
  _maybeRotate(file) {
    if (!this._dir || this._loading || this._unread.has(file)) return;
    const held = this._held[file];
    if (this._logBytes[file] - held <= Math.max(this._rotateBytes, held)) return;
    if (this._logBytes[file] < this._retryAt[file]) return;
    this._rotate(file);
  }

  /** @private The records a rotation writes, in the order that replays to the same store. */
  * _heldRecords(file) {
    if (file === ATT_FILE) {
      for (const [sig, { of }] of this._order) { const a = this._byCmb.get(of)?.get(sig); if (a) yield a; }
    } else if (file === CP_FILE) {
      // Attesters least recently updated first; each conflicting copy after every kept one, so a
      // replay keeps the first and re-derives the conflict.
      for (const m of this._checkpoints.values()) yield* m.values();
      for (const m of this._conflicted.values()) yield* m.values();
    } else {
      // Positions in the order they got their first witness (the global cap drops the oldest first),
      // then the witnesses read from the log that still wait for their checkpoint: a rotation keeps
      // them in the log, where a restart finds them again.
      for (const [a, seq] of this._positions.values()) { const m = this._witnesses.get(a)?.get(seq); if (m) yield* m.values(); }
      for (const w of this._pending.values()) if (this._fromLog.has(w)) yield w;
    }
  }

  /**
   * @private Rotate one log: write the records held to a temp file (every byte, then fsync), link the
   * old log into archive/ under a name no other rotation can take (copied where the filesystem has no
   * hard links), then rename the temp file over the live log. Until the rename the live log is
   * untouched, and the rename replaces it whole, so the live path holds a complete log at every
   * instant. A failure at any step removes what the rotation made, leaves the live log as it was, is
   * said once per distinct error, and is retried after another budget. @returns {boolean}
   */
  _rotate(file) {
    const live = path.join(this._dir, file);
    const base = file.slice(0, -'.jsonl'.length);
    const tmp = `${live}.${process.pid}.${++this._tmpSeq}.rotating`;
    const sizes = [];
    let step = 'write';
    let fd = null;
    let archived = null;
    let marker = null;
    let written = 0;
    try {
      fd = fs.openSync(tmp, 'wx');
      let chunk = '';
      const add = (line) => {
        chunk += line;
        if (chunk.length >= WRITE_CHUNK) { written += writeAll(fd, Buffer.from(chunk)); chunk = ''; }
      };
      for (const rec of this._heldRecords(file)) {
        const line = JSON.stringify(rec) + '\n';
        sizes.push([rec, Buffer.byteLength(line)]);
        add(line);
      }
      if (file === WIT_FILE && this._selfId) {
        // This node's own-witness memory, one line per attester, so a restart knows what it signed
        // even when the witness itself is no longer held.
        for (const [attester, set] of this._ownWitnessed) {
          add(JSON.stringify({ type: OWN_WITNESSED, by: this._selfId, attester, positions: [...set].sort((x, y) => x - y) }) + '\n');
        }
      }
      if (chunk) written += writeAll(fd, Buffer.from(chunk));
      step = 'fsync';
      fs.fsyncSync(fd);
      const onDisk = fs.fstatSync(fd).size;
      if (onDisk !== written) throw Object.assign(new Error(`${onDisk} of ${written} bytes on disk`), { code: 'ESHORTWRITE' });
      fs.closeSync(fd);
      fd = null;
      step = 'archive';
      const made = this._archive(live, base);
      archived = made && made.dest;
      marker = made && made.marker;
      step = 'rename';
      fs.renameSync(tmp, live);
    } catch (err) {
      if (fd !== null) { try { fs.closeSync(fd); } catch { /* closing */ } }
      try { fs.unlinkSync(tmp); } catch { /* not made */ }
      // An archive name left on the live log would grow with it: it is removed with the rest.
      if (archived) { try { fs.unlinkSync(archived); } catch { /* best effort; a start removes it too */ } }
      if (marker) { try { fs.unlinkSync(marker); } catch { /* best effort */ } }
      const wait = Math.max(this._rotateBytes, this._held[file]);
      this._retryAt[file] = this._logBytes[file] + wait;
      const code = (err && (err.code || err.message)) || String(err);
      this._say(`rotate|${file}|${step}|${code}`, `${file} not rotated (${step}: ${code}); the live log is unchanged, retried after another ${wait} bytes`);
      return false;
    }
    if (marker) { try { fs.unlinkSync(marker); } catch { /* a start removes it */ } }
    this._syncDir(this._dir);
    for (const [rec, bytes] of sizes) this._recBytes.set(rec, bytes);
    this._logBytes[file] = written;
    this._held[file] = written;
    this._retryAt[file] = 0;
    this._rotations[file]++;
    this._pruneArchive(base);
    return true;
  }

  /** @private Put the live log into archive/ under a fresh name, never over an existing one.
   *  @returns {string|null} the archive path, or null when there is no live log */
  _archive(live, base) {
    try { fs.statSync(live); } catch (e) { if (e.code === 'ENOENT') return null; throw e; }
    let marker = null;
    const dir = path.join(this._dir, ARCHIVE_DIR);
    fs.mkdirSync(dir, { recursive: true });
    for (let tries = 0; tries < 8; tries++) {
      const dest = path.join(dir, this._archiveName(dir, base));
      try {
        fs.linkSync(live, dest);   // EEXIST rather than replace
      } catch (e) {
        if (e.code === 'EEXIST') continue;
        if (!NO_LINK.has(e.code)) throw e;
        // No hard links here: copy it, never over an existing name, and make the copy durable before
        // the live log is replaced. A marker names the copy until the live log is replaced, so a
        // start after a crash in between can tell a copy of the live log from a real archive.
        try {
          if (!marker) marker = `${live}.${process.pid}.${++this._tmpSeq}.archiving`;
          fs.writeFileSync(marker, path.basename(dest));
          fs.copyFileSync(live, dest, fs.constants.COPYFILE_EXCL);
          const cfd = fs.openSync(dest, 'r+');
          try { fs.fsyncSync(cfd); } finally { fs.closeSync(cfd); }
        } catch (c) {
          if (c.code === 'EEXIST') continue;
          try { fs.unlinkSync(dest); } catch { /* not made */ }
          if (marker) { try { fs.unlinkSync(marker); } catch { /* not made */ } }
          throw c;
        }
      }
      this._syncDir(dir);
      return { dest, marker };
    }
    if (marker) { try { fs.unlinkSync(marker); } catch { /* not made */ } }
    throw Object.assign(new Error('no free archive name'), { code: 'EEXIST' });
  }

  /** @private A name no other rotation takes: the next sequence after every archive of this log on
   *  disk (and every one this store made), then the time and this process's pid. */
  _archiveName(dir, base) {
    let seq = this._archiveSeq;
    for (const f of this._archives(dir, base)) if (f.seq > seq) seq = f.seq;
    this._archiveSeq = seq + 1;
    const stamp = new Date().toISOString().replace(/[-:.]/g, '');
    return `${base}.${String(this._archiveSeq).padStart(12, '0')}.${stamp}.${process.pid}.jsonl`;
  }

  /** @private One log's archives, oldest first: by sequence, then time, then pid, then name — a
   *  total order that does not depend on file times. */
  _archives(dir, base) {
    let names;
    try { names = fs.readdirSync(dir); } catch (e) { if (e.code === 'ENOENT') return []; throw e; }
    const out = [];
    for (const name of names) {
      const m = ARCHIVE_NAME.exec(name);
      if (m && m[1] === base) out.push({ name, file: path.join(dir, name), seq: Number(m[2]), stamp: m[3], pid: Number(m[4]) });
    }
    const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
    return out.sort((a, b) => a.seq - b.seq || cmp(a.stamp, b.stamp) || a.pid - b.pid || cmp(a.name, b.name));
  }

  /** @private The archive bound: the option, else the environment, else 128 MiB; 0 keeps every
   *  archive. A value that is not a number of bytes ≥ 0 is not used, and that is said once. */
  _archiveBound(option, env) {
    const configured = option !== undefined ? option : env;
    if (configured === undefined || configured === null || configured === '') return ARCHIVE_MAX_DEFAULT;
    const n = typeof configured === 'number' ? configured
      : (typeof configured === 'string' && /^\s*\d+\s*$/.test(configured) ? Number(configured) : NaN);
    if (Number.isFinite(n) && n >= 0) return Math.floor(n);
    const from = option !== undefined ? 'archiveMaxBytes' : 'SYM_ATTESTATION_ARCHIVE_MAX_BYTES';
    this._say(`archive-bound|${from}`, `${from}=${JSON.stringify(configured)} is not a number of bytes ≥ 0; archive/ keeps ${ARCHIVE_MAX_DEFAULT} bytes per log`);
    return ARCHIVE_MAX_DEFAULT;
  }

  /** @private Keep at most `archiveMaxBytes` of one log's archives, the newest included: the oldest
   *  go first, and one that alone exceeds the bound goes too. A failed unlink stops the prune (a newer
   *  archive is never deleted before an older one); it is said once and retried at the next rotation. */
  _pruneArchive(base) {
    if (this._maxArchiveBytes === 0) return;   // 0: every archive is kept
    try {
      const files = [];
      for (const f of this._archives(path.join(this._dir, ARCHIVE_DIR), base)) {
        try { f.size = fs.statSync(f.file).size; files.push(f); } catch { /* gone */ }
      }
      let total = files.reduce((sum, f) => sum + f.size, 0);
      for (const f of files) {
        if (total <= this._maxArchiveBytes) break;
        fs.unlinkSync(f.file);
        total -= f.size;
      }
    } catch (err) {
      const code = (err && (err.code || err.message)) || String(err);
      this._say(`prune|${base}|${code}`, `archive of ${base} not pruned (${code}); retried at the next rotation`);
    }
  }

  /** @private At start, undo what a rotation that crashed part way left: its temp file, and an archive
   *  name still on the live log's inode (linked, but never renamed away from). Then each archive is
   *  held to its bound. */
  _tidy() {
    let names = [];
    try { names = fs.readdirSync(this._dir); } catch { return; }
    const dir = path.join(this._dir, ARCHIVE_DIR);
    // Only what a crashed rotation left: a file a live process other than this one is still using
    // (its pid is in the name) is part of a rotation in progress, and is left to it.
    for (const n of names) {
      const m = ROTATING_NAME.exec(n);
      if (m && !otherLiveProcess(Number(m[2]))) { try { fs.unlinkSync(path.join(this._dir, n)); } catch { /* best effort */ } }
    }
    for (const n of names) {
      const m = ARCHIVING_NAME.exec(n);
      if (!m || otherLiveProcess(Number(m[2]))) continue;
      // A copy made where there are no hard links, and a crash before the live log was replaced: if
      // the copy is the live log, byte for byte, it is not an archive of anything. (If the live log was
      // replaced, the copy is the old log, a real archive, and is kept.)
      try {
        const copy = path.join(dir, path.basename(fs.readFileSync(path.join(this._dir, n), 'utf8').trim()));
        if (ARCHIVE_NAME.test(path.basename(copy)) && sameBytes(copy, path.join(this._dir, `${m[1]}.jsonl`))) fs.unlinkSync(copy);
      } catch { /* best effort */ }
      try { fs.unlinkSync(path.join(this._dir, n)); } catch { /* best effort */ }
    }
    for (const file of LOGS) {
      const base = file.slice(0, -'.jsonl'.length);
      let archives = [];
      try { archives = this._archives(dir, base); } catch { continue; }
      if (archives.length === 0) continue;
      let live = null;
      try { live = fs.statSync(path.join(this._dir, file), { bigint: true }); } catch { /* none */ }
      if (live && live.ino !== 0n) {
        for (const f of archives) {
          if (otherLiveProcess(f.pid)) continue;
          try {
            const st = fs.statSync(f.file, { bigint: true });
            if (st.ino === live.ino && st.dev === live.dev) fs.unlinkSync(f.file);
          } catch { /* best effort */ }
        }
      }
      this._pruneArchive(base);
    }
  }

  /** @private fsync a directory, so a link or rename in it is durable. Best effort (not on Windows). */
  _syncDir(dir) {
    let fd = null;
    try { fd = fs.openSync(dir, 'r'); fs.fsyncSync(fd); } catch { /* not supported here */ }
    finally { if (fd !== null) { try { fs.closeSync(fd); } catch { /* closing */ } } }
  }

  /** @private Say a rotation problem once per distinct error. */
  _say(key, msg) {
    if (this._said.has(key)) return;
    if (this._said.size >= 256) this._said.clear();
    this._said.add(key);
    try { this._logFn(msg); } catch { /* a log sink must not break gating */ }
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

  /** @private While over the cap, the attester holding the most loses its oldest attestation. When the
   *  store is over the cap some attester holds more than its share (max / attesters held), and the one
   *  holding the most is such an attester, so no attester at or under its share loses anything. O(1). */
  _evict() {
    while (this._seen.size > this._max && this._maxCount > 0) {
      const [by] = this._byCount.get(this._maxCount);
      this._dropAttestation(this._heldBy.get(by).values().next().value);
    }
  }

  /** @private The attester updated least recently, other than this node itself. */
  _leastRecentAttester() {
    const it = this._heldBy.keys();
    const first = it.next().value;
    return first === this._selfId && this._heldBy.size > 1 ? it.next().value : first;
  }

  /** @private Drop every attestation one attester has here. O(its chain). */
  _dropAttester(by) {
    const mine = this._heldBy.get(by);
    if (mine) for (const key of [...mine]) this._dropAttestation(key);
  }

  /** @private Drop one attestation from every index. */
  _dropAttestation(key) {
    const e = this._order.get(key);
    if (!e) return;
    this._order.delete(key);
    this._seen.delete(key);
    const cmbIdx = this._byCmb.get(e.of);
    const att = cmbIdx && cmbIdx.get(key);
    if (att) this._unkeep(ATT_FILE, att);
    if (cmbIdx) { cmbIdx.delete(key); if (cmbIdx.size === 0) this._byCmb.delete(e.of); }
    // Two attestations can share a position (a chain restarted): only this one's slot is cleared.
    const chain = this._byAttester.get(e.by);
    if (chain && chain.get(e.seq) === att) { chain.delete(e.seq); if (chain.size === 0) this._byAttester.delete(e.by); }
    const mine = this._heldBy.get(e.by);
    if (mine && mine.delete(key)) {
      this._recount(e.by, mine.size + 1, mine.size);
      if (mine.size === 0) this._heldBy.delete(e.by);
    }
  }

  /** @private An attester's count went from `from` to `to` (by one, or to 0 when its chain is
   *  dropped one by one): move it between the count sets and keep the most held. Amortised O(1). */
  _recount(by, from, to) {
    if (from > 0) {
      const s = this._byCount.get(from);
      if (s) { s.delete(by); if (s.size === 0) this._byCount.delete(from); }
    }
    if (to > 0) {
      let s = this._byCount.get(to);
      if (!s) { s = new Set(); this._byCount.set(to, s); }
      s.add(by);
      if (to > this._maxCount) this._maxCount = to;
    }
    while (this._maxCount > 0 && !this._byCount.has(this._maxCount)) this._maxCount--;
  }
}

module.exports = { AttestationStore, chainHash, isPosition, sigKey, isCanonicalSig };
