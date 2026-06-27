'use strict';

const fs = require('fs');
const path = require('path');

/**
 * SVAF Decision Log — an append-only, capped record of EVERY SVAF evaluation
 * (aligned / guarded / redundant / rejected).
 *
 * The memory store holds only ADMITTED CMBs. This log captures the act of
 * selective admission itself — crucially including rejections, which otherwise
 * leave no trace at all (a rejected CMB is simply not stored). That record is
 * what makes the node's autonomy observable: "divergent peers stay sovereign"
 * is a claim you can only show if the rejection was written down.
 *
 * Local-first (same trust boundary as ~/.sym/nodes/<name>/cmbs), label-only
 * (never persists the rejected payload — only the per-field metrics + a short
 * focus label), and bounded (a rejection storm must not fill the disk).
 *
 * Copyright (c) 2026 SYM.BOT Ltd.
 */
class DecisionLog {
  /**
   * @param {string} dir   directory to hold log.jsonl (e.g. ~/.sym/nodes/<name>/decisions)
   * @param {object} [opts]
   * @param {number} [opts.cap=2000]    max retained entries (ring + file)
   * @param {boolean} [opts.enabled=true]
   */
  constructor(dir, { cap = 2000, enabled = true } = {}) {
    this._dir = dir;
    this._file = path.join(dir, 'log.jsonl');
    this._cap = Math.max(50, cap | 0 || 2000);
    this._enabled = enabled !== false;
    this._ring = [];
    this._writes = 0;
    if (this._enabled) this._load();
  }

  _load() {
    try {
      const txt = fs.readFileSync(this._file, 'utf8');
      const lines = txt.split('\n');
      for (const l of lines.slice(-this._cap)) {
        const s = l.trim();
        if (!s) continue;
        try { this._ring.push(JSON.parse(s)); } catch { /* skip malformed */ }
      }
    } catch { /* no log yet — fine */ }
  }

  /**
   * Append one decision record. Never throws and never blocks intake — a log
   * failure must not affect cognition.
   */
  record(entry) {
    if (!this._enabled || !entry) return;
    this._ring.push(entry);
    if (this._ring.length > this._cap) this._ring.splice(0, this._ring.length - this._cap);
    try {
      fs.mkdirSync(this._dir, { recursive: true });
      // Periodic compaction keeps the file bounded to ~cap; cheap append between.
      if (this._writes++ % Math.max(1, Math.floor(this._cap / 4)) === 0) {
        fs.writeFileSync(this._file, this._ring.map((e) => JSON.stringify(e)).join('\n') + '\n');
      } else {
        fs.appendFileSync(this._file, JSON.stringify(entry) + '\n');
      }
    } catch { /* non-fatal */ }
  }

  /**
   * Newest-first decisions, optionally filtered.
   * @param {object} [opts] { limit=200, since=0, decision, source }
   */
  list({ limit = 200, since = 0, decision = null, source = null } = {}) {
    let out = this._ring;
    if (since) out = out.filter((e) => (e.ts || 0) >= since);
    if (decision) out = out.filter((e) => e.decision === decision);
    if (source) out = out.filter((e) => e.source === source);
    return out.slice(-Math.max(0, limit | 0)).reverse();
  }

  count() { return this._ring.length; }
}

module.exports = { DecisionLog };
