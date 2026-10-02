'use strict';

/**
 * @module @sym-bot/sym/roster-keys
 * @description The key registry: the ONE place where a nodeId gets an identity key (design D3,
 * Core Secure identity, 2026-10-02).
 *
 * A nodeId is a UUID v7 bound to an Ed25519 key through an authenticated transcript (MMP §18.3),
 * and a node has one key for life (§3.4). So a binding, once made, is never replaced by a
 * different key, whatever the source. The 0.13 rule "a strictly stronger source overrides" is
 * gone: it let any later source that outranked the first repoint a key.
 *
 * Sources, strongest first:
 *   anchor        — the configured anchor (§6.5/§6.6). Read from configuration at every start and
 *                   NEVER persisted to or replayed from the file, so re-pinning a fresh anchor out
 *                   of band takes effect at the next start.
 *   proven        — a confirmed §5.2 session proved possession of the key.
 *   pinned        — an out-of-band binding: an accepted invite naming the issuer's key, a Legacy
 *                   Import route's mandatory fingerprint, or an operator's resolution of a conflict.
 *   grant         — vouched by an anchor-rooted role grant (granteeKey, inside the signed payload).
 *   legacy-claim  — every pre-0.14 `handshake` entry, relabelled on first load. It was learned from
 *                   an unproven hello, so it verifies nothing; it is the EXPECTED key: a proven
 *                   session presenting it binds `proven`, and one presenting a different key is a
 *                   conflict, so a squatter racing the upgrade cannot take an honest node's id.
 *
 * The conflict matrix:
 *
 *   nodeId unbound, any source            → bind at that source
 *   nodeId bound, same key, any source    → keep; record the stronger source
 *   nodeId bound, DIFFERENT key, any      → conflict: refused, recorded (roster-conflicts.jsonl),
 *                                           shown in `sym status`; the operator resolves it
 *   the configured anchor                 → always its configured key
 *
 * Only `anchor`, `proven`, `pinned` and `grant` bindings verify anything (`get`). A `legacy-claim`
 * is reported by `expected` and by `source`, never by `get`.
 *
 * BINDING LIFETIME (design D3, 0.13.17 re-review). New keypairs are free, so a registry that only
 * grows can be filled by identity churn. A first-contact `proven` binding that has verified nothing
 * since — no record, grant or attestation verified under it, and no later session re-proving it — and
 * has not been seen for BINDING_TTL_MS (30 days) EXPIRES. A binding that ever verified something, or
 * is pinned, grant-vouched (a grant names its key), anchored or a legacy claim (the finite 0.13
 * migration), never expires, so no binding that protects history is forgotten. The facts `seen` and
 * `verified` are persisted with the binding (a `seen` line at most once a day per binding). This
 * replaces 0.13.17's cap of 16,384 never-evicted bindings, which anyone on the LAN could fill.
 *
 * The sticky floor of Legacy Import (design D7) is derived from here, not kept in memory: a nodeId
 * with a `proven` binding has spoken Core Secure, so its legacy route is refused until an operator
 * resets the floor (`resetFloor`), which is persisted too.
 *
 * File format (roster-keys.jsonl): a version marker line `{"v":2,...}`, then one JSON line per
 * binding event. A 0.13 reader skips the marker as malformed and reads the rest. A file without the
 * marker is a 0.13 file: it is replayed by the 0.13 rules, its `handshake` entries become
 * `legacy-claim`, its `anchor` entries are dropped, and it is rewritten once, atomically, with the
 * marker (idempotent: a marked file is never migrated again).
 *
 * @copyright 2026 SYM.BOT. Apache 2.0 License.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const KEYS_FILE = 'roster-keys.jsonl';
const CONFLICTS_FILE = 'roster-conflicts.jsonl';
const FORMAT_MARKER = Object.freeze({ v: 2, format: 'sym-roster-keys', note: 'sym 0.14 key registry; a 0.13 reader skips this line' });

/** Strength, for "record the stronger source" on the same key. The anchor is configuration. */
const SOURCE_RANK = Object.freeze({ 'legacy-claim': 1, grant: 2, pinned: 3, proven: 4, anchor: 5 });
const VERIFYING = new Set(['anchor', 'proven', 'pinned', 'grant']);
const SOURCES = new Set(Object.keys(SOURCE_RANK));
const rankOf = (s) => SOURCE_RANK[s] ?? 0;

/** Bindings kept at most (new proven/grant/legacy bindings are refused past it; pinned never are). */
const MAX_BINDINGS = 65536;
/** A first-contact proven binding that verified nothing expires after this long unseen. */
const BINDING_TTL_MS = 30 * 24 * 60 * 60 * 1000;
/** A `seen` or `verified` fact is written at most this often per binding (in memory it is exact). */
const FACT_PERSIST_MS = 24 * 60 * 60 * 1000;
/** Conflicts recorded at most per nodeId, and in all; past either, a conflict is only counted. */
const MAX_CONFLICTS_PER_NODE = 8;
const MAX_CONFLICTS = 1024;

/** An Ed25519 public key as the wire carries it: 32 raw bytes, unpadded base64url. */
function isIdentityKey(k) {
  return typeof k === 'string' && /^[A-Za-z0-9_-]{43}$/.test(k) && Buffer.from(k, 'base64url').length === 32;
}
const isNodeId = (id) => typeof id === 'string' && id.length > 0 && id.length <= 256;

/** sha256 fingerprint of a raw identity key, as `sha256:<hex>`. */
function keyFingerprint(keyB64url) {
  return `sha256:${crypto.createHash('sha256').update(Buffer.from(String(keyB64url), 'base64url')).digest('hex')}`;
}

class RosterKeyRegistry {
  /**
   * @param {object} [opts]
   * @param {{nodeId: string, publicKey: string}} [opts.anchor] the configured anchor; never persisted.
   * @param {string} [opts.dir] when set, bindings persist here and reload.
   * @param {number} [opts.maxBindings]
   * @param {function} [opts.log]
   */
  constructor(opts = {}) {
    this._now = typeof opts.now === 'function' ? opts.now : Date.now;
    this._ttl = Number.isFinite(opts.bindingTtlMs) && opts.bindingTtlMs > 0 ? opts.bindingTtlMs : BINDING_TTL_MS;
    this._isLive = typeof opts.isLive === 'function' ? opts.isLive : () => false;
    this._expired = 0;               // bindings expired since this registry was built
    // nodeId -> { key, source, at, seenAt, verifiedAt, vouched, seenSaved, verifiedSaved }
    this._byNode = new Map();
    // The expirable bindings (first contact, proven, nothing verified, not vouched), least recently
    // seen first: expiry and eviction take from the head, O(1) each.
    this._lru = new Map();
    this._evicted = 0;
    this._conflicts = [];           // { nodeId, had, hadSource, got, gotSource, at }
    this._conflictCount = 0;        // every conflict, recorded or not
    this._floorReset = new Set();   // nodeIds whose sticky floor an operator reset
    this._dir = opts.dir || null;
    this._max = opts.maxBindings || MAX_BINDINGS;
    this._log = typeof opts.log === 'function' ? opts.log : () => {};
    this._anchor = opts.anchor && isNodeId(opts.anchor.nodeId) && opts.anchor.publicKey
      ? { nodeId: opts.anchor.nodeId, publicKey: opts.anchor.publicKey } : null;
    this._loading = false;
    this._migration = null;
    if (this._dir) {
      try { fs.mkdirSync(this._dir, { recursive: true }); } catch { /* best effort */ }
      this._load();
    }
  }

  // ── Reads ──────────────────────────────────────────────────────────────────────

  /** The key that verifies `nodeId`'s signatures, or undefined. Never a legacy claim. */
  get(nodeId) {
    if (this._anchor && nodeId === this._anchor.nodeId) return this._anchor.publicKey;
    const b = this._byNode.get(nodeId);
    return b && VERIFYING.has(b.source) ? b.key : undefined;
  }

  /** The key bound to `nodeId` at any source, a legacy claim included, or undefined. */
  expected(nodeId) {
    if (this._anchor && nodeId === this._anchor.nodeId) return this._anchor.publicKey;
    return this._byNode.get(nodeId)?.key;
  }

  /** The source of `nodeId`'s binding: anchor | proven | pinned | grant | legacy-claim | undefined. */
  source(nodeId) {
    if (this._anchor && nodeId === this._anchor.nodeId) return 'anchor';
    return this._byNode.get(nodeId)?.source;
  }

  /** Whether `nodeId` has a binding that verifies (not a legacy claim). */
  has(nodeId) { return this.get(nodeId) !== undefined; }

  /** Bindings held (the anchor, which is configuration, is not one). */
  size() { return this._byNode.size; }

  /** The conflicts recorded (each a refused binding of a bound nodeId to a different key). */
  conflicts() { return this._conflicts.map((c) => ({ ...c })); }

  /** How many conflicts happened since this registry was built, recorded or only counted. */
  conflictCount() { return this._conflictCount; }

  /** What the first load of a 0.13 file did, or null when the file was already 0.14's. */
  migration() { return this._migration ? { ...this._migration } : null; }

  /** Every binding, for status and tests: [{ nodeId, key, source, at, seen, verified, vouched }]. */
  entries() {
    const out = [...this._byNode].map(([nodeId, b]) => ({ nodeId, key: b.key, source: b.source, at: b.at, seen: b.seenAt ?? null, verified: b.verifiedAt ?? null, vouched: !!b.vouched }));
    if (this._anchor) out.unshift({ nodeId: this._anchor.nodeId, key: this._anchor.publicKey, source: 'anchor', at: null });
    return out;
  }

  /**
   * The sticky floor (design D7): true when `nodeId` has proven itself over Core Secure and no
   * operator has reset its floor since. Derived from the persisted registry, so it survives restarts.
   */
  floor(nodeId) {
    return this.source(nodeId) === 'proven' && !this._floorReset.has(nodeId);
  }

  // ── Writes ─────────────────────────────────────────────────────────────────────

  /**
   * Bind `nodeId` to `key` from `source`, by the conflict matrix.
   * @param {string} nodeId
   * @param {string} key - base64url Ed25519 public key
   * @param {'proven'|'pinned'|'grant'|'legacy-claim'} source
   * @returns {{ bound: boolean, source?: string, reason?: 'malformed'|'conflict'|'full', had?: string }}
   */
  bind(nodeId, key, source, { at = Date.now() } = {}) {
    if (!isNodeId(nodeId) || !isIdentityKey(key) || !SOURCES.has(source) || source === 'anchor') {
      return { bound: false, reason: 'malformed' };
    }
    if (this._anchor && nodeId === this._anchor.nodeId) {
      // The anchor's key is its configured one, whatever any other source says.
      if (key === this._anchor.publicKey) return { bound: true, source: 'anchor' };
      this._recordConflict(nodeId, this._anchor.publicKey, 'anchor', key, source, at);
      return { bound: false, reason: 'conflict', had: this._anchor.publicKey };
    }
    const b = this._byNode.get(nodeId);
    if (b) {
      if (b.key === key) {
        if (rankOf(source) > rankOf(b.source)) {
          b.source = source;
          this._track(nodeId, b);
          // A proven binding re-arms the sticky floor an operator reset earlier.
          if (source === 'proven' && this._floorReset.delete(nodeId)) this._persist({ nodeId, floorReset: false });
          this._persist({ nodeId, key, source });
        } else if ((source === 'grant' || source === 'pinned') && b.source !== source && !b.vouched) {
          // A grant (or a pin) naming the key a session proved: the binding is vouched for, and so
          // never expires. Written as the source's own line, which replays as this.
          b.vouched = true;
          this._track(nodeId, b);
          this._persist({ nodeId, key, source });
        }
        return { bound: true, source: b.source };
      }
      this._recordConflict(nodeId, b.key, b.source, key, source, at);
      return { bound: false, reason: 'conflict', had: b.key };
    }
    // Full: what has expired goes first, then the least recently seen first-contact binding that
    // verified nothing — never one that protects history. A flood of new identities therefore
    // displaces only its own kind, and an honest newcomer always gets its binding (0.13.17's cap
    // refused it: a lockout anyone could fill). Only when every binding protects history is a new
    // one refused, and its session still verifies under its proven key while it lasts.
    if (this._byNode.size >= this._max && source !== 'pinned' && !this._loading) {
      this.expire();
      if (this._byNode.size >= this._max) this._evictOne();
    }
    if (this._byNode.size >= this._max && source !== 'pinned') return { bound: false, reason: 'full' };
    const now = this._now();
    const nb = { key, source, at, seenAt: this._loading ? null : now, verifiedAt: null, vouched: false, seenSaved: this._loading ? null : now, verifiedSaved: null };
    this._byNode.set(nodeId, nb);
    if (!this._loading) this._track(nodeId, nb);
    this._persist({ nodeId, key, source, seen: now });
    return { bound: true, source, created: true };
  }

  /**
   * `nodeId` was seen: a session with it confirmed, or a frame of its arrived. Kept exactly in
   * memory, written at most once a day.
   */
  noteSeen(nodeId) {
    const b = this._byNode.get(nodeId);
    if (!b) return;
    const now = this._now();
    b.seenAt = now;
    this._track(nodeId, b);
    if (b.seenSaved == null || now - b.seenSaved >= FACT_PERSIST_MS) { b.seenSaved = now; this._persist({ nodeId, seen: now }); }
  }

  /**
   * Something verified under `nodeId`'s binding: a record, a grant or an attestation it signed, or a
   * later session re-proving its key. A binding that ever verified something never expires.
   */
  noteVerified(nodeId) {
    const b = this._byNode.get(nodeId);
    if (!b) return;
    const now = this._now();
    const first = b.verifiedAt == null;
    b.verifiedAt = now;
    b.seenAt = now;
    this._track(nodeId, b);
    if (first || now - (b.verifiedSaved ?? 0) >= FACT_PERSIST_MS) { b.verifiedSaved = now; b.seenSaved = now; this._persist({ nodeId, verified: now }); }
  }

  /** Whether `nodeId`'s binding may expire: first contact, proven, never verified, not vouched. @private */
  _expirable(b) {
    return b.source === 'proven' && b.verifiedAt == null && !b.vouched;
  }

  /** @private Keep the expiry index: an expirable binding moves to the end (just seen), any other leaves. */
  _track(nodeId, b) {
    this._lru.delete(nodeId);
    if (b && this._expirable(b)) this._lru.set(nodeId, true);
  }

  /** @private Drop a binding (expired or evicted). */
  _drop(nodeId) {
    this._byNode.delete(nodeId);
    this._lru.delete(nodeId);
    this._floorReset.delete(nodeId);
  }

  /**
   * Evict the least recently seen expirable binding (a node with a live session counts as seen now).
   * @returns {boolean} whether one went
   * @private
   */
  _evictOne() {
    for (let tries = 0; tries < 64 && this._lru.size; tries++) {
      const nodeId = this._lru.keys().next().value;
      const b = this._byNode.get(nodeId);
      if (!b || !this._expirable(b)) { this._lru.delete(nodeId); continue; }
      if (this._isLive(nodeId)) { b.seenAt = this._now(); this._track(nodeId, b); continue; }
      this._drop(nodeId);
      this._evicted++;
      this._persist({ nodeId, expired: true });
      return true;
    }
    return false;
  }

  /**
   * Expire the first-contact bindings that verified nothing and were not seen for the TTL (a node
   * with a live session is never expired). O(bindings).
   * @returns {number} how many expired
   */
  expire() {
    const now = this._now();
    const gone = [];
    // From the head of the index (least recently seen first) until a binding seen within the TTL.
    while (this._lru.size) {
      const nodeId = this._lru.keys().next().value;
      const b = this._byNode.get(nodeId);
      if (!b || !this._expirable(b)) { this._lru.delete(nodeId); continue; }
      const seen = b.seenAt ?? b.seenSaved ?? null;
      if (seen != null && now - seen <= this._ttl) break;
      if (this._isLive(nodeId)) { b.seenAt = now; this._track(nodeId, b); continue; }
      this._lru.delete(nodeId);
      gone.push(nodeId);
    }
    for (const nodeId of gone) this._drop(nodeId);
    this._expired += gone.length;
    if (gone.length && this._dir && !this._loading) {
      if (gone.length > 64) this._compact();
      else for (const nodeId of gone) this._persist({ nodeId, expired: true });
    }
    return gone.length;
  }

  /** Bindings expired since this registry was built. */
  expiredCount() { return this._expired; }

  /** First-contact bindings evicted to make room since this registry was built. */
  evictedCount() { return this._evicted; }

  /**
   * 0.13-compatible spelling of bind, for callers that pin a vouched key (`pin(id, key, 'grant')`).
   * @returns {{ pinned: boolean, reason?: string }}
   */
  pin(nodeId, key, source = 'grant') {
    const r = this.bind(nodeId, key, source === 'handshake' ? 'legacy-claim' : source);
    return r.bound ? { pinned: true } : { pinned: false, reason: r.reason };
  }

  /** Map-compatible write, at `grant` strength. */
  set(nodeId, key) { this.bind(nodeId, key, 'grant'); return this; }

  /**
   * The operator resolves a conflict for `nodeId`: `key` becomes its binding at `pinned`, whatever
   * was bound before, and the conflicts recorded for it are cleared. This is the one way a binding
   * changes key, and it is an operator's act (`sym keys resolve`), never a source's.
   * @returns {{ resolved: boolean, reason?: string }}
   */
  resolveConflict(nodeId, key) {
    if (!isNodeId(nodeId) || !isIdentityKey(key)) return { resolved: false, reason: 'malformed' };
    if (this._anchor && nodeId === this._anchor.nodeId) return { resolved: false, reason: 'anchor' };
    this._byNode.set(nodeId, { key, source: 'pinned', at: Date.now(), seenAt: this._now(), verifiedAt: null, vouched: false, seenSaved: null, verifiedSaved: null });
    this._lru.delete(nodeId);
    this._persist({ nodeId, key, source: 'pinned', operator: true });
    this._conflicts = this._conflicts.filter((c) => c.nodeId !== nodeId);
    this._rewriteConflicts();
    return { resolved: true };
  }

  /** The operator resets `nodeId`'s sticky floor: its Legacy Import route may be used again. */
  resetFloor(nodeId) {
    if (!isNodeId(nodeId)) return false;
    this._floorReset.add(nodeId);
    this._persist({ nodeId, floorReset: true });
    return true;
  }

  // ── Internals ──────────────────────────────────────────────────────────────────

  _recordConflict(nodeId, had, hadSource, got, gotSource, at) {
    this._conflictCount++;
    if (this._loading) return; // a conflict in the file was recorded when it happened
    if (this._conflicts.some((c) => c.nodeId === nodeId && c.got === got)) return;
    if (this._conflicts.length >= MAX_CONFLICTS) return;
    if (this._conflicts.filter((c) => c.nodeId === nodeId).length >= MAX_CONFLICTS_PER_NODE) return;
    const c = { nodeId, had, hadSource, got, gotSource, at };
    this._conflicts.push(c);
    this._log(`Key conflict: ${String(nodeId).slice(0, 8)} is bound to ${keyFingerprint(had).slice(0, 19)} (${hadSource}); refused ${keyFingerprint(got).slice(0, 19)} (${gotSource}). Resolve with: sym keys resolve ${nodeId} <key>`);
    if (!this._dir) return;
    try { fs.appendFileSync(path.join(this._dir, CONFLICTS_FILE), JSON.stringify(c) + '\n'); } catch { /* best effort */ }
  }

  _rewriteConflicts() {
    if (!this._dir) return;
    const file = path.join(this._dir, CONFLICTS_FILE);
    try {
      const tmp = `${file}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, this._conflicts.map((c) => JSON.stringify(c) + '\n').join(''));
      fs.renameSync(tmp, file);
    } catch { /* best effort */ }
  }

  _persist(rec) {
    if (!this._dir || this._loading) return;
    try { fs.appendFileSync(path.join(this._dir, KEYS_FILE), JSON.stringify(rec) + '\n'); }
    catch { /* best effort — never let persistence break verification */ }
  }

  _load() {
    const file = path.join(this._dir, KEYS_FILE);
    let text = null;
    try { text = fs.readFileSync(file, 'utf8'); } catch { text = null; }
    this._loadConflicts();
    if (text === null) { this._writeFresh(); return; }
    let marked = false;
    const records = [];
    for (const line of text.split('\n')) {
      if (!line.trim()) continue;
      let r;
      try { r = JSON.parse(line); } catch { continue; }
      if (r && typeof r === 'object' && r.v === 2 && r.format === FORMAT_MARKER.format) { marked = true; continue; }
      records.push(r);
    }
    this._loading = true;
    let unstamped = 0;
    let expired = 0;
    try {
      if (!marked) this._migrate013(records);
      else for (const r of records) this._replay(r);
      // A proven binding written before its `seen` was kept starts its clock now (written below).
      const now = this._now();
      for (const b of this._byNode.values()) if (this._expirable(b) && b.seenAt == null) { b.seenAt = now; b.seenSaved = now; unstamped++; }
      // The expiry index, least recently seen first.
      this._lru.clear();
      for (const [id] of [...this._byNode].filter(([, b]) => this._expirable(b)).sort((x, y) => x[1].seenAt - y[1].seenAt)) this._lru.set(id, true);
      expired = this.expire();
    } finally { this._loading = false; }
    // Rewritten once, atomically: a 0.13 file (migration), or one whose lines outgrew its bindings.
    if (!marked || unstamped > 0 || expired > 0 || records.length > 2 * this._byNode.size + 256) this._compact();
  }

  /** Replay one 0.14 line. A 0.13 rollback may have appended lines in its own vocabulary. */
  _replay(r) {
    if (!r || typeof r !== 'object' || !isNodeId(r.nodeId)) return;
    if (r.floorReset === true) { this._floorReset.add(r.nodeId); return; }
    if (r.floorReset === false) { this._floorReset.delete(r.nodeId); return; }
    if (r.expired === true) { this._drop(r.nodeId); return; }
    if (r.key === undefined && (Number.isFinite(r.seen) || Number.isFinite(r.verified))) {
      const b = this._byNode.get(r.nodeId);
      if (!b) return;
      this._applyFacts(b, r);
      return;
    }
    let source = r.source;
    if (source === 'anchor') return;                       // configuration, never replayed
    if (source === 'handshake') source = 'legacy-claim';   // a 0.13 rollback's unproven hello
    if (!SOURCES.has(source) || !isIdentityKey(r.key)) return;
    if (r.operator === true) { this._byNode.set(r.nodeId, { key: r.key, source: 'pinned', at: null, seenAt: null, verifiedAt: null, vouched: false, seenSaved: null, verifiedSaved: null }); return; }
    this.bind(r.nodeId, r.key, source, { at: null });
    const b = this._byNode.get(r.nodeId);
    if (b && b.key === r.key) {
      this._applyFacts(b, r);
      if (r.vouched === true) b.vouched = true;
    }
  }

  /** @private A persisted `seen` / `verified` fact (a line of its own, or on a binding's line). */
  _applyFacts(b, r) {
    const now = this._now();
    if (Number.isFinite(r.seen)) { const t = Math.min(r.seen, now); if (b.seenAt == null || t > b.seenAt) { b.seenAt = t; b.seenSaved = t; } }
    if (Number.isFinite(r.verified)) {
      const t = Math.min(r.verified, now);
      if (b.verifiedAt == null || t > b.verifiedAt) { b.verifiedAt = t; b.verifiedSaved = t; }
      if (b.seenAt == null || t > b.seenAt) { b.seenAt = t; b.seenSaved = t; }
    }
  }

  /**
   * A 0.13 file: replayed by the 0.13 rules (first binding holds, a strictly stronger source of
   * handshake > grant overrode it), so the binding 0.13 used is the one kept; then relabelled.
   */
  _migrate013(records) {
    const rank013 = { grant: 0, handshake: 1, anchor: 2 };
    const final = new Map();
    let read = 0;
    for (const r of records) {
      if (!r || typeof r !== 'object' || !isNodeId(r.nodeId) || typeof r.key !== 'string') continue;
      read++;
      const prev = final.get(r.nodeId);
      const s = rank013[r.source] ?? 0;
      if (!prev || (prev.key !== r.key && s > (rank013[prev.source] ?? 0))) final.set(r.nodeId, { key: r.key, source: r.source });
      else if (prev.key === r.key && s > (rank013[prev.source] ?? 0)) prev.source = r.source;
    }
    const counts = { read, bindings: 0, legacyClaim: 0, grant: 0, droppedAnchor: 0, droppedMalformed: 0 };
    for (const [nodeId, b] of final) {
      if (b.source === 'anchor') { counts.droppedAnchor++; continue; }
      if (!isIdentityKey(b.key)) { counts.droppedMalformed++; continue; }
      const source = b.source === 'grant' ? 'grant' : 'legacy-claim';
      this._byNode.set(nodeId, { key: b.key, source, at: null, seenAt: null, verifiedAt: null, vouched: false, seenSaved: null, verifiedSaved: null });
      counts.bindings++;
      counts[source === 'grant' ? 'grant' : 'legacyClaim']++;
    }
    this._migration = counts;
  }

  /** Rewrite the file as marker + one line per binding (and floor reset), atomically. */
  _compact() {
    const file = path.join(this._dir, KEYS_FILE);
    const lines = [JSON.stringify(FORMAT_MARKER)];
    for (const [nodeId, b] of this._byNode) {
      const line = { nodeId, key: b.key, source: b.source };
      if (b.seenAt != null) line.seen = b.seenAt;
      if (b.verifiedAt != null) line.verified = b.verifiedAt;
      if (b.vouched) line.vouched = true;
      lines.push(JSON.stringify(line));
    }
    for (const nodeId of this._floorReset) lines.push(JSON.stringify({ nodeId, floorReset: true }));
    try {
      const tmp = `${file}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, lines.join('\n') + '\n');
      fs.renameSync(tmp, file);
    } catch (err) {
      this._log(`Key registry: could not rewrite ${file} (${err.code || err.message}); it is migrated again at the next start`);
    }
  }

  _writeFresh() {
    try { fs.writeFileSync(path.join(this._dir, KEYS_FILE), JSON.stringify(FORMAT_MARKER) + '\n', { flag: 'wx' }); }
    catch { /* another writer made it, or the dir is not writable */ }
  }

  _loadConflicts() {
    let text;
    try { text = fs.readFileSync(path.join(this._dir, CONFLICTS_FILE), 'utf8'); } catch { return; }
    for (const line of text.split('\n')) {
      if (!line.trim()) continue;
      let c;
      try { c = JSON.parse(line); } catch { continue; }
      if (!c || !isNodeId(c.nodeId) || typeof c.got !== 'string') continue;
      if (this._conflicts.some((x) => x.nodeId === c.nodeId && x.got === c.got)) continue;
      if (this._conflicts.length >= MAX_CONFLICTS) break;
      this._conflicts.push(c);
    }
  }
}

module.exports = { RosterKeyRegistry, SOURCE_RANK, isIdentityKey, keyFingerprint, KEYS_FILE, CONFLICTS_FILE, FORMAT_MARKER, BINDING_TTL_MS, MAX_CONFLICTS, MAX_CONFLICTS_PER_NODE };
