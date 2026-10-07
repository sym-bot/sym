'use strict';

/**
 * @module @sym-bot/sym/role-grant-store
 * @description Earned-authority role-grant chain (MMP §6.5, §6.6).
 *
 * A node's lifecycle authority (participant → validator → anchor) is EARNED via signed grants,
 * never self-asserted. Authority flows only along chains that terminate at the non-earnable anchor
 * (typically the founder): a grant whose chain does not root there confers NOTHING (Douceur: there
 * is no unconditional decentralized Sybil-resistance — authority must bottom out at a pinned root).
 *
 * AUTHORITY FOLLOWS THE KEY (sym 0.14, design D3):
 *
 *   - Every role-grant carries `granteeKey`, inside the signed payload. A grant without one is
 *     malformed: a grant to a bare nodeId would confer authority on whoever later holds that id.
 *   - `resolveRole(nodeId, key, at)` confers a grant's role only when its `granteeKey` equals `key`,
 *     the key the subject is bound to (the key its session proved, or its registry binding). A node
 *     whose id is claimed by an impostor's key resolves, for that key, to participant.
 *   - Chains are verified TOP-DOWN with the key each kept grant vouches (§6.6: "using each verified
 *     grant's vouched key to reach the next"), never with whatever key the registry holds.
 *
 * WHAT IS KEPT IS A FUNCTION OF THE RECORDS HELD (final re-review, Findings 1 and 2; the founder's
 * ruling A; docs/WIRE-0.14.0.md §6.2). Nothing about a record's meaning is decided at ingest, so the
 * order records arrive in changes nothing:
 *
 *   - A record is kept when it is VERIFIABLE: its signature verifies under the anchor's configured
 *     key, or under a key a kept role-grant vouches for its grantor. Whether its grantor had
 *     authority is decided at resolution, never here.
 *   - The anchor signs at depth 0; a grant kept at depth d makes its (grantee, granteeKey) a signer
 *     at depth d + 1, in the SUBTREE of the anchor grantee at the top of that chain (the shallowest
 *     chain, then the subtree root with the smallest nodeId).
 *   - The anchor's own records are unbounded. Every other record counts against its signer's
 *     subtree: everything an anchor grantee and its descendants sign shares one budget
 *     (SUBTREE_BUDGET). A subtree, however compromised, fills only its own budget, so a revoke
 *     signed in another subtree is never refused by it.
 *   - Inside a budget the kept records are the first in one total order on signed fields: signer
 *     depth, revokes before grants, a revoke's cutoff or a grant's grantedAt, the signature. A record
 *     that ranks above the last one kept replaces it; one below is refused (`outranked`).
 *
 * WHAT COUNTS IS DECIDED AT RESOLUTION (docs/WIRE-0.14.0.md §6.3; the founder's rulings):
 *
 *   - A revoke carries a CUTOFF (re-review N2): its subject's statements signed at or after it never
 *     count. A revoke without one (0.13) has its own signed time as its cutoff.
 *   - A revoke may RATIFY its subject's earlier statements (ruling B): any statement a signer made
 *     before its cutoff counts only while the signer still holds the rank it needs, or if an
 *     effective revoke of the signer lists it. So a revoked key gains nothing by backdating.
 *   - A revoke counts only when its revoker held the rank at every breakpoint from its cutoff to its
 *     signed time (final re-review, Low 8a).
 *   - Grants keep §6.6's cascade (a grant confers at t only while its grantor holds the rank at t)
 *     unless ratified. Every time is a signed time, or now; no receipt time is kept.
 *
 * The file is append-only and never rewritten (re-review N5): lines are the bare record, as 0.13
 * wrote them, and the store is rebuilt from them at load by the same rule.
 *
 * A KEY VOUCH is a view (security review C): `vouchedKey(nodeId)` is the one key the grants in effect
 * NOW vouch for nodeId, and the key registry reads it on demand instead of storing a `grant` binding,
 * so a vouch ends when its grant stops being in effect. A grant never vouches this node's own nodeId
 * (`opts.selfId`). A grant naming a key the registry binds otherwise is recorded there as a conflict.
 *
 * @copyright 2026 SYM.BOT. Apache 2.0 License.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { verifyGrant, roleRank } = require('./core');
const { sigKey } = require('./attestation-store');
const { isCanonicalNodeId } = require('./core/record-canonical');

const GRANTS_FILE = 'role-grants.jsonl';
/**
 * The records one delegation subtree may hold: everything an anchor grantee and its descendants sign
 * (final re-review: it replaces the per-grantor, per-pair and store caps, each of which could evict a
 * voucher whose dependents then freed room, which made the kept set depend on arrival order).
 */
const SUBTREE_BUDGET = 4096;
/** A record dated further than this into the future (by this node's clock) is refused. */
const MAX_FUTURE_MS = 10 * 60 * 1000;
/** Field bounds (security review D): a nodeId, a role name. A key and a signature have fixed lengths. */
const MAX_ID = 128;
const MAX_ROLE = 32;
/** A revoke ratifies at most this many statements (a revoker that must ratify more signs several). */
const MAX_RATIFY = 64;
/** resolveRole's memo is cleared when it holds this many answers (and whenever a record is kept). */
const MEMO_MAX = 65536;
/**
 * Delegation depth (security review D, role-linear): a role reaches at most this many grants from the
 * anchor (the anchor's own grantee is at depth 1). MMP §6.6 sets no depth; 8 is sym's, proposed for
 * the spec, and the role-chain answer already stops there.
 */
const MAX_DELEGATION_DEPTH = 8;
const CANONICAL_SIG = /^[A-Za-z0-9_-]{85}[AQgw]$/;

/** A revoke's cutoff: the signed `cutoff`, or its signed time when it carries none (re-review N2). */
function cutoffOf(g) {
  return g.type === 'role-revoke' && Number.isSafeInteger(g.cutoff) ? g.cutoff : (g.grantedAt ?? 0);
}

/** Whether signer info `a` is better (shallower, then the smaller subtree root) than `b`. */
const better = (a, b) => a.depth < b.depth || (a.depth === b.depth && String(a.root) < String(b.root));

class RoleGrantStore {
  /**
   * @param {object} [opts]
   * @param {{nodeId: string, publicKey: string}} [opts.anchor] the non-earnable root of trust.
   * @param {{get: function(string): (string|undefined), bind?: function, pin?: function}} [opts.keys]
   *   the node's key registry. Read only to resolve a subject's bound key for `resolver()` and the
   *   two-argument `resolveRole`; NEVER to verify a grant.
   * @param {string} [opts.dir] when set, grants persist append-only and reload here.
   * @param {number} [opts.subtreeBudget] records one delegation subtree may hold (SUBTREE_BUDGET).
   */
  constructor(opts = {}) {
    this._anchor = opts.anchor || null;
    this._selfId = typeof opts.selfId === 'string' && opts.selfId ? opts.selfId : null;
    this._selfKey = typeof opts.selfKey === 'string' && opts.selfKey ? opts.selfKey : null;
    // Told of a kept grant in effect that names this node with a key that is not its own (inert, and
    // reported, since someone vouched a foreign key for this node's identity).
    this._onForeignSelfGrant = typeof opts.onForeignSelfGrant === 'function' ? opts.onForeignSelfGrant : null;
    this._now = typeof opts.now === 'function' ? opts.now : Date.now;
    this._keys = opts.keys || new Map();
    this._budget = Number.isSafeInteger(opts.subtreeBudget) && opts.subtreeBudget > 0 ? opts.subtreeBudget : SUBTREE_BUDGET;
    this._pool = new Map();      // sigKey -> { g, signer, sk } : the records kept
    this._reset();
    this._dir = opts.dir || null;
    this._loading = false;
    this._loadReport = { loaded: 0, skipped: {}, unreadable: null };
    if (this._dir) {
      try { fs.mkdirSync(this._dir, { recursive: true }); } catch { /* best effort */ }
      this._load();
    }
  }

  /** @private Clear every structure derived from the pool. */
  _reset() {
    this._byGrantee = new Map();   // grantee nodeId -> [entries]
    this._info = new Map();        // `${nodeId}\0${key}` -> { depth, root } : a signer
    this._signerKeys = new Map();  // nodeId -> Set(keys it signs under)
    this._byRoot = new Map();      // subtree root -> Set(entries)
    this._ratifiers = new Map();   // statement sigKey -> [revoke entries listing it]
    this._times = [];              // record times and cutoffs, sorted, distinct: resolution's breakpoints
    this._worst = new Map();       // subtree root -> its last-ranked entry (a cache)
    this._memo = new Map();
    this._memoNow = undefined;
    this._syncOrder = null;
    this._digest = null;
  }

  /**
   * What the last reload found: records `loaded`, records `skipped` by reason (each stays in the file
   * for the next load), and `unreadable` (why the file could not be read; null when it could).
   * @returns {{ loaded: number, skipped: Object<string, number>, unreadable: string|null }}
   */
  loadReport() {
    return { loaded: this._loadReport.loaded, skipped: { ...this._loadReport.skipped }, unreadable: this._loadReport.unreadable };
  }

  /**
   * The keys a record from `grantedBy` may be verified against: the anchor's configured key, or the
   * keys kept grants vouch for `grantedBy`. Empty when no kept grant reaches it.
   * @returns {string[]}
   */
  grantorKeys(grantedBy) {
    if (this._anchor && grantedBy === this._anchor.nodeId) return [this._anchor.publicKey];
    return [...(this._signerKeys.get(grantedBy) || [])];
  }

  /** Whether any kept grant reaches `grantedBy` (a record from it could verify). */
  grantorKey(grantedBy) { return this.grantorKeys(grantedBy)[0]; }

  /** @private The signer info of (nodeId, key), the anchor's included. */
  _signerInfo(nodeId, key) {
    if (this._anchor && nodeId === this._anchor.nodeId && key === this._anchor.publicKey) return { depth: 0, root: null };
    return this._info.get(`${nodeId}\u0000${key}`);
  }

  /** @private The info a kept grant gives its grantee, or null when it gives none. */
  _grantInfo(e, info) {
    const g = e.g;
    if (g.type !== 'role-grant') return null;
    // No grant makes the anchor, or this node under a key not its own, a signer.
    if (this._anchor && g.grantee === this._anchor.nodeId) return null;
    if (this._selfId && g.grantee === this._selfId && g.granteeKey !== this._selfKey) return null;
    return { depth: info.depth + 1, root: info.root === null ? g.grantee : info.root };
  }

  /**
   * The total order a budget keeps by (final re-review ruling A): signer depth, revokes before grants,
   * a revoke's cutoff or a grant's signed time, then the signature. Negative when `a` ranks first.
   * @private
   */
  _cmp(a, ai, b, bi) {
    if (ai.depth !== bi.depth) return ai.depth - bi.depth;
    const ta = a.g.type === 'role-revoke' ? 0 : 1;
    const tb = b.g.type === 'role-revoke' ? 0 : 1;
    if (ta !== tb) return ta - tb;
    const xa = ta === 0 ? cutoffOf(a.g) : a.g.grantedAt;
    const xb = tb === 0 ? cutoffOf(b.g) : b.g.grantedAt;
    if (xa !== xb) return xa - xb;
    return a.sk < b.sk ? -1 : a.sk > b.sk ? 1 : 0;
  }

  /** @private The last-ranked entry of a subtree (cached). */
  _worstIn(root) {
    const hit = this._worst.get(root);
    if (hit) return hit;
    let w = null;
    for (const e of this._byRoot.get(root) || []) {
      const ei = this._signerInfo(e.g.grantedBy, e.signer);
      if (!w || this._cmp(e, ei, w.e, w.info) > 0) w = { e, info: ei };
    }
    if (w) this._worst.set(root, w);
    return w;
  }

  /**
   * Record a signed role-grant / role-revoke. In order: well-formed (a role-grant carries
   * granteeKey), new (dedup by the signature's bytes), not dated in the future, verifiable (its
   * signature verifies under the anchor's key or a key a kept grant vouches for its grantor), and
   * selected within its subtree's budget. A record that fails any of these is refused with the reason
   * and leaves no trace: not held, not written, not relayed.
   *
   * What is stored, persisted and returned (`grant`, for the caller to relay) is ONE canonical object
   * holding only the fields the signature covers, the signature in its signer's spelling and `sigAlg`
   * (0.13.17 re-review A5). Never throws: a record whose checks fail in a way no reason names is
   * 'unverifiable'.
   * @returns {{ stored: boolean, reason?: string, grant?: object }}
   */
  record(grant) {
    try {
      return this._record(grant);
    } catch {
      return { stored: false, reason: 'unverifiable' };
    }
  }

  /** @private */
  _record(grant) {
    if (malformed(grant)) return { stored: false, reason: 'malformed' };
    const sk = sigKey(grant.sig);
    if (this._pool.has(sk)) return { stored: false, reason: 'duplicate' };
    if (grant.grantedAt > this._now() + MAX_FUTURE_MS) return { stored: false, reason: 'future-dated' };
    const candidates = this.grantorKeys(grant.grantedBy);
    if (candidates.length === 0) return { stored: false, reason: 'unknown-grantor-key' };
    const signer = candidates.find((k) => verifyGrant(grant, k).valid);
    if (!signer) return { stored: false, reason: 'bad-signature' };
    const e = { g: canonicalGrant(grant, sk), signer, sk };
    const info = this._signerInfo(e.g.grantedBy, signer);
    let rebuild = false;
    if (info.root !== null && (this._byRoot.get(info.root)?.size || 0) >= this._budget) {
      const w = this._worstIn(info.root);
      if (w && this._cmp(e, info, w.e, w.info) > 0) return { stored: false, reason: 'outranked' };
      rebuild = true;
    }
    const gi = this._grantInfo(e, info);
    if (gi) {
      const cur = this._info.get(`${e.g.grantee}\u0000${e.g.granteeKey}`);
      if (cur && better(gi, cur)) rebuild = true;
    }
    if (rebuild) {
      this._rebuild([...this._pool.values(), e]);
      if (!this._pool.has(sk)) return { stored: false, reason: 'outranked' };
    } else {
      this._add(e, info);
    }
    this._append(e.g);
    this._noteVouch(e.g);
    const g = e.g;
    if (g.type === 'role-grant' && this._selfId && g.grantee === this._selfId && this._selfKey && g.granteeKey !== this._selfKey) {
      // Kept (it is a verifiable statement, and relayed like one) but inert: this node resolves its own
      // role under its own key, and no grant binds its own nodeId or makes it a signer.
      if (this._onForeignSelfGrant && !this._loading && roleRank(this.resolveRole(g.grantee, g.granteeKey, this._now())) >= 1) {
        try { this._onForeignSelfGrant(g); } catch { /* a report must not fail the store */ }
      }
      return { stored: true, grant: g, inert: 'foreign-key-for-self' };
    }
    return { stored: true, grant: g };
  }

  /** @private Add one entry to the pool and to every derived structure. */
  _add(e, info) {
    this._pool.set(e.sk, e);
    const g = e.g;
    let arr = this._byGrantee.get(g.grantee);
    if (!arr) { arr = []; this._byGrantee.set(g.grantee, arr); }
    arr.push(e);
    if (info.root !== null) {
      let set = this._byRoot.get(info.root);
      if (!set) { set = new Set(); this._byRoot.set(info.root, set); }
      set.add(e);
      const w = this._worst.get(info.root);
      if (w && this._cmp(e, info, w.e, w.info) > 0) this._worst.set(info.root, { e, info });
    }
    const gi = this._grantInfo(e, info);
    if (gi) {
      const k = `${g.grantee}\u0000${g.granteeKey}`;
      const cur = this._info.get(k);
      if (!cur || better(gi, cur)) this._info.set(k, gi);
      let ks = this._signerKeys.get(g.grantee);
      if (!ks) { ks = new Set(); this._signerKeys.set(g.grantee, ks); }
      ks.add(g.granteeKey);
    }
    if (g.type === 'role-revoke' && Array.isArray(g.ratify)) {
      for (const s of g.ratify) {
        let l = this._ratifiers.get(s);
        if (!l) { l = []; this._ratifiers.set(s, l); }
        l.push(e);
      }
    }
    this._addTime(g.grantedAt);
    if (g.type === 'role-revoke') this._addTime(cutoffOf(g));
    this._memo.clear();
    this._syncOrder = null;
    this._digest = null;
  }

  /**
   * @private Recompute the kept set from `entries` by the rule alone (docs/WIRE-0.14.0.md §6.2):
   * the anchor's records, then depth by depth, each depth's records in the budget's total order,
   * each kept while its subtree has room; a record whose signer no kept grant reaches is dropped.
   */
  _rebuild(entries) {
    this._pool = new Map();
    this._reset();
    const anchor = this._anchor;
    const rest = [];
    const level0 = [];
    for (const e of entries) {
      if (anchor && e.g.grantedBy === anchor.nodeId && e.signer === anchor.publicKey) level0.push(e);
      else rest.push(e);
    }
    for (const e of level0) this._add(e, { depth: 0, root: null });
    let left = rest;
    for (let depth = 1; left.length; depth++) {
      const now = [];
      const later = [];
      for (const e of left) {
        const info = this._info.get(`${e.g.grantedBy}\u0000${e.signer}`);
        if (!info) later.push(e); // perhaps reached by a deeper grant
        else if (info.depth === depth) now.push({ e, info });
        else later.push(e);
      }
      if (now.length === 0 && ![...this._info.values()].some((i) => i.depth > depth)) break;
      now.sort((a, b) => this._cmp(a.e, a.info, b.e, b.info));
      for (const { e, info } of now) {
        if ((this._byRoot.get(info.root)?.size || 0) >= this._budget) continue;
        this._add(e, info);
      }
      left = later;
    }
  }

  /** @private Keep `t` in the sorted list of breakpoints. */
  _addTime(t) {
    const a = this._times;
    let lo = 0, hi = a.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (a[mid] < t) lo = mid + 1; else hi = mid; }
    if (a[lo] !== t) a.splice(lo, 0, t);
  }

  /**
   * @private The breakpoint a time resolves as: the latest record time at or before it (-Infinity
   * when none). A role changes only where some record's time or cutoff is crossed, so every time
   * between two breakpoints resolves alike, and the memo holds at most one answer per (node, key,
   * breakpoint).
   */
  _canonicalTime(t) {
    const a = this._times;
    let lo = 0, hi = a.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (a[mid] <= t) lo = mid + 1; else hi = mid; }
    return lo === 0 ? -Infinity : a[lo - 1];
  }

  /**
   * A grant names the grantee's key. The registry reads key vouches as a view (`vouchedKey`), so
   * nothing is pinned; the registry is told of a grant in effect now, so that a different key it
   * already binds is recorded as a conflict and the same key is marked vouched. Never for this node's
   * own id. A plain Map (tests, older hosts) is only filled where it holds nothing.
   * @private
   */
  _noteVouch(grant) {
    if (grant.type !== 'role-grant' || (this._selfId && grant.grantee === this._selfId)) return;
    if (roleRank(this.resolveRole(grant.grantee, grant.granteeKey, this._now())) < 1) return;
    if (typeof this._keys.bind === 'function') this._keys.bind(grant.grantee, grant.granteeKey, 'grant');
    else if (typeof this._keys.set === 'function' && typeof this._keys.setGrantView !== 'function' && !this._keys.get(grant.grantee)) this._keys.set(grant.grantee, grant.granteeKey);
  }

  /**
   * The key the grants in effect NOW vouch for `nodeId`: the granteeKey of a grant under which
   * `nodeId` resolves now to a rank above participant. Undefined when none does, when two keys do
   * (ambiguous: neither verifies), or for this node's own id. The key registry's `grant` view.
   * @returns {string|undefined}
   */
  vouchedKey(nodeId, at = this._now()) {
    if (this._selfId && nodeId === this._selfId) return undefined;
    if (this._anchor && nodeId === this._anchor.nodeId) return undefined;
    const keys = this._signerKeys.get(nodeId);
    if (!keys) return undefined;
    let found;
    for (const k of keys) {
      if (roleRank(this.resolveRole(nodeId, k, at)) < 1) continue;
      if (found !== undefined && found !== k) return undefined;
      found = k;
    }
    return found;
  }

  /**
   * Resolve the role `nodeId`, holding `key`, held at time `at` (ms epoch), by the rule of
   * docs/WIRE-0.14.0.md §6.3:
   *   - the anchor itself, holding its configured key, is `anchor`;
   *   - otherwise replay, in signed-time order, `nodeId`'s grants signed at or before `at` (under
   *     `key`) and its revokes whose cutoff is at or before `at`;
   *   - every statement counts only if its signer held the rank it needs when it signed, and either
   *     still holds it now or an effective revoke of the signer ratifies it;
   *   - a grant also needs its grantor's rank at `at` (§6.6's cascade), unless ratified;
   *   - a revoke needs its revoker's rank at every breakpoint from its cutoff to its signed time;
   *   - cycles and chains that do not reach the anchor resolve to `participant` (rank 0).
   *
   * Two-argument form `resolveRole(nodeId, at)`: `key` is the registry's binding for `nodeId`.
   *
   * @param {string} nodeId
   * @param {string|undefined} key
   * @param {number} at - ms epoch
   * @returns {'participant'|'validator'|'anchor'}
   */
  resolveRole(nodeId, key, at) {
    if (typeof key === 'number' && at === undefined) { at = key; key = this._boundKey(nodeId); }
    if (at === undefined) at = this._now();
    this._freshMemo();
    return this._resolve(nodeId, key, at, new Set()).role;
  }

  /**
   * The role a signer's statement (an attestation) counts with: its role at the statement's signed
   * time, if it still holds that role now or an effective revoke of it ratifies the statement (by its
   * signature); otherwise its role now (docs/WIRE-0.14.0.md §6.3, attestations).
   * @param {string} nodeId
   * @param {string|undefined} key
   * @param {number} at - the statement's signed time
   * @param {string} [sig] - the statement's signature
   * @returns {'participant'|'validator'|'anchor'}
   */
  statementRole(nodeId, key, at, sig) {
    this._freshMemo();
    const seen = new Set();
    const then = this._resolve(nodeId, key, at, seen).role;
    const now = this._resolve(nodeId, key, this._now(), seen).role;
    if (roleRank(now) >= roleRank(then)) return then;
    const rank = (id, k, t) => { const r = this._resolve(id, k, t, seen); return r.depth >= MAX_DELEGATION_DEPTH ? 0 : roleRank(r.role); };
    if (typeof sig === 'string' && this._ratified(sigKey(sig), nodeId, at, roleRank(then), rank)) return then;
    return now;
  }

  /**
   * Whether an effective revoke of `nodeId` ratifies the statement with signature `sig`, signed at
   * `at`, needing rank `need` (docs/WIRE-0.14.0.md §6.3).
   */
  ratifies(nodeId, at, sig, need = 1) {
    if (typeof sig !== 'string') return false;
    this._freshMemo();
    const seen = new Set();
    const rank = (id, k, t) => { const r = this._resolve(id, k, t, seen); return r.depth >= MAX_DELEGATION_DEPTH ? 0 : roleRank(r.role); };
    return this._ratified(sigKey(sig), nodeId, at, need, rank);
  }

  /** @private Clear the memo when "now" has crossed a breakpoint (standing is judged now). */
  _freshMemo() {
    if (this._memo.size >= MEMO_MAX) this._memo.clear();
    const n = this._canonicalTime(this._now());
    if (n !== this._memoNow) { this._memo.clear(); this._memoNow = n; }
  }

  /**
   * @private The rank `nodeId` holding `key` can confer at `at`: its role's rank, or 0 when its role
   * already sits at the delegation depth (it can grant nothing further).
   */
  _authority(nodeId, key, at) {
    this._freshMemo();
    const r = this._resolve(nodeId, key, at, new Set());
    return r.depth >= MAX_DELEGATION_DEPTH ? 0 : roleRank(r.role);
  }

  /**
   * @private The lowest rank `rank(id, key, t)` takes for t from `from` to `to`, checked at `from` and
   * at every breakpoint after it up to `to` (a rank changes only at a breakpoint).
   */
  _minRank(rank, id, key, from, to) {
    let r = rank(id, key, from);
    const a = this._times;
    let lo = 0, hi = a.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (a[mid] <= from) lo = mid + 1; else hi = mid; }
    for (let i = lo; i < a.length && a[i] <= to && r > 0; i++) r = Math.min(r, rank(id, key, a[i]));
    return r;
  }

  /**
   * @private Whether an effective revoke of `signer` ratifies the statement with sigKey `sk`, signed
   * at `signedAt` (before that revoke's cutoff), by a revoker holding at least `need` (and validator)
   * throughout the revoke's span.
   */
  _ratified(sk, signer, signedAt, need, rank) {
    for (const r of this._ratifiers.get(sk) || []) {
      const g = r.g;
      if (g.grantee !== signer || !(signedAt < cutoffOf(g))) continue;
      if (this._revokeAuthority(r, rank) >= Math.max(1, need)) return true;
    }
    return false;
  }

  /**
   * @private A revoke's authority: its revoker's lowest rank from its cutoff to its signed time, or 0
   * when the revoker no longer holds rank now and no effective revoke of it ratifies this revoke.
   */
  _revokeAuthority(r, rank) {
    const g = r.g;
    const a = this._minRank(rank, g.grantedBy, r.signer, cutoffOf(g), g.grantedAt);
    if (a < 1) return 0;
    if (rank(g.grantedBy, r.signer, this._now()) >= 1) return a;
    return this._ratified(r.sk, g.grantedBy, g.grantedAt, 1, rank) ? a : 0;
  }

  /**
   * The resolution, memoised (security review D, role-resolve-cost). An answer is kept only when no
   * cycle was cut while computing it (a cut answer depends on the path), and the memo is cleared
   * whenever a record is kept or "now" crosses a breakpoint. @returns {{ role, depth, pure }}
   * @private
   */
  _resolve(nodeId, key, at, seen) {
    if (this._anchor && nodeId === this._anchor.nodeId) return { role: key === this._anchor.publicKey ? 'anchor' : 'participant', depth: 0, pure: true };
    if (typeof key !== 'string' || !key) return { role: 'participant', depth: 0, pure: true };
    const self = `${nodeId}\u0000${key}`;
    at = this._canonicalTime(at);
    const memoKey = `${self}\u0000${at}`;
    const hit = this._memo.get(memoKey);
    if (hit !== undefined) return { role: hit.role, depth: hit.depth, pure: true };
    if (seen.has(memoKey)) return { role: 'participant', depth: 0, pure: false }; // cycle: not anchor-rooted
    seen.add(memoKey);
    let pure = true;
    let depthOf = 0; // the deepest grantor consulted for the record being replayed
    // A grantor's rank at a time, or 0 when its own role sits at the delegation depth already.
    const rank = (id, k, t) => {
      const r = this._resolve(id, k, t, seen);
      if (!r.pure) pure = false;
      if (r.depth >= MAX_DELEGATION_DEPTH) return 0;
      if (r.depth > depthOf) depthOf = r.depth;
      return roleRank(r.role);
    };
    // A revoke is in the replay from its cutoff on, at its signed place (re-review N2). Ties in signed
    // time order grants before revokes, then by signature, so the replay never depends on the order
    // records were kept in.
    const records = (this._byGrantee.get(nodeId) || [])
      .filter((e) => (e.g.type === 'role-revoke' ? cutoffOf(e.g) : (e.g.grantedAt ?? 0)) <= at)
      .sort((a, b) => (a.g.grantedAt - b.g.grantedAt)
        || ((a.g.type === 'role-revoke' ? 1 : 0) - (b.g.type === 'role-revoke' ? 1 : 0))
        || (a.sk < b.sk ? -1 : a.sk > b.sk ? 1 : 0));
    let role = 'participant';
    let depth = 0;
    const now = this._now();
    for (const e of records) {
      const g = e.g;
      if (g.type === 'role-grant' && g.granteeKey !== key) continue;
      depthOf = 0;
      if (g.type === 'role-revoke') {
        const need = Math.max(1, roleRank(role));
        if (this._revokeAuthority(e, rank) >= need) { role = 'participant'; depth = 0; }
      } else {
        const need = roleRank(g.role);
        const then = rank(g.grantedBy, e.signer, g.grantedAt);
        let ok;
        if (then < need) ok = false;
        else if (rank(g.grantedBy, e.signer, now) >= need) ok = rank(g.grantedBy, e.signer, at) >= need; // standing, then the cascade
        else ok = this._ratified(e.sk, g.grantedBy, g.grantedAt, need, rank); // a ratified grant keeps conferring
        if (ok) { role = g.role; depth = depthOf + 1; }
      }
    }
    seen.delete(memoKey);
    if (role === 'participant') depth = 0;
    if (pure) this._memo.set(memoKey, { role, depth });
    return { role, depth, pure };
  }

  /** @private The key the registry binds `nodeId` to (the anchor's configured key for the anchor). */
  _boundKey(nodeId) {
    if (this._anchor && nodeId === this._anchor.nodeId) return this._anchor.publicKey;
    try { return this._keys.get(nodeId); } catch { return undefined; }
  }

  /** A resolver bound to this store, for `verifyAttestationRole(att, resolver)`: the subject's bound key. */
  resolver() {
    return (nodeId, at) => this.resolveRole(nodeId, this._boundKey(nodeId), at ?? Date.now());
  }

  /** All grant/revoke records for a grantee (chronological). */
  grantsFor(grantee) {
    return (this._byGrantee.get(grantee) || []).map((e) => e.g).sort((a, b) => (a.grantedAt ?? 0) - (b.grantedAt ?? 0));
  }

  /** The records `nodeId` signed, kept here, signed before `before` (for a revoker choosing what to ratify). */
  statementsBy(nodeId, before = Infinity) {
    const out = [];
    for (const e of this._pool.values()) if (e.g.grantedBy === nodeId && e.g.grantedAt < before) out.push(e.g);
    return out.sort((a, b) => a.grantedAt - b.grantedAt);
  }

  /**
   * Every record held, in an order that roots each before it is needed (security review D,
   * anti-entropy): the anchor's records first, then those of each grantor the earlier ones reach,
   * breadth first, each grantor's own records by signed time; what no chain reaches comes last.
   * Cached until the next record is kept.
   * @returns {object[]}
   */
  syncOrder() {
    if (this._syncOrder) return this._syncOrder;
    const byGrantor = new Map();
    for (const e of this._pool.values()) {
      let l = byGrantor.get(e.g.grantedBy);
      if (!l) { l = []; byGrantor.set(e.g.grantedBy, l); }
      l.push(e.g);
    }
    const out = [];
    const done = new Set();
    const queue = this._anchor ? [this._anchor.nodeId] : [];
    for (let i = 0; i < queue.length; i++) {
      const grantor = queue[i];
      if (done.has(grantor)) continue;
      done.add(grantor);
      const l = (byGrantor.get(grantor) || []).sort((a, b) => (a.grantedAt ?? 0) - (b.grantedAt ?? 0) || (a.sig < b.sig ? -1 : 1));
      for (const g of l) { out.push(g); if (g.type === 'role-grant' && !done.has(g.grantee)) queue.push(g.grantee); }
    }
    for (const [grantor, l] of byGrantor) if (!done.has(grantor)) out.push(...l);
    this._syncOrder = out;
    return out;
  }

  /**
   * A digest of every record held (security review D, anti-entropy): sha256 over the sorted
   * signatures' canonical spellings. Two stores holding the same records give the same digest.
   * @returns {{ count: number, digest: string }}
   */
  digest() {
    if (this._digest) return this._digest;
    const h = crypto.createHash('sha256');
    for (const sk of [...this._pool.keys()].sort()) h.update(sk).update('\n');
    this._digest = { count: this._pool.size, digest: h.digest('hex') };
    return this._digest;
  }

  /** Whether a record with this signature is held, however the signature is spelled. */
  has(sig) { return this._pool.has(sigKey(sig)); }
  size() { return this._pool.size; }

  // ── Durable persistence (append-only) ────────────────────────────────────────

  /**
   * One line per record kept: the bare canonical record, as 0.13 wrote it. A record later replaced in
   * its budget stays in the file; a reload recomputes the same kept set by the same rule.
   */
  _append(grant) {
    if (!this._dir || this._loading) return;
    try { fs.appendFileSync(path.join(this._dir, GRANTS_FILE), JSON.stringify(grant) + '\n'); }
    catch { /* best effort — never let persistence break authority */ }
  }

  /**
   * Reload the grant file through `record` — the same checks a frame gets. A record can only be
   * verified once a grant vouching its grantor's key is kept, not necessarily before it in the file,
   * so records refused for a reason a later record can cure (`unknown-grantor-key`, `bad-signature`
   * under the keys known so far) are retried until a pass adds nothing. What is left is skipped and
   * counted, and never removed: the file is only ever appended to (re-review N5). Never throws: a file
   * that cannot be read leaves the store with no grants and `loadReport().unreadable` saying why.
   * @private
   */
  _load() {
    const report = { loaded: 0, skipped: {}, unreadable: null };
    this._loadReport = report;
    const skip = (reason) => { report.skipped[reason] = (report.skipped[reason] || 0) + 1; };
    let text;
    try { text = fs.readFileSync(path.join(this._dir, GRANTS_FILE), 'utf8'); }
    catch (err) {
      if (err && err.code !== 'ENOENT') report.unreadable = `${GRANTS_FILE} could not be read (${err.code || err.message})`;
      return;
    }
    this._loading = true;
    try {
      let pending = [];
      for (const line of text.split('\n')) {
        if (!line.trim()) continue;
        let o;
        try { o = JSON.parse(line); } catch { skip('not-json'); continue; }
        // The bare record (0.13, and 0.14), or `{ grant, receivedAt }` as 0.14 development builds
        // wrote it: the receipt time is ignored.
        if (o && typeof o === 'object' && o.grant && typeof o.grant === 'object') pending.push(o.grant);
        else pending.push(o);
      }
      const curable = new Set(['unknown-grantor-key', 'bad-signature']);
      let reasons = [];
      let progress = true;
      while (progress && pending.length) {
        progress = false;
        const retry = [];
        reasons = [];
        for (const g of pending) {
          let r;
          try { r = this.record(g); } catch { r = { stored: false, reason: 'unverifiable' }; }
          if (r.stored) { report.loaded++; progress = true; }
          else if (curable.has(r.reason)) { retry.push(g); reasons.push(r.reason); }
          else skip(r.reason);
        }
        pending = retry;
      }
      for (const reason of reasons) skip(reason);
      // Lines written, then replaced in their budget, load and are replaced again: what is kept is
      // what the rule keeps, and `loaded` counts it.
      report.loaded = this._pool.size;
    } finally {
      this._loading = false;
    }
  }
}

/**
 * A record as its signed fields only (grantPayload: type, grantee, role, grantedBy, grantedAt,
 * granteeKey, and a revoke's cutoff and ratify), with `sig` and `sigAlg`.
 */
function canonicalGrant(g, sig) {
  const c = { type: g.type, grantee: g.grantee };
  if (typeof g.role === 'string' && g.role) c.role = g.role;
  c.grantedBy = g.grantedBy;
  c.grantedAt = g.grantedAt;
  if (typeof g.granteeKey === 'string' && g.granteeKey) c.granteeKey = g.granteeKey;
  if (g.type === 'role-revoke' && g.cutoff !== undefined) c.cutoff = g.cutoff;
  if (g.type === 'role-revoke' && g.ratify !== undefined) c.ratify = [...g.ratify];
  c.sig = sig;
  c.sigAlg = 'ed25519';
  return c;
}

/** The fields a record must have, of the types it must have them, or it is not a record. */
function malformed(g) {
  if (!g || typeof g !== 'object' || Array.isArray(g)) return true;
  if (g.type !== 'role-grant' && g.type !== 'role-revoke') return true;
  // nodeIds in canonical lowercase only (security review B), and bounded (review D).
  for (const f of ['grantee', 'grantedBy']) if (!isCanonicalNodeId(g[f]) || g[f].length > MAX_ID) return true;
  if (typeof g.sig !== 'string' || !g.sig || g.sig.length > 128) return true;
  if (!Number.isSafeInteger(g.grantedAt) || g.grantedAt < 0) return true;
  // A key, when present, is a raw Ed25519 key; a role holds no `|` (the payload's separator), so no
  // two records sign the same bytes.
  if (g.granteeKey !== undefined && (typeof g.granteeKey !== 'string' || (g.granteeKey !== '' && !/^[A-Za-z0-9_-]{43}$/.test(g.granteeKey)))) return true;
  if (g.role !== undefined && (typeof g.role !== 'string' || g.role.length > MAX_ROLE || g.role.includes('|'))) return true;
  if (g.cutoff !== undefined && (g.type !== 'role-revoke' || !Number.isSafeInteger(g.cutoff) || g.cutoff < 0 || g.cutoff > g.grantedAt)) return true;
  if (g.ratify !== undefined) {
    if (g.type !== 'role-revoke' || g.cutoff === undefined || !Array.isArray(g.ratify) || g.ratify.length === 0 || g.ratify.length > MAX_RATIFY) return true;
    for (let i = 0; i < g.ratify.length; i++) {
      if (typeof g.ratify[i] !== 'string' || !CANONICAL_SIG.test(g.ratify[i])) return true;
      if (i > 0 && !(g.ratify[i - 1] < g.ratify[i])) return true; // sorted, no repeats
    }
  }
  if (g.type === 'role-revoke') return false;
  // A grant confers a rank above participant, on the holder of one key, or it confers nothing.
  return roleRank(g.role) < 1 || typeof g.granteeKey !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(g.granteeKey);
}

module.exports = { RoleGrantStore, canonicalGrant, malformedGrant: malformed, cutoffOf, MAX_DELEGATION_DEPTH, SUBTREE_BUDGET, MAX_RATIFY };
