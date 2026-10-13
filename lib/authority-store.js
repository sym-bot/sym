'use strict';

/**
 * @module @sym-bot/sym/authority-store
 * @description MMP §6.6: authority is a function of a set. A node's view of authority is computed
 * from the verified grant, revoke and endorse statements it holds, and from nothing else: not the
 * order they arrived in, not any clock, not the session that delivered them. Statements name one
 * another by the hash of their signed bytes, so the graph is fixed when they are signed, and two nodes
 * holding the same statements under the same pin resolve the same in-force set and the same root.
 *
 * This module holds the statements and resolves them:
 *
 *   - INGEST (§6.6.3 validity, static): well formed, rooted within MAX_DELEGATION_DEPTH links,
 *     signed (an anchor-level statement by the pin's threshold of distinct pinned keys, each copy
 *     judged on its own entries; any other by the subject key of its authorising grant), and
 *     permitted by its authorising grant's role and scope. A statement whose chain is not held is
 *     PENDING (its own signature is checked first); the caller holds it per session (§6.6.8).
 *   - RESOLVE (§6.6.4): the two-phase, depth-ordered algorithm, exactly: per depth, the revokes and
 *     endorses (phase A), then the grants (phase B); each bucket keeps its own statements first, by
 *     ascending id, within AUTHORITY_QUOTA (the anchor's AUTHORITY_ANCHOR_QUOTA) and
 *     AUTHORITY_DELEGATE_QUOTA; a statement a revoke cut off is rescued only by an in-force endorse
 *     that may rescue it, charged to that endorser's bucket, falling through to the next endorser by id
 *     when a bucket is full; a statement cut off by a quota is never rescued.
 *   - THE LIVE SET and THE ROOT (§6.6.7); authority order, fetch answers and pages (§6.6.8).
 *   - CAPACITY (§6.6.6, errata 1): at most MAX_HELD statements, beyond which only in-force revokes
 *     and in-force anchor-level statements are kept (the quotas bound them). Past the bound the store
 *     drops everything outside the live set first, whatever its kind (a dead or over-quota revoke is
 *     an ordinary candidate), then live statements in reverse authority order (deepest first, grants
 *     before revokes and endorses, highest id first), skipping only in-force revokes and in-force
 *     anchor-level statements. So a removal that is in force is always kept, and one signer's dead
 *     statements never displace another's authority.
 *   - PERSISTENCE: one file of statements, with no integrity of its own and independent of the pin.
 *     At load each is judged again against the pin in force now and the set resolved afresh; a
 *     statement that does not count under this pin (a mistyped pin, a re-pin, a chain not yet held)
 *     is kept in the file as unverified bytes, never deleted, so a corrected pin or a re-pin that
 *     keeps a threshold of the old keys finds what still counts (§6.6.1). No status, root or receipt
 *     time is read from disk.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const fs = require('fs');
const path = require('path');
const A = require('./core/authority');

/** The one statement file, whatever the pin. */
const FILE = 'statements.jsonl';
/**
 * Statements held at most (§6.6.7: a node MUST keep its live set and MAY drop the rest; past this
 * bound it cannot keep everything: see `_evict`). One eviction pass resolves once and frees EVICT_SLACK
 * below the bound (or, when what is left is protected, the next pass waits until that many more have
 * arrived), so a pass, its resolution and its sort are paid once per EVICT_SLACK arrivals.
 */
const MAX_HELD = 200_000;
const evictSlack = (max) => Math.max(1, Math.ceil(max / 64));

const kindGroup = (k) => (k === 'grant' ? 1 : 0); // revokes and endorses before grants (authority order)

class AuthorityStore {
  /**
   * @param {object} opts
   * @param {object|null} opts.pin - a parsed pin (core/authority parsePin), or null: nothing is in force
   * @param {string} [opts.dir] - where statements persist
   * @param {number} [opts.quota] - in place of AUTHORITY_QUOTA (tests: the vector's testQuota)
   * @param {number} [opts.delegateQuota] - in place of AUTHORITY_DELEGATE_QUOTA
   * @param {number} [opts.maxHeld]
   * @param {boolean} [opts.lazy] - queries read the last resolution, and only `resolve()` makes a new
   *   one (a node resolves when it settles, not on every query); otherwise every query is fresh
   * @param {function} [opts.log]
   */
  constructor(opts = {}) {
    this._pin = opts.pin || null;
    this._pinKeys = new Set(this._pin ? this._pin.members.map((m) => m.key) : []);
    this._quota = Number.isSafeInteger(opts.quota) && opts.quota > 0 ? opts.quota : A.AUTHORITY_QUOTA;
    this._anchorQuota = A.AUTHORITY_ANCHOR_QUOTA;
    this._delegateQuota = Number.isSafeInteger(opts.delegateQuota) && opts.delegateQuota > 0 ? opts.delegateQuota : A.AUTHORITY_DELEGATE_QUOTA;
    this._maxHeld = Number.isSafeInteger(opts.maxHeld) && opts.maxHeld > 0 ? opts.maxHeld : MAX_HELD;
    this._log = typeof opts.log === 'function' ? opts.log : () => {};
    this._held = new Map(); // id -> entry { id, s, kind, authBy, depth, chain, role, scope, subject, targets }
    this._resolved = null;  // the last resolution
    this._dirty = true;     // the held set changed since it
    this._lazy = opts.lazy === true;
    this._lastResolveMs = 0;
    this._pinDigest = this._pin ? A.pinDigest(this._pin) : null;
    this._dir = opts.dir || null;
    this._loading = false;
    this._loadReport = { held: 0, pending: 0, invalid: 0, unverified: 0, corrupt: 0 };
    this._capacity = { evicted: 0, refused: 0, liveDropped: 0 };
    this._protectedFloor = 0; // the size a pass could not get below (what is left is protected)
    this._fileLines = 0;      // statements the file holds, held or not, to know when to compact it
    this._unverifiedLines = []; // lines kept from the file that do not count under this pin (as bytes)
    if (this._dir) this._load();
  }

  /** Whether an anchor is pinned. Where none is, nothing is in force (§6.6.1). */
  get anchored() { return !!this._pin; }
  get pin() { return this._pin; }
  get pinDigest() { return this._pinDigest; }
  loadReport() { return { ...this._loadReport }; }
  /** Statements dropped or refused for capacity since start. */
  capacityReport() { return { ...this._capacity }; }
  /** How long the last resolution took (a node paces its settles by it). */
  get lastResolveMs() { return this._lastResolveMs; }
  /** Whether the held set changed since the last resolution. */
  get dirty() { return this._dirty || !this._resolved; }
  size() { return this._held.size; }
  has(id) { return this._held.has(id); }
  /** A held statement (its canonical form, with the signature entries that counted), or null. */
  get(id) { const e = this._held.get(id); return e ? e.s : null; }
  depthOf(id) { const e = this._held.get(id); return e ? e.depth : null; }

  // ── Ingest: §6.6.3 validity ───────────────────────────────────────────────────

  /**
   * Check one statement and hold it if it is valid.
   * @returns {{ result: 'held'|'duplicate'|'pending'|'invalid'|'over-capacity', id?: string, reason?: string, missing?: string }}
   *   'over-capacity': valid, but the store is full and it is what an eviction pass dropped (never
   *   an in-force revoke or anchor-level statement); it says nothing against the statement or who sent it
   */
  ingest(statement) {
    const bad = A.malformedReason(statement);
    if (bad) return { result: 'invalid', reason: `not well formed: ${bad}` };
    const id = A.statementId(statement);
    if (this._held.has(id)) return { result: 'duplicate', id };
    if (!this._pin) return { result: 'invalid', id, reason: 'no anchor is pinned' };
    const v = this._validate(statement, id);
    if (v.result !== 'valid') return { ...v, id };
    this._held.set(id, v.entry);
    this._changed();
    this._compacted = false;
    if (this._held.size > Math.max(this._maxHeld, this._protectedFloor + evictSlack(this._maxHeld)) && this._evict(id).has(id)) {
      this._capacity.refused++;
      return { result: 'over-capacity', id, reason: 'the store is full, and an eviction pass dropped this statement' };
    }
    // A pass that compacted the file wrote every held statement, this one included: once is enough.
    if (!this._compacted) this._append(v.entry.s);
    this._compacted = false;
    return { result: 'held', id };
  }

  /** @private Rules 2 to 4, for a well-formed statement not held. */
  _validate(s, id) {
    const bytes = A.payload(s);
    if (s.authorisedBy === 'anchor') {
      // §6.6.1: at least t distinct pinned keys, each verifying; only the entries counted are kept, and
      // each copy is judged on its own entries (never merged with another copy's).
      const counted = [];
      const seen = new Set();
      for (const e of s.sigs) {
        if (!this._pinKeys.has(e.key) || seen.has(e.key)) continue;
        if (!A.entryVerifies(s, e, bytes)) continue;
        seen.add(e.key);
        counted.push(e);
      }
      if (counted.length < this._pin.threshold) return { result: 'invalid', reason: `${counted.length} of the ${this._pin.threshold} anchor signatures it needs` };
      return { result: 'valid', entry: this._entry(s, id, counted, 1, []) };
    }
    const auth = this._held.get(s.authorisedBy);
    if (!auth) {
      // §6.6.8: a pending statement's own signature is checked, with the key its entry names, before
      // anything else; one that fails is discarded.
      if (!A.entryVerifies(s, s.sigs[0], bytes)) return { result: 'invalid', reason: 'its signature does not verify' };
      return { result: 'pending', missing: s.authorisedBy };
    }
    if (auth.kind !== 'grant') return { result: 'invalid', reason: 'authorisedBy names a statement that is not a grant' };
    const depth = auth.depth + 1;
    if (depth > A.MAX_DELEGATION_DEPTH) return { result: 'invalid', reason: `deeper than ${A.MAX_DELEGATION_DEPTH}` };
    const entry = s.sigs[0];
    if (entry.key !== auth.subject.key) return { result: 'invalid', reason: 'not signed by the subject key of its authorising grant' };
    if (!A.entryVerifies(s, entry, bytes)) return { result: 'invalid', reason: 'its signature does not verify' };
    const why = this._notPermitted(s, auth);
    if (why) return { result: 'invalid', reason: why };
    return { result: 'valid', entry: this._entry(s, id, [entry], depth, [auth.id, ...auth.chain]) };
  }

  /** @private §6.6.2 / §6.6.3 rule 4: what the authorising grant's role permits, and scope narrowing. */
  _notPermitted(s, auth) {
    const role = auth.role;
    if (s.kind === 'grant') {
      if (role === 'admin') { /* admin, validator, issuer and any non-authority role */ }
      else if (role === 'validator' || role === 'issuer') { if (!A.isNonAuthority(s.role)) return `a ${role} grants non-authority roles only`; }
      else return `a ${role} grant permits no statement`;
      if (!A.scopeNarrows(auth.scope, s.scope === undefined ? null : s.scope)) return 'its scope would widen its authorising grant\'s';
      return null;
    }
    if (s.kind === 'revoke') return A.isDelegating(role) ? null : `a ${role} may not revoke`;
    return role === 'admin' ? null : `a ${role} may not endorse`;
  }

  /** @private The held form of a valid statement. */
  _entry(s, id, sigs, depth, chain) {
    const c = A.canonicalStatement(s, sigs);
    return {
      id, s: c, kind: c.kind, authBy: c.authorisedBy, depth, chain,
      role: c.kind === 'grant' ? c.role : null,
      scope: c.kind === 'grant' && c.scope !== undefined ? c.scope : null,
      subject: c.kind === 'grant' ? c.subject : null,
      targets: c.kind === 'grant' ? null : c.targets,
    };
  }

  // ── Resolution: §6.6.4 ────────────────────────────────────────────────────────

  /**
   * Resolve the held set (memoised until it changes).
   * @returns {{ status: Map<string, string>, inForce: Set<string>, keptBy: Map<string, string>, live: Set<string>, root: string|null }}
   */
  resolve() {
    if (this._resolved && !this._dirty) return this._resolved;
    const t0 = process.hrtime.bigint();
    const held = this._held;
    const status = new Map();
    const F = new Set();
    const keptBy = new Map();
    const count = new Map();
    const delegates = new Map();
    // Index: buckets by depth, and for every id the revokes and endorses naming it, ascending id.
    const byDepth = new Map(); // depth -> Map(bucket -> entries)
    const namers = new Map();
    for (const e of held.values()) {
      let buckets = byDepth.get(e.depth);
      if (!buckets) { buckets = new Map(); byDepth.set(e.depth, buckets); }
      let b = buckets.get(e.authBy);
      if (!b) { b = []; buckets.set(e.authBy, b); }
      b.push(e);
      if (e.targets) for (const t of e.targets) {
        let l = namers.get(t);
        if (!l) { l = []; namers.set(t, l); }
        l.push(e);
      }
    }
    const byId = (x, y) => (x.id < y.id ? -1 : x.id > y.id ? 1 : 0);
    for (const l of namers.values()) l.sort(byId);
    const inForce = (bucket) => bucket === 'anchor' || F.has(bucket);
    const Q = (bucket) => (bucket === 'anchor' ? this._anchorQuota : this._quota);
    const keep = (bucket, e) => {
      if ((count.get(bucket) || 0) >= Q(bucket)) return false;
      const delegating = e.kind === 'grant' && A.isDelegating(e.role);
      if (delegating && bucket !== 'anchor' && (delegates.get(bucket) || 0) >= this._delegateQuota) return false;
      count.set(bucket, (count.get(bucket) || 0) + 1);
      if (delegating) delegates.set(bucket, (delegates.get(bucket) || 0) + 1);
      F.add(e.id);
      keptBy.set(e.id, bucket);
      status.set(e.id, 'in-force');
      return true;
    };
    // r may remove g: r is anchor-level or authorised by a grant above g.
    const mayRemove = (r, g) => g.kind === 'grant' && (r.authBy === 'anchor' || g.chain.includes(r.authBy));
    // e may rescue s: s is a grant or revoke, not anchor-level, and e is anchor-level or authorised by
    // a grant above s's authorising grant.
    const mayRescue = (e, s) => {
      if (s.kind === 'endorse' || s.authBy === 'anchor') return false;
      if (e.authBy === 'anchor') return true;
      const auth = held.get(s.authBy);
      return !!auth && auth.chain.includes(e.authBy);
    };
    const removed = (g) => (namers.get(g.id) || []).some((r) => r.kind === 'revoke' && F.has(r.id) && mayRemove(r, g));
    // Past the dead grants on s's chain, the first is removed (cut by a revoke). Over quota is a cut
    // by a quota, which is never rescued.
    const cutByRevoke = (s) => {
      for (const gid of s.chain) {
        const st = status.get(gid);
        if (st === 'dead') continue;
        return st === 'removed';
      }
      return false;
    };
    const rescue = (s) => {
      let tried = false;
      for (const e of namers.get(s.id) || []) {
        if (e.kind !== 'endorse' || !F.has(e.id) || !mayRescue(e, s)) continue;
        tried = true;
        if (keep(e.authBy, s)) return;
      }
      status.set(s.id, tried ? 'over-quota' : 'dead');
    };
    for (let d = 1; d <= A.MAX_DELEGATION_DEPTH; d++) {
      const buckets = byDepth.get(d);
      if (!buckets) continue;
      const kept = [];
      const other = [];
      for (const [bucket, entries] of buckets) (inForce(bucket) ? kept : other).push([bucket, entries]);
      // Phase A: the revokes and endorses at depth d.
      for (const [bucket, entries] of kept) {
        for (const s of entries.filter((x) => x.kind !== 'grant').sort(byId)) if (!keep(bucket, s)) status.set(s.id, 'over-quota');
      }
      let candidates = [];
      for (const [, entries] of other) {
        for (const s of entries) {
          if (s.kind === 'grant') continue;
          if (s.kind === 'endorse') status.set(s.id, 'dead');
          else if (cutByRevoke(s)) candidates.push(s);
          else status.set(s.id, 'dead');
        }
      }
      for (const s of candidates.sort(byId)) rescue(s);
      // Phase B: the grants at depth d.
      for (const [bucket, entries] of kept) {
        for (const g of entries.filter((x) => x.kind === 'grant').sort(byId)) {
          if (removed(g)) status.set(g.id, 'removed');
          else if (!keep(bucket, g)) status.set(g.id, 'over-quota');
        }
      }
      candidates = [];
      for (const [, entries] of other) {
        for (const g of entries) {
          if (g.kind !== 'grant') continue;
          if (!cutByRevoke(g)) status.set(g.id, 'dead');
          else if (removed(g)) status.set(g.id, 'removed');
          else candidates.push(g);
        }
      }
      for (const g of candidates.sort(byId)) rescue(g);
    }
    // The live set: the in-force set and the grants on its members' chains (§6.6.7).
    const live = new Set(F);
    for (const id of F) for (const gid of held.get(id).chain) live.add(gid);
    const root = this._pin ? A.authorityRoot(this._pinDigest, F) : null;
    this._resolved = { status, inForce: F, keptBy, live, root, liveOrder: null };
    this._dirty = false;
    this._lastResolveMs = Number(process.hrtime.bigint() - t0) / 1e6;
    return this._resolved;
  }

  /**
   * The resolution queries read: the last one when the store is lazy (a node resolves when it
   * settles), a fresh one otherwise.
   */
  view() {
    return this._lazy && this._resolved ? this._resolved : this.resolve();
  }

  /** A held statement's status: in-force, removed, over-quota or dead; undefined when not held. */
  statusOf(id) { return this.view().status.get(id); }
  isInForce(id) { return this.view().inForce.has(id); }
  root() { return this.view().root; }
  /** For authority-digest (§6.6.8): the root and the in-force count. */
  digest() { const r = this.view(); return { root: r.root, count: r.inForce.size }; }

  // ── Roles: §6.6.4 "roles follow the key" ─────────────────────────────────────

  /**
   * The roles `nodeId` holding `key` has: those of the in-force grants whose subject is that nodeId
   * and that key, each with its scope (null: the whole mesh), plus `anchor` for a pinned member of a
   * threshold-1 anchor pinned with that nodeId and key.
   * @returns {{ role: string, scope: string|null, grant: string|null }[]}
   */
  rolesOf(nodeId, key) {
    const out = [];
    if (!this._pin || typeof nodeId !== 'string' || typeof key !== 'string') return out;
    if (this._pin.threshold === 1 && this._pin.members.some((m) => m.key === key && m.nodeId === nodeId)) out.push({ role: 'anchor', scope: null, grant: null });
    const { inForce } = this.view();
    for (const id of inForce) {
      const e = this._held.get(id);
      if (e && e.kind === 'grant' && e.subject.nodeId === nodeId && e.subject.key === key) out.push({ role: e.role, scope: e.scope, grant: id });
    }
    return out;
  }

  /**
   * The lifecycle authority (§3.5) `nodeId` holding `key` has over one CMB: the highest of its roles
   * whose scope contains it — 'canonical' (anchor, admin), 'validated' (validator), or 'none'.
   * `contains(scope)` says whether the CMB is inside a scope (the extension owning its namespace
   * decides; a namespace this node does not implement contains nothing). An unscoped role contains
   * every CMB.
   * @param {(scope: string) => boolean} [contains]
   */
  lifecycleOver(nodeId, key, contains = () => false) {
    return lifecycleOf(this.rolesOf(nodeId, key), contains);
  }

  /**
   * The key the in-force grants name for `nodeId` (§6.6.9: a binding source, a view over what is in
   * force now): undefined when none does, or when two different keys do.
   */
  grantKey(nodeId) {
    const { inForce } = this.view();
    let found;
    for (const id of inForce) {
      const e = this._held.get(id);
      if (!e || e.kind !== 'grant' || e.subject.nodeId !== nodeId) continue;
      if (found !== undefined && found !== e.subject.key) return undefined;
      found = e.subject.key;
    }
    return found;
  }

  /** The in-force grants naming `nodeId` with a key other than `key` (a foreign key for this node). */
  foreignGrantsFor(nodeId, key) {
    const out = [];
    for (const id of this.view().inForce) {
      const e = this._held.get(id);
      if (e && e.kind === 'grant' && e.subject.nodeId === nodeId && e.subject.key !== key) out.push(e.s);
    }
    return out;
  }

  /** In-force grants (held, canonical), for a host's listing. */
  inForceStatements() { return [...this.view().inForce].map((id) => this._held.get(id)).filter(Boolean).map((e) => e.s); }

  // ── Serving: §6.6.8 ──────────────────────────────────────────────────────────

  /** @private Authority order: ascending depth; revokes and endorses before grants; ascending id. */
  _orderKey(e) { return `${e.depth}.${kindGroup(e.kind)}.${e.id}`; }

  /** Statements in authority order. */
  authorityOrder(ids) {
    return [...ids].map((id) => this._held.get(id)).filter(Boolean).sort(orderCmp);
  }

  /**
   * An answer to authority-fetch by ids (§6.6.8): each named statement in the live set with its chain,
   * and every in-force revoke and endorse naming a statement in the answer, each with its chain, and so
   * on to a fixpoint (an endorse that keeps a revoke in the answer in force is in the answer too); in
   * authority order, at most AUTHORITY_PAGE statements. A named statement whose closure does not fit
   * is listed missing, as is one not in the live set.
   * @returns {{ statements: object[], missing: string[] }}
   */
  answerIds(ids) {
    const { live, inForce } = this.view();
    const chosen = new Set();
    const missing = [];
    for (const id of ids) {
      if (!live.has(id) || !this._held.has(id)) { missing.push(id); continue; }
      const add = new Set();
      const queue = [id];
      let over = false;
      while (queue.length && !over) {
        const e = this._held.get(queue.pop());
        if (!e) continue;
        for (const y of [e.id, ...e.chain]) {
          if (chosen.has(y) || add.has(y) || !this._held.has(y)) continue;
          add.add(y);
          if (chosen.size + add.size > A.AUTHORITY_PAGE) { over = true; break; }
          for (const n of this._namersOf(y)) if (inForce.has(n.id) && !chosen.has(n.id) && !add.has(n.id)) queue.push(n.id);
        }
      }
      if (over) { missing.push(id); continue; }
      for (const x of add) chosen.add(x);
    }
    return { statements: this.authorityOrder(chosen).map((e) => e.s), missing };
  }

  /** @private The held revokes and endorses naming `id` (an index rebuilt when the held set changes). */
  _namersOf(id) {
    if (!this._namerIndex || this._namerIndexAt !== this._version) {
      const m = new Map();
      for (const e of this._held.values()) if (e.targets) for (const t of e.targets) { let l = m.get(t); if (!l) { l = []; m.set(t, l); } l.push(e); }
      this._namerIndex = m;
      this._namerIndexAt = this._version;
    }
    return this._namerIndex.get(id) || [];
  }

  /**
   * A page of the live set in authority order after `after` (an opaque cursor: '' for the start). The
   * order is sorted once per resolution, and a page found by binary search: O(log S + page).
   * @returns {{ statements: object[], next: string|null }}
   */
  page(after) {
    const r = this.view();
    if (!r.liveOrder) r.liveOrder = this.authorityOrder(r.live);
    const all = r.liveOrder;
    let lo = 0;
    if (typeof after === 'string' && after) {
      let hi = all.length;
      while (lo < hi) {
        const mid = (lo + hi) >>> 1;
        if (this._orderKeyCompare(this._orderKey(all[mid]), after) <= 0) lo = mid + 1; else hi = mid;
      }
    }
    const slice = all.slice(lo, lo + A.AUTHORITY_PAGE);
    const more = lo + slice.length < all.length;
    return { statements: slice.map((e) => e.s), next: more && slice.length ? this._orderKey(slice[slice.length - 1]) : null };
  }

  /** @private Compare two order keys `${depth}.${group}.${id}`. */
  _orderKeyCompare(a, b) {
    const [da, ga, ia] = a.split('.'); const [db, gb, ib] = String(b).split('.');
    return (Number(da) - Number(db)) || (Number(ga) - Number(gb)) || (ia < ib ? -1 : ia > ib ? 1 : 0);
  }

  // ── Capacity and persistence ──────────────────────────────────────────────────

  /**
   * @private One eviction pass (§6.6.6, node capacity, errata 1), down to EVICT_SLACK below the bound.
   * It resolves once, then drops:
   *   1. everything outside the live set, whatever its kind (a dead or over-quota revoke, a dead
   *      anchor-level statement), last in authority order first. Dropping what is not live changes no
   *      status of what stays, so the resolution stays good;
   *   2. if that is not enough, live statements in reverse authority order (deepest first, grants
   *      before revokes and endorses, highest id first), skipping in-force revokes and in-force
   *      anchor-level statements: a removal in force is never dropped. The quotas bound those.
   * The statement arriving (`incomingId`) is judged with the rest: protected only if it is in force.
   * Where what is left is protected, the next pass waits until EVICT_SLACK more have arrived. A node
   * that drops live statements no longer resolves the set its peers do, and it says so.
   * @returns {Set<string>} the ids dropped
   */
  _evict(incomingId) {
    const dropped = new Set();
    const target = Math.max(0, this._maxHeld - evictSlack(this._maxHeld));
    let n = this._held.size - target;
    if (n <= 0) return dropped;
    const r = this.resolve();
    const outside = [];
    const inside = [];
    for (const e of this._held.values()) {
      if (!r.live.has(e.id)) outside.push(e);
      else if (!(r.inForce.has(e.id) && (e.authBy === 'anchor' || e.kind === 'revoke'))) inside.push(e);
    }
    const last = (x, y) => orderCmp(y, x);
    outside.sort(last);
    for (const e of outside.slice(0, n)) { this._held.delete(e.id); dropped.add(e.id); r.status.delete(e.id); }
    n -= dropped.size;
    let liveDropped = 0;
    if (n > 0) {
      inside.sort(last);
      for (const e of inside.slice(0, n)) {
        this._held.delete(e.id);
        dropped.add(e.id);
        if (e.id !== incomingId) liveDropped++;
      }
    }
    this._protectedFloor = this._held.size > target ? this._held.size : 0;
    this._capacity.evicted += dropped.size - (dropped.has(incomingId) ? 1 : 0);
    this._capacity.liveDropped += liveDropped;
    if (this._loading && this._loadEvicted) for (const id of dropped) this._loadEvicted.add(id);
    // Only statements outside the live set went: the resolution holds for what stays.
    this._version = (this._version || 0) + 1;
    if (liveDropped || dropped.has(incomingId) && r.live.has(incomingId)) this._changed();
    if (liveDropped) this._log(`[sym-authority] the store is over ${this._maxHeld} statements: ${liveDropped} live statement(s) dropped, deepest first; this node no longer resolves the same set as its peers`);
    else if (dropped.size) this._log(`Authority store over ${this._maxHeld}: ${dropped.size} statement(s) outside the live set dropped`);
    this._maybeCompact();
    return dropped;
  }

  /** @private The held set changed: the resolution and the namer index are stale. */
  _changed() { this._dirty = true; this._version = (this._version || 0) + 1; }

  /**
   * @private Append a held statement to the file (best effort; the file carries no authority). Each
   * record starts on a line of its own (a torn last line is ended first), and a write that fails part
   * way is cut back to where it began, so one failure costs at most the statement being written.
   */
  _append(s) {
    if (!this._dir || this._loading) return;
    const file = path.join(this._dir, FILE);
    let fd = null;
    let size = 0;
    try {
      fs.mkdirSync(this._dir, { recursive: true });
      fd = fs.openSync(file, 'a+', 0o600);
      size = fs.fstatSync(fd).size;
      let lead = '';
      if (size > 0) {
        const last = Buffer.alloc(1);
        fs.readSync(fd, last, 0, 1, size - 1);
        if (last[0] !== 0x0a) lead = '\n';
      }
      const buf = Buffer.from(`${lead}${JSON.stringify(s)}\n`, 'utf8');
      for (let off = 0; off < buf.length;) off += fs.writeSync(fd, buf, off, buf.length - off);
      this._fileLines++;
    } catch {
      if (fd !== null) { try { fs.ftruncateSync(fd, size); } catch { /* best effort */ } }
    } finally {
      if (fd !== null) { try { fs.closeSync(fd); } catch { /* best effort */ } }
    }
  }

  /**
   * @private The file holds every statement ever appended; one dropped for capacity stays there until
   * the file is rewritten. Rewrite it (the held statements and the lines kept from it as unverified)
   * once it holds twice what that would be, so the disk is bounded by what the store keeps, at a cost
   * paid once per that many appends.
   */
  _maybeCompact() {
    if (!this._dir || this._loading) return;
    const keep = this._held.size + this._unverifiedLines.length;
    if (this._fileLines <= 2 * keep + evictSlack(this._maxHeld)) return;
    if (this._writeFile([...[...this._held.values()].map((e) => JSON.stringify(e.s)), ...this._unverifiedLines])) this._compacted = true;
  }

  /**
   * @private Replace the file with `lines`, crash-safe: written to a temporary file, flushed to disk,
   * renamed over the file, and the directory flushed, so a power loss leaves either the old file or
   * the new one, never an empty one (the lines kept from other pins cannot be fetched from a peer).
   * @returns {boolean} whether the file was replaced
   */
  _writeFile(lines) {
    const file = path.join(this._dir, FILE);
    const tmp = `${file}.${process.pid}.tmp`;
    let fd = null;
    try {
      fs.mkdirSync(this._dir, { recursive: true });
      fd = fs.openSync(tmp, 'w', 0o600);
      const buf = Buffer.from(lines.join('\n') + (lines.length ? '\n' : ''), 'utf8');
      for (let off = 0; off < buf.length;) off += fs.writeSync(fd, buf, off, buf.length - off);
      fs.fsyncSync(fd);
      fs.closeSync(fd);
      fd = null;
      fs.renameSync(tmp, file);
      syncDir(this._dir);
      this._fileLines = lines.length;
      return true;
    } catch {
      if (fd !== null) { try { fs.closeSync(fd); } catch { /* best effort */ } }
      try { fs.unlinkSync(tmp); } catch { /* best effort */ }
      return false;
    }
  }

  /** @private Remove the temporary files a crash left behind (`statements.jsonl.<pid>.tmp` of a process that is gone). */
  _removeStaleTemps() {
    let names = [];
    try { names = fs.readdirSync(this._dir); } catch { return; }
    for (const n of names) {
      const m = /^statements\.jsonl\.(\d+)\.tmp$/.exec(n);
      if (!m) continue;
      const pid = Number(m[1]);
      if (pid !== process.pid && pidAlive(pid)) continue;
      try { fs.unlinkSync(path.join(this._dir, n)); } catch { /* best effort */ }
    }
  }

  /**
   * @private Read the one statement file and judge every statement again against the pin in force,
   * chain by chain: offered in passes until one holds nothing more, so file order does not matter.
   * Nothing read from disk is trusted for being there. What does not count under this pin (a statement
   * that fails, or one whose chain is not held) is never deleted: the file is rewritten as the held
   * statements and, as the bytes they were, the rest, so a corrected pin or a re-pin that keeps a
   * threshold of the old keys finds them again (§6.6.1). Only lines that are not a statement at all
   * (torn, not JSON, not of the shape) and statements dropped for capacity are left out. With no pin,
   * nothing is judged and the file is left as it is.
   */
  _load() {
    this._removeStaleTemps();
    const file = path.join(this._dir, FILE);
    let text = '';
    try { text = fs.readFileSync(file, 'utf8'); } catch { return; }
    const entries = [];
    for (const line of text.split('\n')) {
      if (!line.trim()) continue;
      let s;
      try { s = JSON.parse(line); } catch { this._loadReport.corrupt++; continue; }
      if (A.shapeReason(s)) { this._loadReport.corrupt++; continue; }
      entries.push({ line, s });
    }
    if (!this._pin) { this._loadReport.unverified = entries.length; this._fileLines = entries.length; return; }
    this._loading = true;
    this._loadEvicted = new Set(); // dropped for capacity during this load: not written back
    try {
      let left = entries;
      for (let progress = true; progress && left.length;) {
        progress = false;
        const next = [];
        for (const e of left) {
          const r = this.ingest(e.s);
          if (r.result === 'held') progress = true;
          else if (r.result === 'pending') next.push(e);
        }
        left = next;
      }
      this._loadReport.pending = left.length;
    } finally { this._loading = false; }
    this._loadReport.held = this._held.size;
    const written = new Set();
    const out = [];
    for (const e of this._held.values()) { const l = JSON.stringify(e.s); written.add(l); out.push(l); }
    for (const e of entries) {
      if (written.has(e.line)) continue;
      const id = A.statementId(e.s);
      if (!this._held.has(id) && this._loadEvicted.has(id)) continue;
      // A copy of a held statement whose entries are all held adds nothing; one carrying other entries
      // may count under another pin (§6.6.1), and is kept.
      if (this._held.has(id) && entriesWithin(e.s.sigs, this._held.get(id).s.sigs)) continue;
      written.add(e.line);
      out.push(e.line);
      this._unverifiedLines.push(e.line);
      this._loadReport.unverified++;
    }
    this._loadEvicted = null;
    this._writeFile(out);
  }
}

/** Flush a directory's entries to disk (a rename is durable only once its directory is). Best effort: not every platform can. */
function syncDir(dir) {
  let fd = null;
  try { fd = fs.openSync(dir, 'r'); fs.fsyncSync(fd); } catch { /* best effort */ } finally { if (fd !== null) { try { fs.closeSync(fd); } catch { /* */ } } }
}

/** Whether a process is alive (signal 0 tests without sending anything). */
function pidAlive(pid) {
  try { process.kill(pid, 0); return true; } catch (err) { return !!(err && err.code === 'EPERM'); }
}

/** Whether every signature entry of `a` is one of `b`'s. */
function entriesWithin(a, b) {
  const k = (e) => `${e && e.key}|${e && e.sig}`;
  const set = new Set((b || []).map(k));
  return Array.isArray(a) && a.every((e) => set.has(k(e)));
}

/** Authority order: ascending depth; revokes and endorses before grants; ascending id. */
function orderCmp(x, y) {
  return (x.depth - y.depth) || (kindGroup(x.kind) - kindGroup(y.kind)) || (x.id < y.id ? -1 : x.id > y.id ? 1 : 0);
}

/** The lifecycle level of a role list over one CMB (see AuthorityStore#lifecycleOver). */
function lifecycleOf(roles, contains = () => false) {
  let level = 0;
  for (const r of roles) {
    if (r.scope !== null && !contains(r.scope)) continue;
    if (r.role === 'anchor' || r.role === 'admin') level = Math.max(level, 2);
    else if (r.role === 'validator') level = Math.max(level, 1);
  }
  return level === 2 ? 'canonical' : level === 1 ? 'validated' : 'none';
}

module.exports = { AuthorityStore, lifecycleOf, MAX_HELD };
