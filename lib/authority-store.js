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
 *   - PERSISTENCE: statements are kept on disk with no integrity of their own, in a file named by
 *     the pin's digest (a statement means something only under the pin it was verified against, so
 *     a node started under another pin reads another file and leaves this one as it was). At load
 *     each is verified again against the pinned anchor and the set resolved afresh. No status, root
 *     or receipt time is read from disk.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const fs = require('fs');
const path = require('path');
const A = require('./core/authority');

/** The statements verified under one pin: `statements-<pin digest>.jsonl` in the store's directory. */
const fileFor = (pinDigest) => `statements-${pinDigest}.jsonl`;
/**
 * Statements held at most. A node MUST keep its live set and MAY drop the rest (§6.6.5, §6.6.7);
 * past this it drops dead and over-quota statements that are not live, highest id first, and refuses
 * new ones only when the live set alone fills it.
 */
const MAX_HELD = 200_000;

const kindGroup = (k) => (k === 'grant' ? 1 : 0); // revokes and endorses before grants (authority order)

class AuthorityStore {
  /**
   * @param {object} opts
   * @param {object|null} opts.pin - a parsed pin (core/authority parsePin), or null: nothing is in force
   * @param {string} [opts.dir] - where statements persist
   * @param {number} [opts.quota] - in place of AUTHORITY_QUOTA (tests: the vector's testQuota)
   * @param {number} [opts.delegateQuota] - in place of AUTHORITY_DELEGATE_QUOTA
   * @param {number} [opts.maxHeld]
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
    this._resolved = null;  // the last resolution, or null when the held set changed since
    this._pinDigest = this._pin ? A.pinDigest(this._pin) : null;
    this._dir = opts.dir || null;
    this._loading = false;
    this._loadReport = { held: 0, pending: 0, invalid: 0 };
    if (this._dir && this._pin) this._load();
  }

  /** Whether an anchor is pinned. Where none is, nothing is in force (§6.6.1). */
  get anchored() { return !!this._pin; }
  get pin() { return this._pin; }
  get pinDigest() { return this._pinDigest; }
  loadReport() { return { ...this._loadReport }; }
  size() { return this._held.size; }
  has(id) { return this._held.has(id); }
  /** A held statement (its canonical form, with the signature entries that counted), or null. */
  get(id) { const e = this._held.get(id); return e ? e.s : null; }
  depthOf(id) { const e = this._held.get(id); return e ? e.depth : null; }

  // ── Ingest: §6.6.3 validity ───────────────────────────────────────────────────

  /**
   * Check one statement and hold it if it is valid.
   * @returns {{ result: 'held'|'duplicate'|'pending'|'invalid', id?: string, reason?: string, missing?: string }}
   */
  ingest(statement) {
    const bad = A.malformedReason(statement);
    if (bad) return { result: 'invalid', reason: `not well formed: ${bad}` };
    const id = A.statementId(statement);
    if (this._held.has(id)) return { result: 'duplicate', id };
    if (!this._pin) return { result: 'invalid', id, reason: 'no anchor is pinned' };
    const v = this._validate(statement, id);
    if (v.result !== 'valid') return { ...v, id };
    if (this._held.size >= this._maxHeld && !this._makeRoom()) return { result: 'invalid', id, reason: 'the store is full of live statements' };
    this._held.set(id, v.entry);
    this._resolved = null;
    this._append(v.entry.s);
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
    if (this._resolved) return this._resolved;
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
    this._resolved = { status, inForce: F, keptBy, live, root };
    return this._resolved;
  }

  /** A held statement's status: in-force, removed, over-quota or dead; undefined when not held. */
  statusOf(id) { return this.resolve().status.get(id); }
  isInForce(id) { return this.resolve().inForce.has(id); }
  root() { return this.resolve().root; }
  /** For authority-digest (§6.6.8): the root and the in-force count. */
  digest() { const r = this.resolve(); return { root: r.root, count: r.inForce.size }; }

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
    const { inForce } = this.resolve();
    for (const id of inForce) {
      const e = this._held.get(id);
      if (e.kind === 'grant' && e.subject.nodeId === nodeId && e.subject.key === key) out.push({ role: e.role, scope: e.scope, grant: id });
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
    const { inForce } = this.resolve();
    let found;
    for (const id of inForce) {
      const e = this._held.get(id);
      if (e.kind !== 'grant' || e.subject.nodeId !== nodeId) continue;
      if (found !== undefined && found !== e.subject.key) return undefined;
      found = e.subject.key;
    }
    return found;
  }

  /** The in-force grants naming `nodeId` with a key other than `key` (a foreign key for this node). */
  foreignGrantsFor(nodeId, key) {
    const out = [];
    for (const id of this.resolve().inForce) {
      const e = this._held.get(id);
      if (e.kind === 'grant' && e.subject.nodeId === nodeId && e.subject.key !== key) out.push(e.s);
    }
    return out;
  }

  /** In-force grants (held, canonical), for a host's listing. */
  inForceStatements() { return [...this.resolve().inForce].map((id) => this._held.get(id).s); }

  // ── Serving: §6.6.8 ──────────────────────────────────────────────────────────

  /** @private Authority order: ascending depth; revokes and endorses before grants; ascending id. */
  _orderKey(e) { return `${e.depth}.${kindGroup(e.kind)}.${e.id}`; }

  /** Statements in authority order. */
  authorityOrder(ids) {
    return [...ids].map((id) => this._held.get(id)).filter(Boolean)
      .sort((x, y) => (x.depth - y.depth) || (kindGroup(x.kind) - kindGroup(y.kind)) || (x.id < y.id ? -1 : x.id > y.id ? 1 : 0));
  }

  /**
   * An answer to authority-fetch by ids: each named statement in the live set with its chain, and every
   * in-force revoke and endorse naming a statement in the answer, each with its chain; in authority
   * order, at most AUTHORITY_PAGE statements. What is not served is listed missing.
   * @returns {{ statements: object[], missing: string[] }}
   */
  answerIds(ids) {
    const { live, inForce } = this.resolve();
    const chosen = new Set();
    const missing = [];
    const withChain = (id) => [id, ...this._held.get(id).chain];
    for (const id of ids) {
      if (!live.has(id)) { missing.push(id); continue; }
      const add = new Set(withChain(id).filter((x) => !chosen.has(x)));
      // The in-force revokes and endorses naming anything in the answer so far, with their chains.
      for (const x of [...add, ...chosen]) {
        for (const e of this._namersOf(x)) if (inForce.has(e.id) && !chosen.has(e.id)) for (const y of withChain(e.id)) if (!chosen.has(y)) add.add(y);
      }
      if (chosen.size + add.size > A.AUTHORITY_PAGE) { missing.push(id); continue; }
      for (const x of add) chosen.add(x);
    }
    return { statements: this.authorityOrder(chosen).map((e) => e.s), missing };
  }

  /** @private The held revokes and endorses naming `id`. */
  _namersOf(id) {
    if (!this._namerIndex || this._namerIndexAt !== this._resolved) {
      const m = new Map();
      for (const e of this._held.values()) if (e.targets) for (const t of e.targets) { let l = m.get(t); if (!l) { l = []; m.set(t, l); } l.push(e); }
      this._namerIndex = m;
      this._namerIndexAt = this._resolved;
    }
    return this._namerIndex.get(id) || [];
  }

  /**
   * A page of the live set in authority order after `after` (an opaque cursor: '' for the start).
   * @returns {{ statements: object[], next: string|null }}
   */
  page(after) {
    const { live } = this.resolve();
    const all = this.authorityOrder(live);
    let i = 0;
    if (typeof after === 'string' && after) {
      while (i < all.length && this._orderKeyCompare(this._orderKey(all[i]), after) <= 0) i++;
    }
    const slice = all.slice(i, i + A.AUTHORITY_PAGE);
    const more = i + slice.length < all.length;
    return { statements: slice.map((e) => e.s), next: more && slice.length ? this._orderKey(slice[slice.length - 1]) : null };
  }

  /** @private Compare two order keys `${depth}.${group}.${id}`. */
  _orderKeyCompare(a, b) {
    const [da, ga, ia] = a.split('.'); const [db, gb, ib] = String(b).split('.');
    return (Number(da) - Number(db)) || (Number(ga) - Number(gb)) || (ia < ib ? -1 : ia > ib ? 1 : 0);
  }

  // ── Retention and persistence ─────────────────────────────────────────────────

  /** @private Drop non-live statements (dead, removed, over quota), highest id first, to make room. */
  _makeRoom() {
    const { live } = this.resolve();
    const droppable = [...this._held.keys()].filter((id) => !live.has(id)).sort().reverse();
    const n = Math.max(1, Math.ceil(this._maxHeld / 16));
    for (const id of droppable.slice(0, n)) this._held.delete(id);
    this._resolved = null;
    return this._held.size < this._maxHeld;
  }

  /** @private Append a held statement to the file (best effort; the file carries no authority). */
  _append(s) {
    if (!this._dir || this._loading || !this._pin) return;
    try { fs.mkdirSync(this._dir, { recursive: true }); fs.appendFileSync(path.join(this._dir, fileFor(this._pinDigest)), JSON.stringify(s) + '\n', { mode: 0o600 }); }
    catch { /* best effort */ }
  }

  /**
   * @private Read the file and verify every statement again, chain by chain, against the pinned
   * anchor: offered in passes until one holds nothing more, so file order does not matter. Nothing
   * read from disk is trusted for being there. Statements still pending stay on disk for the next
   * load; the file is then rewritten as the held and pending statements (no status or root is kept).
   */
  _load() {
    const file = path.join(this._dir, fileFor(this._pinDigest));
    let text = '';
    try { text = fs.readFileSync(file, 'utf8'); } catch { return; }
    let pending = [];
    for (const line of text.split('\n')) {
      if (!line) continue;
      try { pending.push(JSON.parse(line)); } catch { this._loadReport.invalid++; }
    }
    this._loading = true;
    const kept = [];
    try {
      for (let progress = true; progress && pending.length;) {
        progress = false;
        const next = [];
        for (const s of pending) {
          const r = this.ingest(s);
          if (r.result === 'held') { progress = true; kept.push(this._held.get(r.id).s); }
          else if (r.result === 'pending') next.push(s);
          else if (r.result !== 'duplicate') this._loadReport.invalid++;
        }
        pending = next;
      }
    } finally { this._loading = false; }
    this._loadReport.held = this._held.size;
    this._loadReport.pending = pending.length;
    try {
      const tmp = `${file}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, [...kept, ...pending].map((s) => JSON.stringify(s)).join('\n') + (kept.length + pending.length ? '\n' : ''), { mode: 0o600 });
      fs.renameSync(tmp, file);
    } catch { /* best effort */ }
  }
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
