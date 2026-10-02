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
 *   - Chains are verified TOP-DOWN with the key each verified grant vouches (§6.6: "using each
 *     verified grant's vouched key to reach the next"): a grant signed by grantor G is checked
 *     against the keys G's own rooted grants vouch for G, never against whatever key the registry
 *     holds for G. So a grantor whose id the registry binds to an impostor still has exactly the
 *     authority its vouched key has, and the impostor has none.
 *
 * AUTHORITY COUNTS ONLY IF THE SIGNER WAS AUTHORISED BOTH WHEN IT SIGNED AND WHEN THIS NODE
 * RECEIVED IT (security review C). One rule for a grant, a key vouch, a revoke and an attestation: a
 * signer revoked at t can still sign a statement dated before t (the date is its own to write), so
 * the signed time alone let a revoked validator backdate grants, key vouches and revokes into its
 * old window. Each record keeps the time this node received it (`receivedAt`, persisted with it),
 * and its signer's rank is taken at both times, the lower counting.
 *
 * A record is KEPT only when it is rooted at the anchor: its grantor held, both when it signed and
 * when it was received, the rank the record needs (a grant: the rank it confers; a revoke: validator
 * or above), under the key that signed it, by the chain this store already holds. An unrooted record
 * has no effect on any resolution, so it is not stored, not relayed, and costs nothing. Resolution
 * still re-checks every chain (role-at-time, revocation cascades, the rank at receipt). Reloading from
 * disk runs the same checks, each record at its persisted receipt time (the file has no integrity of
 * its own, so nothing is trusted for being on it; a receipt time is never before its signed time and
 * never after the load). A line written before 0.14 has no receipt time: it is treated as received
 * at load (draft spec PR meshcognition-website#33), and the file is rewritten with that time.
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
 * Bounds on what is kept, and so on what is relayed, since only a record kept is relayed: records
 * signed by one grantor, records one grantor signed for one grantee, and records in all. A full bound
 * refuses the newcomer and never evicts a record already kept, since a record's authority can depend
 * on its place in a chain. The anchor's own records are never refused. The pair bound is per grantor,
 * so one grantor filling it cannot keep another's grants to that grantee out; and it bounds what one
 * grantor adds to the grantee's role resolution, which every gating decision runs.
 */
const MAX_PER_GRANTOR = 1024;
// 16 per pair (64 until 0.14): a grant, a revoke and a re-grant, several times over, is all an
// honest grantor needs, and what one pair holds is replayed at every resolution of the grantee.
const MAX_PER_PAIR = 16;
const MAX_GRANTS = 65536;
/** A record dated further than this into the future (by this node's clock) is refused. */
const MAX_FUTURE_MS = 10 * 60 * 1000;
/** Field bounds (security review D): a nodeId, a role name. A key and a signature have fixed lengths. */
const MAX_ID = 128;
const MAX_ROLE = 32;
/** resolveRole's memo is cleared when it holds this many answers (and whenever a record is kept). */
const MEMO_MAX = 65536;
/**
 * Delegation depth (security review D, role-linear): a role reaches at most this many grants from the
 * anchor (the anchor's own grantee is at depth 1). MMP §6.6 sets no depth; 8 is sym's, proposed for
 * the spec, and the role-chain answer already stops there.
 */
const MAX_DELEGATION_DEPTH = 8;

class RoleGrantStore {
  /**
   * @param {object} [opts]
   * @param {{nodeId: string, publicKey: string}} [opts.anchor] the non-earnable root of trust.
   * @param {{get: function(string): (string|undefined), bind?: function, pin?: function}} [opts.keys]
   *   the node's key registry. Read only to resolve a subject's bound key for `resolver()` and the
   *   two-argument `resolveRole`; NEVER to verify a grant. A rooted grant's vouched key is pinned
   *   back into it.
   * @param {string} [opts.dir] when set, grants persist append-only and reload here.
   */
  constructor(opts = {}) {
    this._anchor = opts.anchor || null;
    this._selfId = typeof opts.selfId === 'string' && opts.selfId ? opts.selfId : null;
    this._selfKey = typeof opts.selfKey === 'string' && opts.selfKey ? opts.selfKey : null;
    // Told of a kept grant that names this node with a key that is not its own (draft spec PR #33:
    // inert, and reported, since someone vouched a foreign key for this node's identity).
    this._onForeignSelfGrant = typeof opts.onForeignSelfGrant === 'function' ? opts.onForeignSelfGrant : null;
    this._now = typeof opts.now === 'function' ? opts.now : Date.now;
    this._keys = opts.keys || new Map();
    this._receivedAt = new Map(); // sigKey -> when this node received the record (ms epoch)
    this._memo = new Map();       // `${nodeId}\0${key}\0${canonical at}` -> { role, depth } (cleared on every change)
    this._times = [];             // every record's grantedAt, sorted, distinct: resolution's breakpoints
    this._memoKeys = new Map();   // nodeId -> Set(memo keys of its answers), to forget one subtree
    this._grantees = new Map();   // grantor nodeId -> Set(grantee nodeIds it signed records for)
    this._byGrantee = new Map(); // grantee nodeId -> [grant/revoke records]
    this._vouched = new Map();   // nodeId -> Set(keys its rooted role-grants vouch)
    this._signer = new Map();    // sigKey -> the key that verified the record
    this._seen = new Set();      // sigKey dedup: the signature's bytes, however it is spelled
    this._perGrantor = new Map(); // grantor nodeId -> records kept
    this._perPair = new Map();    // grantor nodeId + NUL + grantee nodeId -> records kept
    this._maxPerGrantor = opts.maxPerGrantor || MAX_PER_GRANTOR;
    this._maxPerPair = opts.maxPerPair || MAX_PER_PAIR;
    this._maxGrants = opts.maxGrants || MAX_GRANTS;
    this._dir = opts.dir || null;
    this._loading = false;
    this._loadReport = { loaded: 0, skipped: {}, unreadable: null };
    if (this._dir) {
      try { fs.mkdirSync(this._dir, { recursive: true }); } catch { /* best effort */ }
      this._load();
    }
  }

  /**
   * What the last reload found: records `loaded`, records `skipped` by reason (each a record that
   * could not be verified — not JSON, malformed, unknown grantor key, bad signature, unrooted,
   * duplicate), and `unreadable` (why the file could not be read; null when it could, or none).
   * @returns {{ loaded: number, skipped: Object<string, number>, unreadable: string|null }}
   */
  loadReport() {
    return { loaded: this._loadReport.loaded, skipped: { ...this._loadReport.skipped }, unreadable: this._loadReport.unreadable };
  }

  /**
   * The keys a grant from `grantedBy` may be verified against: the anchor's configured key, or the
   * keys `grantedBy`'s own rooted grants vouch. Empty when no chain reaches it.
   * @returns {string[]}
   */
  grantorKeys(grantedBy) {
    if (this._anchor && grantedBy === this._anchor.nodeId) return [this._anchor.publicKey];
    return [...(this._vouched.get(grantedBy) || [])];
  }

  /** Whether any chain reaches `grantedBy` (a grant from it could verify). */
  grantorKey(grantedBy) { return this.grantorKeys(grantedBy)[0]; }

  /**
   * Record a signed role-grant / role-revoke, if it is rooted at the anchor. In order: the record
   * must be well-formed (a role-grant carries granteeKey), new (dedup by the signature's bytes), within
   * the bounds, from a grantor some chain reaches, ROOTED under one of the grantor's vouched keys, and
   * its signature must verify against that key. A record that fails any of these is refused with the
   * reason and leaves no trace: not held, not written, not relayed.
   *
   * What is stored, persisted and returned (`grant`, for the caller to relay) is ONE canonical
   * object holding only the fields the signature covers, the signature in its signer's spelling and
   * `sigAlg` (0.13.17 re-review A5): an unsigned field a frame carried is never kept, written or
   * passed on. Never throws: a record whose checks fail in a way no reason names is 'unverifiable'.
   * @returns {{ stored: boolean, reason?: string, grant?: object }}
   */
  record(grant, opts = {}) {
    try {
      return this._record(grant, opts);
    } catch {
      return { stored: false, reason: 'unverifiable' };
    }
  }

  /** @private */
  _record(grant, { receivedAt } = {}) {
    if (malformed(grant)) return { stored: false, reason: 'malformed' };
    const sk = sigKey(grant.sig);
    if (this._seen.has(sk)) return { stored: false, reason: 'duplicate' };
    const now = this._now();
    // The time this node received it: now, or (reloading) the persisted time, never before the signed
    // time and never after now.
    receivedAt = Number.isFinite(receivedAt) ? Math.min(Math.max(receivedAt, grant.grantedAt), now) : now;
    if (grant.grantedAt > receivedAt + MAX_FUTURE_MS) return { stored: false, reason: 'future-dated' };
    const fromAnchor = !!this._anchor && grant.grantedBy === this._anchor.nodeId;
    const pair = `${grant.grantedBy}\u0000${grant.grantee}`;
    if (!fromAnchor) {
      if ((this._perGrantor.get(grant.grantedBy) || 0) >= this._maxPerGrantor) return { stored: false, reason: 'grantor-full' };
      if ((this._perPair.get(pair) || 0) >= this._maxPerPair) return { stored: false, reason: 'pair-full' };
      if (this._seen.size >= this._maxGrants) return { stored: false, reason: 'store-full' };
    }
    const candidates = this.grantorKeys(grant.grantedBy);
    if (candidates.length === 0) return { stored: false, reason: 'unknown-grantor-key' };
    // Rooted first (no signature work for a record no key could root), then the signature.
    const rooted = candidates.filter((k) => this._rooted(grant, k, receivedAt));
    if (rooted.length === 0) return { stored: false, reason: 'unrooted' };
    const signer = rooted.find((k) => verifyGrant(grant, k).valid);
    if (!signer) return { stored: false, reason: 'bad-signature' };
    // Kept as its signed fields only, with the signature in its canonical spelling, the one its signer
    // wrote: a re-spelling verifies too, but the spelling is what relay-once and every other node's
    // dedup see.
    grant = canonicalGrant(grant, sk);
    this._seen.add(sk);
    this._signer.set(sk, signer);
    this._receivedAt.set(sk, receivedAt);
    this._addTime(grant.grantedAt);
    let gs = this._grantees.get(grant.grantedBy);
    if (!gs) { gs = new Set(); this._grantees.set(grant.grantedBy, gs); }
    gs.add(grant.grantee);
    this._forgetSubtree(grant.grantee);
    this._perGrantor.set(grant.grantedBy, (this._perGrantor.get(grant.grantedBy) || 0) + 1);
    this._perPair.set(pair, (this._perPair.get(pair) || 0) + 1);
    let arr = this._byGrantee.get(grant.grantee);
    if (!arr) { arr = []; this._byGrantee.set(grant.grantee, arr); }
    arr.push(grant);
    if (grant.type === 'role-grant') {
      let v = this._vouched.get(grant.grantee);
      if (!v) { v = new Set(); this._vouched.set(grant.grantee, v); }
      v.add(grant.granteeKey);
    }
    this._append(grant, receivedAt);
    this._noteVouch(grant);
    if (grant.type === 'role-grant' && this._selfId && grant.grantee === this._selfId && this._selfKey && grant.granteeKey !== this._selfKey) {
      // Stored (it is a rooted statement, and relayed like one) but inert: this node resolves its own
      // role under its own key, and no grant binds its own nodeId.
      if (this._onForeignSelfGrant && !this._loading) { try { this._onForeignSelfGrant(grant); } catch { /* a report must not fail the store */ } }
      return { stored: true, grant, inert: 'foreign-key-for-self' };
    }
    return { stored: true, grant };
  }

  /** When this node received the record with this signature, or undefined. */
  receivedAt(sig) { return this._receivedAt.get(sigKey(sig)); }

  /**
   * Whether a record is rooted at the anchor under `signerKey`: its grantor, holding that key, held
   * the authority the record needs (a grant: the rank it confers; a revoke: validator or above) both
   * when it signed and when it was received (security review C). (A grant from a grantor revoked
   * SINCE it was received is rooted and kept; resolution gives it no effect while the grantor is
   * revoked.)
   * @private
   */
  _rooted(grant, signerKey, receivedAt) {
    const then = this._authority(grant.grantedBy, signerKey, grant.grantedAt);
    const atReceipt = this._authority(grant.grantedBy, signerKey, receivedAt);
    const rank = Math.min(then, atReceipt);
    return grant.type === 'role-revoke' ? rank >= 1 : rank >= roleRank(grant.role);
  }

  /**
   * A rooted grant names the grantee's key. The registry reads key vouches as a view
   * (`vouchedKey`), so nothing is pinned; the registry is told, so that a different key it already
   * binds is recorded as a conflict and the same key is marked vouched. Never for this node's own id.
   * A plain Map (tests, older hosts) is only filled where it holds nothing.
   * @private
   */
  _noteVouch(grant) {
    if (grant.type !== 'role-grant' || (this._selfId && grant.grantee === this._selfId)) return;
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
    const keys = this._vouched.get(nodeId);
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
   * Resolve the role `nodeId`, holding `key`, held at time `at` (ms epoch). Authority only flows from
   * the anchor:
   *   - the anchor itself, holding its configured key, is `anchor`;
   *   - otherwise, replay `nodeId`'s grants/revokes in chronological order up to `at`: a grant counts
   *     only if its granteeKey is `key`, and confers its role iff its grantor — holding the key that
   *     signed the grant — outranked-or-equalled it both when it granted and now; a revoke clears to
   *     `participant` iff the revoker outranked-or-equalled the current role when it revoked.
   *   - cycles and unrooted chains resolve to `participant` (rank 0).
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
    if (this._memo.size >= MEMO_MAX) { this._memo.clear(); this._memoKeys.clear(); }
    return this._resolve(nodeId, key, at, new Set()).role;
  }

  /**
   * @private A record for `nodeId` was kept: the answers for it, and for every node a chain through it
   * reaches, are forgotten; every other answer still holds (a node no chain through `nodeId` reaches
   * resolves alike on both sides of the new record's time).
   */
  _forgetSubtree(nodeId) {
    const queue = [nodeId];
    const done = new Set();
    for (let i = 0; i < queue.length; i++) {
      const id = queue[i];
      if (done.has(id)) continue;
      done.add(id);
      const keys = this._memoKeys.get(id);
      if (keys) { for (const k of keys) this._memo.delete(k); this._memoKeys.delete(id); }
      const next = this._grantees.get(id);
      if (next) for (const g of next) if (!done.has(g)) queue.push(g);
    }
  }

  /**
   * @private The rank `nodeId` holding `key` can confer at `at`: its role's rank, or 0 when its role
   * already sits at the delegation depth (it can grant nothing further).
   */
  _authority(nodeId, key, at) {
    if (this._memo.size >= MEMO_MAX) { this._memo.clear(); this._memoKeys.clear(); }
    const r = this._resolve(nodeId, key, at, new Set());
    return r.depth >= MAX_DELEGATION_DEPTH ? 0 : roleRank(r.role);
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
   * when none). A role changes only where some record's signed time is crossed (the replay takes the
   * records signed at or before the time asked, and asks its grantors at that time or at fixed record
   * times), so every time between two breakpoints resolves alike, and the memo holds at most one
   * answer per (node, key, breakpoint): linear in the records, whatever times are asked.
   */
  _canonicalTime(t) {
    const a = this._times;
    let lo = 0, hi = a.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (a[mid] <= t) lo = mid + 1; else hi = mid; }
    return lo === 0 ? -Infinity : a[lo - 1];
  }

  /**
   * The resolution, memoised (security review D, role-resolve-cost): each record recurses into its
   * grantor at three times (signed, received, `at`), which without a memo cost (3r)^depth. An answer
   * is kept only when no cycle was cut while computing it (a cut answer depends on the path), and the
   * memo is cleared whenever a record is kept. @returns {{ role: string, pure: boolean }}
   * @private
   */
  _resolve(nodeId, key, at, seen) {
    if (this._anchor && nodeId === this._anchor.nodeId) return { role: key === this._anchor.publicKey ? 'anchor' : 'participant', depth: 0, pure: true };
    if (typeof key !== 'string' || !key) return { role: 'participant', depth: 0, pure: true };
    const self = `${nodeId}\u0000${key}`;
    if (seen.has(self)) return { role: 'participant', depth: 0, pure: false }; // cycle — not anchor-rooted
    at = this._canonicalTime(at);
    const memoKey = `${self}\u0000${at}`;
    const hit = this._memo.get(memoKey);
    if (hit !== undefined) return { role: hit.role, depth: hit.depth, pure: true };
    seen.add(self);
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
    const records = (this._byGrantee.get(nodeId) || [])
      .filter(g => (g.grantedAt ?? 0) <= at)
      .sort((a, b) => (a.grantedAt ?? 0) - (b.grantedAt ?? 0)); // chronological
    let role = 'participant';
    let depth = 0;
    for (const g of records) {
      // A grant confers only if the grantor was authorised WHEN it granted (so a grant signed before
      // the grantor held rank never activates), WHEN THIS NODE RECEIVED IT (so a grantor revoked by
      // then cannot backdate a fresh grant into its old window: security review C) AND NOW (so
      // revoking or demoting a grantor cascades to everything it granted). A revoke takes effect on
      // the revoker's rank when it revoked and when it was received, the lower, and is not undone by
      // the revoker's later demotion.
      if (g.type === 'role-grant' && g.granteeKey !== key) continue;
      const signer = this._signer.get(g.sig);
      const signedAt = g.grantedAt ?? 0;
      const recvAt = this._receivedAt.get(g.sig) ?? signedAt;
      depthOf = 0;
      const authority = Math.min(rank(g.grantedBy, signer, signedAt), rank(g.grantedBy, signer, recvAt));
      if (g.type === 'role-revoke') {
        if (authority >= 1 && authority >= roleRank(role)) { role = 'participant'; depth = 0; }
      } else {
        const rankNow = rank(g.grantedBy, signer, at);
        if (Math.min(authority, rankNow) >= roleRank(g.role)) { role = g.role; depth = depthOf + 1; }
      }
    }
    seen.delete(self);
    if (role === 'participant') depth = 0;
    if (pure) {
      this._memo.set(memoKey, { role, depth });
      let ks = this._memoKeys.get(nodeId);
      if (!ks) { ks = new Set(); this._memoKeys.set(nodeId, ks); }
      ks.add(memoKey);
    }
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
    return (this._byGrantee.get(grantee) || []).slice().sort((a, b) => (a.grantedAt ?? 0) - (b.grantedAt ?? 0));
  }

  /**
   * Every record held, in an order that roots each before it is needed (security review D,
   * anti-entropy): the anchor's records first, then those of each grantor the earlier ones reach,
   * breadth first, each grantor's own records by signed time; what no chain reaches comes last.
   * Cached until the next record is kept.
   * @returns {object[]}
   */
  syncOrder() {
    if (this._syncOrder && this._syncOrderAt === this._seen.size) return this._syncOrder;
    const byGrantor = new Map();
    for (const arr of this._byGrantee.values()) for (const g of arr) {
      let l = byGrantor.get(g.grantedBy);
      if (!l) { l = []; byGrantor.set(g.grantedBy, l); }
      l.push(g);
    }
    const out = [];
    const done = new Set();
    const queue = this._anchor ? [this._anchor.nodeId] : [];
    for (let i = 0; i < queue.length; i++) {
      const grantor = queue[i];
      if (done.has(grantor)) continue;
      done.add(grantor);
      const l = (byGrantor.get(grantor) || []).sort((a, b) => (a.grantedAt ?? 0) - (b.grantedAt ?? 0));
      for (const g of l) { out.push(g); if (g.type === 'role-grant' && !done.has(g.grantee)) queue.push(g.grantee); }
    }
    for (const [grantor, l] of byGrantor) if (!done.has(grantor)) out.push(...l);
    this._syncOrder = out;
    this._syncOrderAt = this._seen.size;
    return out;
  }

  /**
   * A digest of every record held (security review D, anti-entropy): sha256 over the sorted
   * signatures' canonical spellings. Two stores holding the same records give the same digest.
   * @returns {{ count: number, digest: string }}
   */
  digest() {
    if (this._digest && this._digestAt === this._seen.size) return this._digest;
    const h = crypto.createHash('sha256');
    for (const sk of [...this._seen].sort()) h.update(sk).update('\n');
    this._digest = { count: this._seen.size, digest: h.digest('hex') };
    this._digestAt = this._seen.size;
    return this._digest;
  }

  /** Whether a grant with this signature is held, however the signature is spelled. */
  has(sig) { return this._seen.has(sigKey(sig)); }
  size() { return this._seen.size; }

  // ── Durable persistence (append-only) ────────────────────────────────────────

  /** One line per record: `{ grant, receivedAt }` (a pre-0.14 line is the bare record). */
  _append(grant, receivedAt) {
    if (!this._dir || this._loading) return;
    try { fs.appendFileSync(path.join(this._dir, GRANTS_FILE), JSON.stringify({ grant, receivedAt }) + '\n'); }
    catch { /* best effort — never let persistence break authority */ }
  }

  /**
   * Reload the grant file through `record` — the same checks a frame gets. A rooted record can only
   * be rooted by records before it in time, not necessarily before it in the file, so records refused
   * for a reason a later record can cure (`unknown-grantor-key`: the grantor's own grant, vouching its
   * key, arrives later; `unrooted`: likewise) are retried until a pass adds nothing. What is left is
   * skipped and counted, as is a record whose check fails in a way no reason names ('unverifiable').
   * Never throws: a file that cannot be read leaves the store with no grants and
   * `loadReport().unreadable` saying why.
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
      let bare = 0;
      for (const line of text.split('\n')) {
        if (!line.trim()) continue;
        let o;
        try { o = JSON.parse(line); } catch { skip('not-json'); continue; }
        // `{ grant, receivedAt }`, or a bare record written before 0.14: no receipt time, so it is
        // treated as received at load (draft spec PR #33).
        if (o && typeof o === 'object' && o.grant && typeof o.grant === 'object') pending.push({ g: o.grant, receivedAt: o.receivedAt });
        else { pending.push({ g: o, receivedAt: undefined }); bare++; }
      }
      this._bareLines = bare;
      const curable = new Set(['unknown-grantor-key', 'unrooted', 'bad-signature']);
      let reasons = [];
      let progress = true;
      while (progress && pending.length) {
        progress = false;
        const retry = [];
        reasons = [];
        for (const e of pending) {
          let r;
          try { r = this.record(e.g, { receivedAt: e.receivedAt }); } catch { r = { stored: false, reason: 'unverifiable' }; }
          if (r.stored) { report.loaded++; progress = true; }
          else if (curable.has(r.reason)) { retry.push(e); reasons.push(r.reason); }
          else skip(r.reason);
        }
        pending = retry;
      }
      for (const reason of reasons) skip(reason);
    } finally {
      this._loading = false;
    }
    // A file holding pre-0.14 lines is rewritten once, atomically, in the 0.14 form.
    if (this._bareLines > 0) this._rewrite();
  }

  /** @private Rewrite the file as one `{ grant, receivedAt }` line per record kept, atomically. */
  _rewrite() {
    const file = path.join(this._dir, GRANTS_FILE);
    const lines = [];
    for (const arr of this._byGrantee.values()) for (const g of arr) lines.push(JSON.stringify({ grant: g, receivedAt: this._receivedAt.get(g.sig) }));
    try {
      const tmp = `${file}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, lines.join('\n') + (lines.length ? '\n' : ''));
      fs.renameSync(tmp, file);
    } catch { /* best effort: read again the same way at the next start */ }
  }
}

/**
 * A record as its signed fields only (grantPayload: type, grantee, role, grantedBy, grantedAt,
 * granteeKey), with `sig` and `sigAlg`. `role` and `granteeKey` are kept when they are non-empty
 * (the payload signs an absent one and an empty one alike).
 */
function canonicalGrant(g, sig) {
  const c = { type: g.type, grantee: g.grantee };
  if (typeof g.role === 'string' && g.role) c.role = g.role;
  c.grantedBy = g.grantedBy;
  c.grantedAt = g.grantedAt;
  if (typeof g.granteeKey === 'string' && g.granteeKey) c.granteeKey = g.granteeKey;
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
  if (g.granteeKey !== undefined && typeof g.granteeKey !== 'string') return true;
  if (g.role !== undefined && (typeof g.role !== 'string' || g.role.length > MAX_ROLE)) return true;
  if (g.type === 'role-revoke') return false;
  // A grant confers a rank above participant, on the holder of one key, or it confers nothing.
  return roleRank(g.role) < 1 || typeof g.granteeKey !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(g.granteeKey);
}

module.exports = { RoleGrantStore, canonicalGrant, malformedGrant: malformed, MAX_DELEGATION_DEPTH };
