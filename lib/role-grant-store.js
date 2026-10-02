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
 * A record is KEPT only when it is rooted at the anchor: its grantor held, at the time it signed, the
 * rank the record needs (a grant: the rank it confers; a revoke: validator or above), under the key
 * that signed it, by the chain this store already holds (0.13.17). An unrooted record has no effect
 * on any resolution, so it is not stored, not relayed, and costs nothing. Resolution still re-checks
 * every chain (role-at-time, revocation cascades). Reloading from disk runs the same checks — the file
 * has no integrity of its own, so nothing is trusted for being on it (0.13.17's record() path).
 *
 * A rooted grant's vouched key is pinned into the key registry at `grant` strength, by the registry's
 * conflict matrix (a different key already bound is a conflict, never an override).
 *
 * @copyright 2026 SYM.BOT. Apache 2.0 License.
 */

const fs = require('fs');
const path = require('path');
const { verifyGrant, roleRank } = require('./core');
const { sigKey } = require('./attestation-store');

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
const MAX_PER_PAIR = 64;
const MAX_GRANTS = 65536;

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
    this._keys = opts.keys || new Map();
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
    if (this._seen.has(sk)) return { stored: false, reason: 'duplicate' };
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
    const rooted = candidates.filter((k) => this._rooted(grant, k));
    if (rooted.length === 0) return { stored: false, reason: 'unrooted' };
    const signer = rooted.find((k) => verifyGrant(grant, k).valid);
    if (!signer) return { stored: false, reason: 'bad-signature' };
    // Kept as its signed fields only, with the signature in its canonical spelling, the one its signer
    // wrote: a re-spelling verifies too, but the spelling is what relay-once and every other node's
    // dedup see.
    grant = canonicalGrant(grant, sk);
    this._seen.add(sk);
    this._signer.set(sk, signer);
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
    this._append(grant);
    this._pinGranteeKey(grant);
    return { stored: true, grant };
  }

  /**
   * Whether a record is rooted at the anchor under `signerKey`: its grantor, holding that key, held
   * at the time it signed the authority the record needs (a grant: the rank it confers; a revoke:
   * validator or above). (A grant from a grantor revoked SINCE it signed is rooted and kept;
   * resolution still gives it no effect while the grantor is revoked.)
   * @private
   */
  _rooted(grant, signerKey) {
    const rank = roleRank(this.resolveRole(grant.grantedBy, signerKey, grant.grantedAt));
    return grant.type === 'role-revoke' ? rank >= 1 : rank >= roleRank(grant.role);
  }

  /**
   * A rooted grant VOUCHES for the grantee's nodeId↔key binding: pin it into the key registry at
   * `grant` strength, through the registry's conflict matrix (a different key already bound is a
   * conflict, never an override). A plain Map is only filled where it holds nothing.
   * @private
   */
  _pinGranteeKey(grant) {
    if (grant.type !== 'role-grant') return;
    if (typeof this._keys.bind === 'function') this._keys.bind(grant.grantee, grant.granteeKey, 'grant');
    else if (typeof this._keys.pin === 'function') this._keys.pin(grant.grantee, grant.granteeKey, 'grant');
    else if (typeof this._keys.set === 'function' && !this._keys.get(grant.grantee)) this._keys.set(grant.grantee, grant.granteeKey);
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
  resolveRole(nodeId, key, at, _seen) {
    if (typeof key === 'number' && at === undefined) { at = key; key = this._boundKey(nodeId); }
    if (at === undefined) at = Date.now();
    if (this._anchor && nodeId === this._anchor.nodeId) return key === this._anchor.publicKey ? 'anchor' : 'participant';
    if (typeof key !== 'string' || !key) return 'participant';
    const seen = _seen || new Set();
    const self = `${nodeId}\u0000${key}`;
    if (seen.has(self)) return 'participant'; // cycle — not anchor-rooted
    const nextSeen = new Set([...seen, self]);
    const records = (this._byGrantee.get(nodeId) || [])
      .filter(g => (g.grantedAt ?? 0) <= at)
      .sort((a, b) => (a.grantedAt ?? 0) - (b.grantedAt ?? 0)); // chronological
    let role = 'participant';
    for (const g of records) {
      // A grant confers only if the grantor was authorised WHEN it granted (so a grant signed before
      // the grantor held rank never activates) AND is still authorised NOW (so revoking/demoting a
      // grantor cascades to everything it granted, and a since-revoked grantor cannot backdate a fresh
      // grant to before its own revoke to resurrect authority). A revoke is sticky: it takes effect on
      // the revoker's rank AT REVOKE TIME and is not undone by the revoker's later demotion.
      if (g.type === 'role-grant' && g.granteeKey !== key) continue;
      const signer = this._signer.get(g.sig);
      const rankThen = roleRank(this.resolveRole(g.grantedBy, signer, g.grantedAt ?? 0, nextSeen));
      if (g.type === 'role-revoke') {
        if (rankThen >= roleRank(role)) role = 'participant';
      } else {
        const rankNow = roleRank(this.resolveRole(g.grantedBy, signer, at, nextSeen));
        if (Math.min(rankThen, rankNow) >= roleRank(g.role)) role = g.role;
      }
    }
    return role;
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

  /** Whether a grant with this signature is held, however the signature is spelled. */
  has(sig) { return this._seen.has(sigKey(sig)); }
  size() { return this._seen.size; }

  // ── Durable persistence (append-only) ────────────────────────────────────────

  _append(grant) {
    if (!this._dir || this._loading) return;
    try { fs.appendFileSync(path.join(this._dir, GRANTS_FILE), JSON.stringify(grant) + '\n'); }
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
      for (const line of text.split('\n')) {
        if (!line.trim()) continue;
        try { pending.push(JSON.parse(line)); } catch { skip('not-json'); }
      }
      const curable = new Set(['unknown-grantor-key', 'unrooted', 'bad-signature']);
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
    } finally {
      this._loading = false;
    }
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
  for (const f of ['grantee', 'grantedBy', 'sig']) if (typeof g[f] !== 'string' || !g[f]) return true;
  if (!Number.isFinite(g.grantedAt)) return true;
  if (g.granteeKey !== undefined && typeof g.granteeKey !== 'string') return true;
  if (g.role !== undefined && typeof g.role !== 'string') return true;
  if (g.type === 'role-revoke') return false;
  // A grant confers a rank above participant, on the holder of one key, or it confers nothing.
  return roleRank(g.role) < 1 || typeof g.granteeKey !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(g.granteeKey);
}

module.exports = { RoleGrantStore, canonicalGrant };
