'use strict';

/**
 * @module @sym-bot/sym/role-grant-store
 * @description Earned-authority role-grant chain (MMP §6.5).
 *
 * A node's lifecycle authority (participant → validator → anchor) is EARNED via
 * signed grants, never self-asserted. This store holds the signed role-grant /
 * role-revoke records and resolves "what role did node N hold at time T" by walking
 * the grant chain — but authority only flows along chains that **terminate at the
 * non-earnable anchor** (typically the founder). A grant whose chain does not root
 * at the anchor confers NOTHING (Douceur: there is no unconditional decentralized
 * Sybil-resistance — authority must bottom out at a pinned root). This is what makes
 * the attestation `role` un-spoofable: `verifyAttestationRole` resolves against this
 * chain, never the stamped category.
 *
 * A record is KEPT only when it is rooted at the anchor: its grantor held, at the time it
 * signed, the rank the record needs (a grant: the rank it confers; a revoke: validator or
 * above), by the chain this store already holds. An unrooted record has no effect on any
 * resolution, so it is not stored, not relayed, and costs nothing — before 0.13.17 it was
 * stored and relayed, so any connected peer could write records here by signing them
 * itself. Resolution still re-checks every chain (role-at-time, revocation cascades).
 *
 * Grantor keys are resolved through ONE interface, the key registry's own lookup (the
 * node's roster), on ingest and on reload alike. Persisted append-only; reloaded on
 * construction through the same checks as a frame, so a record on disk that cannot be
 * verified is skipped and counted, and a file that cannot be read leaves the store empty
 * (`loadReport()` says which) — reading the store never throws.
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
   * @param {{nodeId: string, publicKey: string}} [opts.anchor] the non-earnable root
   *   of trust (founder). resolveRole confers authority only along chains rooting here.
   * @param {{get: function(string): (string|undefined)}} [opts.keys] the key registry grant
   *   signatures are verified against — the node's RosterKeyRegistry, or any Map-like with
   *   `get`. Only ever LOOKED UP through `get` (never copied or iterated); a rooted grant's
   *   vouched grantee key is pinned back into it (`pin`, or `set` when absent on a Map).
   * @param {string} [opts.dir] when set, grants persist append-only and reload here.
   */
  constructor(opts = {}) {
    this._anchor = opts.anchor || null;
    this._keys = opts.keys || new Map();
    this._byGrantee = new Map(); // grantee nodeId -> [grant/revoke records]
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
   * What the last reload found: records `loaded`, records `skipped` by reason (each a record
   * that could not be verified — not JSON, malformed, unknown grantor key, bad signature,
   * unrooted, duplicate), and `unreadable` (why the file could not be read; null when it
   * could, or when there was none).
   * @returns {{ loaded: number, skipped: Object<string, number>, unreadable: string|null }}
   */
  loadReport() {
    return { loaded: this._loadReport.loaded, skipped: { ...this._loadReport.skipped }, unreadable: this._loadReport.unreadable };
  }

  /** Learn/pin an identity key for verifying a node's grants. */
  setKey(nodeId, pubKeyB64url) {
    if (nodeId && pubKeyB64url) this._keys.set(nodeId, pubKeyB64url);
  }

  _grantorKey(grantedBy) {
    if (this._anchor && grantedBy === this._anchor.nodeId) return this._anchor.publicKey;
    return this._keys.get(grantedBy);
  }

  /** The key a grant from `grantedBy` is verified against, or undefined: no verification is possible. */
  grantorKey(grantedBy) { return this._grantorKey(grantedBy); }

  /**
   * Record a signed role-grant / role-revoke, if it is rooted at the anchor. In order: the
   * record must be well-formed, new (dedup by the signature's bytes, so a re-spelling of a held
   * signature is a duplicate), within the bounds (see MAX_PER_GRANTOR), from a grantor whose key
   * the registry resolves, ROOTED (see `_rooted`), and its signature must verify against that key. A
   * record that fails any of these is refused with the reason and leaves no trace: it is
   * not held, not written, and the caller does not relay it. Reloading from disk runs the
   * same checks — the file has no integrity of its own, so nothing is trusted for being on it.
   * @returns {{ stored: boolean, reason?: string }}
   */
  record(grant) {
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
    const key = this._grantorKey(grant.grantedBy);
    if (!key) return { stored: false, reason: 'unknown-grantor-key' };
    if (!this._rooted(grant)) return { stored: false, reason: 'unrooted' };
    if (!verifyGrant(grant, key).valid) return { stored: false, reason: 'bad-signature' };
    // Kept in its canonical spelling, the one its signer wrote: a re-spelling verifies too, but the
    // spelling is what relay-once and every other node's dedup see.
    if (sk !== grant.sig) grant = { ...grant, sig: sk };
    this._seen.add(sk);
    this._perGrantor.set(grant.grantedBy, (this._perGrantor.get(grant.grantedBy) || 0) + 1);
    this._perPair.set(pair, (this._perPair.get(pair) || 0) + 1);
    let arr = this._byGrantee.get(grant.grantee);
    if (!arr) { arr = []; this._byGrantee.set(grant.grantee, arr); }
    arr.push(grant);
    this._append(grant);
    this._pinGranteeKey(grant);
    return { stored: true };
  }

  /**
   * Whether a record is rooted at the anchor: its grantor's role AT THE TIME IT SIGNED,
   * resolved from the chain this store holds, carries the authority the record needs. A
   * grant needs the rank it confers (validators grant validator; only anchors grant
   * anchor); a revoke needs validator or above. Anything else could never change a
   * resolution, which is why it is not kept. (A grant from a grantor revoked SINCE it
   * signed is rooted and kept; resolution still gives it no effect while the grantor is
   * revoked — see resolveRole.)
   * @private
   */
  _rooted(grant) {
    const rank = roleRank(this.resolveRole(grant.grantedBy, grant.grantedAt));
    return grant.type === 'role-revoke' ? rank >= 1 : rank >= roleRank(grant.role);
  }

  /**
   * A rooted grant may VOUCH for the grantee's nodeId↔key binding (granteeKey, bound into the
   * signed payload): pin it into the key registry, so a node that never met the grantee can
   * verify what it signs. Only rooted grants are kept, so a node whose authority we do not
   * trust cannot poison the registry. The roster refuses to overwrite a stronger
   * (handshake/anchor) binding with this grant-sourced one; a plain Map is only filled where
   * it holds nothing.
   * @private
   */
  _pinGranteeKey(grant) {
    if (grant.type !== 'role-grant' || typeof grant.granteeKey !== 'string' || !grant.granteeKey) return;
    if (typeof this._keys.pin === 'function') this._keys.pin(grant.grantee, grant.granteeKey, 'grant');
    else if (typeof this._keys.set === 'function' && !this._keys.get(grant.grantee)) this._keys.set(grant.grantee, grant.granteeKey);
  }

  /**
   * Resolve the role `nodeId` held at time `at` (ms epoch). Authority only flows from
   * the anchor:
   *   - the anchor itself is `anchor`;
   *   - otherwise, replay `nodeId`'s grants/revokes in chronological order up to `at`:
   *     a grant confers its role iff the GRANTOR's role AT GRANT TIME outranks-or-
   *     equals it; a revoke clears to `participant` iff the revoker outranks-or-equals
   *     the current role. Grantor authority is resolved recursively and must itself
   *     root at the anchor — a chain that doesn't confers nothing.
   *   - cycles and unrooted chains resolve to `participant` (rank 0).
   * @param {string} nodeId
   * @param {number} at - ms epoch
   * @returns {'participant'|'validator'|'anchor'}
   */
  resolveRole(nodeId, at, _seen = new Set()) {
    if (this._anchor && nodeId === this._anchor.nodeId) return 'anchor';
    if (_seen.has(nodeId)) return 'participant'; // cycle — not anchor-rooted
    const nextSeen = new Set([..._seen, nodeId]);
    const records = (this._byGrantee.get(nodeId) || [])
      .filter(g => (g.grantedAt ?? 0) <= at)
      .sort((a, b) => (a.grantedAt ?? 0) - (b.grantedAt ?? 0)); // chronological
    let role = 'participant';
    for (const g of records) {
      // A grant confers only if the grantor was authorised WHEN it granted (so a
      // grant signed before the grantor held rank never activates) AND is still
      // authorised NOW (so revoking/demoting a grantor cascades to everything it
      // granted, and a since-revoked grantor cannot backdate a fresh grant to before
      // its own revoke to resurrect authority). A revoke is sticky: it takes effect
      // on the revoker's rank AT REVOKE TIME and is not undone by the revoker's later
      // demotion — you do not un-revoke because the revoker was later removed.
      const rankThen = roleRank(this.resolveRole(g.grantedBy, g.grantedAt ?? 0, nextSeen));
      if (g.type === 'role-revoke') {
        if (rankThen >= roleRank(role)) role = 'participant';
      } else {
        const rankNow = roleRank(this.resolveRole(g.grantedBy, at, nextSeen));
        if (Math.min(rankThen, rankNow) >= roleRank(g.role)) role = g.role;
      }
    }
    return role;
  }

  /** A resolver bound to this store, for `verifyAttestationRole(att, resolver)`. */
  resolver() {
    return (nodeId, at) => this.resolveRole(nodeId, at ?? Date.now());
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
   * Reload the grant file through `record` — the same checks a frame gets. A rooted record
   * can only be rooted by records before it in time, not necessarily before it in the file
   * (0.13.16 kept unrooted records, some of which an anchor grant later rooted), so records
   * refused for a reason a later record can cure (`unknown-grantor-key`: the key arrives
   * vouched in a grant; `unrooted`: the grantor's own grant arrives) are retried until a
   * pass adds nothing. What is left is skipped and counted, as is a record whose check
   * fails in a way no reason names ('unverifiable'). Never throws: a file that cannot be
   * read leaves the store with no grants and `loadReport().unreadable` saying why.
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
      const curable = new Set(['unknown-grantor-key', 'unrooted']);
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

/** The fields a record must have, of the types it must have them, or it is not a record. */
function malformed(g) {
  if (!g || typeof g !== 'object' || Array.isArray(g)) return true;
  if (g.type !== 'role-grant' && g.type !== 'role-revoke') return true;
  for (const f of ['grantee', 'grantedBy', 'sig']) if (typeof g[f] !== 'string' || !g[f]) return true;
  if (!Number.isFinite(g.grantedAt)) return true;
  if (g.granteeKey !== undefined && typeof g.granteeKey !== 'string') return true;
  // A grant confers a rank above participant, or it confers nothing.
  return g.type === 'role-grant' && roleRank(g.role) < 1;
}

module.exports = { RoleGrantStore };
