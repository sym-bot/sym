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
 * resolution, so it is not stored, not relayed, and costs no signature check — before
 * 0.13.17 it was stored and relayed, so any connected peer could write records here by
 * signing them itself. Resolution still re-checks every chain (role-at-time, revocation
 * cascades).
 *
 * Rooted is a property of the chain, not of arrival order: gossip can bring a grant (or a
 * revoke) before the grant that roots its grantor, and there is no grant sync to ask for it
 * again. So a record refused for a reason a later record can cure — `unknown-grantor-key`
 * (the grantor's key arrives vouched in its own grant) or `unrooted` (the grantor's grant
 * arrives) — is HELD in memory, in a bounded pending set (`maxPending`, 1024 by default, the
 * oldest dropped first). It is never written and never relayed while it waits, and has no
 * effect on any resolution. Whenever a record is stored, the pending set is retried by the
 * same fixpoint the reload uses (offer each until a pass stores none); one that is now
 * rooted is stored, persisted and returned to the caller to relay like any other. The
 * pending set is not persisted: what waits when the node stops is gone, as a refused record
 * was before.
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

const GRANTS_FILE = 'role-grants.jsonl';
/** Refusals a later record can cure: the grantor's key, or the grant rooting the grantor, has not arrived. */
const CURABLE = new Set(['unknown-grantor-key', 'unrooted']);
const MAX_PENDING = 1024;

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
   * @param {number} [opts.maxPending=1024] how many refused-but-curable records are held in
   *   memory waiting for their root (the oldest is dropped first).
   */
  constructor(opts = {}) {
    this._anchor = opts.anchor || null;
    this._keys = opts.keys || new Map();
    this._byGrantee = new Map(); // grantee nodeId -> [grant/revoke records]
    this._seen = new Set();      // sig dedup
    this._pending = new Map();   // pendingKey -> { grant, persisted, reason }: curable refusals, in arrival order
    this._maxPending = Number.isInteger(opts.maxPending) && opts.maxPending >= 0 ? opts.maxPending : MAX_PENDING;
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

  /**
   * Record a signed role-grant / role-revoke, if it is rooted at the anchor. In order: the
   * record must be well-formed, new (dedup by sig), from a grantor whose key the registry
   * resolves, ROOTED (see `_rooted`), and its signature must verify against that key. A
   * record that fails any of these is refused with the reason: it is not stored, not written,
   * and the caller does not relay it. One refused for a curable reason (`unknown-grantor-key`,
   * `unrooted`) is held in the pending set until a later record roots it (see the module doc).
   *
   * A record that is stored is followed by a retry of the pending set: the records it rooted
   * (directly, or through one another) are stored and persisted too, and returned as
   * `released`, in the order they were stored, for the caller to relay as it relays this one.
   * Reloading from disk runs the same checks — the file has no integrity of its own, so
   * nothing is trusted for being on it.
   * @returns {{ stored: boolean, reason?: string, released?: object[] }}
   */
  record(grant) {
    const reason = this._refusal(grant);
    if (reason) {
      if (CURABLE.has(reason)) this._hold(grant, false, reason);
      return { stored: false, reason };
    }
    this._keep(grant, false);
    const released = this._retryPending();
    return released.length ? { stored: true, released } : { stored: true };
  }

  /** How many refused-but-curable records are waiting for their root (in memory only). */
  pendingSize() { return this._pending.size; }

  /**
   * Why a record cannot be stored now, or null when it can. Never throws: a record whose
   * checks fail in a way no reason names is 'unverifiable'.
   * @private
   */
  _refusal(grant) {
    try {
      if (malformed(grant)) return 'malformed';
      if (this._seen.has(grant.sig)) return 'duplicate';
      const key = this._grantorKey(grant.grantedBy);
      if (!key) return 'unknown-grantor-key';
      if (!this._rooted(grant)) return 'unrooted';
      if (!verifyGrant(grant, key).valid) return 'bad-signature';
      return null;
    } catch {
      return 'unverifiable';
    }
  }

  /** Store a record that passed `_refusal`: index it, persist it (unless it came from the file), pin its vouched key. @private */
  _keep(grant, persisted) {
    this._seen.add(grant.sig);
    let arr = this._byGrantee.get(grant.grantee);
    if (!arr) { arr = []; this._byGrantee.set(grant.grantee, arr); }
    arr.push(grant);
    if (!persisted) this._append(grant);
    this._pinGranteeKey(grant);
  }

  /**
   * Hold a curable refusal until its root arrives. Keyed by everything the signature covers
   * plus the signature, so a copy that differs from a held record in any signed field is a
   * different record (a forgery sent ahead of the genuine one cannot displace it), and an
   * identical copy is held once. Bounded: the oldest is dropped first.
   * @private
   */
  _hold(grant, persisted, reason) {
    if (this._maxPending === 0) return;
    const key = pendingKey(grant);
    const held = this._pending.get(key);
    if (held) { held.reason = reason; return; }
    while (this._pending.size >= this._maxPending) this._pending.delete(this._pending.keys().next().value);
    this._pending.set(key, { grant, persisted, reason });
  }

  /**
   * The fixpoint the reload and every store share: offer each entry in turn; one that can be
   * stored is stored, one refused for a curable reason is offered again on the next pass, any
   * other refusal is final; stop when a pass stores nothing.
   * @param {{grant: object, persisted: boolean}[]} entries
   * @returns {{ kept: object[], refused: {entry: object, reason: string}[], left: {entry: object, reason: string}[] }}
   * @private
   */
  _settle(entries) {
    const kept = [];
    const refused = [];
    let left = entries.map((entry) => ({ entry, reason: null }));
    let progress = true;
    while (progress && left.length) {
      progress = false;
      const retry = [];
      for (const { entry } of left) {
        const reason = this._refusal(entry.grant);
        if (!reason) { this._keep(entry.grant, entry.persisted); kept.push(entry.grant); progress = true; }
        else if (CURABLE.has(reason)) retry.push({ entry, reason });
        else refused.push({ entry, reason });
      }
      left = retry;
    }
    return { kept, refused, left };
  }

  /**
   * Retry the pending set after a store: what is now rooted is stored (and released to the
   * caller to relay), what can never be stored (a duplicate by now, a bad signature) is
   * dropped, the rest keeps waiting in its arrival order.
   * @private
   */
  _retryPending() {
    if (this._pending.size === 0) return [];
    const { kept, left } = this._settle([...this._pending.values()]);
    this._pending.clear();
    for (const { entry, reason } of left) { entry.reason = reason; this._pending.set(pendingKey(entry.grant), entry); }
    return kept;
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

  has(sig) { return this._seen.has(sig); }
  size() { return this._seen.size; }

  // ── Durable persistence (append-only) ────────────────────────────────────────

  _append(grant) {
    if (!this._dir || this._loading) return;
    try { fs.appendFileSync(path.join(this._dir, GRANTS_FILE), JSON.stringify(grant) + '\n'); }
    catch { /* best effort — never let persistence break authority */ }
  }

  /**
   * Reload the grant file through the checks a frame gets. A rooted record can only be rooted
   * by records before it in time, not necessarily before it in the file (0.13.16 kept unrooted
   * records, some of which an anchor grant later rooted), so the file goes through the same
   * fixpoint a store triggers (`_settle`): records refused for a curable reason are retried
   * until a pass adds nothing. What is left is skipped and counted, as is a record whose check
   * fails in a way no reason names ('unverifiable'); the curable ones left also wait in the
   * pending set, as a record refused on receipt does, since their root may yet arrive (they
   * are on disk already, so one that is rooted later is not written again). Never throws: a
   * file that cannot be read leaves the store with no grants and `loadReport().unreadable`
   * saying why.
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
      const entries = [];
      for (const line of text.split('\n')) {
        if (!line.trim()) continue;
        try { entries.push({ grant: JSON.parse(line), persisted: true }); } catch { skip('not-json'); }
      }
      const { kept, refused, left } = this._settle(entries);
      report.loaded = kept.length;
      for (const { reason } of refused) skip(reason);
      for (const { entry, reason } of left) { skip(reason); this._hold(entry.grant, true, reason); }
    } finally {
      this._loading = false;
    }
  }
}

/** The pending set's key: every field the signature covers, then the signature. */
function pendingKey(g) {
  return `${g.type}|${g.grantee}|${g.role || ''}|${g.grantedBy}|${g.grantedAt}|${g.granteeKey || ''}|${g.sig}`;
}

/** The fields a record must have, of the types it must have them, or it is not a record. */
function malformed(g) {
  if (!g || typeof g !== 'object' || Array.isArray(g)) return true;
  if (g.type !== 'role-grant' && g.type !== 'role-revoke') return true;
  for (const f of ['grantee', 'grantedBy', 'sig']) if (typeof g[f] !== 'string' || !g[f]) return true;
  if (!Number.isFinite(g.grantedAt)) return true;
  if (g.granteeKey !== undefined && typeof g.granteeKey !== 'string') return true;
  if (g.role !== undefined && typeof g.role !== 'string') return true;
  // A grant confers a rank above participant, or it confers nothing.
  return g.type === 'role-grant' && roleRank(g.role) < 1;
}

module.exports = { RoleGrantStore };
