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
 * chain, never the stamped field.
 *
 * Signatures are verified on ingest against the grantor's announced identity key
 * (the anchor's key is pinned). Whether the grantor actually HELD the rank to confer
 * a role is checked at resolve time (role-at-time), so an over-reaching or unrooted
 * grant is stored but inert. Persisted append-only and reloaded on construction.
 *
 * @copyright 2026 SYM.BOT. Apache 2.0 License.
 */

const fs = require('fs');
const path = require('path');
const { verifyGrant, roleRank } = require('@sym-bot/core');

const GRANTS_FILE = 'role-grants.jsonl';

class RoleGrantStore {
  /**
   * @param {object} [opts]
   * @param {{nodeId: string, publicKey: string}} [opts.anchor] the non-earnable root
   *   of trust (founder). resolveRole confers authority only along chains rooting here.
   * @param {Map<string,string>} [opts.keys] live nodeId→pubkey map (e.g. the node's
   *   handshake key map) used to verify grant signatures on ingest.
   * @param {string} [opts.dir] when set, grants persist append-only and reload here.
   */
  constructor(opts = {}) {
    this._anchor = opts.anchor || null;
    this._keys = opts.keys || new Map();
    this._byGrantee = new Map(); // grantee nodeId -> [grant/revoke records]
    this._seen = new Set();      // sig dedup
    this._dir = opts.dir || null;
    this._loading = false;
    if (this._dir) {
      try { fs.mkdirSync(this._dir, { recursive: true }); } catch { /* best effort */ }
      this._load();
    }
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
   * Record a signed role-grant / role-revoke. The signature must verify against the
   * grantor's key (anchor key pinned). Whether the grantor had the RANK to confer is
   * NOT checked here — that is a resolve-time property, so an over-reaching/unrooted
   * grant is stored but confers nothing. Idempotent (dedup by sig). On reload from
   * disk the record is trusted (already verified when first ingested).
   * @returns {{ stored: boolean, reason?: string }}
   */
  record(grant) {
    if (!grant || !grant.grantee || !grant.grantedBy || !grant.sig || !grant.type) {
      return { stored: false, reason: 'malformed' };
    }
    if (this._seen.has(grant.sig)) return { stored: false, reason: 'duplicate' };
    if (!this._loading) {
      const key = this._grantorKey(grant.grantedBy);
      if (!key) return { stored: false, reason: 'unknown-grantor-key' };
      if (!verifyGrant(grant, key).valid) return { stored: false, reason: 'bad-signature' };
    }
    this._seen.add(grant.sig);
    let arr = this._byGrantee.get(grant.grantee);
    if (!arr) { arr = []; this._byGrantee.set(grant.grantee, arr); }
    arr.push(grant);
    this._append(grant);
    this._maybePinGranteeKey(grant);
    return { stored: true };
  }

  /**
   * A grant may VOUCH for the grantee's nodeId↔key binding (granteeKey, bound into the
   * signed payload). We pin it into the key registry only when the grant is actually
   * role-effective — i.e. the grantor's resolved role at grant time outranks-or-equals
   * the conferred role, so the chain roots at the anchor. An unrooted or over-reaching
   * grant confers no role AND vouches for no key: a node whose authority we don't trust
   * cannot poison the registry. The registry itself refuses to overwrite a stronger
   * (handshake/anchor) binding with this grant-sourced one.
   * @private
   */
  _maybePinGranteeKey(grant) {
    if (!grant.granteeKey || grant.type !== 'role-grant' || typeof this._keys.pin !== 'function') return;
    const grantorRole = this.resolveRole(grant.grantedBy, grant.grantedAt ?? 0);
    if (roleRank(grantorRole) >= roleRank(grant.role)) {
      this._keys.pin(grant.grantee, grant.granteeKey, 'grant');
    }
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

  _load() {
    let text;
    try { text = fs.readFileSync(path.join(this._dir, GRANTS_FILE), 'utf8'); }
    catch { return; }
    const raw = [];
    for (const line of text.split('\n')) {
      if (!line.trim()) continue;
      try { raw.push(JSON.parse(line)); } catch { /* skip corrupt line */ }
    }
    // The grant file has no integrity of its own, so a record is NOT trusted just
    // because it is on disk (a file-write attacker could otherwise forge an
    // anchor-rooted grant). Verify signatures top-down: start from the pinned
    // anchor key, and learn each grantee's key from the `granteeKey` vouched in an
    // already-verified grant (bound into its signed payload). A record whose grantor
    // key can never be reached from the anchor is dropped. Authority is still gated
    // independently by resolveRole, so verifying an unrooted grant's signature only
    // lets it be stored-but-inert — no authority leaks from key-learning.
    const known = new Map(this._keys);
    if (this._anchor) known.set(this._anchor.nodeId, this._anchor.publicKey);
    this._loading = true;
    let progress = true;
    while (progress) {
      progress = false;
      for (let i = 0; i < raw.length; i++) {
        const g = raw[i];
        if (!g) continue;
        const grantorKey = known.get(g.grantedBy);
        if (!grantorKey) continue;               // grantor key not yet reachable
        raw[i] = null;
        progress = true;
        if (!g.grantee || !g.grantedBy || !g.sig || !g.type) continue; // malformed → drop
        if (!verifyGrant(g, grantorKey).valid) continue;               // forged/corrupt → drop
        this.record(g);                          // verified: dedup + store (skips re-verify while loading)
        if (g.type === 'role-grant' && g.granteeKey && !known.has(g.grantee)) {
          known.set(g.grantee, g.granteeKey);    // learn the vouched key for the next hop
        }
      }
    }
    this._loading = false;
  }
}

module.exports = { RoleGrantStore };
