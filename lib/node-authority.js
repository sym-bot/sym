'use strict';

/**
 * @module @sym-bot/sym/node-authority
 * @description A SymNode's side of MMP §6.6: its anchor pin, its authority store, the four frames
 * that carry the set (authority-statement, authority-digest, authority-fetch, authority-set, §6.6.8),
 * the statements it signs, and how it uses authority — roles that follow the key (§6.6.9), lifecycle
 * authority judged on each CMB's own fields, scoped (§6.5, §6.6.2), and mesh weights judged against
 * the in-force set at the moment of use (§6.6.10). Installed on SymNode.prototype by lib/node.js.
 *
 * Nothing here reads a clock to decide authority. Timers only pace frames and release what a
 * session held.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const A = require('./core/authority');
const { isKeyKnown } = require('./core/ed25519');
const { AuthorityStore, lifecycleOf } = require('./authority-store');

/** The retired time-replay frames (§6.6.11, §7.1 legacy): ignored on receipt, never emitted. */
const RETIRED_FRAMES = new Set(['role-grant', 'role-revoke', 'role-chain-fetch', 'role-chain', 'role-digest']);
/**
 * A responder's pacing of authority-fetch answers, per session (§6.6.8: for example 4 a second, burst
 * 16). Pacing, not refusal: a request over the rate waits its turn, so an asker that keeps one pull in
 * flight is answered page after page and never left short; at most SERVE_QUEUE_MAX wait, and past that
 * a request is dropped. sym does not take §6.6.8's MAY (refuse a fresh full pull within 60 s): the
 * pacing already bounds what a session can ask for, and a refused pull would leave a differing root
 * unreconciled until the peer's set next changed.
 */
const SERVE_PER_SECOND = 4;
const SERVE_BURST = 16;
const SERVE_QUEUE_MAX = 64;
/** authority-digest after a change, at most once a second per session (§6.6.8). */
const DIGEST_MIN_MS = 1000;
/** How long an ask (a pull page or a fetch by ids) may go unanswered before it is given up. */
const FETCH_TIMEOUT_MS = 10_000;
/** How many times a pull page that went unanswered is asked again, from the same cursor. */
const PULL_RETRIES = 3;
/**
 * What a key not seen before costs a gossip lane, in signature checks. §18.3.2's rules 1 and 2 for a
 * new key are one scalar multiplication (cached per key afterwards, the pinned keys for good), about
 * fifteen times an OpenSSL signature check here; a statement's keys are free to mint, so the lane is
 * charged for the work before it is done.
 */
const FRESH_KEY_COST = 16;
/**
 * The most one statement can cost (§6.6.3): a statement below the anchor is one check, its subject
 * key and its signing key at most two fresh keys; an anchor-level one is at most 16 checks (one per
 * pinned-key entry) and one fresh subject key. 1 + 2 * 16 = 33 bounds both.
 */
const STATEMENT_COST_MAX = 1 + 2 * FRESH_KEY_COST;
/**
 * THE ASKING RULE (§6.6.8). Every statement a session delivers spends that peer's gossip lane, asked
 * for or not. This node asks (a pull's first page, its next page, a fetch by ids) only when the lane
 * can pay the most an answer can cost, a full page of the most costly statements, and reserves that
 * much while the ask is out: so an answer is never dropped for budget, and no answer spends more
 * than the lane holds. One ask in flight per session.
 */
const ASK_COST = A.AUTHORITY_PAGE * STATEMENT_COST_MAX; // 2,112
/** A pull that ends with the roots still apart is started again after this, doubling to the most. */
const REPULL_MIN_MS = 2_000;
const REPULL_MAX_MS = 300_000;
/** An answer is verified in slices of at most this many checks, the event loop free between them. */
const SLICE_COST = 4 * STATEMENT_COST_MAX;
/** The relay-failure mute is kept per delivering peer, never per a key the sender chose (§6.6.8). */
const MUTE = 'authority-statements';
/** Roles by precedence, for the one role a node names (attestation stamps, `resolveRole`). */
const ROLE_ORDER = ['anchor', 'admin', 'validator', 'issuer', 'participant'];
/** Rank of a role for lifecycle authority and weights: anchor and admin 2, validator 1, all else 0. */
function lifecycleRank(role) {
  if (role === 'anchor' || role === 'admin' || role === 'canonical') return 2;
  if (role === 'validator' || role === 'validated') return 1;
  return 0;
}
function highestRole(roles) {
  let best = 'participant';
  for (const r of roles) if (ROLE_ORDER.indexOf(r.role) >= 0 && ROLE_ORDER.indexOf(r.role) < ROLE_ORDER.indexOf(best)) best = r.role;
  return best;
}
const HEX64 = /^[0-9a-f]{64}$/;
const isPlain = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/**
 * Build the node's authority store (called from the SymNode constructor, which has parsed the pin:
 * §6.6.1, a pinned key set with a threshold configured out of band; a bad pin stops the node rather
 * than running with no root of trust it did not ask for).
 */
function initAuthority(node, opts = {}) {
  if (node._pin === undefined) node._pin = A.parsePin(opts.anchor !== undefined ? opts.anchor : (process.env.SYM_FOUNDER_ANCHOR || null));
  // Lazy: queries read the resolution the last settle made; a settle makes the next (see _scheduleAuthoritySettle).
  node._authority = new AuthorityStore({ pin: node._pin, dir: path.join(node._dir, 'authority'), lazy: true, log: (m) => node._log(m) });
  // Scope namespaces this node implements (§6.6.2): namespace -> (path, cmb, scope) => whether the CMB
  // is inside. A namespace not listed contains no CMB, so a scoped grant gives nothing here.
  node._authorityScopes = isPlain(opts.authorityScopes) ? { ...opts.authorityScopes } : {};
  node._authorityPrev = new Set();       // the in-force set at the last settle
  node._authorityRelayed = new Set();    // ids relayed once already (§6.6.8 gossip)
  node._authorityOrigin = new Map();     // id -> the peer that delivered it, until the next settle
  node._authorityReported = new Set();   // foreign-self grants already reported
  node._authorityStats = { held: 0, pending: 0, invalid: 0, duplicate: 0, relayed: 0, fetched: 0, served: 0, pulls: 0, retired: 0, overBudget: 0, pendingFull: 0, overCapacity: 0 };
  node._authoritySettleQueued = false;
  const r = node._authority.loadReport();
  if (r.held || r.pending || r.invalid) node._log(`Authority: ${r.held} statement(s) held, ${r.pending} pending, ${r.invalid} not valid under the pin`);
  node._authorityPrev = new Set(node._authority.resolve().inForce);
}

const methods = {
  // ── Roles and their use ─────────────────────────────────────────────────────

  /** The roles `nodeId` holding `key` has (§6.6.4): [{ role, scope, grant }]. The key defaults to its binding. */
  authorityRoles(nodeId, key) {
    const k = key || (nodeId === this.nodeId ? this._identity.publicKey : this._identityKey(nodeId));
    return this._authority.rolesOf(nodeId, k);
  },

  /** The authority root this node's in-force set has (§6.6.7), or null with no anchor pinned. */
  authorityRoot() { return this._authority.root(); },

  /** Status of the authority set, for hosts and `sym status`. */
  authorityStatus() {
    const d = this._authority.digest();
    return {
      anchored: this._authority.anchored,
      pinDigest: this._authority.pinDigest,
      root: d.root,
      inForce: d.count,
      held: this._authority.size(),
      roles: this.authorityRoles(this.nodeId),
      stats: { ...this._authorityStats },
      capacity: this._authority.capacityReport(),
    };
  },

  /** @private Whether a CMB is inside a scope: the namespace's resolver says (none: no CMB is). */
  _scopeContains(scope, cmb) {
    const i = typeof scope === 'string' ? scope.indexOf(':') : -1;
    if (i <= 0 || !cmb) return false;
    const fn = this._authorityScopes[scope.slice(0, i)];
    if (typeof fn !== 'function') return false;
    try { return fn(scope.slice(i + 1), cmb, scope) === true; } catch { return false; }
  },

  /**
   * The lifecycle authority (§3.5) `nodeId` holding `key` has over one CMB, judged on that CMB's own
   * signed fields: 'canonical', 'validated' or 'none' (§6.5, §6.6.2).
   */
  lifecycleAuthority(nodeId, key, cmb) {
    if (!this._authority.anchored) return 'none';
    return lifecycleOf(this.authorityRoles(nodeId, key), (scope) => this._scopeContains(scope, cmb));
  },

  /**
   * The one role a node names for itself (attestation stamps): its highest unscoped role, or the
   * configured lifecycleRole where no anchor is pinned (a closed development mode, §6.5).
   */
  _resolvedRole() {
    if (!this._authority.anchored) return this._lifecycleRole;
    return highestRole(this.authorityRoles(this.nodeId).filter((r) => r.scope === null));
  },

  /**
   * `nodeId`'s highest role in force now, holding the key it is bound to here (or `opts.key`):
   * 'anchor' | 'admin' | 'validator' | 'issuer' | 'participant'. Only unscoped roles count, or, with
   * `opts.cmb`, the roles whose scope contains that CMB (§6.6.2). Authority carries no time (§6.6):
   * there is no "role at a time" to ask for, and a number passed as the second argument is ignored.
   */
  resolveRole(nodeId, opts = {}) {
    if (typeof opts !== 'object' || opts === null) opts = {};
    if (!this._authority.anchored) return 'participant';
    const cmb = opts.cmb || null;
    return highestRole(this.authorityRoles(nodeId, opts.key).filter((r) => r.scope === null || (cmb && this._scopeContains(r.scope, cmb))));
  },

  /**
   * The role an attestation's signer counts with (§6.6.10): its highest role in force now whose
   * scope contains the attested CMB (an unscoped role always does), judged when the weight is
   * applied. The attestation's own time plays no part.
   * @private
   */
  _attesterRole(att) {
    if (!att) return 'participant';
    let cmb = null;
    // The attested record is the one its assertion names: a cognition key is shared by every record
    // with the same categories, so a record held under it but asserted by another (another author,
    // another room) is not the one attested, and its fields judge no scope (#27).
    try {
      const e = this._store.get(att.of);
      cmb = e && e.cmb && e.cmb.metadata && att.assertionId && e.cmb.metadata.assertionId === att.assertionId ? e.cmb : null;
    } catch { cmb = null; }
    return this.resolveRole(att.by, { cmb });
  },

  /** @private The origin role a received CMB's author counts with (§6.4): its lifecycle authority over it. */
  _authorOriginRole(msg) {
    if (!this._authority.anchored || !msg || msg._cmbVerified !== true || !msg._verifiedAuthorNodeId) return 'participant';
    const level = this.lifecycleAuthority(msg._verifiedAuthorNodeId, msg._authorKey, msg.cmb);
    return level === 'canonical' ? 'admin' : level === 'validated' ? 'validator' : 'participant';
  },

  // ── Signing ──────────────────────────────────────────────────────────────────

  /**
   * @private The authority this node signs `fields` under: 'anchor' when its key is pinned and the
   * threshold is 1 (or `asAnchor` is asked, for a statement the other key holders co-sign), otherwise
   * the lowest-id grant of its own, in force, whose role permits the statement and, for a revoke or
   * endorse, that stands above every target (§6.6.3). Null when it holds none.
   */
  _authoritySignerFor(fields, { asAnchor = false } = {}) {
    const pinned = !!this._pin && this._pin.members.some((m) => m.key === this._identity.publicKey);
    if (pinned && (asAnchor || this._pin.threshold === 1)) return 'anchor';
    if (asAnchor) return null;
    const own = this._authority.rolesOf(this.nodeId, this._identity.publicKey).filter((r) => r.grant).sort((x, y) => (x.grant < y.grant ? -1 : 1));
    for (const r of own) {
      if (fields.kind === 'grant') {
        const ok = r.role === 'admin' || ((r.role === 'validator' || r.role === 'issuer') && A.isNonAuthority(fields.role));
        if (ok && A.scopeNarrows(r.scope, fields.scope === undefined ? null : fields.scope)) return r.grant;
        continue;
      }
      if (fields.kind === 'revoke' && !A.isDelegating(r.role)) continue;
      if (fields.kind === 'endorse' && r.role !== 'admin') continue;
      const above = fields.targets.every((t) => {
        const target = this._authority.get(t);
        if (!target) return false;
        const chain = this._authorityChainOf(t);
        if (fields.kind === 'revoke') return chain.includes(r.grant);
        // An endorse stands above the target's authorising grant.
        return target.authorisedBy !== 'anchor' && this._authorityChainOf(target.authorisedBy).includes(r.grant);
      });
      if (above) return r.grant;
    }
    return null;
  },

  /** @private The grants above a held statement (its chain), [] when not held. */
  _authorityChainOf(id) {
    const e = this._authority._held.get(id);
    return e ? e.chain : [];
  },

  /**
   * Sign a grant, revoke or endorse with this node's key (§6.6.3), under the authority it holds (or
   * `opts.authorisedBy`). Returns the statement, not yet ingested: an anchor-level statement under a
   * threshold above 1 is passed to the other key holders (`cosignAuthority`) and then submitted.
   * @param {{ kind: 'grant'|'revoke'|'endorse', subject?: {nodeId, key}, role?: string, scope?: string, targets?: string[] }} fields
   * @param {{ authorisedBy?: string, asAnchor?: boolean, issuedAt?: number }} [opts]
   * @throws {Error} code ENOAUTHORITY when this node holds no authority that permits the statement
   */
  authorityStatement(fields, opts = {}) {
    const authorisedBy = opts.authorisedBy || this._authoritySignerFor(fields, opts);
    if (!authorisedBy) throw Object.assign(new Error(`authority: this node holds no in-force authority that permits this ${fields.kind}`), { code: 'ENOAUTHORITY' });
    const s = { kind: fields.kind, authorisedBy };
    if (fields.kind === 'grant') {
      s.subject = { nodeId: fields.subject.nodeId, key: fields.subject.key };
      s.role = fields.role;
      if (fields.scope !== undefined && fields.scope !== null) s.scope = fields.scope;
    } else {
      s.targets = [...new Set(fields.targets)];
    }
    s.nonce = A.freshNonce();
    if (Number.isSafeInteger(opts.issuedAt)) s.issuedAt = opts.issuedAt;
    s.sigs = [];
    A.signStatement(s, this._identity.privateKey, this._identity.publicKey);
    const bad = A.malformedReason(s);
    if (bad) throw Object.assign(new Error(`authority: the statement is not well formed (${bad})`), { code: 'EAUTHORITYSHAPE' });
    return s;
  },

  /** Add this node's signature to an anchor-level statement if its key is pinned (§6.6.1). */
  cosignAuthority(statement) {
    if (!statement || statement.authorisedBy !== 'anchor') throw new Error('authority: only an anchor-level statement is co-signed');
    if (!this._pin || !this._pin.members.some((m) => m.key === this._identity.publicKey)) throw Object.assign(new Error('authority: this node\'s key is not pinned'), { code: 'ENOAUTHORITY' });
    if ((statement.sigs || []).some((e) => e.key === this._identity.publicKey)) return statement;
    const s = A.canonicalStatement(statement, statement.sigs || []);
    return A.signStatement(s, this._identity.privateKey, this._identity.publicKey);
  },

  /**
   * Ingest a statement this host hands over (its own, or one it was given out of band), as gossip is
   * ingested, and relay it once if it comes into force.
   * @returns {{ result: string, id?: string, status?: string, reason?: string }}
   */
  submitAuthority(statement) {
    const r = this._ingestAuthority(statement, null);
    this._authoritySettle();
    return { ...r, status: r.id ? this._authority.statusOf(r.id) : undefined };
  },

  /** Grant `role` to `subject` ({ nodeId, key }), optionally within `opts.scope`; signed and submitted. */
  grant(subject, role, opts = {}) {
    const s = this.authorityStatement({ kind: 'grant', subject, role, scope: opts.scope }, opts);
    return { statement: s, ...this.submitAuthority(s) };
  },
  /** Revoke the grants named by id; signed and submitted. */
  revoke(targets, opts = {}) {
    const s = this.authorityStatement({ kind: 'revoke', targets }, opts);
    return { statement: s, ...this.submitAuthority(s) };
  },
  /** Endorse the grants and revokes named by id, to keep them if a revoke cuts them off; signed and submitted. */
  endorse(targets, opts = {}) {
    const s = this.authorityStatement({ kind: 'endorse', targets }, opts);
    return { statement: s, ...this.submitAuthority(s) };
  },

  /**
   * Grant a role to a peer whose key this node has proven (a confirmed session or an out-of-band pin),
   * or `opts.granteeKey`. Returns the signed grant, or null (said in the log) when it cannot be made.
   */
  grantRole(granteeNodeId, role, opts = {}) {
    const source = this._keySource(granteeNodeId);
    const key = opts.granteeKey || ((source === 'proven' || source === 'pinned' || source === 'session') ? this._identityKey(granteeNodeId) : undefined);
    if (!key) { this._log(`Grant for ${String(granteeNodeId).slice(0, 8)} not made: no proven key is known for it`); return null; }
    try {
      const r = this.grant({ nodeId: granteeNodeId, key }, role, opts);
      return r.result === 'held' || r.result === 'duplicate' ? r.statement : null;
    } catch (err) { this._log(`Grant for ${String(granteeNodeId).slice(0, 8)} not made: ${err.message}`); return null; }
  },

  /**
   * Revoke every in-force grant naming `nodeId` that this node may remove, in one revoke (at most 64
   * targets). Returns the revoke, or null when there is nothing this node may revoke.
   */
  revokeRole(nodeId) {
    const targets = [];
    for (const s of this._authority.inForceStatements()) {
      if (s.kind !== 'grant' || s.subject.nodeId !== nodeId) continue;
      targets.push(A.statementId(s));
    }
    const permitted = targets.filter((t) => this._authoritySignerFor({ kind: 'revoke', targets: [t] }));
    if (!permitted.length) { this._log(`Revoke for ${String(nodeId).slice(0, 8)} not made: no in-force grant this node may remove`); return null; }
    try { return this.revoke(permitted.slice(0, A.AUTHORITY_MAX_TARGETS)).statement; }
    catch (err) { this._log(`Revoke for ${String(nodeId).slice(0, 8)} not made: ${err.message}`); return null; }
  },

  /**
   * The grants the retired time-replay rule kept here (§6.6.11), read as plain data for the operator
   * who re-issues what should stand: never verified, never resolved, never sent. The role 'anchor' a
   * grant conferred maps to 'admin'.
   */
  legacyRoleGrants() {
    const file = path.join(this._dir, 'role-grants', 'role-grants.jsonl');
    let text = '';
    try { text = fs.readFileSync(file, 'utf8'); } catch { return []; }
    const out = [];
    for (const line of text.split('\n')) {
      if (!line) continue;
      let o; try { o = JSON.parse(line); } catch { continue; }
      const g = o && o.grant && typeof o.grant === 'object' ? o.grant : o;
      if (!g || g.type !== 'role-grant') continue;
      out.push({ grantee: g.grantee, granteeKey: g.granteeKey || null, role: g.role === 'anchor' ? 'admin' : g.role, grantedBy: g.grantedBy });
    }
    return out;
  },

  // ── Ingest, gossip and anti-entropy: §6.6.8 ─────────────────────────────────

  /**
   * @private One statement, from a session (null: this host). Every statement a session delivers
   * spends that peer's lane (§6.6.8): one this node asked for (`ask`, an answer to its own fetch or
   * pull) from what the ask reserved, so it is never dropped; a pending statement offered again once
   * its chain arrived (`retry`) with no floor; any other only if the lane can pay, or it is dropped.
   * What is dropped for nothing is dropped before any of that: a statement not of the shape (no curve
   * arithmetic yet), a repeat, a pending statement already held, or one the session's pending holds
   * have no room for (checked before its signature is). With no anchor pinned nothing is judged at
   * all, and nothing counts against the session (§6.6.1).
   */
  _ingestAuthority(statement, session, { ask = null, retry = false } = {}) {
    if (!this._authority.anchored && session) return { result: 'ignored' };
    const peerId = session ? session.nodeId : null;
    if (session) {
      const bad = A.shapeReason(statement);
      if (bad) { this._authorityStats.invalid++; this._noteRelayFailure(peerId, MUTE); return { result: 'invalid', reason: `not well formed: ${bad}` }; }
      const id = A.statementId(statement);
      if (this._authority.has(id)) { this._authorityStats.duplicate++; return { result: 'duplicate', id }; }
      // A session that delivered statements failing verification is rate-limited (§6.6.8): past the
      // failures allowed in a window, its authority statements are dropped unread.
      if (this._relayMuted(peerId, MUTE)) return { result: 'muted' };
      if (!retry && statement.authorisedBy !== 'anchor' && !this._authority.has(statement.authorisedBy)) {
        const h = session._authPending;
        if (h && h.has(`${id}|${statement.sigs[0].key}`)) { this._authorityStats.duplicate++; return { result: 'duplicate', id }; }
        if (h && h.size >= A.AUTHORITY_PENDING_MAX) {
          this._authorityStats.pendingFull++;
          this._noteDrop('authority-pending-full', peerId, { frame: 'authority-statement' });
          return { result: 'pending-full', id };
        }
      }
      const cost = this._authorityCost(statement);
      if (ask) {
        const paid = Math.min(ask.left, cost);
        ask.left -= paid;
        if (cost > paid) this._gossipSpend(peerId, cost - paid);
      } else if (retry) this._gossipSpend(peerId, cost);
      else if (!this._gossipBudget(peerId, 'authority-statement', MUTE, cost)) { this._authorityStats.overBudget++; return { result: 'over-budget' }; }
    }
    const r = this._authority.ingest(statement);
    if (r.result === 'held') {
      this._authorityStats.held++;
      if (peerId) this._authorityOrigin.set(r.id, peerId);
      this._authorityRetryPending(r.id);
      this._scheduleAuthoritySettle();
    } else if (r.result === 'duplicate') this._authorityStats.duplicate++;
    else if (r.result === 'pending') {
      this._authorityStats.pending++;
      if (session) this._holdAuthorityPending(session, statement, r);
    } else if (r.result === 'over-capacity') {
      // Valid, but last in authority order in a full store: nothing against it or its sender.
      this._authorityStats.overCapacity++;
    } else {
      this._authorityStats.invalid++;
      if (session) this._noteRelayFailure(peerId, MUTE);
    }
    return r;
  },

  /**
   * @private What checking `s` costs, in signature checks (see STATEMENT_COST_MAX): one check below
   * the anchor; one per pinned-key entry of an anchor-level statement (each may be verified); and
   * FRESH_KEY_COST for every key it makes this node check for the first time.
   */
  _authorityCost(s) {
    let checks = 1;
    if (s.authorisedBy === 'anchor') {
      checks = 0;
      for (const e of s.sigs) if (this._pin && this._pin.members.some((m) => m.key === e.key)) checks++;
      checks = Math.max(1, checks);
    }
    return checks + FRESH_KEY_COST * this._authorityFreshKeys(s);
  },

  /**
   * @private How many keys checking `s` would meet for the first time (§18.3.2 rules 1 and 2 not yet
   * known), counting only the checks the store will make: a grant's subject key, and the signing key
   * of a statement below the anchor when it is verified (its chain not held, so its own signature is
   * checked; or held, and the key the one its authorising grant names). Pinned keys are always known.
   */
  _authorityFreshKeys(s) {
    const keys = new Set();
    if (s.kind === 'grant') keys.add(s.subject.key);
    if (s.authorisedBy !== 'anchor') {
      const auth = this._authority.get(s.authorisedBy);
      const k = s.sigs[0].key;
      if (!auth || (auth.kind === 'grant' && auth.subject.key === k)) keys.add(k);
    }
    let n = 0;
    for (const k of keys) if (!isKeyKnown(k)) n++;
    return n;
  },

  /**
   * @private A pending statement (§6.6.8): held in memory for its session, keyed by id and signing
   * key, at most AUTHORITY_PENDING_MAX (room was checked before it was verified), released after
   * AUTHORITY_PENDING_TIMEOUT or with the session. The missing link is asked for from that session
   * under the asking rule, one ask per missing id.
   */
  _holdAuthorityPending(session, statement, r) {
    const h = session._authPending || (session._authPending = new Map());
    const key = `${r.id}|${statement.sigs[0].key}`;
    if (h.has(key) || h.size >= A.AUTHORITY_PENDING_MAX) return;
    const timer = setTimeout(() => {
      h.delete(key);
      // No pending statement waits for that link any more: a later one may ask for it again.
      if (session._authAsked && ![...h.values()].some((p) => p.missing === r.missing)) session._authAsked.delete(r.missing);
    }, A.AUTHORITY_PENDING_TIMEOUT);
    if (timer.unref) timer.unref();
    h.set(key, { statement, missing: r.missing, timer });
    this._authorityPump(session);
  },

  /** @private A statement was held: offer again what any session held pending for it. */
  _authorityRetryPending(id) {
    for (const session of this._sessions) {
      if (session._authAsked) session._authAsked.delete(id);
      const h = session._authPending;
      if (!h || !h.size || session.closed) continue;
      for (const [k, p] of [...h]) {
        if (p.missing !== id) continue;
        clearTimeout(p.timer);
        h.delete(k);
        this._ingestAuthority(p.statement, session, { retry: true });
      }
    }
  },

  /** @private Release what a closing session held (pending statements, asks, pulls, queued answers). */
  _authorityReleaseSession(session) {
    // A pull this session was in the middle of resumes from its cursor on the peer's next session.
    if (session._authPull && session._authPull.after) this._authorityRemember(session.nodeId, session._authPull.after);
    for (const p of (session._authPending || new Map()).values()) clearTimeout(p.timer);
    // An ask still out gives back its reservation: the peer's lane is shared by its other sessions.
    // (An answer being verified gives it back itself when its next slice finds the session closed.)
    const out = session._authAsk;
    if (out) { clearTimeout(out.timer); if (!out.answering) { this._gossipRefund(session.nodeId, out.left); out.left = 0; } }
    if (this._authorityPullEnds) this._authorityPullEnds.delete(session);
    for (const t of [session._authPumpTimer, session._authRepullTimer, session._authDigestTimer, session._authServeTimer]) if (t) clearTimeout(t);
    session._authPending = null; session._authAsk = null; session._authAsked = null; session._authPull = null;
    session._authPumpTimer = null; session._authRepullTimer = null; session._authServeQueue = null; session._authServeTimer = null;
  },

  /**
   * @private Settle once the current ingest is done (many statements in one tick settle once), and
   * never sooner after the last settle than twice what its resolution took: resolving is linear in
   * the held set, so a stream of statements, one per frame, spends at most a third of the time
   * resolving, whatever the set's size. Queries read the last settled resolution in between.
   */
  _scheduleAuthoritySettle() {
    if (this._authoritySettleQueued) return;
    this._authoritySettleQueued = true;
    const run = () => { this._authoritySettleQueued = false; this._authoritySettle(); };
    const wait = (this._authoritySettledAt || 0) + 2 * this._authority.lastResolveMs - Date.now();
    if (wait > 0) { const t = setTimeout(run, Math.ceil(wait)); if (t.unref) t.unref(); }
    else setImmediate(run);
  },

  /**
   * @private Resolve, and act on what changed: relay each statement that entered the in-force set,
   * once (§6.6.8); tell every session the new root (at most once a second each); bind in-force grants
   * as a key-registry view (§6.6.9) and report one naming this node with a foreign key.
   */
  _authoritySettle() {
    const { inForce } = this._authority.resolve();
    const entered = [...inForce].filter((id) => !this._authorityPrev.has(id));
    const changed = entered.length > 0 || this._authorityPrev.size !== inForce.size;
    for (const id of this._authority.authorityOrder(entered).map((e) => e.id)) {
      const s = this._authority.get(id);
      if (!this._authorityRelayed.has(id)) {
        this._authorityRelayed.add(id);
        this._authorityStats.relayed++;
        this._gossipToRoster({ type: 'authority-statement', statement: s }, this._authorityOrigin.get(id) || null);
      }
      if (s.kind === 'grant') {
        if (s.subject.nodeId === this.nodeId) {
          if (s.subject.key !== this._identity.publicKey && !this._authorityReported.has(id)) {
            this._authorityReported.add(id);
            this._log(`[sym-security] an in-force grant (${id.slice(0, 17)}) names this node's nodeId with a key that is not its own: it confers nothing here; someone vouched a foreign key for this node's identity`);
            this.emit('metric', { type: 'authority-foreign-self-key', id, key: s.subject.key });
          }
        } else if (typeof this._roster.bind === 'function') {
          // A conflicting binding is recorded by the registry, and the binding stays as it was.
          this._roster.bind(s.subject.nodeId, s.subject.key, 'grant');
        }
      }
    }
    this._authorityOrigin.clear();
    this._authorityPrev = new Set(inForce);
    // The relayed-once marks are kept for what is held: one for a statement the store has since
    // dropped (§6.6.7: a node MAY drop what is not live) goes, so the set stays bounded by the store.
    if (this._authorityRelayed.size > 2 * this._authority.size() + 1024) {
      for (const id of this._authorityRelayed) if (!this._authority.has(id)) this._authorityRelayed.delete(id);
    }
    if (changed) {
      for (const session of this._sessions) {
        session._authRepullMs = 0; // this node's set changed: any re-pull backoff starts again
        if (session.confirmed && !session.closed) this._sendAuthorityDigest(session);
      }
      try { this.emit('authority-changed', Object.freeze({ root: this._authority.root(), inForce: inForce.size })); } catch { /* a listener must not stop the settle */ }
    }
    this._authoritySettledAt = Date.now();
    // Pulls that ended before what they brought was settled: decided now, against this resolution.
    if (this._authorityPullEnds && this._authorityPullEnds.size) {
      const ends = [...this._authorityPullEnds];
      this._authorityPullEnds.clear();
      for (const [session, pull] of ends) this._authorityPullEnded(session, pull);
    }
  },

  /** @private authority-digest on `session`, at most once a second (§6.6.8). */
  _sendAuthorityDigest(session, { now = false } = {}) {
    if (!this._authority.anchored || !session || session.closed) return;
    const send = () => {
      session._authDigestTimer = null;
      if (session.closed) return;
      session._authDigestAt = Date.now();
      const d = this._authority.digest();
      session.send({ type: 'authority-digest', root: d.root, count: d.count });
    };
    const since = Date.now() - (session._authDigestAt || 0);
    if (now || since >= DIGEST_MIN_MS) { send(); return; }
    if (session._authDigestTimer) return;
    session._authDigestTimer = setTimeout(send, DIGEST_MIN_MS - since);
    if (session._authDigestTimer.unref) session._authDigestTimer.unref();
  },

  /**
   * @private A peer's root and count (§6.6.8): one that differs from this node's starts a pull of its
   * live set. One pull per session; a digest that arrives during it is remembered, and the pull is
   * started again when it ends if the roots still differ.
   */
  _onAuthorityDigest(session, msg) {
    if (!this._authority.anchored || !msg || typeof msg.root !== 'string' || !HEX64.test(msg.root) || !Number.isSafeInteger(msg.count) || msg.count < 0) return;
    const changed = session._authPeerRoot !== msg.root;
    session._authPeerRoot = msg.root;
    if (msg.root === this._authority.root()) { this._authorityRootsMet(session); return; }
    if (changed) session._authRepullMs = 0; // the peer's set changed: the backoff starts again
    if (session._authPull) { session._authPull.digestSeen = true; return; }
    this._startAuthorityPull(session);
  },

  /**
   * @private Pull the peer's live set (asked for under the asking rule): from the start, or from the
   * cursor a pull from that peer stopped at (a page that never came, a session that closed).
   */
  _startAuthorityPull(session) {
    if (session.closed || session._authPull) return;
    if (session._authRepullTimer) { clearTimeout(session._authRepullTimer); session._authRepullTimer = null; }
    const resume = this._authorityResume && this._authorityResume.get(session.nodeId);
    if (resume) this._authorityResume.delete(session.nodeId);
    session._authPull = { after: resume || '', attempt: 0, want: true, digestSeen: false, first: true, resumed: !!resume };
    this._authorityPump(session);
  },

  /** @private Where a pull from `peerId` stopped early, to resume from (bounded, least recent first out). */
  _authorityRemember(peerId, after) {
    if (!after) return;
    const m = this._authorityResume || (this._authorityResume = new Map());
    m.delete(peerId);
    if (m.size >= 1024) m.delete(m.keys().next().value);
    m.set(peerId, after);
  },

  /** @private The roots met: any re-pull backoff starts again from the shortest. */
  _authorityRootsMet(session) {
    session._authRepullMs = 0;
    if (session._authRepullTimer) { clearTimeout(session._authRepullTimer); session._authRepullTimer = null; }
  },

  /** @private A pull ended with the roots apart: pull again after a backoff, doubling (L3). */
  _scheduleAuthorityRepull(session) {
    if (session.closed || session._authRepullTimer) return;
    const wait = session._authRepullMs || REPULL_MIN_MS;
    session._authRepullMs = Math.min(REPULL_MAX_MS, wait * 2);
    const t = setTimeout(() => {
      session._authRepullTimer = null;
      if (session.closed || !session._authPeerRoot || session._authPeerRoot === this._authority.root()) return;
      this._startAuthorityPull(session);
    }, wait);
    if (t.unref) t.unref();
    session._authRepullTimer = t;
  },

  /**
   * @private Ask the session for what this node wants from it, under the asking rule: one ask in
   * flight per session, and only once the peer's lane can pay a full answer's worst case (ASK_COST),
   * which the ask reserves until its answer, or its timeout, gives back what was not spent. Missing
   * links of pending statements are asked for first (they time out), up to a page of ids at once.
   */
  _authorityPump(session) {
    if (!this._authority.anchored || !session || session.closed || session._authAsk) return;
    const asked = session._authAsked || (session._authAsked = new Set());
    const ids = [];
    for (const p of (session._authPending || new Map()).values()) {
      if (ids.length >= A.AUTHORITY_PAGE) break;
      if (asked.has(p.missing) || ids.includes(p.missing) || this._authority.has(p.missing)) continue;
      ids.push(p.missing);
    }
    const pull = session._authPull && session._authPull.want ? session._authPull : null;
    if (!ids.length && !pull) return;
    const wait = this._gossipReserve(session.nodeId, ASK_COST);
    if (wait > 0) {
      if (!session._authPumpTimer) {
        const t = setTimeout(() => { session._authPumpTimer = null; this._authorityPump(session); }, wait);
        if (t.unref) t.unref();
        session._authPumpTimer = t;
      }
      return;
    }
    const ask = { reqId: `af-${crypto.randomBytes(8).toString('hex')}`, left: ASK_COST, ids: ids.length ? ids : null, pull: ids.length ? null : pull, timer: null };
    ask.timer = setTimeout(() => this._authorityAskTimedOut(session, ask), FETCH_TIMEOUT_MS);
    if (ask.timer.unref) ask.timer.unref();
    session._authAsk = ask;
    if (ask.ids) {
      for (const id of ids) asked.add(id);
      this._authorityStats.fetched++;
      session.send({ type: 'authority-fetch', reqId: ask.reqId, ids });
    } else {
      pull.want = false;
      if (pull.first) { pull.first = false; this._authorityStats.pulls++; }
      session.send({ type: 'authority-fetch', reqId: ask.reqId, after: pull.after });
    }
  },

  /** @private An ask went unanswered: give its reservation back; a pull page is asked again, at most PULL_RETRIES times. */
  _authorityAskTimedOut(session, ask) {
    if (session._authAsk !== ask) return;
    session._authAsk = null;
    this._gossipRefund(session.nodeId, ask.left);
    if (ask.ids && session._authAsked) for (const id of ask.ids) session._authAsked.delete(id);
    if (ask.pull) {
      if (ask.pull.attempt < PULL_RETRIES) { ask.pull.attempt++; ask.pull.want = true; }
      else { session._authPull = null; this._authorityRemember(session.nodeId, ask.pull.after); this._scheduleAuthorityRepull(session); }
    }
    this._authorityPump(session);
  },

  /**
   * @private authority-fetch (§6.6.8): checked, then answered in turn at SERVE_PER_SECOND per session
   * (burst SERVE_BURST); a request over the rate waits, at most SERVE_QUEUE_MAX of them.
   */
  _onAuthorityFetch(session, msg) {
    if (!this._authority.anchored || !msg || typeof msg.reqId !== 'string' || !msg.reqId || msg.reqId.length > 128) return;
    if (Array.isArray(msg.ids) && msg.after === undefined) {
      if (msg.ids.length < 1 || msg.ids.length > A.AUTHORITY_PAGE || !msg.ids.every((x) => typeof x === 'string' && A.STATEMENT_ID.test(x)) || new Set(msg.ids).size !== msg.ids.length) return;
    } else if (!(typeof msg.after === 'string' && msg.after.length <= 128 && msg.ids === undefined)) return;
    const q = session._authServeQueue || (session._authServeQueue = []);
    if (q.length >= SERVE_QUEUE_MAX) { this._noteDrop('authority-fetch-queue-full', session.nodeId, { frame: 'authority-fetch' }); return; }
    q.push(msg);
    this._drainAuthorityServe(session);
  },

  /** @private Answer the queued fetches the session's pacing allows now, and wait for the rest. */
  _drainAuthorityServe(session) {
    const q = session._authServeQueue;
    if (!q || session.closed) { session._authServeQueue = null; return; }
    const now = Date.now();
    const b = session._authServe || (session._authServe = { tokens: SERVE_BURST, at: now });
    b.tokens = Math.min(SERVE_BURST, b.tokens + (Math.max(0, now - b.at) * SERVE_PER_SECOND) / 1000);
    b.at = now;
    while (q.length && b.tokens >= 1) {
      b.tokens -= 1;
      this._serveAuthorityFetch(session, q.shift());
    }
    if (q.length && !session._authServeTimer) {
      const t = setTimeout(() => { session._authServeTimer = null; this._drainAuthorityServe(session); }, Math.ceil(((1 - b.tokens) * 1000) / SERVE_PER_SECOND));
      if (t.unref) t.unref();
      session._authServeTimer = t;
    }
  },

  /** @private One answer: by ids, or a page of the live set, as the set stands when it is sent. */
  _serveAuthorityFetch(session, msg) {
    const answer = msg.ids !== undefined ? this._authority.answerIds(msg.ids) : this._authority.page(msg.after);
    this._authorityStats.served++;
    const frame = { type: 'authority-set', reqId: msg.reqId, statements: answer.statements };
    if (answer.missing && answer.missing.length) frame.missing = answer.missing;
    if (answer.next) frame.next = answer.next;
    session.send(frame);
  },

  /**
   * @private An answer to this node's ask on the same session (§6.6.8): each statement ingested as
   * gossip is, paid from the ask's reservation; what it did not spend goes back to the lane. A pull
   * goes on from the answer's cursor; when it ends with the roots apart it is started again, at once
   * if a digest came during it, after a backoff otherwise.
   */
  _onAuthoritySet(session, msg) {
    if (!msg || typeof msg.reqId !== 'string' || !Array.isArray(msg.statements) || msg.statements.length > A.AUTHORITY_PAGE) return;
    const ask = session._authAsk;
    if (!ask || ask.reqId !== msg.reqId || ask.answering) return; // nobody asked on this session
    clearTimeout(ask.timer);
    ask.answering = true;
    // A page is verified in slices of at most SLICE_COST checks, yielding between them, so one answer
    // never holds the event loop for long (64 fresh-key statements are some 130 scalar multiplications).
    const statements = msg.statements;
    let i = 0;
    // However a slice ends (done, the session closed, or a throw no input should cause), the ask is
    // given up and what it did not spend goes back: the session is never left unable to ask again.
    const finish = (complete) => {
      if (session._authAsk === ask) session._authAsk = null;
      if (complete && !session.closed) this._answered(session, ask, msg);
      else { this._gossipRefund(session.nodeId, ask.left); ask.left = 0; }
    };
    const slice = () => {
      let more = false;
      let complete = false;
      try {
        if (session.closed) return;
        let spent = 0;
        while (i < statements.length && spent < SLICE_COST) {
          const st = statements[i++];
          const before = ask.left;
          this._ingestAuthority(st, session, { ask });
          spent += Math.max(1, before - ask.left);
        }
        if (i < statements.length) { more = true; setImmediate(slice); return; }
        complete = true;
      } catch (err) {
        this._log(`Authority: an answer from ${String(session.nodeId).slice(0, 8)} could not be taken (${err && err.message})`);
      } finally {
        if (!more) finish(complete);
      }
    };
    slice();
  },

  /** @private The whole answer is in: give back what it did not spend, and go on with the pull. */
  _answered(session, ask, msg) {
    this._gossipRefund(session.nodeId, ask.left);
    ask.left = 0;
    const pull = ask.pull;
    if (pull && session._authPull === pull) {
      const next = typeof msg.next === 'string' && msg.next && msg.next.length <= 128 ? msg.next : null;
      if (next) { pull.after = next; pull.attempt = 0; pull.want = true; }
      else {
        session._authPull = null;
        // Whether the roots now meet is read from a settled resolution, never a fresh one forced here
        // (a responder that ends every pull after one page would otherwise buy a full resolve per
        // page): if what the pull brought is not settled yet, the next settle decides.
        if (this._authority.dirty) {
          (this._authorityPullEnds || (this._authorityPullEnds = new Map())).set(session, pull);
          this._scheduleAuthoritySettle();
        } else this._authorityPullEnded(session, pull);
      }
    }
    this._authorityPump(session);
  },

  /** @private A pull ended: if the roots still differ, pull again (at once after a digest or a resumed pull, else after a backoff). */
  _authorityPullEnded(session, pull) {
    if (session.closed) return;
    if (session._authPeerRoot && session._authPeerRoot !== this._authority.root()) {
      // A pull that resumed mid-way saw only the rest of the set: the next one starts from the top.
      if (pull.digestSeen || pull.resumed) this._startAuthorityPull(session);
      else this._scheduleAuthorityRepull(session);
    } else this._authorityRootsMet(session);
  },

  /** @private A retired time-replay frame (§6.6.11): ignored, counted, said once a minute per peer. */
  _onRetiredAuthorityFrame(session, type) {
    this._authorityStats.retired++;
    if (typeof this._noteSessionRefusal === 'function') this._noteSessionRefusal(session, type, 'retired: MMP §6.6.11 (authority statements replace role grants)');
  },
};

module.exports = { initAuthority, methods, RETIRED_FRAMES, FRESH_KEY_COST, STATEMENT_COST_MAX, ASK_COST, SERVE_BURST, SERVE_QUEUE_MAX, lifecycleRank, highestRole, ROLE_ORDER };
