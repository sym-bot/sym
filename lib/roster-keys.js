'use strict';

/**
 * @module @sym-bot/sym/roster-keys
 * @description The key registry: the ONE place where a nodeId gets an identity key (design D3,
 * Core Secure identity, 2026-10-02).
 *
 * A nodeId is self-chosen, so "nodeId X has key K" is always a statement some source makes. A node
 * has one key for life (§3.4), so the registry holds one binding per nodeId, and where sources
 * disagree, PRECEDENCE decides which key verifies (0.14.3, the certification design). Strongest first:
 *
 *   anchor, self  — the configured anchor members (§6.6.1) and this node's own key: configuration,
 *                   read at every start and NEVER persisted or replayed, so re-pinning a fresh anchor
 *                   out of band takes effect at the next start. No source binds either to another key.
 *   pinned        — an out-of-band binding the operator accepted: an invite naming its issuer's key, a
 *                   Legacy Import route's mandatory fingerprint, or `sym keys resolve`. It outranks a
 *                   certification (the operator's explicit local decision); their disagreement is
 *                   recorded and shown.
 *   grant         — an ANCHOR CERTIFICATION: an in-force grant that is a key-binding source (the
 *                   authority store's `bindsKey`: unscoped, and its whole chain unscoped `admin` grants
 *                   up to the anchor; security review R2-1). Only the identity authority certifies WHICH
 *                   key is X's: a session proves only that its peer holds SOME key. A view over the
 *                   in-force set NOW (`opts.grantView`), never stored, so a revoke ends it. While it
 *                   certifies X -> K1:
 *                     - a session proving X with another key is an identity conflict (refused, recorded);
 *                     - nothing verifies as X but under K1;
 *                     - a stored binding of lower rank naming another key is SUPERSEDED: kept on disk,
 *                       marked, recorded as a conflict, and never used to verify;
 *                     - a session proving K1 stores nothing on the grant's account, so a revoke removes
 *                       everything the grant bound.
 *                   Certifications naming two keys for one nodeId certify neither: it verifies nothing
 *                   (fail closed). A grant never binds this node's own nodeId (`opts.self`).
 *   proven        — trust on first proven use: a key a confirmed §5.2 session proved, made durable once
 *                   it is EARNED (an admitted verified record), or a legacy claim a session proved. (A
 *                   live session's key that is not stored is the node's session-scoped binding: the same
 *                   rank, held while the session lasts.)
 *   legacy-claim  — every pre-0.14 `handshake` entry, relabelled on first load. It was learned from
 *                   an unproven hello, so it verifies nothing; it is the EXPECTED key: a proven
 *                   session presenting it binds `proven`, and one presenting a different key is a
 *                   conflict, so a squatter racing the upgrade cannot take an honest node's id.
 *
 * SUPERSEDED IS FAIL CLOSED. When the certification that superseded a binding is revoked or expires,
 * the binding stays conflicted: it verifies nothing and every session for that nodeId is refused (the
 * authority once said that key was not X's) until the operator resolves it (`sym keys resolve`) or a
 * new source settles it: a pin of either key, or a new certification (one naming the superseded key
 * clears the mark). A nodeId that only a certification bound is simply unbound again: a later session
 * binds it by first proven use.
 *
 * The conflict matrix (`bind`):
 *
 *   nodeId unbound, nothing certifies it, any source    → bind at that source
 *   certified K1; a session (proven) says K1            → nothing stored: the binding ends with the grant
 *   certified K1; a proven or legacy-claim source K2    → refused, recorded
 *   certified K1; stored proven / legacy-claim K2       → K2 superseded: kept, marked, recorded
 *   certified K1; pinned K2 (either order)              → the pin binds and verifies; the conflict recorded
 *   superseded K2, nothing certifies; a pin (K1 or K2)  → the pin settles it: bound pinned
 *   superseded K2, nothing certifies; any other source  → refused, recorded (fail closed)
 *   nodeId bound, same key, any source                  → keep; record the stronger source
 *   nodeId bound (not superseded), DIFFERENT key, any
 *     source that is not a certification               → conflict: refused, recorded (roster-conflicts.jsonl),
 *                                                         shown in `sym status`; the operator resolves it
 *                                                         (a pin, too: an invite never repoints a key the
 *                                                         authority has not superseded, design D5)
 *   the configured anchor, this node's own nodeId       → always its configured key
 *
 * `binding(nodeId)` is the decision; `get` is its key when it verifies. Only `anchor`, `self`,
 * `pinned`, `grant` and `proven` verify; a `legacy-claim` is reported by `expected` and `source`, never
 * by `get`, and a superseded binding (source `conflicted`) by `superseded` and `entries`.
 *
 * BINDING LIFETIME (design D3, 0.13.17 re-review). New keypairs are free, so a registry that only
 * grows can be filled by identity churn. A first-contact `proven` binding that has verified nothing
 * since — no record, grant or attestation verified under it (a later session re-proving the key does
 * NOT count: anyone minting identities can handshake twice, security review D) — and has not been
 * seen for BINDING_TTL_MS (30 days) EXPIRES. A binding that ever verified something, or is pinned,
 * vouched (a grant in effect, or a pin, names its key), anchored or a legacy claim (the finite 0.13
 * migration), never expires, so no binding that protects history is forgotten. The facts `seen` and
 * `verified` are persisted with the binding (a `seen` line at most once a day per binding).
 * AMENDED (security review R2-9, 0.14.3): an earned binding ages out too — a new one (everything it
 * verified fell within a day) after BINDING_TTL_MS unseen, and new ones hold at most a quarter of the
 * registry; an established one after EARNED_TTL_MS (180 days) unseen (see EARNED_TTL_MS). A
 * certification is never stored, so it is no earned binding and never ages out as one; a SUPERSEDED
 * binding never expires (expiry would unbind the nodeId and let the next session take it) and is
 * outside the new-binding share (only a certification, which the authority quotas bound, makes one).
 *
 * A binding is NEVER EVICTED before it expires (security review D): when the registry is full, what
 * has expired goes, and if nothing has, a newcomer is refused a binding (`full`) and is held for its
 * session only — the key its live session proved verifies what it signs while that session lasts.
 * Eviction let a flood of fresh identities push an honest binding out and squat its nodeId.
 *
 * THE STICKY FLOOR of Legacy Import (design D7) is its own persisted fact, independent of any
 * binding's lifetime (security review): a nodeId that has a Legacy Import route (`opts.isRouted`)
 * and proves itself over Core Secure arms its floor, and the floor stays armed — through the
 * binding's expiry, a full registry, or a restart — until an operator resets it (`resetFloor`).
 *
 * File format (roster-keys.jsonl): a version marker line `{"v":2,...}`, then one JSON line per
 * binding event. A 0.13 reader skips the marker as malformed and reads the rest. A file without the
 * marker is a 0.13 file: it is replayed by the 0.13 rules, its `handshake` entries become
 * `legacy-claim`, its `anchor` entries are dropped, and it is rewritten once, atomically, with the
 * marker (idempotent: a marked file is never migrated again). A supersession is a line
 * `{nodeId, key, superseded: <certified key>}` (`superseded: false` clears it), and a compacted
 * binding line carries the same member; an earlier 0.14 reader skips the one and ignores the other.
 *
 * @copyright 2026 SYM.BOT. Apache 2.0 License.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const KEYS_FILE = 'roster-keys.jsonl';
const CONFLICTS_FILE = 'roster-conflicts.jsonl';
const FORMAT_MARKER = Object.freeze({ v: 2, format: 'sym-roster-keys', note: 'sym 0.14 key registry; a 0.13 reader skips this line' });

/**
 * Precedence, strongest first (see the module header): the anchor (and this node's own key, `self`),
 * then `pinned`, then `grant` (an anchor certification, a view), then `proven`, then `legacy-claim`.
 * The anchor is configuration. `pinned` outranks `proven` (mesh-channel 0.11.0 defect report): a
 * session proving a pinned key confirms it and keeps it pinned (and so never expiring). `grant`
 * outranks `proven` (0.14.3): a certification supersedes a stored binding of another key.
 */
const SOURCE_RANK = Object.freeze({ 'legacy-claim': 1, proven: 2, grant: 3, pinned: 4, anchor: 5 });
const SOURCES = new Set(Object.keys(SOURCE_RANK));
const rankOf = (s) => SOURCE_RANK[s] ?? 0;
/** What `binding` says of a nodeId nothing may verify as: superseded, or certified two ways. */
const CONFLICTED = Object.freeze({ key: null, source: 'conflicted', verifies: false });
const NONE = Object.freeze([]);

/** Bindings kept at most (new proven/legacy bindings are refused past it; pinned never are). */
const MAX_BINDINGS = 65536;
/** A first-contact proven binding that verified nothing expires after this long unseen. */
const BINDING_TTL_MS = 30 * 24 * 60 * 60 * 1000;
/**
 * EARNED BINDINGS AGE OUT TOO, AND NEW ONES HAVE A SHARE (security review R2-9, 0.14.3). One record,
 * which any fresh identity can send (a directed one is delivered whatever SVAF decides, and an empty
 * memory admits anything), earned a binding that never expired, so a flood of identities filled the
 * registry for good and no honest newcomer could earn one again. Now a proven binding is in one of
 * two expiry classes:
 *   - NEW: nothing verified under it yet, or what did all fell within ESTABLISH_MS (one day) of the
 *     first. It expires after BINDING_TTL_MS unseen, and new bindings hold at most a 1/SHORT_SHARE
 *     share of the registry: past it a newcomer is held for its session only (`full`), however much
 *     room the rest of the registry has, so a flood of one-shot identities fills a quarter at most,
 *     and only for a month;
 *   - ESTABLISHED: it verified records on occasions at least ESTABLISH_MS apart (a peer that came
 *     back). It expires after EARNED_TTL_MS (180 days) unseen.
 * Pinned, vouched, anchored and legacy-claim bindings never expire, as before. A 0.14.2 binding that
 * verified something counts as established (it was one that never expired).
 */
const EARNED_TTL_MS = 180 * 24 * 60 * 60 * 1000;
const ESTABLISH_MS = 24 * 60 * 60 * 1000;
const SHORT_SHARE = 4;
/** A `seen` or `verified` fact is written at most this often per binding (in memory it is exact). */
const FACT_PERSIST_MS = 24 * 60 * 60 * 1000;
/** Conflicts recorded at most per nodeId, and in all; past either, a conflict is only counted. */
const MAX_CONFLICTS_PER_NODE = 8;
const MAX_CONFLICTS = 1024;

/** An Ed25519 public key as the wire carries it: 32 raw bytes, unpadded base64url. */
function isIdentityKey(k) {
  // Canonical only (R2-14): the last character's 2 unused bits are zero, so one key has one spelling.
  return typeof k === 'string' && /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(k) && Buffer.from(k, 'base64url').length === 32;
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
   * @param {{nodeId: string, publicKey: string}[]} [opts.anchors] the pinned anchor members configured
   *   with a nodeId (MMP §6.6.1: a key set with a threshold); never persisted. Each binds its nodeId.
   * @param {string} [opts.dir] when set, bindings persist here and reload.
   * @param {number} [opts.maxBindings]
   * @param {function} [opts.log]
   */
  constructor(opts = {}) {
    this._now = typeof opts.now === 'function' ? opts.now : Date.now;
    this._ttl = Number.isFinite(opts.bindingTtlMs) && opts.bindingTtlMs > 0 ? opts.bindingTtlMs : BINDING_TTL_MS;
    this._earnedTtl = Number.isFinite(opts.earnedTtlMs) && opts.earnedTtlMs > 0 ? opts.earnedTtlMs : EARNED_TTL_MS;
    this._isLive = typeof opts.isLive === 'function' ? opts.isLive : () => false;
    this._isRouted = typeof opts.isRouted === 'function' ? opts.isRouted : () => false;
    // The in-force grants now (the authority store, MMP §6.6.9): nodeId -> the one key they name, or undefined.
    this._grantView = typeof opts.grantView === 'function' ? opts.grantView : null;
    this._self = opts.self && isNodeId(opts.self.nodeId) && isIdentityKey(opts.self.publicKey)
      ? { nodeId: opts.self.nodeId, publicKey: opts.self.publicKey } : null;
    this._expired = 0;               // bindings expired since this registry was built
    // nodeId -> { key, source, at, seenAt, verifiedAt, vouched, seenSaved, verifiedSaved }
    this._byNode = new Map();
    // The expirable bindings (first contact, proven, nothing verified, not vouched), least recently
    // seen first: expiry takes from the head, O(1) each.
    this._lru = new Map();
    // The established bindings (verified on occasions a day or more apart), least recently seen first:
    // they expire after EARNED_TTL_MS unseen (R2-9).
    this._lruLong = new Map();
    this._refusedFull = 0;          // newcomers refused a binding because nothing had expired
    this._refusedShare = 0;         // of them, refused because new bindings held their share (R2-9)
    this._conflicts = [];           // { nodeId, had, hadSource, got, gotSource, at }
    this._conflictCount = 0;        // every conflict, recorded or not
    this._floorArmed = new Set();   // nodeIds whose sticky floor is armed (persisted, never expires)
    this._floorReset = new Set();   // nodeIds whose sticky floor an operator reset
    this._dir = opts.dir || null;
    // A read-only registry (`sym keys` list while the node may run): loads, expires and migrates
    // nothing on disk, and writes nothing (security review: listing must never change the file).
    this._readOnly = opts.readOnly === true;
    this._max = opts.maxBindings || MAX_BINDINGS;
    this._log = typeof opts.log === 'function' ? opts.log : () => {};
    // The anchor pin's members that name their node: configuration, read at every start (§6.6.1).
    this._anchors = new Map();
    for (const a of [...(opts.anchor ? [opts.anchor] : []), ...(Array.isArray(opts.anchors) ? opts.anchors : [])]) {
      if (a && isNodeId(a.nodeId) && a.publicKey) this._anchors.set(a.nodeId, a.publicKey);
    }
    this._loading = false;
    this._migration = null;
    if (this._dir) {
      try { fs.mkdirSync(this._dir, { recursive: true }); } catch { /* best effort */ }
      this._load();
    }
  }

  // ── Reads ──────────────────────────────────────────────────────────────────────

  /**
   * The binding that decides `nodeId` now, by precedence: `{ key, source, verifies }`, or undefined
   * when nothing binds it (a live session may, for as long as it lasts: that is the node's).
   *   anchor | self   its configured key
   *   pinned          the pin (it outranks a certification, whose disagreement is a recorded conflict)
   *   grant           the one key the in-force certifications name; `proven` when a stored proven
   *                   binding holds that very key (it is its own, and outlives the certification)
   *   conflicted      `{ key: null }`: certifications naming two keys, or a stored binding a
   *                   certification superseded while nothing certifies the nodeId now (fail closed)
   *   proven          the stored proven binding
   *   legacy-claim    the expected key, which verifies nothing (`verifies: false`)
   * @returns {{ key: string|null, source: string, verifies: boolean }|undefined}
   */
  binding(nodeId) {
    if (this._anchors.has(nodeId)) return { key: this._anchors.get(nodeId), source: 'anchor', verifies: true };
    if (this._self && nodeId === this._self.nodeId) return { key: this._self.publicKey, source: 'self', verifies: true };
    const b = this._byNode.get(nodeId);
    if (b && b.source === 'pinned') return { key: b.key, source: 'pinned', verifies: true };
    const certs = this._certKeys(nodeId);
    if (certs.length > 1) return CONFLICTED;
    if (certs.length === 1) {
      const own = b && !b.superseded && b.key === certs[0] && b.source === 'proven';
      return { key: certs[0], source: own ? 'proven' : 'grant', verifies: true };
    }
    if (!b) return undefined;
    if (b.superseded) return CONFLICTED;
    return { key: b.key, source: b.source, verifies: b.source !== 'legacy-claim' };
  }

  /** The key that verifies `nodeId`'s signatures, or undefined. Never a legacy claim or a superseded binding. */
  get(nodeId) {
    const d = this.binding(nodeId);
    return d && d.verifies ? d.key : undefined;
  }

  /**
   * The key `nodeId` is bound to at any source, a legacy claim included, or undefined. For a
   * conflicted nodeId: the key on file, or a certification's.
   */
  expected(nodeId) {
    const d = this.binding(nodeId);
    if (!d) return undefined;
    if (d.key) return d.key;
    const b = this._byNode.get(nodeId);
    return b ? b.key : this._certKeys(nodeId)[0];
  }

  /** The source of `nodeId`'s binding: anchor | self | pinned | grant | proven | legacy-claim | conflicted | undefined. */
  source(nodeId) {
    const d = this.binding(nodeId);
    return d ? d.source : undefined;
  }

  /**
   * The key configured or stored for `nodeId` — the anchor, this node's own key, or a stored binding
   * in any state (a legacy claim, a superseded one) — or undefined. Never the certification view; it
   * decides nothing (`binding` does).
   */
  durable(nodeId) {
    if (this._anchors.has(nodeId)) return this._anchors.get(nodeId);
    if (this._self && nodeId === this._self.nodeId) return this._self.publicKey;
    const b = this._byNode.get(nodeId);
    return b ? b.key : undefined;
  }

  /** A stored binding a certification superseded: `{ key, by }` (the certified key), or null. */
  superseded(nodeId) {
    const b = this._byNode.get(nodeId);
    return b && b.superseded ? { key: b.key, by: b.superseded } : null;
  }

  /** The one key the in-force certifications name for `nodeId` now (the view), or undefined. */
  viewKey(nodeId) { return this._viewKey(nodeId); }

  /** @private The one key the certifications in force now name for `nodeId`, or undefined (none, or two). */
  _viewKey(nodeId) {
    const c = this._certKeys(nodeId);
    return c.length === 1 ? c[0] : undefined;
  }

  /**
   * @private The distinct keys the certifications in force now name for `nodeId` (never this node's
   * own). The view answers a key, or a list of them; nothing is read while the file loads.
   */
  _certKeys(nodeId) {
    if (!this._grantView || this._loading || (this._self && nodeId === this._self.nodeId)) return NONE;
    let v;
    try { v = this._grantView(nodeId); } catch { return NONE; }
    if (v === undefined || v === null) return NONE;
    const list = typeof v === 'string' ? [v] : (Array.isArray(v) || v instanceof Set) ? [...v] : NONE;
    const keys = [];
    for (const k of list) if (isIdentityKey(k) && !keys.includes(k)) keys.push(k);
    return keys;
  }

  /** Set the grant view after construction (the authority store is built after this registry). */
  setGrantView(fn) { this._grantView = typeof fn === 'function' ? fn : null; }

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

  /**
   * Every stored binding, for status and tests: [{ nodeId, key, source, at, seen, verified, vouched,
   * superseded }] (`superseded`: the certified key that superseded it, or null).
   */
  entries() {
    const out = [...this._byNode].map(([nodeId, b]) => ({ nodeId, key: b.key, source: b.source, at: b.at, seen: b.seenAt ?? null, verified: b.verifiedAt ?? null, vouched: !!b.vouched, superseded: b.superseded || null }));
    for (const [nodeId, key] of [...this._anchors].reverse()) out.unshift({ nodeId, key, source: 'anchor', at: null });
    return out;
  }

  /**
   * The sticky floor (design D7): true when `nodeId` has proven itself over Core Secure while it had
   * a Legacy Import route, and no operator has reset its floor since. Its own persisted fact: it does
   * not end with the binding (expiry, a full registry) and survives restarts (security review).
   */
  floor(nodeId) {
    return this._floorArmed.has(nodeId) && !this._floorReset.has(nodeId);
  }

  /**
   * `nodeId` proved itself over Core Secure: arm its sticky floor if it has a Legacy Import route.
   * Called on every admitted session (and by a `proven` bind), whether or not a binding was kept.
   * An operator's earlier reset is undone by a new proof.
   */
  armFloor(nodeId) {
    if (!isNodeId(nodeId) || !this._isRouted(nodeId)) return false;
    const reset = this._floorReset.delete(nodeId);
    if (this._floorArmed.has(nodeId) && !reset) return true;
    this._floorArmed.add(nodeId);
    this._persist({ nodeId, floor: true, ...(reset ? { floorReset: false } : {}) });
    return true;
  }

  // ── Writes ─────────────────────────────────────────────────────────────────────

  /**
   * Bind `nodeId` to `key` from `source`, by the conflict matrix (the module header).
   *
   * `grant` is a certification the node offers (its settle, for each key-binding grant that entered
   * the in-force set, and its start, for every one in force): it acts only when the view names that
   * key now, stores nothing, and supersedes a stored binding of lower rank naming another key.
   * @param {string} nodeId
   * @param {string} key - base64url Ed25519 public key
   * @param {'proven'|'pinned'|'grant'|'legacy-claim'} source
   * @returns {{ bound: boolean, source?: string, reason?: 'malformed'|'conflict'|'full'|'not-in-effect',
   *   had?: string, created?: true, conflict?: 'grant', superseded?: true }}
   */
  bind(nodeId, key, source, { at = Date.now() } = {}) {
    if (!isNodeId(nodeId) || !isIdentityKey(key) || !SOURCES.has(source) || source === 'anchor') {
      return { bound: false, reason: 'malformed' };
    }
    if (this._anchors.has(nodeId)) {
      // A pinned anchor member's key is its configured one, whatever any other source says.
      const pinned = this._anchors.get(nodeId);
      if (key === pinned) return { bound: true, source: 'anchor' };
      this._recordConflict(nodeId, pinned, 'anchor', key, source, at);
      return { bound: false, reason: 'conflict', had: pinned };
    }
    if (this._self && nodeId === this._self.nodeId) {
      // This node's own nodeId is its own key: no session, pin or grant binds it to another.
      if (key === this._self.publicKey) return { bound: true, source: 'self' };
      this._recordConflict(nodeId, this._self.publicKey, 'self', key, source, at);
      return { bound: false, reason: 'conflict', had: this._self.publicKey };
    }
    const b = this._byNode.get(nodeId);
    const certs = this._certKeys(nodeId);
    if (source === 'grant') return this._certify(nodeId, key, b, certs, at);
    // A pin outranks every source but configuration: the same key confirms it, another is a conflict.
    if (b && b.source === 'pinned') return this._sameOrConflict(nodeId, b, key, source, at);
    if (source === 'pinned') {
      if (b && !b.superseded && b.key !== key) {
        // A pin never repoints a stored binding the authority has not superseded (design D5: an
        // invite never repoints a key): the operator resolves it.
        this._recordConflict(nodeId, b.key, b.source, key, source, at);
        return { bound: false, reason: 'conflict', had: b.key };
      }
      // It outranks a certification: it binds, and a certification naming another key is a
      // recorded conflict the pin wins (the operator's explicit local decision).
      const other = certs.find((k) => k !== key);
      if (other !== undefined) this._recordConflict(nodeId, key, 'pinned', other, 'grant', at, 'pin-over-certification');
      // The same key confirms (and settles a supersession of it); otherwise the pin binds, settling
      // a supersession of another key.
      const r = b && b.key === key ? this._sameKey(nodeId, b, key, source) : this._create(nodeId, key, source, at);
      return other !== undefined && r.bound ? { ...r, conflict: 'grant', had: other } : r;
    }
    // A session's proof (proven) or a legacy claim: below a certification.
    if (certs.length) {
      if (b) this._settleCertified(nodeId, b, certs, at);
      if (certs.length === 1 && certs[0] === key) {
        if (b && !b.superseded && b.key === key) return this._sameKey(nodeId, b, key, source);
        // A session proving the certified key stores nothing on the grant's account: a revoke
        // removes everything the grant bound. (A first proof still arms the sticky floor.)
        if (source === 'proven') { this.armFloor(nodeId); return { bound: true, source: 'grant' }; }
        if (!b) return this._create(nodeId, key, source, at); // a legacy claim is its own expected key
        return { bound: false, reason: 'conflict', had: b.key };
      }
      // The certification decides: another key is an identity conflict, refused and recorded.
      const had = certs.find((k) => k !== key);
      this._recordConflict(nodeId, had, 'grant', key, source, at);
      return { bound: false, reason: 'conflict', had };
    }
    if (b && b.superseded) {
      // FAIL CLOSED: a binding a certification superseded binds nothing, whatever the key, until the
      // operator resolves it or a pin or a new certification settles it.
      this._recordConflict(nodeId, b.key, 'conflicted', key, source, at);
      return { bound: false, reason: 'conflict', had: b.key, superseded: true };
    }
    if (b) return this._sameOrConflict(nodeId, b, key, source, at);
    return this._create(nodeId, key, source, at);
  }

  /** @private A stored binding (not superseded) and a source naming `key`: the same key, or a conflict. */
  _sameOrConflict(nodeId, b, key, source, at) {
    if (b.key === key) return this._sameKey(nodeId, b, key, source);
    this._recordConflict(nodeId, b.key, b.source, key, source, at);
    return { bound: false, reason: 'conflict', had: b.key };
  }

  /** @private A source naming the key bound: keep it; record the stronger source. */
  _sameKey(nodeId, b, key, source) {
    // A proof of the key bound (never of another: a squatter's conflict arms nothing).
    if (source === 'proven') this.armFloor(nodeId);
    if (b.superseded) {
      // Only a pin reaches a superseded binding here (any other source is refused before): the
      // operator's pin of that very key settles the supersession.
      b.superseded = null;
      b.source = source;
      this._track(nodeId, b);
      this._persist({ nodeId, key, source });
      return { bound: true, source: b.source, settled: true };
    }
    if (rankOf(source) > rankOf(b.source)) {
      b.source = source;
      this._track(nodeId, b);
      this._persist({ nodeId, key, source });
    } else if (source === 'pinned' && b.source !== source && !b.vouched) {
      // A pin naming the key a session proved: the binding is vouched for, and so never
      // expires. Written as the source's own line, which replays as this.
      b.vouched = true;
      this._track(nodeId, b);
      this._persist({ nodeId, key, source });
    }
    // A certification naming the bound key changes nothing stored: while it is in effect the view
    // keeps the binding from expiring (expire).
    return { bound: true, source: b.source };
  }

  /**
   * @private A new binding (or a pin replacing a binding a certification superseded: it settles it).
   * Full: what has expired goes, and nothing else (security review D): a binding is never evicted
   * before it expires, so a flood of new identities cannot push an honest binding out and squat its
   * nodeId. A newcomer refused here is held for its session only (the node verifies what it signs
   * under the key its live session proved, for as long as that session lasts).
   */
  _create(nodeId, key, source, at) {
    // A first proof arms the floor even when the registry is full and keeps no binding.
    if (source === 'proven') this.armFloor(nodeId);
    if (this._byNode.size >= this._max && source !== 'pinned' && !this._loading) this.expire();
    if (this._byNode.size >= this._max && source !== 'pinned') { this._refusedFull++; return { bound: false, reason: 'full' }; }
    // New proven bindings hold at most their share of the registry (R2-9).
    if (source === 'proven' && !this._loading && this._lru.size >= this._shortCap()) {
      this.expire();
      if (this._lru.size >= this._shortCap()) { this._refusedFull++; this._refusedShare++; return { bound: false, reason: 'full' }; }
    }
    const now = this._now();
    const nb = { key, source, at, seenAt: this._loading ? null : now, verifiedAt: null, vouched: false, seenSaved: this._loading ? null : now, verifiedSaved: null, superseded: null };
    this._byNode.set(nodeId, nb);
    if (!this._loading) this._track(nodeId, nb);
    this._persist({ nodeId, key, source, seen: now });
    return { bound: true, source, created: true };
  }

  /**
   * @private A certification of `nodeId` -> `key` offered (source `grant`). It acts only when the view
   * names that key now: a grant not in force says nothing, records nothing and supersedes nothing.
   */
  _certify(nodeId, key, b, certs, at) {
    if (!certs.includes(key)) {
      if (b && !b.superseded && b.key === key) return { bound: true, source: b.source };
      return { bound: false, reason: 'not-in-effect' };
    }
    if (b && b.source === 'pinned') {
      // The pin wins (the operator's explicit local decision); the disagreement is recorded and shown.
      if (b.key === key) return { bound: true, source: 'pinned' };
      this._recordConflict(nodeId, b.key, 'pinned', key, 'grant', at, 'pin-over-certification');
      return { bound: false, reason: 'conflict', had: b.key };
    }
    const other = certs.find((k) => k !== key);
    // Certifications naming two keys for one nodeId certify neither (fail closed), and are recorded.
    if (other !== undefined) this._recordConflict(nodeId, other, 'grant', key, 'grant', at, 'certifications-disagree');
    if (b) this._settleCertified(nodeId, b, certs, at);
    if (other !== undefined) return { bound: false, reason: 'conflict', had: other };
    if (b && !b.superseded && b.key === key) return { bound: true, source: b.source === 'proven' ? 'proven' : 'grant' };
    return { bound: true, source: 'grant' };
  }

  /**
   * @private The certifications in force now name `certs` for `nodeId`, which has the stored binding
   * `b` (not pinned). One naming another key supersedes it: kept on disk, marked, recorded as a
   * conflict, never used to verify, and out of the expiry indexes (it never expires and is outside the
   * new-binding share). A new certification naming the very key of a superseded binding settles it.
   */
  _settleCertified(nodeId, b, certs, at) {
    if (certs.length === 1 && b.key === certs[0]) {
      if (b.superseded) {
        b.superseded = null;
        this._track(nodeId, b);
        this._persist({ nodeId, key: b.key, superseded: false });
        this._log(`Key registry: ${String(nodeId).slice(0, 8)} — a certification in force names the key that was superseded; it is bound to it again`);
      }
      return;
    }
    if (b.superseded) return; // superseded already: it stays so (fail closed)
    const by = certs.find((k) => k !== b.key);
    b.superseded = by;
    this._track(nodeId, b);
    this._persist({ nodeId, key: b.key, superseded: by });
    this._recordConflict(nodeId, by, 'grant', b.key, b.source, at, 'superseded');
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
    if (this._loading) { this._seenWhileLoading = true; return; } // written by the load's compaction
    if (b.seenSaved == null || now - b.seenSaved >= FACT_PERSIST_MS) { b.seenSaved = now; this._persist({ nodeId, seen: now }); }
  }

  /**
   * Something verified under `nodeId`'s binding: a record, a grant or an attestation it signed (never
   * a session re-proving the key: security review D). A binding that ever verified something never
   * expires. With `key`, only a stored binding of that very key is credited: what verified under a
   * certification never credits a binding it superseded.
   */
  noteVerified(nodeId, key) {
    const b = this._byNode.get(nodeId);
    if (!b || b.superseded || (key !== undefined && b.key !== key)) return;
    const now = this._now();
    const first = b.verifiedAt == null;
    if (b.firstVerifiedAt == null) b.firstVerifiedAt = now;
    const before = this._class(b);
    b.verifiedAt = now;
    b.seenAt = now;
    const changed = this._class(b) !== before; // it became established (R2-9)
    this._track(nodeId, b);
    if (first || changed || now - (b.verifiedSaved ?? 0) >= FACT_PERSIST_MS) { b.verifiedSaved = now; b.seenSaved = now; this._persist({ nodeId, verified: now, first: b.firstVerifiedAt }); }
  }

  /**
   * Whether a binding may expire: first contact, proven, never verified, not pinned-vouched (static,
   * the expiry index). A grant in effect naming its key also keeps it (dynamic, checked at expiry).
   * @private
   */
  _expirable(b) { return this._class(b) !== null; }

  /**
   * @private Which expiry class a binding is in (R2-9): 'short' (new: nothing verified, or all of it
   * within ESTABLISH_MS of the first; BINDING_TTL_MS, and the capped share), 'long' (established:
   * EARNED_TTL_MS), or null (never expires: pinned, vouched, anchored, a legacy claim, or superseded:
   * held for the operator, and outside the new-binding share).
   */
  _class(b) {
    if (!b || b.source !== 'proven' || b.vouched || b.superseded) return null;
    if (b.verifiedAt == null) return 'short';
    const first = b.firstVerifiedAt ?? b.verifiedAt;
    return b.verifiedAt - first >= ESTABLISH_MS ? 'long' : 'short';
  }

  /** @private The most bindings the short class may hold. */
  _shortCap() { return Math.max(1, Math.floor(this._max / SHORT_SHARE)); }

  /** @private Keep the expiry indexes: an expirable binding moves to the end of its class (just seen), any other leaves. */
  _track(nodeId, b) {
    this._lru.delete(nodeId);
    this._lruLong.delete(nodeId);
    const c = this._class(b);
    if (c === 'short') this._lru.set(nodeId, true);
    else if (c === 'long') this._lruLong.set(nodeId, true);
  }

  /** @private Drop an expired binding. Its sticky floor, a fact of its own, stays. */
  _drop(nodeId) {
    this._byNode.delete(nodeId);
    this._lru.delete(nodeId);
    this._lruLong.delete(nodeId);
  }

  /**
   * Expire the first-contact bindings that verified nothing and were not seen for the TTL (a node
   * with a live session is never expired). O(bindings).
   * @returns {number} how many expired
   */
  expire() {
    const now = this._now();
    const gone = [];
    // From the head of each class's index (least recently seen first) until a binding seen within
    // that class's TTL.
    for (const [lru, cls, ttl] of [[this._lru, 'short', this._ttl], [this._lruLong, 'long', this._earnedTtl]]) {
      while (lru.size) {
        const nodeId = lru.keys().next().value;
        const b = this._byNode.get(nodeId);
        if (!b || this._class(b) !== cls) { lru.delete(nodeId); if (b) this._track(nodeId, b); continue; }
        const seen = b.seenAt ?? b.seenSaved ?? null;
        if (seen != null && now - seen <= ttl) break;
        // A node with a live session, or a binding a grant in effect vouches, counts as seen now, and
        // that is persisted (a restart reads the file: a live peer's old `seen` must not expire it).
        if (this._isLive(nodeId) || (this._grantView && this._viewKey(nodeId) === b.key)) { this.noteSeen(nodeId); continue; }
        lru.delete(nodeId);
        gone.push(nodeId);
      }
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

  /** Bindings evicted to make room: always 0 (a binding is never evicted before it expires). */
  evictedCount() { return 0; }

  /** Newcomers refused a binding because the registry was full and nothing had expired. */
  refusedFullCount() { return this._refusedFull; }

  /** Newcomers refused because the share for new bindings was full (R2-9). */
  refusedShareCount() { return this._refusedShare || 0; }

  /**
   * 0.13-compatible spelling of bind, for callers that pin a vouched key (`pin(id, key, 'grant')`: it
   * acts only when an in-force certification names that key, as `bind` does).
   * @returns {{ pinned: boolean, reason?: string }}
   */
  pin(nodeId, key, source = 'grant') {
    const r = this.bind(nodeId, key, source === 'handshake' ? 'legacy-claim' : source);
    return r.bound ? { pinned: true } : { pinned: false, reason: r.reason };
  }

  /** Map-compatible write, at `pinned` strength (a grant is never stored: see `grantView`). */
  set(nodeId, key) { this.bind(nodeId, key, 'pinned'); return this; }

  /**
   * The operator resolves a conflict for `nodeId`: `key` becomes its binding at `pinned`, whatever
   * was bound before, and the conflicts recorded for it are cleared. This is the one way a binding
   * changes key, and it is an operator's act (`sym keys resolve`), never a source's.
   * @returns {{ resolved: boolean, reason?: string }}
   */
  resolveConflict(nodeId, key) {
    if (!isNodeId(nodeId) || !isIdentityKey(key)) return { resolved: false, reason: 'malformed' };
    if (this._anchors.has(nodeId)) return { resolved: false, reason: 'anchor' };
    if (this._self && nodeId === this._self.nodeId) return { resolved: false, reason: 'self' };
    this._byNode.set(nodeId, { key, source: 'pinned', at: Date.now(), seenAt: this._now(), verifiedAt: null, vouched: false, seenSaved: null, verifiedSaved: null, superseded: null });
    this._lru.delete(nodeId);
    this._lruLong.delete(nodeId);
    this._persist({ nodeId, key, source: 'pinned', operator: true });
    this._conflicts = this._conflicts.filter((c) => c.nodeId !== nodeId);
    this._rewriteConflicts();
    return { resolved: true };
  }

  /**
   * Record a conflict found outside the registry: a session proving `got` for `nodeId` while a live
   * session-scoped binding (the node's, not persisted here) holds `had` (security review D).
   */
  noteConflict(nodeId, had, hadSource, got, gotSource, at = Date.now()) {
    if (!isNodeId(nodeId) || !isIdentityKey(had) || !isIdentityKey(got)) return;
    this._recordConflict(nodeId, had, hadSource, got, gotSource, at);
  }

  /** The operator resets `nodeId`'s sticky floor: its Legacy Import route may be used again. */
  resetFloor(nodeId) {
    if (!isNodeId(nodeId)) return false;
    this._floorReset.add(nodeId);
    this._persist({ nodeId, floorReset: true });
    return true;
  }

  // ── Internals ──────────────────────────────────────────────────────────────────

  /**
   * Record a conflict: `had` (from `hadSource`) is what holds, `got` (from `gotSource`) what was
   * refused or set aside. `kind` names the certification cases: 'superseded' (a certification set a
   * stored binding aside), 'pin-over-certification' (a pin holds against a certification),
   * 'certifications-disagree' (two keys certified for one nodeId: neither verifies).
   * @private
   */
  _recordConflict(nodeId, had, hadSource, got, gotSource, at, kind) {
    this._conflictCount++;
    if (this._loading || this._readOnly) return; // a conflict in the file was recorded when it happened
    if (this._conflicts.some((c) => c.nodeId === nodeId && c.got === got)) return;
    if (this._conflicts.length >= MAX_CONFLICTS) return;
    if (this._conflicts.filter((c) => c.nodeId === nodeId).length >= MAX_CONFLICTS_PER_NODE) return;
    const c = { nodeId, had, hadSource, got, gotSource, at, ...(kind ? { kind } : {}) };
    this._conflicts.push(c);
    const id8 = String(nodeId).slice(0, 8);
    const fp = (k) => keyFingerprint(k).slice(0, 19);
    const said = kind === 'superseded'
      ? `${id8} is certified to ${fp(had)} by an in-force grant; its stored ${fp(got)} (${gotSource}) is superseded: kept, and it verifies nothing`
      : kind === 'pin-over-certification'
        ? `${id8} is pinned to ${fp(had)}; an in-force grant certifies ${fp(got)}: the pin holds`
        : kind === 'certifications-disagree'
          ? `in-force grants certify both ${fp(had)} and ${fp(got)} for ${id8}: neither verifies`
          : `${id8} is bound to ${fp(had)} (${hadSource}); refused ${fp(got)} (${gotSource})`;
    this._log(`Key conflict: ${said}. Resolve with: sym keys resolve ${nodeId} <key>`);
    if (!this._dir) return;
    try { fs.appendFileSync(path.join(this._dir, CONFLICTS_FILE), JSON.stringify(c) + '\n'); } catch { /* best effort */ }
  }

  _rewriteConflicts() {
    if (!this._dir || this._readOnly) return;
    const file = path.join(this._dir, CONFLICTS_FILE);
    try {
      const tmp = `${file}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, this._conflicts.map((c) => JSON.stringify(c) + '\n').join(''));
      fs.renameSync(tmp, file);
    } catch { /* best effort */ }
  }

  _persist(rec) {
    if (!this._dir || this._loading || this._readOnly) return;
    try { fs.appendFileSync(path.join(this._dir, KEYS_FILE), JSON.stringify(rec) + '\n'); }
    catch { /* best effort — never let persistence break verification */ }
  }

  _load() {
    const file = path.join(this._dir, KEYS_FILE);
    let text = null;
    try { text = fs.readFileSync(file, 'utf8'); } catch { text = null; }
    this._loadConflicts();
    if (text === null) { if (!this._readOnly) this._writeFresh(); return; }
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
      this._lruLong.clear();
      for (const [id, b] of [...this._byNode].filter(([, x]) => this._expirable(x)).sort((x, y) => x[1].seenAt - y[1].seenAt)) this._track(id, b);
      if (!this._readOnly) expired = this.expire();
    } finally { this._loading = false; }
    // Rewritten once, atomically: a 0.13 file (migration), or one whose lines outgrew its bindings.
    if (this._readOnly) return;
    if (!marked || unstamped > 0 || expired > 0 || this._seenWhileLoading || records.length > 2 * this._byNode.size + 256) this._compact();
    this._seenWhileLoading = false;
  }

  /** Replay one 0.14 line. A 0.13 rollback may have appended lines in its own vocabulary. */
  _replay(r) {
    if (!r || typeof r !== 'object' || !isNodeId(r.nodeId)) return;
    if (r.floor === true) { this._floorArmed.add(r.nodeId); if (r.floorReset === false) this._floorReset.delete(r.nodeId); return; }
    if (r.floorReset === true) { this._floorReset.add(r.nodeId); return; }
    if (r.floorReset === false) { this._floorReset.delete(r.nodeId); return; }
    if (r.expired === true) { this._drop(r.nodeId); return; }
    if (r.source === undefined && r.superseded !== undefined) {
      // A supersession (a certification's key), or `false`: a certification or a pin settled it.
      const b = this._byNode.get(r.nodeId);
      if (b && b.key === r.key && b.source !== 'pinned') b.superseded = isIdentityKey(r.superseded) ? r.superseded : null;
      return;
    }
    if (r.key === undefined && (Number.isFinite(r.seen) || Number.isFinite(r.verified))) {
      const b = this._byNode.get(r.nodeId);
      if (!b) return;
      this._applyFacts(b, r);
      return;
    }
    let source = r.source;
    if (source === 'anchor') return;                       // configuration, never replayed
    if (source === 'handshake') source = 'legacy-claim';   // a 0.13 rollback's unproven hello
    if (source === 'grant') return;                        // a view over grants, never stored (review C)
    if (!SOURCES.has(source) || !isIdentityKey(r.key)) return;
    if (this._self && r.nodeId === this._self.nodeId) return; // this node's own id is configuration
    if (r.operator === true) { this._byNode.set(r.nodeId, { key: r.key, source: 'pinned', at: null, seenAt: null, verifiedAt: null, vouched: false, seenSaved: null, verifiedSaved: null, superseded: null }); return; }
    this.bind(r.nodeId, r.key, source, { at: null });
    const b = this._byNode.get(r.nodeId);
    if (b && b.key === r.key) {
      this._applyFacts(b, r);
      if (r.vouched === true) b.vouched = true;
      if (isIdentityKey(r.superseded) && b.source !== 'pinned') b.superseded = r.superseded; // a compacted line
    }
  }

  /** @private A persisted `seen` / `verified` fact (a line of its own, or on a binding's line). */
  _applyFacts(b, r) {
    const now = this._now();
    if (Number.isFinite(r.seen)) { const t = Math.min(r.seen, now); if (b.seenAt == null || t > b.seenAt) { b.seenAt = t; b.seenSaved = t; } }
    if (Number.isFinite(r.verified)) {
      // When it first verified something (R2-9). A 0.14.2 line names nothing: it counts as
      // established (it was a binding that never expired).
      const firstAt = Number.isFinite(r.first) ? Math.min(r.first, now) : Math.min(r.verified, now) - ESTABLISH_MS;
      if (b.firstVerifiedAt == null || firstAt < b.firstVerifiedAt) b.firstVerifiedAt = firstAt;
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
    const counts = { read, bindings: 0, legacyClaim: 0, grant: 0, droppedAnchor: 0, droppedMalformed: 0, droppedSelf: 0 };
    for (const [nodeId, b] of final) {
      if (b.source === 'anchor') { counts.droppedAnchor++; continue; }
      if (!isIdentityKey(b.key)) { counts.droppedMalformed++; continue; }
      if (this._self && nodeId === this._self.nodeId) { counts.droppedSelf++; continue; }
      // Every 0.13 entry is a legacy claim, a `grant` one too (security review C): 0.13 pinned a
      // grant's key without checking that its grantor was authorised when it signed or still is, so
      // it is the EXPECTED key, never one that verifies. Authority now comes only from §6.6 statements,
      // whose in-force set is the view that binds.
      this._byNode.set(nodeId, { key: b.key, source: 'legacy-claim', at: null, seenAt: null, verifiedAt: null, vouched: false, seenSaved: null, verifiedSaved: null, superseded: null });
      counts.bindings++;
      counts.legacyClaim++;
      if (b.source === 'grant') counts.grant++;
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
      if (b.verifiedAt != null && b.firstVerifiedAt != null) line.first = b.firstVerifiedAt;
      if (b.vouched) line.vouched = true;
      if (b.superseded) line.superseded = b.superseded;
      lines.push(JSON.stringify(line));
    }
    for (const nodeId of this._floorArmed) lines.push(JSON.stringify({ nodeId, floor: true }));
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

module.exports = { RosterKeyRegistry, SOURCE_RANK, isIdentityKey, keyFingerprint, KEYS_FILE, CONFLICTS_FILE, FORMAT_MARKER, BINDING_TTL_MS, EARNED_TTL_MS, ESTABLISH_MS, SHORT_SHARE, MAX_CONFLICTS, MAX_CONFLICTS_PER_NODE };
