'use strict';

/**
 * @module @sym-bot/sym/roster-keys
 * @description Roster key registry — the authenticated nodeId→publicKey map a node
 * uses to verify signatures from peers it may never have directly handshook.
 *
 * A `nodeId` is a uuidv7, independent of the node's Ed25519 key, so a key carried in
 * a relayed frame is NOT self-verifying — the binding must come from an authenticated
 * source. This registry pins bindings by SOURCE PRECEDENCE, strongest wins:
 *
 *   anchor    (2) — the pinned founder root; configured out-of-band, never overridden.
 *   handshake (1) — learned on a direct authenticated connection (the peer proved the key).
 *   grant     (0) — VOUCHED along the rooted authority chain: a grant whose grantor
 *                   actually held the rank binds the grantee's key into its signed
 *                   payload, so a node that never met the grantee still learns its key,
 *                   tamper-evidently (swapping the key breaks the grantor's signature).
 *
 * The relayer never vouches: a forwarded grant/attestation is trusted only because the
 * ORIGINATOR signed it, verified against the key this registry pins. A weaker-or-equal
 * source can never overwrite a stronger binding, so a gossiped grant cannot repoint a
 * key learnt from a direct handshake or the pinned anchor. Conflicts at equal strength
 * are refused (first binding holds) and surfaced as evidence, not silently merged.
 *
 * Duck-types Map's `get`/`set` so it can drop in wherever a plain key map was used.
 * Persisted append-only and reloaded on construction.
 *
 * @copyright 2026 SYM.BOT. Apache 2.0 License.
 */

const fs = require('fs');
const path = require('path');

const KEYS_FILE = 'roster-keys.jsonl';
const SOURCE_RANK = Object.freeze({ grant: 0, handshake: 1, anchor: 2 });
function sourceRank(s) { return SOURCE_RANK[s] ?? 0; }

class RosterKeyRegistry {
  /**
   * @param {object} [opts]
   * @param {{nodeId: string, publicKey: string}} [opts.anchor] pinned at 'anchor' strength.
   * @param {string} [opts.dir] when set, bindings persist append-only and reload here.
   */
  constructor(opts = {}) {
    this._byNode = new Map();   // nodeId -> { key, source, at }
    this._conflicts = [];       // refused equal/weaker rebindings (omission/impersonation evidence)
    this._dir = opts.dir || null;
    this._loading = false;
    if (this._dir) {
      try { fs.mkdirSync(this._dir, { recursive: true }); } catch { /* best effort */ }
      this._load();
    }
    if (opts.anchor && opts.anchor.nodeId && opts.anchor.publicKey) {
      this.pin(opts.anchor.nodeId, opts.anchor.publicKey, 'anchor');
    }
  }

  /**
   * Pin a nodeId→key binding from a named source. A binding is accepted iff there is
   * no existing binding, or the new source strictly outranks the existing one, or it
   * re-affirms the SAME key. A different key at equal-or-weaker strength is refused and
   * recorded as a conflict — never silently overwrites stronger trust.
   * @param {string} nodeId
   * @param {string} keyB64url
   * @param {'anchor'|'handshake'|'grant'} source
   * @returns {{ pinned: boolean, reason?: string }}
   */
  pin(nodeId, keyB64url, source = 'grant') {
    if (!nodeId || !keyB64url) return { pinned: false, reason: 'malformed' };
    const existing = this._byNode.get(nodeId);
    if (existing) {
      if (existing.key === keyB64url) {
        // same key — upgrade the recorded source if the new one is stronger
        if (sourceRank(source) > sourceRank(existing.source)) {
          existing.source = source;
          this._persist(nodeId, keyB64url, source);
        }
        return { pinned: true };
      }
      if (sourceRank(source) <= sourceRank(existing.source)) {
        this._conflicts.push({ nodeId, had: existing.key, got: keyB64url, source, at: existing.at });
        return { pinned: false, reason: 'conflict' };
      }
      // strictly stronger source overrides a weaker binding (e.g. a direct handshake
      // corrects a previously grant-vouched key)
    }
    const rec = { key: keyB64url, source, at: existing?.at ?? null };
    this._byNode.set(nodeId, rec);
    this._persist(nodeId, keyB64url, source);
    return { pinned: true };
  }

  /** Map-compatible read: the pinned public key for a nodeId, or undefined. */
  get(nodeId) { return this._byNode.get(nodeId)?.key; }

  /** Map-compatible write: pin at the default 'grant' strength (used as a key map drop-in). */
  set(nodeId, keyB64url) { this.pin(nodeId, keyB64url, 'grant'); return this; }

  has(nodeId) { return this._byNode.has(nodeId); }
  source(nodeId) { return this._byNode.get(nodeId)?.source; }
  size() { return this._byNode.size; }
  conflicts() { return this._conflicts.slice(); }

  // ── Durable persistence (append-only; last write per nodeId wins on reload) ──────

  _persist(nodeId, key, source) {
    if (!this._dir || this._loading) return;
    try { fs.appendFileSync(path.join(this._dir, KEYS_FILE), JSON.stringify({ nodeId, key, source }) + '\n'); }
    catch { /* best effort — never let persistence break verification */ }
  }

  _load() {
    this._loading = true;
    let text;
    try { text = fs.readFileSync(path.join(this._dir, KEYS_FILE), 'utf8'); }
    catch { this._loading = false; return; }
    for (const line of text.split('\n')) {
      if (!line.trim()) continue;
      try { const r = JSON.parse(line); this.pin(r.nodeId, r.key, r.source); }
      catch { /* skip corrupt line */ }
    }
    this._loading = false;
  }
}

module.exports = { RosterKeyRegistry, SOURCE_RANK };
