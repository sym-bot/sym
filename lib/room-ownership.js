'use strict';

/**
 * @module sym/room-ownership
 * @description Which key owns which room — the receiver's local answer to
 * "may this peer be here?" (docs/DESIGN-room-join-authorization.md, founder ruling
 * 2026-08-26).
 *
 * WHAT OWNERSHIP IS FOR. Without an owner, a room's membership is knowledge of its
 * name, so "shared deliberately" and "leaked" are the SAME STATE and no one can tell
 * them apart afterwards. That is not a hypothetical: on 2026-08-26 a crew from another
 * deployment met this one's commissions in a room neither had chosen to share, and the
 * evidence of it arrived days later. Ownership is what makes sharing an ACT rather than
 * an accident — and the mesh's advantage depends on foreign nodes being welcome, so the
 * point of an owner is not to keep the room small; it is to make an open room a
 * decision someone actually made, and can therefore make deliberately more often.
 *
 * OWNERSHIP IS NEVER LEARNED FROM THE WIRE, and this module deliberately offers no
 * path to it. An authorization root taught by a stranger is not a root: if a peer could
 * announce "I own this room", the announcement would be the whole attack. So the three
 * sources are all out-of-band with respect to the mesh — operator config, this node's
 * own minting, and a human-carried invite. Compare roster-keys.js, which does accept a
 * gossiped `grant` source for KEY BINDINGS, because a grant is tamper-evident against a
 * grantor's signature; an ownership claim has no such backing until an owner is known,
 * which is the circularity this absence breaks.
 *
 * Precedence, strongest wins, mirroring RosterKeyRegistry: `config` (2) — pinned by the
 * operator, never overridden; `own` (1) — this node minted the room and holds the key;
 * `invite` (0) — carried by a human who pasted a link. A different owner at equal-or-
 * weaker strength is REFUSED and recorded as a conflict rather than silently applied,
 * so an attempt to re-point a room is evidence instead of a state change.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const fs = require('fs');
const path = require('path');
const { isOwnableRoom } = require('./core/room-grant');

const OWNERS_FILE = 'room-owners.jsonl';
const SOURCE_RANK = Object.freeze({ invite: 0, own: 1, config: 2 });
function sourceRank(s) { return SOURCE_RANK[s] ?? -1; }

class RoomOwnershipRegistry {
  /**
   * @param {object} [opts]
   * @param {string} [opts.dir] when set, ownership persists append-only and reloads here.
   */
  constructor(opts = {}) {
    this._byRoom = new Map();   // room -> { nodeId, publicKey, source, at }
    this._conflicts = [];       // refused re-pointings — impersonation evidence, not noise
    this._dir = opts.dir || null;
    this._loading = false;
    if (this._dir) {
      try { fs.mkdirSync(this._dir, { recursive: true }); } catch { /* best effort */ }
      this._load();
    }
  }

  /**
   * Record that `nodeId`/`publicKey` owns `room`, from a named out-of-band source.
   * Accepted iff there is no existing owner, the new source strictly outranks the
   * existing one, or it re-affirms the SAME owner. Refuses unownable rooms outright —
   * `default` is the public mesh, and a name that collapses onto another room's service
   * type (e.g. `sym`) would gate a room it is not.
   * @param {'config'|'own'|'invite'} source
   * @returns {{ pinned: boolean, reason?: string }}
   */
  pin(room, nodeId, publicKey, source = 'invite') {
    if (!room || !nodeId || !publicKey) return { pinned: false, reason: 'malformed' };
    if (sourceRank(source) < 0) return { pinned: false, reason: 'unknown-source' };
    if (!isOwnableRoom(room)) return { pinned: false, reason: 'room-not-ownable' };
    const existing = this._byRoom.get(room);
    if (existing) {
      if (existing.nodeId === nodeId && existing.publicKey === publicKey) {
        if (sourceRank(source) > sourceRank(existing.source)) {
          existing.source = source;
          this._persist(room, nodeId, publicKey, source);
        }
        return { pinned: true };
      }
      if (sourceRank(source) <= sourceRank(existing.source)) {
        this._conflicts.push({ room, had: existing.nodeId, got: nodeId, source, at: Date.now() });
        return { pinned: false, reason: 'conflict' };
      }
    }
    this._byRoom.set(room, { nodeId, publicKey, source, at: existing?.at ?? Date.now() });
    this._persist(room, nodeId, publicKey, source);
    return { pinned: true };
  }

  /** The owner this receiver believes in, or null when the room is ungated. */
  ownerOf(room) {
    const r = this._byRoom.get(room);
    return r ? { nodeId: r.nodeId, publicKey: r.publicKey, source: r.source } : null;
  }

  /**
   * Is this room gated? A room with no known owner is OPEN and behaves exactly as it
   * did before this design existed — ownership is opt-in at creation, so upgrade day
   * changes nothing for any room already in use.
   */
  isGated(room) { return this._byRoom.has(room); }

  /**
   * The operator-visible mode for a room, so a partially-enforced room can never be
   * mistaken for a closed one (review F8). `gated-partial` is reported by the caller
   * when legacy peers are admitted alongside grant-bearing ones.
   */
  modeOf(room) { return this.isGated(room) ? 'gated' : 'open'; }

  rooms() { return [...this._byRoom.keys()]; }
  conflicts() { return this._conflicts.slice(); }

  // ── Durable persistence (append-only; last accepted write per room wins on reload) ──

  _persist(room, nodeId, publicKey, source) {
    if (!this._dir || this._loading) return;
    try {
      fs.appendFileSync(path.join(this._dir, OWNERS_FILE),
        JSON.stringify({ room, nodeId, publicKey, source }) + '\n');
    } catch { /* best effort — persistence must never break verification */ }
  }

  _load() {
    this._loading = true;
    let text;
    try { text = fs.readFileSync(path.join(this._dir, OWNERS_FILE), 'utf8'); }
    catch { this._loading = false; return; }
    for (const line of text.split('\n')) {
      if (!line.trim()) continue;
      try { const r = JSON.parse(line); this.pin(r.room, r.nodeId, r.publicKey, r.source); }
      catch { /* skip corrupt line */ }
    }
    this._loading = false;
  }
}

module.exports = { RoomOwnershipRegistry, SOURCE_RANK };
