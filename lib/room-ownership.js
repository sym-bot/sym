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
 * announce "I own this room", the announcement would be the whole attack. Compare
 * roster-keys.js, which does accept a gossiped `grant` source for KEY BINDINGS, because
 * a grant is tamper-evident against a grantor's signature; an ownership claim has no
 * such backing until an owner is known, which is the circularity this absence breaks.
 *
 * AND THE DISK IS NOT THE WIRE, BUT IT IS NOT AN AUTHORITY EITHER. The persisted file
 * carries no signature, so anything that can write the state directory could otherwise
 * install itself as owner at the strongest rank simply by writing `"source":"config"`.
 * It cannot: a replayed record is admitted at most at `own`, never at `config`, so the
 * FILE IS A CACHE AND THE OPERATOR'S CONFIG IS THE AUTHORITY — `config` pins are
 * supplied at construction on every boot and outrank anything the disk claims. The
 * directory is created 0700 and the file written 0600 so the ordinary case does not
 * rely on that argument alone.
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
      try { fs.mkdirSync(this._dir, { recursive: true, mode: 0o700 }); } catch { /* best effort */ }
      this._load();
    }
    // Operator config is applied AFTER the replay and at the strongest rank, so a boot
    // always re-establishes the owners a human declared — and so a persisted record can
    // never quietly outrank them (mirrors RosterKeyRegistry pinning its anchor last).
    for (const o of opts.owners || []) {
      if (o && o.room && o.nodeId && o.publicKey) this.pin(o.room, o.nodeId, o.publicKey, 'config');
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
    // Replay is EXACT: the file is an append-only log of accepted writes, so reloading it
    // must reproduce the state that was written, last write winning. Running precedence
    // during a replay made the FIRST line win instead, so a process that had legitimately
    // re-pinned a room disagreed with every process booted afterwards about who owns it.
    if (this._loading) {
      this._byRoom.set(room, { nodeId, publicKey, source, at: Date.now() });
      return { pinned: true };
    }
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

  /**
   * Replace a room's owner deliberately — key rotation, or correcting a mistaken pin.
   *
   * `pin()` refuses an equal-rank change, which is right for a stranger and wrong for the
   * operator who set it: without this, a rotated owner key could only be fixed by editing
   * the state file by hand, i.e. through the one unauthenticated path this module works to
   * make irrelevant. The replacement is recorded as evidence like any other re-pointing, so
   * a rotation is visible rather than silent.
   */
  repin(room, nodeId, publicKey, source = 'config') {
    const prev = this._byRoom.get(room);
    if (prev) this._conflicts.push({ room, had: prev.nodeId, got: nodeId, source, replaced: true, at: Date.now() });
    this._byRoom.delete(room);
    return this.pin(room, nodeId, publicKey, source);
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
        JSON.stringify({ room, nodeId, publicKey, source }) + '\n', { mode: 0o600 });
    } catch { /* best effort — persistence must never break verification */ }
  }

  _load() {
    this._loading = true;
    let text;
    try { text = fs.readFileSync(path.join(this._dir, OWNERS_FILE), 'utf8'); }
    catch { this._loading = false; return; }
    for (const line of text.split('\n')) {
      if (!line.trim()) continue;
      // A record NEVER restores itself at `config`: the file is unsigned, so letting it
      // name the operator rank would make the state directory the authorization root.
      try {
        const r = JSON.parse(line);
        this.pin(r.room, r.nodeId, r.publicKey, r.source === 'config' ? 'own' : r.source);
      }
      catch { /* skip corrupt line */ }
    }
    this._loading = false;
  }
}

module.exports = { RoomOwnershipRegistry, SOURCE_RANK };
