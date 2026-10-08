'use strict';

/**
 * Mesh rooms (MMP §5.8) — the shared source of truth for how a room name
 * maps to a Bonjour/mDNS service type, and what a valid room name is.
 *
 * This MUST match the mapping used by sym-mesh-channel (the Claude MCP node)
 * and sym-swift, or CLI nodes won't discover app/Claude nodes in the same
 * room. Convention:
 *   - "default"        -> _sym._tcp   (the global/public mesh)
 *   - "<kebab-room>"  -> _<room>._tcp   (a private room / "room chat")
 *
 * Room names are kebab-case (e.g. "backend-team") or the literal "default".
 * A DOUBLE hyphen is legal as a segment separator ("x-review--team-02779b…"):
 * it is the tenant-suffix grammar xMesh scopes recipe rooms with (founder ruling
 * 2026-08-26, docs/DESIGN-room-join-authorization.md) — before this, sym's own
 * CLI and daemon could not join the rooms its flagship product creates.
 *
 * STATED PLAINLY (grammar review F2/F3): roomServiceType() feeds the room name
 * into a DNS-SD Service Name unmodified, and RFC 6763 §7 forbids consecutive
 * hyphens there (and caps the label at 15 chars). Suffixed names are therefore
 * KNOWINGLY outside RFC 6335's Service Name rules; isolation rests on responders
 * not enforcing them (macOS mDNSResponder does not — measured twice, independently,
 * 2026-08-26 and 2026-08-27: a 39-char suffixed type registers and browses
 * untruncated and does not leak onto _sym._tcp).
 *
 * CORRECTED 2026-08-27, and the correction matters because this comment is the
 * stated rationale for the whole grammar. An earlier version of it claimed MeloMove's
 * 15-char cap COLLIDES two tenants' "x-review--team-…" rooms onto one type. It does
 * not: that consumer cuts to a 9-char prefix plus a 5-char FNV digest of the FULL
 * name, so the two produce distinct types. The claim was taken from a review excerpt
 * and written up as fact without reading the source — the excerpt was stale.
 *
 * The real interop harm is different and worse. For any room name over 15 characters,
 * a truncating consumer emits a service type NO other implementation emits, so it is
 * INVISIBLE rather than misrouted — and on iOS that type is undeclarable anyway,
 * because NSBonjourServices is a build-time allow-list with no wildcard, so a room
 * named at runtime can never be joined there at all. Which is the same conclusion the
 * old comment reached by the wrong route: names were never the boundary. An admission
 * decision has to live somewhere a runtime name can reach, and the only such place is
 * the handshake.
 *
 * Copyright (c) 2026 SYM.BOT. Apache 2.0 License.
 */

const KEBAB_CASE_RE = /^[a-z0-9]+(?:--?[a-z0-9]+)*$/;
const { isRoomId } = require('./core/room-id');

/**
 * A valid room name is a §5.8 room identifier: `[a-z0-9._-]`, 1 to 64 characters (MMP 2.0 update 1,
 * one grammar everywhere). Until the update this was kebab-case only, which refused §5.8-valid
 * rooms, the spec's recommended dotted names (`acme.prod`) and underscores among them.
 *
 * One name is refused though the grammar admits it: `sym`. While per-room service types are
 * advertised anywhere, `sym` maps to `_sym._tcp`, indistinguishable there from `default` (§5.1
 * migration: it MUST NOT be owned and SHOULD NOT be used). A node asking for a room named `sym` would
 * believe it is somewhere specific and be in the public square.
 *
 * Refuse rather than repair. A name that is not already valid MUST NOT be rewritten into one that is:
 * repair maps several distinct names onto one room.
 */
function isValidRoom(room) {
  if (room === 'default') return true;
  return isRoomId(room) && room !== 'sym';
}

/**
 * The canonical name for a room, or null if there is not one.
 *
 * The sanctioned way to accept a name from outside — config, a CLI flag, an
 * invite URL, a UI field. Whitespace around a name is not part of it, so it is
 * trimmed; nothing else is altered. Returns null rather than a best effort, so
 * a caller cannot proceed on a repaired value by forgetting to check.
 */
function canonicalRoom(room) {
  if (typeof room !== 'string') return null;
  const trimmed = room.trim();
  return isValidRoom(trimmed) ? trimmed : null;
}

/**
 * The per-room Bonjour service type earlier releases advertised a room on (`_<room>._tcp`; default:
 * `_sym._tcp`). Since MMP 2.0 update 1 every room is advertised on `_sym._tcp` with its name in the
 * TXT `room` key (§5.1); this mapping is kept for display and for the migration browse
 * (core/room-id legacyServiceType says where it names a valid service).
 */
function roomServiceType(room) {
  return (room && room !== 'default') ? `_${room}._tcp` : '_sym._tcp';
}

/** Inverse: derive a room name from a service type (`_acme._tcp` -> "acme"). */
function serviceTypeToRoom(serviceType) {
  if (!serviceType || serviceType === '_sym._tcp') return 'default';
  return serviceType.replace(/^_/, '').replace(/\._tcp$/, '');
}

module.exports = {
  isValidRoom, canonicalRoom, roomServiceType, serviceTypeToRoom, KEBAB_CASE_RE,
};
