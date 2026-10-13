'use strict';

/**
 * Mesh rooms (MMP §5.8, MMP 2.0 update 1) — what a valid room name is, and the per-room Bonjour service
 * type earlier releases advertised on.
 *
 * A room identifier is `[a-z0-9._-]`, 1 to 64 characters, case-sensitive, or the literal "default"
 * (lib/core/room-id.js is the one grammar, used wherever a room is named: the handshake, a record, an
 * attestation, a grant, relay-auth). `sym` is refused: while per-room service types exist anywhere it
 * maps to `_sym._tcp`, indistinguishable there from the default room (§5.1 migration).
 *
 * Since update 1 EVERY room is advertised on `_sym._tcp` with its name in the TXT `room` key (§5.1), and a
 * node dials only advertisements whose TXT room is its own; the handshake, not the service type, is what
 * admits. `roomServiceType()` is the per-room type earlier releases advertised on (`_<room>._tcp`), kept for
 * display and for the migration browse (core/room-id `legacyServiceType` says where it names a valid
 * RFC 6335 service name; a long or double-hyphen room such as the tenant-suffixed `x-review--team-…` is
 * therefore not browsed under its old type, and mesh-channel must move to `_sym._tcp` plus TXT `room`).
 *
 * Refuse rather than repair: a name that is not already valid is never rewritten into one that is.
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
