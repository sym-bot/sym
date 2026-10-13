'use strict';

/**
 * @module sym/core/room-id
 * @description The room identifier (MMP §5.8): `[a-z0-9._-]`, 1 to 64 characters, case-sensitive.
 *
 * One grammar everywhere a room is named (MMP 2.0 update 1): a node's own room, the handshake, a
 * record's signed room, an attestation's room, a room-join grant, relay-auth and the TXT `room` key.
 * Being ASCII, a valid identifier is its own NFC form, so the NFC rules for rooms are met by it.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const ROOM_RE = /^[a-z0-9._-]{1,64}$/;

/** Whether `room` is a §5.8 room identifier. */
const isRoomId = (room) => typeof room === 'string' && ROOM_RE.test(room);

/**
 * The per-room DNS-SD service type earlier releases derived from a room (`_<room>._tcp`), where that
 * is a valid RFC 6335 service name (§5.1 migration: browsed, never advertised), or null: 1 to 15
 * letters, digits and hyphens, at least one letter, no hyphen first, last or twice in a row.
 */
function legacyServiceType(room) {
  if (!isRoomId(room) || room === 'default') return null;
  if (room.length > 15 || !/^[a-z0-9-]+$/.test(room) || !/[a-z]/.test(room) || room.startsWith('-') || room.endsWith('-') || room.includes('--')) return null;
  return `_${room}._tcp`;
}

module.exports = { ROOM_RE, isRoomId, legacyServiceType };
