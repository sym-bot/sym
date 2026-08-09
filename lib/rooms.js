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
 *
 * Copyright (c) 2026 SYM.BOT. Apache 2.0 License.
 */

const KEBAB_CASE_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

/** A valid room name is "default" or kebab-case. */
function isValidRoom(room) {
  return room === 'default' || (typeof room === 'string' && KEBAB_CASE_RE.test(room));
}

/** Map a room name to its Bonjour service type. */
function roomServiceType(room) {
  return (room && room !== 'default') ? `_${room}._tcp` : '_sym._tcp';
}

/** Inverse: derive a room name from a service type (`_acme._tcp` -> "acme"). */
function serviceTypeToRoom(serviceType) {
  if (!serviceType || serviceType === '_sym._tcp') return 'default';
  return serviceType.replace(/^_/, '').replace(/\._tcp$/, '');
}

module.exports = { isValidRoom, roomServiceType, serviceTypeToRoom, KEBAB_CASE_RE };
