'use strict';

/**
 * @module sym/core/room-grant
 * @description Ed25519-signed ROOM-JOIN grants — membership as a right, not as
 * knowledge of a string (docs/DESIGN-room-join-authorization.md; founder ruling
 * 2026-08-26, option B as folded).
 *
 * WHAT THIS EXISTS TO STOP, measured rather than imagined: a room is a NAME, and
 * three independent paths turn knowledge of that name into membership (LAN mDNS,
 * the same-host loopback registry, the relay) — none of which asks anyone's
 * permission. On 2026-08-26 that cost a real incident: twenty-three Claude Code
 * sessions running in an unrelated directory joined a room by name, took another
 * tenant's commissioned work off the wire, and wrote the results where they stood.
 *
 * A room-join grant is a signed statement by a room's OWNER binding
 * {room, grantee nodeId, grantee public key, expiry}. It is deliberately NOT a
 * role grant: role-grant.js confers RANK along an anchor-rooted chain and its
 * payload has no room and no expiry, so this carries its own canonical payload
 * rather than widening that one — changing `grantPayload` would invalidate every
 * signature already on disk.
 *
 * V1 IS OWNER-ONLY. The draft allowed "a member the owner authorized to invite";
 * the mesh review struck it as a third decision smuggled into a two-question
 * ruling — delegation has no stated depth, no attenuation and no bound, and the
 * role-grant chain already shows the problems it would have to solve. Not here.
 *
 * THE 24-HOUR CAP IS ENFORCED BY THE VERIFIER, not by the minter. Revocation is
 * live gossip with no catch-up replay (lib/node.js `_gossipToRoster`), so a peer
 * that is offline when a revoke publishes never learns it — which makes the grant's
 * own lifetime the real revocation exposure window. A cap only the minter honoured
 * would be a suggestion; a receiver that accepts a ten-year grant has no window at
 * all. This does not escape the rekey cost of a shared room secret, it RENAMES it
 * into a bounded window, and that is the trade the ruling took.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const crypto = require('crypto');
const { privateKeyObject, publicKeyObject } = require('./cmb-signing');
const { lp } = require('./cmb-encoder');
const { isValidRoom, roomServiceType, serviceTypeToRoom } = require('../rooms');

/** Grants may never outlive this. The number IS the offline-revocation window. */
const MAX_GRANT_LIFETIME_MS = 24 * 60 * 60 * 1000;

/** Clock-skew tolerance when judging expiry across devices. */
const EXPIRY_SKEW_MS = 5 * 60 * 1000;

/**
 * May this room name be OWNED (and therefore gated)?
 *
 * `default` is the public mesh and is never ownable by rule (MMP §5.8). Everything
 * else is derived rather than listed: a name is ownable only if it survives the
 * room↔service-type round trip, which is what refuses `sym` — `roomServiceType('sym')`
 * is `_sym._tcp` and its inverse is `default`, so the mapping is NOT injective and an
 * "owned" room named `sym` would silently BE the public square (grammar review F5).
 * Deriving it means a future name with the same collapse is refused without anyone
 * remembering to add it to a list.
 */
function isOwnableRoom(room) {
  if (!isValidRoom(room) || room === 'default') return false;
  return serviceTypeToRoom(roomServiceType(room)) === room;
}

/** Domain separator: a signature over these bytes can never be read as a CMB
 *  (`mmp-cmb-v1`) or as a role grant, even by a key that legitimately signs both. */
const ROOM_GRANT_DOMAIN = 'mmp-room-join-v1\n';

/**
 * Canonical bytes signed for a room-join grant. Binds the room, the grantee, the
 * grantee's announced key, the owner, and both timestamps — so one signature cannot
 * be replayed into a different room, onto a different node, with a substituted key,
 * or with a stretched expiry. Both signer and verifier use this function.
 *
 * NETSTRING LENGTH-PREFIXED, not delimiter-joined, and the reason is a real attack
 * rather than tidiness: a `${a}|${b}` encoding is NOT injective, so
 * {grantee:'x|y', granteeKey:'z'} and {grantee:'x', granteeKey:'y|z'} produce
 * identical bytes — one owner signature would then authorise a grantee the owner
 * never named. `lp()` is the same injection-proof preimage helper the CMB address
 * uses (cmb-encoder.js): a delimiter inside a field can no longer shift a field
 * boundary.
 *
 * @param {object} g - { room, grantee, granteeKey, grantedBy, grantedAt, expiresAt }
 * @returns {Buffer}
 */
function roomGrantPayload(g) {
  return Buffer.concat([
    Buffer.from(ROOM_GRANT_DOMAIN, 'utf8'),
    lp(g.room),
    lp(g.grantee),
    lp(g.granteeKey || ''),
    lp(g.grantedBy),
    lp(String(g.grantedAt)),
    lp(String(g.expiresAt)),
  ]);
}

/**
 * Mint and sign a room-join grant with the OWNER's raw Ed25519 private key.
 * Refuses an unownable room and clamps the lifetime to the cap at mint time — the
 * verifier enforces it again, because that is where it has to hold.
 * @returns {object} the signed grant
 */
function signRoomGrant(grant, ownerPrivateKeyB64url) {
  if (!grant || !grant.room || !grant.grantee || !grant.grantedBy) {
    throw new Error('signRoomGrant requires room + grantee + grantedBy');
  }
  if (!isOwnableRoom(grant.room)) {
    throw new Error(`room '${grant.room}' cannot be owned (reserved, invalid, or collapses onto another room)`);
  }
  const grantedAt = grant.grantedAt ?? Date.now();
  const requested = grant.expiresAt ?? (grantedAt + MAX_GRANT_LIFETIME_MS);
  const g = {
    ...grant,
    type: 'room-join',
    grantedAt,
    expiresAt: Math.min(requested, grantedAt + MAX_GRANT_LIFETIME_MS),
  };
  g.sig = crypto.sign(null, roomGrantPayload(g), privateKeyObject(ownerPrivateKeyB64url)).toString('base64url');
  g.sigAlg = 'ed25519';
  return g;
}

/**
 * Verify a room-join grant AT JOIN TIME. Fail-closed: every path that is not an
 * affirmative pass returns ok:false with a reason.
 *
 * Expiry is judged HERE and only here — an already-admitted peer is never evicted
 * mid-session by its grant lapsing (review F9: a phone's room node must not strand
 * mid-listen; it presents a fresh grant on its next join).
 *
 * @param {object} grant
 * @param {string} ownerPublicKeyB64url - the key this receiver believes owns the room
 * @param {{ room: string, grantee: string, now?: number }} expect
 * @returns {{ ok: boolean, reason?: string }}
 */
function verifyRoomGrant(grant, ownerPublicKeyB64url, expect = {}) {
  const now = expect.now ?? Date.now();
  if (!grant || grant.type !== 'room-join') return { ok: false, reason: 'not-a-room-join-grant' };
  if (!grant.sig || grant.sigAlg !== 'ed25519') return { ok: false, reason: 'unsigned' };
  if (!ownerPublicKeyB64url) return { ok: false, reason: 'no-owner-key-pinned' };
  if (!isOwnableRoom(grant.room)) return { ok: false, reason: 'room-not-ownable' };
  if (expect.room && grant.room !== expect.room) return { ok: false, reason: 'room-mismatch' };
  if (expect.grantee && grant.grantee !== expect.grantee) return { ok: false, reason: 'grantee-mismatch' };

  const grantedAt = Number(grant.grantedAt);
  const expiresAt = Number(grant.expiresAt);
  if (!Number.isFinite(grantedAt) || !Number.isFinite(expiresAt)) return { ok: false, reason: 'bad-timestamps' };
  // The cap is enforced by the RECEIVER: a grant minted with a longer life is
  // refused outright rather than silently truncated, so the window is never a
  // number the far end chose.
  if (expiresAt - grantedAt > MAX_GRANT_LIFETIME_MS) return { ok: false, reason: 'lifetime-exceeds-cap' };
  if (now > expiresAt + EXPIRY_SKEW_MS) return { ok: false, reason: 'expired' };
  if (now + EXPIRY_SKEW_MS < grantedAt) return { ok: false, reason: 'not-yet-valid' };

  let valid = false;
  try {
    valid = crypto.verify(
      null,
      roomGrantPayload(grant),
      publicKeyObject(ownerPublicKeyB64url),
      Buffer.from(grant.sig, 'base64url'),
    );
  } catch (e) {
    return { ok: false, reason: `verify-failed: ${e.message}` };
  }
  return valid ? { ok: true } : { ok: false, reason: 'bad-signature' };
}

module.exports = {
  ROOM_GRANT_DOMAIN,
  signRoomGrant,
  verifyRoomGrant,
  roomGrantPayload,
  isOwnableRoom,
  MAX_GRANT_LIFETIME_MS,
  EXPIRY_SKEW_MS,
};
