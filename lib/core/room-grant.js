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
 * {room, grantee nodeId, grantee public key, expiry}. It is deliberately NOT an
 * authority statement: a §6.6 grant confers a ROLE through a hash-linked chain from
 * the pinned anchor and carries no room and no time, so this keeps its own canonical
 * payload (MMP §5.8.1) under its own domain.
 *
 * V1 IS OWNER-ONLY. The draft allowed "a member the owner authorized to invite";
 * the mesh review struck it as a third decision smuggled into a two-question
 * ruling — delegation has no stated depth, no attenuation and no bound here (MMP
 * §6.6 has all three for roles; room-join grants are not part of it). Not here.
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
const { verifyStrict } = require('./ed25519');
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
 *
 * WHAT THIS DOES NOT PROVE, stated because the predicate reads stronger than it is: the
 * round trip tests SYM'S OWN mapping, not every consumer's. A shipped consumer that
 * truncates the service name at 15 characters collapses `x-review--team-<a>` and
 * `x-review--team-<b>` onto one type, and this predicate blesses both — two rooms with
 * different owners looking like one room on that path. The name was never the boundary;
 * the grant is. This check removes one silent collapse, it does not make names unique.
 */
function isOwnableRoom(room) {
  if (!isValidRoom(room) || room === 'default') return false;
  return serviceTypeToRoom(roomServiceType(room)) === room;
}

/** Domain separator: a signature over these bytes can never be read as a CMB
 *  (`mmp-cmb-v1`) or as an authority statement (`mmp-authority-v1`), even by a key that legitimately signs both. */
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

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const GRANT_MEMBERS = new Set(['type', 'room', 'grantee', 'granteeKey', 'grantedBy', 'grantedAt', 'expiresAt', 'sigAlg', 'sig']);
const isTime = (t) => Number.isSafeInteger(t) && t >= 0;

/**
 * MMP §5.8.1 (room-join.schema.json's grant), checked BEFORE the signature: a closed object of
 * exactly the signed members, typed as the schema types them. The payload signs decimal text, so
 * `"1786…"` and `1786…` sign the same bytes; only this check keeps a string timestamp, which the
 * expiry timer would not arm on, from being taken (spec review #31).
 * @returns {string|null} why not, or null
 */
function grantShapeReason(g) {
  if (!g || typeof g !== 'object' || Array.isArray(g)) return 'not an object';
  for (const k of Object.keys(g)) if (!GRANT_MEMBERS.has(k)) return `a member the schema does not define (${String(k).slice(0, 32)})`;
  if (g.type !== 'room-join') return 'type';
  if (typeof g.room !== 'string' || !/^[a-z0-9._-]{1,64}$/.test(g.room)) return 'room';
  if (typeof g.grantee !== 'string' || !UUID.test(g.grantee)) return 'grantee is not a lowercase UUID';
  if (typeof g.granteeKey !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(g.granteeKey)) return 'granteeKey';
  if (typeof g.grantedBy !== 'string' || !UUID.test(g.grantedBy)) return 'grantedBy is not a lowercase UUID';
  if (!isTime(g.grantedAt)) return 'grantedAt is not an integer';
  if (!isTime(g.expiresAt)) return 'expiresAt is not an integer';
  if (g.sigAlg !== 'ed25519') return 'sigAlg';
  if (typeof g.sig !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(g.sig)) return 'sig';
  return null;
}

/** A grant as it goes on the wire: the schema's members only, whatever object the host passed. */
function grantForWire(g) {
  const out = {};
  if (g && typeof g === 'object') for (const k of GRANT_MEMBERS) if (g[k] !== undefined) out[k] = g[k];
  return out;
}

/**
 * Mint and sign a room-join grant with the OWNER's raw Ed25519 private key. The grant is exactly
 * the schema's object (members the caller passed beyond it are not kept), and one that could never
 * verify is refused here. Refuses an unownable room and clamps the lifetime to the cap at mint time
 * — the verifier enforces it again, because that is where it has to hold.
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
    type: 'room-join',
    room: grant.room,
    grantee: grant.grantee,
    granteeKey: grant.granteeKey,
    grantedBy: grant.grantedBy,
    grantedAt,
    expiresAt: Math.min(requested, grantedAt + MAX_GRANT_LIFETIME_MS),
  };
  g.sig = crypto.sign(null, roomGrantPayload(g), privateKeyObject(ownerPrivateKeyB64url)).toString('base64url');
  g.sigAlg = 'ed25519';
  const bad = grantShapeReason(g);
  if (bad) throw new Error(`signRoomGrant: the grant would not be well formed (${bad})`);
  return g;
}

/**
 * Verify a room-join grant AT JOIN TIME. Fail-closed: every path that is not an
 * affirmative pass returns ok:false with a reason.
 *
 * Expiry is judged here at join time, and the node arms a timer from the verified
 * `expiresAt` that closes the admitted session when its grant lapses (security review:
 * a grant admits until it expires, not for as long as the session lasts); the grantee
 * presents a fresh grant on its next join.
 *
 * THE EXPECTATION IS MANDATORY. `expect.room` and `expect.grantee` are what turn a
 * signature into an authorisation FOR THIS PEER, IN THIS ROOM; when they were optional,
 * the default call `verifyRoomGrant(g, ownerKey)` returned ok for any unexpired grant the
 * owner ever minted, presented by anyone holding a copy — a bearer token, produced by a
 * caller merely forgetting an argument. A guard whose safe use depends on remembering an
 * optional key is not a guard, so omitting either is now a refusal rather than a pass.
 *
 * @param {object} grant
 * @param {string} ownerPublicKeyB64url - the key this receiver believes owns the room
 * @param {{ room: string, grantee: string, now?: number }} expect - room + grantee REQUIRED
 * @returns {{ ok: boolean, reason?: string }}
 */
function verifyRoomGrant(grant, ownerPublicKeyB64url, expect = {}) {
  const now = expect.now ?? Date.now();
  if (!expect.room || !expect.grantee) return { ok: false, reason: 'no-expectation' };
  if (!grant || grant.type !== 'room-join') return { ok: false, reason: 'not-a-room-join-grant' };
  if (!grant.sig || grant.sigAlg !== 'ed25519') return { ok: false, reason: 'unsigned' };
  // The schema first, before anything is verified (MMP §5.8.1): integer timestamps, no extra member.
  const bad = grantShapeReason(grant);
  if (bad) return { ok: false, reason: `malformed: ${bad}` };
  if (!ownerPublicKeyB64url) return { ok: false, reason: 'no-owner-key-pinned' };
  if (!isOwnableRoom(grant.room)) return { ok: false, reason: 'room-not-ownable' };
  if (grant.room !== expect.room) return { ok: false, reason: 'room-mismatch' };
  if (grant.grantee !== expect.grantee) return { ok: false, reason: 'grantee-mismatch' };
  // THE GRANT MUST NAME THE HAND THAT SIGNED IT. `grantedBy` is inside the signed payload, so it
  // cannot be altered by a third party — but nothing compared it to the owner, and the signature
  // is checked against the owner's key selected by ROOM. So an owner could mint a grant recording
  // somebody else as its issuer and it would verify: not an admission hole, since only the owner's
  // key admits, but the grant is the EVIDENCE of admission and its audit trail could say what the
  // cryptography does not support. Checked only when the caller supplies the owner's identifier,
  // so an older caller keeps working rather than failing closed on a field it never passed.
  //
  // THIS IS A COHERENCE CHECK, NOT THE ENFORCEMENT. Owner-only is enforced by verifying against
  // the owner's pinned key, chosen by the room. A verifier that instead looked the key up BY this
  // field would let the grant name its own verifier, which is the classic key-confusion shape and
  // would admit any member-issued grant. Never select a key by something the credential carries.
  if (expect.ownerNodeId && grant.grantedBy !== expect.ownerNodeId) {
    return { ok: false, reason: `grantor-not-owner (grant records ${grant.grantedBy}, room is owned by ${expect.ownerNodeId})` };
  }

  // THE BINDING THIS GRANT CLAIMS, NOW ENFORCED — and it FAILS CLOSED when it cannot be.
  //
  // `granteeKey` was signed into the payload from the start and compared to nothing, while
  // DESIGN-room-join-authorization.md described the result as "tamper-evident vouching that
  // already teaches third parties a key they never handshook". It taught nobody anything: with
  // only {room, grantee} expected, a grant admitted WHOEVER HELD THE STRING while asserting the
  // grantee's nodeId — a bearer token for the room with a 24h life, not a credential. Found by
  // dev-team-3 from the code, reproduced by its failing test on 2026-09-16: an impostor offering
  // a different key was admitted to a gated room.
  //
  // The caller must present the key the peer PROVED in its §5.2 handshake, and there is no way to
  // pass "trust the asserted one" — that would be no bar at all, since the key is inside the grant
  // the impostor is holding. Absent proof, admission is refused rather than granted. In 0.14 every
  // session runs the proving handshake, and the node passes the session's proven key here.
  if (!expect.provenKey) return { ok: false, reason: 'no-proven-key — a gated room requires a proving handshake; the asserted key is not a credential' };
  if (!grant.granteeKey) return { ok: false, reason: 'grant-binds-no-key' };
  if (grant.granteeKey !== expect.provenKey) return { ok: false, reason: 'grantee-key-mismatch' };

  const grantedAt = grant.grantedAt;
  const expiresAt = grant.expiresAt;
  // The cap is enforced by the RECEIVER: a grant minted with a longer life is
  // refused outright rather than silently truncated, so the window is never a
  // number the far end chose.
  if (expiresAt - grantedAt > MAX_GRANT_LIFETIME_MS) return { ok: false, reason: 'lifetime-exceeds-cap' };
  if (now > expiresAt + EXPIRY_SKEW_MS) return { ok: false, reason: 'expired' };
  if (now + EXPIRY_SKEW_MS < grantedAt) return { ok: false, reason: 'not-yet-valid' };

  let valid = false;
  try {
    // MMP §18.3.2: the one Ed25519 rule.
    valid = verifyStrict(roomGrantPayload(grant), ownerPublicKeyB64url, grant.sig);
  } catch (e) {
    return { ok: false, reason: `verify-failed: ${e.message}` };
  }
  return valid ? { ok: true } : { ok: false, reason: 'bad-signature' };
}

module.exports = {
  ROOM_GRANT_DOMAIN,
  signRoomGrant,
  verifyRoomGrant,
  grantShapeReason,
  grantForWire,
  roomGrantPayload,
  isOwnableRoom,
  MAX_GRANT_LIFETIME_MS,
  EXPIRY_SKEW_MS,
};
