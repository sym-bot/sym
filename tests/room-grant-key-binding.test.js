/**
 * FAILING TEST — a room-join grant is a BEARER TOKEN, not a credential bound to a node.
 * Written for sym-dev-team-1 (2026-09-16) after both of us read the code and reached the same
 * conclusion from greps. A test is worth more than either grep, so here is the thing itself.
 *
 *   Run:  node room-grant-bearer.test.js         (no framework; exits 1 on the vulnerability)
 *
 * WHAT IT ASSERTS
 *   1. `signRoomGrant` binds `granteeKey` into the signed payload (lib/core/room-grant.js:98).
 *   2. `verifyRoomGrant` ACCEPTS that grant when presented by a party holding a DIFFERENT key,
 *      because its expectations are only {room, grantee} (room-grant.js:151-159).
 *   3. The node's own admission rule (lib/node.js:2683-2691) therefore admits an impostor: the
 *      grantee id it compares against is `handshakeMsg.nodeId`, which `_buildHandshake` (2596)
 *      asserts with no proof, and handshake-v2 is not reachable from the connection path.
 *
 * Test 3 replicates those four lines rather than booting a node, so the test states the rule it
 * is testing in full and cannot drift silently if the surrounding method is refactored. If you
 * prefer it against a live node, say so and I will rewrite it that way.
 *
 * EXPECTED AFTER THE FIX: assertions 2 and 3 flip — `verifyRoomGrant` must refuse when the
 * presenter's PROVEN identity key is not `grant.granteeKey`, and a gated room must require a
 * proving handshake. Change `EXPECT_VULNERABLE` to false and this becomes the regression test.
 */
const crypto = require('node:crypto');
const path = require('node:path');
const SYM = process.env.SYM_DIR || path.join(__dirname, '..');
const { signRoomGrant, verifyRoomGrant } = require(path.join(SYM, 'lib/core/room-grant.js'));

const EXPECT_VULNERABLE = false;   // FIXED 2026-09-16: the verifier requires a PROVEN key and fails closed without one

const b64u = (buf) => Buffer.from(buf).toString('base64url');
function ed25519() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    pub: b64u(publicKey.export({ type: 'spki', format: 'der' }).subarray(-32)),
    privB64: b64u(privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32)),   // raw 32-byte seed, as cmb-signing expects
    priv: privateKey,
  };
}

const owner = ed25519();           // the room's owner
const invitee = ed25519();         // the node the owner MEANT to admit
const impostor = ed25519();        // anyone who sees the invite URL

const ROOM = 'first-scar-strike';
const OWNER_ID = '018f47a0-7b21-7abc-8def-0000000000a1'; // lowercase UUIDs: MMP §5.8.1's grant schema
const INVITEE_ID = '018f47a0-7b21-7abc-8def-0000000000a2';

let failures = 0;
const check = (name, got, want) => {
  const ok = got === want;
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}  (got ${got}, want ${want})`);
};

// ── 1 · the grant binds the invitee's key, as the design document promises
const grant = signRoomGrant({
  room: ROOM, grantee: INVITEE_ID, granteeKey: invitee.pub, grantedBy: OWNER_ID,
}, owner.privB64);
check('grant carries granteeKey', grant.granteeKey === invitee.pub, true);
check('grant is owner-signed', typeof grant.sig === 'string' && grant.sigAlg === 'ed25519', true);

// ── 2 · verifyRoomGrant now enforces the binding the grant carries
// With the invitee's key PROVEN, the grant admits — this is the only way in.
const asInvitee = verifyRoomGrant(grant, owner.pub, { room: ROOM, grantee: INVITEE_ID, provenKey: invitee.pub });
check('the real invitee is admitted WHEN ITS KEY IS PROVEN', asInvitee.ok, true);

// Without proof, nobody is admitted — including the legitimate invitee. That is the point: the
// old handshake only ASSERTS a key, and the key an impostor must assert is printed inside the
// grant it holds, so "check the asserted key" would be no bar at all. A gated room therefore
// stays shut until the proving handshake (lib/core/handshake-v2.js) reaches this path.
const unproven = verifyRoomGrant(grant, owner.pub, { room: ROOM, grantee: INVITEE_ID });
check('an UNPROVEN presenter is refused, invitee or not', unproven.ok, false);
check('  and the refusal says why', /no-proven-key/.test(String(unproven.reason)), true);

// the impostor presents the SAME grant, proving a key that is not the bound one.
const asImpostor = verifyRoomGrant(grant, owner.pub, { room: ROOM, grantee: INVITEE_ID, provenKey: impostor.pub });
check('IMPOSTOR IS ADMITTED BY verifyRoomGrant', asImpostor.ok, EXPECT_VULNERABLE);
check('  impostor refusal names the key mismatch', /grantee-key-mismatch/.test(String(asImpostor.reason)), true);

// the two guards that DO hold, so the test cannot be read as "nothing works"
check('a grant for another room is refused',
  verifyRoomGrant(grant, owner.pub, { room: 'another-room', grantee: INVITEE_ID }).reason, 'room-mismatch');
check('a grant for another grantee is refused',
  verifyRoomGrant(grant, owner.pub, { room: ROOM, grantee: 'node-someone-else' }).reason, 'grantee-mismatch');

// ── 3 · the node's admission rule, replicated from lib/node.js:2683-2691
function roomAdmission({ room, owner: ownerPin, handshakeMsg, peerId }) {
  const claimed = handshakeMsg && handshakeMsg.room;
  if (!claimed) return { admit: true, reason: 'no room claimed' };
  if (claimed !== room) return { admit: false, reason: 'room-mismatch' };
  if (!ownerPin) return { admit: true, reason: 'ungated' };
  const granteeId = (handshakeMsg && handshakeMsg.nodeId) || peerId;      // ← self-asserted
  if (granteeId === ownerPin.nodeId) return { admit: true, reason: 'owner' };
  const g = handshakeMsg && handshakeMsg.roomGrant;
  if (!g) return { admit: false, reason: 'no room-join grant presented for a gated room' };
  const v = verifyRoomGrant(g, ownerPin.publicKey, { room, grantee: granteeId });
  return v.ok ? { admit: true } : { admit: false, reason: `room-join grant refused: ${v.reason}` };
}

// the impostor speaks the invitee's nodeId, presents the invite it copied, and offers ITS OWN key
const impostorHandshake = {
  type: 'handshake', nodeId: INVITEE_ID, name: 'not-the-invitee', version: '0.2.3',
  room: ROOM, roomGrant: grant, publicKey: impostor.pub, e2ePublicKey: impostor.pub,
};
const decision = roomAdmission({
  room: ROOM, owner: { nodeId: OWNER_ID, publicKey: owner.pub },
  handshakeMsg: impostorHandshake, peerId: 'peer-impostor',
});
check('IMPOSTOR IS ADMITTED TO THE GATED ROOM', decision.admit, EXPECT_VULNERABLE);
console.log(`      admission said: ${JSON.stringify(decision)}`);
console.log(`      the grant bound ${grant.granteeKey.slice(0, 12)}…, the presenter offered ${impostor.pub.slice(0, 12)}…`);

console.log(failures === 0
  ? `\nAll ${EXPECT_VULNERABLE ? 'assertions hold — the vulnerability is present as described' : 'assertions hold — the key binding is enforced'}.`
  : `\n${failures} assertion(s) did not hold — the code no longer behaves as this test describes.`);
process.exit(failures === 0 ? 0 : 1);
