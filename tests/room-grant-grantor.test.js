'use strict';

/**
 * The grant must NAME the hand that signed it — and the label must never be what selects the key.
 *
 * These live in their own file deliberately. They were first appended to
 * room-grant-key-binding.test.js, which is dev-team-3's standalone script: it calls process.exit()
 * at the end, so everything after it never ran and reported as a pass. That is the third instance
 * today of a check reporting success for something it never executed, and the second where the
 * check was mine.
 */
const { describe, it } = require('node:test');
const assert = require('node:assert');

describe('the grant must name the hand that signed it', () => {
  const crypto = require('node:crypto');
  const { signRoomGrant, verifyRoomGrant } = require('../lib/core/room-grant');
  const kp = () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    return {
      pub: publicKey.export({ type: 'spki', format: 'der' }).subarray(12).toString('base64url'),
      priv: privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(16).toString('base64url'),
    };
  };
  const ROOM2 = 'x-review--team-02779b950c3d8d7378fd11d6';
  // MMP §5.8.1's grant schema: nodeIds are lowercase UUIDs, the key is 43 base64url characters.
  const PEER = '018f47a0-7b21-7abc-8def-000000000001';
  const SOMEONE_ELSE = '018f47a0-7b21-7abc-8def-0000000000e1';
  const THE_OWNER = '018f47a0-7b21-7abc-8def-0000000000a1';
  const WHOEVER = '018f47a0-7b21-7abc-8def-0000000000b1';
  const PK = kp().pub;

  it('refuses a grant recording an issuer who is not the room owner, even when the OWNER signed it', () => {
    // Only the owner's key can produce this, so it is not an admission hole. But the grant IS the
    // evidence of admission, and an audit trail that names someone the cryptography does not
    // support is a record that cannot be relied on later.
    const owner = kp();
    const g = signRoomGrant({ room: ROOM2, grantee: PEER, granteeKey: PK, grantedBy: SOMEONE_ELSE }, owner.priv);
    const v = verifyRoomGrant(g, owner.pub, { room: ROOM2, grantee: PEER, provenKey: PK, ownerNodeId: THE_OWNER });
    assert.equal(v.ok, false);
    assert.match(v.reason, /grantor-not-owner/);
    assert.ok(v.reason.includes(SOMEONE_ELSE), 'the refusal must name what the grant claimed');
  });

  it('accepts a coherent grant', () => {
    const owner = kp();
    const g = signRoomGrant({ room: ROOM2, grantee: PEER, granteeKey: PK, grantedBy: THE_OWNER }, owner.priv);
    assert.equal(verifyRoomGrant(g, owner.pub, { room: ROOM2, grantee: PEER, provenKey: PK, ownerNodeId: THE_OWNER }).ok, true);
  });

  it('a grant signed by a MEMBER is refused by the signature, not merely by the coherence check', () => {
    // THE ENFORCEMENT, distinct from the diagnostic. Even with grantedBy set coherently to the
    // owner, a grant the owner did not sign must fail — because the key is selected by ROOM, never
    // by a field the credential carries. A verifier that looked the key up by grantedBy would
    // admit this, which is exactly the hole dev-team-3 found in their own implementation.
    const owner = kp(); const member = kp();
    const g = signRoomGrant({ room: ROOM2, grantee: PEER, granteeKey: PK, grantedBy: THE_OWNER }, member.priv);
    const v = verifyRoomGrant(g, owner.pub, { room: ROOM2, grantee: PEER, provenKey: PK, ownerNodeId: THE_OWNER });
    assert.equal(v.ok, false);
    assert.equal(v.reason, 'bad-signature', 'owner-only is enforced by the key, not by the label');
  });

  it('an older caller that passes no ownerNodeId still works', () => {
    const owner = kp();
    const g = signRoomGrant({ room: ROOM2, grantee: PEER, granteeKey: PK, grantedBy: WHOEVER }, owner.priv);
    assert.equal(verifyRoomGrant(g, owner.pub, { room: ROOM2, grantee: PEER, provenKey: PK }).ok, true);
  });
});
