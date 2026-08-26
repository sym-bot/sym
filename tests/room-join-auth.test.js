'use strict';

/**
 * Room join authorization — the grant (core/room-grant.js) and the receiver's
 * ownership registry (room-ownership.js). Founder ruling 2026-08-26, option B as
 * folded by the mesh review; every ruled property is pinned here.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const {
  signRoomGrant, verifyRoomGrant, isOwnableRoom, roomGrantPayload, ROOM_GRANT_DOMAIN,
  MAX_GRANT_LIFETIME_MS, EXPIRY_SKEW_MS,
} = require('../lib/core/room-grant');
const { RoomOwnershipRegistry } = require('../lib/room-ownership');

/** A raw Ed25519 keypair in the base64url form the signing helpers take. */
function keypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    pub: publicKey.export({ type: 'spki', format: 'der' }).subarray(12).toString('base64url'),
    priv: privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(16).toString('base64url'),
  };
}

const ROOM = 'x-review--team-02779b950c3d8d7378fd11d6';

describe('room ownability — derived from the mapping, not a hardcoded list', () => {
  it('ordinary and tenant-suffixed rooms are ownable', () => {
    assert.strictEqual(isOwnableRoom('backend-team'), true);
    assert.strictEqual(isOwnableRoom(ROOM), true);
  });

  it('default is never ownable — it is the public mesh by rule', () => {
    assert.strictEqual(isOwnableRoom('default'), false);
  });

  it('sym is refused structurally: its service type collapses onto default', () => {
    // roomServiceType('sym') === '_sym._tcp' and the inverse is 'default', so an
    // "owned" room named sym would silently BE the public square (grammar review F5).
    assert.strictEqual(isOwnableRoom('sym'), false);
  });

  it('an invalid room name is not ownable', () => {
    for (const bad of ['UPPER', 'has space', '-leading', 'a---b', '']) {
      assert.strictEqual(isOwnableRoom(bad), false, bad);
    }
  });
});

describe('the grant — mint and verify', () => {
  it('a grant minted by the owner verifies against the owner key', () => {
    const owner = keypair(), grantee = keypair();
    const g = signRoomGrant({ room: ROOM, grantee: 'node-b', granteeKey: grantee.pub, grantedBy: 'node-a' }, owner.priv);
    assert.deepStrictEqual(verifyRoomGrant(g, owner.pub, { room: ROOM, grantee: 'node-b' }), { ok: true });
  });

  it('a DIFFERENT key never verifies it — the signature is the whole gate', () => {
    const owner = keypair(), impostor = keypair();
    const g = signRoomGrant({ room: ROOM, grantee: 'node-b', grantedBy: 'node-a' }, owner.priv);
    assert.strictEqual(verifyRoomGrant(g, impostor.pub, { room: ROOM }).ok, false);
  });

  it('a grant for one room cannot be replayed into another', () => {
    const owner = keypair();
    const g = signRoomGrant({ room: ROOM, grantee: 'node-b', grantedBy: 'node-a' }, owner.priv);
    const moved = { ...g, room: 'other-room--team-0123456789abcdef01234567' };
    assert.strictEqual(verifyRoomGrant(moved, owner.pub, { room: moved.room }).ok, false, 'signature binds the room');
    assert.strictEqual(verifyRoomGrant(g, owner.pub, { room: 'other-room' }).reason, 'room-mismatch');
  });

  it('a grant for one grantee cannot be presented by another', () => {
    const owner = keypair();
    const g = signRoomGrant({ room: ROOM, grantee: 'node-b', grantedBy: 'node-a' }, owner.priv);
    assert.strictEqual(verifyRoomGrant(g, owner.pub, { room: ROOM, grantee: 'node-c' }).reason, 'grantee-mismatch');
  });

  it('the grantee key is bound: swapping it breaks the signature', () => {
    const owner = keypair(), a = keypair(), b = keypair();
    const g = signRoomGrant({ room: ROOM, grantee: 'node-b', granteeKey: a.pub, grantedBy: 'node-a' }, owner.priv);
    assert.strictEqual(verifyRoomGrant({ ...g, granteeKey: b.pub }, owner.pub, { room: ROOM }).ok, false);
  });

  it('an unownable room cannot be granted at all, at mint or at verify', () => {
    const owner = keypair();
    assert.throws(() => signRoomGrant({ room: 'sym', grantee: 'n', grantedBy: 'o' }, owner.priv), /cannot be owned/);
    assert.throws(() => signRoomGrant({ room: 'default', grantee: 'n', grantedBy: 'o' }, owner.priv), /cannot be owned/);
  });
});

describe('the payload is injective — a delimiter cannot shift a field boundary', () => {
  it('the pipe-collision that a delimiter-joined encoding would have signed away', () => {
    // Under `${grantee}|${granteeKey}` these two produce IDENTICAL bytes, so ONE owner
    // signature would authorise a grantee the owner never named. Length-prefixing is
    // what makes them different documents.
    const a = roomGrantPayload({ room: ROOM, grantee: 'x|y', granteeKey: 'z', grantedBy: 'o', grantedAt: 1, expiresAt: 2 });
    const b = roomGrantPayload({ room: ROOM, grantee: 'x', granteeKey: 'y|z', grantedBy: 'o', grantedAt: 1, expiresAt: 2 });
    assert.ok(!a.equals(b), 'distinct grants must never share a preimage');
  });

  it('a grant signed for one grantee does not verify when re-split across the key field', () => {
    const owner = keypair();
    const g = signRoomGrant({ room: ROOM, grantee: 'x|y', granteeKey: 'z', grantedBy: 'o' }, owner.priv);
    const resplit = { ...g, grantee: 'x', granteeKey: 'y|z' };
    assert.strictEqual(verifyRoomGrant(resplit, owner.pub, { room: ROOM, grantee: 'x' }).ok, false);
  });

  it('the domain separator keeps a room grant from being read as any other signed object', () => {
    const p = roomGrantPayload({ room: ROOM, grantee: 'b', granteeKey: '', grantedBy: 'o', grantedAt: 1, expiresAt: 2 });
    assert.ok(p.subarray(0, ROOM_GRANT_DOMAIN.length).toString('utf8') === ROOM_GRANT_DOMAIN);
  });
});

describe('the 24h cap IS the offline-revocation window — enforced by the receiver', () => {
  it('the minter clamps a longer request to the cap', () => {
    const owner = keypair();
    const now = 1_700_000_000_000;
    const g = signRoomGrant({ room: ROOM, grantee: 'b', grantedBy: 'a', grantedAt: now, expiresAt: now + 365 * 86400_000 }, owner.priv);
    assert.strictEqual(g.expiresAt, now + MAX_GRANT_LIFETIME_MS, 'clamped at mint');
  });

  it('and a hand-rolled over-cap grant is REFUSED by the verifier, not truncated', () => {
    // the cap must not be a number the far end gets to choose: a minter that skips
    // the clamp (or a hostile one) must not buy a longer window from this receiver
    const owner = keypair();
    const now = 1_700_000_000_000;
    const g = { type: 'room-join', room: ROOM, grantee: 'b', granteeKey: '', grantedBy: 'a', grantedAt: now, expiresAt: now + 30 * 86400_000 };
    g.sig = crypto.sign(null,
      Buffer.from(`room-join|${g.room}|${g.grantee}||${g.grantedBy}|${g.grantedAt}|${g.expiresAt}`, 'utf8'),
      crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(owner.priv, 'base64url')]), format: 'der', type: 'pkcs8' })).toString('base64url');
    g.sigAlg = 'ed25519';
    const v = verifyRoomGrant(g, owner.pub, { room: ROOM, now: now + 1000 });
    assert.strictEqual(v.ok, false);
    assert.strictEqual(v.reason, 'lifetime-exceeds-cap', 'refused outright — the window is never the sender\'s choice');
  });

  it('an expired grant is refused, and skew is tolerated at the boundary', () => {
    const owner = keypair();
    const now = 1_700_000_000_000;
    const g = signRoomGrant({ room: ROOM, grantee: 'b', grantedBy: 'a', grantedAt: now, expiresAt: now + 60_000 }, owner.priv);
    assert.strictEqual(verifyRoomGrant(g, owner.pub, { room: ROOM, now: now + 30_000 }).ok, true, 'live');
    assert.strictEqual(verifyRoomGrant(g, owner.pub, { room: ROOM, now: now + 60_000 + EXPIRY_SKEW_MS - 1 }).ok, true, 'inside skew');
    assert.strictEqual(verifyRoomGrant(g, owner.pub, { room: ROOM, now: now + 60_000 + EXPIRY_SKEW_MS + 1 }).reason, 'expired');
  });

  it('a grant from the future is refused beyond skew', () => {
    const owner = keypair();
    const now = 1_700_000_000_000;
    const g = signRoomGrant({ room: ROOM, grantee: 'b', grantedBy: 'a', grantedAt: now, expiresAt: now + 3600_000 }, owner.priv);
    assert.strictEqual(verifyRoomGrant(g, owner.pub, { room: ROOM, now: now - EXPIRY_SKEW_MS - 1 }).reason, 'not-yet-valid');
  });

  it('unsigned, wrong-typed and key-less inputs all fail closed', () => {
    const owner = keypair();
    const g = signRoomGrant({ room: ROOM, grantee: 'b', grantedBy: 'a' }, owner.priv);
    assert.strictEqual(verifyRoomGrant({ ...g, sig: undefined }, owner.pub, {}).reason, 'unsigned');
    assert.strictEqual(verifyRoomGrant({ ...g, type: 'role-grant' }, owner.pub, {}).reason, 'not-a-room-join-grant');
    assert.strictEqual(verifyRoomGrant(g, null, {}).reason, 'no-owner-key-pinned');
    assert.strictEqual(verifyRoomGrant(null, owner.pub, {}).ok, false);
  });
});

describe('ownership registry — out-of-band only, precedence, and open-by-default', () => {
  const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'room-own-'));

  it('a room with no owner is OPEN — nothing existing changes on upgrade day', () => {
    const r = new RoomOwnershipRegistry();
    assert.strictEqual(r.isGated('backend-team'), false);
    assert.strictEqual(r.ownerOf('backend-team'), null);
    assert.strictEqual(r.modeOf('backend-team'), 'open');
  });

  it('an owner makes the room gated, and the mode is reportable to an operator', () => {
    const r = new RoomOwnershipRegistry();
    const o = keypair();
    assert.deepStrictEqual(r.pin(ROOM, 'node-a', o.pub, 'own'), { pinned: true });
    assert.strictEqual(r.isGated(ROOM), true);
    assert.strictEqual(r.modeOf(ROOM), 'gated');
    assert.strictEqual(r.ownerOf(ROOM).nodeId, 'node-a');
  });

  it('a weaker source cannot re-point a room, and the attempt is kept as evidence', () => {
    const r = new RoomOwnershipRegistry();
    const real = keypair(), impostor = keypair();
    r.pin(ROOM, 'node-a', real.pub, 'config');
    assert.strictEqual(r.pin(ROOM, 'evil', impostor.pub, 'invite').reason, 'conflict');
    assert.strictEqual(r.pin(ROOM, 'evil', impostor.pub, 'own').reason, 'conflict');
    assert.strictEqual(r.ownerOf(ROOM).nodeId, 'node-a', 'unchanged');
    assert.strictEqual(r.conflicts().length, 2, 'both refusals are evidence, not silence');
  });

  it('a strictly stronger source may correct a weaker binding', () => {
    const r = new RoomOwnershipRegistry();
    const a = keypair(), b = keypair();
    r.pin(ROOM, 'from-invite', a.pub, 'invite');
    assert.strictEqual(r.pin(ROOM, 'from-config', b.pub, 'config').pinned, true);
    assert.strictEqual(r.ownerOf(ROOM).nodeId, 'from-config');
  });

  it('re-affirming the same owner upgrades the recorded source without conflict', () => {
    const r = new RoomOwnershipRegistry();
    const o = keypair();
    r.pin(ROOM, 'node-a', o.pub, 'invite');
    assert.strictEqual(r.pin(ROOM, 'node-a', o.pub, 'config').pinned, true);
    assert.strictEqual(r.ownerOf(ROOM).source, 'config');
    assert.strictEqual(r.conflicts().length, 0);
  });

  it('there is NO wire source — an unknown source is refused outright', () => {
    const r = new RoomOwnershipRegistry();
    const o = keypair();
    for (const s of ['wire', 'gossip', 'grant', 'peer', '']) {
      assert.strictEqual(r.pin(ROOM, 'n', o.pub, s).reason, 'unknown-source', s);
    }
    assert.strictEqual(r.isGated(ROOM), false, 'nothing from the wire ever gated a room');
  });

  it('unownable rooms are refused by the registry too', () => {
    const r = new RoomOwnershipRegistry();
    const o = keypair();
    assert.strictEqual(r.pin('default', 'n', o.pub, 'config').reason, 'room-not-ownable');
    assert.strictEqual(r.pin('sym', 'n', o.pub, 'config').reason, 'room-not-ownable');
  });

  it('ownership survives a restart, and the reload does not fabricate conflicts', () => {
    const dir = tmp();
    const o = keypair();
    const first = new RoomOwnershipRegistry({ dir });
    first.pin(ROOM, 'node-a', o.pub, 'config');
    const second = new RoomOwnershipRegistry({ dir });
    assert.strictEqual(second.ownerOf(ROOM).nodeId, 'node-a');
    assert.strictEqual(second.ownerOf(ROOM).source, 'config');
    assert.strictEqual(second.conflicts().length, 0, 'replaying our own record is not a conflict');
  });
});

describe('end to end: the incident this exists to make impossible', () => {
  it('a peer with no grant cannot join a gated room; one with the owner\'s grant can', () => {
    const owner = keypair(), volunteer = keypair();
    const reg = new RoomOwnershipRegistry();
    reg.pin(ROOM, 'owner-node', owner.pub, 'own');

    // the stranger presents nothing — there is no path to admission
    assert.strictEqual(reg.isGated(ROOM), true);
    assert.strictEqual(verifyRoomGrant(null, reg.ownerOf(ROOM).publicKey, { room: ROOM }).ok, false);

    // the owner deliberately admits a FOREIGN crew — sharing as an act
    const grant = signRoomGrant(
      { room: ROOM, grantee: 'volunteer-node', granteeKey: volunteer.pub, grantedBy: 'owner-node' }, owner.priv);
    assert.strictEqual(
      verifyRoomGrant(grant, reg.ownerOf(ROOM).publicKey, { room: ROOM, grantee: 'volunteer-node' }).ok, true,
      'an open room stays possible — it is now a decision someone made');
  });
});
