'use strict';

/**
 * Room join authorization — the grant (core/room-grant.js) and the receiver's
 * ownership registry (room-ownership.js). Founder ruling 2026-08-26, option B as
 * folded by the mesh review; every ruled property is pinned here.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { tmpdir } = require('./_tmpdir');

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

// MMP §5.8.1's grant schema: grantee and grantedBy are lowercase UUIDs, and a grant names the key
// it binds. A readable name in these tests stands for a fixed UUID; a grant minted without a key
// binds a fresh one.
const U = (name) => { if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(String(name))) return name; const h = crypto.createHash('sha256').update(String(name)).digest('hex'); return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`; };
function mint(fields, priv) {
  return signRoomGrant({ ...fields, grantee: U(fields.grantee), grantedBy: U(fields.grantedBy), granteeKey: fields.granteeKey || keypair().pub }, priv);
}

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
    for (const bad of ['UPPER', 'has space', 'café', 'x'.repeat(65), '']) {
      assert.strictEqual(isOwnableRoom(bad), false, bad);
    }
  });
});

describe('the grant — mint and verify', () => {
  it('a grant minted by the owner verifies against the owner key', () => {
    const owner = keypair(), grantee = keypair();
    const g = mint({ room: ROOM, grantee: U('node-b'), granteeKey: grantee.pub, grantedBy: 'node-a' }, owner.priv);
    assert.deepStrictEqual(verifyRoomGrant(g, owner.pub, { room: ROOM, grantee: U('node-b'), provenKey: grantee.pub }), { ok: true });
  });

  it('a DIFFERENT key never verifies it — the signature is the whole gate', () => {
    const owner = keypair(), impostor = keypair();
    const g = mint({ room: ROOM, grantee: U('node-b'), grantedBy: 'node-a' }, owner.priv);
    assert.strictEqual(verifyRoomGrant(g, impostor.pub, { room: ROOM, grantee: U('node-b'), provenKey: 'proof-not-under-test' }).ok, false);
  });

  it('a grant for one room cannot be replayed into another', () => {
    const owner = keypair();
    const g = mint({ room: ROOM, grantee: U('node-b'), grantedBy: 'node-a' }, owner.priv);
    const moved = { ...g, room: 'other-room--team-0123456789abcdef01234567' };
    assert.strictEqual(verifyRoomGrant(moved, owner.pub, { room: moved.room, grantee: U('node-b'), provenKey: 'proof-not-under-test' }).ok, false, 'signature binds the room');
    assert.strictEqual(verifyRoomGrant(g, owner.pub, { room: 'other-room', grantee: U('node-b'), provenKey: 'proof-not-under-test' }).reason, 'room-mismatch');
  });

  it('a grant for one grantee cannot be presented by another', () => {
    const owner = keypair();
    const g = mint({ room: ROOM, grantee: U('node-b'), grantedBy: 'node-a' }, owner.priv);
    assert.strictEqual(verifyRoomGrant(g, owner.pub, { room: ROOM, grantee: U('node-c'), provenKey: 'proof-not-under-test' }).reason, 'grantee-mismatch');
  });

  it('the grantee key is bound: swapping it breaks the signature', () => {
    const owner = keypair(), a = keypair(), b = keypair();
    const g = mint({ room: ROOM, grantee: U('node-b'), granteeKey: a.pub, grantedBy: 'node-a' }, owner.priv);
    assert.strictEqual(verifyRoomGrant({ ...g, granteeKey: b.pub }, owner.pub, { room: ROOM, grantee: U('node-b'), provenKey: 'proof-not-under-test' }).ok, false);
  });

  it('an unownable room cannot be granted at all, at mint or at verify', () => {
    const owner = keypair();
    assert.throws(() => mint({ room: 'sym', grantee: U('n'), grantedBy: 'o' }, owner.priv), /cannot be owned/);
    assert.throws(() => mint({ room: 'default', grantee: U('n'), grantedBy: 'o' }, owner.priv), /cannot be owned/);
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

  it('a grant cannot even be minted for a grantee that is not a UUID, so there is nothing to re-split', () => {
    const owner = keypair();
    assert.throws(() => signRoomGrant({ room: ROOM, grantee: 'x|y', granteeKey: keypair().pub, grantedBy: U('o') }, owner.priv), /not be well formed/);
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
    const g = mint({ room: ROOM, grantee: U('b'), grantedBy: 'a', grantedAt: now, expiresAt: now + 365 * 86400_000 }, owner.priv);
    assert.strictEqual(g.expiresAt, now + MAX_GRANT_LIFETIME_MS, 'clamped at mint');
  });

  it('and a hand-rolled over-cap grant is REFUSED by the verifier, not truncated', () => {
    // the cap must not be a number the far end gets to choose: a minter that skips
    // the clamp (or a hostile one) must not buy a longer window from this receiver
    const owner = keypair();
    const now = 1_700_000_000_000;
    const k = keypair().pub;
    const g = { type: 'room-join', room: ROOM, grantee: U('b'), granteeKey: k, grantedBy: U('a'), grantedAt: now, expiresAt: now + 30 * 86400_000 };
    g.sig = crypto.sign(null, roomGrantPayload(g),
      crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(owner.priv, 'base64url')]), format: 'der', type: 'pkcs8' })).toString('base64url');
    g.sigAlg = 'ed25519';
    const v = verifyRoomGrant(g, owner.pub, { room: ROOM, grantee: U('b'), provenKey: k, now: now + 1000 });
    assert.strictEqual(v.ok, false);
    assert.strictEqual(v.reason, 'lifetime-exceeds-cap', 'refused outright — the window is never the sender\'s choice');
  });

  it('an expired grant is refused, and skew is tolerated at the boundary', () => {
    const owner = keypair(), inv = keypair();
    const now = 1_700_000_000_000;
    const g = mint({ room: ROOM, grantee: U('b'), granteeKey: inv.pub, grantedBy: 'a', grantedAt: now, expiresAt: now + 60_000 }, owner.priv);
    assert.strictEqual(verifyRoomGrant(g, owner.pub, { room: ROOM, grantee: U('b'), provenKey: inv.pub, now: now + 30_000 }).ok, true, 'live');
    assert.strictEqual(verifyRoomGrant(g, owner.pub, { room: ROOM, grantee: U('b'), provenKey: inv.pub, now: now + 60_000 + EXPIRY_SKEW_MS - 1 }).ok, true, 'inside skew');
    assert.strictEqual(verifyRoomGrant(g, owner.pub, { room: ROOM, grantee: U('b'), provenKey: inv.pub, now: now + 60_000 + EXPIRY_SKEW_MS + 1 }).reason, 'expired');
  });

  it('a grant from the future is refused beyond skew', () => {
    const owner = keypair(), inv = keypair();
    const now = 1_700_000_000_000;
    const g = mint({ room: ROOM, grantee: U('b'), granteeKey: inv.pub, grantedBy: 'a', grantedAt: now, expiresAt: now + 3600_000 }, owner.priv);
    assert.strictEqual(verifyRoomGrant(g, owner.pub, { room: ROOM, grantee: U('b'), provenKey: inv.pub, now: now - EXPIRY_SKEW_MS - 1 }).reason, 'not-yet-valid');
  });

  it('unsigned, wrong-typed and key-less inputs all fail closed', () => {
    const owner = keypair();
    const g = mint({ room: ROOM, grantee: U('b'), grantedBy: 'a' }, owner.priv);
    assert.strictEqual(verifyRoomGrant({ ...g, sig: undefined }, owner.pub, { room: ROOM, grantee: U('b') }).reason, 'unsigned');
    assert.strictEqual(verifyRoomGrant({ ...g, type: 'role-grant' }, owner.pub, { room: ROOM, grantee: U('b') }).reason, 'not-a-room-join-grant');
    assert.strictEqual(verifyRoomGrant(g, null, { room: ROOM, grantee: U('b') }).reason, 'no-owner-key-pinned');
    assert.strictEqual(verifyRoomGrant(null, owner.pub, { room: ROOM, grantee: U('b') }).ok, false);
  });
});

describe('ownership registry — out-of-band only, precedence, and open-by-default', () => {
  const tmp = () => tmpdir('room-own-');

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

  it('ownership survives a restart — but comes back as a CACHE, not as operator authority', () => {
    const dir = tmp();
    const o = keypair();
    const first = new RoomOwnershipRegistry({ dir });
    first.pin(ROOM, 'node-a', o.pub, 'config');

    const second = new RoomOwnershipRegistry({ dir });
    assert.strictEqual(second.ownerOf(ROOM).nodeId, 'node-a', 'the room stays gated across a restart');
    assert.strictEqual(second.ownerOf(ROOM).source, 'own',
      'a replayed record never restores itself at the operator rank — the file is unsigned');
    assert.strictEqual(second.conflicts().length, 0, 'replaying our own record is not a conflict');

    const third = new RoomOwnershipRegistry({ dir, owners: [{ room: ROOM, nodeId: 'node-a', publicKey: o.pub }] });
    assert.strictEqual(third.ownerOf(ROOM).source, 'config', 'boot-time config re-establishes the authority');
  });
});

describe('end to end: the incident this exists to make impossible', () => {
  it('a peer with no grant cannot join a gated room; one with the owner\'s grant can', () => {
    const owner = keypair(), volunteer = keypair();
    const reg = new RoomOwnershipRegistry();
    reg.pin(ROOM, 'owner-node', owner.pub, 'own');

    // the stranger presents nothing — there is no path to admission
    assert.strictEqual(reg.isGated(ROOM), true);
    assert.strictEqual(verifyRoomGrant(null, reg.ownerOf(ROOM).publicKey, { room: ROOM, grantee: U('stranger-node'), provenKey: 'anything' }).ok, false);

    // the owner deliberately admits a FOREIGN crew — sharing as an act
    const grant = mint(
      { room: ROOM, grantee: 'volunteer-node', granteeKey: volunteer.pub, grantedBy: 'owner-node' }, owner.priv);
    assert.strictEqual(
      verifyRoomGrant(grant, reg.ownerOf(ROOM).publicKey, { room: ROOM, grantee: U('volunteer-node'), provenKey: volunteer.pub }).ok, true,
      'an open room stays possible — it is now a decision someone made');
  });
});

describe('review folds — the guard cannot be defeated by how it is CALLED', () => {
  it('F2: omitting the expectation is a refusal, never a pass — no bearer tokens', () => {
    const owner = keypair();
    const g = mint({ room: ROOM, grantee: U('b'), grantedBy: 'a' }, owner.priv);
    // the old default returned ok here: any copy of any unexpired grant, presented by anyone
    assert.strictEqual(verifyRoomGrant(g, owner.pub).reason, 'no-expectation');
    assert.strictEqual(verifyRoomGrant(g, owner.pub, {}).reason, 'no-expectation');
    assert.strictEqual(verifyRoomGrant(g, owner.pub, { room: ROOM }).reason, 'no-expectation', 'room alone is not enough');
    assert.strictEqual(verifyRoomGrant(g, owner.pub, { grantee: U('b') }).reason, 'no-expectation', 'grantee alone is not enough');
    // AND THE HALF THIS TEST WAS NAMED FOR BUT DID NOT COVER (2026-09-16): room + grantee alone
    // used to admit, which made the grant a bearer token for anyone holding the string. A proven
    // key is now part of the expectation, and its absence is a refusal like any other.
    assert.strictEqual(verifyRoomGrant(g, owner.pub, { room: ROOM, grantee: U('b') }).ok, false, 'room + grantee alone is a bearer token');
    assert.match(String(verifyRoomGrant(g, owner.pub, { room: ROOM, grantee: U('b') }).reason), /no-proven-key/);
  });
});

describe('review folds — the state file is a cache, not an authority', () => {
  const tmp = () => tmpdir('room-own-fold-');

  it('F4: a hand-written record claiming source:config loads at most as own, and config overrides it', () => {
    const dir = tmp();
    const evil = keypair(), real = keypair();
    fs.writeFileSync(path.join(dir, 'room-owners.jsonl'),
      JSON.stringify({ room: ROOM, nodeId: 'attacker', publicKey: evil.pub, source: 'config' }) + '\n');
    const r = new RoomOwnershipRegistry({ dir });
    assert.strictEqual(r.ownerOf(ROOM).source, 'own', 'the disk cannot name the operator rank');
    // and the operator's boot-time config wins outright
    const r2 = new RoomOwnershipRegistry({ dir, owners: [{ room: ROOM, nodeId: 'real', publicKey: real.pub }] });
    assert.strictEqual(r2.ownerOf(ROOM).nodeId, 'real');
    assert.strictEqual(r2.ownerOf(ROOM).source, 'config');
  });

  it('F5: reload is replay-EXACT — the last accepted write wins, so two processes agree', () => {
    const dir = tmp();
    const a = keypair(), b = keypair();
    const first = new RoomOwnershipRegistry({ dir });
    first.pin(ROOM, 'node-a', a.pub, 'config');
    first.repin(ROOM, 'node-b', b.pub, 'config');          // a deliberate rotation
    const reloaded = new RoomOwnershipRegistry({ dir });
    assert.strictEqual(reloaded.ownerOf(ROOM).nodeId, 'node-b', 'not the first line');
    assert.strictEqual(reloaded.conflicts().length, 0, 'a replay of our own log is not a conflict');
  });

  it('F6: an operator can rotate a compromised owner key without hand-editing state', () => {
    const r = new RoomOwnershipRegistry();
    const old = keypair(), fresh = keypair();
    r.pin(ROOM, 'node-a', old.pub, 'config');
    assert.strictEqual(r.pin(ROOM, 'node-a', fresh.pub, 'config').reason, 'conflict', 'pin still refuses');
    assert.strictEqual(r.repin(ROOM, 'node-a', fresh.pub, 'config').pinned, true);
    assert.strictEqual(r.ownerOf(ROOM).publicKey, fresh.pub);
    assert.ok(r.conflicts().some((c) => c.replaced), 'the rotation is visible, not silent');
  });
});
