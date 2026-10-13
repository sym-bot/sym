'use strict';

/**
 * The room door (design D6, Core Secure). The room is explicit and inside the §5.2 transcript: a
 * room mismatch, or a hello naming no room, closes the connection before admission (see
 * core-secure-session.test.js). What is left to decide is a GATED room: its owner is recognised by
 * its pinned key, and a grantee when its room-join grant's bound key equals the key its session
 * PROVED. Tested against the real prototype method with a minimal receiver stub.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');

const { SymNode } = require('../lib/node');
const { RoomOwnershipRegistry } = require('../lib/room-ownership');
const { signRoomGrant } = require('../lib/core/room-grant');

function keypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    pub: publicKey.export({ type: 'spki', format: 'der' }).subarray(12).toString('base64url'),
    priv: privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(16).toString('base64url'),
  };
}

const ROOM = 'x-review--team-02779b950c3d8d7378fd11d6';
// MMP §5.8.1's grant schema: nodeIds are lowercase UUIDs. A readable name stands for a fixed one.
const U = (name) => { const h = crypto.createHash('sha256').update(String(name)).digest('hex'); return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`; };

/** A receiver in `room`, optionally gating it with `owner`. */
function receiver(room, owner) {
  const owners = new RoomOwnershipRegistry();
  if (owner) owners.pin(room, owner.nodeId, owner.publicKey, 'config');
  return { _room: room, _roomOwners: owners, _log: () => {} };
}
/** The decision for a confirmed session that proved `key` for `nodeId`, presenting `grant`. */
const decide = (rcv, nodeId, key, grant) => SymNode.prototype._roomAdmissionDecide.call(rcv, { nodeId, identityKey: key, roomGrant: grant || null });

describe('ungated rooms admit every confirmed session', () => {
  it('a session in an ungated room is admitted with no grant, because none is required', () => {
    assert.deepStrictEqual(decide(receiver('backend-team'), 'p', keypair().pub), { admit: true });
    assert.deepStrictEqual(decide(receiver(ROOM), 'p', keypair().pub), { admit: true });
  });
});

describe('gated rooms — fail closed on proven keys, and the owner is never locked out', () => {
  it('a stranger with no grant is pending (refused when its handshake timeout passes)', () => {
    const owner = keypair();
    const r = receiver(ROOM, { nodeId: U('owner-node'), publicKey: owner.pub });
    assert.deepStrictEqual(decide(r, U('stranger'), keypair().pub), { pending: true });
  });

  it('the OWNER needs no grant in its own room — recognised by its pinned key, not its id', () => {
    const owner = keypair();
    const r = receiver(ROOM, { nodeId: U('owner-node'), publicKey: owner.pub });
    assert.strictEqual(decide(r, U('owner-node'), owner.pub).admit, true);
    const imp = decide(r, U('owner-node'), keypair().pub);
    assert.strictEqual(imp.admit, false, 'the owner\'s id under another key is not the owner');
    assert.match(imp.reason, /under another key/);
  });

  it('a grantee is admitted when the grant binds the key its session proved; an impostor proving its own key is not', () => {
    const owner = keypair(), volunteer = keypair();
    const r = receiver(ROOM, { nodeId: U('owner-node'), publicKey: owner.pub });
    const grant = signRoomGrant({ room: ROOM, grantee: U('volunteer'), granteeKey: volunteer.pub, grantedBy: U('owner-node') }, owner.priv);
    assert.strictEqual(decide(r, U('volunteer'), volunteer.pub, grant).admit, true, 'sharing stays possible, as an act');
    const imp = decide(r, U('volunteer'), keypair().pub, grant);
    assert.strictEqual(imp.admit, false, 'a copied grant admits nobody: the binding is enforced');
    assert.match(String(imp.reason), /grantee-key-mismatch/);
  });

  it('a grant minted by someone who is NOT the owner is refused', () => {
    const owner = keypair(), impostor = keypair(), evil = keypair();
    const r = receiver(ROOM, { nodeId: U('owner-node'), publicKey: owner.pub });
    const forged = signRoomGrant({ room: ROOM, grantee: U('evil'), granteeKey: evil.pub, grantedBy: U('owner-node') }, impostor.priv);
    const d = decide(r, U('evil'), evil.pub, forged);
    assert.strictEqual(d.admit, false);
    assert.match(d.reason, /grant refused/);
  });

  it('a valid grant issued to SOMEONE ELSE cannot be presented by this session', () => {
    const owner = keypair(), alice = keypair();
    const r = receiver(ROOM, { nodeId: U('owner-node'), publicKey: owner.pub });
    const grant = signRoomGrant({ room: ROOM, grantee: U('alice'), granteeKey: alice.pub, grantedBy: U('owner-node') }, owner.priv);
    const d = decide(r, U('mallory'), keypair().pub, grant);
    assert.strictEqual(d.admit, false);
    assert.match(d.reason, /grantee-mismatch/);
  });

  it('a grant that binds no key is a bearer token and is refused (§5.8.1)', () => {
    const owner = keypair(), bob = keypair();
    const r = receiver(ROOM, { nodeId: U('owner-node'), publicKey: owner.pub });
    assert.throws(() => signRoomGrant({ room: ROOM, grantee: U('bob'), grantedBy: U('owner-node') }, owner.priv), /not be well formed/, 'never minted');
    const keyed = signRoomGrant({ room: ROOM, grantee: U('bob'), granteeKey: bob.pub, grantedBy: U('owner-node') }, owner.priv);
    const { granteeKey, ...bearer } = keyed; void granteeKey;
    assert.strictEqual(decide(r, U('bob'), bob.pub, bearer).admit, false);
  });

  it('an expired grant is refused at join', () => {
    const owner = keypair(), late = keypair();
    const r = receiver(ROOM, { nodeId: U('owner-node'), publicKey: owner.pub });
    const longAgo = Date.now() - 48 * 3600_000;
    const grant = signRoomGrant(
      { room: ROOM, grantee: U('late'), granteeKey: late.pub, grantedBy: U('owner-node'), grantedAt: longAgo, expiresAt: longAgo + 3600_000 },
      owner.priv);
    assert.match(decide(r, U('late'), late.pub, grant).reason, /expired/);
  });
});

describe('the decision is made for every session before anything per-peer exists', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const src = fs.readFileSync(path.join(__dirname, '..', 'lib', 'node.js'), 'utf8');

  it('every confirmed session, client or server, goes through the door before it is admitted', () => {
    const confirmed = src.slice(src.indexOf('  _onSessionConfirmed(session) {'), src.indexOf('  _decideAdmission(session) {'));
    assert.match(confirmed, /this\._decideAdmission\(session\)/);
    assert.doesNotMatch(confirmed, /this\._peers\.set/, 'no peer is created at confirmation');
    const admit = src.slice(src.indexOf('  _admitSession(session) {'), src.indexOf('  _greetSession('));
    assert.match(admit, /this\._peers\.set/, 'the peer is created on admission only');
  });

  it('a frame from a session the door has not admitted is refused, except its room-join grant', () => {
    const frame = src.slice(src.indexOf('  _onSessionFrame(session, frame) {'), src.indexOf('  _onSessionClosed(session, info) {'));
    assert.match(frame, /state !== 'admitted'/);
    assert.match(frame, /'room-join'/, 'the room-join frame (draft spec PR #31; mesh-room-join until the rename)');
    assert.match(frame, /not-admitted/);
  });
});
