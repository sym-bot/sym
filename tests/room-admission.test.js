'use strict';

/**
 * Stage 2 — the handshake admission decision (SymNode#_roomAdmission).
 *
 * Before this existed, NOTHING compared the room at all: the handshake has always
 * carried `room` and bound it into the signed transcript, but no receiver looked, so a
 * peer announcing any room joined the peer set and LAN isolation was a property of the
 * mDNS browse filter rather than of any check.
 *
 * Tested against the real prototype method with a minimal receiver stub, so these pin the
 * shipped implementation rather than a re-description of it.
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

/** A receiver in `room`, optionally gating it with `owner`. */
function receiver(room, owner) {
  const owners = new RoomOwnershipRegistry();
  if (owner) owners.pin(room, owner.nodeId, owner.publicKey, 'config');
  return { _room: room, _roomOwners: owners };
}
const admit = (rcv, peerId, msg) => SymNode.prototype._roomAdmission.call(rcv, peerId, msg);

describe('the room comparison that did not exist', () => {
  it('a peer claiming a DIFFERENT room is refused, even when the room is ungated', () => {
    const r = receiver('backend-team');
    const d = admit(r, 'peer-1', { nodeId: 'peer-1', room: 'someone-elses-room' });
    assert.strictEqual(d.admit, false);
    assert.match(d.reason, /room-mismatch/);
  });

  it('a handshake with no room at all is treated as `default` and refused elsewhere', () => {
    assert.strictEqual(admit(receiver('backend-team'), 'p', { nodeId: 'p' }).admit, false);
    assert.strictEqual(admit(receiver('default'), 'p', { nodeId: 'p' }).admit, true, 'and admitted in default');
  });
});

describe('ungated rooms are unchanged — upgrade day moves nothing', () => {
  it('a matching room with no owner admits exactly as before', () => {
    assert.strictEqual(admit(receiver(ROOM), 'peer-1', { nodeId: 'peer-1', room: ROOM }).admit, true);
  });

  it('and it admits with no grant presented, because none is required', () => {
    const d = admit(receiver('backend-team'), 'p', { nodeId: 'p', room: 'backend-team', roomGrant: undefined });
    assert.strictEqual(d.admit, true);
  });
});

describe('gated rooms — fail closed, and the owner is never locked out', () => {
  it('a stranger with no grant is refused', () => {
    const owner = keypair();
    const r = receiver(ROOM, { nodeId: 'owner-node', publicKey: owner.pub });
    const d = admit(r, 'stranger', { nodeId: 'stranger', room: ROOM });
    assert.strictEqual(d.admit, false);
    assert.match(d.reason, /no room-join grant/);
  });

  it('the OWNER needs no grant in its own room', () => {
    const owner = keypair();
    const r = receiver(ROOM, { nodeId: 'owner-node', publicKey: owner.pub });
    assert.strictEqual(admit(r, 'owner-node', { nodeId: 'owner-node', room: ROOM }).admit, true);
  });

  it('a foreign peer WITH the owner\'s grant is admitted — sharing stays possible, as an act', () => {
    const owner = keypair(), volunteer = keypair();
    const r = receiver(ROOM, { nodeId: 'owner-node', publicKey: owner.pub });
    const grant = signRoomGrant(
      { room: ROOM, grantee: 'volunteer', granteeKey: volunteer.pub, grantedBy: 'owner-node' }, owner.priv);
    assert.strictEqual(admit(r, 'volunteer', { nodeId: 'volunteer', room: ROOM, roomGrant: grant }).admit, true);
  });

  it('a grant minted by someone who is NOT the owner is refused', () => {
    const owner = keypair(), impostor = keypair();
    const r = receiver(ROOM, { nodeId: 'owner-node', publicKey: owner.pub });
    const forged = signRoomGrant({ room: ROOM, grantee: 'evil', grantedBy: 'owner-node' }, impostor.priv);
    const d = admit(r, 'evil', { nodeId: 'evil', room: ROOM, roomGrant: forged });
    assert.strictEqual(d.admit, false);
    assert.match(d.reason, /grant refused/);
  });

  it('a valid grant issued to SOMEONE ELSE cannot be presented by this peer', () => {
    const owner = keypair();
    const r = receiver(ROOM, { nodeId: 'owner-node', publicKey: owner.pub });
    const grant = signRoomGrant({ room: ROOM, grantee: 'alice', grantedBy: 'owner-node' }, owner.priv);
    const d = admit(r, 'mallory', { nodeId: 'mallory', room: ROOM, roomGrant: grant });
    assert.strictEqual(d.admit, false);
    assert.match(d.reason, /grantee-mismatch/);
  });

  it('an expired grant is refused at join', () => {
    const owner = keypair();
    const r = receiver(ROOM, { nodeId: 'owner-node', publicKey: owner.pub });
    const long_ago = Date.now() - 48 * 3600_000;
    const grant = signRoomGrant(
      { room: ROOM, grantee: 'late', grantedBy: 'owner-node', grantedAt: long_ago, expiresAt: long_ago + 3600_000 },
      owner.priv);
    assert.match(admit(r, 'late', { nodeId: 'late', room: ROOM, roomGrant: grant }).reason, /expired/);
  });

  it('the grantee is the handshake nodeId, not the transport peerId', () => {
    // a peer cannot present a grant for a nodeId it is not announcing
    const owner = keypair();
    const r = receiver(ROOM, { nodeId: 'owner-node', publicKey: owner.pub });
    const grant = signRoomGrant({ room: ROOM, grantee: 'alice', grantedBy: 'owner-node' }, owner.priv);
    assert.strictEqual(admit(r, 'alice', { nodeId: 'mallory', room: ROOM, roomGrant: grant }).admit, false,
      'the announced identity is what the grant must name');
  });
});

describe('the decision is enforced in BOTH directions', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const read = (f) => fs.readFileSync(path.join(__dirname, '..', f), 'utf8');

  it('the inbound path decides BEFORE the peer is added to the set', () => {
    const src = read('lib/node.js');
    const decide = src.indexOf('const admission = this._roomAdmission(peerId, handshakeMsg)');
    const add = src.indexOf('const peer = this._createPeer(transport, peerId, peerName, false, \'bonjour\')');
    assert.ok(decide > 0 && add > 0, 'both present');
    assert.ok(decide < add, 'refused peers are never created or added');
  });

  it('the outbound path decides when the dialled peer\'s handshake arrives', () => {
    // the loopback tie-break means the stranger dials US in half of all nodeId
    // orderings — a check on only the accepting path is dead code for those pairs
    const src = read('lib/core/frame-handler.js');
    assert.match(src, /_handleHandshake\(peerId, peerName, msg\) \{[\s\S]{0,900}_roomAdmission\(peerId, msg\)/);
    assert.match(src, /this\._node\._peers\.delete\(peerId\)/, 'a refused peer is removed, not merely logged');
  });

  it('the handshake carries the grant so a gated room is joinable at all', () => {
    assert.match(read('lib/node.js'), /roomGrant: this\._roomGrant \|\| undefined/);
  });
});
