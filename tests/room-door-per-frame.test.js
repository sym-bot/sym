'use strict';

/**
 * Stage 3 — THE DOOR, consulted per frame (SymNode#_roomDoor + FrameHandler#handle).
 *
 * Stages 1 and 2 put a comparison and a grant check into the handshake. Neither reached a
 * frame. dev3, building the xmesh simulation against this spec, traced its bad node pushing
 * a word straight onto the delivery queue with no join, and asked whether the door belongs
 * everywhere or only in that one scene. Reading THIS tree answered it: the same shape is
 * reachable here for a different reason. On the dialling side `_connectToPeer` attaches the
 * frame listener and calls `_addPeer` before any handshake exists, so a peer that speaks
 * first is judged by SVAF with no admission decision ever having been made; on the accepting
 * side the refusal closes the transport one statement AFTER the listener was attached.
 *
 * These tests pin what the door refuses and, just as deliberately, what it does not.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');

const { SymNode } = require('../lib/node');
const { RoomOwnershipRegistry } = require('../lib/room-ownership');
const { FrameHandler } = require('../lib/core/frame-handler');

const ROOM = 'x-review--team-02779b950c3d8d7378fd11d6';
const OWNER = { nodeId: 'owner-node', publicKey: 'ownerkey' };

function receiver(room, owner) {
  const owners = new RoomOwnershipRegistry();
  if (owner) owners.pin(room, owner.nodeId, owner.publicKey, 'config');
  const logged = [];
  return { _room: room, _roomOwners: owners, _log: (m) => logged.push(m), logged, _peers: new Map() };
}
const admit = (r, peerId, msg) => SymNode.prototype._roomAdmission.call(r, peerId, msg);
const door = (r, peerId) => SymNode.prototype._roomDoor.call(r, peerId);

describe('a word from a node that never joined', () => {
  it('is REFUSED in a gated room — this is dev3s bad node, in this tree', () => {
    const r = receiver(ROOM, OWNER);
    const d = door(r, 'mallory');        // no handshake ever processed for this peer
    assert.equal(d.pass, false);
    assert.match(d.reason, /without joining it/);
  });

  it('is ADMITTED in an ungated room, and counted, because nothing was required of it', () => {
    const r = receiver(ROOM, null);
    assert.equal(door(r, 'mallory').pass, true);
    assert.equal(door(r, 'other').pass, true);
    assert.equal(r._doorUngatedPassCount, 2,
      'the population passing on absence must be countable before anyone tightens this');
  });

  it('a peer REFUSED at handshake stays refused on every later frame', () => {
    const r = receiver(ROOM, null);
    const a = admit(r, 'liar', { nodeId: 'liar', room: 'someone-elses-room' });
    assert.equal(a.admit, false);
    const d = door(r, 'liar');
    assert.equal(d.pass, false);
    assert.match(d.reason, /room-mismatch/,
      'the door must repeat the ADMISSION reason, not invent a second one');
  });

  it('a peer ADMITTED at handshake passes, and does not touch the ungated counter', () => {
    const r = receiver(ROOM, null);
    assert.equal(admit(r, 'friend', { nodeId: 'friend', room: ROOM }).admit, true);
    assert.equal(door(r, 'friend').pass, true);
    assert.equal(r._doorUngatedPassCount, undefined,
      'a peer with a recorded verdict is not an absent-handshake case');
  });
});

describe('what the dispatcher does with the doors answer', () => {
  function dispatcher(room, owner) {
    const node = receiver(room, owner);
    node._roomDoor = (peerId) => SymNode.prototype._roomDoor.call(node, peerId);
    node._roomAdmission = (peerId, msg) => SymNode.prototype._roomAdmission.call(node, peerId, msg);
    const seen = [];
    const fh = new FrameHandler(node);
    for (const m of ['_handleMemoryShare', '_handleMood', '_handleMessage', '_handleXMeshInsight',
                     '_handleWakeChannel', '_handlePeerInfo']) {
      fh[m] = (_p, _n, msg) => seen.push(msg.type);
    }
    return { node, fh, seen };
  }

  it('drops a cmb from an unjoined peer in a gated room BEFORE SVAF sees it', () => {
    const { fh, seen, node } = dispatcher(ROOM, OWNER);
    fh.handle('mallory', 'mallory', { type: 'cmb', cmb: { content: 'trust me' } });
    assert.deepEqual(seen, [], 'the word must not reach the sub-handler at all');
    assert.ok(node.logged.some((l) => /Door refused 'cmb'/.test(l)),
      'a refusal nobody can read is not a gate');
  });

  it('refuses EVERY meaning-carrying category, not just cmb', () => {
    const { fh, seen } = dispatcher(ROOM, OWNER);
    for (const type of ['cmb', 'mood', 'message', 'xmesh-insight', 'wake-channel', 'peer-info']) {
      fh.handle('mallory', 'mallory', { type });
    }
    assert.deepEqual(seen, []);
  });

  it('still lets the handshake through — otherwise a grant-holder could never join', () => {
    const { fh, node } = dispatcher(ROOM, OWNER);
    fh.handle('friend', 'friend', { type: 'handshake', nodeId: 'friend', room: ROOM });
    assert.ok(node._roomVerdicts.has('friend'),
      'the handshake must reach admission, or the door locks out the people it is for');
  });

  it('still answers ping — liveness tells a refused peer nothing a closed socket would not', () => {
    const { node, fh } = dispatcher(ROOM, OWNER);
    const sent = [];
    node._peers.set('mallory', { transport: { send: (m) => sent.push(m.type) } });
    fh.handle('mallory', 'mallory', { type: 'ping' });
    assert.deepEqual(sent, ['pong']);
  });

  it('passes a cmb through in an ungated room — the door adds no new refusal there', () => {
    const { fh, seen } = dispatcher(ROOM, null);
    fh.handle('stranger', 'stranger', { type: 'cmb', cmb: { content: 'hello' } });
    assert.deepEqual(seen, ['cmb']);
  });
});
