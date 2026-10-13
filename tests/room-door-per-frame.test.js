'use strict';

/**
 * THE DOOR, consulted per frame (§5.8.1; design D6). In Core Secure a frame reaches the handler only
 * from a confirmed session the room door admitted (SymNode#_onSessionFrame): a session not yet
 * admitted may send only its room-join grant. The handler consults the door again on every frame
 * (FrameHandler#handle → SymNode#_roomDoor), so no later path can dispatch around it. These tests pin
 * what the door refuses and, just as deliberately, what it does not.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');

const { SymNode } = require('../lib/node');
const { RoomOwnershipRegistry } = require('../lib/room-ownership');
// THE LIVE MODULE: the frame handler lib/node.js loads (the assertion below proves it).
const { FrameHandler } = require('../lib/frame-handler');

const ROOM = 'x-review--team-02779b950c3d8d7378fd11d6';
const OWNER = { nodeId: 'owner-node', publicKey: 'A'.repeat(43) };

function receiver(room, owner) {
  const owners = new RoomOwnershipRegistry();
  if (owner) owners.pin(room, owner.nodeId, owner.publicKey, 'config');
  const logged = [];
  return { _room: room, _roomOwners: owners, _log: (m) => logged.push(m), logged, _peers: new Map(), _roomVerdicts: new Map() };
}
const door = (r, peerId) => SymNode.prototype._roomDoor.call(r, peerId);
const session = (nodeId) => ({ nodeId, name: nodeId, identityKey: 'k', confirmed: true, has: () => true, send: () => true });

describe('a word from a node that was never admitted', () => {
  it('is REFUSED in a gated room', () => {
    const r = receiver(ROOM, OWNER);
    const d = door(r, 'mallory');
    assert.equal(d.pass, false);
    assert.match(d.reason, /without joining it/);
  });

  it('passes in an ungated room: there is nothing to have failed', () => {
    assert.equal(door(receiver(ROOM, null), 'mallory').pass, true);
  });

  it('a session REFUSED at admission stays refused on every later frame, with the admission reason', () => {
    const r = receiver(ROOM, OWNER);
    r._roomVerdicts.set('liar', { admit: false, reason: 'room-join grant refused: grantee-mismatch' });
    const d = door(r, 'liar');
    assert.equal(d.pass, false);
    assert.match(d.reason, /grantee-mismatch/, 'the door repeats the ADMISSION reason');
  });

  it('an ADMITTED peer passes', () => {
    const r = receiver(ROOM, OWNER);
    r._peers.set('friend', { peerId: 'friend' });
    r._roomVerdicts.set('friend', { admit: true });
    assert.equal(door(r, 'friend').pass, true);
  });
});

describe('what the dispatcher does with the door\'s answer', () => {
  function dispatcher(room, owner) {
    const node = receiver(room, owner);
    node._roomDoor = (peerId) => SymNode.prototype._roomDoor.call(node, peerId);
    const seen = [];
    const fh = new FrameHandler(node);
    for (const m of ['_handleMemoryShare', '_handleMood', '_handleXMeshInsight', '_handleWakeChannel', '_handlePeerInfo']) {
      fh[m] = (_p, _n, msg) => seen.push(msg.type);
    }
    return { node, fh, seen };
  }

  it('drops a cmb from an unadmitted peer in a gated room BEFORE SVAF sees it', () => {
    const { fh, seen, node } = dispatcher(ROOM, OWNER);
    fh.handle(session('mallory'), { type: 'cmb', cmb: { content: 'trust me' } });
    assert.deepEqual(seen, [], 'the word must not reach the sub-handler at all');
    assert.ok(node.logged.some((l) => /Door refused 'cmb'/.test(l)), 'a refusal nobody can read is not a gate');
  });

  it('refuses EVERY meaning-carrying category, not just cmb', () => {
    const { fh, seen } = dispatcher(ROOM, OWNER);
    for (const type of ['cmb', 'mood', 'xmesh-insight', 'wake-channel', 'peer-info']) fh.handle(session('mallory'), { type });
    assert.deepEqual(seen, []);
  });

  it('passes a cmb through in an ungated room — the door adds no new refusal there', () => {
    const { fh, seen } = dispatcher(ROOM, null);
    fh.handle(session('stranger'), { type: 'cmb', cmb: { content: 'hello' } });
    assert.deepEqual(seen, ['cmb']);
  });

  it('refuses a frame from anything that is not a confirmed session', () => {
    const { fh } = dispatcher(ROOM, null);
    assert.throws(() => fh.handle({ nodeId: 'x', confirmed: false }, { type: 'cmb' }), /confirmed session/);
    assert.throws(() => fh.handle('peer-id-string', 'name', { type: 'cmb' }), /confirmed session/, 'the 0.13 (peerId, peerName, frame) call is gone');
  });
});

describe('roomGate — the question a caller could not ask', () => {
  const gate = (room, owners) => SymNode.prototype.roomGate.call({ _room: room, _roomOwners: owners });

  it('reports an ungated room as ungated with no owner', () => {
    const g = gate(ROOM, new RoomOwnershipRegistry());
    assert.equal(g.gated, false);
    assert.equal(g.owner, null);
    assert.equal(g.admits, 'anyone', 'an ungated room admits by declaration (MMP §5.8)');
  });

  it('reports a gated room with the owner\'s PUBLIC key, where the pin came from, and that it admits grant-holders', () => {
    const owners = new RoomOwnershipRegistry();
    owners.pin(ROOM, OWNER.nodeId, OWNER.publicKey, 'config');
    const g = gate(ROOM, owners);
    assert.equal(g.gated, true);
    assert.equal(g.owner.nodeId, OWNER.nodeId);
    assert.equal(g.owner.publicKey, OWNER.publicKey);
    assert.equal(g.owner.source, 'config');
    assert.equal(g.admits, 'grant-holders', 'Core Secure sessions prove the key a grant binds');
    assert.ok(!/priv/i.test(JSON.stringify(g)));
  });
});

describe('the door is in the module the node actually loads', () => {
  it('lib/node.js requires the SAME frame-handler these tests exercise', () => {
    const fs = require('node:fs');
    const nodeSrc = fs.readFileSync(require.resolve('../lib/node.js'), 'utf8');
    const required = /require\('\.\/(core\/)?frame-handler'\)/.exec(nodeSrc);
    assert.ok(required, 'lib/node.js must require a frame-handler');
    assert.equal(required[1], undefined, 'node.js requires ./frame-handler (lib/frame-handler.js)');
    const live = fs.readFileSync(require.resolve('../lib/frame-handler.js'), 'utf8');
    assert.match(live, /_roomDoor/, 'the door must live in the module the node loads');
    assert.match(nodeSrc, /_roomAdmissionDecide\(session\)/, 'and the admission decision in the node, per session');
  });
});
