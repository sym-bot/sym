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
// THE LIVE MODULE, NOT lib/core/frame-handler.js. These tests originally imported the core copy,
// which lib/node.js does not load — so the door passed nine tests while never running in
// production. `require` the same path node.js does, and let the assertion below prove it.
const { FrameHandler } = require('../lib/frame-handler');

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

describe('roomGate — the question a caller could not ask', () => {
  const { RoomOwnershipRegistry: Reg } = require('../lib/room-ownership');
  const gate = (room, owners, proves = false) => SymNode.prototype.roomGate.call({
    _room: room, _roomOwners: owners,
    _buildHandshake: () => (proves ? { provenPublicKey: 'proven-key' } : { publicKey: 'asserted-only' }),
  });

  it('reports an ungated room as ungated with no owner', () => {
    const g = gate(ROOM, new Reg());
    assert.equal(g.gated, false);
    assert.equal(g.owner, null);
    assert.equal(g.admits, 'anyone', 'an ungated room admits by declaration (MMP §5.8)');
  });

  it('reports a gated room with the owners PUBLIC key and where the pin came from', () => {
    const owners = new Reg();
    owners.pin(ROOM, OWNER.nodeId, OWNER.publicKey, 'config');
    const g = gate(ROOM, owners);
    assert.equal(g.gated, true);
    assert.equal(g.owner.nodeId, OWNER.nodeId);
    assert.equal(g.owner.publicKey, OWNER.publicKey);
    assert.equal(g.owner.source, 'config');
  });

  it('never exposes a private key — verifying needs the public half, minting is the owners act', () => {
    const owners = new Reg();
    owners.pin(ROOM, OWNER.nodeId, OWNER.publicKey, 'config');
    const flat = JSON.stringify(gate(ROOM, owners));
    assert.ok(!/priv/i.test(flat), flat);
  });
});

describe('the door is in the module the node actually loads', () => {
  it('lib/node.js requires the SAME frame-handler these tests exercise', () => {
    // WHY THIS TEST EXISTS. The door was written into lib/core/frame-handler.js and tested there.
    // lib/node.js requires './frame-handler' — a different, larger file — so nine passing tests
    // covered code no runtime ever loaded, and the door was reported as shipped while being dead.
    // A green suite against the wrong file is worse than no suite: it retires the question.
    const fs = require('node:fs');
    const nodeSrc = fs.readFileSync(require.resolve('../lib/node.js'), 'utf8');
    const required = /require\('\.\/(core\/)?frame-handler'\)/.exec(nodeSrc);
    assert.ok(required, 'lib/node.js must require a frame-handler');
    assert.equal(required[1], undefined,
      'node.js requires ./frame-handler (lib/frame-handler.js) — tests must import that one');
    const live = fs.readFileSync(require.resolve('../lib/frame-handler.js'), 'utf8');
    assert.match(live, /_roomDoor/, 'the door must live in the module the node loads');
    assert.match(live, /_roomAdmission/, 'and so must the handshake admission check');
  });
});

describe('roomGate reports what the gate ENFORCES, not only that one is pinned', () => {
  const { RoomOwnershipRegistry: Reg } = require('../lib/room-ownership');
  const gate = (proves) => {
    const owners = new Reg();
    owners.pin(ROOM, OWNER.nodeId, OWNER.publicKey, 'config');
    return SymNode.prototype.roomGate.call({
      _room: ROOM, _roomOwners: owners,
      _buildHandshake: () => (proves ? { provenPublicKey: 'proven' } : { publicKey: 'asserted-only' }),
    });
  };

  it('says a gated room admits NOBODY while this runtime cannot prove a key', () => {
    // The dangerous reading this replaces: `gated: true` alone invites the conclusion that the
    // room admits the invited. verifyRoomGrant refuses for want of proof BEFORE comparing keys,
    // so a legitimate grant-holder is refused for the same reason as a thief.
    const g = gate(false);
    assert.equal(g.gated, true);
    assert.equal(g.admits, 'nobody');
    assert.match(g.why, /refuses every peer, holder or not/);
  });

  it('says grant-holders once the handshake proves a key — without anyone editing this method', () => {
    // Asked of our OWN handshake rather than hard-coded, so wiring lib/core/handshake-v2.js
    // flips the answer on its own. A constant here would have to be remembered.
    const g = gate(true);
    assert.equal(g.admits, 'grant-holders');
    assert.equal(g.why, null);
  });

  it('never reports a room as admitting more than it can enforce', () => {
    const order = ['nobody', 'grant-holders'];
    assert.ok(order.indexOf(gate(false).admits) < order.indexOf(gate(true).admits),
      'the non-proving runtime must never claim the wider admission');
  });
});
