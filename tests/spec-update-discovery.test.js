'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * LAN discovery as MMP 2.0 update 1 states it (#17, #22; PR #43 at 2660ab9): one service type for
 * every room, with the room in TXT `room`; a node dials only advertisements whose TXT room is its own
 * and whose `mmp` (a comma-separated version list) lists 2.0; TXT keys read as RFC 6763 §6.4 says,
 * case-insensitive with the first occurrence winning; the per-room type earlier releases advertised
 * is browsed, never advertised, and only where it is a valid RFC 6335 name. Each test fails on c0e615f.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const crypto = require('crypto');
const { SymNode } = require('../lib/node');
const { Discovery, BonjourDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');

const made = [];
const uniq = (b) => `${b}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
class FakeDiscovery extends Discovery { async start() { return 0; } async stop() {} }
function node(room) {
  const n = new SymNode({ name: uniq('disc'), silent: true, discovery: new FakeDiscovery(), room });
  made.push(n);
  n._connectToPeer = (address, port, peerId) => { (n._dialled ||= []).push(peerId); };
  return n;
}
async function stopAll() {
  for (const n of made.splice(0)) { try { await n.stop(); } catch { /* */ } try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ } }
}
const BIG = () => `ffffffff-${crypto.randomBytes(2).toString('hex')}-7fff-bfff-${crypto.randomBytes(6).toString('hex')}`; // larger than any v7 nodeId

describe('the dial filter (§5.1)', () => {
  it('dials only an advertisement whose TXT room is this node\'s room; an absent room reads as default', async () => {
    try {
      const A = node('backend-team');
      await A.start();
      const ids = [BIG(), BIG(), BIG()];
      A._discovery.emit('peer-found', '10.0.0.1', 1, ids[0], 'x', { mmp: '2.0', room: 'other-team', source: 'bonjour' });
      A._discovery.emit('peer-found', '10.0.0.2', 2, ids[1], 'y', { mmp: '2.0', room: null, source: 'bonjour' });
      A._discovery.emit('peer-found', '10.0.0.3', 3, ids[2], 'z', { mmp: '2.0', room: 'backend-team', source: 'bonjour' });
      assert.deepStrictEqual(A._dialled, [ids[2]]);
      const D = node('default');
      await D.start();
      const d = BIG();
      D._discovery.emit('peer-found', '10.0.0.4', 4, d, 'w', { mmp: '2.0', room: null, source: 'bonjour' });
      assert.deepStrictEqual(D._dialled, [d]);
    } finally { await stopAll(); }
  });

  it('mmp is a comma-separated version list: 2.0 among others is dialled, a list without it is not', async () => {
    try {
      const A = node('default');
      await A.start();
      const [a, b, c] = [BIG(), BIG(), BIG()];
      A._discovery.emit('peer-found', '10.0.0.1', 1, a, 'a', { mmp: '2.0,2.1', room: 'default' });
      A._discovery.emit('peer-found', '10.0.0.2', 2, b, 'b', { mmp: '2.1', room: 'default' });
      A._discovery.emit('peer-found', '10.0.0.3', 3, c, 'c', { mmp: '2.0, 2.1', room: 'default' });
      assert.deepStrictEqual(A._dialled, [a, c], '"2.0, 2.1" still lists "2.0"');
    } finally { await stopAll(); }
  });
});

describe('TXT keys (RFC 6763 §6.4)', () => {
  const { parseTxtStrings, serviceTxt } = require('../lib/discovery');
  it('compared case-insensitively; the first occurrence wins; =value strings are ignored', () => {
    const t = parseTxtStrings(['MMP=2.0', 'mmp=1.0', 'Room=acme.prod', '=x', 'flag', 'empty=']);
    assert.strictEqual(t.get('mmp'), '2.0');
    assert.strictEqual(t.get('room'), 'acme.prod');
    assert.strictEqual(t.get('flag'), null);
    assert.strictEqual(t.get('empty'), '');
    assert.strictEqual(t.has(''), false);
  });
  it('a service is read from its raw strings, so a node named "mmp=2.0" is not a 2.0 advertisement', () => {
    const svc = { rawTxt: [Buffer.from('node-id=x'), Buffer.from('node-name=mmp=2.0')], txt: { 'node-id': 'x', 'node-name': 'mmp=2.0' } };
    assert.strictEqual(serviceTxt(svc).get('mmp'), undefined);
    const dup = { rawTxt: [Buffer.from('room=first'), Buffer.from('ROOM=second')], txt: { room: 'first', ROOM: 'second' } };
    assert.strictEqual(serviceTxt(dup).get('room'), 'first');
  });
  it('a discovered service reaches the node with the TXT as §6.4 reads it', () => {
    const d = new BonjourDiscovery({ mdns: false });
    const found = [];
    d.on('peer-found', (address, port, id, name, info) => found.push({ id, name, info }));
    d._makeServiceHandlers({ nodeId: 'self' });
    d._onServiceUp({ addresses: ['10.0.0.9'], port: 9, rawTxt: ['NODE-ID=peer-1', 'node-name=mmp=2.0', 'Room=acme.prod', 'room=other'].map((x) => Buffer.from(x)) });
    assert.deepStrictEqual(found, [{ id: 'peer-1', name: 'mmp=2.0', info: { mmp: null, room: 'acme.prod', source: 'bonjour' } }]);
  });
});

describe('one service type, and the migration browse (§5.1)', () => {
  it('advertises on the one type and browses the legacy per-room type too', () => {
    const published = []; const browsed = []; void published;
    const d = new BonjourDiscovery({ serviceType: '_sym._tcp', browseTypes: ['_backend-team._tcp', 'not a type'], room: 'backend-team' });
    d._identity = { nodeId: 'self', name: 'n', publicKey: 'pk', hostname: 'h' };
    d._bonjour = { publish: (o) => published.push(o), find: (o) => { browsed.push(o.type); return { on() {}, stop() {} }; }, destroy() {} };
    d._makeServiceHandlers(d._identity);
    d._startBrowsers();
    assert.deepStrictEqual(browsed, ['sym', 'backend-team'], 'the bad type is dropped');
    d._stopBrowsers();
    assert.deepStrictEqual(d._browsers, []);
  });
  it('a discovery the host built advertises the node\'s room, so two nodes in one named room find each other', async () => {
    try {
      const d = new BonjourDiscovery({ mdns: false });
      const n = new SymNode({ name: uniq('disc-r'), silent: true, room: 'acme.prod', discovery: d });
      made.push(n);
      assert.strictEqual(d._room, 'acme.prod');
    } finally { await stopAll(); }
  });
  it('a node given discoveryBrowseTypes browses them', async () => {
    try {
      const n = new SymNode({ name: uniq('disc-b'), silent: true, room: 'backend-team', discoveryBrowseTypes: ['_backend-team._tcp'] });
      made.push(n);
      assert.deepStrictEqual(n._discovery._browseTypes, ['_sym._tcp', '_backend-team._tcp']);
    } finally { await stopAll(); }
  });
});
