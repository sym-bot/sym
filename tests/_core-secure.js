'use strict';

/**
 * Test helpers for Core Secure (sym 0.14): identities, in-memory transports, signed v2.0 records,
 * and wiring two SymNodes (or a node and a bare PeerSession) through the real §5.2 handshake.
 *
 * Nothing here bypasses the handshake: a pair is connected by attaching a transport to each node
 * with its role, and the sessions prove themselves exactly as they do over TCP or a relay.
 */

const crypto = require('crypto');
const { createCMB, signCMB, assertionIdV2_0 } = require('../lib/core');

function uuidv7() { return require('../lib/config').uuidv7(); }

/** A fresh identity { nodeId, name, publicKey, privateKey } (keys raw, base64url). */
function identity(name = 'peer') {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    nodeId: uuidv7(),
    name,
    publicKey: publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('base64url'),
    privateKey: privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(16).toString('base64url'),
  };
}

/**
 * Two transports joined back to back. Frames are delivered asynchronously (setImmediate), in order,
 * as copies (JSON round trip), as a socket would. `tap` sees every frame on the wire.
 */
function memoryPipe({ tap } = {}) {
  const ends = [mkEnd(), mkEnd()];
  function mkEnd() {
    const listeners = { message: [], close: [] };
    return {
      _closed: false,
      on(ev, fn) { (listeners[ev] ||= []).push(fn); return this; },
      once(ev, fn) { const w = (...a) => { this.off(ev, w); fn(...a); }; return this.on(ev, w); },
      off(ev, fn) { listeners[ev] = (listeners[ev] || []).filter((f) => f !== fn); return this; },
      removeListener(ev, fn) { return this.off(ev, fn); },
      removeAllListeners(ev) { if (ev) listeners[ev] = []; else for (const k of Object.keys(listeners)) listeners[k] = []; return this; },
      emit(ev, ...a) { for (const f of [...(listeners[ev] || [])]) f(...a); },
      _listeners: listeners,
    };
  }
  const [a, b] = ends;
  for (const [self, other] of [[a, b], [b, a]]) {
    self.trySend = (frame) => {
      if (self._closed) return { ok: false, reason: 'not-connected' };
      const copy = JSON.parse(JSON.stringify(frame));
      if (tap) tap(copy, self === a ? 'a→b' : 'b→a');
      setImmediate(() => { if (!other._closed) other.emit('message', copy); });
      return { ok: true };
    };
    self.send = (frame) => self.trySend(frame).ok;
    self.close = () => {
      if (self._closed) return;
      self._closed = true;
      setImmediate(() => self.emit('close'));
      if (!other._closed) { other._closed = true; setImmediate(() => other.emit('close')); }
    };
    self.destroy = self.close;
  }
  return [a, b];
}

/**
 * Connect two SymNodes over an in-memory pipe through the real handshake: `client` dials `server`.
 * `kind` is 'bonjour' (LAN/loopback) or 'relay'. Resolves when both have the other as a peer.
 */
async function connectNodes(client, server, { kind = 'bonjour', timeoutMs = 5000, tap } = {}) {
  const [tc, ts] = memoryPipe({ tap });
  if (kind === 'bonjour') {
    server.connectTransport(ts, { role: 'server' });
    client.connectTransport(tc, { role: 'client', expectNodeId: server.nodeId });
  } else {
    // A relay session is fed by the node's envelope router, not by its transport: the pipe stands in
    // for the relay channel between the two, so it is wired here.
    const ss = server._attachTransport(ts, { role: 'server', kind, relayFrom: client.nodeId, expectNodeId: client.nodeId });
    ts.on('message', (f) => ss.receiveWire(f));
    ts.on('close', () => ss.close('relay-peer-left', { notify: false }));
    const cs = client._attachTransport(tc, { role: 'client', kind, expectNodeId: server.nodeId, relayFrom: server.nodeId });
    tc.on('message', (f) => cs.receiveWire(f));
    tc.on('close', () => cs.close('relay-peer-left', { notify: false }));
  }
  // Resolved when THIS pair of sessions has confirmed on both sides (a pair already joined over
  // another transport does not count).
  const joined = (n, other) => { const s = n._peers.get(other.nodeId)?.transports?.get(kind); return !!(s && s.confirmed && !s.closed); };
  await until(() => joined(client, server) && joined(server, client), timeoutMs);
  if (!joined(client, server) || !joined(server, client)) throw new Error('connectNodes: the pair did not confirm');
  return { tc, ts };
}

async function until(cond, ms = 5000, step = 10) {
  for (let t = 0; t < ms && !cond(); t += step) await new Promise((r) => setTimeout(r, step));
  return cond();
}

/** A signed v2.0 record from `author` (an identity), as remember() mints it. */
function signedRecord(author, { categories = { focus: 'a signed observation' }, room = 'default', to = null, application = null, lineage = null } = {}) {
  const cmb = createCMB({ categories, createdBy: author.name, createdByNodeId: author.nodeId, room, to, lineage, emitV2: true, application });
  cmb.metadata.assertionId = assertionIdV2_0(cmb);
  signCMB(cmb, author.privateKey);
  return cmb;
}

/** An application section for `bytes` (Buffer), signed into the record. */
function applicationFor(bytes, { mediaType = 'application/json', schema = 'https://sym.bot/schema/test-v1.json' } = {}) {
  return {
    mediaType, schema, encoding: 'base64url', byteLength: bytes.length,
    digest: `sha256-${crypto.createHash('sha256').update(bytes).digest('hex')}`,
    data: bytes.toString('base64url'),
  };
}

/**
 * For handler-level tests: what a confirmed, admitted §5.2 session leaves behind — the identity's key
 * bound `proven` in the node's registry, and a session registered as the peer's transport — so a test
 * can hand authenticated inner frames to node._receiveSessionFrame (the one guarded dispatch) or to
 * node._frameHandler.handle(session, frame). Frames the node sends back to it are kept in `sent`.
 * @param {object} node
 * @param {{ nodeId: string, name?: string, publicKey?: string }} id
 */
function admitAs(node, id, { extensions = ['cmb-encrypted-v2', 'sym-attest-v1', 'xmesh-insight-v1'], kind = 'bonjour' } = {}) {
  const sent = [];
  const session = {
    nodeId: id.nodeId, name: id.name || id.nodeId, identityKey: id.publicKey || null,
    sessionId: crypto.randomBytes(16).toString('hex'), kind, role: 'server', room: node._room,
    confirmed: true, closed: false, _closed: false, selected: [...extensions],
    has(e) { return this.selected.includes(e); },
    admission: { state: 'admitted' }, peerImplementation: { name: 'test', version: '0' },
    confirmedAt: Date.now(), lastSeen: Date.now(), relayFrom: kind === 'relay' ? id.nodeId : null,
    sent,
    send(f) { sent.push(f); return true; },
    trySend(f) { sent.push(f); return { ok: true }; },
    close() { this.closed = true; this._closed = true; },
  };
  if (id.publicKey) node._roster.bind(id.nodeId, id.publicKey, 'proven');
  node._peers.set(id.nodeId, { peerId: id.nodeId, name: session.name, identityKey: id.publicKey || null, transports: new Map([[kind, session]]), transport: session, isOutbound: false, source: kind, lastSeen: Date.now() });
  return session;
}

/**
 * A captured transport admitted as a session (the 0.13 tests' `_addPeer(_createPeer(t, id, …))`):
 * what the node sends to the peer reaches `transport.send` before it is sealed.
 */
function plantSession(node, transport, nodeId, name, kind = 'bonjour') {
  const s = admitAs(node, { nodeId, name }, { kind });
  s.send = (f) => transport.send(f) !== false;
  s.trySend = (f) => (typeof transport.trySend === 'function' ? transport.trySend(f) : (s.send(f) ? { ok: true } : { ok: false, reason: 'send-failed' }));
  return s;
}

/** Hand an authenticated frame to the node through its one guarded dispatch. */
function deliver(node, session, frame) { return node._receiveSessionFrame(session, frame); }

/** A node's own identity as a signer: { nodeId, name, publicKey, privateKey }. */
function signerOf(node) { return { nodeId: node.nodeId, name: node.name, publicKey: node._identity.publicKey, privateKey: node._identity.privateKey }; }

module.exports = { identity, memoryPipe, connectNodes, until, signedRecord, applicationFor, uuidv7, admitAs, plantSession, deliver, signerOf };
