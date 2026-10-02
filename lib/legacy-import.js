'use strict';

/**
 * @module @sym-bot/sym/legacy-import
 * @description Legacy Import (MMP §17.3; sym 0.14 design D7): explicit, outbound, temporary.
 *
 * A 0.13 node cannot complete the Core Secure handshake. It is reached only through a ROUTE the
 * operator configures, never through negotiation failure, and never by accepting its hello:
 *
 *   - Off by default. A route names the peer's nodeId, its endpoint (`host:port` for LAN or the
 *     loopback, or `relay` for the relay channel) and its identity key — the full key or its
 *     `sha256:<hex>` fingerprint. The fingerprint is MANDATORY; the key is pinned at `pinned` for
 *     that nodeId (design D3's matrix applies: a different key already bound is a conflict).
 *   - This node always dials a route itself, and never accepts a legacy hello: the Core Secure
 *     listener refuses one at once. That covers both id orders (0.13 dials only when its own id is
 *     smaller on the loopback), and the profile is chosen by the route before any byte is read.
 *   - Over the relay, the route's session is this node sending a legacy `handshake` to the routed
 *     nodeId. Relay-auth is unproven (§4.4.1), so a squatter could answer as that nodeId: records
 *     are accepted only when their signature verifies against the pinned key, and only records the
 *     routed node itself signed.
 *   - Connection-level frames from a legacy session (peer-info, wake-channel, mood, role grants…)
 *     are hints: none is stored.
 *   - What this node sends on a legacy session: its records as legacy `cmb` frames under the legacy
 *     E2E construction (X25519 + AES-256-GCM, from an ephemeral key per legacy session), so the
 *     relay never sees plaintext. Nothing else but ping/pong. `sym status` says plainly that the
 *     session uses legacy encryption, with no forward secrecy and no transcript proof.
 *   - Quarantine: everything received is stored with `verified: false` and `profile:
 *     'legacy-import'`; never given authority, never shown as verified, flagged on the channel.
 *   - The sticky floor is PERSISTED: it is the registry's proven binding (roster-keys.js `floor`).
 *     Once a nodeId has proven itself over Core Secure, its legacy route is refused until an
 *     operator resets the floor (`sym keys reset-floor <nodeId>`).
 *   - The window: network Legacy Import is removed in sym 0.15.0; offline store import stays.
 *
 * @copyright 2026 SYM.BOT. Apache 2.0 License.
 */

const fs = require('fs');
const net = require('net');
const path = require('path');
const { EventEmitter } = require('events');
const { TcpTransport } = require('./transport');
const { e2eGenerateKeyPair, e2eDeriveSharedSecret, encryptCategories, decryptCategories } = require('./core');
const { isIdentityKey, keyFingerprint } = require('./roster-keys');
const { SEND_FAILURE } = require('./frame-parser');

const HANDSHAKE_TIMEOUT_MS = 10_000;
const REDIAL_MS = 15_000;
const ROUTES_FILE = 'legacy-routes.json';
const LEGACY_ENCRYPTION = 'legacy (X25519 + AES-256-GCM per connection; no forward secrecy, no transcript proof)';
const isNodeId = (id) => typeof id === 'string' && id.length > 0 && id.length <= 256;

/**
 * Check one configured route. Throws with what is wrong: a route without a key or a fingerprint is
 * refused, because a legacy hello proves nothing (§18.3) and the pin is the only identity it has.
 * @returns {{ nodeId: string, endpoint: string, key: string|null, fingerprint: string, name: string|null }}
 */
function checkRoute(r) {
  if (!r || typeof r !== 'object') throw new Error('legacy route: not an object');
  if (!isNodeId(r.nodeId)) throw new Error('legacy route: nodeId is required');
  const endpoint = typeof r.endpoint === 'string' ? r.endpoint.trim() : '';
  if (endpoint !== 'relay' && !/^[^\s:]+:\d{1,5}$/.test(endpoint)) throw new Error(`legacy route ${r.nodeId.slice(0, 8)}: endpoint must be host:port or 'relay'`);
  let key = null;
  let fingerprint = null;
  if (r.key !== undefined) {
    if (!isIdentityKey(r.key)) throw new Error(`legacy route ${r.nodeId.slice(0, 8)}: key is not a base64url Ed25519 public key`);
    key = r.key;
    fingerprint = keyFingerprint(r.key);
  }
  if (r.fingerprint !== undefined) {
    if (typeof r.fingerprint !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(r.fingerprint)) throw new Error(`legacy route ${r.nodeId.slice(0, 8)}: fingerprint must be sha256:<64 hex>`);
    if (fingerprint && fingerprint !== r.fingerprint) throw new Error(`legacy route ${r.nodeId.slice(0, 8)}: key and fingerprint disagree`);
    fingerprint = r.fingerprint;
  }
  if (!fingerprint) throw new Error(`legacy route ${r.nodeId.slice(0, 8)}: the identity key fingerprint is mandatory`);
  return { nodeId: r.nodeId, endpoint, key, fingerprint, name: typeof r.name === 'string' ? r.name.slice(0, 64) : null };
}

/**
 * One Legacy Import session: the 0.13 wire on one connection, with the route's pinned identity.
 * Shaped like a PeerSession where the node reads one (nodeId, name, kind, confirmed, send/trySend,
 * close, `legacy: true`), so the peer table and the frame handler take it, quarantined.
 */
class LegacySession extends EventEmitter {
  constructor({ route, kind, transport, local, room }) {
    super();
    this.legacy = true;
    this.route = route;
    this.kind = kind;                 // 'bonjour' (LAN/loopback) | 'relay'
    this.relayFrom = kind === 'relay' ? route.nodeId : null;
    this.transport = transport;
    this.state = 'authenticating';
    this.nodeId = null; this.name = null; this.identityKey = null;
    this.sessionId = null; this.selected = []; this.role = 'client'; this.room = room;
    this.startedAt = Date.now(); this.lastSeen = Date.now(); this.confirmedAt = null;
    this.encryption = LEGACY_ENCRYPTION;
    this._local = local;
    this._e2e = e2eGenerateKeyPair();   // ephemeral: one per legacy session, never persisted
    this._secret = null;
    this._timer = setTimeout(() => this.close('timeout'), HANDSHAKE_TIMEOUT_MS);
    if (this._timer.unref) this._timer.unref();
  }

  get confirmed() { return this.state === 'confirmed'; }
  get closed() { return this.state === 'closed'; }
  get _closed() { return this.state === 'closed'; }
  has() { return false; }

  /** The 0.13 hello this node sends on its route (the only place one is ever built). */
  hello() {
    return {
      type: 'handshake',
      nodeId: this._local.nodeId,
      name: this._local.name,
      version: '0.2.3',
      extensions: [],
      room: this.room,
      publicKey: this._local.publicKey,
      e2ePublicKey: this._e2e.publicKey.toString('base64'),
      lifecycleRole: 'participant',
    };
  }

  start() { this._wire(this.hello()); }

  receiveWire(f) {
    if (this.closed || !f || typeof f !== 'object' || typeof f.type !== 'string') return;
    this.lastSeen = Date.now();
    try {
      if (this.state === 'authenticating') {
        if (f.type !== 'handshake') return; // a 0.13 node may send anchors first: they wait for nothing
        this._takeHello(f);
        return;
      }
      if (f.type === 'handshake') return; // a repeated hello (0.13 re-sends on new transports)
      if (f.type === 'ping') { this._wire({ type: 'pong' }); return; }
      if (f.type === 'pong') return;
      if (f.type !== 'cmb') { this.emit('hint', f.type); return; } // connection-level frames are hints
      const msg = { ...f };
      if (msg.cmb && typeof msg.cmb.categories === 'string' && msg.cmb._e2e) {
        if (!this._secret) { this.emit('hint', 'cmb-without-secret'); return; }
        try {
          msg.cmb = { ...msg.cmb, categories: decryptCategories(msg.cmb.categories, msg.cmb._e2e.nonce, this._secret) };
          delete msg.cmb._e2e;
        } catch { this.emit('hint', 'cmb-undecryptable'); return; }
      }
      msg._legacyImport = true;
      msg._legacyPinnedKey = this.identityKey;
      this.emit('frame', msg, this);
    } catch (err) {
      this.close('error', err && err.message);
    }
  }

  _takeHello(h) {
    if (h.nodeId !== this.route.nodeId) { this.close('node-id-mismatch', `the route names ${this.route.nodeId.slice(0, 8)}, the hello ${String(h.nodeId).slice(0, 8)}`); return; }
    if (!isIdentityKey(h.publicKey) || keyFingerprint(h.publicKey) !== this.route.fingerprint) {
      this.close('fingerprint-mismatch', 'the hello\'s identity key is not the one the route pins');
      return;
    }
    if (typeof h.e2ePublicKey === 'string' && h.e2ePublicKey) {
      try { this._secret = e2eDeriveSharedSecret(this._e2e.privateKey, Buffer.from(h.e2ePublicKey, 'base64')); }
      catch { this._secret = null; }
    }
    clearTimeout(this._timer);
    this.nodeId = h.nodeId;
    this.name = typeof h.name === 'string' && h.name ? h.name.slice(0, 256) : (this.route.name || 'legacy');
    this.identityKey = h.publicKey;
    this.state = 'confirmed';
    this.confirmedAt = Date.now();
    this.emit('confirmed', this);
  }

  /**
   * Send on the legacy session: a record as a legacy `cmb` frame under the legacy E2E construction
   * (never in the clear), ping/pong as they are. Everything else is not sent.
   */
  trySend(frame) {
    if (!this.confirmed) return { ok: false, reason: SEND_FAILURE.NOT_CONNECTED };
    if (!frame || typeof frame.type !== 'string') return { ok: false, reason: 'not-a-frame' };
    if (frame.type === 'ping' || frame.type === 'pong') return this._wire({ type: frame.type });
    if (frame.type !== 'cmb' || !frame.cmb || !frame.cmb.categories) return { ok: false, reason: 'not-sent-on-legacy' };
    if (!this._secret) return { ok: false, reason: 'no-legacy-secret' };
    const { ciphertext, nonce } = encryptCategories(frame.cmb.categories, this._secret);
    const to = frame.cmb.metadata && typeof frame.cmb.metadata.to === 'string' ? frame.cmb.metadata.to : null;
    return this._wire({ type: 'cmb', timestamp: frame.timestamp || Date.now(), cmb: { ...frame.cmb, categories: ciphertext, _e2e: { nonce } }, ...(to ? { to, directed: true } : {}) });
  }

  send(frame) { return this.trySend(frame).ok; }

  _wire(frame) {
    try {
      if (typeof this.transport.trySend === 'function') return this.transport.trySend(frame);
      return this.transport.send(frame) !== false ? { ok: true } : { ok: false, reason: 'send-failed' };
    } catch { return { ok: false, reason: SEND_FAILURE.WRITE_FAILED }; }
  }

  close(reason = 'closed', detail = null) {
    if (this.closed) return;
    const wasConfirmed = this.state === 'confirmed';
    clearTimeout(this._timer);
    this.state = 'closed';
    this._secret = null;
    if (this.kind !== 'relay') { try { this.transport.close(); } catch { /* gone */ } }
    this.emit('closed', { reason, detail, wasConfirmed }, this);
  }
}

class LegacyImport {
  /**
   * @param {object} node - the SymNode
   * @param {object} [opts]
   * @param {object[]} [opts.routes] - configured routes (also read from <nodeDir>/legacy-routes.json)
   */
  constructor(node, opts = {}) {
    this._node = node;
    this._routes = new Map();     // nodeId -> route
    this._sessions = new Map();   // nodeId -> LegacySession
    this._refused = new Map();    // nodeId -> why the route is not used
    this._timers = new Map();
    this._hints = 0;
    const configured = [...(Array.isArray(opts.routes) ? opts.routes : []), ...readRoutesFile(node._dir)];
    for (const r of configured) {
      try {
        const route = checkRoute(r);
        this._routes.set(route.nodeId, route);
      } catch (err) {
        this._refused.set(r && r.nodeId ? String(r.nodeId) : '?', err.message);
        node._log(`Legacy Import: ${err.message} — route not used`);
      }
    }
  }

  get size() { return this._routes.size; }

  /** Start every route this node may use: pin its key, then dial it (LAN) or wait for it (relay). */
  start() {
    for (const route of this._routes.values()) {
      if (route.key) {
        const b = this._node._roster.bind(route.nodeId, route.key, 'pinned');
        if (!b.bound && b.reason === 'conflict') {
          this._refused.set(route.nodeId, 'its pinned key conflicts with the key bound to that nodeId');
          continue;
        }
      }
      if (route.endpoint !== 'relay') this._dial(route);
    }
    if (this._routes.size) this._node._log(`Legacy Import: ${this._routes.size} route(s) configured — legacy encryption, no forward secrecy, no transcript proof; removed in sym 0.15.0`);
  }

  stop() {
    for (const t of this._timers.values()) clearTimeout(t);
    this._timers.clear();
    for (const s of [...this._sessions.values()]) s.close('node-stopped');
    this._sessions.clear();
  }

  /** Whether the floor (design D7) refuses `nodeId`'s route now. */
  _floored(route) {
    if (!this._node._roster.floor(route.nodeId)) return false;
    this._refused.set(route.nodeId, 'sticky floor: this nodeId has proven itself over Core Secure; an operator reset is required (sym keys reset-floor)');
    return true;
  }

  _dial(route) {
    if (!this._node._running || this._sessions.has(route.nodeId) || this._floored(route)) return;
    const [host, portStr] = [route.endpoint.slice(0, route.endpoint.lastIndexOf(':')), route.endpoint.slice(route.endpoint.lastIndexOf(':') + 1)];
    const socket = net.createConnection({ host, port: Number(portStr) }, () => {
      socket.setTimeout(0);
      const transport = new TcpTransport(socket);
      const session = this._open(route, 'bonjour', transport);
      transport.on('message', (f) => session.receiveWire(f));
      transport.on('close', () => session.close('transport-closed'));
      transport.on('error', () => {});
      session.start();
    });
    socket.on('error', () => this._redial(route));
    socket.setTimeout(10_000, () => socket.destroy());
  }

  _redial(route) {
    if (!this._node._running || route.endpoint === 'relay' || this._timers.has(route.nodeId)) return;
    const t = setTimeout(() => { this._timers.delete(route.nodeId); this._dial(route); }, REDIAL_MS);
    if (t.unref) t.unref();
    this._timers.set(route.nodeId, t);
  }

  _open(route, kind, transport) {
    const node = this._node;
    const session = new LegacySession({
      route, kind, transport, room: node._room,
      local: { nodeId: node.nodeId, name: node.name, publicKey: node._identity.publicKey },
    });
    this._sessions.set(route.nodeId, session);
    session.on('confirmed', () => this._confirmed(session));
    session.on('frame', (frame) => node._receiveSessionFrame(session, frame));
    session.on('hint', () => { this._hints++; });
    session.on('closed', (info) => this._closed(session, info));
    return session;
  }

  _confirmed(session) {
    const node = this._node;
    const route = session.route;
    // A fingerprint-only route pins the key its hello presented, now that it matched.
    if (!route.key) {
      const b = node._roster.bind(route.nodeId, session.identityKey, 'pinned');
      if (!b.bound && b.reason === 'conflict') { session.close('key-conflict'); return; }
    }
    if (this._floored(route)) { session.close('floor'); return; }
    const existing = node._peers.get(route.nodeId);
    if (existing && existing.transports.size && [...existing.transports.values()].some((t) => !t.legacy)) {
      session.close('core-secure-session-live');
      return;
    }
    let peer = existing;
    if (!peer) {
      peer = { peerId: route.nodeId, name: session.name, identityKey: session.identityKey, transports: new Map(), transport: null, isOutbound: true, source: session.kind, lastSeen: Date.now(), joinedAt: Date.now(), legacy: true };
      node._peers.set(route.nodeId, peer);
    }
    peer.transports.set(session.kind, session);
    peer.transport = node._bestTransport(peer);
    this._refused.delete(route.nodeId);
    node._log(`Legacy Import session with ${session.name} (${route.nodeId.slice(0, 8)}) over ${session.kind === 'relay' ? 'the relay' : route.endpoint}: ${LEGACY_ENCRYPTION}. Records from it are quarantined (verified: false).`);
    if (!existing) {
      node._metrics.peersJoined++;
      node.emit('peer-joined', { id: route.nodeId, name: session.name, source: session.kind, profile: 'legacy-import' });
    }
  }

  _closed(session, info) {
    const node = this._node;
    const nodeId = session.route.nodeId;
    if (this._sessions.get(nodeId) === session) this._sessions.delete(nodeId);
    const peer = node._peers.get(nodeId);
    if (peer && peer.transports.get(session.kind) === session) {
      peer.transports.delete(session.kind);
      peer.transport = node._bestTransport(peer);
      if (peer.transports.size === 0) {
        node._peers.delete(nodeId);
        node._metrics.peersLeft++;
        node.emit('peer-left', { id: nodeId, name: peer.name });
      }
    }
    if (info && !info.wasConfirmed && info.reason !== 'node-stopped') {
      this._refused.set(nodeId, `${info.reason}${info.detail ? `: ${info.detail}` : ''}`);
      node._log(`Legacy Import route ${nodeId.slice(0, 8)} not opened: ${info.reason}${info.detail ? ` (${info.detail})` : ''}`);
    }
    if (info && info.reason !== 'node-stopped' && info.reason !== 'floor' && info.reason !== 'fingerprint-mismatch' && info.reason !== 'key-conflict') this._redial(session.route);
  }

  /** The relay names a routed node present: this node sends its legacy hello to it (it never waits). */
  relayPresent(nodeId) {
    const route = this._routes.get(nodeId);
    if (!route || route.endpoint !== 'relay' || this._sessions.has(nodeId) || this._floored(route)) return;
    const session = this._open(route, 'relay', this._node._relay.transportFor(nodeId));
    session.start();
  }

  relayGone(nodeId) {
    const s = this._sessions.get(nodeId);
    if (s && s.kind === 'relay') s.close('relay-peer-left');
  }

  /** An envelope from a relay `from` that is not Core Secure: a routed legacy node's, or not ours. */
  relayFrame(from, fromName, payload) {
    const route = this._routes.get(from);
    if (!route || route.endpoint !== 'relay') return false;
    let s = this._sessions.get(from);
    if (!s) {
      // The route is chosen by configuration before any byte is read: this node opens the session
      // and sends its own hello, then takes the peer's frames on it.
      if (this._floored(route)) return true;
      s = this._open(route, 'relay', this._node._relay.transportFor(from));
      s.start();
    }
    s.receiveWire(payload);
    return true;
  }

  status() {
    return {
      routes: this._routes.size,
      window: 'network Legacy Import is removed in sym 0.15.0',
      sessions: [...this._sessions.values()].filter((s) => s.confirmed).map((s) => ({
        nodeId: s.nodeId, name: s.name, transport: s.kind === 'relay' ? 'relay' : s.route.endpoint,
        encryption: s.encryption, verified: false, since: s.confirmedAt,
      })),
      refused: [...this._refused].map(([nodeId, why]) => ({ nodeId, why })),
      hintsIgnored: this._hints,
    };
  }
}

function readRoutesFile(dir) {
  if (!dir) return [];
  try {
    const parsed = JSON.parse(fs.readFileSync(path.join(dir, ROUTES_FILE), 'utf8'));
    return Array.isArray(parsed) ? parsed : (Array.isArray(parsed.routes) ? parsed.routes : []);
  } catch { return []; }
}

module.exports = { LegacyImport, LegacySession, checkRoute, ROUTES_FILE, LEGACY_ENCRYPTION };
