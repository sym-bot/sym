'use strict';

/**
 * Discovery — pluggable peer discovery for SYM mesh nodes.
 *
 * Three implementations:
 * - BonjourDiscovery: LAN discovery via bonjour-service (multicast DNS, every platform)
 * - NullDiscovery: no-op for relay-only nodes and tests
 *
 * SymNode accepts a discovery instance via opts.discovery. If not provided,
 * it creates BonjourDiscovery (default) or NullDiscovery (if relayOnly).
 *
 * See MMP v0.2.0 Section 5 (Connection, Layer 2).
 *
 * Copyright (c) 2026 SYM.BOT. Apache 2.0 License.
 */

const net = require('net');
const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');
const { TcpTransport } = require('./transport');
const { wireNodeId, wireName } = require('./wire-identity');

// ONE EXIT HOOK FOR EVERY LIVE LOOPBACK REGISTRATION IN THE PROCESS. Each discovery added its own 'exit' listener, so a
// process hosting many nodes carried one listener per live node: the xmesh runtime logged Node's
// MaxListenersExceededWarning at every boot (11 exit listeners on its core-team host, 2026-09-28), and a process
// hosting thousands of nodes would carry thousands. The live registrations are one set; the process's one hook
// unlinks whatever is still registered when it exits, and stop() takes its file out of the set.
const _liveRegistrations = new Set();
let _exitHookInstalled = false;
function _unlinkOnExit(file) {
  _liveRegistrations.add(file);
  if (_exitHookInstalled) return;
  _exitHookInstalled = true;
  process.once('exit', () => {
    for (const f of _liveRegistrations) { try { fs.unlinkSync(f); } catch {} }
  });
}

// ── Interface ────────────────────────────────────────────────

/**
 * Base discovery class. Subclasses implement start/stop.
 * Emits:
 *   'peer-found' (address, port, peerId, peerName) — outbound connection needed
 *   'inbound-connection' (transport, peerId, peerName) — peer connected to us
 *   'error' (err) — non-fatal discovery error
 */
class Discovery extends EventEmitter {
  /**
   * Start discovery: listen for inbound connections + advertise + browse for peers.
   * @param {object} identity — { nodeId, name, publicKey, hostname }
   * @param {function} log — logging function
   * @returns {Promise<number>} listening port (0 if no listener)
   */
  async start(identity, log) { return 0; }

  /** The node's room (§5.8), advertised in TXT `room` (§5.1). Called before start(). */
  setRoom(room) { this._room = room; }

  /**
   * Stop discovery: close listener, stop browsing, clean up.
   * @returns {Promise<void>}
   */
  async stop() {}

  /**
   * Trigger an immediate reconnection attempt for any cached peers
   * that are not currently connected. Called by SymNode when a send
   * fails (0 delivered) so the next send doesn't have to wait for
   * the background reconnect timer.
   */
  reconnect() {
    if (this._reconnectCachedPeers) this._reconnectCachedPeers();
  }
}

/**
 * A bonjour-service instance whose mDNS failures reach `onError` and are never thrown. Every
 * user of bonjour-service in sym makes its instance here.
 *
 * bonjour-service answers mDNS queries through its multicast-dns socket, and given no error
 * callback it THROWS a failed send from inside the socket's callback, where nothing can catch
 * it: the sym daemon's room beacon, made without one, died of `send EHOSTUNREACH
 * 224.0.0.251:5353` three times in September 2026 when the network dropped. multicast-dns also
 * emits 'error' for a socket that cannot bind, which throws when nothing listens. The listener
 * this file attached for that looked for `bonjour.mdns`, which bonjour-service 1.4 does not have
 * (the socket's emitter is `bonjour.server.mdns`), so it was never attached.
 */
function createBonjour(onError) {
  const { Bonjour } = require('bonjour-service');
  const bonjour = new Bonjour(undefined, onError);
  const mdns = (bonjour.server && bonjour.server.mdns) || bonjour.mdns;
  if (mdns && typeof mdns.on === 'function') mdns.on('error', onError);
  return bonjour;
}

/** Inbound LAN connections that have not yet sent their first frame, at most (in all, and per address). */
const LISTENER_INFLIGHT_MAX = 256;
const LISTENER_INFLIGHT_PER_HOST = 16;
/** A LAN peer not re-announced for this long is dropped from the reconnect cache (see _reconnectCachedPeers). */
const BONJOUR_PEER_TTL_MS = 5 * 60_000;

// ── TXT records (RFC 6763 §6) ────────────────────────────────

/**
 * A DNS-SD TXT record's keys, as RFC 6763 §6.4 reads them and MMP §5.1 requires: a key is compared
 * case-insensitively (held lowercase), and when a key occurs more than once the FIRST occurrence wins.
 * A string with no `=` is a key present with no value (null); one that begins with `=` is ignored.
 * @param {Array<Buffer|string>} strings - the record's character-strings, in order
 * @returns {Map<string, string|null>}
 */
function parseTxtStrings(strings) {
  const out = new Map();
  for (const raw of Array.isArray(strings) ? strings : []) {
    const str = Buffer.isBuffer(raw) ? raw.toString('utf8') : (typeof raw === 'string' ? raw : null);
    if (str === null || str.length === 0 || str[0] === '=') continue;
    const eq = str.indexOf('=');
    const key = (eq === -1 ? str : str.slice(0, eq)).toLowerCase();
    if (out.has(key)) continue;
    out.set(key, eq === -1 ? null : str.slice(eq + 1));
  }
  return out;
}

/** A discovered service's TXT keys: from its raw strings when the library kept them, else its object. */
function serviceTxt(service) {
  if (service && Array.isArray(service.rawTxt)) return parseTxtStrings(service.rawTxt);
  const obj = service && service.txt && typeof service.txt === 'object' ? service.txt : {};
  return parseTxtStrings(Object.entries(obj).map(([k, v]) => `${k}=${v}`));
}

/**
 * Whether an advertisement's `mmp` value lists protocol version 2.0 (MMP §5.1): a comma-separated
 * list with no spaces; versions this node does not know are ignored.
 */
function mmpLists20(mmp) {
  return typeof mmp === 'string' && mmp.split(',').includes('2.0');
}

// ── Bonjour Discovery ────────────────────────────────────────

/**
 * LAN discovery via TCP server + Bonjour/mDNS.
 * Uses system dns-sd on macOS, falls back to bonjour-service on Linux.
 */
class BonjourDiscovery extends Discovery {
  /**
   * @param {object} [opts]
   * @param {boolean} [opts.mdns=true] — enable mDNS advertisement/browsing (set false for server-only mode)
   * @param {string} [opts.serviceType='_sym._tcp'] — Bonjour/mDNS service type
   *   for LAN isolation per MMP §5.8 Mesh Rooms. Default `_sym._tcp` stays
   *   compatible with the general sym mesh; apps that want an isolated
   *   sub-mesh on the same LAN (e.g. `_melotune._tcp`) pass their own
   *   service type here. Peers on different service types never discover
   *   each other at the mDNS layer.
   * @param {string[]} [opts.browseTypes] — further service types to browse, never advertised: the
   *   §5.1 migration browse of the per-room type earlier releases advertised (core/room-id
   *   legacyServiceType), so a 2.0 node still advertising only that type is found.
   * @param {number} [opts.handshakeTimeoutMs=10000] — inbound identification deadline (MMP §19.1)
   */
  constructor(opts = {}) {
    super();
    this._mdnsEnabled = opts.mdns !== false;
    this._handshakeTimeoutMs = opts.handshakeTimeoutMs ?? 10000;
    // MMP §5.8: Bonjour isolation by service type. Default `_sym._tcp`
    // preserves prior behaviour for callers who don't specify a room.
    this._serviceType = opts.serviceType || '_sym._tcp';
    // bonjour-service package expects the short form (no leading `_` or
    // trailing `._tcp`). Derive it from the full service type.
    this._bonjourType = this._serviceType
      .replace(/^_/, '')
      .replace(/\._tcp\.?$/, '');
    // The types browsed: the advertised one, then the migration browse (§5.1).
    this._browseTypes = [...new Set([this._serviceType, ...(Array.isArray(opts.browseTypes) ? opts.browseTypes.filter((t) => typeof t === 'string' && /^_[a-z0-9-]{1,15}\._tcp$/.test(t)) : [])])];
    this._server = null;
    this._bonjour = null;
    this._browsers = [];
    this._port = 0;
    this._identity = null;
    this._log = () => {};
    // The room advertised in TXT and the loopback registry (§5.1 `room`; the default room is 'default').
    this._room = opts.room || 'default';
  }

  async start(identity, log) {
    this._identity = identity;
    this._log = log || (() => {});

    // Start TCP server
    await this._startServer();

    // Same-host loopback discovery (network-independent). Two nodes on the
    // same machine mesh over 127.0.0.1 via a small filesystem registry —
    // even with no network interface (Wi-Fi off) where mDNS can't multicast.
    this._startLoopbackRegistry();

    // Start Bonjour advertisement + browsing (skip in server-only mode).
    //
    // Uses the bonjour-service npm package (pure JS multicast DNS) instead
    // of the native dns-sd binary. The dns-sd binary is available on macOS
    // but its resolve step (dns-sd -L) uses unicast queries that fail to
    // resolve services advertised by Windows' Bonjour implementation.
    // The bonjour-service package uses multicast for both browse AND
    // resolve, which works cross-platform (verified Mac↔Windows 2026-04-09).
    // See CHANGELOG 0.3.72 for the full diagnosis.
    if (this._mdnsEnabled) {
      this._startBonjourFallback();
    }

    return this._port;
  }

  async stop() {
    // Stop bonjour-service
    if (this._reconnectTimer) {
      clearInterval(this._reconnectTimer);
      this._reconnectTimer = null;
    }
    if (this._bonjourPeerCache) {
      this._bonjourPeerCache.clear();
      this._bonjourPeerCache = null;
    }
    this._stopBrowsers();
    if (this._bonjour) {
      try { this._bonjour.destroy(); } catch {}
      this._bonjour = null;
    }

    // Stop loopback registry + remove our endpoint.
    if (this._loopbackTimer) {
      clearInterval(this._loopbackTimer);
      this._loopbackTimer = null;
    }
    if (this._loopbackCatchup) {
      for (const t of this._loopbackCatchup) { try { clearTimeout(t); } catch {} }
      this._loopbackCatchup = null;
    }
    if (this._regFile) {
      try { fs.unlinkSync(this._regFile); } catch {}
      _liveRegistrations.delete(this._regFile);
      this._regFile = null;
    }

    // Close TCP server
    if (this._server) {
      await new Promise((resolve) => {
        this._server.close(() => resolve());
        setTimeout(resolve, 1000);
      });
      this._server = null;
    }
  }

  _startServer() {
    return new Promise((resolve, reject) => {
      this._server = net.createServer((socket) => {
        this._handleInboundConnection(socket);
      });
      this._server.on('error', (err) => {
        this._log(`Server error: ${err.message}`);
        reject(err);
      });
      this._server.listen(0, '0.0.0.0', () => {
        this._port = this._server.address().port;
        resolve();
      });
    });
  }

  /**
   * THE CORE SECURE LISTENER (design D2, §5.2): the first frame must be `client-hello`, and nothing
   * else is taken. A legacy `handshake` is refused at once — the connection closes and the refusal is
   * reported ('legacy-hello-refused', rate-limited by the node) — because a first-frame type chosen
   * by the peer must never choose the security policy (mmp-ingress). A 0.13 peer is reached only by a
   * Legacy Import route this node dials itself (design D7).
   */
  _handleInboundConnection(socket) {
    const transport = new TcpTransport(socket);
    const remote = `${socket.remoteAddress || '?'}:${socket.remotePort || '?'}`;
    let identified = false;
    const timeout = setTimeout(() => { if (!identified) transport.close(); }, this._handshakeTimeoutMs);
    // In flight before the first frame: at most LISTENER_INFLIGHT_MAX connections, and at most
    // LISTENER_INFLIGHT_PER_HOST from one address (security review D). Past either, the OLDEST such
    // connection is closed, so a flood of idle sockets cannot keep a newcomer out (it waits the
    // flood's whole deadline only if it is slower than LISTENER_INFLIGHT_MAX new connections).
    const host = socket.remoteAddress || '?';
    const entry = { transport, host };
    if (!this._preIdent) this._preIdent = new Set();
    const sameHost = [...this._preIdent].filter((e) => e.host === host);
    if (sameHost.length >= LISTENER_INFLIGHT_PER_HOST) sameHost[0].transport.close();
    if (this._preIdent.size >= LISTENER_INFLIGHT_MAX) this._preIdent.values().next().value.transport.close();
    this._preIdent.add(entry);
    const leave = () => this._preIdent.delete(entry);

    transport.on('message', (msg) => {
      if (identified) return;
      identified = true;
      leave();
      clearTimeout(timeout);
      transport.removeAllListeners('message');
      if (!msg || msg.type !== 'client-hello') {
        transport.close();
        if (msg && msg.type === 'handshake') this.emit('legacy-hello-refused', remote);
        return;
      }
      this.emit('inbound-connection', transport, msg, remote);
    });

    // A parse error must not cancel the identification deadline (MMP §4.1, §19.1):
    // the timer is cleared only by a handshake or by the transport closing.
    transport.on('error', () => {});
    transport.on('close', () => { clearTimeout(timeout); leave(); });
  }

  _startBonjourFallback() {
    const identity = this._identity;
    // A host whose multicast socket cannot bind or send (Termux on Android without a multicast
    // lock, some containers and VPNs) used to take the whole node down with an unhandled socket
    // error. LAN discovery is one transport of several: it degrades to "no LAN peers", says so,
    // and the relay (if configured) carries on. `SYM_RELAY_ONLY=1` skips this entirely.
    try {
      this._bonjour = createBonjour((err) => {
        this._log(`LAN discovery error (${err && err.message ? err.message : err}) — no LAN peers until it clears; relay peers unaffected`);
      });
    } catch (err) {
      this._log(`LAN discovery could not start (${err && err.message ? err.message : err}) — no LAN peers; relay peers unaffected`);
      this._bonjour = null;
      return;
    }

    // Explicit `host` — bonjour-service otherwise defaults to the bare
    // os.hostname(), which on Windows has no `.local` suffix and produces an
    // SRV target that macOS mDNSResponder refuses to resolve (breaks Mac↔Win).
    this._bonjour.publish({
      name: identity.nodeId,
      type: this._bonjourType,
      port: this._port,
      host: identity.hostname,
      // mmp=2.0 marks a Core Secure advertisement (design D2; drafted for §5.1): a 0.14 node dials a
      // record as Core Secure only when it carries it. room=<room> is §5.1's optional field.
      txt: { 'node-id': identity.nodeId, 'node-name': identity.name, 'public-key': identity.publicKey, 'hostname': identity.hostname, mmp: '2.0', room: this._room },
    });

    this._makeServiceHandlers(identity);
    this._startBrowsers();

    // Reconnect: restart the browser to force a fresh mDNS query.
    // bonjour-service caches discoveries and only fires 'up' once per
    // service name. If a peer restarts with a new port, the stale
    // cache has the wrong port and TCP silently fails. Restarting the
    // browser clears the cache and re-discovers with current ports.
    this._reconnectCachedPeers = () => {
      // Also try cached peers for fast reconnect when port hasn't changed. A peer that died without
      // an mDNS goodbye (killed, crashed, the host asleep) never fires 'down', so it used to stay
      // cached and be re-dialled every 15 s for as long as this node ran: on one host up to 17 dead
      // endpoints at once, 8.6 million "Connect failed" lines, 837 MB of the daemon's 1 GB log
      // (2026-09-28). Each browser restart below re-announces every live peer, so one not
      // announced for BONJOUR_PEER_TTL_MS (about 20 restarts) is gone, and is dropped.
      for (const [peerId, info] of this._cachedPeersToReoffer()) {
        this.emit('peer-found', info.address, info.port, peerId, info.peerName, info.info || {});
      }
      // Restart the browsers to discover updated ports
      this._stopBrowsers();
      this._startBrowsers();
    };

    // Background timer: periodic reconnect every 15s.
    this._reconnectTimer = setInterval(this._reconnectCachedPeers, 15000);
  }

  /** The browsers' handlers: a discovered service is offered to the node with its TXT read as §6.4 says. */
  _makeServiceHandlers(identity) {
    // Cache discovered peers so we can reconnect when TCP drops.
    this._bonjourPeerCache = new Map();

    // Named handlers so the browser can be restarted with the same logic.
    this._onServiceUp = (service) => {
      // TXT keys as RFC 6763 §6.4 reads them (MMP §5.1): case-insensitive, the first occurrence wins.
      // bonjour-service's own `txt` lets the last one win and keeps case, so the raw strings are read.
      const txt = serviceTxt(service);
      const peerId = txt.get('node-id');
      if (!peerId || peerId === identity.nodeId) return;
      const peerName = txt.get('node-name') || 'unknown';
      // Prefer IPv4 over IPv6 link-local.
      const allAddrs = service.addresses || [];
      const ipv4 = allAddrs.find(a => a && !a.includes(':'));
      const address = ipv4 || service.referer?.address || allAddrs[0];
      const port = service.port;
      if (!address || !port) return;

      const info = { mmp: typeof txt.get('mmp') === 'string' ? txt.get('mmp') : null, room: typeof txt.get('room') === 'string' ? txt.get('room') : null, source: 'bonjour' };
      // Update cache with current address:port, and when this peer was last announced
      this._bonjourPeerCache.set(peerId, { address, port, peerName, info, seenAt: Date.now() });

      this.emit('peer-found', address, port, peerId, peerName, info);
    };

    this._onServiceDown = (service) => {
      const peerId = serviceTxt(service).get('node-id');
      if (peerId) this._bonjourPeerCache.delete(peerId);
    };
  }

  /** One bonjour-service browser per browsed type (the advertised one, then the migration browse). */
  _startBrowsers() {
    if (!this._bonjour) return;
    for (const type of this._browseTypes) {
      const b = this._bonjour.find({ type: type.replace(/^_/, '').replace(/\._tcp\.?$/, '') });
      b.on('up', this._onServiceUp);
      b.on('down', this._onServiceDown);
      this._browsers.push(b);
    }
  }

  _stopBrowsers() {
    for (const b of this._browsers.splice(0)) { try { b.stop(); } catch {} }
  }

  /** The cached LAN peers to offer for reconnection now. A peer not announced for BONJOUR_PEER_TTL_MS
   *  is dropped from the cache instead (see _reconnectCachedPeers). */
  _cachedPeersToReoffer(now = Date.now()) {
    const due = [];
    if (!this._bonjourPeerCache) return due;
    for (const [peerId, info] of this._bonjourPeerCache) {
      if (!(now - info.seenAt <= BONJOUR_PEER_TTL_MS)) { this._bonjourPeerCache.delete(peerId); continue; }
      due.push([peerId, info]);
    }
    return due;
  }

  // ── Same-host loopback discovery ───────────────────────────
  //
  // mDNS needs a network interface to multicast; with Wi-Fi off, two nodes
  // on the same host can't see each other even though each already listens
  // on a TCP port. This registry makes same-host meshing network-independent:
  // each node advertises its loopback endpoint to ~/.sym/loopback/<nodeId>.json
  // (with a heartbeat) and scans the dir for live, same-room peers, dialing
  // them over 127.0.0.1 through the exact same handshake/transport path as
  // Bonjour. Runs ALONGSIDE Bonjour (deduped by nodeId in SymNode), so it
  // also fills in when mDNS is flaky. See MMP §5 (Connection, Layer 2).

  _loopbackDir() {
    // Under the state root, like every other file the engine keeps: a rooted deployment meets only
    // the nodes of its own root over 127.0.0.1.
    return require('./core/state-root').symPath('loopback');
  }

  _startLoopbackRegistry() {
    try {
      this._regDir = this._loopbackDir();
      fs.mkdirSync(this._regDir, { recursive: true });
      this._regFile = path.join(this._regDir, `${this._identity.nodeId}.json`);
      // Self-clean on abrupt exit. stop() unlinks the endpoint on graceful
      // teardown, but a process that exits or is signalled without calling
      // stop() (test runs that just finish, Ctrl-C) would leave a stale
      // registration behind until a pid-liveness check filters it out. The
      // process's one sync unlink on 'exit' (fires on normal completion and
      // process.exit()) makes the common case self-clean; a repeated start
      // adds the same file to the set, so nothing stacks.
      _unlinkOnExit(this._regFile);
      this._writeEndpoint();
      this._scanLoopback();
      // Quick catch-up scans so two agents started at nearly the same moment
      // find each other within ~1s, instead of waiting for the periodic tick
      // (the initial scan races: a peer that starts just after us isn't in the
      // registry yet).
      this._loopbackCatchup = [300, 1200, 3000].map((ms) => {
        const t = setTimeout(() => this._scanLoopback(), ms);
        if (t.unref) t.unref();
        return t;
      });
      // Steady-state heartbeat + rescan every 5s — keeps the endpoint well
      // inside the 30s staleness window and re-dials peers that restart on a
      // new port or join late.
      this._loopbackTimer = setInterval(() => {
        this._writeEndpoint();
        this._scanLoopback();
      }, 5000);
      if (this._loopbackTimer.unref) this._loopbackTimer.unref();
      this._log(`loopback registry active: ${this._regFile} (port ${this._port})`);
    } catch (err) {
      this._log(`loopback registry unavailable: ${err.message}`);
    }
  }

  _writeEndpoint() {
    try {
      const rec = JSON.stringify({
        nodeId: this._identity.nodeId,
        name: this._identity.name,
        port: this._port,
        pid: process.pid,
        serviceType: this._serviceType,
        // A Core Secure endpoint (design D2): a 0.13 registration has no mmp field.
        mmp: '2.0',
        room: this._room,
        ts: Date.now(),
      });
      // Atomic write (temp + rename) so a scanning peer never reads a partial file.
      const tmp = `${this._regFile}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, rec);
      fs.renameSync(tmp, this._regFile);
    } catch (err) {
      this._log(`loopback endpoint write failed: ${err.message}`);
    }
  }

  _scanLoopback() {
    if (!this._regFile) return; // stopped — don't dial after teardown
    const identity = this._identity;
    let files;
    try { files = fs.readdirSync(this._regDir); } catch { return; }
    const now = Date.now();
    for (const f of files) {
      if (!f.endsWith('.json') || f.endsWith('.tmp')) continue;
      const full = path.join(this._regDir, f);
      let rec;
      try { rec = loopbackRecord(JSON.parse(fs.readFileSync(full, 'utf8'))); } catch { continue; }
      if (!rec || rec.nodeId === identity.nodeId) continue;
      // Liveness FIRST, for every registration whatever its room: a dead process's registration is garbage to every
      // scanner. Same-host pid check: signal 0 tests existence; EPERM means the process exists but is not ours (alive);
      // ESRCH means dead. This used to run after the room filter below, so a registration whose room had no live node
      // left (every finished mission's) was never collected by anyone: 492 of 516 on one host (2026-09-28), and every
      // live node re-read all of them every 5 s. Room isolation now gates dialing only, as it should.
      let alive = true;
      if (rec.pid) {
        try { process.kill(rec.pid, 0); } catch (e) { alive = e.code === 'EPERM'; }
      }
      if (!alive) { try { fs.unlinkSync(full); } catch {} continue; } // GC dead entries, any room
      // A registration under a type this node browses (the room itself is filtered on TXT room by the
      // node, §5.1).
      if (rec.serviceType && !this._browseTypes.includes(rec.serviceType)) continue;
      const fresh = rec.ts && (now - rec.ts) < 30000;
      if (!fresh) continue;
      if (!rec.port) continue;
      // Tie-break: the lower nodeId dials; the higher one accepts the inbound, so the pair connects once.
      if (identity.nodeId < rec.nodeId) {
        this.emit('peer-found', '127.0.0.1', rec.port, rec.nodeId, rec.name, { mmp: rec.mmp, room: rec.room, source: 'loopback' });
      }
    }
  }
}

/**
 * A loopback registration read from the registry directory, taken as what it must be, or null. The
 * scan runs in a timer, where a throw is uncaught, and does arithmetic and comparisons on these
 * fields (`now - ts`, `nodeId < other`) and passes `name` on to be printed: a file holding an
 * object there (one that cannot be turned into a number or text) threw in that timer. Any process
 * of this user can write the directory, so its files are read like a frame.
 * @returns {{nodeId: string, name: string, port: number, pid: (number|null), serviceType: (string|null), ts: number, mmp: (string|null), room: (string|null)}|null}
 */
function loopbackRecord(r) {
  if (!r || typeof r !== 'object' || Array.isArray(r)) return null;
  const nodeId = wireNodeId(r.nodeId);
  if (!nodeId) return null;
  const port = Number.isInteger(r.port) && r.port > 0 && r.port < 65536 ? r.port : null;
  const pid = Number.isSafeInteger(r.pid) && r.pid > 0 ? r.pid : null;
  const ts = Number.isFinite(r.ts) ? r.ts : null;
  const serviceType = typeof r.serviceType === 'string' ? r.serviceType : null;
  // The Core Secure profile and room (§5.1), as the TXT record carries them; text or nothing.
  const mmp = typeof r.mmp === 'string' && r.mmp.length <= 16 ? r.mmp : null;
  const room = typeof r.room === 'string' && r.room.length <= 256 ? r.room : null;
  return { nodeId, name: wireName(r.name), port, pid, serviceType, ts, mmp, room };
}

// ── Null Discovery ───────────────────────────────────────────

/**
 * No-op discovery for relay-only nodes and testing.
 * No TCP server, no Bonjour, no child processes.
 */
class NullDiscovery extends Discovery {
  async start() { return 0; }
  async stop() {}
}

module.exports = { Discovery, BonjourDiscovery, NullDiscovery, createBonjour, parseTxtStrings, serviceTxt, mmpLists20 };
