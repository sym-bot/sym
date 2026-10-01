'use strict';

/**
 * Discovery — pluggable peer discovery for SYM mesh nodes.
 *
 * Three implementations:
 * - BonjourDiscovery: LAN discovery via dns-sd (macOS) or bonjour-service (Linux)
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
const os = require('os');
const path = require('path');
const { EventEmitter } = require('events');
const { TcpTransport } = require('./transport');

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

/** A LAN peer not re-announced for this long is dropped from the reconnect cache (see _reconnectCachedPeers). */
const BONJOUR_PEER_TTL_MS = 5 * 60_000;

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
    // Regex anchor for dns-sd browse output. Escape for embedding.
    this._browseAnchor = this._serviceType.replace(/\./g, '\\.');
    this._server = null;
    this._dnssdRegister = null;
    this._dnssdBrowse = null;
    this._bonjour = null;
    this._browser = null;
    this._port = 0;
    this._identity = null;
    this._log = () => {};
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
    // Kill dns-sd processes
    if (this._dnssdRegister) {
      try { this._dnssdRegister.kill(); } catch {}
      this._dnssdRegister = null;
    }
    if (this._dnssdBrowse) {
      try { this._dnssdBrowse.kill(); } catch {}
      this._dnssdBrowse = null;
    }

    // Stop bonjour-service fallback
    if (this._reconnectTimer) {
      clearInterval(this._reconnectTimer);
      this._reconnectTimer = null;
    }
    if (this._bonjourPeerCache) {
      this._bonjourPeerCache.clear();
      this._bonjourPeerCache = null;
    }
    if (this._browser) {
      try { this._browser.stop(); } catch {}
      this._browser = null;
    }
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

  _handleInboundConnection(socket) {
    const transport = new TcpTransport(socket);
    let identified = false;
    const timeout = setTimeout(() => { if (!identified) transport.close(); }, this._handshakeTimeoutMs);

    transport.on('message', (msg) => {
      if (identified) return;
      if (msg.type !== 'handshake') { transport.close(); return; }
      identified = true;
      clearTimeout(timeout);

      transport.removeAllListeners('message');
      this.emit('inbound-connection', transport, msg.nodeId, msg.name, msg);
    });

    // A parse error must not cancel the identification deadline (MMP §4.1, §19.1):
    // the timer is cleared only by a handshake or by the transport closing.
    transport.on('error', () => {});
    transport.on('close', () => clearTimeout(timeout));
  }

  _startDnsSd() {
    const { spawn } = require('child_process');
    const identity = this._identity;

    const txtParts = [
      `node-id=${identity.nodeId}`,
      `node-name=${identity.name}`,
      `public-key=${identity.publicKey}`,
      `hostname=${identity.hostname}`,
    ];
    this._dnssdRegister = spawn('dns-sd', [
      '-R', identity.nodeId, this._serviceType, 'local.',
      String(this._port), ...txtParts,
    ], { stdio: 'ignore', windowsHide: true });

    this._dnssdRegister.on('error', (err) => {
      this._log(`dns-sd not available, falling back to bonjour-service: ${err.message}`);
      this._dnssdRegister = null;
      if (this._dnssdBrowse) {
        try { this._dnssdBrowse.kill(); } catch {}
        this._dnssdBrowse = null;
      }
      this._startBonjourFallback();
    });

    this._dnssdBrowse = spawn('dns-sd', ['-B', this._serviceType], { stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true });
    this._dnssdBrowse.on('error', () => { this._dnssdBrowse = null; });

    const browseRegex = new RegExp(`\\s+Add\\s+\\d+\\s+\\d+\\s+\\S+\\s+${this._browseAnchor}\\.\\s+(.+)$`);
    let browseBuffer = '';
    this._dnssdBrowse.stdout.on('data', (data) => {
      browseBuffer += data.toString();
      let idx;
      while ((idx = browseBuffer.indexOf('\n')) !== -1) {
        const line = browseBuffer.slice(0, idx).trim();
        browseBuffer = browseBuffer.slice(idx + 1);
        const match = line.match(browseRegex);
        if (match) {
          const instanceName = match[1].trim();
          if (instanceName === identity.nodeId) continue;
          this._resolvePeer(instanceName);
        }
      }
    });
  }

  _resolvePeer(instanceName) {
    const { spawn } = require('child_process');
    const identity = this._identity;
    const resolve = spawn('dns-sd', ['-L', instanceName, this._serviceType, 'local.'], { stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true });
    let resolveBuffer = '';
    const timeout = setTimeout(() => resolve.kill(), 5000);

    resolve.stdout.on('data', (data) => {
      resolveBuffer += data.toString();
      const match = resolveBuffer.match(/can be reached at (.+?):(\d+)/);
      if (!match) return;

      clearTimeout(timeout);
      const host = match[1];
      const port = parseInt(match[2]);

      const nodeIdMatch = resolveBuffer.match(/node-id=(\S+)/);
      const nodeNameMatch = resolveBuffer.match(/node-name=(\S+)/);
      const peerId = nodeIdMatch ? nodeIdMatch[1] : instanceName;
      const peerName = nodeNameMatch ? nodeNameMatch[1] : 'unknown';

      resolve.kill();

      if (peerId === identity.nodeId) return;
      if (identity.nodeId < peerId) {
        this.emit('peer-found', host, port, peerId, peerName);
      }
    });
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
      txt: { 'node-id': identity.nodeId, 'node-name': identity.name, 'public-key': identity.publicKey, 'hostname': identity.hostname },
    });

    this._browser = this._bonjour.find({ type: this._bonjourType });

    // Cache discovered peers so we can reconnect when TCP drops.
    this._bonjourPeerCache = new Map();

    // Named handlers so the browser can be restarted with the same logic.
    this._onServiceUp = (service) => {
      const peerId = service.txt?.['node-id'];
      if (!peerId || peerId === identity.nodeId) return;
      const peerName = service.txt?.['node-name'] || 'unknown';
      // Prefer IPv4 over IPv6 link-local.
      const allAddrs = service.addresses || [];
      const ipv4 = allAddrs.find(a => a && !a.includes(':'));
      const address = ipv4 || service.referer?.address || allAddrs[0];
      const port = service.port;
      if (!address || !port) return;

      // Update cache with current address:port, and when this peer was last announced
      this._bonjourPeerCache.set(peerId, { address, port, peerName, seenAt: Date.now() });

      this.emit('peer-found', address, port, peerId, peerName);
    };

    this._onServiceDown = (service) => {
      const peerId = service.txt?.['node-id'];
      if (peerId) this._bonjourPeerCache.delete(peerId);
    };

    this._browser.on('up', this._onServiceUp);
    this._browser.on('down', this._onServiceDown);

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
        this.emit('peer-found', info.address, info.port, peerId, info.peerName);
      }
      // Restart the browser to discover updated ports
      if (this._browser) {
        try { this._browser.stop(); } catch {}
      }
      this._browser = this._bonjour.find({ type: this._bonjourType });
      this._browser.on('up', this._onServiceUp);
      this._browser.on('down', this._onServiceDown);
    };

    // Background timer: periodic reconnect every 15s.
    this._reconnectTimer = setInterval(this._reconnectCachedPeers, 15000);
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
    return path.join(os.homedir(), '.sym', 'loopback');
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
      try { rec = JSON.parse(fs.readFileSync(full, 'utf8')); } catch { continue; }
      if (!rec || !rec.nodeId || rec.nodeId === identity.nodeId) continue;
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
      // Room isolation — only mesh the same service type (MMP §5.8).
      if (rec.serviceType && rec.serviceType !== this._serviceType) continue;
      const fresh = rec.ts && (now - rec.ts) < 30000;
      if (!fresh) continue;
      if (!rec.port) continue;
      // Tie-break: the lower nodeId dials; the higher one accepts the inbound.
      // Mirrors the Bonjour _resolvePeer path so we connect exactly once.
      if (identity.nodeId < rec.nodeId) {
        this.emit('peer-found', '127.0.0.1', rec.port, rec.nodeId, rec.name || 'unknown');
      }
    }
  }
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

module.exports = { Discovery, BonjourDiscovery, NullDiscovery, createBonjour };
