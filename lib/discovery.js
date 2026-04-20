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
 * Copyright (c) 2026 SYM.BOT Ltd. Apache 2.0 License.
 */

const net = require('net');
const { EventEmitter } = require('events');
const { TcpTransport } = require('./transport');

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
   *   for LAN isolation per MMP §5.8 Mesh Groups. Default `_sym._tcp` stays
   *   compatible with the general sym mesh; apps that want an isolated
   *   sub-mesh on the same LAN (e.g. `_melotune._tcp`) pass their own
   *   service type here. Peers on different service types never discover
   *   each other at the mDNS layer.
   */
  constructor(opts = {}) {
    super();
    this._mdnsEnabled = opts.mdns !== false;
    // MMP §5.8: Bonjour isolation by service type. Default `_sym._tcp`
    // preserves prior behaviour for callers who don't specify a group.
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
    const timeout = setTimeout(() => { if (!identified) transport.close(); }, 10000);

    transport.on('message', (msg) => {
      if (identified) return;
      if (msg.type !== 'handshake') { transport.close(); return; }
      identified = true;
      clearTimeout(timeout);

      transport.removeAllListeners('message');
      this.emit('inbound-connection', transport, msg.nodeId, msg.name, msg);
    });

    transport.on('error', () => clearTimeout(timeout));
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
    const { Bonjour } = require('bonjour-service');
    const identity = this._identity;
    this._bonjour = new Bonjour();

    this._bonjour.publish({
      name: identity.nodeId,
      type: this._bonjourType,
      port: this._port,
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

      // Update cache with current address:port
      this._bonjourPeerCache.set(peerId, { address, port, peerName });

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
      // Also try cached peers for fast reconnect when port hasn't changed
      if (this._bonjourPeerCache) {
        for (const [peerId, info] of this._bonjourPeerCache) {
          this.emit('peer-found', info.address, info.port, peerId, info.peerName);
        }
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

module.exports = { Discovery, BonjourDiscovery, NullDiscovery };
