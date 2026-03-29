'use strict';

const fs = require('fs');
const net = require('net');
const path = require('path');
const { EventEmitter } = require('events');
const { MeshNode } = require('@sym-bot/core');
const { nodeDir, loadOrCreateIdentity, log: logMsg } = require('./config');
const { MemoryStore } = require('./memory-store');
const {
  encode, DIM, createCMB, renderContent, FIELD_WEIGHT_PROFILES,
  SVAFEvaluator, FrameHandler, WakeManager, XMesh,
} = require('@sym-bot/core');
const { TcpTransport } = require('./transport');
const { RelayConnection } = require('./relay');

/**
 * SymNode — a sovereign mesh node with cognitive coupling.
 *
 * Each node encodes its memories into a hidden state vector.
 * When peers connect, the coupling engine evaluates drift between
 * their cognitive states and autonomously decides whether to couple.
 *
 * Aligned peers share memories. Divergent peers stay independent.
 * The intelligence is in the decision to share, not in the sharing itself.
 */
class SymNode extends EventEmitter {

  constructor(opts = {}) {
    super();
    if (!opts.name) throw new Error('SymNode requires a name');
    this._silent = opts.silent || false;

    this.name = opts.name;
    this._cognitiveProfile = opts.cognitiveProfile || null;
    this._moodThreshold = opts.moodThreshold ?? 0.8;

    // SVAF parameters (paper Section 3.2-3.3)
    this._svafStableThreshold = opts.svafStableThreshold ?? 0.25;
    this._svafGuardedThreshold = opts.svafGuardedThreshold ?? 0.5;
    this._svafTemporalLambda = opts.svafTemporalLambda ?? 0.3;
    this._svafFreshnessSeconds = opts.svafFreshnessSeconds ?? 1800;
    this._svafFieldWeights = opts.svafFieldWeights ?? FIELD_WEIGHT_PROFILES.uniform;

    // Neural SVAF evaluator (Layer 4 cognition — falls back to heuristic if unavailable)
    this._svafEvaluator = new SVAFEvaluator({
      log: (msg) => this._log(msg),
    });
    this._identity = loadOrCreateIdentity(this.name);
    this._dir = nodeDir(this.name);
    this._meshmemDir = path.join(this._dir, 'meshmem');
    const legacyDir = path.join(this._dir, 'memories');
    this._store = new MemoryStore(this._meshmemDir, this.name, {
      legacyDir: fs.existsSync(legacyDir) ? legacyDir : undefined,
    });

    // Coupling engine — evaluates peer cognitive state
    this._meshNode = new MeshNode({ hiddenDim: DIM });
    this._initLocalState();

    // xMesh — per-agent LNN (Layer 6)
    this._xmesh = new XMesh({
      log: (msg) => this._log(msg),
      onInsight: (insight) => {
        this.broadcastInsight(insight);
        this.emit('insight', insight);
      },
    });

    // Peer state
    this._peers = new Map();
    this._server = null;
    this._bonjour = null;
    this._browser = null;
    this._port = 0;
    this._running = false;

    // Wake
    this._wakeChannel = opts.wakeChannel || null;
    this._peerWakeChannels = new Map();
    this._peerLastWake = new Map();
    this._pendingFrames = new Map();

    this._wakeManager = new WakeManager({
      wakeChannelsFile: path.join(this._dir, 'wake-channels.json'),
      peerWakeChannels: this._peerWakeChannels,
      peerLastWake: this._peerLastWake,
      pendingFrames: this._pendingFrames,
      wakeCooldownMs: opts.wakeCooldownMs || 5 * 60 * 1000,
      wakeChannel: this._wakeChannel,
      log: (msg) => this._log(msg),
      getPeers: () => this._peers,
      getMeshNode: () => this._meshNode,
      getIdentity: () => this._identity,
      nodeName: this.name,
    });
    this._wakeManager.loadWakeChannels();

    // Relay
    this._relayUrl = opts.relay || null;
    this._relayToken = opts.relayToken || null;
    this._relayOnly = opts.relayOnly || false;

    this._relay = new RelayConnection({
      relayUrl: this._relayUrl,
      relayToken: this._relayToken,
      wakeChannel: this._wakeChannel,
      log: (msg) => this._log(msg),
      getIdentity: () => this._identity,
      isRunning: () => this._running,
      getPeers: () => this._peers,
      getMeshNode: () => this._meshNode,
      createPeer: (transport, peerId, peerName, isOutbound, source) => this._createPeer(transport, peerId, peerName, isOutbound, source),
      addPeer: (peer) => this._addPeer(peer),
      handlePeerMessage: (peerId, peerName, msg) => this._frameHandler.handle(peerId, peerName, msg),
      onPeerLeft: (peerId, peerName) => this.emit('peer-left', { id: peerId, name: peerName }),
      nodeName: this.name,
      peerWakeChannels: this._peerWakeChannels,
      saveWakeChannels: () => this._wakeManager.saveWakeChannels(),
    });

    // Frame handler
    this._frameHandler = new FrameHandler(this);

    // Synthesis delegate — agent processes xMesh insight and produces new outbound CMBs
    this._synthesisDelegate = opts.onSynthesis || null;

    // Timers
    this._heartbeatInterval = opts.heartbeatInterval || 5000;
    this._heartbeatTimeout = opts.heartbeatTimeout || 15000;
    this._heartbeatTimer = null;
    this._encodeInterval = opts.encodeInterval || 30000;
    this._encodeTimer = null;
  }

  // ── Context Encoding ───────────────────────────────────────

  _initLocalState() {
    const context = this._buildContext();
    if (context.length > 5) {
      const { h1, h2 } = encode(context);
      this._meshNode.updateLocalState(h1, h2, 0.8);
    } else {
      const h1 = Array.from({ length: DIM }, () => (Math.random() - 0.5) * 0.1);
      const h2 = Array.from({ length: DIM }, () => (Math.random() - 0.5) * 0.1);
      this._meshNode.updateLocalState(h1, h2, 0.3);
    }
  }

  _buildContext() {
    const parts = [];
    if (this._cognitiveProfile) parts.push(this._cognitiveProfile);
    const entries = this._store.allEntries().slice(0, 20);
    parts.push(...entries.map(e => e.content || ''));
    return parts.join('\n');
  }

  _reencodeAndBroadcast() {
    const context = this._buildContext();
    if (context.length < 5) return;

    const { h1, h2 } = encode(context);
    this._meshNode.updateLocalState(h1, h2, 0.8);
    this._broadcastToPeers({ type: 'state-sync', h1, h2, confidence: 0.8 });
  }

  /**
   * Update cognitive state from external context (e.g. Claude Code's memories).
   * Does not store anything — just re-encodes and broadcasts.
   */
  updateContext(text) {
    if (!text || text.length < 5) return;
    const { h1, h2 } = encode(text);
    this._meshNode.updateLocalState(h1, h2, 0.8);
    this._broadcastToPeers({ type: 'state-sync', h1, h2, confidence: 0.8 });
  }

  /**
   * Share content with cognitively aligned peers without storing locally.
   * Used by ClaudeMemoryBridge — Claude Code's memory dir is the source of truth.
   */
  shareWithPeers(content, opts = {}) {
    const cmb = opts.cmb || createCMB({ rawText: content, createdBy: opts.source || this.name });

    // Build memory-share frame per MMP spec Section 7
    const frame = {
      type: 'memory-share',
      timestamp: Date.now(),
      cmb,
    };

    this._meshNode.coupledState();

    let shared = 0;
    for (const [peerId, peer] of this._peers) {
      peer.transport.send(frame);
      shared++;
    }

    this._log(`Shared: "${content.slice(0, 50)}${content.length > 50 ? '...' : ''}" → ${shared}/${this._peers.size} peers`);
    return { key: cmb.key, content, cmb, timestamp: frame.timestamp };
  }

  // ── Lifecycle ──────────────────────────────────────────────

  async start() {
    if (this._running) return;
    this._running = true;

    if (!this._relayOnly) {
      await this._startServer();
      this._startDiscovery();
    }

    if (this._relayUrl) {
      this._relay.connect();
    }

    this._heartbeatTimer = setInterval(() => this._checkHeartbeats(), this._heartbeatInterval);
    this._encodeTimer = setInterval(() => this._reencodeAndBroadcast(), this._encodeInterval);

    this._log(`Started (port: ${this._port}, id: ${this._identity.nodeId.slice(0, 8)}${this._relayUrl ? ', relay: ' + this._relayUrl : ''})`);
  }

  async stop() {
    if (!this._running) return;
    this._running = false;

    if (this._heartbeatTimer) clearInterval(this._heartbeatTimer);
    if (this._encodeTimer) clearInterval(this._encodeTimer);

    this._relay.destroy();

    for (const [, peer] of this._peers) {
      peer.transport.close();
    }
    this._peers.clear();

    if (this._dnssdRegister) {
      try { this._dnssdRegister.kill(); } catch {}
      this._dnssdRegister = null;
    }
    if (this._dnssdBrowse) {
      try { this._dnssdBrowse.kill(); } catch {}
      this._dnssdBrowse = null;
    }
    if (this._bonjour) {
      try { this._bonjour.destroy(); } catch {}
      this._bonjour = null;
    }

    if (this._server) {
      this._server.close();
      this._server = null;
    }

    this._log('Stopped');
  }

  // ── Memory (with cognitive coupling) ───────────────────────

  remember(fields, opts = {}) {
    if (!opts.cmb) {
      if (!fields || typeof fields !== 'object') {
        throw new Error('remember() requires CAT7 fields — the agent LLM extracts fields');
      }
      opts.cmb = createCMB({ fields, createdBy: this.name });
    }
    const content = renderContent(opts.cmb);
    const entry = this._store.write(content, opts);

    // Duplicate — already stored, skip broadcast
    if (!entry) return null;

    const context = this._buildContext();
    const { h1, h2 } = encode(context);
    this._meshNode.updateLocalState(h1, h2, 0.8);

    this._meshNode.coupledState();

    // Build memory-share frame per MMP spec Section 7: timestamp + cmb only
    const frame = {
      type: 'memory-share',
      timestamp: entry.storedAt,
      cmb: entry.cmb || null,
    };

    let shared = 0;
    for (const [peerId, peer] of this._peers) {
      peer.transport.send(frame);
      shared++;
    }

    // Feed signal to xMesh (Layer 6)
    this._xmesh.ingestSignal({
      from: this.name,
      content,
      timestamp: entry.storedAt,
      type: 'own',
      valence: opts.cmb?.fields?.mood?.valence || 0,
      arousal: opts.cmb?.fields?.mood?.arousal || 0,
    });

    this._log(`Remembered: "${content.slice(0, 50)}${content.length > 50 ? '...' : ''}" → ${shared}/${this._peers.size} peers`);
    return entry;
  }

  recall(query) {
    return this._store.search(query);
  }

  // ── Mood (with cognitive evaluation) ───────────────────────

  broadcastMood(mood, opts = {}) {
    const frame = {
      type: 'mood',
      from: this._identity.nodeId,
      fromName: this.name,
      mood,
      context: opts.context || null,
      timestamp: Date.now(),
    };
    this._broadcastToPeers(frame);
    this._wakeManager.wakeSleepingPeers('mood', frame);
    this._log(`Mood broadcast: "${mood.slice(0, 50)}"`);
  }

  // ── xMesh Insight (per-agent LNN cognitive state) ──────────

  broadcastInsight(insight) {
    const frame = {
      type: 'xmesh-insight',
      from: this._identity.nodeId,
      fromName: this.name,
      trajectory: insight.trajectory,
      patterns: insight.patterns,
      anomaly: insight.anomaly,
      remixScore: insight.remixScore,
      coherence: insight.coherence,
      timestamp: Date.now(),
    };
    this._broadcastToPeers(frame);
    this._wakeManager.wakeSleepingPeers('xmesh-insight', frame);
    this._log(`xMesh insight broadcast`);
  }

  set onSynthesis(fn) {
    this._synthesisDelegate = typeof fn === 'function' ? fn : null;
  }

  // ── Communication ──────────────────────────────────────────

  send(message, opts = {}) {
    const frame = {
      type: 'message',
      from: this._identity.nodeId,
      fromName: this.name,
      content: message,
      timestamp: Date.now(),
    };
    if (opts.to) {
      const peer = this._peers.get(opts.to);
      if (peer) peer.transport.send(frame);
    } else {
      this._broadcastToPeers(frame);
      this._wakeManager.wakeSleepingPeers('message', frame);
    }
  }

  // ── Wake (delegated) ──────────────────────────────────────

  async wakeIfNeeded(peerId, reason = 'message') {
    return this._wakeManager.wakeIfNeeded(peerId, reason);
  }

  async wakeAllPeers(reason = 'message') {
    return this._wakeManager.wakeAllPeers(reason);
  }

  // ── Monitoring ─────────────────────────────────────────────

  peers() {
    const result = [];
    const decisions = this._meshNode.couplingDecisions;
    for (const [id, peer] of this._peers) {
      const d = decisions.get(id);
      result.push({
        id: id.slice(0, 8),
        name: peer.name || 'unknown',
        connected: true,
        lastSeen: peer.lastSeen,
        coupling: d ? d.decision : 'pending',
        drift: d ? parseFloat(d.drift.toFixed(3)) : null,
        source: peer.source || 'bonjour',
      });
    }
    return result;
  }

  memories() {
    return this._store.count();
  }

  coherence() {
    return this._meshNode.coherence;
  }

  status() {
    return {
      name: this.name,
      nodeId: this._identity.nodeId.slice(0, 8),
      running: this._running,
      port: this._port,
      relay: this._relayUrl || null,
      relayConnected: this._relay.ws?.readyState === 1 || false,
      peers: this.peers(),
      peerCount: this._peers.size,
      memoryCount: this.memories(),
      coherence: this.coherence(),
    };
  }

  // ── TCP Server ─────────────────────────────────────────────

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
      if (this._peers.has(msg.nodeId)) { transport.close(); return; }

      transport.removeAllListeners('message');
      transport.on('message', (m) => {
        const peer = this._peers.get(msg.nodeId);
        if (peer) peer.lastSeen = Date.now();
        this._frameHandler.handle(msg.nodeId, msg.name, m);
      });

      const peer = this._createPeer(transport, msg.nodeId, msg.name, false, 'bonjour');
      this._addPeer(peer);
    });

    transport.on('error', () => clearTimeout(timeout));
  }

  // ── Bonjour Discovery ──────────────────────────────────────

  _startDiscovery() {
    const { spawn } = require('child_process');

    // Register via system dns-sd (Apple's native mDNS responder).
    // This ensures NWConnection on iOS can resolve the service endpoint.
    // The JavaScript bonjour-service library uses its own multicast DNS
    // which Apple's Network framework cannot resolve.
    const txtParts = [
      `node-id=${this._identity.nodeId}`,
      `node-name=${this.name}`,
      `hostname=${this._identity.hostname}`,
    ];
    this._dnssdRegister = spawn('dns-sd', [
      '-R', this._identity.nodeId, '_sym._tcp', 'local.',
      String(this._port), ...txtParts,
    ], { stdio: 'ignore' });

    this._dnssdRegister.on('error', (err) => {
      // Fallback to JavaScript mDNS if dns-sd not available (Linux)
      this._log(`dns-sd not available, falling back to bonjour-service: ${err.message}`);
      this._startBonjourFallback();
    });

    // Browse for peers via dns-sd
    this._dnssdBrowse = spawn('dns-sd', ['-B', '_sym._tcp'], { stdio: ['ignore', 'pipe', 'ignore'] });
    let browseBuffer = '';
    this._dnssdBrowse.stdout.on('data', (data) => {
      browseBuffer += data.toString();
      let idx;
      while ((idx = browseBuffer.indexOf('\n')) !== -1) {
        const line = browseBuffer.slice(0, idx).trim();
        browseBuffer = browseBuffer.slice(idx + 1);
        // Parse dns-sd -B output: "Timestamp  A/R  Flags  if  Domain  Service Type  Instance Name"
        const match = line.match(/\s+Add\s+\d+\s+\d+\s+\S+\s+_sym\._tcp\.\s+(.+)$/);
        if (match) {
          const instanceName = match[1].trim();
          if (instanceName === this._identity.nodeId) continue; // self
          this._resolvePeer(instanceName);
        }
      }
    });
  }

  _resolvePeer(instanceName) {
    const { spawn } = require('child_process');
    const resolve = spawn('dns-sd', ['-L', instanceName, '_sym._tcp', 'local.'], { stdio: ['ignore', 'pipe', 'ignore'] });
    let resolveBuffer = '';
    const timeout = setTimeout(() => resolve.kill(), 5000);

    resolve.stdout.on('data', (data) => {
      resolveBuffer += data.toString();
      // Parse: "instance._sym._tcp.local. can be reached at hostname:port (interface N)"
      const match = resolveBuffer.match(/can be reached at (.+?):(\d+)/);
      if (!match) return;

      clearTimeout(timeout);
      const host = match[1];
      const port = parseInt(match[2]);

      // Extract TXT record values
      const nodeIdMatch = resolveBuffer.match(/node-id=(\S+)/);
      const nodeNameMatch = resolveBuffer.match(/node-name=(\S+)/);
      const peerId = nodeIdMatch ? nodeIdMatch[1] : instanceName;
      const peerName = nodeNameMatch ? nodeNameMatch[1] : 'unknown';

      resolve.kill();

      if (peerId === this._identity.nodeId) return;
      if (this._identity.nodeId < peerId && !this._peers.has(peerId)) {
        this._connectToPeer(host, port, peerId, peerName);
      }
    });
  }

  _startBonjourFallback() {
    const { Bonjour } = require('bonjour-service');
    this._bonjour = new Bonjour();

    this._bonjour.publish({
      name: this._identity.nodeId,
      type: 'sym',
      port: this._port,
      txt: { 'node-id': this._identity.nodeId, 'node-name': this.name, 'hostname': this._identity.hostname },
    });

    this._browser = this._bonjour.find({ type: 'sym' });

    this._browser.on('up', (service) => {
      const peerId = service.txt?.['node-id'];
      if (!peerId || peerId === this._identity.nodeId) return;
      const peerName = service.txt?.['node-name'] || 'unknown';
      const address = service.referer?.address || service.addresses?.[0];
      const port = service.port;
      if (!address || !port) return;
      if (this._identity.nodeId < peerId && !this._peers.has(peerId)) {
        this._connectToPeer(address, port, peerId, peerName);
      }
    });
  }

  _connectToPeer(address, port, peerId, peerName) {
    if (this._peers.has(peerId)) return;
    const socket = net.createConnection({ host: address, port }, () => {
      const transport = new TcpTransport(socket);
      transport.on('message', (msg) => {
        const peer = this._peers.get(peerId);
        if (peer) peer.lastSeen = Date.now();
        this._frameHandler.handle(peerId, peerName, msg);
      });
      transport.on('error', () => {});
      const peer = this._createPeer(transport, peerId, peerName, true, 'bonjour');
      this._addPeer(peer);
    });
    socket.on('error', (err) => this._log(`Connect failed to ${peerName}: ${err.message}`));
    socket.setTimeout(10000, () => socket.destroy());
  }

  // ── Peer Management ────────────────────────────────────────

  _createPeer(transport, peerId, peerName, isOutbound, source) {
    transport.on('close', () => {
      this._peers.delete(peerId);
      this._meshNode.removePeer(peerId);
      this._log(`Peer disconnected: ${peerName}`);
      this.emit('peer-left', { id: peerId, name: peerName });
    });

    return { transport, peerId, name: peerName, isOutbound, source, lastSeen: Date.now() };
  }

  _addPeer(peer) {
    this._peers.set(peer.peerId, peer);

    // Handshake
    peer.transport.send({ type: 'handshake', nodeId: this._identity.nodeId, name: this.name });

    // Send cognitive state for coupling evaluation
    const [h1, h2] = this._meshNode.coupledState();
    peer.transport.send({ type: 'state-sync', h1, h2, confidence: 0.8 });

    // Send wake channel if configured (legacy, for backward compat)
    if (this._wakeChannel) {
      peer.transport.send({ type: 'wake-channel', ...this._wakeChannel });
    }

    // Send peer-info gossip
    const knownPeers = [];
    for (const [id, wc] of this._peerWakeChannels) {
      if (id !== peer.peerId) {
        const peerEntry = this._peers.get(id);
        knownPeers.push({ nodeId: id, name: peerEntry?.name || 'unknown', wakeChannel: wc, lastSeen: Date.now() });
      }
    }
    if (knownPeers.length > 0) {
      peer.transport.send({ type: 'peer-info', peers: knownPeers });
    }

    this._log(`Peer connected: ${peer.name} (${peer.isOutbound ? 'outbound' : 'inbound'}, ${peer.source})`);
    this.emit('peer-joined', { id: peer.peerId, name: peer.name });

    // Deliver any frames queued while this peer was sleeping
    const pending = this._pendingFrames.get(peer.peerId);
    if (pending && pending.length > 0) {
      this._log(`Delivering ${pending.length} pending frame(s) to ${peer.name}`);
      for (const frame of pending) {
        peer.transport.send(frame);
      }
      this._pendingFrames.delete(peer.peerId);
    }
  }

  _broadcastToPeers(frame) {
    for (const [, peer] of this._peers) {
      peer.transport.send(frame);
    }
  }

  _checkHeartbeats() {
    const now = Date.now();
    for (const [id, peer] of this._peers) {
      if (now - peer.lastSeen > this._heartbeatTimeout) {
        this._log(`Heartbeat timeout: ${peer.name}`);
        peer.transport.close();
        this._peers.delete(id);
        this._meshNode.removePeer(id);
      } else if (now - peer.lastSeen > this._heartbeatInterval) {
        peer.transport.send({ type: 'ping' });
      }
    }
  }

  _log(msg) {
    if (!this._silent) logMsg(this.name, msg);
  }
}

module.exports = { SymNode };
