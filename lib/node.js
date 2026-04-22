'use strict';

/**
 * SymNode — sovereign mesh node with cognitive coupling.
 *
 * Each node encodes its memories into a hidden state vector.
 * When peers connect, the coupling engine evaluates drift between
 * their cognitive states and autonomously decides whether to couple.
 *
 * Aligned peers share memories. Divergent peers stay independent.
 * The intelligence is in the decision to share, not in the sharing itself.
 *
 * See MMP v0.2.0 Section 3 (Identity), Section 4 (Transport),
 * Section 5 (Connection), Section 6 (Memory), Section 9 (Coupling & SVAF).
 *
 * Copyright (c) 2026 SYM.BOT. Apache 2.0 License.
 */

const fs = require('fs');
const net = require('net');
const path = require('path');
const { EventEmitter } = require('events');
const { MeshNode } = require('@sym-bot/core');
const { nodeDir, loadOrCreateIdentity, acquireIdentityLock, log: logMsg } = require('./config');
const { MemoryStore } = require('./memory-store');
const {
  encode, DIM, createCMB, renderContent, FIELD_WEIGHT_PROFILES,
  SVAFEvaluator, WakeManager, XMesh,
  e2eGenerateKeyPair, e2eDeriveSharedSecret, encryptFields,
} = require('@sym-bot/core');
const { FrameHandler } = require('./frame-handler');
const { TcpTransport } = require('./transport');
const { RelayConnection } = require('./relay');
const { BonjourDiscovery, NullDiscovery } = require('./discovery');
class SymNode extends EventEmitter {

  /**
   * Create a new SymNode.
   *
   * @param {object} opts
   * @param {string} opts.name — required node name (See MMP v0.2.0 Section 3)
   * @param {string} [opts.cognitiveProfile] — free-text cognitive profile for encoding
   * @param {number} [opts.moodThreshold=0.8] — threshold for mood acceptance
   * @param {number} [opts.svafStableThreshold=0.25] — SVAF stable coupling threshold
   * @param {number} [opts.svafGuardedThreshold=0.5] — SVAF guarded coupling threshold
   * @param {number} [opts.svafTemporalLambda=0.3] — SVAF temporal decay lambda
   * @param {number} [opts.svafFreshnessSeconds=1800] — SVAF freshness window
   * @param {object} [opts.svafFieldWeights] — per-field weight profile (See MMP v0.2.0 Section 9)
   * @param {number} [opts.retentionSeconds=86400] — CMB retention period
   * @param {object} [opts.wakeChannel] — wake channel configuration
   * @param {string} [opts.relay] — WebSocket relay URL (See MMP v0.2.0 Section 4)
   * @param {string} [opts.relayToken] — relay authentication token
   * @param {boolean} [opts.relayOnly=false] — skip LAN discovery, relay only
   * @param {boolean} [opts.silent=false] — suppress log output
   * @param {function} [opts.onSynthesis] — synthesis delegate for xMesh insights
   * @param {number} [opts.heartbeatInterval=5000] — heartbeat check interval in ms
   * @param {number} [opts.heartbeatTimeout=15000] — heartbeat timeout in ms
   * @param {number} [opts.encodeInterval=30000] — re-encode and broadcast interval in ms
   */
  constructor(opts = {}) {
    super();
    if (!opts.name) throw new Error('SymNode requires a name');
    this._silent = opts.silent || false;

    this.name = opts.name;
    this.nodeId = null; // set after identity loaded (see below)
    this._cognitiveProfile = opts.cognitiveProfile || null;
    this._moodThreshold = opts.moodThreshold ?? 0.8;

    // Section 3.5: Node lifecycle role — observer (default), validator, or anchor.
    // Validator/anchor nodes produce feedback CMBs with elevated anchor weight (Section 11.1).
    this._lifecycleRole = opts.lifecycleRole || 'observer';

    // Track peer lifecycle roles from handshake (Section 6.4: validator-origin weight 2.0)
    this._peerLifecycleRoles = new Map();

    // SVAF parameters (paper Section 3.2-3.3)
    this._svafStableThreshold = opts.svafStableThreshold ?? 0.25;
    this._svafGuardedThreshold = opts.svafGuardedThreshold ?? 0.5;
    this._svafTemporalLambda = opts.svafTemporalLambda ?? 0.3;
    this._svafFreshnessSeconds = opts.svafFreshnessSeconds ?? 1800;
    this._svafFieldWeights = opts.svafFieldWeights ?? FIELD_WEIGHT_PROFILES.uniform;

    // Retention — how long to keep CMBs in local storage (default 86400s = 24h)
    // Regulated domains MUST set per compliance: legal (jurisdiction), health (HIPAA 6yr), finance (MiFID II 5yr, SEC 7yr)
    this._retentionSeconds = opts.retentionSeconds ?? 86400;

    // Neural SVAF evaluator (Layer 4 cognition). See MMP v0.2.0 Section 9.
    this._svafEvaluator = new SVAFEvaluator({
      log: (msg) => this._log(msg),
    });
    this._identity = loadOrCreateIdentity(this.name);
    this.nodeId = this._identity.nodeId;
    this._dir = nodeDir(this.name);

    // Acquire exclusive lock on this identity. Prevents two SymNode
    // processes on the same host from claiming the same nodeId, which
    // caused duplicate-identity races on the relay (close 4004 / 4006
    // loops, peer-flap floods, broken push paths). The lock is held
    // for the lifetime of this process; stop() releases it. Hosts MUST
    // wire SIGTERM/SIGINT to call stop() so the lockfile is cleaned
    // up on graceful exit — otherwise the lock becomes stale and the
    // next start() reclaims it via dead-PID detection.
    //
    // Throws with code 'EIDENTITYLOCK' if another process already holds
    // the lock. Hosts should catch and exit cleanly (or pick a
    // different SYM_NODE_NAME).
    this._releaseIdentityLock = acquireIdentityLock(this.name);

    // E2E encryption — X25519 keypair for CMB field encryption
    this._e2eKeyPair = this._loadOrCreateE2EKeyPair();
    this._peerSharedSecrets = new Map();
    this._meshmemDir = path.join(this._dir, 'meshmem');
    const legacyDir = path.join(this._dir, 'memories');
    this._store = new MemoryStore(this._meshmemDir, this.name, {
      legacyDir: fs.existsSync(legacyDir) ? legacyDir : undefined,
    });

    // Wrap receiveFromPeer to emit 'cmb-accepted' event.
    // frame-handler.js (sym-core) calls _store.receiveFromPeer() after SVAF
    // accepts an incoming CMB. This proxy lets application-layer agents react
    // to accepted signals in real-time for remix (MMP v0.2.0 Section 14).
    const originalReceiveFromPeer = this._store.receiveFromPeer.bind(this._store);
    this._store.receiveFromPeer = (peerId, entry) => {
      const stored = originalReceiveFromPeer(peerId, entry);
      if (stored) {
        this._metrics.cmbAccepted++;
        // Preserve _anchor flag from reconnect anchor CMBs so mesh-agent
        // can skip remix for historical context replays.
        if (entry._anchor) stored._anchor = true;
        this.emit('cmb-accepted', stored);
        this.emit('metric', { type: 'cmb-accepted', from: entry.source || peerId, key: stored.key });
      }
      return stored;
    };

    // Protocol-level metrics — structured event tracking for observability.
    // Every significant protocol operation is counted and emitted.
    // Applications (sym.day, monitoring) subscribe via node.on('metric', ...)
    // See MMP v0.2.0 Section 13 (Application).
    this._metrics = {
      cmbProduced: 0,        // CMBs created by this agent via remember()
      cmbAccepted: 0,        // Peer CMBs accepted by SVAF
      cmbRejected: 0,        // Peer CMBs rejected by SVAF (logged by sym-core)
      remixProduced: 0,      // Remix CMBs (remember() with parents)
      remixRejected: 0,      // Remix attempts rejected (no new domain data)
      svafAligned: 0,        // SVAF aligned decisions
      svafGuarded: 0,        // SVAF guarded decisions
      svafRejected: 0,       // SVAF rejected decisions
      peersJoined: 0,        // Peers that connected
      peersLeft: 0,          // Peers that disconnected
      recalls: 0,            // recall() queries
      llmCalls: 0,           // LLM API calls reported by agent
      llmTokensIn: 0,        // Total input tokens
      llmTokensOut: 0,       // Total output tokens
      llmModel: null,        // Last model used
      startedAt: null,       // When the node started
    };

    // LLM cost pricing (USD per token). Updated by reportLLMUsage().
    // Default: gpt-4o-mini pricing as of 2026-03.
    this._llmPricing = {
      'gpt-4o-mini': { input: 0.15 / 1_000_000, output: 0.60 / 1_000_000 },
      'gpt-4o':      { input: 2.50 / 1_000_000, output: 10.00 / 1_000_000 },
    };

    // Remix guard — MMP v0.2.0 Section 14: agents MUST NOT remix without
    // new domain data. remember() sets this flag when the agent produces an
    // original observation from its domain. canRemix() checks it before
    // allowing remix of peer signals. Prevents remix storms.
    this._hasNewDomainData = false;

    // Coupling engine — evaluates peer cognitive state
    this._meshNode = new MeshNode({ hiddenDim: DIM });
    this._cfcStatePath = path.join(this._dir, 'cfc-state.json');
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
    this._port = 0;
    this._running = false;

    // Mesh group membership per MMP §5.8. `default` is the reserved implicit
    // group for nodes that do not declare one; `group` is advertised in the
    // handshake frame (§5.2 optional field) so heterogeneous peers on the same
    // LAN can tell which group they belong to.
    this._group = opts.group || 'default';

    // Discovery — pluggable for testability. See MMP v0.2.0 Section 5.
    // `discoveryServiceType` enables LAN-level Bonjour isolation for mesh
    // groups (MMP §5.8: "Bonjour isolation + relay token for WAN"). Default
    // `_sym._tcp` preserves backward compatibility; per-group service types
    // (e.g. `_melotune._tcp`, `_melotune-{roomId}._tcp`) isolate LAN peers
    // at the mDNS layer so nodes in different groups never discover each
    // other. Matches the sym-swift SymNode(discoveryServiceType:) parameter.
    this._discoveryServiceType = opts.discoveryServiceType || '_sym._tcp';
    this._discovery = opts.discovery || (
      opts.relayOnly
        ? new NullDiscovery()
        : new BonjourDiscovery({ serviceType: this._discoveryServiceType })
    );

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
      handlePeerMessage: (peerId, peerName, msg) => {
        // Emit raw frame for hosted agents (Section 4.3.2: forward before evaluation)
        this.emit('frame-received', { peerId, peerName, frame: msg });
        this._frameHandler.handle(peerId, peerName, msg);
      },
      onPeerLeft: (peerId, peerName) => { this._metrics.peersLeft++; this.emit('peer-left', { id: peerId, name: peerName }); this.emit('metric', { type: 'peer-left', name: peerName }); },
      onIdentityCollision: (info) => {
        // Surface the collision as an event so hosts can take action.
        // Default behavior (if no listener): the relay layer has already
        // logged loudly and stopped reconnecting; the node remains alive
        // but in a degraded state (no relay transport, only Bonjour LAN
        // peers reachable). Hosts that prefer to exit hard should listen
        // and call process.exit() themselves.
        this.emit('identity-collision', info);
      },
      nodeName: this.name,
      peerWakeChannels: this._peerWakeChannels,
      saveWakeChannels: () => this._wakeManager.saveWakeChannels(),
    });

    // Frame handler — cliHostMode forwards frames without storing or SVAF.
    // Local CLI-host peer pattern: hosts the IPC surface for the sym CLI
    // on a single machine without participating in mesh cognition.
    this._cliHostMode = opts.cliHostMode || false;
    this._frameHandler = new FrameHandler(this, { cliHostMode: this._cliHostMode });

    // Synthesis delegate — agent processes xMesh insight and produces new outbound CMBs
    this._synthesisDelegate = opts.onSynthesis || null;

    // Timers
    this._heartbeatInterval = opts.heartbeatInterval || 10000;
    this._heartbeatTimeout = opts.heartbeatTimeout || 120000;
    this._heartbeatTimer = null;
    this._encodeInterval = opts.encodeInterval || 30000;
    this._encodeTimer = null;
  }

  // ── E2E Encryption ─────────────────────────────────────────

  /**
   * Load or create a persistent X25519 keypair for E2E field encryption.
   * Stored alongside identity at ~/.sym/nodes/<name>/e2e-keypair.json.
   * @returns {{ publicKey: Buffer, privateKey: Buffer }}
   * @private
   */
  _loadOrCreateE2EKeyPair() {
    const kpPath = path.join(this._dir, 'e2e-keypair.json');
    if (fs.existsSync(kpPath)) {
      try {
        const data = JSON.parse(fs.readFileSync(kpPath, 'utf8'));
        return {
          publicKey: Buffer.from(data.publicKey, 'base64'),
          privateKey: Buffer.from(data.privateKey, 'base64'),
        };
      } catch (e) {
        this._log(`E2E keypair corrupt — regenerating: ${e.message}`);
      }
    }
    const kp = e2eGenerateKeyPair();
    fs.writeFileSync(kpPath, JSON.stringify({
      publicKey: kp.publicKey.toString('base64'),
      privateKey: kp.privateKey.toString('base64'),
    }, null, 2));
    return kp;
  }

  /**
   * Derive shared secret from peer's X25519 public key and store it.
   * @param {string} peerId
   * @param {string} peerPublicKeyB64 — base64-encoded peer public key
   * @private
   */
  _deriveAndStoreSecret(peerId, peerPublicKeyB64) {
    // Skip if we already have a shared secret for this peer+key combo
    const cacheKey = `${peerId}:${peerPublicKeyB64}`;
    if (this._e2eDerivedKeys && this._e2eDerivedKeys.has(cacheKey)) return;
    try {
      const peerPubKey = Buffer.from(peerPublicKeyB64, 'base64');
      const secret = e2eDeriveSharedSecret(this._e2eKeyPair.privateKey, peerPubKey);
      this._peerSharedSecrets.set(peerId, secret);
      if (!this._e2eDerivedKeys) this._e2eDerivedKeys = new Set();
      this._e2eDerivedKeys.add(cacheKey);
      this._log(`E2E shared secret derived for peer ${peerId.slice(0, 8)}`);
    } catch (err) {
      this._log(`E2E key derivation failed for peer ${peerId.slice(0, 8)}: ${err.message}`);
    }
  }

  /**
   * Encrypt CMB fields for a specific peer. Returns a modified CMB copy
   * with fields replaced by ciphertext and E2E metadata attached.
   * @param {object} cmb — original CMB
   * @param {Buffer} sharedSecret — 32-byte shared secret
   * @returns {object} — CMB with encrypted fields
   * @private
   */
  _encryptCMBForPeer(cmb, sharedSecret) {
    if (!cmb || !cmb.fields || typeof cmb.fields !== 'object') return cmb;
    const { ciphertext, nonce } = encryptFields(cmb.fields, sharedSecret);
    return {
      ...cmb,
      fields: ciphertext,
      _e2e: { nonce },
    };
  }

  // ── Context Encoding ───────────────────────────────────────

  _initLocalState() {
    // Restore persisted CfC state if available — preserves slow-τ adaptation
    // across restarts. Without this, feedback modulation (Section 11) resets
    // and the agent must re-learn from stored CMB anchors.
    if (fs.existsSync(this._cfcStatePath)) {
      try {
        const saved = JSON.parse(fs.readFileSync(this._cfcStatePath, 'utf8'));
        if (saved.h1?.length === DIM && saved.h2?.length === DIM) {
          this._meshNode.updateLocalState(saved.h1, saved.h2, 0.8);
          this._log('CfC state restored from disk');
          return;
        }
      } catch (e) {
        this._log(`CfC state restore failed: ${e.message}`);
      }
    }

    // No persisted state — encode from stored CMBs or random init
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

  /**
   * Persist current CfC hidden state to disk.
   * Called after state updates to preserve slow-τ adaptation across restarts.
   */
  _persistCfCState() {
    try {
      const [h1, h2] = this._meshNode.coupledState();
      fs.writeFileSync(this._cfcStatePath, JSON.stringify({ h1, h2, savedAt: Date.now() }));
    } catch (e) {
      // Non-fatal — state will be re-encoded from CMBs on next restart
    }
  }

  _buildContext() {
    const parts = [];
    if (this._cognitiveProfile) parts.push(this._cognitiveProfile);
    const entries = this._store.allEntries().slice(0, 20);
    parts.push(...entries.map(e => e.content || ''));
    return parts.join('\n');
  }

  _runRetentionPurge() {
    const retentionMs = this._retentionSeconds * 1000;
    const compacted = this._store.compact(retentionMs);
    const purged = this._store.purge();
    if (compacted > 0 || purged > 0) {
      this._log(`Retention purge: ${compacted} compacted, ${purged} removed (retention: ${this._retentionSeconds}s)`);
    }
  }

  _reencodeAndBroadcast() {
    const context = this._buildContext();
    if (context.length < 5) return;

    const { h1, h2 } = encode(context);
    this._meshNode.updateLocalState(h1, h2, 0.8);
    // MMP v0.2.2: do not broadcast hidden state. SVAF (Xu, 2026,
    // arXiv:2604.03955, §3.4) requires that hidden states stay private to
    // each agent. The local state update above is sufficient for the
    // local CfC to evaluate future incoming CMBs at SVAF Layer 4.
    // Cognitive signals propagate to peers as CMBs only.
    this._persistCfCState();
  }

  /**
   * Update cognitive state from external context (e.g. Claude Code's memories).
   * Updates the local CfC only — MMP v0.2.2: hidden states never cross the
   * wire under SVAF (Xu, 2026, arXiv:2604.03955, §3.4). Cognitive signals
   * propagate to peers as CMBs via `remember()`, not as raw state.
   *
   * @param {string} text — context text to encode (min 5 chars)
   */
  updateContext(text) {
    if (!text || text.length < 5) return;
    const { h1, h2 } = encode(text);
    this._meshNode.updateLocalState(h1, h2, 0.8);
    this._persistCfCState();
  }

  /**
   * Share content with cognitively aligned peers without storing locally.
   * Used by ClaudeMemoryBridge — Claude Code's memory dir is the source of truth.
   * See MMP v0.2.0 Section 7 (Frame Types).
   *
   * @param {string} content — raw content to share
   * @param {object} [opts]
   * @param {object} [opts.cmb] — pre-built CMB; auto-created from content if omitted
   * @param {string} [opts.source] — creator name override
   * @returns {{ key: string, content: string, cmb: object, timestamp: number }}
   */
  shareWithPeers(content, opts = {}) {
    const cmb = opts.cmb || createCMB({ rawText: content, createdBy: opts.source || this.name });

    this._meshNode.coupledState();

    const ts = Date.now();
    let shared = 0;
    for (const [peerId, peer] of this._peers) {
      const sharedSecret = this._peerSharedSecrets.get(peerId);
      let peerCmb = cmb;
      if (sharedSecret) {
        peerCmb = this._encryptCMBForPeer(cmb, sharedSecret);
        this._log(`E2E encrypted fields for peer ${peerId.slice(0, 8)}`);
      }
      peer.transport.send({
        type: 'cmb',
        timestamp: ts,
        cmb: peerCmb,
      });
      shared++;
    }

    this._log(`Shared: "${content.slice(0, 50)}${content.length > 50 ? '...' : ''}" → ${shared}/${this._peers.size} peers`);
    return { key: cmb.key, content, cmb, timestamp: frame.timestamp };
  }

  // ── Lifecycle ──────────────────────────────────────────────

  /**
   * Start the node: TCP server, Bonjour discovery, relay, heartbeats, retention.
   * See MMP v0.2.0 Section 4 (Transport), Section 5 (Connection).
   * @returns {Promise<void>}
   */
  async start() {
    if (this._running) return;
    this._running = true;
    this._metrics.startedAt = Date.now();

    // Track pending Bonjour connections to prevent duplicate connect attempts.
    // dns-sd may resolve the same peer multiple times.
    this._pendingBonjour = new Set();

    // Wire discovery events to peer management
    this._discovery.on('peer-found', (address, port, peerId, peerName) => {
      // Skip if already connecting or already have Bonjour transport
      if (this._pendingBonjour.has(peerId)) return;
      const existing = this._peers.get(peerId);
      if (existing && existing.transports && existing.transports.has('bonjour')) return;

      this._pendingBonjour.add(peerId);
      this._connectToPeer(address, port, peerId, peerName);
    });
    this._discovery.on('inbound-connection', (transport, peerId, peerName, handshakeMsg) => {
      // Section 5.2 + 4.6: if peer exists via SAME transport type, reject.
      // If different transport type, accept as secondary.
      const existingPeer = this._peers.get(peerId);
      if (existingPeer && existingPeer.transports.has('bonjour')) { transport.close(); return; }
      if (handshakeMsg.e2ePublicKey) {
        this._deriveAndStoreSecret(peerId, handshakeMsg.e2ePublicKey);
      }
      transport.on('message', (m) => {
        const peer = this._peers.get(peerId);
        if (peer) peer.lastSeen = Date.now();
        this._frameHandler.handle(peerId, peerName, m);
      });
      const peer = this._createPeer(transport, peerId, peerName, false, 'bonjour');
      this._addPeer(peer);
    });

    this._port = await this._discovery.start(this._identity, (msg) => this._log(msg));

    if (this._relayUrl) {
      this._relay.connect();
    }

    this._heartbeatTimer = setInterval(() => this._checkHeartbeats(), this._heartbeatInterval);
    this._encodeTimer = setInterval(() => this._reencodeAndBroadcast(), this._encodeInterval);

    // Retention purge — run on start + every hour
    this._runRetentionPurge();
    this._purgeTimer = setInterval(() => this._runRetentionPurge(), 3600_000);

    this._log(`Started (port: ${this._port}, id: ${this._identity.nodeId.slice(0, 8)}${this._relayUrl ? ', relay: ' + this._relayUrl : ''})`);
  }

  /**
   * Stop the node: close all peers, timers, relay, and discovery.
   * @returns {Promise<void>}
   */
  async stop() {
    if (!this._running) return;
    this._running = false;

    if (this._heartbeatTimer) clearInterval(this._heartbeatTimer);
    if (this._encodeTimer) clearInterval(this._encodeTimer);
    if (this._purgeTimer) clearInterval(this._purgeTimer);

    this._relay.destroy();

    for (const [, peer] of this._peers) {
      peer.transport.close();
    }
    this._peers.clear();

    await this._discovery.stop();
    this._discovery.removeAllListeners();

    // Release the identity lock so a successor process (e.g. a fresh
    // restart) can claim this nodeId without waiting for stale-PID
    // detection. Best-effort: errors are swallowed because we're
    // shutting down anyway.
    if (this._releaseIdentityLock) {
      try { this._releaseIdentityLock(); } catch {}
      this._releaseIdentityLock = null;
    }

    this._log('Stopped');
  }

  // ── Memory (with cognitive coupling) ───────────────────────

  /**
   * Store a memory with structured CAT7 fields and broadcast to coupled peers.
   * See MMP v0.2.0 Section 6 (Memory), Section 7 (Frame Types), Section 14 (Remix).
   *
   * @param {object} fields — CAT7 fields: focus, issue, intent, motivation, commitment, perspective, mood
   * @param {object} [opts]
   * @param {object} [opts.cmb] — pre-built CMB; auto-created from fields if omitted
   * @param {Array<object>} [opts.parents] — parent CMBs for lineage (Section 14)
   * @param {Array<string>} [opts.tags] — optional tags for search
   * @param {string} [opts.to] — full peerId of a single target peer. When
   *   set, the CMB frame is emitted only to that peer (per MMP §4.4.4
   *   relay-routing envelope for targeted sends). When omitted (default),
   *   the frame is broadcast to all connected peers. The local store write
   *   happens in both cases — lineage stays intact even if the target peer
   *   is not currently connected, and remix-guard invariants (§14.7) are
   *   enforced identically for broadcast and targeted sends.
   * @returns {object|null} stored entry, or null if duplicate or remix rejected
   */
  remember(fields, opts = {}) {
    if (!opts.cmb) {
      if (!fields || typeof fields !== 'object') {
        throw new Error('remember() requires CAT7 fields — the agent LLM extracts fields');
      }

      // MMP Section 14.7: enforce remix requires new domain data.
      // If parents are specified (this is a remix), the agent MUST have
      // produced new domain observations since its last remix.
      // Without this, agents paraphrase each other — noise, not intelligence.
      if (opts.parents && opts.parents.length > 0 && !this._hasNewDomainData) {
        this._metrics.remixRejected++;
        this._log('Remix rejected: no new domain data (MMP Section 14.7)');
        this.emit('metric', { type: 'remix-rejected', reason: 'no-new-domain-data' });
        return null;
      }

      // Compute lineage from parents (MMP spec Section 14)
      let lineage = null;
      if (opts.parents && opts.parents.length > 0) {
        lineage = {
          parents: opts.parents.map(p => p.key),
          ancestors: opts.parents.flatMap(p => [...(p.lineage?.ancestors || []), p.key]),
          method: 'SVAF-v2',
        };
      }
      opts.cmb = createCMB({ fields, createdBy: this.name, lineage });
      if (opts.meta) opts.cmb.meta = opts.meta;
    }
    const content = renderContent(opts.cmb);
    const entry = this._store.write(content, opts);

    // Duplicate — already stored, skip broadcast
    if (!entry) return null;

    // Per MMP Section 14.7: only original observations (no parents) count
    // as new domain data. A remix consuming domain data resets the flag —
    // the agent must produce fresh observations before remixing again.
    if (opts.parents && opts.parents.length > 0) {
      this._hasNewDomainData = false;
    } else {
      this._hasNewDomainData = true;
    }

    // Protocol metrics
    this._metrics.cmbProduced++;
    if (opts.parents && opts.parents.length > 0) {
      this._metrics.remixProduced++;
    }
    this.emit('metric', { type: 'cmb-produced', key: entry.key, hasLineage: !!(opts.parents?.length) });

    const context = this._buildContext();
    const { h1, h2 } = encode(context);
    this._meshNode.updateLocalState(h1, h2, 0.8);

    this._meshNode.coupledState();

    // Build cmb frame per MMP spec Section 7: timestamp + cmb only
    // Encrypt fields per-peer if shared secret is available (E2E encryption)
    const baseCmb = entry.cmb || null;

    // Fan-out: broadcast to all peers by default, or to a single peer when
    // opts.to is set (MMP §4.4.4). The local store write above already ran,
    // so the CMB persists regardless of how many peers receive this frame.
    let targets;
    if (opts.to) {
      const targeted = this._peers.get(opts.to);
      if (targeted) {
        targets = [[opts.to, targeted]];
      } else {
        targets = [];
        this._log(`Targeted send: peer ${opts.to.slice(0, 8)} not connected; CMB stored locally only`);
      }
    } else {
      targets = this._peers;
    }

    let shared = 0;
    for (const [peerId, peer] of targets) {
      const sharedSecret = this._peerSharedSecrets.get(peerId);
      let cmb = baseCmb;
      if (sharedSecret && baseCmb) {
        cmb = this._encryptCMBForPeer(baseCmb, sharedSecret);
        this._log(`E2E encrypted fields for peer ${peerId.slice(0, 8)}`);
      }
      peer.transport.send({
        type: 'cmb',
        timestamp: entry.storedAt,
        cmb,
      });
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

    const fanoutDesc = opts.to
      ? `target=${opts.to.slice(0, 8)} (${shared ? 'sent' : 'not connected'})`
      : `${shared}/${this._peers.size} peers`;
    this._log(`Remembered: "${content.slice(0, 50)}${content.length > 50 ? '...' : ''}" → ${fanoutDesc}`);
    return entry;
  }

  /**
   * Search local mesh memory by keyword.
   * See MMP v0.2.0 Section 6 (Memory).
   *
   * @param {string} query — search keyword
   * @returns {Array<object>} matching entries sorted by recency
   */
  recall(query) {
    this._metrics.recalls++;
    return this._store.search(query);
  }

  // ── Startup Primer ─────────────────────────────────────────

  /**
   * Reconstitute the agent's remix-memory as a human-readable primer
   * suitable for injection into LLM context at session start. The
   * operationalisation of MMP §4.2 O2: rejoin-without-replay — a fresh
   * agent session picks up its prior state automatically, with zero
   * first-turn overhead.
   *
   * Plugin startup integration pattern:
   *
   *   const node = new SymNode({ name, ... });
   *   await node.start();
   *   // ... register tool surface, transport, etc ...
   *   const primer = node.buildStartupPrimer();   // final init step
   *   mcpServer.instructions += '\n\n' + primer.text;
   *
   * The primer is bounded in both time and count so a long-running
   * store does not flood LLM context. Callers may tune the caps per
   * deployment.
   *
   * @param {object} [opts]
   * @param {number} [opts.maxCount=20]  — cap on entries returned.
   * @param {number} [opts.maxAgeMs=86400000] — recency window (default 24h).
   * @returns {{ text: string, count: number, dropped: number, totalInStore: number }}
   *   `text`         — formatted primer, empty string if store is empty
   *   `count`        — entries included in the primer
   *   `dropped`      — entries elided by the caps (0 if none)
   *   `totalInStore` — total entries in the agent's remix store
   */
  buildStartupPrimer(opts = {}) {
    const maxCount = Number.isInteger(opts.maxCount) && opts.maxCount > 0 ? opts.maxCount : 20;
    const maxAgeMs = Number.isInteger(opts.maxAgeMs) && opts.maxAgeMs > 0 ? opts.maxAgeMs : 86_400_000; // 24h
    const cutoff = Date.now() - maxAgeMs;

    // recall('') returns every entry sorted newest-first — the remix store
    // is the agent's memory, not a curated view. No tag-filter gating.
    const all = this._store.search('');
    const totalInStore = all.length;
    if (!totalInStore) {
      return { text: '', count: 0, dropped: 0, totalInStore: 0 };
    }

    // Apply recency window first, then count cap.
    const withinWindow = all.filter((e) => (e.storedAt || e.timestamp || 0) >= cutoff);
    const kept = withinWindow.slice(0, maxCount);
    const dropped = totalInStore - kept.length;

    const lines = [];
    lines.push(`## Mesh memory primer — ${this.name} (${kept.length}/${totalInStore} CMBs)`);
    lines.push('');
    lines.push(
      `The following are the most recent ${kept.length} Cognitive Memory Blocks ` +
      `in this agent's remix store — its own observations plus peer observations ` +
      `admitted by SVAF. Treat this as prior cognitive state; act accordingly.`,
    );
    if (dropped > 0) {
      lines.push('');
      lines.push(
        `(${dropped} older entries elided by the startup primer caps ` +
        `(maxCount=${maxCount}, maxAgeMs=${maxAgeMs}). ` +
        `Use sym_recall to retrieve them if needed.)`,
      );
    }
    lines.push('');
    for (const e of kept) {
      const when = e.storedAt ? new Date(e.storedAt).toISOString() : '—';
      const keyShort = (e.key || '').slice(0, 16);
      const src = e.source || e.createdBy || 'unknown';
      const focus = e.cmb?.fields?.focus?.text || e.content || '';
      lines.push(`- [${when}] ${src} · ${keyShort} — ${focus}`);
    }

    return {
      text: lines.join('\n'),
      count: kept.length,
      dropped,
      totalInStore,
    };
  }

  // ── Remix Guard (MMP v0.2.0 Section 14) ────────────────────

  /**
   * Check whether this agent has new domain data available for remix.
   * Per MMP Section 14: agents MUST NOT remix peer signals unless they
   * have new observations from their own domain to intersect with.
   * Silence is correct when the agent has nothing new to contribute.
   *
   * Set to true automatically when remember() stores a new CMB.
   * Reset to false by markRemixed() after a remix cycle completes.
   *
   * @returns {boolean} true if agent has new domain data since last remix
   */
  canRemix() {
    return this._hasNewDomainData;
  }

  /**
   * Mark that the agent has completed a remix cycle. Resets the
   * new-domain-data flag so the agent stays silent until it has
   * fresh observations from its domain.
   */
  markRemixed() {
    this._hasNewDomainData = false;
  }

  // ── Metrics (MMP protocol-level observability) ─────────────

  /**
   * Report an LLM API call for protocol-level cost tracking.
   * Called by the agent after each LLM invocation (e.g. from role-reason.js).
   *
   * @param {number} tokensIn — input/prompt tokens
   * @param {number} tokensOut — output/completion tokens
   * @param {string} [model] — model name (default: 'gpt-4o-mini')
   */
  reportLLMUsage(tokensIn, tokensOut, model = 'gpt-4o-mini') {
    this._metrics.llmCalls++;
    this._metrics.llmTokensIn += tokensIn;
    this._metrics.llmTokensOut += tokensOut;
    this._metrics.llmModel = model;
    this.emit('metric', { type: 'llm-call', tokensIn, tokensOut, model });
  }

  /**
   * Get protocol-level metrics for this node.
   * Tracks: CMBs produced/accepted, remixes, SVAF decisions,
   * peer events, recall queries, LLM usage with cost, uptime.
   *
   * Applications (sym.day, monitoring) use this for observability.
   * Subscribe to node.on('metric', ...) for real-time events.
   *
   * @returns {object} cumulative metrics since node start
   */
  metrics() {
    const m = this._metrics;
    const uptimeMs = m.startedAt ? Date.now() - m.startedAt : 0;

    // Compute LLM cost based on model pricing
    const pricing = this._llmPricing[m.llmModel] || this._llmPricing['gpt-4o-mini'];
    const llmCostUSD = (m.llmTokensIn * pricing.input) + (m.llmTokensOut * pricing.output);

    return {
      ...m,
      uptimeMs,
      llmCostUSD: Math.round(llmCostUSD * 1_000_000) / 1_000_000,
    };
  }

  // ── Mood (with cognitive evaluation) ───────────────────────

  /**
   * Broadcast a mood frame to all connected peers.
   * See MMP v0.2.0 Section 7 (Frame Types).
   *
   * @param {string} mood — mood text
   * @param {object} [opts]
   * @param {string} [opts.context] — optional context for the mood
   */
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

  /**
   * Broadcast an xMesh insight to all connected peers.
   * See MMP v0.2.0 Section 12 (xMesh).
   *
   * @param {object} insight — xMesh insight with trajectory, patterns, anomaly, etc.
   */
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

  /**
   * Set the synthesis delegate for xMesh insights.
   * See MMP v0.2.0 Section 12 (xMesh).
   *
   * @param {function|null} fn — synthesis callback or null to clear
   */
  set onSynthesis(fn) {
    this._synthesisDelegate = typeof fn === 'function' ? fn : null;
  }

  // ── Communication ──────────────────────────────────────────

  /**
   * Send a message to a specific peer or broadcast to all peers.
   * See MMP v0.2.0 Section 7 (Frame Types).
   *
   * @param {string} message — message content
   * @param {object} [opts]
   * @param {string} [opts.to] — target peer ID; broadcasts to all if omitted
   */
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
      if (peer) {
        try { peer.transport.send(frame); return 1; } catch { return 0; }
      }
      return 0;
    }
    const delivered = this._broadcastToPeers(frame);
    this._wakeManager.wakeSleepingPeers('message', frame);
    // If no peers received the message, trigger an immediate reconnect
    // attempt for any cached bonjour peers. The next send will find
    // them connected instead of waiting for the 15s background timer.
    if (delivered === 0) {
      this._discovery.reconnect();
    }
    return delivered;
  }

  // ── Error Frame (MMP Section 7.2) ─────────────────────────

  /**
   * Send an error frame to a peer. Per MMP Section 7.2, error frames are
   * informational — the receiver MUST NOT treat them as commands.
   * Codes 1xxx are connection-level (close after sending).
   * Codes 2xxx are evaluation-level (informational only).
   *
   * @param {string} peerId — target peer
   * @param {number} code — error code (1001-1005, 2001-2002)
   * @param {string} message — human-readable error description
   * @param {string} [detail] — optional debug detail (MUST NOT contain sensitive info)
   */
  sendError(peerId, code, message, detail) {
    const peer = this._peers.get(peerId);
    if (!peer) return;
    peer.transport.send({ type: 'error', code, message, detail: detail || undefined });
    this._log(`Error sent to ${peer.name}: ${code} ${message}`);
  }

  // ── Wake (delegated) ──────────────────────────────────────

  /**
   * Wake a sleeping peer if needed (e.g. iOS background).
   *
   * @param {string} peerId — peer to wake
   * @param {string} [reason='message'] — wake reason
   * @returns {Promise<boolean>}
   */
  async wakeIfNeeded(peerId, reason = 'message') {
    return this._wakeManager.wakeIfNeeded(peerId, reason);
  }

  /**
   * Wake all known sleeping peers.
   *
   * @param {string} [reason='message'] — wake reason
   * @returns {Promise<void>}
   */
  async wakeAllPeers(reason = 'message') {
    return this._wakeManager.wakeAllPeers(reason);
  }

  // ── Monitoring ─────────────────────────────────────────────

  /**
   * List connected peers with coupling state.
   * See MMP v0.2.0 Section 5 (Connection), Section 9 (Coupling & SVAF).
   *
   * @returns {Array<{ id: string, peerId: string, name: string, connected: boolean, lastSeen: number, coupling: string, drift: number|null, source: string }>}
   *   `id` is the truncated 8-char display form; `peerId` is the full nodeId
   *   suitable for passing to `remember({to})` (MMP §4.4.4 targeted send).
   */
  peers() {
    const result = [];
    const decisions = this._meshNode.couplingDecisions;
    for (const [id, peer] of this._peers) {
      const d = decisions.get(id);
      result.push({
        id: id.slice(0, 8),
        peerId: id,
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

  /**
   * Count of stored memories.
   * @returns {number}
   */
  memories() {
    return this._store.count();
  }

  /**
   * Current mesh coherence score.
   * @returns {number}
   */
  coherence() {
    return this._meshNode.coherence;
  }

  /**
   * Full node status snapshot.
   * See MMP v0.2.0 Section 13 (Application).
   *
   * @returns {{ name: string, nodeId: string, running: boolean, port: number, relay: string|null, relayConnected: boolean, peers: Array, peerCount: number, memoryCount: number, coherence: number }}
   */
  status() {
    return {
      name: this.name,
      nodeId: this._identity.nodeId,
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

  _connectToPeer(address, port, peerId, peerName) {
    // Connect timeout: 10s to establish the TCP connection. Cleared once
    // connected so the socket doesn't die from idle — LAN connections
    // should stay open indefinitely. The old code left the 10s timeout
    // running after connect, which killed every connection that was
    // idle for >10s (i.e., all of them between messages).
    const socket = net.createConnection({ host: address, port }, () => {
      socket.setTimeout(0); // clear connect timeout — connection is alive
      this._pendingBonjour.delete(peerId);
      const transport = new TcpTransport(socket);
      transport.on('message', (msg) => {
        const peer = this._peers.get(peerId);
        if (peer) peer.lastSeen = Date.now();
        this._frameHandler.handle(peerId, peerName, msg);
      });
      transport.on('error', () => {});
      const peer = this._createPeer(transport, peerId, peerName, true, 'bonjour');
      if (!this._peers.has(peerId)) {
        this._addPeer(peer);
      }
    });
    socket.on('error', (err) => {
      this._pendingBonjour.delete(peerId);
      this._log(`Connect failed to ${peerName}: ${err.message}`);
    });
    socket.setTimeout(10000, () => { this._pendingBonjour.delete(peerId); socket.destroy(); });
  }

  // ── Peer Management ────────────────────────────────────────

  /**
   * Create or update a peer with a transport. Per MMP Section 4.6, a peer
   * MAY have multiple transports (LAN TCP + WAN relay). The peer is only
   * removed when ALL transports are closed.
   *
   * Transport priority: bonjour (LAN) > relay (WAN).
   * The highest-priority healthy transport is used for sending.
   */
  _createPeer(transport, peerId, peerName, isOutbound, source) {
    const existingPeer = this._peers.get(peerId);

    if (existingPeer) {
      // Section 4.6: add as secondary transport, don't reject.
      // But if same transport type already exists and is connected, skip —
      // prevents relay reconnect loops replacing active connections.
      const existingTransport = existingPeer.transports.get(source);
      if (existingTransport && !existingTransport._closed) {
        transport.close();
        return existingPeer;
      }
      existingPeer.transports.set(source, transport);
      this._log(`Transport added for ${peerName}: ${source} (${existingPeer.transports.size} transports)`);

      transport.on('close', () => {
        existingPeer.transports.delete(source);
        this._log(`Transport closed for ${peerName}: ${source} (${existingPeer.transports.size} remaining)`);

        // Update active transport to highest-priority remaining
        existingPeer.transport = this._bestTransport(existingPeer);

        // Section 5.5: peer-left only when ALL transports closed
        if (existingPeer.transports.size === 0) {
          this._peers.delete(peerId);
          this._meshNode.removePeer(peerId);
          this._metrics.peersLeft++;
          this._log(`Peer disconnected: ${peerName} (all transports closed)`);
          this.emit('peer-left', { id: peerId, name: peerName });
          this.emit('metric', { type: 'peer-left', name: peerName });
        }
      });

      return existingPeer;
    }

    // New peer — first transport
    const transports = new Map();
    transports.set(source, transport);

    const peer = { transport, transports, peerId, name: peerName, isOutbound, source, lastSeen: Date.now() };

    transport.on('close', () => {
      transports.delete(source);
      this._log(`Transport closed for ${peerName}: ${source} (${transports.size} remaining)`);

      peer.transport = this._bestTransport(peer);

      if (transports.size === 0) {
        this._peers.delete(peerId);
        this._meshNode.removePeer(peerId);
        this._metrics.peersLeft++;
        this._log(`Peer disconnected: ${peerName} (all transports closed)`);
        this.emit('peer-left', { id: peerId, name: peerName });
        this.emit('metric', { type: 'peer-left', name: peerName });
      }
    });

    return peer;
  }

  /**
   * Select the highest-priority healthy transport for a peer.
   * Priority: bonjour (LAN) > relay (WAN).
   * Per MMP Section 4.6.
   */
  _bestTransport(peer) {
    const priority = ['bonjour', 'relay'];
    for (const src of priority) {
      const t = peer.transports.get(src);
      if (t) return t;
    }
    // Fallback: any remaining transport
    for (const t of peer.transports.values()) return t;
    return null;
  }

  _addPeer(peer) {
    this._peers.set(peer.peerId, peer);

    // Handshake — per MMP Section 5.2 + §5.8 optional `group` field
    peer.transport.send({
      type: 'handshake',
      nodeId: this._identity.nodeId,
      name: this.name,
      version: '0.2.3',
      extensions: [],
      group: this._group,
      publicKey: this._identity.publicKey,
      e2ePublicKey: this._e2eKeyPair.publicKey.toString('base64'),
      lifecycleRole: this._lifecycleRole,
    });

    // MMP v0.2.2: no state-sync — hidden states never cross the wire under
    // SVAF (Xu, 2026, arXiv:2604.03955, §3.4). Cognitive bootstrap to a
    // freshly-connected peer happens via the anchor CMB exchange below,
    // evaluated by the peer's SVAF Layer 4 against its own anchor memory.

    // Debounce anchor CMB exchange — skip if peer reconnected within 60 seconds.
    // Prevents CMB storms from unstable relay connections.
    if (!this._lastAnchorSent) this._lastAnchorSent = new Map();
    const lastSent = this._lastAnchorSent.get(peer.peerId) || 0;
    const now = Date.now();
    if (now - lastSent < 60000) {
      this._log(`Skipping anchor CMBs for ${peer.name} (reconnected within 60s)`);
    } else {
      this._lastAnchorSent.set(peer.peerId, now);

      // Send recent CMB anchors — enables the "Ask the Mesh" pattern.
      // New peers need context to respond relevantly. Without this,
      // a periodic agent that connects briefly can't see questions
      // that were asked before it joined. See MMP Section 13.6.
      const sharedSecret = this._peerSharedSecrets.get(peer.peerId);
      const recentAnchors = this._store.recent(5);
      for (const anchor of recentAnchors) {
        if (!anchor.cmb) continue;
        let cmb = anchor.cmb;
        if (sharedSecret) {
          cmb = this._encryptCMBForPeer(cmb, sharedSecret);
        }
        peer.transport.send({
          type: 'cmb',
          timestamp: anchor.storedAt || anchor.timestamp,
          cmb,
          _anchor: true,
        });
      }
      if (recentAnchors.length > 0) {
        this._log(`Sent ${recentAnchors.length} anchor CMB(s) to ${peer.name}`);
      }
    }

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
    this._metrics.peersJoined++;
    this.emit('peer-joined', { id: peer.peerId, name: peer.name });
    this.emit('metric', { type: 'peer-joined', name: peer.name, source: peer.source });

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
    let delivered = 0;
    for (const [, peer] of this._peers) {
      try {
        peer.transport.send(frame);
        delivered++;
      } catch {
        // Transport failed (broken socket, peer closed). Don't crash the
        // broadcast — count it as undelivered. The peer's close handler
        // will clean up _peers in due course; we just report the truth.
      }
    }
    return delivered;
  }

  _checkHeartbeats() {
    const now = Date.now();
    for (const [id, peer] of this._peers) {
      if (now - peer.lastSeen > this._heartbeatTimeout) {
        this._log(`Heartbeat timeout: ${peer.name}`);
        // Close the active transport — the close handler in _createPeer
        // will failover to the next transport or remove the peer if none remain.
        // Per MMP Section 4.6 + 5.5: don't delete peer directly.
        if (peer.transport) peer.transport.close();
      } else if (now - peer.lastSeen > this._heartbeatInterval) {
        // Send ping on ALL transports — ensures liveness check reaches
        // the peer even if the active transport is degraded.
        if (peer.transports) {
          for (const t of peer.transports.values()) {
            try { t.send({ type: 'ping' }); } catch {}
          }
        } else if (peer.transport) {
          peer.transport.send({ type: 'ping' });
        }
      }
    }
  }

  _log(msg) {
    if (!this._silent) logMsg(this.name, msg);
  }
}

module.exports = { SymNode };

// Lazy-load MeshAgent to avoid circular dependency (mesh-agent requires node)
Object.defineProperty(module.exports, 'MeshAgent', {
  get() { return require('./mesh-agent').MeshAgent; },
  enumerable: true,
});

Object.defineProperty(module.exports, 'llm', {
  get() { return require('./llm-reason'); },
  enumerable: true,
});

// Backward compat — agents using { claude } still work
Object.defineProperty(module.exports, 'claude', {
  get() { return require('./llm-reason'); },
  enumerable: true,
});

Object.defineProperty(module.exports, 'platform', {
  get() { return require('./platform'); },
  enumerable: true,
});
