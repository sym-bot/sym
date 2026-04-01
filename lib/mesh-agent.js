'use strict';

/**
 * MeshAgent — protocol-level agent lifecycle per MMP v0.2.0.
 *
 * Pure protocol infrastructure. No LLM, no prompts, no AI opinions.
 * The agent IS the intelligence (Section 13). The protocol provides:
 *
 *   1. cmb-accepted → canRemix() → agent.remix() → remember() with lineage
 *   2. Domain poll → fingerprint change → agent.reason() → remember()
 *   3. Silence when nothing new (Section 14.7)
 *
 * Usage:
 *   const agent = new MeshAgent({
 *     name: 'github-ops',
 *     svafFieldWeights: { focus: 1.5, issue: 2.0, ... },
 *     pollInterval: 6 * 60 * 60 * 1000,
 *     fetchDomain: async () => ({ data: '...', fingerprint: '...' }),
 *     reason: async (domainData, meshContext) => ({ focus: '...', ... }),
 *     remix: async (incomingCMB, meshContext) => ({ focus: '...', ... }),
 *   });
 *   await agent.start();
 *
 * See MMP v0.2.0 Section 13 (Application), Section 14 (Remix).
 *
 * Copyright (c) 2026 SYM.BOT Ltd. Apache 2.0 License.
 */

const fs = require('fs');
const path = require('path');
const net = require('net');
const os = require('os');
const { SymNode } = require('./node');
const { NullDiscovery } = require('./discovery');

const DAEMON_SOCKET = path.join(os.homedir(), '.sym', 'daemon.sock');

// ── State Persistence ────────────────────────────────────

function loadState(agentDir) {
  const p = path.join(agentDir, 'state.json');
  if (!fs.existsSync(p)) return {};
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return {}; }
}

function saveState(agentDir, state) {
  state.lastRun = new Date().toISOString();
  fs.writeFileSync(path.join(agentDir, 'state.json'), JSON.stringify(state, null, 2));
}

// ── MeshAgent ────────────────────────────────────────────

class MeshAgent {
  /**
   * @param {object} opts
   * @param {string} opts.name — agent name (e.g. 'github-ops')
   * @param {string} [opts.agentDir] — agent root directory (default: process.cwd())
   * @param {string} [opts.cognitiveProfile] — short description for coupling
   * @param {object} [opts.svafFieldWeights] — per-field SVAF weights
   * @param {number} [opts.svafFreshnessSeconds] — temporal decay (default: 43200)
   * @param {number} [opts.pollInterval] — domain poll interval in ms (default: 30 min)
   * @param {Function} opts.fetchDomain — async () => { data: string, fingerprint: string } | null
   *   Returns domain data + change fingerprint. Return null to signal "no data".
   * @param {Function} opts.reason — async (domainData, meshContext) => CAT7 fields | null
   *   Agent's intelligence: produce CMB fields from domain data + mesh context.
   *   meshContext: [{ focus, source, key }]. Return null to stay silent.
   * @param {Function} opts.remix — async (incomingCMB, meshContext) => CAT7 fields | null
   *   Agent's intelligence: produce remixed CMB fields from accepted peer signal.
   *   incomingCMB: { key, source, fields: { focus, issue, ... } }.
   *   Return null to stay silent — per Section 14.7, silence is correct.
   * @param {Function} [opts.shouldRemix] — (entry) => boolean — filter which CMBs to remix.
   *   Default: remix all non-self CMBs.
   * @param {Function} [opts.onStarted] — async (node) => void — called after node starts
   */
  constructor(opts) {
    if (!opts.name) throw new Error('MeshAgent requires a name');
    if (!opts.fetchDomain) throw new Error('MeshAgent requires fetchDomain()');
    if (!opts.reason) throw new Error('MeshAgent requires reason()');
    if (!opts.remix) throw new Error('MeshAgent requires remix()');

    this._name = opts.name;
    this._opts = opts;
    this._agentDir = opts.agentDir || process.cwd();
    this._pollInterval = opts.pollInterval || 30 * 60 * 1000;
    this._fetchDomain = opts.fetchDomain;
    this._reason = opts.reason;
    this._remix = opts.remix;
    this._shouldRemix = opts.shouldRemix || ((entry) => entry.source !== this._name);
    this._onStarted = opts.onStarted || null;
    this._hosted = false;
    this._daemonSocket = null;
    this._node = null;

    this._state = loadState(this._agentDir);
    this._state._lastFingerprint = this._state._lastFingerprint || '';
    this._pollTimer = null;
    this._saveTimer = null;
  }

  /** @returns {SymNode} the underlying node */
  get node() { return this._node; }

  /** @returns {object} persistent state — agent can store domain-specific data here */
  get state() { return this._state; }

  /** @returns {boolean} true if connected to daemon as hosted agent */
  get hosted() { return this._hosted; }

  // ── Lifecycle ──────────────────────────────────────────

  async start() {
    // Section 4.3: detect daemon — use hosted mode if available
    const daemonPath = process.env.SYM_SOCKET || DAEMON_SOCKET;
    const daemonAvailable = fs.existsSync(daemonPath);

    if (daemonAvailable) {
      await this._startHosted(daemonPath);
    } else {
      await this._startStandalone();
    }

    if (this._onStarted) await this._onStarted(this._node);

    // Wait for peer sync before first domain check
    await new Promise(r => setTimeout(r, this._hosted ? 2000 : 5000));

    // Domain check on startup, then on interval
    await this._checkDomain().catch(err =>
      console.error(`[${this._name}] domain error:`, err.message)
    );
    this._pollTimer = setInterval(() => {
      this._checkDomain().catch(err =>
        console.error(`[${this._name}] domain error:`, err.message)
      );
    }, this._pollInterval);

    // Save state periodically
    this._saveTimer = setInterval(() => this._save(), 5 * 60 * 1000);

    // Graceful shutdown
    const shutdown = async () => {
      console.log(`\n[${this._name}] shutting down...`);
      this._save();
      clearInterval(this._pollTimer);
      clearInterval(this._saveTimer);
      if (this._daemonSocket) this._daemonSocket.destroy();
      if (this._node) await this._node.stop();
      process.exit(0);
    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
  }

  // ── Standalone Mode (own transport) ────────────────────

  async _startStandalone() {
    const opts = this._opts;
    this._node = new SymNode({
      name: opts.name,
      cognitiveProfile: opts.cognitiveProfile || `${opts.name} mesh agent`,
      svafFieldWeights: opts.svafFieldWeights || {},
      svafFreshnessSeconds: opts.svafFreshnessSeconds || 43200,
      relay: process.env.SYM_RELAY_URL || null,
      relayToken: process.env.SYM_RELAY_TOKEN || null,
      silent: false,
    });

    const node = this._node;
    node.on('cmb-accepted', (entry) => {
      this._onCMBAccepted(entry).catch(err =>
        console.error(`[${this._name}] remix error:`, err.message)
      );
    });
    node.on('peer-joined', ({ name }) => console.log(`[${this._name}] peer joined: ${name}`));
    node.on('peer-left', ({ name }) => console.log(`[${this._name}] peer left: ${name}`));

    await node.start();
    console.log(`[${this._name}] started standalone (${node.nodeId.slice(0, 8)})`);
  }

  // ── Hosted Mode (Section 4.3: shared transport via daemon) ─

  async _startHosted(daemonPath) {
    const opts = this._opts;
    // Create SymNode with no transport — SVAF + memory only
    this._node = new SymNode({
      name: opts.name,
      cognitiveProfile: opts.cognitiveProfile || `${opts.name} mesh agent`,
      svafFieldWeights: opts.svafFieldWeights || {},
      svafFreshnessSeconds: opts.svafFreshnessSeconds || 43200,
      discovery: new NullDiscovery(),
      silent: true,
    });

    const node = this._node;
    node.on('cmb-accepted', (entry) => {
      this._onCMBAccepted(entry).catch(err =>
        console.error(`[${this._name}] remix error:`, err.message)
      );
    });

    await node.start();
    this._hosted = true;

    // Connect to daemon via IPC
    await new Promise((resolve, reject) => {
      const socket = net.createConnection(daemonPath, () => {
        this._daemonSocket = socket;

        // Register as hosted agent (Section 4.3.1)
        socket.write(JSON.stringify({
          type: 'register-agent',
          nodeId: node.nodeId,
          name: opts.name,
          publicKey: node._identity?.publicKey || null,
          cognitiveProfile: opts.cognitiveProfile,
          svafFieldWeights: opts.svafFieldWeights,
          svafFreshnessSeconds: opts.svafFreshnessSeconds,
        }) + '\n');
      });

      let buffer = '';
      socket.on('data', (data) => {
        buffer += data.toString();
        let idx;
        while ((idx = buffer.indexOf('\n')) !== -1) {
          const line = buffer.slice(0, idx);
          buffer = buffer.slice(idx + 1);
          if (!line.trim()) continue;
          try {
            const msg = JSON.parse(line);
            if (msg.type === 'registered-agent') {
              console.log(`[${this._name}] hosted on daemon (${msg.daemonNodeId?.slice(0, 8)})`);
              resolve();
            } else if (msg.type === 'event' && msg.event === 'frame-received') {
              this._handleDaemonFrame(msg.data);
            } else if (msg.type === 'event' && msg.event === 'peer-joined') {
              console.log(`[${this._name}] peer joined: ${msg.data?.name}`);
            } else if (msg.type === 'event' && msg.event === 'peer-left') {
              console.log(`[${this._name}] peer left: ${msg.data?.name}`);
            } else if (msg.type === 'event' && msg.event === 'catchup') {
              console.log(`[${this._name}] catchup triggered`);
              this._checkDomain().catch(err =>
                console.error(`[${this._name}] catchup error:`, err.message)
              );
            }
          } catch {}
        }
      });

      socket.on('error', (err) => {
        console.error(`[${this._name}] daemon connection error: ${err.message}`);
        reject(err);
      });

      socket.on('close', () => {
        console.log(`[${this._name}] daemon connection lost`);
        this._daemonSocket = null;
      });

      setTimeout(() => reject(new Error('Daemon registration timeout')), 5000);
    });

  }

  /**
   * Handle a raw frame forwarded from the daemon (Section 4.3.2).
   * Feed into the local SymNode's frame handler for SVAF evaluation.
   */
  _handleDaemonFrame(data) {
    if (!data || !data.frame) return;
    const { peerId, peerName, frame } = data;
    // Skip own frames that bounced back
    if (frame.from === this._node.nodeId) return;
    // Feed into local frame handler — runs SVAF with this agent's weights
    this._node._frameHandler.handle(peerId || frame.from || 'unknown', peerName || frame.fromName || 'unknown', frame);
  }

  // ── Event-driven remix (Section 14) ────────────────────

  async _onCMBAccepted(entry) {
    if (!this._shouldRemix(entry)) return;

    const source = entry.source || entry.cmb?.createdBy || 'unknown';
    const focusText = entry.cmb?.fields?.focus?.text || entry.content || '';
    console.log(`[${this._name}] accepted from ${source}: ${focusText.slice(0, 80)}`);
    this._activity('remixing');

    // Section 14.7: remix requires new domain data
    if (!this._node.canRemix()) {
      console.log(`[${this._name}] no new domain data — silent (14.7)`);
      this._activity('idle');
      return;
    }

    // Prepare incoming signal for the agent's remix function
    const fields = entry.cmb?.fields || {};
    const incoming = {
      key: entry.key,
      source,
      fields: Object.fromEntries(
        Object.entries(fields).map(([k, v]) => [k, typeof v === 'object' ? v.text || JSON.stringify(v) : v])
      ),
    };

    const meshContext = this._meshContext();
    const remixFields = await this._remix(incoming, meshContext);
    if (!remixFields) return;

    // Store with lineage (Section 14.2)
    const parent = {
      key: entry.key,
      lineage: entry.lineage || entry.cmb?.lineage || null,
    };

    const stored = this._remember(remixFields, { parents: [parent] });
    if (!stored) {
      console.log(`[${this._name}] remix rejected by SDK`);
      return;
    }

    console.log(`[${this._name}] remixed ${source} → ${stored.key.slice(0, 16)}`);
    this._activity('idle');
  }

  // ── Domain observation (Section 13) ────────────────────

  async _checkDomain() {
    console.log(`[${this._name}] checking domain...`);
    this._activity('checking');

    const result = await this._fetchDomain();
    if (!result || !result.data) {
      console.log(`[${this._name}] no domain data — silent`);
      return;
    }

    // Fingerprint change detection — "one CMB per significant signal"
    const fp = result.fingerprint || '';
    if (fp && fp === this._state._lastFingerprint) {
      console.log(`[${this._name}] domain unchanged — silent`);
      return;
    }
    if (fp) this._state._lastFingerprint = fp;

    this._activity('reasoning');
    const meshContext = this._meshContext();
    const fields = await this._reason(result.data, meshContext);
    if (!fields) {
      console.log(`[${this._name}] reason() returned null — silent`);
      this._activity('idle');
      return;
    }

    // Original observation — no parents
    const stored = this._remember(fields);
    if (!stored) {
      console.log(`[${this._name}] observation rejected (duplicate)`);
      return;
    }

    console.log(`[${this._name}] domain observation: ${fields.focus?.slice(0, 100)}`);
    this._activity('idle');
    this._save();
  }

  // ── Activity Status ─────────────────────────────────────

  _activity(status) {
    if (this._hosted && this._daemonSocket) {
      try {
        this._daemonSocket.write(JSON.stringify({
          type: 'agent-activity',
          nodeId: this._node?.nodeId,
          name: this._name,
          status, // 'checking', 'reasoning', 'remixing', 'idle'
          timestamp: Date.now(),
        }) + '\n');
      } catch {}
    }
  }

  // ── Helpers ────────────────────────────────────────────

  /**
   * Store a CMB locally and broadcast to the mesh.
   * In hosted mode, sends the CMB to the daemon for broadcast (Section 4.3.2).
   * In standalone mode, remember() broadcasts directly via SymNode's transports.
   */
  _remember(fields, opts = {}) {
    const stored = this._node.remember(fields, opts);
    if (!stored) return null;

    // In hosted mode, send the CMB to daemon for broadcast to remote peers
    if (this._hosted && this._daemonSocket) {
      try {
        this._daemonSocket.write(JSON.stringify({
          type: 'agent-cmb',
          from: this._node.nodeId,
          fromName: this._name,
          timestamp: stored.timestamp || Date.now(),
          cmb: stored.cmb,
        }) + '\n');
      } catch {}
    }
    return stored;
  }

  _meshContext() {
    return (this._node.recall('') || [])
      .filter(r => r.source !== this._name)
      .slice(0, 5)
      .map(r => ({
        focus: r.cmb?.fields?.focus?.text || r.content || '',
        source: r.source || 'unknown',
        key: r.key,
      }));
  }

  _save() {
    saveState(this._agentDir, this._state);
  }
}

module.exports = { MeshAgent };
