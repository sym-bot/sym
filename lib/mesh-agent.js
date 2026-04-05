'use strict';

/**
 * MeshAgent — protocol-level agent lifecycle per MMP v0.2.1.
 *
 * Every agent is a full peer node with its own identity, coupling engine,
 * and memory store. Coupling is per-node — an agent that shares another
 * node's identity cannot have independent SVAF weights or coupling decisions.
 *
 * The agent IS the intelligence (Section 13). The protocol provides:
 *
 *   1. cmb-accepted → canRemix() → agent.remix() → remember() with lineage
 *   2. Domain poll → fingerprint change → agent.reason() → remember()
 *   3. Silence when nothing new (Section 14.7)
 *
 * Usage:
 *   const agent = new MeshAgent({
 *     name: 'research',
 *     svafFieldWeights: { focus: 2.0, perspective: 2.0, ... },
 *     pollInterval: 6 * 60 * 60 * 1000,
 *     fetchDomain: async () => ({ data: '...', fingerprint: '...' }),
 *     reason: async (domainData, meshContext) => ({ focus: '...', ... }),
 *     remix: async (incomingCMB, meshContext) => ({ focus: '...', ... }),
 *   });
 *   await agent.start();
 *
 * See MMP v0.2.1 Section 13 (Application), Section 14 (Remix).
 *
 * Copyright (c) 2026 SYM.BOT Ltd. Apache 2.0 License.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { SymNode } = require('./node');

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
   * @param {string} opts.name — agent name (e.g. 'research')
   * @param {string} [opts.agentDir] — agent root directory (default: process.cwd())
   * @param {string} [opts.cognitiveProfile] — short description for coupling
   * @param {object} [opts.svafFieldWeights] — per-field SVAF weights
   * @param {number} [opts.svafFreshnessSeconds] — temporal decay (default: 43200)
   * @param {number} [opts.pollInterval] — domain poll interval in ms (default: 30 min)
   * @param {Function} opts.fetchDomain — async () => { data: string, fingerprint: string } | null
   * @param {Function} opts.reason — async (domainData, meshContext) => CAT7 fields | null
   * @param {Function} opts.remix — async (incomingCMB, meshContext) => CAT7 fields | null
   * @param {Function} [opts.shouldRemix] — (entry) => boolean — filter which CMBs to remix
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

    // Load relay config from ~/.sym/relay.env if env vars not set
    // Same pattern as sym-daemon — agents are full peers and need relay
    if (!process.env.SYM_RELAY_URL) {
      const envFile = path.join(os.homedir(), '.sym', 'relay.env');
      if (fs.existsSync(envFile)) {
        for (const line of fs.readFileSync(envFile, 'utf8').split('\n')) {
          const m = line.match(/^(\w+)=(.*)$/);
          if (m && !process.env[m[1]]) process.env[m[1]] = m[2].trim();
        }
      }
    }

    // Every agent is a full peer node (MMP v0.2.1 Section 2.4)
    this._node = new SymNode({
      name: opts.name,
      cognitiveProfile: opts.cognitiveProfile || `${opts.name} mesh agent`,
      svafFieldWeights: opts.svafFieldWeights || {},
      svafFreshnessSeconds: opts.svafFreshnessSeconds || 43200,
      relay: process.env.SYM_RELAY_URL || null,
      relayToken: process.env.SYM_RELAY_TOKEN || null,
      silent: false,
    });

    this._state = loadState(this._agentDir);
    this._state._lastFingerprint = this._state._lastFingerprint || '';
    this._pollTimer = null;
    this._saveTimer = null;
  }

  /** @returns {SymNode} the underlying node */
  get node() { return this._node; }

  /** @returns {object} persistent state — agent can store domain-specific data here */
  get state() { return this._state; }

  // ── Lifecycle ──────────────────────────────────────────

  async start() {
    const node = this._node;

    // Event-driven remix — the primary path (Section 14)
    node.on('cmb-accepted', (entry) => {
      this._onCMBAccepted(entry).catch(err =>
        console.error(`[${this._name}] remix error:`, err.message)
      );
    });
    node.on('peer-joined', ({ name }) => console.log(`[${this._name}] peer joined: ${name}`));
    node.on('peer-left', ({ name }) => console.log(`[${this._name}] peer left: ${name}`));

    // Catchup: peers broadcast "catchup" message to trigger immediate domain poll
    // See MMP Section 7: message frame emits (fromName, content, msg)
    node.on('message', (from, content) => {
      if (content === 'catchup') {
        console.log(`[${this._name}] catchup received`);
        this._checkDomain().catch(err =>
          console.error(`[${this._name}] catchup error:`, err.message)
        );
      }
    });

    await node.start();
    console.log(`[${this._name}] started (${node.nodeId.slice(0, 8)})`);

    if (this._onStarted) await this._onStarted(node);

    // Wait for peer discovery before first domain check
    await new Promise(r => setTimeout(r, 5000));

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
      await this._node.stop();
      process.exit(0);
    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
  }

  // ── Event-driven remix (Section 14) ────────────────────

  async _onCMBAccepted(entry) {
    if (!this._shouldRemix(entry)) return;

    const source = entry.source || entry.cmb?.createdBy || 'unknown';
    const focusText = entry.cmb?.fields?.focus?.text || entry.content || '';
    console.log(`[${this._name}] accepted from ${source}: ${focusText.slice(0, 80)}`);

    // Section 14.7: remix requires new domain data
    if (!this._node.canRemix()) {
      console.log(`[${this._name}] no new domain data — silent (14.7)`);
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

    // Extract agent meta — travels with CMB over wire
    const meta = remixFields._meta || null;
    delete remixFields._meta;

    // Store with lineage (Section 14.2)
    const parent = {
      key: entry.key,
      lineage: entry.lineage || entry.cmb?.lineage || null,
    };

    const stored = this._node.remember(remixFields, { parents: [parent], ...(meta ? { meta } : {}) });
    if (!stored) {
      console.log(`[${this._name}] remix rejected by SDK`);
      return;
    }

    console.log(`[${this._name}] remixed ${source} → ${stored.key.slice(0, 16)}`);
  }

  // ── Domain observation (Section 13) ────────────────────

  async _checkDomain() {
    console.log(`[${this._name}] checking domain...`);

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

    const meshContext = this._meshContext();
    const fields = await this._reason(result.data, meshContext);
    if (!fields) {
      console.log(`[${this._name}] reason() returned null — silent`);
      return;
    }

    // Extract agent meta (e.g. founderAction) — travels with CMB over wire
    const meta = fields._meta || null;
    delete fields._meta;

    // Original observation — no parents
    const stored = this._node.remember(fields, meta ? { meta } : undefined);
    if (!stored) {
      console.log(`[${this._name}] observation rejected (duplicate)`);
      return;
    }

    console.log(`[${this._name}] domain observation: ${fields.focus?.slice(0, 100)}`);
    this._save();
  }

  // ── Helpers ────────────────────────────────────────────

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
