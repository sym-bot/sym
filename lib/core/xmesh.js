'use strict';

/**
 * @module @sym-bot/core/xmesh
 * @description xMesh — Per-agent Liquid Neural Network for collective intelligence.
 *
 * Each agent runs its own CfC (Closed-form Continuous-time) model,
 * processing bidirectional CMB flows:
 *   - Outbound: agent's own observations (weighted by its alpha_f category weights)
 *   - Inbound: mesh signals from other agents (SVAF-evaluated, fused CMBs)
 *
 * The CfC evolves the agent's cognitive state (h1, h2) from both flows.
 * Collective intelligence emerges from coupling independent cognitive
 * states via state-sync — not from a central model.
 *
 * On the daemon, this class manages signal ingestion and periodic CfC
 * inference via Python subprocess. On iOS, inference runs natively.
 *
 * Training signal: CMB lineage — CMBs cited by other agents represent
 * valuable cognitive state evolution.
 *
 * See MMP v0.2.0 Section 12: xMesh (Layer 6).
 * See MMP v0.2.0 Section 14: Remix.
 *
 * @copyright 2026 SYM.BOT Ltd. All rights reserved.
 * @license Apache-2.0
 */

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { symPath } = require('./state-root');
const XMESH_DIR = symPath('xmesh');
const SIGNALS_PATH = path.join(XMESH_DIR, 'signals.json');
const INSIGHTS_PATH = path.join(XMESH_DIR, 'insights.json');
const PACKAGE_ROOT = path.resolve(__dirname, '..');
const MODEL_PATH = path.join(PACKAGE_ROOT, 'models', 'xmesh_v4.pt');

// ── Concurrent-writer safety (public-opening gate G3c) ──────────────────────────────────
//
// signals.json and insights.json are SHARED files: seats, daemons, and operators each hold
// their own in-memory array and, before this, each persist rewrote the whole file from that
// memory — last-writer-wins, the other writers' records erased silently. The 0.7.3 state
// root fixed where these files live; this fixes who may rewrite them.
//
// The persist is now a lock-guarded read-merge-write: take the lock, re-read the file,
// union it with this process's records by id, cap by recency, write atomically
// (tmp + rename), release. Two writers each merge the other's records before writing, so
// neither can erase the other. On lock exhaustion the caller KEEPS its memory and the next
// persist retries — degraded to later, never to lost.
//
// Records carry a process-unique id because merge needs identity; legacy id-less records
// merge by content, so two copies of the same old record collapse instead of duplicating.

let idSeq = 0;
function newId(prefix) {
  return `${prefix}-${Date.now()}-${process.pid}-${(idSeq++).toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
}

const LOCK_RETRIES = 100;
const LOCK_WAIT_MS = 20;
const LOCK_STALE_MS = 5000;

/** Sleep without an event loop: persists are called from sync paths. */
function sleepSync(ms) {
  try { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }
  catch { const until = Date.now() + ms; while (Date.now() < until) { /* fallback spin */ } }
}

/** mkdir is the portable atomic take. A lock older than LOCK_STALE_MS is a dead holder
 *  (writes are ms-scale) and is broken rather than waited on forever. */
function acquireLock(file) {
  const lockDir = `${file}.lock`;
  for (let i = 0; i < LOCK_RETRIES; i++) {
    try { fs.mkdirSync(lockDir); return lockDir; }
    catch {
      try {
        if (Date.now() - fs.statSync(lockDir).mtimeMs > LOCK_STALE_MS) {
          try { fs.rmdirSync(lockDir); } catch { /* lost the race to another breaker */ }
          continue;
        }
      } catch { continue; } // holder released between mkdir and stat — retry now
      sleepSync(LOCK_WAIT_MS);
    }
  }
  return null;
}

/** Union disk with this process's records, newest-capped, written atomically under the
 *  lock. Returns the merged array for the caller's memory to adopt, or null if the lock
 *  could not be taken (caller keeps its records; a later persist carries them). */
function mergePersist(file, mine, cap, pretty) {
  const lock = acquireLock(file);
  if (!lock) return null;
  try {
    let disk = [];
    try { if (fs.existsSync(file)) disk = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { disk = []; }
    if (!Array.isArray(disk)) disk = [];
    const seen = new Set();
    const merged = [];
    for (const e of [...disk, ...mine]) {
      const key = e && e.id != null ? `i:${e.id}` : `c:${JSON.stringify(e)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      merged.push(e);
    }
    merged.sort((a, b) => ((a && a.timestamp) || 0) - ((b && b.timestamp) || 0));
    const capped = merged.length > cap ? merged.slice(-cap) : merged;
    const tmp = `${file}.tmp-${process.pid}`;
    fs.writeFileSync(tmp, pretty ? JSON.stringify(capped, null, 2) : JSON.stringify(capped));
    fs.renameSync(tmp, file);
    return capped;
  } catch { return null; }
  finally { try { fs.rmdirSync(lock); } catch { /* already released */ } }
}

/**
 * Per-agent xMesh LNN manager.
 *
 * Ingests signals from local agent activity and mesh peers,
 * runs periodic CfC inference, and produces cognitive insights.
 */
class XMesh {

  /**
   * @param {object} [opts]
   * @param {number} [opts.maxSignals=1000] - Maximum retained signals.
   * @param {number} [opts.maxInsights=200] - Maximum retained insights.
   * @param {function} [opts.log] - Logging function.
   * @param {number} [opts.inferenceInterval=60000] - Minimum ms between inference runs.
   * @param {function} [opts.onInsight] - Callback invoked with each new insight.
   */
  constructor(opts = {}) {
    this._signals = [];
    this._insights = [];
    this._maxSignals = opts.maxSignals || 1000;
    this._maxInsights = opts.maxInsights || 200;
    this._log = opts.log || (() => {});
    this._inferenceInterval = opts.inferenceInterval || 60000;
    this._lastInferenceTime = 0;
    this._inferenceRunning = false;
    this._onInsight = opts.onInsight || null;
    this._coldStart = true; // First inference needs longer timeout (PyTorch import)

    this._modelAvailable = fs.existsSync(MODEL_PATH);
    if (this._modelAvailable) {
      this._log(`xMesh: model loaded from ${MODEL_PATH}`);
    } else {
      this._log(`xMesh: model not found at ${MODEL_PATH} — running in signal-only mode`);
    }

    try { fs.mkdirSync(XMESH_DIR, { recursive: true }); } catch (e) { this._log(`xMesh: storage dir error: ${e.message}`); }

    this._loadSignals();
    this._loadInsights();
  }

  // ── Signal Ingestion ──────────────────────────────────────

  /**
   * Ingest a signal from local agent activity or a mesh peer.
   *
   * @param {object} signal
   * @param {string} [signal.type='unknown'] - Signal type (e.g. 'local', 'mesh').
   * @param {string} [signal.from='unknown'] - Originating agent name.
   * @param {string} [signal.content=''] - Signal text content.
   * @param {object} [signal.categories] - Structured CMB categories, if available.
   * @param {number} [signal.valence=0] - Mood valence [-1, 1].
   * @param {number} [signal.arousal=0] - Mood arousal [0, 1].
   * @param {number} [signal.drift] - Coupling drift score.
   * @param {string} [signal.decision] - Coupling decision.
   * @returns {void}
   */
  ingestSignal(signal) {
    const entry = {
      id: newId('sig'),
      type: signal.type || 'unknown',
      from: signal.from || 'unknown',
      content: signal.content || '',
      categories: signal.categories || null,
      valence: signal.valence ?? (signal.categories?.mood?.valence ?? 0),
      arousal: signal.arousal ?? (signal.categories?.mood?.arousal ?? 0),
      drift: signal.drift,
      decision: signal.decision,
      timestamp: Date.now(),
    };

    this._signals.push(entry);
    if (this._signals.length > this._maxSignals) {
      this._signals = this._signals.slice(-this._maxSignals);
    }
    this._persistSignals();

    this._log(`xMesh: ingested ${entry.type} from ${entry.from}`);

    const now = Date.now();
    if (this._modelAvailable && !this._inferenceRunning &&
        now - this._lastInferenceTime > this._inferenceInterval) {
      this._runInference();
    }
  }

  // ── CfC Inference ─────────────────────────────────────────

  /** @private */
  _runInference() {
    if (this._signals.length < 3) {
      this._log('xMesh: skipping inference — fewer than 3 signals');
      return;
    }

    this._inferenceRunning = true;
    this._lastInferenceTime = Date.now();

    const input = JSON.stringify({
      model_path: MODEL_PATH,
      signals: this._signals.map(s => ({
        agent: s.from,
        text: s.content,
        timestamp: s.timestamp / 1000,
        type: s.type,
        valence: s.valence ?? 0,
        arousal: s.arousal ?? 0,
      })),
    });

    const inferScript = path.join(PACKAGE_ROOT, 'inference', 'xmesh_infer.py');
    const pythonBin = process.env.PYTHON_BIN || (process.platform === 'win32' ? 'python' : 'python3');
    // First run needs longer timeout for PyTorch cold-start (especially on Windows)
    const timeout = this._coldStart ? 90000 : 30000;
    const child = spawn(pythonBin, [inferScript], {
      timeout,
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });

    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });

    child.stdin.on('error', () => {});
    child.stdin.write(input);
    child.stdin.end();

    child.on('error', (err) => {
      this._inferenceRunning = false;
      this._log(`xMesh: spawn error: ${err.message}`);
    });

    child.on('close', (code) => {
      this._inferenceRunning = false;
      this._coldStart = false; // Subsequent runs use shorter timeout

      if (code !== 0) {
        this._log(`xMesh: inference failed (exit ${code}): ${stderr.slice(0, 200)}`);
        return;
      }

      try {
        const result = JSON.parse(stdout);
        this._processInferenceResult(result);
      } catch (e) {
        this._log(`xMesh: inference parse error: ${e.message}`);
      }
    });
  }

  /** @private */
  _processInferenceResult(result) {
    const insight = {
      id: newId('insight'),
      timestamp: Date.now(),
      trajectory: result.trajectory,
      patterns: result.patterns,
      anomaly: result.anomaly,
      remixScore: result.remix_score,
      coherence: result.coherence,
      signalCount: this._signals.length,
    };

    this._insights.push(insight);
    if (this._insights.length > this._maxInsights) {
      this._insights = this._insights.slice(-this._maxInsights);
    }
    this._persistInsights();

    this._log(`xMesh: insight — anomaly=${insight.anomaly?.toFixed(3)}, remix=${insight.remixScore?.toFixed(3)}, coherence=${insight.coherence?.toFixed(3)}`);

    if (this._onInsight) {
      this._onInsight(insight);
    }
  }

  // ── Query ─────────────────────────────────────────────────

  /**
   * Get a summary of xMesh context within a time window.
   *
   * @param {object} [opts]
   * @param {number} [opts.timeWindow=86400000] - Time window in ms (default 24h).
   * @returns {{ modelAvailable: boolean, insightCount: number, signalCount: number, timeWindowHours: number, latestInsight: object|null, agents: object, insights: object[] }}
   */
  getContext(opts = {}) {
    const now = Date.now();
    const timeWindow = opts.timeWindow || 86400000;
    const recentInsights = this._insights.filter(i => now - i.timestamp < timeWindow);
    const recentSignals = this._signals.filter(s => now - s.timestamp < timeWindow);

    const agents = {};
    for (const s of recentSignals) {
      if (!agents[s.from]) agents[s.from] = { count: 0, lastSeen: 0 };
      agents[s.from].count++;
      agents[s.from].lastSeen = Math.max(agents[s.from].lastSeen, s.timestamp);
    }

    return {
      modelAvailable: this._modelAvailable,
      insightCount: recentInsights.length,
      signalCount: recentSignals.length,
      timeWindowHours: timeWindow / 3600000,
      latestInsight: recentInsights.length > 0 ? recentInsights[recentInsights.length - 1] : null,
      agents,
      insights: recentInsights.slice(-5),
    };
  }

  /**
   * Get the most recent insights.
   *
   * @param {number} [limit=10] - Maximum number of insights to return.
   * @returns {object[]} Array of insight objects, most recent last.
   */
  getInsights(limit = 10) {
    return this._insights.slice(-limit);
  }

  // ── Persistence ───────────────────────────────────────────

  /** @private */
  _loadSignals() {
    try {
      if (fs.existsSync(SIGNALS_PATH)) {
        this._signals = JSON.parse(fs.readFileSync(SIGNALS_PATH, 'utf8'));
      }
    } catch { this._signals = []; }
  }

  /** @private */
  _persistSignals() {
    const merged = mergePersist(SIGNALS_PATH, this._signals, this._maxSignals, false);
    // Memory adopts the union so the next rewrite carries other writers' records too; on a
    // failed take, memory is kept and the next persist retries.
    if (merged) this._signals = merged;
  }

  /** @private */
  _loadInsights() {
    try {
      if (fs.existsSync(INSIGHTS_PATH)) {
        this._insights = JSON.parse(fs.readFileSync(INSIGHTS_PATH, 'utf8'));
      }
    } catch { this._insights = []; }
  }

  /** @private */
  _persistInsights() {
    const merged = mergePersist(INSIGHTS_PATH, this._insights, this._maxInsights, true);
    if (merged) this._insights = merged;
  }
}

module.exports = { XMesh };
