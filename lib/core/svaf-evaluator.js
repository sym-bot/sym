'use strict';

/**
 * @module @sym-bot/core/svaf-evaluator
 * @description Neural SVAF Evaluator — runs the trained SVAF model for memory evaluation.
 *
 * Called by SymNode when a cmb frame arrives. Spawns Python
 * subprocess for neural inference, returns per-category drift and decision.
 *
 * Falls back to heuristic evaluation if the model is not available
 * or inference fails.
 *
 * See MMP v0.2.0 Section 9: Coupling & SVAF.
 *
 * @copyright 2026 SYM.BOT Ltd. All rights reserved.
 * @license UNLICENSED
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const PACKAGE_ROOT = path.resolve(__dirname, '..');
const MODEL_PATH = path.join(PACKAGE_ROOT, 'models', 'svaf_v2.pt');
const INFER_SCRIPT = path.join(PACKAGE_ROOT, 'inference', 'svaf_infer.py');

/**
 * Neural SVAF evaluator for incoming memory signals.
 *
 * Wraps a Python subprocess that runs the trained SVAF model.
 * Returns per-category drift scores and an accept/reject decision.
 */
class SVAFEvaluator {

  /**
   * @param {object} [opts]
   * @param {function} [opts.log] - Logging function, defaults to console.log.
   */
  constructor(opts = {}) {
    this._log = opts.log || ((msg) => console.log(`[SVAF] ${msg}`));
    this._modelAvailable = fs.existsSync(MODEL_PATH);
    this._inferRunning = false;
    this._coldStart = true; // First inference needs longer timeout (PyTorch import)

    if (this._modelAvailable) {
      this._log(`Neural SVAF model loaded from ${MODEL_PATH}`);
    } else {
      this._log(`Neural SVAF model not found at ${MODEL_PATH} — heuristic only`);
    }
  }

  /**
   * Evaluate an incoming memory signal using neural SVAF.
   *
   * See MMP v0.2.0 Section 9: Coupling & SVAF.
   *
   * @param {object} incoming - Incoming signal descriptor.
   * @param {string} incoming.text - Signal text content.
   * @param {string} incoming.source - Originating agent/peer name.
   * @param {string[]} incoming.tags - Signal tags.
   * @param {number} incoming.confidence - Signal confidence [0, 1].
   * @param {object[]} anchors - Local memory anchors [{ text, source, tags }].
   * @param {number} ageSeconds - Age of the signal in seconds.
   * @returns {Promise<object|null>} { decision, total_drift, field_drifts, gate_values } or null on failure.
   */
  async evaluate(incoming, anchors, ageSeconds) {
    if (!this._modelAvailable) {
      return null; // Caller falls back to heuristic
    }

    if (this._inferRunning) {
      this._log('SVAF inference already running, skipping');
      return null;
    }

    return new Promise((resolve) => {
      this._inferRunning = true;

      const input = JSON.stringify({
        model_path: MODEL_PATH,
        incoming: {
          text: incoming.text || incoming.content || '',
          source: incoming.source || incoming.fromName || 'unknown',
          tags: incoming.tags || [],
        },
        anchors: (anchors || []).map(a => ({
          text: a.content || a.text || '',
          source: a.source || 'local',
          tags: a.tags || [],
        })),
        age_seconds: ageSeconds || 0,
        confidence: incoming.confidence || 0.8,
      });

      const pythonBin = process.env.PYTHON_BIN || (process.platform === 'win32' ? 'python' : 'python3');
      // First run needs longer timeout for PyTorch cold-start (especially on Windows)
      const timeout = this._coldStart ? 60000 : 15000;
      const child = spawn(pythonBin, [INFER_SCRIPT], {
        timeout,
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true,
      });

      let stdout = '';
      let stderr = '';
      child.stdout.on('data', (d) => { stdout += d; });
      child.stderr.on('data', (d) => { stderr += d; });

      child.stdin.on('error', () => {}); // Prevent EPIPE crash
      child.stdin.write(input);
      child.stdin.end();

      child.on('close', (code) => {
        this._inferRunning = false;
        this._coldStart = false; // Subsequent runs use shorter timeout

        if (code !== 0) {
          this._log(`SVAF inference failed (exit ${code}): ${stderr.slice(0, 200)}`);
          resolve(null);
          return;
        }

        try {
          const result = JSON.parse(stdout);
          this._log(`SVAF neural: ${result.decision} (drift: ${result.total_drift?.toFixed(3)}, ` +
            `mood: ${result.gate_values?.mood?.toFixed(2)}, ` +
            `focus: ${result.gate_values?.focus?.toFixed(2)}, ` +
            `issue: ${result.gate_values?.issue?.toFixed(2)})`);
          resolve(result);
        } catch (e) {
          this._log(`SVAF inference parse error: ${e.message}`);
          resolve(null);
        }
      });

      child.on('error', (err) => {
        this._inferRunning = false;
        this._log(`SVAF inference spawn error: ${err.message}`);
        resolve(null);
      });
    });
  }

  /**
   * Whether the neural SVAF model file is present on disk.
   * @returns {boolean}
   */
  get available() {
    return this._modelAvailable;
  }
}

module.exports = { SVAFEvaluator };
