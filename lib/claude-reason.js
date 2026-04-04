'use strict';

/**
 * claude-reason — invoke Claude CLI and extract structured CAT7 output.
 *
 * Single public function: invoke({ agentDir, agentName, prompt, ... })
 * Prompt construction is the agent's responsibility.
 * The SDK handles: CLI invocation, output parsing, CAT7 validation.
 *
 * Copyright (c) 2026 SYM.BOT Ltd. Apache 2.0 License.
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

// ── CAT7 validation ─────────────────────────────────────────────

const CAT7_FIELDS = ['focus', 'issue', 'intent', 'motivation', 'commitment', 'perspective', 'mood'];

function isValidCAT7(obj) {
  if (!obj || typeof obj !== 'object') return false;
  for (const field of CAT7_FIELDS) {
    if (!(field in obj)) return false;
  }
  if (typeof obj.mood !== 'object' || obj.mood === null) return false;
  if (typeof obj.mood.text !== 'string') return false;
  if (typeof obj.mood.valence !== 'number') return false;
  if (typeof obj.mood.arousal !== 'number') return false;
  return true;
}

// ── JSON extraction ─────────────────────────────────────────────

function tryParse(str) {
  try { return JSON.parse(str); } catch { return null; }
}

/**
 * Scan text for a balanced JSON object matching a predicate.
 * Tries every '{' as a potential start, counts braces (respecting
 * JSON strings), and tests each complete candidate.
 */
function findBalancedJSON(text, predicate) {
  for (let i = 0; i < text.length; i++) {
    if (text[i] !== '{') continue;
    let depth = 0;
    let inString = false;
    let escape = false;
    for (let j = i; j < text.length; j++) {
      const ch = text[j];
      if (escape) { escape = false; continue; }
      if (ch === '\\' && inString) { escape = true; continue; }
      if (ch === '"') { inString = !inString; continue; }
      if (inString) continue;
      if (ch === '{') depth++;
      else if (ch === '}') {
        depth--;
        if (depth === 0) {
          const parsed = tryParse(text.slice(i, j + 1));
          if (parsed && predicate(parsed)) return parsed;
          break;
        }
      }
    }
  }
  return null;
}

/**
 * Extract CAT7 from Claude CLI output.
 *
 * Handles: direct JSON, --output-format json envelope, code fences,
 * CAT7 embedded in prose, and result as string or object.
 */
function extractCAT7(raw) {
  if (!raw) return null;

  // 1. Direct parse
  const direct = tryParse(raw);
  if (direct && isValidCAT7(direct)) return direct;

  // 2. Unwrap Claude CLI envelope { type: "result", result: "..." }
  const envelope = (direct && direct.type === 'result')
    ? direct
    : findBalancedJSON(raw, obj => obj.type === 'result');

  if (envelope && envelope.result != null) {
    const content = envelope.result;
    if (typeof content === 'object' && isValidCAT7(content)) return content;
    if (typeof content === 'string') {
      const stripped = content.replace(/```json?\s*\n?/g, '').replace(/```/g, '').trim();
      const fromStripped = tryParse(stripped);
      if (fromStripped && isValidCAT7(fromStripped)) return fromStripped;
      const found = findBalancedJSON(stripped, isValidCAT7);
      if (found) return found;
    }
  }

  // 3. Last resort — scan entire raw output
  return findBalancedJSON(raw, isValidCAT7);
}

// ── Role prompt loading ─────────────────────────────────────────

function loadRolePrompt(agentDir) {
  const skillsDir = path.join(agentDir, '.agents', 'skills');
  if (fs.existsSync(skillsDir)) {
    const dirs = fs.readdirSync(skillsDir).filter(d => d !== 'sym');
    for (const dir of dirs) {
      const p = path.join(skillsDir, dir, 'SKILL.md');
      if (fs.existsSync(p)) return fs.readFileSync(p, 'utf8');
    }
  }
  const legacy = path.join(agentDir, 'config', 'role-prompt.md');
  if (fs.existsSync(legacy)) return fs.readFileSync(legacy, 'utf8');
  return 'You are a mesh agent. Produce a CMB with 7 CAT7 fields.';
}

// ── Public API ──────────────────────────────────────────────────

/**
 * Invoke Claude CLI and extract CAT7 from the response.
 *
 * @param {object} opts
 * @param {string} opts.agentDir   — agent root directory (for role prompt + cwd)
 * @param {string} opts.agentName  — agent name (for temp file naming + error logs)
 * @param {string} opts.prompt     — the full prompt (agent constructs this)
 * @param {string} [opts.model]    — model override (default: sonnet)
 * @param {number} [opts.maxBudget] — max USD per call (default: 0.05)
 * @param {string[]} [opts.addDirs] — additional directories for Claude access
 * @returns {object|null} CAT7 fields or null on failure
 */
function invoke(opts) {
  const rolePrompt = loadRolePrompt(opts.agentDir);
  const model = opts.model || process.env.CLAUDE_AGENT_MODEL || 'sonnet';
  const maxBudget = opts.maxBudget || 0.05;

  const tmpDir = path.join(os.tmpdir(), 'sym-claude');
  if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true });
  const promptFile = path.join(tmpDir, `${opts.agentName}-prompt.txt`);
  const systemFile = path.join(tmpDir, `${opts.agentName}-system.txt`);
  fs.writeFileSync(promptFile, opts.prompt + '\n\nReturn a JSON object with 7 CAT7 fields: focus, issue, intent, motivation, commitment, perspective, mood (with text, valence, arousal).');
  fs.writeFileSync(systemFile, rolePrompt);

  // Resolve Claude CLI binary — cross-platform.
  // Windows: .cmd wrappers can't receive stdin via execFileSync, so resolve
  // to the underlying node script or use shell: true on Windows.
  const isWin = process.platform === 'win32';
  let claudeBin = process.env.CLAUDE_BIN;
  if (!claudeBin) {
    try {
      const { execSync } = require('child_process');
      claudeBin = execSync(isWin ? 'where claude' : 'which claude', { encoding: 'utf8' }).trim().split('\n')[0];
    } catch {
      claudeBin = isWin ? 'claude' : '/usr/local/bin/claude';
    }
  }

  // On Windows, long --append-system-prompt args hit the 8192 char command
  // line limit. Prepend the system prompt to stdin instead.
  const useStdinSystem = isWin || rolePrompt.length > 4000;
  const args = ['-p', '--output-format', 'json', '--model', model,
    '--max-budget-usd', String(maxBudget),
    '--no-session-persistence'];
  if (!useStdinSystem) {
    args.push('--append-system-prompt', rolePrompt);
  }
  if (opts.addDirs) {
    for (const d of opts.addDirs) { args.push('--add-dir', d); }
  }

  try {
    const { execFileSync } = require('child_process');
    let prompt = fs.readFileSync(promptFile, 'utf8');
    // Prepend system prompt to stdin when CLI arg would be too long
    if (useStdinSystem) {
      prompt = `[SYSTEM CONTEXT]\n${rolePrompt}\n\n[USER PROMPT]\n${prompt}`;
    }
    // Windows .cmd wrappers need shell: true to handle stdin piping.
    const execOpts = {
      input: prompt,
      encoding: 'utf8',
      timeout: 120000,
      maxBuffer: 10 * 1024 * 1024,
      cwd: opts.agentDir,
    };
    if (isWin) execOpts.shell = true;
    const result = execFileSync(claudeBin, args, execOpts).trim();

    const cat7 = extractCAT7(result);
    if (!cat7) {
      // Log first 300 chars of raw output for debugging
      console.error(`[claude] ${opts.agentName} raw output (no CAT7): ${result.slice(0, 300)}`);
      throw new Error('No valid CAT7 JSON in Claude output');
    }
    return cat7;
  } catch (err) {
    console.error(`[claude] ${opts.agentName} invoke failed: ${err.message?.slice(0, 200)}`);
    return null;
  } finally {
    try { fs.unlinkSync(promptFile); fs.unlinkSync(systemFile); } catch {}
  }
}

module.exports = { invoke, loadRolePrompt, extractCAT7, isValidCAT7 };
