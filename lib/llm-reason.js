'use strict';

/**
 * claude-reason — invoke LLM API and extract structured CAT7 output.
 *
 * Single public function: invoke({ agentDir, agentName, prompt, ... })
 * Prompt construction is the agent's responsibility.
 * The SDK handles: API invocation, output parsing, CAT7 validation.
 *
 * Supports any OpenAI-compatible API (OpenAI, Anthropic, Ollama, etc.)
 * via environment variables:
 *   SYM_LLM_PROVIDER  — 'openai' (default) | 'anthropic'
 *   SYM_LLM_API_KEY   — API key (or OPENAI_API_KEY / ANTHROPIC_API_KEY)
 *   SYM_LLM_MODEL     — model name (default: gpt-4o-mini / claude-sonnet-4-6)
 *   SYM_LLM_BASE_URL  — custom endpoint (default: provider's standard URL)
 *
 * Copyright (c) 2026 SYM.BOT Ltd. Apache 2.0 License.
 */

const fs = require('fs');
const path = require('path');

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
 * Extract CAT7 from LLM output.
 *
 * Handles: direct JSON, code fences, CAT7 embedded in prose.
 */
function extractCAT7(raw) {
  if (!raw) return null;

  // 1. Direct parse
  const direct = tryParse(raw);
  if (direct && isValidCAT7(direct)) return direct;

  // 2. Strip code fences and try again
  const stripped = raw.replace(/```json?\s*\n?/g, '').replace(/```/g, '').trim();
  const fromStripped = tryParse(stripped);
  if (fromStripped && isValidCAT7(fromStripped)) return fromStripped;

  // 3. Unwrap Claude CLI envelope { type: "result", result: "..." }
  const envelope = (direct && direct.type === 'result')
    ? direct
    : findBalancedJSON(raw, obj => obj.type === 'result');

  if (envelope && envelope.result != null) {
    const content = envelope.result;
    if (typeof content === 'object' && isValidCAT7(content)) return content;
    if (typeof content === 'string') {
      const s = content.replace(/```json?\s*\n?/g, '').replace(/```/g, '').trim();
      const fromS = tryParse(s);
      if (fromS && isValidCAT7(fromS)) return fromS;
      const found = findBalancedJSON(s, isValidCAT7);
      if (found) return found;
    }
  }

  // 4. Last resort — scan entire raw output
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

// ── Load env from relay.env ──────────────────────────────────────

let _envLoaded = false;
function ensureEnv() {
  if (_envLoaded) return;
  _envLoaded = true;
  if (process.env.SYM_LLM_API_KEY) return;
  const os = require('os');
  const envFile = path.join(os.homedir(), '.sym', 'relay.env');
  if (!fs.existsSync(envFile)) return;
  for (const line of fs.readFileSync(envFile, 'utf8').split('\n')) {
    const m = line.match(/^(\w+)=(.*)$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2].trim();
  }
}

// ── Provider config ─────────────────────────────────────────────

function getProviderConfig(opts) {
  ensureEnv();
  const provider = opts.provider || process.env.SYM_LLM_PROVIDER || 'openai';

  if (provider === 'anthropic') {
    return {
      provider: 'anthropic',
      apiKey: opts.apiKey || process.env.SYM_LLM_API_KEY || process.env.ANTHROPIC_API_KEY,
      model: opts.model || process.env.SYM_LLM_MODEL || process.env.CLAUDE_AGENT_MODEL || 'claude-sonnet-4-6',
      baseUrl: opts.baseUrl || process.env.SYM_LLM_BASE_URL || 'https://api.anthropic.com',
    };
  }

  // Default: OpenAI-compatible (works with OpenAI, Ollama, vLLM, etc.)
  return {
    provider: 'openai',
    apiKey: opts.apiKey || process.env.SYM_LLM_API_KEY || process.env.OPENAI_API_KEY,
    model: opts.model || process.env.SYM_LLM_MODEL || process.env.CLAUDE_AGENT_MODEL || 'gpt-4o-mini',
    baseUrl: opts.baseUrl || process.env.SYM_LLM_BASE_URL || 'https://api.openai.com',
  };
}

// ── API calls ───────────────────────────────────────────────────

async function callOpenAI(config, systemPrompt, userPrompt) {
  const url = `${config.baseUrl.replace(/\/$/, '')}/v1/chat/completions`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${config.apiKey}`,
    },
    body: JSON.stringify({
      model: config.model,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt },
      ],
      temperature: 0.3,
      max_tokens: 2048,
    }),
    signal: AbortSignal.timeout(120000),
  });

  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`OpenAI API ${res.status}: ${body.slice(0, 200)}`);
  }

  const data = await res.json();
  const usage = data.usage;
  return { text: data.choices?.[0]?.message?.content || null, usage };
}

async function callAnthropic(config, systemPrompt, userPrompt) {
  const url = `${config.baseUrl.replace(/\/$/, '')}/v1/messages`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': config.apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: config.model,
      system: systemPrompt,
      messages: [
        { role: 'user', content: userPrompt },
      ],
      temperature: 0.3,
      max_tokens: 2048,
    }),
    signal: AbortSignal.timeout(120000),
  });

  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Anthropic API ${res.status}: ${body.slice(0, 200)}`);
  }

  const data = await res.json();
  const usage = data.usage ? { prompt_tokens: data.usage.input_tokens, completion_tokens: data.usage.output_tokens } : null;
  return { text: data.content?.[0]?.text || null, usage };
}

/**
 * Retry wrapper for transient API errors (429, 503, network).
 * Single retry with 2s backoff.
 */
async function withRetry(fn) {
  try {
    return await fn();
  } catch (err) {
    const status = parseInt(err.message?.match(/API (\d+)/)?.[1] || '0');
    if (status === 429 || status === 503 || err.name === 'AbortError') {
      await new Promise(r => setTimeout(r, 2000));
      return fn();
    }
    throw err;
  }
}

// ── Public API ──────────────────────────────────────────────────

/**
 * Invoke LLM and extract CAT7 from the response.
 *
 * @param {object} opts
 * @param {string} opts.agentDir   — agent root directory (for role prompt)
 * @param {string} opts.agentName  — agent name (for error logs)
 * @param {string} opts.prompt     — the full prompt (agent constructs this)
 * @param {string} [opts.model]    — model override
 * @param {string} [opts.provider] — 'openai' | 'anthropic'
 * @param {string} [opts.apiKey]   — API key override
 * @param {string} [opts.baseUrl]  — base URL override
 * @returns {Promise<object|null>} CAT7 fields or null on failure
 */
async function invoke(opts) {
  const rolePrompt = loadRolePrompt(opts.agentDir);
  const config = getProviderConfig(opts);

  if (!config.apiKey) {
    console.error(`[llm] ${opts.agentName} no API key configured. Set SYM_LLM_API_KEY, OPENAI_API_KEY, or ANTHROPIC_API_KEY`);
    return null;
  }

  const userPrompt = opts.prompt +
    '\n\nReturn a JSON object with 7 CAT7 fields: focus, issue, intent, motivation, commitment, perspective, mood (with text, valence, arousal).';

  try {
    const callFn = config.provider === 'anthropic'
      ? () => callAnthropic(config, rolePrompt, userPrompt)
      : () => callOpenAI(config, rolePrompt, userPrompt);

    const result = await withRetry(callFn);
    const raw = result.text;

    // Report token usage if callback provided
    if (result.usage && opts.onUsage) {
      opts.onUsage({
        model: config.model,
        promptTokens: result.usage.prompt_tokens || 0,
        completionTokens: result.usage.completion_tokens || 0,
      });
    }

    const cat7 = extractCAT7(raw);
    if (!cat7) {
      console.error(`[llm] ${opts.agentName} raw output (no CAT7): ${(raw || '').slice(0, 300)}`);
      throw new Error('No valid CAT7 JSON in LLM output');
    }
    return cat7;
  } catch (err) {
    console.error(`[llm] ${opts.agentName} invoke failed: ${err.message?.slice(0, 200)}`);
    return null;
  }
}

module.exports = { invoke, loadRolePrompt, extractCAT7, isValidCAT7 };
