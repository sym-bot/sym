'use strict';

/**
 * @module @sym-bot/sym/llm-cli
 * @description Claude Code CLI provider — invoke `claude` as a subprocess.
 *
 * Why this exists: the OpenAI / Anthropic HTTP providers in llm-reason.js
 * give chat-completion-only access. Agents can't Read files, WebFetch
 * URLs, run Bash, or invoke Skills. Per project_claude_cli_agents.md
 * the SYM.BOT direction is to give every agent the same tool surface
 * Claude Code itself uses, so research-win can WebFetch a Spotify blog
 * post directly instead of relying on RSS paraphrase, coo-win can Read
 * the actual paper.tex, etc.
 *
 * This provider:
 *   - Spawns `claude -p --output-format json` as a subprocess
 *   - Sets cwd to the agent directory so CLAUDE.md, .claude/settings.json,
 *     and project skills resolve naturally
 *   - Appends the agent's SKILL.md content via --append-system-prompt
 *     (additive, so Claude Code's default tool descriptions stay loaded)
 *   - Supports --add-dir for additional file scope (already a parameter
 *     on existing llm.invoke calls — silently ignored by HTTP providers)
 *   - Supports --allowedTools for safety constraint (default: unrestricted)
 *   - Inherits Claude Code's local auth — no API key needed
 *
 * Trade-offs vs HTTP API mode:
 *   + Full tool access (Read, Write, Bash, Grep, WebFetch, Skill, etc.)
 *   + SKILL.md / CLAUDE.md hierarchy auto-loaded by Claude Code
 *   + Uses local Claude Code subscription billing instead of API tokens
 *   - Subprocess spawn ~200ms vs API ~50ms first byte
 *   - Requires `claude` CLI installed and authenticated on the host
 *   - No streaming (--print mode is one-shot)
 *
 * Copyright (c) 2026 SYM.BOT Ltd. Apache 2.0 License.
 */

const { spawn } = require('child_process');

/// Maps full Anthropic model IDs to the short aliases the CLI accepts.
/// Callers can pass either form.
const MODEL_ALIASES = {
  'claude-opus-4-6': 'opus',
  'claude-sonnet-4-6': 'sonnet',
  'claude-haiku-4-5-20251001': 'haiku',
  'claude-haiku-4-5': 'haiku',
};

function normalizeModel(model) {
  if (!model) return 'sonnet';
  return MODEL_ALIASES[model] || model;
}

/**
 * Invoke `claude` CLI as a subprocess and return the result.
 *
 * @param {object} config
 * @param {string} config.model         — short alias or full model id
 * @param {string} [config.cwd]         — working directory (sets project context). Defaults to process.cwd().
 * @param {string[]} [config.addDirs]   — additional dirs to allow tool access to
 * @param {string} [config.allowedTools] — comma/space-separated tool whitelist. Default: unrestricted.
 * @param {string} [config.permissionMode] — 'bypassPermissions' (default), 'acceptEdits', 'plan', etc.
 * @param {number} [config.maxBudgetUsd] — cost cap per call
 * @param {number} [config.timeoutMs]   — kill the subprocess after N ms (default 180000)
 * @param {string} systemPrompt — appended to Claude Code's default system prompt
 * @param {string} userPrompt   — the user message
 * @returns {Promise<{text, usage, costUsd, durationMs, model}>}
 */
function callClaudeCLI(config, systemPrompt, userPrompt) {
  return new Promise((resolve, reject) => {
    const args = [
      '-p',
      '--output-format', 'json',
      '--no-session-persistence',
      '--model', normalizeModel(config.model),
      '--permission-mode', config.permissionMode || 'bypassPermissions',
    ];

    // Append the SKILL.md content as additional system prompt. Using
    // --append (not --system-prompt) keeps Claude Code's default tool
    // descriptions and behaviour intact while adding the agent role.
    if (systemPrompt && systemPrompt.trim()) {
      args.push('--append-system-prompt', systemPrompt);
    }

    if (config.allowedTools) {
      args.push('--allowedTools', config.allowedTools);
    }

    if (Array.isArray(config.addDirs) && config.addDirs.length > 0) {
      args.push('--add-dir', ...config.addDirs);
    }

    if (config.maxBudgetUsd && config.maxBudgetUsd > 0) {
      args.push('--max-budget-usd', String(config.maxBudgetUsd));
    }

    // The user prompt is the final positional arg.
    args.push(userPrompt);

    const proc = spawn('claude', args, {
      cwd: config.cwd || process.cwd(),
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    proc.stdout.on('data', (chunk) => { stdout += chunk; });
    proc.stderr.on('data', (chunk) => { stderr += chunk; });

    const timeoutMs = config.timeoutMs || 180000;
    const timer = setTimeout(() => {
      proc.kill('SIGTERM');
      // Give it a moment to clean up before SIGKILL
      setTimeout(() => { try { proc.kill('SIGKILL'); } catch {} }, 2000);
      reject(new Error(`claude CLI timeout after ${timeoutMs}ms`));
    }, timeoutMs);

    proc.on('error', (err) => {
      clearTimeout(timer);
      if (err.code === 'ENOENT') {
        reject(new Error(`claude CLI not found in PATH. Install Claude Code: https://docs.claude.com/claude-code`));
      } else {
        reject(new Error(`claude CLI spawn failed: ${err.message}`));
      }
    });

    proc.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        return reject(new Error(`claude CLI exited ${code}: ${(stderr || stdout).slice(0, 500)}`));
      }
      try {
        const data = JSON.parse(stdout);
        if (data.is_error) {
          return reject(new Error(`claude CLI returned error: ${(data.result || '').slice(0, 300)}`));
        }
        // Normalize usage fields to match the OpenAI/Anthropic shape that
        // llm-reason.js withRetry/onUsage expects.
        const usage = data.usage ? {
          prompt_tokens: data.usage.input_tokens || 0,
          completion_tokens: data.usage.output_tokens || 0,
          cache_creation_tokens: data.usage.cache_creation_input_tokens || 0,
          cache_read_tokens: data.usage.cache_read_input_tokens || 0,
        } : null;
        resolve({
          text: data.result || '',
          usage,
          costUsd: data.total_cost_usd || 0,
          durationMs: data.duration_ms || 0,
          model: Object.keys(data.modelUsage || {})[0] || config.model,
        });
      } catch (err) {
        reject(new Error(`claude CLI output not valid JSON: ${err.message}\n${stdout.slice(0, 500)}`));
      }
    });
  });
}

module.exports = { callClaudeCLI, normalizeModel };
