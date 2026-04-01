'use strict';

/**
 * Claude CLI reasoning — replaces OpenAI role-reason.js.
 *
 * Each agent invokes Claude CLI with its role prompt as system prompt
 * and the domain data / incoming signal as the user prompt.
 * Claude CLI has full tool access: file editing, web search, skills.
 *
 * Session continuity via --resume: each agent maintains a named session
 * so Claude retains context across invocations.
 *
 * Copyright (c) 2026 SYM.BOT Ltd. Apache 2.0 License.
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const CAT7_SCHEMA = JSON.stringify({
  type: 'object',
  properties: {
    focus:       { type: 'string' },
    issue:       { type: 'string' },
    intent:      { type: 'string' },
    motivation:  { type: 'string' },
    commitment:  { type: 'string' },
    perspective: { type: 'string' },
    mood:        { type: 'object', properties: {
      text: { type: 'string' },
      valence: { type: 'number' },
      arousal: { type: 'number' },
    }, required: ['text', 'valence', 'arousal'] },
  },
  required: ['focus', 'issue', 'intent', 'motivation', 'commitment', 'perspective', 'mood'],
});

/**
 * Load the agent's role prompt from SKILL.md or config/role-prompt.md.
 */
function loadRolePrompt(agentDir) {
  // Agent Skills standard: .agents/skills/<name>/SKILL.md
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

/**
 * Invoke Claude CLI to reason on domain data or remix a signal.
 *
 * @param {object} opts
 * @param {string} opts.agentDir — agent root directory
 * @param {string} opts.agentName — agent name (for session naming)
 * @param {string} opts.prompt — the user prompt (domain data or remix instruction)
 * @param {string} [opts.model] — model override (default: sonnet for cost efficiency)
 * @param {number} [opts.maxBudget] — max USD per call (default: 0.05)
 * @param {string[]} [opts.addDirs] — additional directories to give Claude access to
 * @returns {object|null} CAT7 fields or null on failure
 */
function claudeReason(opts) {
  const rolePrompt = loadRolePrompt(opts.agentDir);
  const model = opts.model || process.env.CLAUDE_AGENT_MODEL || 'sonnet';
  const maxBudget = opts.maxBudget || 0.05;

  const args = [
    'claude',
    '-p',
    '--output-format', 'json',
    '--json-schema', CAT7_SCHEMA,
    '--model', model,
    '--max-budget-usd', String(maxBudget),
    '--system-prompt', rolePrompt,
    '--permission-mode', 'auto',
    '--no-session-persistence',
  ];

  if (opts.addDirs) {
    for (const dir of opts.addDirs) {
      args.push('--add-dir', dir);
    }
  }

  try {
    const result = execSync(
      args.map(a => `'${a.replace(/'/g, "'\\''")}'`).join(' ') +
      ` <<'PROMPT_EOF'\n${opts.prompt}\nPROMPT_EOF`,
      {
        encoding: 'utf8',
        timeout: 120000, // 2 min max
        maxBuffer: 10 * 1024 * 1024,
        cwd: opts.agentDir,
        shell: '/bin/bash',
      }
    ).trim();

    // Parse JSON response
    const parsed = JSON.parse(result);
    // Claude --output-format json wraps in { result: "..." }
    const content = parsed.result || parsed;
    if (typeof content === 'string') {
      // Try parsing the result string as JSON
      const cleaned = content.replace(/```json?\n?/g, '').replace(/```/g, '').trim();
      return JSON.parse(cleaned);
    }
    return content;
  } catch (err) {
    console.error(`[claude-reason] failed: ${err.message?.slice(0, 200)}`);
    return null;
  }
}

/**
 * Reason on domain data — produce a CMB from the agent's perspective.
 */
function reason(agentDir, agentName, domainData, meshContext) {
  const meshBlock = meshContext && meshContext.length > 0
    ? `\n\nMesh signals from other agents:\n${meshContext.map(s => `- [${s.source}] ${s.focus}`).join('\n')}`
    : '';

  return claudeReason({
    agentDir,
    agentName,
    prompt: `Here is the latest data from your domain:\n\n${domainData}${meshBlock}\n\nReason on this data with your professional expertise. Produce a single CMB with 7 CAT7 fields as JSON.`,
  });
}

/**
 * Remix an incoming signal — produce a new CMB from the agent's perspective.
 */
function remix(agentDir, agentName, incoming, meshContext) {
  const signal = Object.entries(incoming.fields)
    .map(([k, v]) => `  ${k}: ${v}`)
    .join('\n');

  const meshBlock = meshContext && meshContext.length > 0
    ? `\nBroader mesh context:\n${meshContext.map(s => `- [${s.source}] ${s.focus}`).join('\n')}`
    : '';

  return claudeReason({
    agentDir,
    agentName,
    prompt: `An incoming signal was accepted by SVAF and needs your remix.\n\nFROM: ${incoming.source}\nSIGNAL:\n${signal}${meshBlock}\n\nREMIX this signal through YOUR domain expertise. Create NEW knowledge from the intersection. Produce a CMB with 7 CAT7 fields as JSON.`,
  });
}

module.exports = { claudeReason, reason, remix, loadRolePrompt };
