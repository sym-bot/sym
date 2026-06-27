'use strict';

// `sym ask` — ask the whole mesh one question, get one answer.
//
// These tests run the CLI offline: no daemon, no LLM provider (env cleared),
// so they exercise the gather + raw-contribution fallback path deterministically
// and NEVER call a paid API. The synthesis path itself is provider-gated and
// covered by the llm-reason unit check below (NO_PROVIDER without a key).

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const CLI = path.join(__dirname, '..', 'bin', 'sym.js');

// Run `sym ask` with a throwaway mesh home and no LLM provider configured.
function runAsk(homeDir, argv) {
  const env = { ...process.env, HOME: homeDir };
  // Force the no-provider path so the test is hermetic and free.
  for (const k of ['OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'SYM_LLM_API_KEY', 'SYM_LLM_PROVIDER', 'CLAUDE_AGENT_MODEL']) {
    delete env[k];
  }
  try {
    return { code: 0, out: execFileSync('node', [CLI, 'ask', ...argv], { env, encoding: 'utf8' }) };
  } catch (err) {
    return { code: err.status ?? 1, out: (err.stdout || '') + (err.stderr || '') };
  }
}

function seedMemory(homeDir, nodeName, key, entry) {
  const dir = path.join(homeDir, '.sym', 'nodes', nodeName, 'cmbs');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `cmb-${key}.json`), JSON.stringify(entry));
}

function tmpHome() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'sym-ask-'));
}

describe('sym ask', () => {
  it('requires a question', () => {
    const home = tmpHome();
    const { code, out } = runAsk(home, []);
    assert.strictEqual(code, 1);
    assert.match(out, /Usage: sym ask/);
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('reports an empty mesh gracefully', () => {
    const home = tmpHome();
    const { code, out } = runAsk(home, ['anything at all?']);
    assert.strictEqual(code, 0);
    assert.match(out, /nothing relevant yet/i);
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('gathers relevant contributions and cites their source agents (no-provider path)', () => {
    const home = tmpHome();
    seedMemory(home, 'inventory-agent', 'a', { content: 'blue variant restock confirmed, arriving Thursday', source: 'inventory-agent', storedAt: 1 });
    seedMemory(home, 'analytics-agent', 'b', { content: 'blue variant page views up 300% this week', source: 'analytics-agent', storedAt: 2 });
    seedMemory(home, 'fitness-agent', 'c', { content: 'user walked 4000 steps today', source: 'fitness-agent', storedAt: 3 });

    const { code, out } = runAsk(home, ['when is the blue variant back in stock?']);
    assert.strictEqual(code, 0);
    // The two relevant agents are surfaced and attributed...
    assert.match(out, /\[inventory-agent\] blue variant restock confirmed/);
    assert.match(out, /\[analytics-agent\]/);
    // ...and the no-provider hint tells the user how to get a synthesized answer.
    assert.match(out, /No LLM provider configured/);
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('ranks the more relevant contribution first', () => {
    const home = tmpHome();
    // "restock" contains "stock" → matches blue+variant+stock (3); analytics matches blue+variant (2).
    seedMemory(home, 'analytics-agent', 'b', { content: 'blue variant page views up 300%', source: 'analytics-agent', storedAt: 9 });
    seedMemory(home, 'inventory-agent', 'a', { content: 'blue variant restock arriving Thursday', source: 'inventory-agent', storedAt: 1 });

    const { out } = runAsk(home, ['blue variant stock?']);
    assert.ok(out.indexOf('inventory-agent') < out.indexOf('analytics-agent'),
      'inventory-agent (higher keyword overlap) should rank before analytics-agent');
    fs.rmSync(home, { recursive: true, force: true });
  });
});

describe('llm-reason synthesis exports', () => {
  const llm = require('../lib/llm-reason');

  it('exposes complete + hasProvider', () => {
    assert.strictEqual(typeof llm.complete, 'function');
    assert.strictEqual(typeof llm.hasProvider, 'function');
  });

  it('complete() throws NO_PROVIDER when no key/CLI provider is configured', async () => {
    const saved = {};
    for (const k of ['OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'SYM_LLM_API_KEY', 'SYM_LLM_PROVIDER']) {
      saved[k] = process.env[k]; delete process.env[k];
    }
    try {
      await assert.rejects(
        () => llm.complete({ provider: 'openai', apiKey: '', prompt: 'hi' }),
        (err) => err.code === 'NO_PROVIDER'
      );
      assert.strictEqual(llm.hasProvider({ provider: 'openai', apiKey: '' }), false);
      assert.strictEqual(llm.hasProvider({ provider: 'cli' }), true);
    } finally {
      for (const k of Object.keys(saved)) if (saved[k] !== undefined) process.env[k] = saved[k];
    }
  });
});
