'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { extractCAT7, isValidCAT7 } = require('../lib/llm-reason');

// ── Fixtures ────────────────────────────────────────────────────

const VALID_CAT7 = {
  focus: 'debugging auth module',
  issue: 'exhausted after 3 hours',
  intent: 'needs a break',
  motivation: 'prevent fatigue-driven bugs',
  commitment: 'coding session with Claude',
  perspective: 'developer, afternoon',
  mood: { text: 'frustrated', valence: -0.6, arousal: -0.4 },
};

const ENVELOPE_CLEAN = JSON.stringify({
  type: 'result',
  result: JSON.stringify(VALID_CAT7),
  session_id: 'abc-123',
  cost_usd: 0.003,
});

const ENVELOPE_CODE_FENCE = JSON.stringify({
  type: 'result',
  result: '```json\n' + JSON.stringify(VALID_CAT7, null, 2) + '\n```',
  session_id: 'abc-123',
  cost_usd: 0.003,
});

const ENVELOPE_PROSE = JSON.stringify({
  type: 'result',
  result: 'Here is the analysis:\n\n' + JSON.stringify(VALID_CAT7) + '\n\nThis reflects the current state.',
  session_id: 'abc-123',
  cost_usd: 0.003,
});

const ENVELOPE_OBJECT_RESULT = JSON.stringify({
  type: 'result',
  result: VALID_CAT7,
  session_id: 'abc-123',
  cost_usd: 0.003,
});

// ── isValidCAT7 ─────────────────────────────────────────────────

describe('isValidCAT7', () => {
  it('accepts a complete CAT7 object', () => {
    assert.strictEqual(isValidCAT7(VALID_CAT7), true);
  });

  it('rejects null', () => {
    assert.strictEqual(isValidCAT7(null), false);
  });

  it('rejects missing field', () => {
    const { focus, ...rest } = VALID_CAT7;
    assert.strictEqual(isValidCAT7(rest), false);
  });

  it('rejects mood without valence', () => {
    assert.strictEqual(isValidCAT7({ ...VALID_CAT7, mood: { text: 'ok', arousal: 0 } }), false);
  });

  it('rejects mood as string', () => {
    assert.strictEqual(isValidCAT7({ ...VALID_CAT7, mood: 'happy' }), false);
  });

  it('rejects a plain string', () => {
    assert.strictEqual(isValidCAT7('focus'), false);
  });
});

// ── extractCAT7 ─────────────────────────────────────────────────

describe('extractCAT7', () => {
  it('parses direct CAT7 JSON', () => {
    assert.deepStrictEqual(extractCAT7(JSON.stringify(VALID_CAT7)), VALID_CAT7);
  });

  it('unwraps clean envelope', () => {
    assert.deepStrictEqual(extractCAT7(ENVELOPE_CLEAN), VALID_CAT7);
  });

  it('unwraps envelope with code fences', () => {
    assert.deepStrictEqual(extractCAT7(ENVELOPE_CODE_FENCE), VALID_CAT7);
  });

  it('unwraps envelope with prose around JSON', () => {
    assert.deepStrictEqual(extractCAT7(ENVELOPE_PROSE), VALID_CAT7);
  });

  it('handles result as object', () => {
    assert.deepStrictEqual(extractCAT7(ENVELOPE_OBJECT_RESULT), VALID_CAT7);
  });

  it('handles trailing text after envelope', () => {
    assert.deepStrictEqual(extractCAT7(ENVELOPE_CLEAN + '\nSome log output'), VALID_CAT7);
  });

  it('handles leading text before envelope', () => {
    assert.deepStrictEqual(extractCAT7('Starting CLI...\n' + ENVELOPE_CLEAN), VALID_CAT7);
  });

  it('finds CAT7 after junk braces in raw output', () => {
    const raw = 'junk {broken ' + JSON.stringify(VALID_CAT7) + ' more junk';
    assert.deepStrictEqual(extractCAT7(raw), VALID_CAT7);
  });

  it('returns null for empty input', () => {
    assert.strictEqual(extractCAT7(''), null);
    assert.strictEqual(extractCAT7(null), null);
  });

  it('returns null for non-JSON garbage', () => {
    assert.strictEqual(extractCAT7('Error: something went wrong'), null);
  });

  it('returns null for JSON without CAT7 fields', () => {
    assert.strictEqual(extractCAT7(JSON.stringify({ type: 'result', result: '{"foo":"bar"}' })), null);
  });

  it('returns null for envelope with empty result', () => {
    assert.strictEqual(extractCAT7(JSON.stringify({ type: 'result', result: '' })), null);
  });

  it('handles code fence with language tag in prose', () => {
    const raw = JSON.stringify({
      type: 'result',
      result: 'Here:\n\n```json\n' + JSON.stringify(VALID_CAT7) + '\n```\n\nDone.',
    });
    assert.deepStrictEqual(extractCAT7(raw), VALID_CAT7);
  });
});
