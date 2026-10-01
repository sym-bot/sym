'use strict';

/**
 * The semantic encoder is loaded once per process (0.13.15). Under load, a second caller asking
 * for it while the first load was still running started a second model load, and parallel loads
 * were what made the full suite report "semantic encoder did not become ready".
 *
 * Run in a child process with the model library replaced by a counting stand-in, so no model is
 * downloaded and the module's load-time call is part of what is counted.
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const ENCODER = path.resolve(__dirname, '..', 'lib', 'core', 'context-encoder.js');

test('one model load however many callers ask while it is loading', () => {
  const out = execFileSync(process.execPath, ['-e', `
    const Module = require('module');
    let loads = 0;
    const stand = { pipeline: () => { loads++; return new Promise((r) => setTimeout(() => r(async () => ({ data: new Float32Array(384) })), 100)); } };
    const real = Module._load;
    Module._load = function (req, ...rest) { return req === '@huggingface/transformers' ? stand : real.call(this, req, ...rest); };
    const enc = require(${JSON.stringify(ENCODER)});
    Promise.all([enc.semanticSettled(), enc.semanticSettled(), enc.semanticSettled()]).then((r) => {
      process.stdout.write(JSON.stringify({ loads, settled: r, ready: enc.isSemanticReady() }));
    });`], { encoding: 'utf8' });
  const r = JSON.parse(out.trim().split('\n').pop());
  assert.equal(r.loads, 1, 'the module load and three callers share one model load');
  assert.deepEqual(r.settled, [true, true, true]);
  assert.equal(r.ready, true);
});
