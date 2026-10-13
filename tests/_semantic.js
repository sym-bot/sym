'use strict';

/**
 * Wait for the semantic encoder (the kernel the §9.2.1 reject floor is calibrated on). It awaits the
 * encoder's own load instead of polling against a fixed timeout: the full suite loads the model in
 * several test processes at once, and a guessed 30 s ran out under that contention. The test's own
 * timeout is the only bound.
 */
const { semanticSettled } = require('../lib/core/context-encoder');

async function awaitSemantic() {
  if (!(await semanticSettled())) throw new Error('the semantic encoder failed to load (see the [encoder] line above)');
}

module.exports = { awaitSemantic };
