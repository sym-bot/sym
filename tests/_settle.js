'use strict';

/**
 * Wait for inbound CMB frames to finish processing instead of guessing how long that takes.
 *
 * node._frameHandler.handle() returns before a cmb frame is processed: admission is asynchronous
 * (the injected evaluator, then the §15.8 tether evaluation, which encodes the stored record and
 * its root), and the store write and every surface happen at the end of that chain. A fixed sleep
 * is a guess at its duration, and the guess fails whenever the machine is slower than it, which is
 * how these tests started failing under load once the neural path began evaluating the tether.
 *
 * Every processing chain the frame handler starts is recorded here, and settle(ms) waits at least
 * `ms` (what the fixed sleep used to give, for anything that is not a frame) and then until every
 * recorded chain has settled. Require it after ./_isolate-home, like any module that loads lib/.
 */

const { FrameHandler } = require('../lib/frame-handler');

const inFlight = new Set();
const handleMemoryShare = FrameHandler.prototype._handleMemoryShare;
FrameHandler.prototype._handleMemoryShare = function tracked(...args) {
  const chain = handleMemoryShare.apply(this, args);
  if (chain && typeof chain.then === 'function') {
    inFlight.add(chain);
    const done = () => inFlight.delete(chain);
    chain.then(done, done);
  }
  return chain;
};

async function settle(ms = 150) {
  await new Promise((r) => setTimeout(r, ms));
  while (inFlight.size) await Promise.allSettled([...inFlight]);
}

module.exports = { settle };
