'use strict';

/**
 * B-D6 (residual): a frame handed to a socket that is destroyed, or no longer writable, was counted
 * as sent until 'close' fired, so a send in that window reported delivery.dispatched for nothing.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const net = require('node:net');
const { sendFrame } = require('../lib/frame-parser');

describe('sendFrame', () => {
  it('refuses a destroyed socket, a non-writable one, and none at all', () => {
    const destroyed = new net.Socket();
    destroyed.destroy();
    assert.strictEqual(sendFrame(destroyed, { type: 'cmb' }), false);
    const ended = { destroyed: false, writable: false, write: () => true };
    assert.strictEqual(sendFrame(ended, { type: 'cmb' }), false);
    assert.strictEqual(sendFrame(null, { type: 'cmb' }), false);
  });

  it('still sends on a writable socket', () => {
    const writes = [];
    const live = { destroyed: false, writable: true, write: (b) => { writes.push(b); return true; } };
    assert.strictEqual(sendFrame(live, { type: 'cmb', n: 1 }), true);
    assert.strictEqual(writes.length, 1);
  });
});
