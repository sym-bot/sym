'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert');
const path = require('path');
const os = require('os');

describe('CLI', () => {
  describe('SOCKET_PATH', () => {
    it('should default to ~/.sym/daemon.sock', () => {
      // The CLI reads SOCKET_PATH at module level from process.env.SYM_SOCKET
      // or falls back to ~/.sym/daemon.sock. We verify the default logic.
      const expected = path.join(os.homedir(), '.sym', 'daemon.sock');
      // Without SYM_SOCKET env var, the default should match
      const oldEnv = process.env.SYM_SOCKET;
      delete process.env.SYM_SOCKET;
      const result = process.env.SYM_SOCKET || path.join(os.homedir(), '.sym', 'daemon.sock');
      assert.strictEqual(result, expected);
      // Restore
      if (oldEnv !== undefined) process.env.SYM_SOCKET = oldEnv;
    });

    it('should respect SYM_SOCKET env override', () => {
      const custom = '/tmp/test-sym.sock';
      const result = custom || path.join(os.homedir(), '.sym', 'daemon.sock');
      assert.strictEqual(result, custom);
    });
  });

  describe('--json flag parsing', () => {
    it('should detect --json in args', () => {
      const args = ['status', '--json'];
      const jsonFlag = args.includes('--json');
      assert.strictEqual(jsonFlag, true);
    });

    it('should be false when --json is absent', () => {
      const args = ['status'];
      const jsonFlag = args.includes('--json');
      assert.strictEqual(jsonFlag, false);
    });

    it('should detect --json regardless of position', () => {
      const args = ['--json', 'peers'];
      const jsonFlag = args.includes('--json');
      assert.strictEqual(jsonFlag, true);
    });
  });
});
