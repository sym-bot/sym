'use strict';

/**
 * ACCEPTANCE TEST — starts at sym_send, crosses the package seam.
 *
 * THIS TEST IS EXPECTED TO FAIL TODAY. That red is the result, not a defect.
 *
 * Why it exists (CTO ruling 2026-08-10, after two rulings were corrected):
 *
 *   A directed send to a peer that is not connected is REFUSED inside
 *   mesh-channel (server.js, the `matches.length === 0` branch) BEFORE
 *   explicitSend is called. No envelope leaves the package. So a correct,
 *   well-tested delivery spool in sym-daemon sits downstream of a message that
 *   was never sent — and neither package's suite can see it, because
 *   mesh-channel's tests cannot see the daemon and the daemon's tests cannot see
 *   mesh-channel. The refusal lived in the seam between two suites, invisible to
 *   both, and to two people who reasoned about it rather than crossing it.
 *
 *   Measured, not assumed: mesh-channel 0.6.5 has ZERO references to
 *   register-agent, daemon.sock or agent-cmb, and the daemon log carries ZERO
 *   hosted-agent registrations for any seat (claude-sym-dev, claude-sym-cto,
 *   codex-mac) against 109 for the ops agents. Seats are standalone SymNodes, so
 *   a daemon-side spool cannot serve them until they register at all.
 *
 * What must become true for this to go green — either path closes it:
 *   (a) SENDER-SIDE QUEUE (ruled, CTO owns): mesh-channel holds the envelope in
 *       its own durable store for a KNOWN peer and flushes on reappearance.
 *   (b) L2 + daemon spool (open, not this week): seats register as hosted agents
 *       and lib/hosted-spool.js holds it for them.
 *
 * The assertions below describe the DESTINATION, deliberately. They encode the
 * contract the ruling settled — held-at-sender must never be reported as
 * delivered, and must name the peer it is waiting for — so that whichever path
 * lands, this test is what says it actually arrived.
 */

const { test } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

const MESH_CHANNEL = path.join(
  process.env.NVM_BIN ? path.dirname(process.env.NVM_BIN) : '/Users/hongwei/.nvm/versions/node/v22.22.1',
  'lib/node_modules/@sym-bot/mesh-channel/server.js',
);

/** Minimal MCP stdio client — we drive the real tool surface, not a stub. */
function mcpClient(env) {
  const child = spawn(process.execPath, [MESH_CHANNEL], {
    env: { ...process.env, ...env },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  let buf = '';
  const pending = new Map();
  child.stdout.on('data', (d) => {
    buf += d.toString();
    let i;
    while ((i = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, i); buf = buf.slice(i + 1);
      if (!line.trim()) continue;
      try {
        const msg = JSON.parse(line);
        if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
      } catch { /* not JSON-RPC — server chatter */ }
    }
  });
  let id = 0;
  const call = (method, params) => new Promise((resolve, reject) => {
    const rid = ++id;
    const timer = setTimeout(() => reject(new Error(`timeout on ${method}`)), 20000);
    pending.set(rid, (m) => { clearTimeout(timer); resolve(m); });
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: rid, method, params }) + '\n');
  });
  return { child, call, kill: () => { try { child.kill('SIGTERM'); } catch {} } };
}

test('a directed send to a KNOWN-BUT-ABSENT seat is held, never refused into the void', async (t) => {
  if (!fs.existsSync(MESH_CHANNEL)) {
    t.skip(`mesh-channel not installed at ${MESH_CHANNEL}`);
    return;
  }

  // Isolated room and HOME so this never touches the live mesh or a real store.
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'seam-'));
  const c = mcpClient({
    HOME: home,
    SYM_ROOM: `seam-test-${Date.now()}`,
    SYM_NODE_NAME: 'seam-sender',
    CLAUDE_PROJECT_DIR: home,
  });

  try {
    await c.call('initialize', {
      protocolVersion: '2024-11-05', capabilities: {},
      clientInfo: { name: 'seam-acceptance', version: '1' },
    });

    const res = await c.call('tools/call', {
      name: 'sym_send',
      arguments: {
        to: 'codex-mac',                       // a real seat name, deliberately absent here
        focus: 'the reply that was refused at 09:10:51 — held, not lost',
        issue: 'none',
        intent: 'acceptance: the seam between mesh-channel and the daemon',
      },
    });

    const text = (res.result?.content ?? res.error?.content ?? [])
      .map((c2) => c2.text || '').join(' ');

    // ── THE CONTRACT, as ruled ────────────────────────────────────────────
    // 1. It must not be refused into the void. Today this line FAILS with
    //    "Peer \"codex-mac\" not connected." — that failure is the point.
    assert.ok(
      !/not connected/i.test(text),
      `directed send was REFUSED at the sender, so no envelope crossed the seam — got: ${text}`,
    );

    // 2. Held must be visibly held, and must name who it waits for. A queue at
    //    the sender is INVISIBLE TO THE RECEIVER: nobody but the sender knows the
    //    message exists, so the tool output is the only place that fact can live.
    assert.match(text, /held|queued|pending/i, 'the response must say the envelope is held');
    assert.match(text, /codex-mac/, 'and must name the peer it is waiting for');

    // 3. Held is NOT delivered. This is the same invariant as `dispatched` vs
    //    `delivered` in lib/node.js: socket.write is dispatch, and a queue is not
    //    even dispatch. Reporting queued as sent is the original defect wearing
    //    a new coat.
    assert.ok(
      !/^Sent CMB/.test(text.trim()),
      'a held envelope must never be reported as sent',
    );
  } finally {
    c.kill();
    fs.rmSync(home, { recursive: true, force: true });
  }
});
