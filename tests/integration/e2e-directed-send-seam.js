/**
 * ACCEPTANCE TEST — starts at sym_send and crosses the package seam.
 *
 * STATUS: GREEN as of mesh-channel 0.7.1. It was RED by design before that, and
 * the history is the point.
 *
 * Why it exists (CTO ruling 2026-08-10, after two rulings were corrected):
 *
 *   A directed send to an absent peer was REFUSED inside mesh-channel, in the
 *   `matches.length === 0` branch, BEFORE explicitSend was called. No envelope
 *   left the package, so a correct daemon-side spool sat downstream of a message
 *   that was never sent. Neither suite could see it: mesh-channel's tests cannot
 *   see the daemon, the daemon's tests cannot see mesh-channel. The defect lived
 *   in the seam between two suites, invisible to both and to two people who
 *   reasoned about it rather than crossing it. Every test either seat had began
 *   BELOW the layer that refused. This one starts above it and drives the real
 *   MCP tool surface over stdio, against the INSTALLED artifact rather than a
 *   working tree.
 *
 * A CORRECTION THIS TEST MADE TO ITSELF, kept because it is the more useful half:
 *   Against 0.7.1 it still failed — and the implementation was right, the test was
 *   wrong. It asserted "KNOWN-but-absent" while its fixture established neither:
 *   an isolated HOME and a fresh room mean the node has never observed the peer,
 *   so 0.7.1 correctly refused it as an UNKNOWN name rather than holding it. The
 *   fixture now seeds known-peers.json — the system's own record of having
 *   observed a peer — and the unknown case became its own test rather than a
 *   silent assumption. A red test is only evidence if its preconditions are real.
 *
 * NOT COVERED, stated rather than implied: earning the roster entry through a
 * genuine observe-then-disconnect, and the FLUSH when the peer reappears. Both
 * need two live nodes and a reconnection. They are the next case, deliberately
 * not smuggled in as a slow flaky one that gets skipped.
 *
 * Still open elsewhere: seats are standalone SymNodes with ZERO hosted-agent
 * registrations against 109 for the ops agents, so the daemon spool at
 * lib/hosted-spool.js cannot serve seats until L2 lands and they register at all.
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

/** Seed the roster the production code reads. `known-peers.json` IS the system's
 *  own record of "this node has observed that peer", written by outbox.rememberPeer
 *  when a peer is actually seen. Writing it constructs the documented precondition
 *  rather than bypassing a check — the send below still runs the real refusal
 *  branch, the real isKnownPeer gate and the real outbox.hold.
 *
 *  What this does NOT cover, stated rather than implied: earning that roster entry
 *  through a genuine observe-then-disconnect, and the FLUSH on reappearance. Both
 *  need two live nodes and a reconnection; they are the next case, deliberately not
 *  smuggled in as a slow flaky one that gets skipped. */
function seedKnownPeer(home, nodeName, peerName) {
  const dir = path.join(home, '.sym', 'nodes', nodeName);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'known-peers.json'),
    JSON.stringify({ [peerName]: { peerId: null, lastSeen: null } }, null, 2));
}

async function sendTo(home, to, { known = false } = {}) {
  const nodeName = 'seam-sender';
  if (known) seedKnownPeer(home, nodeName, to);
  const c = mcpClient({
    HOME: home,
    SYM_ROOM: `seam-test-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    SYM_NODE_NAME: nodeName,
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
        to,
        focus: 'the reply that was refused at 09:10:51 — held, not lost',
        issue: 'none',
        intent: 'acceptance: the seam between mesh-channel and the daemon',
      },
    });
    return (res.result?.content ?? res.error?.content ?? []).map((x) => x.text || '').join(' ');
  } finally { c.kill(); }
}

test('a directed send to a KNOWN-BUT-ABSENT seat is HELD, never refused into the void', async (t) => {
  if (!fs.existsSync(MESH_CHANNEL)) { t.skip(`mesh-channel not installed at ${MESH_CHANNEL}`); return; }
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'seam-known-'));
  try {
    const text = await sendTo(home, 'codex-mac', { known: true });

    // 1. Not refused into the void — the envelope must not evaporate at the sender.
    assert.ok(!/not connected\. Call sym_peers/.test(text),
      `directed send was REFUSED at the sender, so nothing crossed the seam — got: ${text}`);

    // 2. Held must be visibly held and must NAME who it waits for. A sender-side
    //    queue is invisible to the receiver, so this text is the only place that
    //    fact can live.
    assert.match(text, /held|queued|waiting/i, 'the response must say the envelope is held');
    assert.match(text, /codex-mac/, 'and must name the peer it is waiting for');

    // 3. Held is NOT delivered. Same invariant as dispatched-vs-delivered one layer
    //    down: socket.write is dispatch, and a queue is not even dispatch.
    assert.ok(!/^Sent CMB/.test(text.trim()), 'a held envelope must never be reported as sent');
    assert.match(text, /not deliver|is not delivery/i,
      'and must say so in words the operator reads, not only by omission');
  } finally { fs.rmSync(home, { recursive: true, force: true }); }
});

test('a directed send to an UNKNOWN name is refused and queues NOTHING', async (t) => {
  if (!fs.existsSync(MESH_CHANNEL)) { t.skip(`mesh-channel not installed at ${MESH_CHANNEL}`); return; }
  // Gate 4: a typo must not create state. This is the case that made my first
  // version of this test fail against a CORRECT implementation — I asserted
  // "known but absent" while my fixture established neither.
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'seam-unknown-'));
  try {
    const text = await sendTo(home, 'peer-that-never-existed', { known: false });
    assert.match(text, /never seen|not connected/i, 'an unknown name is refused');
    assert.match(text, /nothing was queued|cannot create a queue/i,
      'and the refusal must say that nothing was queued');
    const outbox = path.join(home, '.sym', 'nodes', 'seam-sender', 'outbox.json');
    if (fs.existsSync(outbox)) {
      const o = JSON.parse(fs.readFileSync(outbox, 'utf8'));
      assert.strictEqual((o.items || []).length, 0, 'a typo must leave the outbox empty');
    }
  } finally { fs.rmSync(home, { recursive: true, force: true }); }
});
