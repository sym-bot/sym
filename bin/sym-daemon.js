#!/usr/bin/env node
'use strict';

// ── EPIPE/EIO Safety (must be first — OpenClaw issue #4632) ────
// launchd may close stdout/stderr pipes during restart. Without this,
// Node.js throws uncaught EPIPE and enters a crash loop with exponential
// throttle, causing hours-long outages.
function suppressEpipe(stream) {
  stream.on('error', (err) => {
    if (err.code === 'EPIPE' || err.code === 'EIO') process.exit(0);
    throw err;
  });
}
suppressEpipe(process.stdout);
suppressEpipe(process.stderr);

/**
 * sym-daemon — persistent physical mesh node for macOS/Linux.
 *
 * Runs as a background service (launchd LaunchAgent on macOS, systemd on Linux).
 * Maintains relay connection, Bonjour discovery, peer state, and wake channels
 * independently of any application. Virtual nodes (Claude Code, MeloTune Mac, etc.)
 * connect via Unix socket IPC.
 *
 * MMP v0.2.0: The daemon IS the device's mesh presence.
 *
 * Usage:
 *   sym-daemon                    # Run in foreground
 *   sym-daemon --install          # Install as launchd LaunchAgent (macOS)
 *   sym-daemon --uninstall        # Remove LaunchAgent
 *   sym-daemon --status           # Show daemon status
 *
 * Copyright (c) 2026 SYM.BOT Ltd. Apache 2.0 License.
 */

const net = require('net');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { SymNode } = require('../lib/node');
const { XMesh } = require('@sym-bot/core');

// ── Configuration ──────────────────────────────────────────────

const SOCKET_PATH = process.env.SYM_SOCKET || '/tmp/sym.sock';
// Stable name: use SYM_NODE_NAME env, or 'sym-daemon' (not hostname — macOS
// appends random suffixes to hostname on WiFi, causing new identity each restart)
const NODE_NAME = process.env.SYM_NODE_NAME || 'sym-daemon';
const LOG_DIR = path.join(os.homedir(), 'Library', 'Logs', 'sym-daemon');

// Load relay config from ~/.sym/relay.env if env vars not set
if (!process.env.SYM_RELAY_URL) {
  const envFile = path.join(os.homedir(), '.sym', 'relay.env');
  if (fs.existsSync(envFile)) {
    for (const line of fs.readFileSync(envFile, 'utf8').split('\n')) {
      const m = line.match(/^(\w+)=(.*)$/);
      if (m && !process.env[m[1]]) process.env[m[1]] = m[2].trim();
    }
  }
}

const relayUrl = process.env.SYM_RELAY_URL || null;
const relayToken = process.env.SYM_RELAY_TOKEN || null;

// ── CLI Commands ───────────────────────────────────────────────

const args = process.argv.slice(2);

if (args.includes('--install')) {
  installLaunchAgent();
  process.exit(0);
}

if (args.includes('--uninstall')) {
  uninstallLaunchAgent();
  process.exit(0);
}

if (args.includes('--status')) {
  showStatus();
  process.exit(0);
}

// ── SYM Node ───────────────────────────────────────────────────

const node = new SymNode({
  name: NODE_NAME,
  cognitiveProfile: `Physical mesh node for ${os.hostname()}. Routes frames between virtual nodes and the mesh.`,
  svafFreshnessSeconds: 7200,  // 2 hours — current coding session context
  relay: relayUrl,
  relayToken: relayToken,
  silent: false,
});

// ── xMesh Intelligence Layer ──────────────────────────────────

const xmesh = new XMesh({
  log,
  onInsight: (insight) => {
    // Share this agent's cognitive state with mesh peers via xmesh-insight frame
    // Each peer processes it through their own LNN as an inbound CMB flow
    node.broadcastInsight(insight);
    log(`xMesh: insight broadcast to mesh`);
  },
});

// ── IPC Server (Unix Socket) ───────────────────────────────────

/** Connected virtual nodes. socketId → { socket, name, cognitiveProfile } */
const virtualNodes = new Map();
let nextSocketId = 1;

function startIPCServer() {
  // Clean up stale socket
  if (fs.existsSync(SOCKET_PATH)) {
    try { fs.unlinkSync(SOCKET_PATH); } catch {}
  }

  const server = net.createServer((socket) => {
    const socketId = nextSocketId++;
    let buffer = '';

    socket.on('data', (data) => {
      buffer += data.toString();
      let idx;
      while ((idx = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 1);
        if (line.trim()) {
          try {
            handleIPCMessage(socketId, socket, JSON.parse(line));
          } catch (err) {
            log(`IPC parse error: ${err.message}`);
          }
        }
      }
    });

    socket.on('close', () => {
      const vn = virtualNodes.get(socketId);
      if (vn) {
        log(`Virtual node disconnected: ${vn.name}`);
        virtualNodes.delete(socketId);
      }
    });

    socket.on('error', (err) => {
      if (err.code !== 'EPIPE' && err.code !== 'ECONNRESET') {
        log(`IPC socket error: ${err.message}`);
      }
      virtualNodes.delete(socketId);
    });
  });

  server.listen(SOCKET_PATH, () => {
    fs.chmodSync(SOCKET_PATH, 0o700);
    log(`IPC server listening: ${SOCKET_PATH}`);
  });

  server.on('error', (err) => {
    log(`IPC server error: ${err.message}`);
    process.exit(1);
  });

  return server;
}

function handleIPCMessage(socketId, socket, msg) {
  switch (msg.type) {
    case 'register': {
      virtualNodes.set(socketId, {
        socket,
        name: msg.name || `virtual-${socketId}`,
        cognitiveProfile: msg.cognitiveProfile || null,
      });
      sendIPC(socket, {
        type: 'registered',
        nodeId: node._identity?.nodeId,
        name: node.name,
        relay: relayUrl,
      });
      log(`Virtual node registered: ${msg.name}`);
      break;
    }

    case 'mood':
      if (msg.mood) {
        node.broadcastMood(msg.mood, { context: msg.context });
        sendIPC(socket, { type: 'result', action: 'mood', peers: node.peers().length });
        // Feed virtual node moods into xMesh
        const vnMood = virtualNodes.get(socketId);
        xmesh.ingestSignal({
          type: 'mood',
          from: vnMood?.name || 'virtual-node',
          content: msg.mood,
        });
      }
      break;

    case 'message':
      if (msg.content) {
        node.send(msg.content, msg.to ? { to: msg.to } : {});
        sendIPC(socket, { type: 'result', action: 'message', peers: node.peers().length });
      }
      break;

    case 'remember':
      if (msg.content) {
        const entry = node.remember(msg.content, { tags: msg.tags });
        if (entry) {
          sendIPC(socket, { type: 'result', action: 'remember', key: entry.key });
          // Feed virtual node memories into xMesh
          const vn = virtualNodes.get(socketId);
          xmesh.ingestSignal({
            type: 'memory',
            from: vn?.name || 'virtual-node',
            content: msg.content,
          });
        } else {
          sendIPC(socket, { type: 'result', action: 'remember', duplicate: true });
        }
      }
      break;

    case 'recall': {
      const results = node.recall(msg.query || '');
      sendIPC(socket, { type: 'result', action: 'recall', results });
      break;
    }

    case 'send':
      if (msg.message) {
        node.send(msg.message);
        sendIPC(socket, { type: 'result', action: 'send', peers: node.peers().length });
      }
      break;

    case 'peers':
      sendIPC(socket, { type: 'result', action: 'peers', peers: node.peers() });
      break;

    case 'status':
      sendIPC(socket, {
        type: 'result',
        action: 'status',
        status: node.status(),
        virtualNodes: Array.from(virtualNodes.values()).map(v => v.name),
      });
      break;

    case 'xmesh-context':
      sendIPC(socket, {
        type: 'result',
        action: 'xmesh-context',
        context: xmesh.getContext({ timeWindow: msg.timeWindow }),
      });
      break;

    case 'xmesh-search':
      sendIPC(socket, {
        type: 'result',
        action: 'xmesh-search',
        insights: xmesh.searchInsights(msg.query),
      });
      break;

    default:
      log(`Unknown IPC message type: ${msg.type}`);
  }
}

function sendIPC(socket, msg) {
  try { socket.write(JSON.stringify(msg) + '\n'); } catch {}
}

/** Forward mesh events to all registered virtual nodes. */
function forwardEventsToVirtualNodes() {
  const events = [
    ['mood-accepted', (d) => ({ type: 'event', event: 'mood-accepted', data: d })],
    ['mood-rejected', (d) => ({ type: 'event', event: 'mood-rejected', data: d })],
    ['peer-joined', (d) => ({ type: 'event', event: 'peer-joined', data: d })],
    ['peer-left', (d) => ({ type: 'event', event: 'peer-left', data: d })],
    ['coupling-decision', (d) => ({ type: 'event', event: 'coupling-decision', data: d })],
  ];

  for (const [event, formatter] of events) {
    node.on(event, (data) => broadcastToVirtualNodes(formatter(data)));
  }

  node.on('message', (from, content) => {
    broadcastToVirtualNodes({ type: 'event', event: 'message', data: { from, content } });

    // Feed messages (including Telegram) into xMesh
    xmesh.ingestSignal({ type: 'message', from, content });

    // Wake sleeping peers that might need this message.
    // The daemon acts as wake proxy — it has APNs keys and gossiped wake channels.
    // When a remote peer (Telegram bot) sends a message, and a local peer (MeloTune)
    // is sleeping, the daemon wakes it so the relay can deliver the message.
    node._wakeSleepingPeers('message', {
      type: 'message', from: node._identity.nodeId, fromName: node.name,
      content, timestamp: Date.now(),
    });
  });

  node.on('mood-accepted', (data) => {
    // Feed into xMesh intelligence layer
    xmesh.ingestSignal({
      type: 'mood',
      from: data.from || data.fromName || 'unknown',
      content: data.mood,
      drift: data.drift,
    });

    // Also wake on mood — daemon may receive mood from a remote peer
    // that a sleeping local peer should hear
    node._wakeSleepingPeers('mood', {
      type: 'mood', from: node._identity.nodeId, fromName: node.name,
      mood: data.mood, timestamp: Date.now(),
    });
  });

  node.on('xmesh-insight', (data) => {
    broadcastToVirtualNodes({ type: 'event', event: 'xmesh-insight', data });
  });

  node.on('memory-received', ({ from, entry, decision }) => {
    // Feed into xMesh intelligence layer
    xmesh.ingestSignal({
      type: 'memory',
      from: from,
      content: entry.content,
      decision: decision,
    });

    broadcastToVirtualNodes({ type: 'event', event: 'memory-received', data: { from, content: entry.content, decision } });
  });
}

function broadcastToVirtualNodes(msg) {
  const data = JSON.stringify(msg) + '\n';
  for (const [id, vn] of virtualNodes) {
    try { vn.socket.write(data); } catch { virtualNodes.delete(id); }
  }
}

// ── launchd Install/Uninstall ──────────────────────────────────

function launchAgentPlist() {
  // Resolve node binary — prefer stable symlink over Cellar path
  const nodePath = fs.existsSync('/opt/homebrew/bin/node')
    ? '/opt/homebrew/bin/node'
    : fs.existsSync('/usr/local/bin/node')
      ? '/usr/local/bin/node'
      : process.execPath;

  const scriptPath = path.resolve(__dirname, 'sym-daemon.js');
  const symDir = path.resolve(__dirname, '..');

  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>bot.sym.daemon</string>
  <key>ProgramArguments</key>
  <array>
    <string>${nodePath}</string>
    <string>${scriptPath}</string>
  </array>
  <key>WorkingDirectory</key>
  <string>${symDir}</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
    <key>HOME</key>
    <string>${os.homedir()}</string>
    <key>NODE_ENV</key>
    <string>production</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>5</integer>
  <key>ProcessType</key>
  <string>Background</string>
  <key>ExitTimeOut</key>
  <integer>15</integer>
  <key>StandardOutPath</key>
  <string>${LOG_DIR}/stdout.log</string>
  <key>StandardErrorPath</key>
  <string>${LOG_DIR}/stderr.log</string>
</dict>
</plist>`;
}

function installLaunchAgent() {
  if (process.platform !== 'darwin') {
    console.error('--install is macOS only. On Linux, create a systemd service.');
    process.exit(1);
  }

  const plistDir = path.join(os.homedir(), 'Library', 'LaunchAgents');
  const plistPath = path.join(plistDir, 'bot.sym.daemon.plist');

  // Ensure directories exist
  if (!fs.existsSync(plistDir)) fs.mkdirSync(plistDir, { recursive: true });
  if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });

  // Write plist with correct permissions (644 — launchd rejects writable plists)
  fs.writeFileSync(plistPath, launchAgentPlist(), { mode: 0o644 });
  console.log(`Installed: ${plistPath}`);

  // Load using modern launchctl API
  const { execSync } = require('child_process');
  const uid = process.getuid();
  try { execSync(`launchctl bootout gui/${uid}/bot.sym.daemon 2>/dev/null`); } catch {}
  execSync(`launchctl bootstrap gui/${uid} "${plistPath}"`);
  console.log(`sym-daemon started. Logs: ${LOG_DIR}/`);
  console.log('Check status: sym-daemon --status');
}

function uninstallLaunchAgent() {
  if (process.platform !== 'darwin') {
    console.error('--uninstall is macOS only.');
    process.exit(1);
  }

  const plistPath = path.join(os.homedir(), 'Library', 'LaunchAgents', 'bot.sym.daemon.plist');
  const { execSync } = require('child_process');

  try { execSync(`launchctl bootout gui/${process.getuid()}/bot.sym.daemon`); } catch {}

  if (fs.existsSync(plistPath)) {
    fs.unlinkSync(plistPath);
    console.log('sym-daemon uninstalled.');
  } else {
    console.log('sym-daemon is not installed.');
  }

  if (fs.existsSync(SOCKET_PATH)) {
    try { fs.unlinkSync(SOCKET_PATH); } catch {}
  }
}

function showStatus() {
  if (!fs.existsSync(SOCKET_PATH)) {
    console.log('sym-daemon: not running (no socket)');
    return;
  }

  const client = net.createConnection(SOCKET_PATH, () => {
    client.write(JSON.stringify({ type: 'status' }) + '\n');
  });

  let data = '';
  client.on('data', (chunk) => {
    data += chunk;
    if (data.includes('\n')) {
      try {
        const msg = JSON.parse(data.split('\n')[0]);
        if (msg.type === 'result' && msg.status) {
          const s = msg.status;
          console.log('sym-daemon: running');
          console.log(`  node:     ${s.name} (${s.nodeId})`);
          console.log(`  relay:    ${s.relayConnected ? 'connected' : 'disconnected'} (${s.relay || 'none'})`);
          console.log(`  peers:    ${s.peerCount}`);
          console.log(`  memories: ${s.memoryCount}`);
          console.log(`  virtual:  ${(msg.virtualNodes || []).join(', ') || 'none'}`);
          console.log(`  socket:   ${SOCKET_PATH}`);
        }
      } catch {}
      client.end();
    }
  });

  client.on('error', () => {
    console.log('sym-daemon: socket exists but not responding');
  });

  setTimeout(() => client.destroy(), 3000);
}

// ── Logging ────────────────────────────────────────────────────

function log(msg) {
  const ts = new Date().toISOString().slice(11, 19);
  console.log(`[${ts}] ${msg}`);
}

// ── Startup ────────────────────────────────────────────────────

async function main() {
  log(`sym-daemon starting: ${NODE_NAME}`);
  log(`  relay: ${relayUrl || 'none'}`);
  log(`  socket: ${SOCKET_PATH}`);

  await node.start();
  log(`SYM node started (${node._identity?.nodeId?.slice(0, 8)})`);

  forwardEventsToVirtualNodes();

  const ipcServer = startIPCServer();

  log('sym-daemon ready');

  // Graceful shutdown (launchd sends SIGTERM, then SIGKILL after ExitTimeOut)
  const shutdown = () => {
    log('Shutting down...');
    node.stop();
    ipcServer.close();
    if (fs.existsSync(SOCKET_PATH)) {
      try { fs.unlinkSync(SOCKET_PATH); } catch {}
    }
    process.exit(0);
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch((err) => {
  log(`Fatal: ${err.message}`);
  process.exit(1);
});
