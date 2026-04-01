#!/usr/bin/env node
'use strict';

// ── EPIPE/EIO Safety (must be first — OpenClaw issue #4632) ────
// launchd may close stdout/stderr pipes during restart. Without this,
// Node.js throws uncaught EPIPE and enters a crash loop with exponential
// throttle, causing hours-long outages.
/**
 * Suppress EPIPE/EIO errors on stdout/stderr that occur when launchd
 * closes pipes during restart (OpenClaw issue #4632).
 * @param {stream.Writable} stream — process.stdout or process.stderr
 */
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

// ── Global error handlers ─────────────────────────────────────
process.on('uncaughtException', (err) => {
  console.error(`[${new Date().toISOString()}] [FATAL] Uncaught exception: ${err.stack || err.message}`);
  process.exit(1);
});
process.on('unhandledRejection', (reason) => {
  console.error(`[${new Date().toISOString()}] [ERROR] Unhandled rejection: ${reason}`);
});

// ── Configuration ──────────────────────────────────────────────

const SYM_DIR = path.join(os.homedir(), '.sym');
const SOCKET_PATH = process.env.SYM_SOCKET || path.join(SYM_DIR, 'daemon.sock');
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

// ── IPC Server (Unix Socket) ───────────────────────────────────

/** Connected virtual nodes. socketId → { socket, name, cognitiveProfile } */
const virtualNodes = new Map();
/** Hosted agents (Section 3.2 + 4.3). socketId → { socket, nodeId, name, publicKey } */
const hostedAgents = new Map();
let nextSocketId = 1;

/**
 * Start the Unix socket IPC server for virtual node connections.
 * See MMP v0.2.0 Section 13 (Application).
 * @returns {net.Server}
 */
function startIPCServer() {
  // Ensure ~/.sym/ exists
  if (!fs.existsSync(SYM_DIR)) {
    fs.mkdirSync(SYM_DIR, { recursive: true });
  }
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
      if (vn) { log(`Virtual node disconnected: ${vn.name}`); virtualNodes.delete(socketId); }
      const ha = hostedAgents.get(socketId);
      if (ha) { log(`Hosted agent disconnected: ${ha.name}`); hostedAgents.delete(socketId); }
    });

    socket.on('error', (err) => {
      if (err.code !== 'EPIPE' && err.code !== 'ECONNRESET') {
        log(`IPC socket error: ${err.message}`);
      }
      virtualNodes.delete(socketId);
      hostedAgents.delete(socketId);
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

/**
 * Handle a single IPC message from a virtual node.
 * Routes to the appropriate SymNode method and sends result back.
 *
 * @param {number} socketId — virtual node socket identifier
 * @param {net.Socket} socket — the IPC socket
 * @param {object} msg — parsed JSON message
 */
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

    // ── Hosted Agent Registration (Section 4.3.1) ──────────
    case 'register-agent': {
      if (!msg.nodeId || !msg.name) {
        sendIPC(socket, { type: 'error', message: 'register-agent requires nodeId and name' });
        break;
      }
      hostedAgents.set(socketId, {
        socket,
        nodeId: msg.nodeId,
        name: msg.name,
        publicKey: msg.publicKey || null,
        svafFieldWeights: msg.svafFieldWeights || null,
        svafFreshnessSeconds: msg.svafFreshnessSeconds || null,
      });
      sendIPC(socket, {
        type: 'registered-agent',
        nodeId: msg.nodeId,
        daemonNodeId: node._identity?.nodeId,
        relay: relayUrl,
        peers: node.peers(),
      });
      log(`Hosted agent registered: ${msg.name} (${msg.nodeId.slice(0, 8)})`);
      break;
    }

    // ── Hosted Agent Outbound CMB (Section 4.3.2) ─────────
    case 'agent-cmb': {
      // Hosted agent produced a CMB — broadcast to remote peers with agent's nodeId
      if (!msg.cmb || !msg.from) break;
      const frame = { type: 'cmb', timestamp: msg.timestamp || Date.now(), cmb: msg.cmb, from: msg.from, fromName: msg.fromName };
      // Broadcast via all peer transports
      for (const [, peer] of node._peers) {
        peer.transport.send(frame);
      }
      // Also forward to other hosted agents (local mesh)
      for (const [id, agent] of hostedAgents) {
        if (id !== socketId) {
          sendIPC(agent.socket, { type: 'event', event: 'frame-received', data: { peerId: msg.from, peerName: msg.fromName, frame } });
        }
      }
      break;
    }

    case 'message':
      if (msg.content) {
        node.send(msg.content, msg.to ? { to: msg.to } : {});
        sendIPC(socket, { type: 'result', action: 'message', peers: node.peers().length });
      }
      break;

    case 'remember':
      if (msg.fields) {
        try {
          const entry = node.remember(msg.fields, { tags: msg.tags });
          if (entry) {
            sendIPC(socket, { type: 'result', action: 'remember', key: entry.key });
          } else {
            sendIPC(socket, { type: 'result', action: 'remember', duplicate: true });
          }
        } catch (err) {
          log(`remember failed: ${err.message}`);
          sendIPC(socket, { type: 'result', action: 'remember', error: err.message });
        }
      }
      break;

    case 'recall': {
      let results = node.recall(msg.query || '');
      if (msg.limit && msg.limit > 0) results = results.slice(0, msg.limit);
      sendIPC(socket, { type: 'result', action: 'recall', results });
      break;
    }

    case 'send':
      if (msg.message) {
        node.send(msg.message);
        sendIPC(socket, { type: 'result', action: 'send', peers: node.peers().length });
      }
      break;

    case 'peers': {
      // Include mesh peers + hosted agents. Hosted takes priority over
      // stale mesh peers with the same name (e.g. ceo-ops reconnected as hosted).
      const hostedNames = new Set(Array.from(hostedAgents.values()).map(a => a.name));
      const meshPeers = node.peers().filter(p => !hostedNames.has(p.name));
      const hosted = Array.from(hostedAgents.values()).map(a => ({
        id: a.nodeId?.slice(0, 8) || '',
        name: a.name,
        connected: true,
        lastSeen: Date.now(),
        coupling: 'hosted',
        drift: 0,
        source: 'ipc',
      }));
      sendIPC(socket, { type: 'result', action: 'peers', peers: [...meshPeers, ...hosted] });
      break;
    }

    case 'metrics':
      sendIPC(socket, { type: 'result', action: 'metrics', metrics: node.metrics() });
      break;

    case 'status':
      sendIPC(socket, {
        type: 'result',
        action: 'status',
        status: node.status(),
        virtualNodes: Array.from(virtualNodes.values()).map(v => v.name),
        hostedAgents: Array.from(hostedAgents.values()).map(a => ({
          nodeId: a.nodeId, name: a.name,
        })),
      });
      break;

    case 'xmesh-context':
      sendIPC(socket, {
        type: 'result',
        action: 'xmesh-context',
        context: node._xmesh.getContext({ timeWindow: msg.timeWindow }),
      });
      break;

    case 'xmesh-search':
      sendIPC(socket, {
        type: 'result',
        action: 'xmesh-search',
        insights: node._xmesh.getInsights(msg.query),
      });
      break;

    case 'catchup':
      // Trigger all hosted agents to check their domains immediately
      broadcastToHostedAgents({ type: 'event', event: 'catchup' });
      sendIPC(socket, { type: 'result', action: 'catchup', agents: hostedAgents.size });
      log(`Catchup triggered for ${hostedAgents.size} hosted agent(s)`);
      break;

    default:
      log(`Unknown IPC message type: ${msg.type}`);
  }
}

/**
 * Send a newline-delimited JSON message over an IPC socket.
 * @param {net.Socket} socket — IPC socket
 * @param {object} msg — message to send
 */
function sendIPC(socket, msg) {
  try { socket.write(JSON.stringify(msg) + '\n'); } catch {}
}

/**
 * Broadcast to all hosted agents (Section 4.3.2).
 * Hosted agents receive raw frames — they run their own SVAF.
 */
function broadcastToHostedAgents(msg) {
  const data = JSON.stringify(msg) + '\n';
  for (const [id, agent] of hostedAgents) {
    try { agent.socket.write(data); } catch { hostedAgents.delete(id); }
  }
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
    node._xmesh.ingestSignal({ type: 'message', from, content });

    // Wake sleeping peers that might need this message.
    // The daemon acts as wake proxy — it has APNs keys and gossiped wake channels.
    // When a remote peer (Telegram bot) sends a message, and a local peer (MeloTune)
    // is sleeping, the daemon wakes it so the relay can deliver the message.
    node._wakeManager?.wakeSleepingPeers('message', {
      type: 'message', from: node._identity.nodeId, fromName: node.name,
      content, timestamp: Date.now(),
    });
  });

  node.on('mood-accepted', (data) => {
    // xMesh ingestion happens via cmb → SVAF path, not here.
    // Wake sleeping local peers so they can receive the mood.
    node._wakeManager?.wakeSleepingPeers('mood', {
      type: 'mood', from: node._identity.nodeId, fromName: node.name,
      mood: data.mood, timestamp: Date.now(),
    });
  });

  node.on('xmesh-insight', (data) => {
    broadcastToVirtualNodes({ type: 'event', event: 'xmesh-insight', data });
  });

  node.on('memory-received', ({ from, entry, decision }) => {
    // xMesh ingestion already happens in frame-handler after SVAF evaluation.
    broadcastToVirtualNodes({ type: 'event', event: 'memory-received', data: { from, content: entry.content, decision } });
  });
}

/**
 * Broadcast a message to all connected virtual nodes.
 * @param {object} msg — message to broadcast
 */
function broadcastToVirtualNodes(msg) {
  const data = JSON.stringify(msg) + '\n';
  for (const [id, vn] of virtualNodes) {
    try { vn.socket.write(data); } catch { virtualNodes.delete(id); }
  }
}

// ── launchd Install/Uninstall ──────────────────────────────────

/**
 * Generate the launchd plist XML for the daemon LaunchAgent.
 * @returns {string} plist XML content
 */
function launchAgentPlist() {
  // Resolve node binary — use the same node that ran the install command
  const nodePath = process.execPath;

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

/**
 * Install the daemon as a macOS LaunchAgent and start it.
 */
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

/**
 * Remove the daemon LaunchAgent and clean up the socket.
 */
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

/**
 * Connect to the daemon socket and print status, then exit.
 */
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

/**
 * Log a timestamped daemon message.
 * @param {string} msg — message to log
 */
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

  // Section 4.3.2: forward raw frames to hosted agents (before SVAF evaluation)
  node.on('frame-received', ({ peerId, peerName, frame }) => {
    if (hostedAgents.size > 0) {
      broadcastToHostedAgents({ type: 'event', event: 'frame-received', data: { peerId, peerName, frame } });
    }
  });

  // When daemon accepts a CMB (from peer or local observe), forward to hosted agents
  // so they can ingest it into their local memory via their own SVAF
  node.on('cmb-accepted', (entry) => {
    if (hostedAgents.size > 0) {
      // Wrap as a cmb frame so hosted agent's SVAF can evaluate it
      const frame = {
        type: 'cmb',
        timestamp: entry.timestamp || entry.storedAt || Date.now(),
        cmb: entry.cmb,
        source: entry.source,
      };
      broadcastToHostedAgents({ type: 'event', event: 'frame-received', data: {
        peerId: entry.peerId || entry.source || 'daemon',
        peerName: entry.source || 'daemon',
        frame,
      }});
    }
  });

  // Forward peer events to hosted agents
  node.on('peer-joined', (data) => broadcastToHostedAgents({ type: 'event', event: 'peer-joined', data }));
  node.on('peer-left', (data) => broadcastToHostedAgents({ type: 'event', event: 'peer-left', data }));

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
