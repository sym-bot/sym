#!/usr/bin/env node
'use strict';

const { recordCreatedBy } = require('../lib/record');

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
 * Copyright (c) 2026 SYM.BOT. Apache 2.0 License.
 */

const net = require('net');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { SymNode, migrateStores } = require('../lib/node');

// ── Global error handlers ─────────────────────────────────────
process.on('uncaughtException', (err) => {
  console.error(`[${new Date().toISOString()}] [FATAL] Uncaught exception: ${err.stack || err.message}`);
  process.exit(1);
});
process.on('unhandledRejection', (reason) => {
  console.error(`[${new Date().toISOString()}] [ERROR] Unhandled rejection: ${reason}`);
});

// Under the test runner, a daemon whose state root is the real home is refused (ETESTHOME)
// before it reads relay.env, migrates stores or builds its node — all of which touch ~/.sym.
require('../lib/core/state-root').assertTestSandbox();

// ── Configuration ──────────────────────────────────────────────

// The daemon's own files live in the same state root as every node's: SYM_STATE_DIR when set, else
// ~/.sym. Building it from the home dir sent a rooted daemon's room, tasks and relay.env to the
// user's real ~/.sym.
const SYM_DIR = require('../lib/core/state-root').SYM_STATE_DIR;
const { getSocketPath, getLogDir, listenExclusive, socketAnswers } = require('../lib/platform');
const SOCKET_PATH = getSocketPath();
// Stable name: use SYM_NODE_NAME env, or platform-scoped default
// (not hostname — macOS appends random suffixes to hostname on WiFi,
// causing a new identity each restart). Platform suffix lets the
// same role run on multiple devices without nodeId collisions.
const PLATFORM_SUFFIX =
  process.platform === 'darwin' ? 'mac'
  : process.platform === 'win32' ? 'win'
  : process.platform === 'linux' ? 'linux'
  : process.platform;
const NODE_NAME = process.env.SYM_NODE_NAME || `sym-daemon-${PLATFORM_SUFFIX}`;
const LOG_DIR = getLogDir('sym-daemon');

// Load relay config from ~/.sym/relay.env if env vars not set
if (!process.env.SYM_RELAY_URL) {
  const envFile = path.join(SYM_DIR, 'relay.env');
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

// ── Mesh room (MMP §5.8) ──────────────────────────────────────
// Resolve which room this node joins, in precedence order:
//   1. SYM_ROOM env   2. persisted ~/.sym/room (written by `sym join`)   3. default
// The persisted file is the source of truth across launchd/spawn restarts;
// env overrides it for one run. room -> service type matches the MCP node +
// sym-swift, so CLI peers discover app/Claude peers in the same room.
const { roomServiceType, isValidRoom } = require('../lib/rooms');
const ROOM_FILE = path.join(SYM_DIR, 'room');
// The room used to persist under a different filename. That file is NOT read — one name, no
// fallback — but its presence is ANNOUNCED, because the alternative is the worst outcome
// available: a node that silently drops to the default room, stops seeing every peer it had, and
// reports nothing. A membership that vanishes without a message is indistinguishable from a mesh
// that has gone quiet. Naming it costs one line and turns a mystery into an instruction.
const RETIRED_ROOM_FILE = path.join(SYM_DIR, 'group');
let ROOM = process.env.SYM_ROOM
  || (() => { try { return fs.readFileSync(ROOM_FILE, 'utf8').trim(); } catch { return ''; } })()
  || 'default';
// Announce the retired file if it is still there and we did NOT inherit its value. Refusing to
// read it is the rule; leaving the operator to guess why their mesh went quiet is not.
if (ROOM === 'default' && !process.env.SYM_ROOM) {
  try {
    const stale = fs.readFileSync(RETIRED_ROOM_FILE, 'utf8').trim();
    if (stale && stale !== 'default') {
      console.error(
        `sym: found a retired room file at ${RETIRED_ROOM_FILE} naming "${stale}", and it is NOT read. ` +
        `This node has started in "default" and will not see the peers it had. ` +
        `Run \`sym join ${stale}\` to restore it, then delete that file.`,
      );
    }
  } catch { /* absent is the normal case */ }
}

if (!isValidRoom(ROOM)) {
  log(`Invalid room "${ROOM}" — must be kebab-case or "default". Falling back to default.`);
  ROOM = 'default';
}
log(`Mesh room: ${ROOM} (${roomServiceType(ROOM)})`);

// ── SYM Node ───────────────────────────────────────────────────

// One-time bulk store migration (meshmem/ → cmbs/) for all non-live nodes,
// run on daemon start so readers use the cmbs/ name with no fallback.
try { const n = migrateStores(); if (n) log(`Migrated ${n} node store(s): meshmem → cmbs`); } catch { /* non-fatal */ }

// RELAY-ONLY (2026-09-05): a host with no usable multicast — Termux on Android, a locked-down
// container, a VPN that drops mDNS — joins the mesh over the relay alone and never touches
// Bonjour. `SYM_RELAY_ONLY=1` (also persisted by `sym start --relay-only`). Without it the
// node advertises and browses on the LAN as before.
const RELAY_ONLY = /^(1|true|yes)$/i.test(String(process.env.SYM_RELAY_ONLY || ''));   // relay.env is folded into process.env above
if (RELAY_ONLY) log(`relay-only: LAN discovery off (SYM_RELAY_ONLY); ${relayUrl ? `joining ${relayUrl}` : 'WARNING — no SYM_RELAY_URL, so this node will have no peers at all'}`);

const node = new SymNode({
  name: NODE_NAME,
  cognitiveProfile: `Local CLI-host for ${os.hostname()}. Hosts IPC surface for sym CLI. Forwards frames, no storage, no SVAF.`,
  cliHostMode: true,  // Local CLI-host peer — forward only, no persistence
  relayOnly: RELAY_ONLY,
  room: ROOM,
  discoveryServiceType: roomServiceType(ROOM),
  relay: relayUrl,
  relayToken: relayToken,
  silent: false,
});

// ── IPC Server (Unix Socket) ───────────────────────────────────

// sym 0.14 (design D8): ONE AGENT, ONE NODE. The daemon's virtual nodes (`register`), hosted agents
// (`register-agent`) and their outbound path (`agent-cmb`, which broadcast a plain `cmb` with a
// client-supplied `from`) are gone: an autonomous agent is its own node, with its own identity, and a
// node's reasoning process is its interior (lib/interior.js), which has no mesh identity. Local
// clients query the daemon's node and subscribe to its events with `listen` (MMP §14.9).
/** Agent activity state. name → { status, timestamp } */
const agentActivity = new Map();
/** Task board — persisted to ~/.sym/tasks.json */
const TASKS_PATH = path.join(SYM_DIR, 'tasks.json');
const tasks = new Map();
let nextTaskId = 1;

function loadTasks() {
  if (!fs.existsSync(TASKS_PATH)) return;
  try {
    const data = JSON.parse(fs.readFileSync(TASKS_PATH, 'utf8'));
    for (const t of data.tasks || []) { tasks.set(t.id, t); }
    nextTaskId = data.nextId || tasks.size + 1;
  } catch {}
}

function saveTasks() {
  try {
    if (!fs.existsSync(SYM_DIR)) fs.mkdirSync(SYM_DIR, { recursive: true });
    fs.writeFileSync(TASKS_PATH, JSON.stringify({
      nextId: nextTaskId,
      tasks: Array.from(tasks.values()),
    }, null, 2));
  } catch {}
}
let nextSocketId = 1;
const listeners = new Map(); // socketId → socket — real-time event subscribers

/**
 * Start the Unix socket IPC server for virtual node connections.
 * See MMP v0.2.0 Section 13 (Application).
 * @returns {net.Server}
 */
/**
 * Whether a daemon is serving the socket path: a connect that succeeds means yes; a refused or
 * missing socket is stale. Named pipes (Windows) have no file to remove, so they are not probed.
 * @returns {Promise<boolean>}
 */
function socketServed() {
  if (process.platform === 'win32' || !fs.existsSync(SOCKET_PATH)) return Promise.resolve(false);
  return socketAnswers(SOCKET_PATH);
}

/** The socket file this daemon created (its inode), so it never removes another daemon's. */
let ownSocketIno = null;
function socketIsOurs() {
  if (process.platform === 'win32' || ownSocketIno === null) return false;
  try { return fs.statSync(SOCKET_PATH).ino === ownSocketIno; } catch { return false; }
}

/** The server listening on SOCKET_PATH now. Closing a Unix-socket server removes its path, whoever
 *  has bound it since, so it is closed only while the path is still its own. */
let listeningServer = null;

/** One IPC connection: newline-delimited JSON in, results and events out. */
function onIPCConnection(socket) {
  const socketId = nextSocketId++;
  let buffer = '';

  socket.on('data', (data) => {
    buffer += data.toString();
    // One line is at most IPC_MAX_LINE: a client that never sends a newline cannot grow the buffer.
    if (buffer.length > IPC_MAX_LINE && buffer.indexOf('\n') === -1) {
      log(`IPC client ${socketId} sent ${buffer.length} bytes without a newline; closing it`);
      buffer = '';
      socket.destroy();
      return;
    }
    let idx;
    while ((idx = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 1);
      if (line.trim()) takeIPCLine(socketId, socket, line);
    }
  });

  socket.on('close', () => {
    listeners.delete(socketId);
  });

  socket.on('error', (err) => {
    if (err.code !== 'EPIPE' && err.code !== 'ECONNRESET') {
      log(`IPC socket error: ${err.message}`);
    }
    listeners.delete(socketId);
  });
}

function onListening() {
  // chmod not applicable on Windows named pipes
  if (process.platform !== 'win32') {
    try { fs.chmodSync(SOCKET_PATH, 0o700); } catch {}
    try { ownSocketIno = fs.statSync(SOCKET_PATH).ino; } catch { ownSocketIno = null; }
  }
  log(`IPC server listening: ${SOCKET_PATH}`);
}

/** A server that only logs its errors once it is listening: an accept error never ends the daemon. */
function newIPCServer() {
  const server = net.createServer(onIPCConnection);
  return server;
}

/** @returns {Promise<net.Server|null>} the listening server, or null when another daemon serves the path */
async function startIPCServer() {
  // Ensure ~/.sym/ exists
  if (!fs.existsSync(SYM_DIR)) {
    fs.mkdirSync(SYM_DIR, { recursive: true });
  }
  // Bind first, and probe only a path that is taken: a socket file is removed only when nothing
  // answers on it and it is still the file probed. Probing first and then removing whatever was
  // there let two daemons starting together each take the path from the other.
  const server = newIPCServer();
  if (await listenExclusive(server, SOCKET_PATH) === 'served') return null;
  server.on('error', (err) => log(`IPC server error: ${err.message}`));
  listeningServer = server;
  onListening();

  // If the socket file is removed or replaced while this daemon runs, clients can no longer reach
  // it. It is checked every 30 s and, when gone, a fresh server listens on it. That never waits for
  // the clients already connected: they stay on the connections they have (closing a server stops it
  // accepting and leaves its connections open). One attempt at a time, and a failure is logged and
  // retried at the next check, never fatal.
  if (process.platform !== 'win32') {
    let relistening = false;
    setInterval(async () => {
      if (relistening || ownSocketIno === null || socketIsOurs()) return;
      if (fs.existsSync(SOCKET_PATH)) return; // another process's socket now: leave it alone
      relistening = true;
      try {
        log(`IPC socket ${SOCKET_PATH} was removed while this daemon was serving; listening again`);
        // The old listener goes first: closing it removes the path, which is still empty now.
        if (listeningServer) { listeningServer.close(); listeningServer = null; }
        ownSocketIno = null;
        const fresh = newIPCServer();
        if (await listenExclusive(fresh, SOCKET_PATH) === 'served') {
          log(`Another sym-daemon now serves ${SOCKET_PATH}; this one keeps the clients it has`);
          return;
        }
        fresh.on('error', (err) => log(`IPC server error: ${err.message}`));
        listeningServer = fresh;
        onListening();
      } catch (err) {
        log(`IPC listen again on ${SOCKET_PATH} failed: ${err.message}; retried at the next check`);
      } finally {
        relistening = false;
      }
    }, Number(process.env.SYM_SOCKET_CHECK_MS) || 30_000).unref();
  }

  return server;
}

const NO_INSIGHT_ENGINE = 'this node runs no insight engine';
/** The longest IPC line taken (a remember with its payload is far below it). */
const IPC_MAX_LINE = 8 * 1024 * 1024;

/** The text of a thrown value, without trusting it to print. */
function errorText(err) {
  return err && typeof err.message === 'string' ? err.message.slice(0, 500) : 'unknown error';
}

/**
 * Take one IPC line. An IPC message is typed at the door, as a wire frame is: it is a JSON object
 * whose `type` is a non-empty string, or it is refused with an error reply and handled no
 * further. Only then is anything in it printed: the catch below names the message by its type,
 * and in 0.13.17 as first built it printed `type` unchecked, so one line whose type was an object
 * that cannot be turned into text made the catch itself throw, and the daemon exited (FATAL).
 */
function takeIPCLine(socketId, socket, line) {
  let msg;
  try { msg = JSON.parse(line); } catch (err) {
    log(`IPC parse error: ${errorText(err)}`);
    sendIPC(socket, { type: 'result', action: null, error: 'not JSON' });
    return;
  }
  if (!msg || typeof msg !== 'object' || Array.isArray(msg) || typeof msg.type !== 'string' || !msg.type) {
    log('IPC message refused: not an object with a string type');
    sendIPC(socket, { type: 'result', action: null, error: 'an IPC message is a JSON object with a string type' });
    return;
  }
  const type = msg.type.slice(0, 64);
  try {
    handleIPCMessage(socketId, socket, msg);
  } catch (err) {
    log(`IPC '${type}' failed: ${errorText(err)}`);
    sendIPC(socket, { type: 'result', action: type, error: errorText(err), code: err && typeof err.code === 'string' ? err.code : undefined });
  }
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
    // A client's opener: who this daemon's node is. (The `register` virtual-node path is gone in
    // 0.14, design D8: a client is not a node.)
    case 'hello':
      sendIPC(socket, { type: 'result', action: 'hello', nodeId: node._identity?.nodeId, name: node.name, relay: relayUrl });
      break;

    case 'register':
    case 'register-agent':
    case 'agent-cmb':
      sendIPC(socket, {
        type: 'result', action: msg.type, code: 'EREMOVED',
        error: `'${msg.type}' was removed in sym 0.14 (one agent, one node): an agent runs its own node; a node's mind submits through its interior socket. Use 'hello' and 'listen' for local clients.`,
      });
      break;

    case 'agent-activity':
      if (msg.name && msg.status) {
        const prev = agentActivity.get(msg.name);
        agentActivity.set(msg.name, { status: msg.status, timestamp: msg.timestamp || Date.now() });

        // Auto-progress tickets based on agent lifecycle
        const agentTasks = Array.from(tasks.values()).filter(t => t.agent === msg.name && t.agent !== 'founder');
        if (msg.status === 'reasoning' || msg.status === 'remixing') {
          for (const t of agentTasks) {
            if (t.status === 'assigned') {
              if (!t.history) t.history = [];
              t.history.push({ type: 'status', from: 'assigned', to: 'working', actor: msg.name, timestamp: Date.now() });
              t.status = 'working';
              t.updatedAt = Date.now();
              log(`Task ${t.id} auto-progressed to working (${msg.name} reasoning)`);
            }
          }
          saveTasks();
        } else if (msg.status === 'idle' && prev && (prev.status === 'reasoning' || prev.status === 'remixing')) {
          for (const t of agentTasks) {
            if (t.status === 'working') {
              if (!t.history) t.history = [];
              t.history.push({ type: 'status', from: 'working', to: 'review', actor: msg.name, timestamp: Date.now() });
              t.status = 'review';
              t.updatedAt = Date.now();
              log(`Task ${t.id} auto-progressed to review (${msg.name} completed)`);
            }
          }
          saveTasks();
        }
      }
      break;

    // ── Task Board ────────────────────────────────────
    case 'task-create': {
      const id = `task-${nextTaskId++}`;
      const task = {
        id,
        title: msg.title || '',
        body: msg.body || '',
        agent: msg.agent || 'unassigned',
        status: msg.status || 'backlog', // backlog, assigned, working, review, done
        priority: msg.priority || 0,
        createdAt: Date.now(),
        updatedAt: Date.now(),
        source: msg.source || 'manual',
      };
      tasks.set(id, task);
      saveTasks();
      sendIPC(socket, { type: 'result', action: 'task-create', task });
      broadcastToListeners({ type: 'event', event: 'task-created', data: task });
      break;
    }

    case 'task-update': {
      const task = tasks.get(msg.id);
      if (!task) { sendIPC(socket, { type: 'result', action: 'task-update', error: 'not found' }); break; }
      if (!task.history) task.history = [];
      const now = Date.now();
      const actor = msg.actor || 'system';

      if (msg.status !== undefined && msg.status !== task.status) {
        task.history.push({ type: 'status', from: task.status, to: msg.status, actor, timestamp: now });
        task.status = msg.status;
      }
      if (msg.agent !== undefined && msg.agent !== task.agent) {
        task.history.push({ type: 'assign', from: task.agent, to: msg.agent, actor, timestamp: now });
        task.agent = msg.agent;
      }
      if (msg.priority !== undefined) task.priority = msg.priority;
      if (msg.title !== undefined) task.title = msg.title;
      if (msg.body !== undefined) task.body = msg.body;
      task.updatedAt = now;
      saveTasks();
      sendIPC(socket, { type: 'result', action: 'task-update', task });
      broadcastToListeners({ type: 'event', event: 'task-updated', data: task });
      break;
    }

    case 'task-list':
      sendIPC(socket, { type: 'result', action: 'task-list', tasks: Array.from(tasks.values()) });
      break;

    case 'message':
      if (msg.content) {
        node.send(msg.content, msg.to ? { to: msg.to } : {});
        sendIPC(socket, { type: 'result', action: 'message', peers: node.peers().length });
      }
      break;

    case 'remember':
      if (msg.categories) {
        try {
          const entry = node.remember(msg.categories, { tags: msg.tags, parents: msg.parents });
          if (entry && !entry.duplicate) {
            sendIPC(socket, { type: 'result', action: 'remember', key: entry.key });
          } else if (entry) {
            sendIPC(socket, { type: 'result', action: 'remember', key: entry.key, duplicate: true });
          } else {
            sendIPC(socket, { type: 'result', action: 'remember', error: 'not stored', code: 'ESTORE' });
          }
        } catch (err) {
          log(`remember failed: ${err.message}`);
          sendIPC(socket, { type: 'result', action: 'remember', error: err.message, code: err.code });
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
        // Send as both: transient message frame (real-time) + CMB (persistent, recallable).
        // Message frame: immediate delivery to connected peers (MMP Section 7).
        // CMB: stored in mesh memory, flows through SVAF, recallable via sym recall.
        node.send(msg.message);
        node.remember({
          focus: msg.message,
          issue: 'none',
          intent: 'inter-node message',
          motivation: 'mesh communication',
          commitment: msg.message.slice(0, 120),
          perspective: `${node.name}, direct message`,
          mood: { text: 'neutral', valence: 0, arousal: 0 },
        });
        sendIPC(socket, { type: 'result', action: 'send', peers: node.peers().length });
      }
      break;

    case 'listen':
      // MMP Section 13.9: Local Event Interface.
      // Register this socket for real-time mesh events.
      // Subscriber MAY declare category weights for domain-specific filtering.
      listeners.set(socketId, { socket, categoryWeights: msg.categoryWeights || null });
      sendIPC(socket, { type: 'result', action: 'listen', status: 'subscribed' });
      log(`Listener registered (socket ${socketId}${msg.categoryWeights ? ', with category weights' : ''})`);
      break;

    case 'peers':
      sendIPC(socket, { type: 'result', action: 'peers', peers: node.peers() });
      break;

    case 'metrics':
      sendIPC(socket, { type: 'result', action: 'metrics', metrics: node.metrics() });
      break;

    case 'status':
      sendIPC(socket, {
        type: 'result',
        action: 'status',
        status: node.status(),
      });
      break;

    // The insight engine is a capability a node may not have (a stock daemon has none): checked,
    // answered either way, never assumed — unchecked, this threw and the client waited out its timeout.
    case 'xmesh-context':
      sendIPC(socket, node._xmesh
        ? { type: 'result', action: 'xmesh-context', context: node._xmesh.getContext({ timeWindow: msg.timeWindow }) }
        : { type: 'result', action: 'xmesh-context', error: NO_INSIGHT_ENGINE });
      break;

    case 'xmesh-search':
      sendIPC(socket, node._xmesh
        ? { type: 'result', action: 'xmesh-search', insights: node._xmesh.getInsights(msg.query) }
        : { type: 'result', action: 'xmesh-search', error: NO_INSIGHT_ENGINE });
      break;

    case 'catchup':
      // Broadcast catchup message to all standalone peer agents
      node.send('catchup');
      sendIPC(socket, { type: 'result', action: 'catchup', agents: node.peers().length });
      log(`Catchup broadcast to ${node.peers().length} peer(s)`);
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

// MMP Section 13.9.2: Subscriber Category Weights.
// If subscriber declared category weights, evaluate CMB relevance before delivery.
function shouldDeliverToListener(listener, msg) {
  if (!listener.categoryWeights) return true; // no weights = receive everything
  if (msg.event !== 'cmb-accepted') return true; // non-CMB events always delivered

  const categories = msg.data?.categories;
  if (!categories) return true;

  // Weighted relevance: sum(α_f * hasContent_f) / sum(α_f)
  // Deliver if any high-weight category has content
  const weights = listener.categoryWeights;
  let weightedScore = 0, totalWeight = 0;
  for (const [category, weight] of Object.entries(weights)) {
    totalWeight += weight;
    const text = categories[category]?.text || '';
    if (text && text !== 'none' && text !== 'neutral') {
      weightedScore += weight;
    }
  }
  // Deliver if weighted content coverage > 30% of total weight
  return totalWeight > 0 && (weightedScore / totalWeight) > 0.3;
}

function broadcastToListeners(msg) {
  for (const [id, listener] of listeners) {
    if (!shouldDeliverToListener(listener, msg)) continue;
    try {
      listener.socket.write(JSON.stringify(msg) + '\n');
    } catch { listeners.delete(id); }
  }
}

/** Forward mesh events to the local subscribers (`listen`, MMP §14.9). */
function forwardEventsToListeners() {
  const events = [
    ['mood-delivered', (d) => ({ type: 'event', event: 'mood-delivered', data: d })],
    ['mood-rejected', (d) => ({ type: 'event', event: 'mood-rejected', data: d })],
    ['peer-joined', (d) => ({ type: 'event', event: 'peer-joined', data: d })],
    ['peer-left', (d) => ({ type: 'event', event: 'peer-left', data: d })],
    ['coupling-decision', (d) => ({ type: 'event', event: 'coupling-decision', data: d })],
  ];

  for (const [event, formatter] of events) {
    node.on(event, (data) => broadcastToListeners(formatter(data)));
  }

  node.on('message', (from, content) => {
    broadcastToListeners({ type: 'event', event: 'message', data: { from, content, timestamp: Date.now() } });

    // Feed messages (including Telegram) into the insight engine, if this node has one. A stock
    // daemon has none (`node._xmesh` is null: the engine is injected, never assumed); calling it
    // unchecked threw inside the frame dispatch, so any peer's `message` frame over the relay
    // took the daemon down in 0.13.16.
    if (node._xmesh) node._xmesh.ingestSignal({ type: 'message', from, content });

    // A peer's message is not re-sent under this node's name to sleeping peers (security review):
    // it was the peer's, signed to this node. A message for another node is that node's to send.
  });

  // A peer's mood is not re-broadcast under this node's name either (security review): before
  // 0.14 the daemon queued every delivered mood for sleeping peers as its own `mood` frame.

  node.on('xmesh-insight', (data) => {
    broadcastToListeners({ type: 'event', event: 'xmesh-insight', data });
  });

  node.on('memory-received', ({ from, entry, decision }) => {
    // XMesh ingestion already happens in frame-handler after SVAF evaluation.
    broadcastToListeners({ type: 'event', event: 'memory-received', data: { from, content: entry.content, decision } });
  });
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
          if (s.coreSecure) console.log(`  sessions: ${s.coreSecure.sessions.confirmed} confirmed (Core Secure)${s.coreSecure.keyConflicts.length ? `, ${s.coreSecure.keyConflicts.length} KEY CONFLICT(S) to resolve: sym keys` : ''}`);
          if (s.legacyImport && s.legacyImport.sessions.length) console.log(`  legacy:   ${s.legacyImport.sessions.length} Legacy Import session(s) — legacy encryption, no forward secrecy, no transcript proof`);
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

// ── Room discovery beacon (MMP §5.8) ──────────────────────────
// Advertise this node's room on one shared service type so `sym rooms` can
// list live rooms cross-platform — bonjour-service browse works where Apple
// dns-sd is absent (e.g. Windows). Discovery-only: comms stay isolated on the
// room's own `_<room>._tcp`. The room name is whatever the user chose and
// can be an anonymous/opaque code, so the broadcast need not reveal its purpose.
let roomBeacon = null;
function startRoomBeacon() {
  try {
    const { createBonjour } = require('../lib/discovery');
    // A failed mDNS send (the network dropped, a sleep/wake) is logged, at most once a minute, and never thrown: made
    // without an error callback, this beacon took the daemon down with `send EHOSTUNREACH 224.0.0.251:5353`.
    let lastBeaconError = 0;
    roomBeacon = createBonjour((err) => {
      if (Date.now() - lastBeaconError < 60_000) return;
      lastBeaconError = Date.now();
      log(`Room beacon: ${err && err.message ? err.message : err} — \`sym rooms\` may miss this node until the network returns; the node itself is unaffected`);
    });
    roomBeacon.publish({
      name: NODE_NAME,
      type: 'symrooms',
      port: node._port || 7777,
      txt: { room: ROOM, node: NODE_NAME },
    });
    log(`Room beacon: room="${ROOM}" on _symrooms._tcp`);
  } catch (e) {
    log(`Room beacon unavailable (sym rooms listing limited): ${e.message}`);
  }
}
function stopRoomBeacon() {
  if (!roomBeacon) return;
  try { roomBeacon.unpublishAll(() => { try { roomBeacon.destroy(); } catch {} }); } catch {}
  roomBeacon = null;
}

async function main() {
  log(`sym-daemon starting: ${NODE_NAME}`);
  log(`  relay: ${relayUrl || 'none'}`);
  log(`  socket: ${SOCKET_PATH}`);

  // A socket another daemon answers on is its: this start stops before its node joins anything.
  if (await socketServed()) {
    log(`Another sym-daemon is serving ${SOCKET_PATH}; not starting a second one.`);
    process.exit(1);
  }

  await node.start();
  log(`SYM node started (${node._identity?.nodeId?.slice(0, 8)})`);

  // A relay-only daemon has LAN discovery off, so it must not announce its room on the LAN either.
  if (RELAY_ONLY) log('Room beacon: off (relay-only)');
  else startRoomBeacon();

  loadTasks();
  log(`Loaded ${tasks.size} task(s)`);

  forwardEventsToListeners();

  // A CMB the daemon's node accepted (from a peer or a local observe) goes to the subscribers.
  node.on('cmb-accepted', (entry) => {
    broadcastToListeners({
      type: 'event', event: 'cmb-accepted',
      data: {
        key: entry.key,
        source: entry.source || recordCreatedBy(entry.cmb) || 'unknown',
        focus: entry.cmb?.categories?.focus?.text || entry.content || '',
        categories: entry.cmb?.categories || null, // Section 13.9.2: needed for subscriber category weight filtering
        timestamp: entry.timestamp || Date.now(),
      },
    });
  });

  // peer-joined/left reach the subscribers through forwardEventsToListeners.

  if (!(await startIPCServer())) {
    log(`Another sym-daemon is serving ${SOCKET_PATH}; not starting a second one.`);
    await node.stop();
    process.exit(1);
  }

  log('sym-daemon ready');

  // Graceful shutdown (launchd sends SIGTERM, then SIGKILL after ExitTimeOut)
  const shutdown = () => {
    log('Shutting down...');
    stopRoomBeacon();
    node.stop();
    // Only our own socket file: closing a server removes its path, so a path another daemon now
    // serves is not closed over; exiting releases this one's handle without touching it.
    if (listeningServer && socketIsOurs()) listeningServer.close();
    process.exit(0);
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch((err) => {
  log(`Fatal: ${err.message}`);
  process.exit(1);
});
