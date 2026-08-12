#!/usr/bin/env node
'use strict';

const { recordCreatedBy } = require('../lib/record');

/**
 * sym — CLI for the SYM mesh.
 *
 * Thin wrapper over the sym-daemon IPC socket. Every command connects,
 * sends one request, prints the result, and exits.
 *
 * Usage:
 *   sym start                         # Install & start daemon
 *   sym stop                          # Stop daemon
 *   sym status                        # Show mesh status
 *   sym peers                         # List connected peers
 *   sym publish [flags] <json>        # Publish a projection (CAT7 categories as JSON)
 *                                     #   --standalone: daemon-less one-shot SymNode (auto-fallback if daemon is down)
 *                                     #   --name <id>:  mesh identity for standalone mode (REQUIRED — no default)
 *                                     #   --parents <keys>: comma-separated parent CMB keys (lineage, implies --standalone)
 *   sym emit [flags] <json>           # One-shot Class 1 emit to a REMOTE mesh node (no daemon, §17.1)
 *                                     #   --server <host:port> (required), --room <g>, --name <id>,
 *                                     #   --to <node>, --parents <keys>
 *   sym recall <query>                # Search mesh memory
 *   sym ask "<question>"              # Ask the whole mesh; get one synthesized answer
 *   sym insight                       # Get xMesh collective intelligence
 *   sym send <message>                # Send message to all peers
 *   sym room                         # Show current mesh room
 *   sym rooms                        # Discover rooms live on the LAN
 *   sym join <name>                   # Switch into a room ("room chat")
 *   sym leave                         # Return to the default global mesh
 *   sym logs                          # Tail daemon logs
 *   sym version                       # Show version
 *
 * Copyright (c) 2026 SYM.BOT. Apache 2.0 License.
 */

const net = require('net');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync, spawn } = require('child_process');

const { getSocketPath, getLogDir } = require('../lib/platform');
const { isValidRoom, roomServiceType } = require('../lib/rooms');
const ROOM_FILE = path.join(os.homedir(), '.sym', 'room');
const PID_FILE = path.join(os.homedir(), '.sym', 'daemon.pid');

// Portable synchronous sleep — no shell dependency (`sleep` is POSIX-only and
// absent on Windows). Used between daemon stop/start on a room switch.
function sleepMs(ms) {
  try { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); } catch {}
}
const SOCKET_PATH = process.env.SYM_SOCKET || getSocketPath();
const LOG_DIR = getLogDir('sym-daemon');
const VERSION = require('../package.json').version;

// ── Argument Parsing ──────────────────────────────────────────

const args = process.argv.slice(2);
const command = args[0];
const jsonFlag = args.includes('--json');
const actorIdx = args.indexOf('--actor');
const actorFlag = actorIdx >= 0 ? args[actorIdx + 1] : null;

if (!command || command === '--help' || command === '-h') {
  printUsage();
  process.exit(0);
}

if (command === '--version' || command === 'version') {
  console.log(`sym ${VERSION}`);
  process.exit(0);
}

// ── Commands ──────────────────────────────────────────────────

switch (command) {
  case 'start':   cmdStart(); break;
  case 'stop':    cmdStop(); break;
  case 'status':  cmdIPC({ type: 'status' }, jsonFlag ? formatJSON : formatStatus); break;
  case 'peers':   cmdIPC({ type: 'peers' }, jsonFlag ? formatJSON : formatPeers); break;
  case 'metrics': cmdIPC({ type: 'metrics' }, jsonFlag ? formatJSON : formatMetrics); break;
  case 'publish': cmdPublish(); break;
  case 'emit':    cmdEmit().catch((e) => { console.error(e.message); process.exit(1); }); break;
  case 'recall':  cmdRecall(); break;
  case 'ask':     cmdAsk().catch((e) => { console.error(e.message); process.exit(1); }); break;
  case 'insight': cmdIPC({ type: 'xmesh-context' }, formatInsight); break;
  case 'send':    cmdSend(); break;
  case 'listen':  cmdListen(); break;
  case 'join':    cmdJoin(); break;
  case 'leave':   cmdLeave(); break;
  case 'rooms':  cmdRooms(); break;
  case 'room':   cmdRoom(); break;
  case 'catchup': cmdIPC({ type: 'catchup' }, (msg) => { console.log(`Catchup triggered for ${msg.agents || 0} hosted agent(s).`); }); break;
  case 'task':    cmdTask(); break;
  case 'logs':    cmdLogs(); break;
  default:
    console.error(`Unknown command: ${command}`);
    console.error('Run sym --help for usage.');
    process.exit(1);
}

// ── Command Implementations ───────────────────────────────────

function cmdStart() {
  applyStartFlags();                       // parse + persist --room / --relay-* first
  if (isDaemonRunning()) {
    console.log('sym-daemon is already running.');
    console.log(`room: ${readRoom()}`);
    return;
  }
  spawnDaemon();
}

// ── Mesh rooms (MMP §5.8) ─────────────────────────────────────
// A room is the "room chat" boundary. The persisted ~/.sym/room file is
// the source of truth across launchd/spawn restarts; the daemon reads it (or
// SYM_ROOM env) at startup and maps the name to a Bonjour service type that
// matches the MCP node + sym-swift, so peers in the same room discover each
// other. See lib/rooms.js.

function flagValue(name) {
  const i = args.indexOf(name);
  return i !== -1 ? (args[i + 1] || '') : null;
}

function persistRoom(room) {
  const dir = path.dirname(ROOM_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(ROOM_FILE, room + '\n');
}

function readRoom() {
  try { return fs.readFileSync(ROOM_FILE, 'utf8').trim() || 'default'; }
  catch { return 'default'; }
}

function persistRelay(url, token) {
  const dir = path.join(os.homedir(), '.sym');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const f = path.join(dir, 'relay.env');
  const kv = {};
  try {
    for (const line of fs.readFileSync(f, 'utf8').split('\n')) {
      const m = line.match(/^([A-Z_]+)=(.*)$/);
      if (m) kv[m[1]] = m[2];
    }
  } catch {}
  if (url) kv.SYM_RELAY_URL = url;
  if (token) kv.SYM_RELAY_TOKEN = token;
  fs.writeFileSync(f, Object.entries(kv).map(([k, v]) => `${k}=${v}`).join('\n') + '\n');
}

// Validate + persist --room / --relay-url / --relay-token before a launch.
function applyStartFlags() {
  const g = flagValue('--room');
  if (g !== null) {
    if (!isValidRoom(g)) {
      console.error(`Invalid room "${g}" — use kebab-case (e.g. backend-team) or "default".`);
      process.exit(1);
    }
    persistRoom(g);
  }
  const url = flagValue('--relay-url');
  const token = flagValue('--relay-token');
  if (url || token) persistRelay(url, token);
}

// Launch the daemon (no running-check). Passes SYM_ROOM in env for the
// spawn path (Linux/immediate); the persisted file covers launchd (macOS).
function spawnDaemon() {
  const daemonPath = path.join(__dirname, 'sym-daemon.js');
  const env = { ...process.env, SYM_ROOM: readRoom() };
  if (process.platform === 'darwin') {
    try {
      execSync(`node "${daemonPath}" --install`, { stdio: 'inherit', env });
    } catch (err) {
      console.error('Failed to start daemon:', err.message);
      process.exit(1);
    }
  } else {
    const child = spawn(process.execPath, [daemonPath], { detached: true, stdio: 'ignore', env });
    child.unref();
    // Track the pid so `sym stop` works without `pgrep` (absent on Windows).
    try { fs.writeFileSync(PID_FILE, String(child.pid)); } catch {}
    console.log(`sym-daemon started (pid ${child.pid})`);
  }
  console.log(`room: ${readRoom()}`);
}

// Restart the daemon into a (newly persisted) room.
function restartIntoRoom(room, doneMsg) {
  persistRoom(room);
  if (isDaemonRunning()) {
    cmdStop();
    sleepMs(1000);   // let the old node fully release the socket (portable)
  }
  spawnDaemon();
  console.log(doneMsg);
}

function cmdJoin() {
  const g = args[1];
  if (!g) { console.error('Usage: sym join <room>   (kebab-case, or "default")'); process.exit(1); }
  if (!isValidRoom(g)) {
    console.error(`Invalid room "${g}" — use kebab-case (e.g. backend-team) or "default".`);
    process.exit(1);
  }
  restartIntoRoom(g, `joined room "${g}".`);
}

function cmdLeave() {
  restartIntoRoom('default', 'left — back on the default mesh (_sym._tcp).');
}

function cmdRoom() {
  const g = readRoom();
  console.log(`current room: ${g}   (${roomServiceType(g)})`);
}

// Discover SYM-mesh rooms with at least one node online on this LAN.
// Mirrors the MCP node's discovery (dns-sd on macOS/Windows, avahi on Linux).
// Discover SYM rooms live on the LAN. Browses the shared `_symrooms._tcp`
// beacon every running node advertises (room name in TXT) via the pure-JS
// bonjour-service — works cross-platform, including Windows where Apple's
// dns-sd is absent. Each live node publishes its room; we list the distinct
// rooms (room names may be opaque/anonymous codes — we just show what's
// advertised). Discovery-only; comms stay isolated per room.
function cmdRooms() {
  let Bonjour;
  try { ({ Bonjour } = require('bonjour-service')); }
  catch (e) { console.error(`room discovery unavailable: ${e.message}`); return; }

  const bonjour = new Bonjour();
  const rooms = new Map();   // room name -> Set(node names)
  let browser;
  try {
    browser = bonjour.find({ type: 'symrooms' }, (svc) => {
      const txt = svc.txt || {};
      const g = txt.room != null ? String(txt.room) : null;
      const n = txt.node != null ? String(txt.node) : (svc.name || '?');
      if (g) {
        if (!rooms.has(g)) rooms.set(g, new Set());
        rooms.get(g).add(n);
      }
    });
  } catch (e) {
    try { bonjour.destroy(); } catch {}
    console.error(`room discovery failed: ${e.message}`);
    return;
  }

  setTimeout(() => {
    try { if (browser && browser.stop) browser.stop(); bonjour.destroy(); } catch {}
    const current = readRoom();
    if (rooms.size === 0) {
      console.log('No SYM rooms visible on the LAN right now (only rooms with a live node appear).');
      console.log(`Your room: ${current}  ·  switch with: sym join <name>`);
      return;
    }
    console.log(`SYM rooms live on the LAN (${rooms.size}):`);
    for (const [g, nodes] of [...rooms.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
      const mark = g === current ? '   <- your room' : '';
      console.log(`  ${g.padEnd(22)} ${nodes.size} node(s): ${[...nodes].join(', ')}${mark}`);
    }
  }, 2200);
}

function cmdStop() {
  if (process.platform === 'darwin') {
    const daemonPath = path.join(__dirname, 'sym-daemon.js');
    try {
      execSync(`node "${daemonPath}" --uninstall`, { stdio: 'inherit' });
    } catch {
      console.log('sym-daemon is not running.');
    }
  } else {
    // Linux / Windows: kill the tracked daemon pid. Portable — no `pgrep`
    // (which is POSIX-only and absent on Windows). Falls back to pgrep on
    // Linux for daemons started before pid-tracking existed.
    let pid = null;
    try { pid = parseInt(fs.readFileSync(PID_FILE, 'utf8').trim(), 10) || null; } catch {}
    if (!pid && process.platform !== 'win32') {
      try { pid = parseInt(execSync('pgrep -f sym-daemon.js', { encoding: 'utf8' }).trim(), 10) || null; } catch {}
    }
    if (pid) {
      try { process.kill(pid, 'SIGTERM'); console.log('sym-daemon stopped.'); }
      catch { console.log('sym-daemon is not running.'); }
      try { fs.unlinkSync(PID_FILE); } catch {}
    } else {
      console.log('sym-daemon is not running.');
    }
  }
}


/**
 * Parse `sym publish` flags out of the positional args. Returns
 * { positional, standalone, name, parents } where `positional` is
 * the remaining non-flag args (the JSON payload).
 *
 * Flags:
 *   --standalone          Force standalone (daemon-less) emission.
 *                         Also automatically enabled when the daemon
 *                         is not running, or when --parents is used.
 *   --name <id>           Node name / mesh identity for standalone
 *                         emission. NO DEFAULT — falls back to SYM_NODE_NAME,
 *                         and refuses if neither is set. Claude Code
 *                         users typically pass --name claude-code-mac
 *                         (or claude-code-win) so their CMBs are
 *                         attributable on the mesh grid.
 *   --parents <keys>      Comma-separated parent CMB keys for remix
 *                         lineage. Using this flag implies --standalone
 *                         because the daemon IPC `remember` handler
 *                         does not accept lineage parents.
 */
function parseObserveFlags(argv) {
  // NO INVENTED DEFAULT IDENTITY (D-04). This used to default to the literal string `sym-cli`,
  // which meant that whenever the daemon was down the CLI published under an agent nobody chose
  // and nobody had earned anything as. Resolve a REAL identity or resolve nothing; the caller
  // below refuses rather than inventing one.
  const out = { positional: [], standalone: false, name: process.env.SYM_NODE_NAME || null, parents: [] };
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--standalone') { out.standalone = true; }
    else if (a === '--name') { out.name = argv[++i] || out.name; }
    else if (a === '--parents') {
      out.parents = (argv[++i] || '').split(',').map(s => s.trim()).filter(Boolean);
      out.standalone = true;  // lineage requires the standalone SymNode path
    }
    else { out.positional.push(a); }
  }
  return out;
}

/**
 * sym emit — one-shot MMP Class 1 emitter (§17.1): deliver a signed CAT7
 * block to a REMOTE mesh node over TCP. No daemon, no store, no identity
 * lock — the light door for CI jobs, sensors, and scripts. Contrast with
 * `sym publish`, which speaks AS this machine's resident node via IPC.
 */
async function cmdEmit() {
  const flags = { server: null, room: 'default', name: 'emitter', to: null, parents: [] };
  const positional = [];
  for (let i = 1; i < args.length; i++) {
    const a = args[i];
    if (a === '--server') flags.server = args[++i];
    else if (a === '--room') flags.room = args[++i];
    else if (a === '--name') flags.name = args[++i];
    else if (a === '--to') flags.to = args[++i];
    else if (a === '--parents') flags.parents = String(args[++i] || '').split(',').filter(Boolean);
    else positional.push(a);
  }
  const content = positional.join(' ');
  if (!flags.server || !content) {
    console.error('Usage: sym emit --server <host:port> [--room <g>] [--name <id>] [--to <node>] [--parents <k1,k2>] \'{"focus":"...",...}\'');
    console.error('  Emits ONE signed v1 block to a remote mesh node and exits (MMP §17.1 Class 1).');
    console.error('  Grounding from CI: --parents <cmb-key> with categories {"intent":"ground","commitment":"verified: ..."}');
    process.exit(1);
  }
  let categories;
  try { categories = JSON.parse(content); } catch {
    console.error('Error: content must be a JSON object with CAT7 categories.');
    process.exit(1);
  }
  const { emitOnce } = require('../lib/emit');
  const { key } = await emitOnce(
    { server: flags.server, room: flags.room, name: flags.name },
    categories,
    { to: flags.to || undefined, parents: flags.parents },
  );
  console.log(`Emitted ${key}`);
  console.log(`  as ${flags.name} → ${flags.server} (room: ${flags.room}${flags.to ? `, to: ${flags.to}` : ''})`);
}

function cmdPublish() {
  const parsed = parseObserveFlags(args);
  const content = parsed.positional.join(' ');

  if (!content) {
    console.error('Usage: sym publish [--standalone] [--name <id>] [--parents <key1,key2>] \'{"focus":"...","mood":{"text":"...","valence":0,"arousal":0},...}\'');
    console.error('  The calling agent (LLM) extracts CAT7 categories. The protocol does not parse raw text.');
    console.error('  --standalone: emit without sym-daemon running (one-shot SymNode). Auto-enabled if daemon is down.');
    console.error('  --name:       mesh identity for standalone mode. REQUIRED (or set SYM_NODE_NAME).');
    console.error('                Claude Code users: --name claude-code-mac (or claude-code-win).');
    console.error('  --parents:    comma-separated parent CMB keys for remix lineage. Implies --standalone.');
    process.exit(1);
  }

  let categories;
  try {
    categories = JSON.parse(content);
  } catch {
    console.error('Error: content must be a JSON object with CAT7 categories.');
    console.error('  The agent LLM is responsible for extracting categories from observations.');
    process.exit(1);
  }

  // Decide which path to use:
  //   - Explicit --standalone  → standalone
  //   - --parents supplied     → standalone (lineage not plumbed through daemon IPC)
  //   - Daemon not running     → standalone (graceful fallback, not a failure)
  //   - Otherwise              → daemon IPC (fast path, preserves local CfC state)
  const useStandalone = parsed.standalone || !isDaemonRunning();

  // REFUSE RATHER THAN INVENT AN IDENTITY (D-04).
  //
  // Standalone emission mints a CMB signed by whatever identity it is told to use. When that
  // defaulted to `sym-cli`, a daemon that happened to be down silently rerouted a node's whole
  // output through an agent it never chose — the CMBs are real, signed and delivered, and
  // attributed to somebody else. On 2026-08-01 an entire day of CTO-seat coordination went out
  // this way: peers received rulings and gate verdicts from `sym-cli`, and they only made sense
  // because the author's name happened to be repeated in the CAT7 text. That is the
  // holder-vs-author defect the record model removed `source` to prevent, reintroduced one layer
  // up — identity carried in prose instead of in a key.
  //
  // This is the same ruling as halt-on-missing-identity, applied to emission rather than to
  // startup: an agent with no identity does not get a substitute, it gets an error. Note the
  // lease is NOT the failure mode being handled here — if another process holds the requested
  // identity, SymNode already refuses loudly and correctly. The failure being closed is the
  // quiet one, where nothing refuses because a name was manufactured to satisfy the call.
  if (useStandalone && !parsed.name) {
    console.error('Refusing to publish: no mesh identity resolved.');
    console.error('');
    console.error('  Standalone emission signs the CMB as some agent, and this command will not');
    console.error('  invent one. A block attributed to an agent nobody chose is worse than no');
    console.error('  block: it is indistinguishable from a real assertion by a real peer.');
    console.error('');
    console.error('  Pass --name <agent@mesh>, or set SYM_NODE_NAME.');
    process.exit(2);
  }

  if (useStandalone) {
    standaloneObserve(categories, { name: parsed.name, parents: parsed.parents })
      .catch((err) => {
        console.error('Standalone publish failed:', err.message || err);
        process.exit(2);
      });
    return;
  }

  cmdIPC({ type: 'remember', categories }, (res) => {
    if (res.duplicate) {
      console.log('Already shared (duplicate CMB).');
    } else {
      console.log(`Shared: ${res.key || ''}`);
    }
  });
}

/**
 * Daemon-less one-shot CMB emission. Spins up a fresh SymNode inside
 * the CLI process, connects to the relay using credentials from
 * ~/.sym/relay.env (or %USERPROFILE%\.sym\relay.env on Windows), emits
 * one CMB with optional remix lineage, waits briefly for propagation,
 * and disconnects.
 *
 * This is the same pattern persistent MeshAgent-based agents use
 * (sym/lib/mesh-agent.js), just scoped to a single emission. It lets
 * any user run `sym publish` without starting sym-daemon first — the
 * daemon is an optimisation, not a requirement.
 *
 * Node identity is stable across invocations: the SymIdentity layer
 * persists the keypair to ~/.sym/nodes/<name>/identity.json, so
 * repeated calls with the same --name resolve to the same nodeId.
 *
 * Ships CAT7 category vectors via SymNode's internal encoder — the caller
 * only needs to supply text (and valence/arousal for mood).
 */
async function standaloneObserve(categories, opts) {
  const { SymNode } = require('..');

  // Load relay credentials from ~/.sym/relay.env if the env vars are
  // not already present. Same pattern as MeshAgent (sym/lib/mesh-agent.js:160).
  if (!process.env.SYM_RELAY_URL || !process.env.SYM_RELAY_TOKEN) {
    const envFile = path.join(os.homedir(), '.sym', 'relay.env');
    if (fs.existsSync(envFile)) {
      for (const line of fs.readFileSync(envFile, 'utf8').split('\n')) {
        const m = line.match(/^(\w+)=(.*)$/);
        if (m && !process.env[m[1]]) process.env[m[1]] = m[2].trim();
      }
    }
  }
  if (!process.env.SYM_RELAY_URL) {
    throw new Error(`SYM_RELAY_URL not set (checked ~/.sym/relay.env)`);
  }
  if (!process.env.SYM_RELAY_TOKEN) {
    throw new Error(`SYM_RELAY_TOKEN not set (checked ~/.sym/relay.env)`);
  }

  // Normalise CAT7 categories. Callers may pass scalar strings for the
  // six non-mood categories (as the daemon-IPC path historically accepts),
  // but the SymNode.remember() API expects { text, vector } objects —
  // the vector is synthesised on the node side by the encoder, so we
  // only need to lift scalar strings into { text } objects here.
  const normaliseField = (v) => {
    if (v == null) return undefined;
    if (typeof v === 'string') return { text: v };
    if (typeof v === 'object') return v;
    return { text: String(v) };
  };
  const normalised = {};
  for (const key of ['focus', 'issue', 'intent', 'motivation', 'commitment', 'perspective', 'mood']) {
    const v = normaliseField(categories[key]);
    if (v !== undefined) normalised[key] = v;
  }
  if (!normalised.mood || typeof normalised.mood.text !== 'string') {
    throw new Error('categories.mood.text is required (MMP §9.3 protocol guarantee R5)');
  }

  const node = new SymNode({
    name: opts.name,
    cognitiveProfile:
      `sym-cli one-shot participant (${process.platform}). Emits single CMBs ` +
      'via `sym publish` without a persistent daemon. Identity is stable ' +
      'across invocations via the cached keypair in ~/.sym/nodes/.',
    svafFieldWeights: {
      focus: 2.0, issue: 1.5, intent: 1.5,
      motivation: 1.0, commitment: 1.2, perspective: 1.0, mood: 0.8,
    },
    svafFreshnessSeconds: 43200,
    relay: process.env.SYM_RELAY_URL,
    relayToken: process.env.SYM_RELAY_TOKEN,
    lifecycleRole: 'participant',
    silent: true,
  });

  try {
    await node.start();
  } catch (err) {
    throw new Error(`node.start() failed: ${err.message}`);
  }

  // Let the handshake settle before emitting. Without this, fast-exit
  // processes can tear down the socket before the relay queues the
  // outbound CMB frame.
  await new Promise((r) => setTimeout(r, 1500));

  // Build parent CMB stubs for lineage. The remember() lineage logic
  // (sym/lib/node.js:566-570) walks `.key` and `.lineage?.ancestors`
  // on each parent, so a minimal `{ key, lineage: null }` stub is
  // sufficient when the caller only has parent keys (not full CMBs).
  const parentCMBs = (opts.parents || []).map((k) => ({ key: k, lineage: null }));

  let entry;
  try {
    entry = node.remember(normalised, {
      tags: [opts.name, 'sym-cli', 'standalone'],
      parents: parentCMBs,
    });
  } catch (err) {
    await node.stop().catch(() => {});
    throw new Error(`node.remember() threw: ${err.message}`);
  }

  if (!entry) {
    await node.stop().catch(() => {});
    throw new Error('node.remember() returned null — remix rejected or store write failed');
  }

  // Give the relay a moment to broadcast the CMB to peers before we
  // tear down the socket. Without this, peers can miss the envelope.
  await new Promise((r) => setTimeout(r, 1500));

  try {
    await node.stop();
  } catch {
    // non-fatal
  }

  console.log(`Shared: ${entry.key}`);
}

/**
 * Federated recall — scan all local node cmbs stores directly from
 * the CLI process. The CLI-host daemon does not store CMBs (cliHostMode);
 * each running agent stores its own copy. We dedupe by CMB key (each CMB
 * has a unique content-addressable key, so the same CMB landing in 5
 * agents collapses to 1 result).
 *
 * Works even when the daemon is down. No IPC dependency.
 *
 * Optional --node <name> filter scopes the scan to one node directory.
 */
function cmdRecall() {
  const fs = require('fs');
  const path = require('path');
  const os = require('os');

  const recallArgs = args.slice(1).filter(a => a !== '--json');
  const limitIdx = recallArgs.indexOf('--limit');
  let limit = 50;
  if (limitIdx !== -1) {
    limit = parseInt(recallArgs[limitIdx + 1]) || 50;
    recallArgs.splice(limitIdx, 2);
  }
  const nodeIdx = recallArgs.indexOf('--node');
  let nodeFilter = null;
  if (nodeIdx !== -1) {
    nodeFilter = recallArgs[nodeIdx + 1];
    recallArgs.splice(nodeIdx, 2);
  }
  const query = recallArgs.join(' ').toLowerCase();

  const nodesDir = path.join(os.homedir(), '.sym', 'nodes');
  if (!fs.existsSync(nodesDir)) {
    console.log('No memories found.');
    return;
  }

  const nodeNames = nodeFilter
    ? [nodeFilter]
    : fs.readdirSync(nodesDir).filter(n => fs.statSync(path.join(nodesDir, n)).isDirectory());

  const seen = new Map(); // cmbKey → entry
  for (const nodeName of nodeNames) {
    const memDir = path.join(nodesDir, nodeName, 'cmbs');
    if (!fs.existsSync(memDir)) continue;
    let files;
    try { files = fs.readdirSync(memDir); } catch { continue; }
    for (const file of files) {
      if (!file.startsWith('cmb') || !file.endsWith('.json')) continue;
      const key = file.slice(0, -5);
      if (seen.has(key)) continue;
      try {
        const raw = fs.readFileSync(path.join(memDir, file), 'utf8');
        const entry = JSON.parse(raw);
        const content = entry.content || '';
        if (query && !content.toLowerCase().includes(query)) continue;
        seen.set(key, {
          key,
          timestamp: entry.storedAt || entry.timestamp || 0,
          content,
          source: entry.source || recordCreatedBy(entry.cmb) || 'unknown',
          tags: entry.tags,
          _node: nodeName,
        });
      } catch {}
    }
  }

  const results = [...seen.values()]
    .sort((a, b) => b.timestamp - a.timestamp)
    .slice(0, limit);

  if (jsonFlag) {
    console.log(JSON.stringify({ results }));
    return;
  }
  if (results.length === 0) {
    console.log('No memories found.');
    return;
  }
  for (const r of results) {
    const time = r.timestamp ? new Date(r.timestamp).toLocaleString() : '';
    console.log(`  ${dim(time)}  ${dim('[' + r._node + ']')} ${r.content}`);
    if (r.tags) console.log(`    ${dim('tags: ' + r.tags)}`);
  }
}

function cmdSend() {
  const message = args.slice(1).join(' ');
  if (!message) {
    console.error('Usage: sym send <message>');
    process.exit(1);
  }
  cmdIPC({ type: 'send', message }, (msg) => {
    console.log(`Message sent to ${msg.peers || 0} peer(s).`);
  });
}

/**
 * `sym ask "<question>"` — ask the whole mesh one question, get one answer.
 *
 * This is the headline experience: you ask the mesh directly. It (1) broadcasts
 * the question so live agents can contribute, (2) gathers what the mesh already
 * knows — the contributions every peer has fused into shared memory — and
 * (3) synthesizes one answer with the configured LLM provider, citing which
 * agents informed it. With no provider configured it prints the raw
 * contributions instead of erroring, so it always tells you something.
 */
// End `sym ask` without forcing teardown mid-close. Calling process.exit()
// while the synthesis transport (a spawned claude subprocess's stdio pipes,
// or a fetch socket) is still closing trips a libuv assertion on Windows
// (UV_HANDLE_CLOSING -> exit 0xC0000409). So prefer a natural drain — set the
// code and return — with a deferred, unref'd fallback that force-exits only if
// some idle keep-alive handle lingers, by which point the closing handle is
// long gone (so the force-exit can't hit the assertion either).
function endAsk() {
  process.exitCode = 0;
  const t = setTimeout(() => process.exit(0), 300);
  if (t && t.unref) t.unref();
}

async function cmdAsk() {
  const askArgs = args.slice(1).filter((a) => a !== '--json' && a !== '--raw');
  const rawOnly = args.includes('--raw');
  const question = askArgs.join(' ').trim();
  if (!question) {
    console.error('Usage: sym ask "<question>"');
    process.exit(1);
  }

  // 1. Broadcast the question so live agents on the mesh can contribute
  //    (and it's logged with lineage). Best-effort — never blocks the answer.
  await broadcastQuestion(question).catch(() => {});

  // 2. Gather what the mesh already knows.
  const contributions = gatherMeshMemory(question, 12);

  // 3. Synthesize one answer — or fall back to the raw contributions.
  const llm = require('../lib/llm-reason');
  if (!rawOnly && llm.hasProvider() && contributions.length > 0) {
    try {
      const ctx = contributions.map((c) => `- [${c.source}] ${c.content}`).join('\n');
      const systemPrompt =
        'You are the collective voice of a mesh of AI agents. Answer the user using ONLY the agent contributions provided. ' +
        'After each claim, cite the agent that supports it in brackets, e.g. [inventory-agent]. ' +
        'If the contributions do not answer the question, say so plainly and name what is missing. Be concise and direct.';
      const prompt = `Question: ${question}\n\nAgent contributions from the mesh:\n${ctx}\n\nAnswer:`;
      const { text } = await llm.complete({ systemPrompt, prompt });
      const agents = new Set(contributions.map((c) => c._node)).size;
      console.log('\n' + (text || '').trim() + '\n');
      console.log(dim(`  — synthesized from ${contributions.length} contribution(s) across ${agents} agent(s) on the mesh`));
      return endAsk();
    } catch (err) {
      console.error(dim(`  (synthesis failed: ${(err.message || '').slice(0, 120)} — showing raw contributions)`));
      printContributions(question, contributions, true);
      return endAsk();
    }
  }

  // No provider, --raw, or nothing gathered: show what the mesh knows.
  printContributions(question, contributions, llm.hasProvider());
  return endAsk();
}

/**
 * Broadcast a question to the mesh, best-effort. Resolves false (never throws)
 * if the daemon is down or slow — `sym ask` still answers from stored memory.
 */
function broadcastQuestion(question) {
  return new Promise((resolve) => {
    if (!isDaemonRunning()) return resolve(false);
    let settled = false;
    let timer = null;
    // socket.destroy() (not .end()) — fully tears down the handle synchronously
    // so no named-pipe handle is left mid-close when `sym ask` later exits.
    // On Windows, exiting with a half-closed handle trips a libuv assertion
    // (UV_HANDLE_CLOSING, win/async.c) and aborts with 0xC0000409.
    const finish = (v) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      try { socket.removeAllListeners('data'); socket.destroy(); } catch {}
      resolve(v);
    };
    const socket = net.createConnection(SOCKET_PATH, () => {
      socket.write(JSON.stringify({ type: 'register', name: 'sym-cli' }) + '\n');
    });
    let buffer = '';
    socket.on('data', (data) => {
      buffer += data.toString();
      let idx;
      while ((idx = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, idx); buffer = buffer.slice(idx + 1);
        if (!line.trim()) continue;
        try {
          const res = JSON.parse(line);
          if (res.type === 'registered') {
            socket.write(JSON.stringify({ type: 'send', message: question }) + '\n');
          } else if (res.type === 'result') {
            finish(true); return;
          }
        } catch {}
      }
    });
    socket.on('error', () => finish(false));
    timer = setTimeout(() => finish(false), 2000);
  });
}

/**
 * Scan the local mesh memory store for contributions relevant to a question.
 * Scores each CMB by how many question keywords it contains; falls back to the
 * most recent memories when nothing matches, so `ask` always has context.
 */
function gatherMeshMemory(question, limit) {
  const nodesDir = path.join(os.homedir(), '.sym', 'nodes');
  if (!fs.existsSync(nodesDir)) return [];
  const words = question.toLowerCase().split(/[^a-z0-9]+/).filter((w) => w.length > 2);

  const seen = new Map();
  let nodeNames = [];
  try {
    nodeNames = fs.readdirSync(nodesDir).filter((n) => {
      try { return fs.statSync(path.join(nodesDir, n)).isDirectory(); } catch { return false; }
    });
  } catch { return []; }

  for (const nodeName of nodeNames) {
    const memDir = path.join(nodesDir, nodeName, 'cmbs');
    if (!fs.existsSync(memDir)) continue;
    let files;
    try { files = fs.readdirSync(memDir); } catch { continue; }
    for (const file of files) {
      if (!file.startsWith('cmb') || !file.endsWith('.json')) continue;
      const key = file.slice(0, -5);
      if (seen.has(key)) continue;
      try {
        const entry = JSON.parse(fs.readFileSync(path.join(memDir, file), 'utf8'));
        const content = (entry.content || '').trim();
        if (!content) continue;
        const lc = content.toLowerCase();
        let score = 0;
        for (const w of words) { if (lc.includes(w)) score++; }
        seen.set(key, {
          content,
          source: entry.source || recordCreatedBy(entry.cmb) || nodeName,
          _node: nodeName,
          timestamp: entry.storedAt || entry.timestamp || 0,
          score,
        });
      } catch {}
    }
  }

  const all = [...seen.values()];
  const matched = all.filter((c) => c.score > 0).sort((a, b) => b.score - a.score || b.timestamp - a.timestamp);
  const pool = matched.length > 0 ? matched : all.sort((a, b) => b.timestamp - a.timestamp);
  return pool.slice(0, limit).map((c) => ({
    ...c,
    content: c.content.length > 400 ? c.content.slice(0, 400) + '…' : c.content,
  }));
}

/** Print the gathered contributions when there's no synthesis (no provider / --raw). */
function printContributions(question, contributions, hasProvider) {
  if (contributions.length === 0) {
    console.log('The mesh has nothing relevant yet. As your agents share what they learn, sym ask will draw on it.');
    return;
  }
  console.log(`\nWhat the mesh knows about "${question}":\n`);
  for (const c of contributions) {
    console.log(`  ${dim('[' + c.source + ']')} ${c.content}`);
  }
  if (!hasProvider) {
    console.log('\n' + dim('No LLM provider configured, so these are the raw contributions. Set ANTHROPIC_API_KEY / OPENAI_API_KEY / SYM_LLM_API_KEY (or SYM_LLM_PROVIDER=claude-cli) to get one synthesized answer.'));
  }
}

function cmdListen() {
  if (!isDaemonRunning()) {
    console.error('sym-daemon is not running. Start it with: sym start');
    process.exit(1);
  }
  const socket = net.createConnection(SOCKET_PATH, () => {
    socket.write(JSON.stringify({ type: 'listen' }) + '\n');
  });
  let buffer = '';
  socket.on('data', (data) => {
    buffer += data.toString();
    let idx;
    while ((idx = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 1);
      if (!line.trim()) continue;
      try {
        const msg = JSON.parse(line);
        if (msg.action === 'listen') {
          console.log('Listening for mesh events... (Ctrl+C to stop)');
          continue;
        }
        if (msg.event === 'cmb-accepted') {
          const d = msg.data;
          console.log(`[${d.source}] ${d.focus}`);
        } else if (msg.event === 'message') {
          const d = msg.data;
          console.log(`[message from ${d.from}] ${d.content}`);
        } else if (msg.event === 'peer-joined') {
          console.log(`[+] ${msg.data.name} joined`);
        } else if (msg.event === 'peer-left') {
          console.log(`[-] ${msg.data.name} left`);
        } else if (jsonFlag) {
          console.log(JSON.stringify(msg));
        }
      } catch {}
    }
  });
  socket.on('error', (err) => {
    console.error(`Connection error: ${err.message}`);
    process.exit(1);
  });
  socket.on('close', () => {
    console.log('Disconnected from daemon.');
    process.exit(0);
  });
  process.on('SIGINT', () => { socket.destroy(); process.exit(0); });
}

function cmdTask() {
  const sub = args[1]; // create, list, update, assign
  if (sub === 'create') {
    const title = args.slice(2).join(' ');
    cmdIPC({ type: 'task-create', title, agent: 'unassigned' }, (msg) => {
      console.log(`Task created: ${msg.task?.id} — "${msg.task?.title}"`);
    });
  } else if (sub === 'assign') {
    const id = args[2];
    const agent = args[3];
    cmdIPC({ type: 'task-update', id, agent, status: 'assigned' }, (msg) => {
      if (msg.error) { console.log(`Error: ${msg.error}`); return; }
      console.log(`Task ${id} assigned to ${agent}`);
    });
  } else if (sub === 'done') {
    const id = args[2];
    const actor = actorFlag || 'system';
    cmdIPC({ type: 'task-update', id, status: 'done', actor }, (msg) => {
      if (msg.error) { console.log(`Error: ${msg.error}`); return; }
      console.log(`Task ${id} marked done`);
    });
  } else if (sub === 'move') {
    const id = args[2];
    const status = args[3];
    const actor = actorFlag || 'system';
    cmdIPC({ type: 'task-update', id, status, actor }, (msg) => {
      if (msg.error) { console.log(`Error: ${msg.error}`); return; }
      console.log(`Task ${id} moved to ${status}`);
    });
  } else {
    // Default: list
    cmdIPC({ type: 'task-list' }, jsonFlag ? formatJSON : (msg) => {
      const tasks = msg.tasks || [];
      if (tasks.length === 0) { console.log('No tasks.'); return; }
      for (const t of tasks) {
        console.log(`  [${t.status}] ${t.id} → ${t.agent}: ${t.title}`);
      }
    });
  }
}

function cmdLogs() {
  const logFile = path.join(LOG_DIR, 'stdout.log');
  if (!fs.existsSync(logFile)) {
    console.error(`No logs found at ${LOG_DIR}/`);
    process.exit(1);
  }
  const child = spawn('tail', ['-f', '-n', '50', logFile], { stdio: 'inherit' });
  process.on('SIGINT', () => { child.kill(); process.exit(0); });
}

// ── Formatters ────────────────────────────────────────────────

function formatJSON(msg) {
  // Strip IPC wrapper, output clean JSON for programmatic consumers
  const { type, action, ...data } = msg;
  console.log(JSON.stringify(data));
}

function formatStatus(msg) {
  const s = msg.status || {};
  console.log(`sym-daemon: ${bold('running')}`);
  console.log(`  node:     ${s.name || '?'} ${dim(s.nodeId ? '(' + s.nodeId.slice(0, 8) + ')' : '')}`);
  console.log(`  relay:    ${s.relayConnected ? green('connected') : dim('disconnected')} ${dim(s.relay || '')}`);
  console.log(`  peers:    ${s.peerCount || 0}`);
  console.log(`  memories: ${s.memoryCount || 0}`);
  const vn = msg.virtualNodes || [];
  console.log(`  virtual:  ${vn.length > 0 ? vn.join(', ') : dim('none')}`);
}

function formatPeers(msg) {
  const peers = msg.peers || [];
  if (peers.length === 0) {
    console.log('No peers connected.');
    return;
  }
  console.log(`${peers.length} peer(s):\n`);
  for (const p of peers) {
    const via = p.via || (p.relay ? 'relay' : 'lan');
    console.log(`  ${bold(p.name || p.nodeId)} ${dim('via ' + via)}`);
    if (p.mood) console.log(`    mood: ${p.mood}`);
  }
}

function formatMetrics(msg) {
  const m = msg.metrics || {};
  console.log('Mesh Metrics:\n');
  console.log(`  CMBs produced:    ${m.cmbProduced || 0}`);
  console.log(`  CMBs accepted:    ${m.cmbAccepted || 0}`);
  console.log(`  Remixes produced: ${m.remixProduced || 0}`);
  console.log(`  Remixes rejected: ${m.remixRejected || 0}`);
  console.log(`  Peers joined:     ${m.peersJoined || 0}`);
  console.log(`  Peers left:       ${m.peersLeft || 0}`);
  console.log(`  Recalls:          ${m.recalls || 0}`);
  console.log(`  LLM calls:        ${m.llmCalls || 0}`);
  console.log(`  LLM tokens in:    ${(m.llmTokensIn || 0).toLocaleString()}`);
  console.log(`  LLM tokens out:   ${(m.llmTokensOut || 0).toLocaleString()}`);
  console.log(`  LLM model:        ${m.llmModel || 'none'}`);
  console.log(`  LLM cost:         $${(m.llmCostUSD || 0).toFixed(6)}`);
  const uptimeH = Math.floor((m.uptimeMs || 0) / 3600000);
  const uptimeM = Math.floor(((m.uptimeMs || 0) % 3600000) / 60000);
  console.log(`  Uptime:           ${uptimeH}h ${uptimeM}m`);
}

function formatInsight(msg) {
  const ctx = msg.context || {};
  if (!ctx.trajectory && !ctx.anomaly && !ctx.insights) {
    console.log('No collective intelligence available yet.');
    return;
  }
  console.log(bold('Collective Intelligence\n'));
  if (ctx.trajectory) console.log(`  trajectory:  ${ctx.trajectory}`);
  if (ctx.anomaly) console.log(`  anomaly:     ${ctx.anomaly}`);
  if (ctx.prediction) console.log(`  prediction:  ${ctx.prediction}`);
  if (ctx.insights && ctx.insights.length > 0) {
    console.log(`\n  insights:`);
    for (const i of ctx.insights) {
      console.log(`    - ${i}`);
    }
  }
}

// ── IPC Transport ─────────────────────────────────────────────

function cmdIPC(msg, formatter) {
  if (!isDaemonRunning()) {
    console.error('sym-daemon is not running. Start it with: sym start');
    process.exit(1);
  }

  const socket = net.createConnection(SOCKET_PATH, () => {
    // For status, no registration needed — send raw
    if (msg.type === 'status') {
      socket.write(JSON.stringify(msg) + '\n');
      return;
    }

    // Register first, then send command
    socket.write(JSON.stringify({ type: 'register', name: 'sym-cli' }) + '\n');
  });

  let buffer = '';
  let registered = false;

  function done() {
    clearTimeout(timer);
    socket.end();
  }

  socket.on('data', (data) => {
    buffer += data.toString();
    let idx;
    while ((idx = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 1);
      if (!line.trim()) continue;

      try {
        const res = JSON.parse(line);

        // Handle status response (no registration)
        if (msg.type === 'status' && res.type === 'result') {
          formatter(res);
          done();
          return;
        }

        // Handle registration
        if (res.type === 'registered' && !registered) {
          registered = true;
          socket.write(JSON.stringify(msg) + '\n');
          return;
        }

        // Handle command result
        if (res.type === 'result') {
          formatter(res);
          done();
          return;
        }
      } catch {}
    }
  });

  socket.on('error', (err) => {
    clearTimeout(timer);
    if (err.code === 'ENOENT' || err.code === 'ECONNREFUSED') {
      console.error('sym-daemon is not running. Start it with: sym start');
    } else {
      console.error('Connection error:', err.message);
    }
    process.exit(1);
  });

  const timer = setTimeout(() => {
    console.error('Timeout waiting for daemon response.');
    socket.destroy();
    process.exit(1);
  }, 5000);
}

function isDaemonRunning() {
  // fs.existsSync doesn't work for Windows named pipes (//./pipe/sym-daemon),
  // so on Windows check the tracked daemon pid for liveness instead of the
  // socket path. (Previously this returned `true` unconditionally, which made
  // `sym start` always think the daemon was already up.)
  if (process.platform === 'win32') {
    try {
      const pid = parseInt(fs.readFileSync(PID_FILE, 'utf8').trim(), 10);
      process.kill(pid, 0);   // throws if the process is gone
      return true;
    } catch { return false; }
  }
  return fs.existsSync(SOCKET_PATH);
}

// ── Terminal Formatting ───────────────────────────────────────

function bold(s) { return process.stdout.isTTY ? `\x1b[1m${s}\x1b[0m` : s; }
function dim(s) { return process.stdout.isTTY ? `\x1b[2m${s}\x1b[0m` : s; }
function green(s) { return process.stdout.isTTY ? `\x1b[32m${s}\x1b[0m` : s; }

// ── Usage ─────────────────────────────────────────────────────

function printUsage() {
  console.log(`
${bold('sym')} — local AI mesh for collective intelligence

${bold('Usage:')}
  sym start [--room <name>]         Start the mesh daemon (in a room; default = global mesh)
                                     Flags: --relay-url <url>, --relay-token <token>
  sym stop                           Stop the mesh daemon
  sym status                         Show mesh status
  sym peers                          List connected peers
  sym room                          Show the current room
  sym rooms                         Discover SYM-mesh rooms live on the LAN
  sym join <name>                    Switch into a room (kebab-case, or "default")
  sym leave                          Return to the default global mesh
  sym metrics                        Show protocol metrics and LLM cost
  sym publish [flags] <json>         Publish a projection (CAT7 categories as JSON)
                                     Flags: --standalone, --name <id>, --parents <keys>
  sym ask "<question>"               Ask the whole mesh one question, get one answer
                                     Flags: --raw (skip synthesis, show contributions)
  sym recall <query>                 Search mesh memory
  sym insight                        Get collective intelligence
  sym send <message>                 Send message to all peers
  sym logs                           Tail daemon logs
  sym version                        Show version

${bold('CAT7 categories:')}
  focus         What the observation is centrally about
  issue         Risks, gaps, open questions
  intent        Desired change or purpose
  motivation    Reasons, drivers, incentives
  commitment    Who will do what, by when
  perspective   Whose viewpoint, situational context
  mood          { text, valence (-1..1), arousal (-1..1) }

${bold('Examples:')}
  sym start
  sym publish '{"focus":"debugging auth","mood":{"text":"tired","valence":-0.4,"arousal":-0.3}}'
  sym recall "energy patterns"
  sym ask "should we use UUID v7 or keep v4?"
  sym insight

${bold('Daemon-less one-shot observations:')}
  # Works even when sym-daemon is not running. Auto-enabled if the
  # daemon is down; force with --standalone. Uses ~/.sym/relay.env
  # for relay credentials. Identity is stable across invocations via
  # the cached keypair in ~/.sym/nodes/<name>/.
  sym publish --standalone --name claude-code-mac \\
    '{"focus":"resolved 3 review board tickets","mood":{"text":"focused","valence":0.3,"arousal":0.2}}'

  # Remix with lineage (resolve upstream tickets). --parents implies --standalone.
  sym publish --name claude-code-mac --parents cmb-876bbd483a,cmb-c0d4332a \\
    '{"focus":"ANX+CFN positioning memo","intent":"resolve tickets","mood":{"text":"resolved","valence":0.3,"arousal":0.1}}'
`);
}
