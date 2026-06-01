#!/usr/bin/env node
'use strict';

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
 *   sym observe [flags] <json>        # Share observation (CAT7 fields as JSON)
 *                                     #   --standalone: daemon-less one-shot SymNode (auto-fallback if daemon is down)
 *                                     #   --name <id>:  mesh identity for standalone mode (default: sym-cli)
 *                                     #   --parents <keys>: comma-separated parent CMB keys (lineage, implies --standalone)
 *   sym recall <query>                # Search mesh memory
 *   sym ask "<question>"              # Ask the whole mesh; get one synthesized answer
 *   sym insight                       # Get xMesh collective intelligence
 *   sym send <message>                # Send message to all peers
 *   sym group                         # Show current mesh group
 *   sym groups                        # Discover groups live on the LAN
 *   sym join <name>                   # Switch into a group ("group chat")
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
const { isValidGroup, groupServiceType } = require('../lib/groups');
const GROUP_FILE = path.join(os.homedir(), '.sym', 'group');
const PID_FILE = path.join(os.homedir(), '.sym', 'daemon.pid');

// Portable synchronous sleep — no shell dependency (`sleep` is POSIX-only and
// absent on Windows). Used between daemon stop/start on a group switch.
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
  case 'observe': cmdObserve(); break;
  case 'recall':  cmdRecall(); break;
  case 'ask':     cmdAsk().catch((e) => { console.error(e.message); process.exit(1); }); break;
  case 'insight': cmdIPC({ type: 'xmesh-context' }, formatInsight); break;
  case 'send':    cmdSend(); break;
  case 'listen':  cmdListen(); break;
  case 'join':    cmdJoin(); break;
  case 'leave':   cmdLeave(); break;
  case 'groups':  cmdGroups(); break;
  case 'group':   cmdGroup(); break;
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
  applyStartFlags();                       // parse + persist --group / --relay-* first
  if (isDaemonRunning()) {
    console.log('sym-daemon is already running.');
    console.log(`group: ${readGroup()}`);
    return;
  }
  spawnDaemon();
}

// ── Mesh groups (MMP §5.8) ─────────────────────────────────────
// A group is the "group chat" boundary. The persisted ~/.sym/group file is
// the source of truth across launchd/spawn restarts; the daemon reads it (or
// SYM_GROUP env) at startup and maps the name to a Bonjour service type that
// matches the MCP node + sym-swift, so peers in the same group discover each
// other. See lib/groups.js.

function flagValue(name) {
  const i = args.indexOf(name);
  return i !== -1 ? (args[i + 1] || '') : null;
}

function persistGroup(group) {
  const dir = path.dirname(GROUP_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(GROUP_FILE, group + '\n');
}

function readGroup() {
  try { return fs.readFileSync(GROUP_FILE, 'utf8').trim() || 'default'; }
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

// Validate + persist --group / --relay-url / --relay-token before a launch.
function applyStartFlags() {
  const g = flagValue('--group');
  if (g !== null) {
    if (!isValidGroup(g)) {
      console.error(`Invalid group "${g}" — use kebab-case (e.g. backend-team) or "default".`);
      process.exit(1);
    }
    persistGroup(g);
  }
  const url = flagValue('--relay-url');
  const token = flagValue('--relay-token');
  if (url || token) persistRelay(url, token);
}

// Launch the daemon (no running-check). Passes SYM_GROUP in env for the
// spawn path (Linux/immediate); the persisted file covers launchd (macOS).
function spawnDaemon() {
  const daemonPath = path.join(__dirname, 'sym-daemon.js');
  const env = { ...process.env, SYM_GROUP: readGroup() };
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
  console.log(`group: ${readGroup()}`);
}

// Restart the daemon into a (newly persisted) group.
function restartIntoGroup(group, doneMsg) {
  persistGroup(group);
  if (isDaemonRunning()) {
    cmdStop();
    sleepMs(1000);   // let the old node fully release the socket (portable)
  }
  spawnDaemon();
  console.log(doneMsg);
}

function cmdJoin() {
  const g = args[1];
  if (!g) { console.error('Usage: sym join <group>   (kebab-case, or "default")'); process.exit(1); }
  if (!isValidGroup(g)) {
    console.error(`Invalid group "${g}" — use kebab-case (e.g. backend-team) or "default".`);
    process.exit(1);
  }
  restartIntoGroup(g, `joined group "${g}".`);
}

function cmdLeave() {
  restartIntoGroup('default', 'left — back on the default mesh (_sym._tcp).');
}

function cmdGroup() {
  const g = readGroup();
  console.log(`current group: ${g}   (${groupServiceType(g)})`);
}

// Discover SYM-mesh groups with at least one node online on this LAN.
// Mirrors the MCP node's discovery (dns-sd on macOS/Windows, avahi on Linux).
function cmdGroups() {
  const platform = process.platform;
  const cmd = (platform === 'linux') ? 'avahi-browse' : 'dns-sd';
  const argv = (platform === 'linux') ? ['-t', '-a', '-p'] : ['-B', '_services._dns-sd._udp', 'local.'];
  let child;
  try { child = spawn(cmd, argv, { stdio: ['ignore', 'pipe', 'pipe'] }); }
  catch (e) {
    console.error(`Could not run discovery ('${cmd}'): ${e.message}` +
      (platform === 'linux' ? '\nInstall avahi-utils: sudo apt install avahi-utils' : ''));
    return;
  }
  const out = [];
  child.stdout.on('data', (c) => out.push(c));
  child.on('error', (e) => console.error(`discovery failed: ${e.message}`));
  const timer = setTimeout(() => { try { child.kill('SIGTERM'); } catch {} }, 2200);
  child.on('close', () => {
    clearTimeout(timer);
    const text = Buffer.concat(out).toString('utf8');
    const typeRe = /_([a-z0-9][a-z0-9-]+)\._tcp/gi;
    const seen = new Set();
    let m;
    while ((m = typeRe.exec(text)) !== null) {
      const full = `_${m[1]}._tcp`;
      // SYM family only: global sym, named groups, app-scoped rooms.
      if (/^_(sym|[a-z0-9]+-[a-z0-9]+|[a-z0-9]+-team)\._tcp$/i.test(full)) seen.add(full);
    }
    const current = groupServiceType(readGroup());
    if (seen.size === 0) {
      console.log('No SYM-mesh groups visible on the LAN right now (only shows groups with a node online).');
      console.log(`Your group: ${readGroup()}  (${current})`);
      return;
    }
    console.log(`SYM-mesh groups on the LAN (${seen.size}):`);
    for (const st of [...seen].sort()) {
      const name = st.replace(/^_/, '').replace(/\._tcp$/, '');
      console.log(`  ${name.padEnd(20)} ${st}${st === current ? '   <- your group' : ''}`);
    }
  });
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
 * Parse `sym observe` flags out of the positional args. Returns
 * { positional, standalone, name, parents } where `positional` is
 * the remaining non-flag args (the JSON payload).
 *
 * Flags:
 *   --standalone          Force standalone (daemon-less) emission.
 *                         Also automatically enabled when the daemon
 *                         is not running, or when --parents is used.
 *   --name <id>           Node name / mesh identity for standalone
 *                         emission. Defaults to `sym-cli`. Claude Code
 *                         users typically pass --name claude-code-mac
 *                         (or claude-code-win) so their CMBs are
 *                         attributable on the mesh grid.
 *   --parents <keys>      Comma-separated parent CMB keys for remix
 *                         lineage. Using this flag implies --standalone
 *                         because the daemon IPC `remember` handler
 *                         does not accept lineage parents.
 */
function parseObserveFlags(argv) {
  const out = { positional: [], standalone: false, name: 'sym-cli', parents: [] };
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

function cmdObserve() {
  const parsed = parseObserveFlags(args);
  const content = parsed.positional.join(' ');

  if (!content) {
    console.error('Usage: sym observe [--standalone] [--name <id>] [--parents <key1,key2>] \'{"focus":"...","mood":{"text":"...","valence":0,"arousal":0},...}\'');
    console.error('  The calling agent (LLM) extracts CAT7 fields. The protocol does not parse raw text.');
    console.error('  --standalone: emit without sym-daemon running (one-shot SymNode). Auto-enabled if daemon is down.');
    console.error('  --name:       mesh identity for standalone mode (default: sym-cli).');
    console.error('                Claude Code users: --name claude-code-mac (or claude-code-win).');
    console.error('  --parents:    comma-separated parent CMB keys for remix lineage. Implies --standalone.');
    process.exit(1);
  }

  let fields;
  try {
    fields = JSON.parse(content);
  } catch {
    console.error('Error: content must be a JSON object with CAT7 fields.');
    console.error('  The agent LLM is responsible for extracting fields from observations.');
    process.exit(1);
  }

  // Decide which path to use:
  //   - Explicit --standalone  → standalone
  //   - --parents supplied     → standalone (lineage not plumbed through daemon IPC)
  //   - Daemon not running     → standalone (graceful fallback, not a failure)
  //   - Otherwise              → daemon IPC (fast path, preserves local CfC state)
  const useStandalone = parsed.standalone || !isDaemonRunning();

  if (useStandalone) {
    standaloneObserve(fields, { name: parsed.name, parents: parsed.parents })
      .catch((err) => {
        console.error('Standalone observe failed:', err.message || err);
        process.exit(2);
      });
    return;
  }

  cmdIPC({ type: 'remember', fields }, (res) => {
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
 * any user run `sym observe` without starting sym-daemon first — the
 * daemon is an optimisation, not a requirement.
 *
 * Node identity is stable across invocations: the SymIdentity layer
 * persists the keypair to ~/.sym/nodes/<name>/identity.json, so
 * repeated calls with the same --name resolve to the same nodeId.
 *
 * Ships CAT7 field vectors via SymNode's internal encoder — the caller
 * only needs to supply text (and valence/arousal for mood).
 */
async function standaloneObserve(fields, opts) {
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

  // Normalise CAT7 fields. Callers may pass scalar strings for the
  // six non-mood fields (as the daemon-IPC path historically accepts),
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
    const v = normaliseField(fields[key]);
    if (v !== undefined) normalised[key] = v;
  }
  if (!normalised.mood || typeof normalised.mood.text !== 'string') {
    throw new Error('fields.mood.text is required (MMP §9.3 protocol guarantee R5)');
  }

  const node = new SymNode({
    name: opts.name,
    cognitiveProfile:
      `sym-cli one-shot observer (${process.platform}). Emits single CMBs ` +
      'via `sym observe` without a persistent daemon. Identity is stable ' +
      'across invocations via the cached keypair in ~/.sym/nodes/.',
    svafFieldWeights: {
      focus: 2.0, issue: 1.5, intent: 1.5,
      motivation: 1.0, commitment: 1.2, perspective: 1.0, mood: 0.8,
    },
    svafFreshnessSeconds: 43200,
    relay: process.env.SYM_RELAY_URL,
    relayToken: process.env.SYM_RELAY_TOKEN,
    lifecycleRole: 'observer',
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
 * Federated recall — scan all local node meshmem stores directly from
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
    const memDir = path.join(nodesDir, nodeName, 'meshmem');
    if (!fs.existsSync(memDir)) continue;
    let files;
    try { files = fs.readdirSync(memDir); } catch { continue; }
    for (const file of files) {
      if (!file.startsWith('cmb-') || !file.endsWith('.json')) continue;
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
          source: entry.source || (entry.cmb && entry.cmb.createdBy) || 'unknown',
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
      process.exit(0);
    } catch (err) {
      console.error(dim(`  (synthesis failed: ${(err.message || '').slice(0, 120)} — showing raw contributions)`));
      printContributions(question, contributions, true);
      process.exit(0);
    }
  }

  // No provider, --raw, or nothing gathered: show what the mesh knows.
  printContributions(question, contributions, llm.hasProvider());
  process.exit(0);
}

/**
 * Broadcast a question to the mesh, best-effort. Resolves false (never throws)
 * if the daemon is down or slow — `sym ask` still answers from stored memory.
 */
function broadcastQuestion(question) {
  return new Promise((resolve) => {
    if (!isDaemonRunning()) return resolve(false);
    let settled = false;
    const finish = (v) => { if (!settled) { settled = true; try { socket.end(); } catch {} resolve(v); } };
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
    setTimeout(() => finish(false), 2000);
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
    const memDir = path.join(nodesDir, nodeName, 'meshmem');
    if (!fs.existsSync(memDir)) continue;
    let files;
    try { files = fs.readdirSync(memDir); } catch { continue; }
    for (const file of files) {
      if (!file.startsWith('cmb-') || !file.endsWith('.json')) continue;
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
          source: entry.source || (entry.cmb && entry.cmb.createdBy) || nodeName,
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
  sym start [--group <name>]         Start the mesh daemon (in a group; default = global mesh)
                                     Flags: --relay-url <url>, --relay-token <token>
  sym stop                           Stop the mesh daemon
  sym status                         Show mesh status
  sym peers                          List connected peers
  sym group                          Show the current group
  sym groups                         Discover SYM-mesh groups live on the LAN
  sym join <name>                    Switch into a group (kebab-case, or "default")
  sym leave                          Return to the default global mesh
  sym metrics                        Show protocol metrics and LLM cost
  sym observe [flags] <json>         Share observation (CAT7 fields as JSON)
                                     Flags: --standalone, --name <id>, --parents <keys>
  sym ask "<question>"               Ask the whole mesh one question, get one answer
                                     Flags: --raw (skip synthesis, show contributions)
  sym recall <query>                 Search mesh memory
  sym insight                        Get collective intelligence
  sym send <message>                 Send message to all peers
  sym logs                           Tail daemon logs
  sym version                        Show version

${bold('CAT7 fields:')}
  focus         What the observation is centrally about
  issue         Risks, gaps, open questions
  intent        Desired change or purpose
  motivation    Reasons, drivers, incentives
  commitment    Who will do what, by when
  perspective   Whose viewpoint, situational context
  mood          { text, valence (-1..1), arousal (-1..1) }

${bold('Examples:')}
  sym start
  sym observe '{"focus":"debugging auth","mood":{"text":"tired","valence":-0.4,"arousal":-0.3}}'
  sym recall "energy patterns"
  sym ask "should we use UUID v7 or keep v4?"
  sym insight

${bold('Daemon-less one-shot observations:')}
  # Works even when sym-daemon is not running. Auto-enabled if the
  # daemon is down; force with --standalone. Uses ~/.sym/relay.env
  # for relay credentials. Identity is stable across invocations via
  # the cached keypair in ~/.sym/nodes/<name>/.
  sym observe --standalone --name claude-code-mac \\
    '{"focus":"resolved 3 review board tickets","mood":{"text":"focused","valence":0.3,"arousal":0.2}}'

  # Remix with lineage (resolve upstream tickets). --parents implies --standalone.
  sym observe --name claude-code-mac --parents cmb-876bbd483a,cmb-c0d4332a \\
    '{"focus":"ANX+CFN positioning memo","intent":"resolve tickets","mood":{"text":"resolved","valence":0.3,"arousal":0.1}}'
`);
}
