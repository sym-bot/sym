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
 *   sym observe <json>                # Share observation (CAT7 fields as JSON)
 *   sym recall <query>                # Search mesh memory
 *   sym insight                       # Get xMesh collective intelligence
 *   sym send <message>                # Send message to all peers
 *   sym logs                          # Tail daemon logs
 *   sym version                       # Show version
 *
 * Copyright (c) 2026 SYM.BOT Ltd. Apache 2.0 License.
 */

const net = require('net');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync, spawn } = require('child_process');

const SOCKET_PATH = process.env.SYM_SOCKET || path.join(os.homedir(), '.sym', 'daemon.sock');
const LOG_DIR = path.join(os.homedir(), 'Library', 'Logs', 'sym-daemon');
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
  case 'insight': cmdIPC({ type: 'xmesh-context' }, formatInsight); break;
  case 'send':    cmdSend(); break;
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
  if (isDaemonRunning()) {
    console.log('sym-daemon is already running.');
    return;
  }

  const daemonPath = path.join(__dirname, 'sym-daemon.js');

  if (process.platform === 'darwin') {
    // Install and start via launchd
    try {
      execSync(`node "${daemonPath}" --install`, { stdio: 'inherit' });
    } catch (err) {
      console.error('Failed to start daemon:', err.message);
      process.exit(1);
    }
  } else {
    // Linux/other: start in background
    const child = spawn(process.execPath, [daemonPath], {
      detached: true,
      stdio: 'ignore',
    });
    child.unref();
    console.log(`sym-daemon started (pid ${child.pid})`);
  }
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
    // Try to find and kill the process
    try {
      const pid = execSync('pgrep -f sym-daemon.js', { encoding: 'utf8' }).trim();
      if (pid) {
        process.kill(parseInt(pid), 'SIGTERM');
        console.log('sym-daemon stopped.');
      }
    } catch {
      console.log('sym-daemon is not running.');
    }
  }
}


function cmdObserve() {
  const content = args.slice(1).join(' ');

  if (!content) {
    console.error('Usage: sym observe \'{"focus":"...","issue":"...","intent":"...","motivation":"...","commitment":"...","perspective":"...","mood":{"text":"...","valence":0,"arousal":0}}\'');
    console.error('  The calling agent (LLM) extracts CAT7 fields. The protocol does not parse raw text.');
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

  cmdIPC({ type: 'remember', fields }, (res) => {
    if (res.duplicate) {
      console.log('Already shared (duplicate CMB).');
    } else {
      console.log(`Shared: ${res.key || ''}`);
    }
  });
}

function cmdRecall() {
  const recallArgs = args.slice(1).filter(a => a !== '--json');
  const limitIdx = recallArgs.indexOf('--limit');
  let limit = 0;
  if (limitIdx !== -1) {
    limit = parseInt(recallArgs[limitIdx + 1]) || 0;
    recallArgs.splice(limitIdx, 2);
  }
  const query = recallArgs.join(' ') || '';
  cmdIPC({ type: 'recall', query, limit }, (msg) => {
    const results = msg.results || [];
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
      console.log(`  ${dim(time)}  ${r.content}`);
      if (r.tags) console.log(`    ${dim('tags: ' + r.tags)}`);
    }
  });
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
  sym start                          Start the mesh daemon
  sym stop                           Stop the mesh daemon
  sym status                         Show mesh status
  sym peers                          List connected peers
  sym metrics                        Show protocol metrics and LLM cost
  sym observe <json>                 Share observation (CAT7 fields as JSON)
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
  sym insight
`);
}
