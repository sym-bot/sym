'use strict';

/**
 * Configuration helpers for SYM mesh nodes.
 *
 * Manages identity persistence, node directories, and logging.
 * Node data lives under ~/.sym/nodes/<name>/.
 *
 * See MMP v0.2.0 Section 3 (Identity), Section 18 (Configuration).
 *
 * Copyright (c) 2026 SYM.BOT Ltd. Apache 2.0 License.
 */

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const os = require('os');

/** Root SYM configuration directory (~/.sym). */
const SYM_DIR = path.join(process.env.HOME || os.homedir(), '.sym');

/** Directory containing all node data (~/.sym/nodes). */
const NODES_DIR = path.join(SYM_DIR, 'nodes');

/**
 * Ensure a directory exists, creating it recursively if needed.
 * @param {string} dir — directory path
 */
function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

/**
 * Get the data directory for a named node.
 * @param {string} name — node name
 * @returns {string} path to ~/.sym/nodes/<name>
 */
function nodeDir(name) {
  return path.join(NODES_DIR, name);
}

/**
 * Load or create a persistent identity for a node.
 * Identity is stored as ~/.sym/nodes/<name>/identity.json.
 * See MMP v0.2.0 Section 3 (Identity).
 *
 * @param {string} name — node name
 * @returns {{ nodeId: string, name: string, hostname: string, createdAt: number }}
 */
function loadOrCreateIdentity(name) {
  const dir = nodeDir(name);
  ensureDir(dir);
  const idPath = path.join(dir, 'identity.json');
  if (fs.existsSync(idPath)) {
    try {
      return JSON.parse(fs.readFileSync(idPath, 'utf8'));
    } catch (e) {
      console.error(`[SYM] WARNING: identity.json corrupt or unreadable — regenerating. Error: ${e.message}`);
    }
  }
  const identity = {
    nodeId: crypto.randomUUID(),
    name,
    hostname: os.hostname(),
    createdAt: Date.now(),
  };
  fs.writeFileSync(idPath, JSON.stringify(identity, null, 2));
  return identity;
}

/**
 * Log a timestamped message with node name prefix.
 * @param {string} nodeName — node name for prefix
 * @param {string} msg — message to log
 */
function log(nodeName, msg) {
  const ts = new Date().toISOString().slice(11, 19);
  console.log(`[${ts}] [${nodeName}] ${msg}`);
}

module.exports = {
  SYM_DIR,
  NODES_DIR,
  ensureDir,
  nodeDir,
  loadOrCreateIdentity,
  log,
};
