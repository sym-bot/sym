'use strict';

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const os = require('os');

const SYM_DIR = path.join(process.env.HOME || os.homedir(), '.sym');
const NODES_DIR = path.join(SYM_DIR, 'nodes');

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function nodeDir(name) {
  return path.join(NODES_DIR, name);
}

function loadOrCreateIdentity(name) {
  const dir = nodeDir(name);
  ensureDir(dir);
  const idPath = path.join(dir, 'identity.json');
  if (fs.existsSync(idPath)) {
    try {
      return JSON.parse(fs.readFileSync(idPath, 'utf8'));
    } catch {}
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
