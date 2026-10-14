'use strict';

/**
 * @module @sym-bot/sym/store
 * @description The documented public way to open a STOPPED identity's CMB store: one function, and a handle
 * with three methods. It is the subpath `@sym-bot/sym/store` (package.json "exports"). README "Public API"
 * says what it promises and what it does not.
 *
 * A running node's own store is reached through the node (`node.validateCMB`, `node.dismissCMB`, ...), which
 * resolve the node's authority. This is for the other case: the identity is stopped (a crew that has
 * dissolved), its store directory is still on disk, and an operator has to record a verdict in it.
 *
 * @copyright 2026 SYM.BOT Ltd
 * @license Apache-2.0
 */

const fs = require('fs');
const { MemoryStore } = require('../memory-store');

/**
 * Open the CMB store in `cmbsDir` (a node directory's `cmbs/`) for the identity named `sourceName`.
 *
 * It never creates the directory: a directory that is not there throws ENOSTORE, so opening a path that
 * is not a store cannot litter the disk with an empty one.
 *
 * Open a store only while NO node holds it. A running node keeps its own copy of the store in memory and
 * writes its own files, so a second writer is not coordinated with it: use the node's methods for a
 * running node.
 *
 * The handle does not check that the caller holds the authority it asserts. A store is a directory of
 * files, so whoever can open the directory can write it; `lifecycle` here is the caller's statement
 * of the authority it exercises (a node resolves it from its role and grants, MMP §6.5), and the handle
 * refuses only a caller that claims none.
 *
 * @param {string} cmbsDir
 * @param {string} sourceName the identity's name
 * @returns {{
 *   get(key: string): (object|null),
 *   validateCMB(key: string, opts: { lifecycle: 'validated'|'canonical' }): { ok: boolean, reason?: string },
 *   dismissCMB(key: string, opts: { lifecycle: 'validated'|'canonical' }): { ok: boolean, reason?: string },
 * }}
 */
function openStore(cmbsDir, sourceName) {
  if (typeof cmbsDir !== 'string' || !cmbsDir) throw new TypeError('openStore: cmbsDir must be a directory path');
  if (typeof sourceName !== 'string' || !sourceName) throw new TypeError('openStore: sourceName must be the identity\'s name');
  let isDir = false;
  try { isDir = fs.statSync(cmbsDir).isDirectory(); } catch { /* absent */ }
  if (!isDir) {
    const e = new Error(`openStore: no store at ${cmbsDir}`);
    e.code = 'ENOSTORE';
    throw e;
  }
  const store = new MemoryStore(cmbsDir, sourceName);
  return Object.freeze({
    /** The stored entry under `key`, a copy (`lifecycle`, `anchorWeight`, `cmb`, ...), or null. */
    get: (key) => {
      const entry = store.get(key);
      return entry ? JSON.parse(JSON.stringify(entry)) : null;
    },
    validateCMB: (key, opts) => store.validateCMB(key, opts),
    dismissCMB: (key, opts) => store.dismissCMB(key, opts),
  });
}

exports.openStore = openStore;
Object.freeze(module.exports);
