'use strict';

/**
 * lib/hosted-spool.js — the daemon's delivery spool for HOSTED agents.
 *
 * A SymNode has had a durable inbox since the founder's 2026-08-04 ruling:
 * "communication is addressed to the NODE, and a new session RELINKS to it —
 * including what was delivered while no session was attached." A hosted agent
 * registered over ~/.sym/daemon.sock is NOT a SymNode, so nothing held its mail
 * while its harness socket was down. A sender addressing it was REFUSED at the
 * sender ("Peer not connected") — not dropped, not queued. That refusal is the
 * whole defect: duplex does not require both ends up at once, it requires the
 * mesh to be willing to hold a message.
 *
 * REUSE THE SEMANTICS, NEVER THE STORE. The ring, seq, cursor and ordering are
 * taken from SymNode's inbox; the FILE is not. They are different objects with
 * different lifetimes:
 *
 *   spool         — RAW VERIFIED DIRECTED ENVELOPES held for a DETACHED identity.
 *                   The daemon is a custodian; it has not admitted anything.
 *   inbox.json    — the ADMITTED delivery feed of a RUNNING node, written by that
 *                   node after its own verify + SVAF + remix.
 *
 * My first cut wrote the spool into <nodeDir>/inbox.json to get "one mailbox".
 * That was wrong, and codex-mac drew the boundary: pre-admitting into a node's
 * own feed would let the DAEMON write into any node's admitted memory, bypassing
 * the receiver's verification and its receiver-autonomous SVAF. The spool hands
 * over envelopes on attach; the recipient still decides what to admit.
 *
 * Design decisions taken by the dev seat and ruled by the CTO (2026-08-10):
 *  - Spool is keyed by IMMUTABLE nodeId, resolved from the agent's on-disk
 *    identity.json. Names are claimed; nodeIds are recorded.
 *  - A count cap AND a byte cap. The existing ring caps by COUNT alone, which is
 *    the wrong instrument when message size varies by orders of magnitude:
 *    measured 82MB across 125 inboxes, ~20KB a message, and big-text CMBs run far
 *    larger.
 *  - NO TTL. A TTL silently deletes unread mail, which is the exact failure this
 *    work exists to end.
 *  - NEVER evict below the cursor, and evict loudly. Discarding a message the
 *    session has already read is free; discarding one it has not is unrecoverable
 *    loss, and the two must never look alike.
 */

const fs = require('fs');
const path = require('path');
const { nodeDir, SYM_DIR } = require('./config');

/** Ring bounds. Count mirrors SymNode's _inboxMax; bytes is the addition. */
const DEFAULT_MAX_COUNT = 500;
const DEFAULT_MAX_BYTES = 8 * 1024 * 1024;

/**
 * Spool file, keyed by IMMUTABLE nodeId — deliberately NOT <nodeDir>/inbox.json.
 * Separate file, separate lifetime, and it never pre-admits into a node's feed.
 */
function spoolPath(nodeId) {
  return path.join(SYM_DIR, 'spool', `${nodeId}.json`);
}

/** Read the agent's mailbox. Missing/corrupt file starts empty — same as SymNode. */
function loadSpool(nodeId) {
  try {
    const d = JSON.parse(fs.readFileSync(spoolPath(nodeId), 'utf8'));
    return {
      seq: Number.isSafeInteger(d.seq) ? d.seq : 0,
      cursor: Number.isSafeInteger(d.cursor) ? d.cursor : 0,
      messages: Array.isArray(d.messages) ? d.messages : [],
    };
  } catch {
    return { seq: 0, cursor: 0, messages: [] };
  }
}

/** Write atomically: a torn inbox loses mail that was already accepted. */
function saveSpool(nodeId, box) {
  const p = spoolPath(nodeId);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const tmp = p + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(box));
  fs.renameSync(tmp, p);
}

/**
 * Bind a claimed (name, nodeId) to the identity ON DISK.
 *
 * This is NOT proof of key possession — register-agent has none, and adding it is
 * blocked ahead of any cross-daemon routing (CTO policy, 2026-08-10). It is the
 * weaker but real check that the pair matches a local identity that actually
 * exists, so a typo cannot mint a permanent spool directory. The CTO's original
 * gate — "a name with an identity.json" — was measured to admit 961 of 962 node
 * directories, so existence alone gates nothing; the nodeId must match too.
 */
function verifyIdentity(name, nodeId) {
  if (!name || !nodeId) return { ok: false, reason: 'name and nodeId are both required' };
  let id;
  try {
    id = JSON.parse(fs.readFileSync(path.join(nodeDir(name), 'identity.json'), 'utf8'));
  } catch {
    return { ok: false, reason: `no local identity for "${name}" — refusing to spool for an unknown name` };
  }
  if (id.nodeId !== nodeId) {
    return { ok: false, reason: `nodeId does not match the identity on disk for "${name}"` };
  }
  return { ok: true, nodeId: id.nodeId };
}

/**
 * Append one delivery. Returns { accepted, evicted } — `evicted` lists UNREAD
 * messages destroyed to make room, which the caller must surface rather than
 * swallow.
 *
 * The record shape mirrors SymNode._pushInbox so a standalone node reading this
 * file sees the same fields it would have written itself.
 */
function appendSpool(nodeId, delivery, opts = {}) {
  const maxCount = opts.maxCount || DEFAULT_MAX_COUNT;
  const maxBytes = opts.maxBytes || DEFAULT_MAX_BYTES;
  const box = loadSpool(nodeId);

  box.seq += 1;
  // An ENVELOPE, not an admitted record. `cmb` is stored AS RECEIVED — if the
  // sender E2E-encrypted it, the daemon holds ciphertext and never needs the
  // plaintext categories to do its custodial job.
  box.messages.push({
    seq: box.seq,
    id: `sp${String(box.seq).padStart(4, '0')}`,
    from: delivery.from || 'unknown',
    fromName: delivery.fromName || null,
    to: delivery.to || null,
    cmb: delivery.cmb ?? null,
    directed: true,
    encrypted: !!delivery.encrypted,
    key: delivery.key || null,
    spooledAt: Date.now(),
  });

  const evicted = [];
  const overCount = () => box.messages.length > maxCount;
  const overBytes = () => Buffer.byteLength(JSON.stringify(box)) > maxBytes;

  // Evict oldest-first, but NEVER below the cursor: everything at or under the
  // cursor has been read and is free to recycle; anything above it is mail nobody
  // has seen. If only unread messages remain, eviction is real loss and says so.
  while ((overCount() || overBytes()) && box.messages.length > 1) {
    const oldest = box.messages[0];
    if (oldest.seq > box.cursor) evicted.push(oldest);
    box.messages.shift();
  }

  saveSpool(nodeId, box);
  return { accepted: true, seq: box.seq, evicted, held: box.messages.length };
}

/**
 * Hand over everything since the cursor. `peek` leaves the cursor untouched so a
 * caller can inspect without consuming.
 *
 * The cursor advances only on an explicit drain — not on socket write. Deleting
 * on write loses the batch to a reconnect race, which is why SymNode uses a
 * cursor and why this does too.
 */
function drainSpool(nodeId, opts = {}) {
  const limit = Math.max(1, Math.min(opts.limit || 50, DEFAULT_MAX_COUNT));
  const box = loadSpool(nodeId);
  const fresh = box.messages.filter((m) => m.seq > box.cursor);
  const slice = fresh.slice(0, limit);
  if (!opts.peek && slice.length) {
    box.cursor = Math.max(box.cursor, slice[slice.length - 1].seq);
    saveSpool(nodeId, box);
  }
  return {
    messages: slice,
    drained: slice.length,
    remaining: fresh.length - slice.length,
    cursor: box.cursor,
  };
}

/** What this spool is holding — the answer to "is anyone coming back for this?" */
function spoolStatus(nodeId) {
  const box = loadSpool(nodeId);
  const undrained = box.messages.filter((m) => m.seq > box.cursor);
  return {
    seq: box.seq,
    cursor: box.cursor,
    held: box.messages.length,
    undrained: undrained.length,
    undrainedDirected: undrained.filter((m) => m.directed).length,
    neverDrained: box.cursor === 0 && box.seq > 0,
    bytes: Buffer.byteLength(JSON.stringify(box)),
  };
}

module.exports = {
  spoolPath, loadSpool, saveSpool, verifyIdentity,
  appendSpool, drainSpool, spoolStatus,
  DEFAULT_MAX_COUNT, DEFAULT_MAX_BYTES,
};
