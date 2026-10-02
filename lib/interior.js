'use strict';

/**
 * @module @sym-bot/sym/interior
 * @description A node's interior (sym 0.14, design D9.3): the local submission path through which
 * the node's MIND — the reasoning process it runs for one mission — asks the node to emit.
 *
 * One rule (design D8): an autonomous agent is its own node, and a node's reasoning process is its
 * interior, with no mesh identity of its own. The mind does not couple, keep a store or evaluate
 * SVAF, and it never holds the node's key: it SUBMITS, and the node checks, signs and sends.
 *
 *   - A submission carries a PER-MIND CAPABILITY: a random token the node issues when it starts a
 *     mind for one mission, revoked when that mind exits. A submission without a live capability is
 *     refused.
 *   - The node's checks before it signs:
 *       audience — `to` must be in the mission's allowlist, or absent (the room);
 *       size     — at most 64 KiB of category text, at most 512 KiB of application data;
 *       rate     — per capability;
 *       intent   — the mission's declared kinds only;
 *       lineage  — no `parents` outside the node's store.
 *   - ONE MIND PER NODE at a time. A node busy with a mission queues the next (`queueMind`), and the
 *     runtime may offer it elsewhere; `startMind` on a busy node is refused (EMINDBUSY). A node with
 *     several concurrent minds would be several agents under one identity (§3.2), unless it is
 *     declared a gateway (§5.10).
 *
 * This supersedes the 2026-08-02 Q1a fallback (a scoped signing grant to a worker).
 *
 * Socket protocol: newline-delimited JSON on a Unix domain socket (`<node dir>/interior.sock`,
 * 0600; a named pipe on Windows). Each request carries an `id`, echoed in its reply:
 *   → { id, type: 'submit', capability, kind, categories, to?, parents?, payload? }
 *   ← { id, type: 'submitted', key, assertionId }  |  { id, type: 'refused', reason }
 *   → { id, type: 'end', capability }               ← { id, type: 'ended' }
 *
 * @copyright 2026 SYM.BOT. Apache 2.0 License.
 */

const fs = require('fs');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const { CAT7_CATEGORIES } = require('./core');
const { nestedTooDeep } = require('./core/json-depth');

const MAX_CATEGORY_TEXT = 64 * 1024;
const MAX_APPLICATION = 512 * 1024;
const DEFAULT_RATE_PER_MINUTE = 60;
const MAX_REQUEST_BYTES = 1024 * 1024;

/**
 * Where the interior socket listens: `<node dir>/interior.sock`, unless that path is longer than a
 * Unix socket address can hold (104 bytes on macOS, 108 on Linux — a longer one is silently
 * truncated), in which case a short path in a per-user 0700 directory under the OS temp dir. A named
 * pipe on Windows.
 */
function defaultSocketPath(node) {
  if (process.platform === 'win32') return `\\\\.\\pipe\\sym-interior-${node.nodeId}`;
  const inDir = path.join(node._dir, 'interior.sock');
  if (Buffer.byteLength(inDir, 'utf8') <= 100) return inDir;
  const uid = typeof process.getuid === 'function' ? process.getuid() : 'u';
  const dir = path.join(require('os').tmpdir(), `sym-interior-${uid}`);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  try { fs.chmodSync(dir, 0o700); } catch { /* best effort */ }
  const short = crypto.createHash('sha256').update(node.nodeId).digest('hex').slice(0, 16);
  return path.join(dir, `${short}.sock`);
}

class Interior {
  constructor(node) {
    this._node = node;
    this._mind = null;       // { mindId, capability, mission, bucket, startedAt }
    this._queue = [];        // [{ mission, resolve, reject }]
    this._server = null;
    this._socketPath = null;
    this._clients = new Set();   // open interior connections, ended with the node
    this._stats = { submitted: 0, refused: 0, refusedByReason: {} };
  }

  /** Whether a mind is running now. */
  get busy() { return !!this._mind; }

  /** The running mind's public facts (never its capability), or null. */
  mind() {
    const m = this._mind;
    return m ? { mindId: m.mindId, mission: m.mission.id, kinds: [...m.mission.kinds], allowTo: [...m.mission.allowTo], startedAt: m.startedAt } : null;
  }

  stats() { return { ...this._stats, refusedByReason: { ...this._stats.refusedByReason }, busy: this.busy, queued: this._queue.length }; }

  _mission(m = {}) {
    const kinds = Array.isArray(m.kinds) ? m.kinds.filter((k) => typeof k === 'string' && k) : [];
    if (kinds.length === 0) throw new Error('interior: a mission declares the kinds of submission it may make');
    return {
      id: typeof m.id === 'string' ? m.id.slice(0, 128) : `mission-${Date.now()}`,
      kinds: new Set(kinds),
      allowTo: new Set(Array.isArray(m.allowTo) ? m.allowTo.filter((t) => typeof t === 'string') : []),
      ratePerMinute: Number.isFinite(m.ratePerMinute) && m.ratePerMinute > 0 ? m.ratePerMinute : DEFAULT_RATE_PER_MINUTE,
    };
  }

  /**
   * Start a mind for one mission and issue its capability. Refused (EMINDBUSY) while another mind
   * runs: one mind per node.
   * @param {{ id?: string, kinds: string[], allowTo?: string[], ratePerMinute?: number }} mission
   * @returns {{ mindId: string, capability: string, socketPath: string|null }}
   */
  startMind(mission) {
    if (this._mind) {
      const e = new Error('interior: this node is busy with a mission (one mind per node); queue it or offer it elsewhere');
      e.code = 'EMINDBUSY';
      throw e;
    }
    return this._start(this._mission(mission));
  }

  /** Queue a mission behind the running one; resolves with its capability when it starts. */
  queueMind(mission) {
    const m = this._mission(mission);
    if (!this._mind) return Promise.resolve(this._start(m));
    return new Promise((resolve, reject) => this._queue.push({ mission: m, resolve, reject }));
  }

  _start(mission) {
    const capability = crypto.randomBytes(32).toString('base64url');
    const mindId = `mind-${crypto.randomBytes(6).toString('hex')}`;
    this._mind = { mindId, capability, mission, startedAt: Date.now(), bucket: { tokens: mission.ratePerMinute, at: Date.now() } };
    this._node._log(`Interior: mind ${mindId} started for mission ${mission.id} (kinds ${[...mission.kinds].join(', ')})`);
    return { mindId, capability, socketPath: this._socketPath };
  }

  /** End the running mind (its capability is revoked), and start the next queued mission. */
  endMind(capabilityOrMindId) {
    const m = this._mind;
    if (!m) return false;
    if (capabilityOrMindId !== m.mindId && !this._capabilityIs(capabilityOrMindId)) return false;
    this._mind = null;
    this._node._log(`Interior: mind ${m.mindId} ended; its capability is revoked`);
    const next = this._queue.shift();
    if (next) next.resolve(this._start(next.mission));
    return true;
  }

  _capabilityIs(cap) {
    const m = this._mind;
    if (!m || typeof cap !== 'string') return false;
    const a = Buffer.from(cap);
    const b = Buffer.from(m.capability);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }

  _refuse(reason) {
    this._stats.refused++;
    this._stats.refusedByReason[reason] = (this._stats.refusedByReason[reason] || 0) + 1;
    return { ok: false, reason };
  }

  /**
   * Check and, if every check passes, sign and send one submission as this node's record.
   * @returns {{ ok: boolean, reason?: string, key?: string, assertionId?: string }}
   */
  submit(capability, sub = {}) {
    const m = this._mind;
    if (!this._capabilityIs(capability)) return this._refuse('no-live-capability');
    if (!sub || typeof sub !== 'object') return this._refuse('malformed');
    if (typeof sub.kind !== 'string' || !m.mission.kinds.has(sub.kind)) return this._refuse('kind-not-declared');
    const to = sub.to === undefined || sub.to === null ? null : sub.to;
    if (to !== null && (typeof to !== 'string' || !m.mission.allowTo.has(to))) return this._refuse('audience-not-allowed');
    const cats = sub.categories;
    if (!cats || typeof cats !== 'object' || Array.isArray(cats)) return this._refuse('malformed');
    let text = 0;
    for (const f of Object.keys(cats)) {
      if (!CAT7_CATEGORIES.includes(f)) return this._refuse('not-a-cat7-category');
      const v = cats[f];
      const t = typeof v === 'string' ? v : (v && typeof v.text === 'string' ? v.text : '');
      text += Buffer.byteLength(t, 'utf8');
    }
    if (text > MAX_CATEGORY_TEXT) return this._refuse('categories-too-large');
    if (sub.payload !== undefined && Buffer.byteLength(JSON.stringify(sub.payload), 'utf8') > MAX_APPLICATION) return this._refuse('application-too-large');
    const parents = Array.isArray(sub.parents) ? sub.parents : [];
    for (const k of parents) {
      if (typeof k !== 'string' || !this._node._store.get(k)) return this._refuse('parent-not-in-store');
    }
    const now = Date.now();
    const b = m.bucket;
    b.tokens = Math.min(m.mission.ratePerMinute, b.tokens + ((now - b.at) * m.mission.ratePerMinute) / 60000);
    b.at = now;
    if (b.tokens < 1) return this._refuse('rate');
    b.tokens -= 1;
    let entry;
    try {
      entry = this._node.remember(cats, { to: to || undefined, parents: parents.map((key) => ({ key })), payload: sub.payload });
    } catch (err) {
      return this._refuse(err && err.code ? err.code : 'emit-failed');
    }
    if (!entry) return this._refuse('not-minted');
    this._stats.submitted++;
    return { ok: true, key: entry.key, assertionId: entry.cmb?.metadata?.assertionId ?? null };
  }

  /**
   * Listen on the interior socket. Only this user can connect (0600); every request still needs the
   * live capability.
   * @returns {Promise<string>} the socket path
   */
  listen(socketPath) {
    if (this._server) return Promise.resolve(this._socketPath);
    const p = socketPath || defaultSocketPath(this._node);
    if (process.platform !== 'win32') { try { fs.unlinkSync(p); } catch { /* none */ } }
    this._server = net.createServer((sock) => this._serve(sock));
    return new Promise((resolve, reject) => {
      this._server.once('error', reject);
      this._server.listen(p, () => {
        if (process.platform !== 'win32') { try { fs.chmodSync(p, 0o600); } catch { /* best effort */ } }
        this._socketPath = p;
        resolve(p);
      });
    });
  }

  _serve(sock) {
    let buf = '';
    this._clients.add(sock);
    sock.on('close', () => this._clients.delete(sock));
    sock.on('error', () => {});
    sock.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      if (buf.length > MAX_REQUEST_BYTES) { sock.destroy(); return; }
      let i;
      while ((i = buf.indexOf('\n')) !== -1) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 1);
        if (!line.trim()) continue;
        let req;
        try { if (nestedTooDeep(line)) throw new Error('too deep'); req = JSON.parse(line); } catch { sock.write(JSON.stringify({ type: 'refused', reason: 'not-json' }) + '\n'); continue; }
        const id = req && (typeof req.id === 'string' || typeof req.id === 'number') ? req.id : null;
        let reply;
        if (req && req.type === 'submit') {
          const r = this.submit(req.capability, req);
          reply = r.ok ? { id, type: 'submitted', key: r.key, assertionId: r.assertionId } : { id, type: 'refused', reason: r.reason };
        } else if (req && req.type === 'end') {
          reply = this.endMind(req.capability) ? { id, type: 'ended' } : { id, type: 'refused', reason: 'no-live-capability' };
        } else {
          reply = { id, type: 'refused', reason: 'unknown-request' };
        }
        sock.write(JSON.stringify(reply) + '\n');
      }
    });
  }

  close() {
    // A stopped node ends every interior connection (its capabilities die with it); server.close()
    // alone would wait for them.
    for (const c of this._clients) { try { c.destroy(); } catch { /* */ } }
    this._clients.clear();
    if (this._server) { try { this._server.close(); } catch { /* */ } this._server = null; }
    if (this._socketPath && process.platform !== 'win32') { try { fs.unlinkSync(this._socketPath); } catch { /* */ } }
    for (const q of this._queue.splice(0)) q.reject(new Error('interior: the node stopped'));
    this._mind = null;
  }
}

module.exports = { Interior, MAX_CATEGORY_TEXT, MAX_APPLICATION };
