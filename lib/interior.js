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
 *   - THE CAPABILITY IS BOUND TO ITS CONNECTION (security review; mesh-channel 0.11.0): on the socket
 *     it is bound to the first connection that presents it, and never accepted on another; when that
 *     connection closes, the mind ends and the capability with it. It is not a bearer token another
 *     local process can replay. (The alternative, a per-mind socket path, was not chosen: one socket
 *     and a first-frame binding need no directory per mind and no path handed around.) The
 *     in-process API (`submit`) is the host's own and takes the capability as given.
 *   - Ending a mind over the socket takes its capability, never its mindId (which is logged).
 *   - The node's checks before it signs:
 *       audience — `to` must be in the mission's allowlist, or absent (the room);
 *       size     — at most 64 KiB of category text, at most 512 KiB of application data;
 *       rate     — per capability;
 *       intent   — the mission's declared kinds only, and the KIND IS SIGNED: it is the record's
 *                  intent category (a submission whose intent says otherwise is refused);
 *       lineage  — no `parents` outside the node's store.
 *   - ONE MIND PER IDENTITY at a time, in this process (security review): two SymNode objects for one
 *     nodeId share the one slot (another process is kept out by the identity lock). A node busy with
 *     a mission queues the next (`queueMind`), and the runtime may offer it elsewhere; `startMind` on
 *     a busy identity is refused (EMINDBUSY). A node with several concurrent minds would be several
 *     agents under one identity (§3.2), unless it is declared a gateway (§5.10).
 *
 * This supersedes the 2026-08-02 Q1a fallback (a scoped signing grant to a worker).
 *
 * Socket protocol: newline-delimited JSON on a Unix domain socket in a 0700 directory this node made
 * (`<node dir>/interior/interior.sock`, or a fresh directory under the OS temp dir when that path is
 * too long for a socket address), the socket itself 0600. Each request carries an `id`, echoed in its
 * reply, and the capability; the first request binds the capability to the connection:
 *   → { id, type: 'submit', capability, kind, categories, to?, parents?, payload? }
 *   ← { id, type: 'submitted', key, assertionId }  |  { id, type: 'refused', reason }
 *   → { id, type: 'end', capability }               ← { id, type: 'ended' }
 *   → { id, type: 'mission', capability }           ← { id, type: 'mission', mindId, missionId, kinds,
 *                                                       allowTo, ratePerMinute, nodeId, name, room }
 *   → { id, type: 'deliveries', capability, after?, limit?, peek? }
 *                                                   ← { id, type: 'deliveries', items, cursor, remaining }
 *   → { id, type: 'subscribe', capability }         ← { id, type: 'subscribed' }, then unsolicited
 *                                                       { type: 'delivery', item } lines
 *   → { id, type: 'ack', capability, delivery }     ← { id, type: 'acked' }
 *   → { id, type: 'recall', capability, query, limit? } ← { id, type: 'recall', items }
 * A delivery item is { seq, id, kind: 'directed'|'broadcast', record, verified: true, profile,
 * assertionId, verification, session, author, remixed, receivedAt, acked }: only Core Secure
 * deliveries that verified — a record signed to this node, or a room broadcast it admitted — never
 * a quarantined one. A recall item is { key, record, verified, storedAt, author }.
 *
 * THE READ SIDE IS SCOPED TO THE MIND'S MISSION (final re-review, Finding 6; the founder's ruling C).
 * A mind is the node's reasoning for ONE mission, and must not read what the node received for
 * another:
 *   - each mind has its own READ VIEW: the deliveries that arrived while it runs (after its start),
 *     a directed one only when its verified author is in the mission's `allowTo`, and room broadcasts;
 *   - its own CURSOR: `deliveries` drains the mind's view, never the host's inbox (`node.inbox()` is
 *     the host's and is never moved by a mind);
 *   - `recall` returns only records in the view, the ones the mind submitted, and the mission's
 *     declared `context` keys; a `parents` key outside that scope is refused as if absent;
 *   - `ack` acks only an item in the view, in the mind's view only;
 *   - read requests are rate-limited per mind (READS_PER_SECOND, burst READS_BURST).
 *
 * Windows: a named pipe takes the default DACL Node gives it, which this module cannot narrow, so
 * `listen` refuses on Windows unless the host passes `{ allowDefaultPipeAcl: true }` (security review).
 *
 * @copyright 2026 SYM.BOT. Apache 2.0 License.
 */

const fs = require('fs');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const { CAT7_CATEGORIES } = require('./core');
const { signedProjection } = require('./core/record-canonical');
const recordOf = (cmb) => { try { return signedProjection(cmb); } catch { return null; } };
const { nestedTooDeep } = require('./core/json-depth');

const MAX_CATEGORY_TEXT = 64 * 1024;
const MAX_APPLICATION = 512 * 1024;
const DEFAULT_RATE_PER_MINUTE = 60;
const MAX_REQUEST_BYTES = 1024 * 1024;
const MAX_DELIVERIES = 200;
const MAX_RECALL = 100;
/** Read requests (deliveries, recall, ack, mission, subscribe) a mind may make: a token bucket. */
const READS_PER_SECOND = 10;
const READS_BURST = 20;
/** Keys a mind's scope holds at most (its submissions and the mission's context). */
const MAX_SCOPE_KEYS = 10000;

/** The mind running for each identity in this process: nodeId -> the Interior holding it. */
const MINDS = new Map();

/**
 * A directory this process owns and only its user can enter: made 0700 if absent, and refused if it
 * is a symlink, is not a directory, is owned by another user, or is open to anyone else (security
 * review: the tmp fallback used to follow a symlink another user planted).
 */
function ownedPrivateDir(dir) {
  try { fs.mkdirSync(dir, { mode: 0o700 }); } catch (e) { if (e.code !== 'EEXIST') throw e; }
  const st = fs.lstatSync(dir);
  if (st.isSymbolicLink() || !st.isDirectory()) throw Object.assign(new Error(`interior: ${dir} is not a directory of this node's`), { code: 'EINTERIORDIR' });
  if (typeof process.getuid === 'function' && st.uid !== process.getuid()) throw Object.assign(new Error(`interior: ${dir} is owned by another user`), { code: 'EINTERIORDIR' });
  if ((st.mode & 0o077) !== 0) fs.chmodSync(dir, 0o700);
  return dir;
}

/**
 * Where the interior socket listens: `<node dir>/interior/interior.sock`, in a 0700 directory, unless
 * that path is longer than a Unix socket address can hold (104 bytes on macOS, 108 on Linux — a
 * longer one is silently truncated), in which case a FRESH directory under the OS temp dir
 * (mkdtemp: random, made by this process, 0700) is used and removed at close. A named pipe on Windows.
 * @returns {{ path: string, tmpDir: string|null }}
 */
function defaultSocketPath(node) {
  if (process.platform === 'win32') return { path: `\\\\.\\pipe\\sym-interior-${node.nodeId}`, tmpDir: null };
  const dir = path.join(node._dir, 'interior');
  const inDir = path.join(dir, 'interior.sock');
  if (Buffer.byteLength(inDir, 'utf8') <= 100) { ownedPrivateDir(dir); return { path: inDir, tmpDir: null }; }
  const tmpDir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'sym-interior-'));
  ownedPrivateDir(tmpDir);
  return { path: path.join(tmpDir, 's.sock'), tmpDir };
}

class Interior {
  constructor(node) {
    this._node = node;
    this._mind = null;       // { mindId, capability, mission, bucket, startedAt }
    this._queue = [];        // [{ mission, resolve, reject }]
    this._server = null;
    this._socketPath = null;
    this._clients = new Set();   // open interior connections, ended with the node
    this._subscribers = new Set(); // connections subscribed to deliveries
    this._tmpDir = null;
    this._stats = { submitted: 0, refused: 0, refusedByReason: {} };
    this._onDelivery = (entry) => this._pushDelivery(entry);
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
      // Records the host gives the mind to read and cite (its view holds nothing from before it started).
      context: new Set(Array.isArray(m.context) ? m.context.filter((k) => typeof k === 'string').slice(0, MAX_SCOPE_KEYS) : []),
      ratePerMinute: Number.isFinite(m.ratePerMinute) && m.ratePerMinute > 0 ? m.ratePerMinute : DEFAULT_RATE_PER_MINUTE,
    };
  }

  /**
   * Start a mind for one mission and issue its capability. Refused (EMINDBUSY) while another mind
   * runs: one mind per node.
   * @param {{ id?: string, kinds: string[], allowTo?: string[], context?: string[], ratePerMinute?: number }} mission
   *   `context`: record keys the host gives the mind to read and cite (its view holds nothing from
   *   before it started).
   * @returns {{ mindId: string, capability: string, socketPath: string|null }}
   */
  startMind(mission) {
    if (this._mind || this._identityBusy()) {
      const e = new Error('interior: this identity is busy with a mission (one mind per identity); queue it or offer it elsewhere');
      e.code = 'EMINDBUSY';
      throw e;
    }
    return this._start(this._mission(mission));
  }

  /** Queue a mission behind the running one; resolves with its capability when it starts. */
  queueMind(mission) {
    const m = this._mission(mission);
    if (!this._mind && !this._identityBusy()) return Promise.resolve(this._start(m));
    return new Promise((resolve, reject) => this._queue.push({ mission: m, resolve, reject }));
  }

  /** @private Whether another Interior in this process holds this identity's mind. */
  _identityBusy() {
    const holder = MINDS.get(this._node.nodeId);
    return !!(holder && holder !== this && holder._mind);
  }

  _start(mission) {
    const capability = crypto.randomBytes(32).toString('base64url');
    const mindId = `mind-${crypto.randomBytes(6).toString('hex')}`;
    MINDS.set(this._node.nodeId, this);
    // The mind's read view starts after the deliveries already in the inbox (ruling C).
    const floor = this._node._inboxSeq || 0;
    this._mind = {
      mindId, capability, mission, startedAt: Date.now(), bucket: { tokens: mission.ratePerMinute, at: Date.now() }, conn: null,
      floor, cursor: floor, acked: new Set(), submitted: new Set(), reads: { tokens: READS_BURST, at: Date.now() },
    };
    this._node._log(`Interior: mind ${mindId} started for mission ${mission.id} (kinds ${[...mission.kinds].join(', ')})`);
    return { mindId, capability, socketPath: this._socketPath };
  }

  /** End the running mind (its capability is revoked), and start the next queued mission. */
  endMind(capabilityOrMindId) {
    const m = this._mind;
    if (!m) return false;
    if (capabilityOrMindId !== m.mindId && !this._capabilityIs(capabilityOrMindId)) return false;
    this._end(m);
    return true;
  }

  /** @private End mind `m`: its capability is revoked, its connection's subscription with it. */
  _end(m) {
    if (this._mind !== m) return;
    this._mind = null;
    if (MINDS.get(this._node.nodeId) === this) MINDS.delete(this._node.nodeId);
    if (m.conn) this._subscribers.delete(m.conn);
    this._node._log(`Interior: mind ${m.mindId} ended; its capability is revoked`);
    const next = this._queue.shift();
    if (next) next.resolve(this._start(next.mission));
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
    // The kind is signed (security review): it is the record's intent, so what peers verify says what
    // the mission declared. An intent saying something else is refused.
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
    const intent = cats.intent === undefined ? undefined : (typeof cats.intent === 'string' ? cats.intent : (cats.intent && cats.intent.text));
    if (intent !== undefined && intent !== sub.kind) return this._refuse('intent-is-not-the-kind');
    if (sub.payload !== undefined && Buffer.byteLength(JSON.stringify(sub.payload), 'utf8') > MAX_APPLICATION) return this._refuse('application-too-large');
    const parents = Array.isArray(sub.parents) ? sub.parents : [];
    // A parent the mind cites must be in its scope: one outside it is refused as if absent, so the
    // check is no oracle for what the node holds (ruling C).
    const scope = this._scopeKeys(m);
    for (const k of parents) {
      if (typeof k !== 'string' || !scope.has(k) || !this._node._store.get(k)) return this._refuse('parent-not-in-store');
    }
    const now = Date.now();
    const b = m.bucket;
    b.tokens = Math.min(m.mission.ratePerMinute, b.tokens + ((now - b.at) * m.mission.ratePerMinute) / 60000);
    b.at = now;
    if (b.tokens < 1) return this._refuse('rate');
    b.tokens -= 1;
    let entry;
    try {
      entry = this._node.remember({ ...cats, intent: sub.kind }, { to: to || undefined, parents: parents.map((key) => ({ key })), payload: sub.payload });
    } catch (err) {
      return this._refuse(err && err.code ? err.code : 'emit-failed');
    }
    if (!entry) return this._refuse('not-minted');
    if (entry.key && m.submitted.size < MAX_SCOPE_KEYS) m.submitted.add(entry.key);
    if (entry.duplicate && !entry.cmb) return { ok: true, key: entry.key, duplicate: true };
    this._stats.submitted++;
    return { ok: true, key: entry.key, assertionId: entry.cmb?.metadata?.assertionId ?? null, ...(entry.duplicate ? { duplicate: true } : {}) };
  }

  /**
   * Listen on the interior socket. Only this user can connect (0600); every request still needs the
   * live capability.
   * @returns {Promise<string>} the socket path
   */
  listen(socketPath, opts = {}) {
    if (this._server) return Promise.resolve(this._socketPath);
    if (process.platform === 'win32' && !opts.allowDefaultPipeAcl) {
      return Promise.reject(Object.assign(new Error('interior: on Windows the pipe takes a default DACL this module cannot narrow; pass { allowDefaultPipeAcl: true } to listen anyway'), { code: 'EINTERIORACL' }));
    }
    let p = socketPath;
    if (!p) { const d = defaultSocketPath(this._node); p = d.path; this._tmpDir = d.tmpDir; }
    else if (process.platform !== 'win32') ownedPrivateDir(path.dirname(p));
    if (process.platform !== 'win32') {
      try { const st = fs.lstatSync(p); if (st.isSocket()) fs.unlinkSync(p); else return Promise.reject(Object.assign(new Error(`interior: ${p} exists and is not a socket`), { code: 'EINTERIORDIR' })); } catch (e) { if (e.code !== 'ENOENT') return Promise.reject(e); }
    }
    this._server = net.createServer((sock) => this._serve(sock));
    this._node.on('cmb-accepted', this._onDelivery);
    return new Promise((resolve, reject) => {
      this._server.once('error', reject);
      // The socket is made in a directory only this user can enter, set so before listen (security
      // review), and is itself 0600 once it exists.
      this._server.listen(p, () => {
        if (process.platform !== 'win32') { try { fs.chmodSync(p, 0o600); } catch { /* best effort */ } }
        this._socketPath = p;
        resolve(p);
      });
    });
  }

  /** @private The mind's capability on this connection: bound to the first that presents it. */
  _authorise(sock, capability) {
    const m = this._mind;
    if (!this._capabilityIs(capability)) return null;
    if (m.conn === null) {
      m.conn = sock;
      // The connection that holds the capability ending ends the mind (and revokes the capability).
      sock.once('close', () => this._end(m));
      return m;
    }
    return m.conn === sock ? m : null;
  }

  /** @private One delivery item, or null when it is not one a mind is given. */
  _item(e) {
    if (!e || e.verified !== true || e.profile !== 'core-secure' || !e.record) return null;
    // The inbox entry with its provenance (mesh-channel DESIGN-0.11.0 D2) and its id.
    return {
      seq: e.seq, id: e.id, kind: e.directed ? 'directed' : 'broadcast', record: e.record,
      verified: true, profile: e.profile, assertionId: e.assertionId || null, verification: e.verification || null,
      session: e.session || null, author: e.author || null, remixed: e.remixed === true, receivedAt: e.receivedAt,
    };
  }

  /**
   * @private Whether an inbox entry is in mind `m`'s read view (ruling C): it arrived after the mind
   * started, it is a Core Secure delivery that verified, and a directed one is from a node the mission
   * may address.
   */
  _inView(m, e) {
    if (!m || !e || !(e.seq > m.floor)) return false;
    if (!this._item(e)) return false;
    if (e.directed) return !!(e.author && typeof e.author.nodeId === 'string' && m.mission.allowTo.has(e.author.nodeId));
    return true;
  }

  /** @private The record keys mind `m` may read and cite: its view's, its own submissions, its context. */
  _scopeKeys(m) {
    const keys = new Set([...m.submitted, ...m.mission.context]);
    for (const e of this._node._inbox || []) if (e.key && this._inView(m, e)) keys.add(e.key);
    return keys;
  }

  /** @private Spend one of mind `m`'s read tokens; false past its rate. */
  _readOk(m) {
    const now = Date.now();
    const b = m.reads;
    b.tokens = Math.min(READS_BURST, b.tokens + ((now - b.at) * READS_PER_SECOND) / 1000);
    b.at = now;
    if (b.tokens < 1) { this._refuse('read-rate'); return false; }
    b.tokens -= 1;
    return true;
  }

  /** @private A delivery the node just surfaced, to the subscribed mind connection (in its view only). */
  _pushDelivery(entry) {
    if (!this._subscribers.size || !entry || !entry.inboxId) return;
    const m = this._mind;
    const e = this._node.inboxGet(entry.inboxId);
    if (!m || !this._inView(m, e)) return;
    const it = this._item(e);
    if (!it) return;
    for (const c of this._subscribers) { try { c.write(JSON.stringify({ type: 'delivery', item: it }) + '\n'); } catch { /* the connection is going */ } }
  }

  _request(sock, req, id) {
    const type = req && req.type;
    const m = this._authorise(sock, req && req.capability);
    if (!m) return { id, type: 'refused', reason: this._mind && this._capabilityIs(req && req.capability) ? 'capability-bound-to-another-connection' : 'no-live-capability' };
    if (type !== 'submit' && type !== 'end' && !this._readOk(m)) return { id, type: 'refused', reason: 'rate' };
    switch (type) {
      case 'submit': {
        const r = this.submit(req.capability, req);
        return r.ok ? { id, type: 'submitted', key: r.key, assertionId: r.assertionId ?? null, ...(r.duplicate ? { duplicate: true } : {}) } : { id, type: 'refused', reason: r.reason };
      }
      case 'end':
        this._end(m);
        return { id, type: 'ended' };
      case 'mission':
        return { id, type: 'mission', mindId: m.mindId, missionId: m.mission.id, kinds: [...m.mission.kinds], allowTo: [...m.mission.allowTo], ratePerMinute: m.mission.ratePerMinute, nodeId: this._node.nodeId, name: this._node.name, room: this._node._room };
      case 'deliveries': {
        // The mind's own view and cursor; the host's inbox cursor never moves (ruling C).
        const limit = Number.isSafeInteger(req.limit) && req.limit > 0 ? Math.min(req.limit, MAX_DELIVERIES) : 50;
        const from = Number.isSafeInteger(req.after) ? Math.max(req.after, m.floor) : m.cursor;
        const view = (this._node._inbox || []).filter((e) => e.seq > from && this._inView(m, e));
        const slice = view.slice(0, limit);
        if (req.peek !== true && slice.length) m.cursor = Math.max(m.cursor, slice[slice.length - 1].seq);
        const items = slice.map((e) => ({ ...this._item(e), acked: m.acked.has(e.id) }));
        return { id, type: 'deliveries', items, cursor: m.cursor, remaining: view.length - slice.length };
      }
      case 'subscribe':
        this._subscribers.add(sock);
        sock.once('close', () => this._subscribers.delete(sock));
        return { id, type: 'subscribed' };
      case 'ack': {
        // Only an item in the mind's view, and only in the mind's view: the host's inbox is the host's.
        if (typeof req.delivery !== 'string') return { id, type: 'refused', reason: 'malformed' };
        const e = this._node.inboxGet(req.delivery);
        if (!this._inView(m, e)) return { id, type: 'refused', reason: 'not-in-view' };
        m.acked.add(e.id);
        return { id, type: 'acked' };
      }
      case 'recall': {
        if (typeof req.query !== 'string') return { id, type: 'refused', reason: 'malformed' };
        const limit = Number.isSafeInteger(req.limit) && req.limit > 0 ? Math.min(req.limit, MAX_RECALL) : 20;
        const own = this._node.nodeId;
        const scope = this._scopeKeys(m);
        const items = [];
        for (const e of this._node.recall(req.query) || []) {
          if (items.length >= limit) break;
          if (!e || !scope.has(e.key)) continue; // only what the mission may see (ruling C)
          const mine = !e.peerId;
          if (!mine && e.verified !== true) continue; // a peer's record only when it verified
          const md = e.cmb && e.cmb.metadata;
          items.push({ key: e.key, record: e.cmb && md && md.signatureSuite === 'mmp-sig-v2.0' ? recordOf(e.cmb) : null, verified: mine ? true : e.verified === true, storedAt: e.storedAt ?? null, author: mine ? { name: this._node.name, nodeId: own } : (e.author || null) });
        }
        return { id, type: 'recall', items };
      }
      default:
        return { id, type: 'refused', reason: 'unknown-request' };
    }
  }

  _serve(sock) {
    let buf = '';
    this._clients.add(sock);
    sock.on('close', () => { this._clients.delete(sock); this._subscribers.delete(sock); });
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
        try { reply = this._request(sock, req, id); } catch { reply = { id, type: 'refused', reason: 'failed' }; }
        sock.write(JSON.stringify(reply) + '\n');
      }
    });
  }

  close() {
    // A stopped node ends every interior connection (its capabilities die with it); server.close()
    // alone would wait for them.
    for (const q of this._queue.splice(0)) q.reject(new Error('interior: the node stopped'));
    if (this._mind) this._end(this._mind);
    for (const c of this._clients) { try { c.destroy(); } catch { /* */ } }
    this._clients.clear();
    this._subscribers.clear();
    this._node.removeListener('cmb-accepted', this._onDelivery);
    if (this._server) { try { this._server.close(); } catch { /* */ } this._server = null; }
    if (this._socketPath && process.platform !== 'win32') { try { fs.unlinkSync(this._socketPath); } catch { /* */ } }
    if (this._tmpDir) { try { fs.rmSync(this._tmpDir, { recursive: true, force: true }); } catch { /* */ } this._tmpDir = null; }
    this._socketPath = null;
  }
}

module.exports = { Interior, MAX_CATEGORY_TEXT, MAX_APPLICATION, READS_PER_SECOND, READS_BURST, ownedPrivateDir };
