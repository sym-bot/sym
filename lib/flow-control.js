'use strict';

/**
 * @module @sym-bot/sym/flow-control
 * @description Flow control for directed and room records (sym 0.14.3).
 *
 * A receiver bounds what one session's records cost it: a record budget per session, by count (8 a
 * second after a burst of 32, security review D) and by size (128 KiB of record text a second after
 * 1.5 MiB, R2-3), before SVAF evaluates anything. Until 0.14.3 a record past the budget was DROPPED
 * unevaluated while its sender reported it dispatched, and nothing offered it again: 49 directed
 * messages sent in a burst reached the receiver as 38, 12 records of 200 KB as 7, and 120 records
 * held across a relay drop as 37. The budget is there to bound CPU and memory; it must not lose
 * honest traffic. So:
 *
 *   RECEIVER. A record past the budget is QUEUED, per session, in arrival order, and admitted
 *   (verified, evaluated, surfaced) as the budget refills: it is delayed, never dropped. The queue is
 *   bounded per session (QUEUE_SECONDS of the budget: 512 records, 8 Mi characters) and in all
 *   (QUEUE_TOTAL_*). Only past a bound is a record refused, and then the receiver tells the sender in
 *   a sealed control frame, `cmb-refused`, naming the refused assertionIds and a retry-after. A peer
 *   that keeps sending past the bound after it was told is cut (closed, and not admitted again for a
 *   minute): an honest sender never is, it paces.
 *
 *   ADVERTISEMENT. Once a session is admitted, each side tells the other its budget in a sealed
 *   control frame, `cmb-budget` (the rate and burst by count and by size, and the queue bound).
 *
 *   SENDER. Records to a peer — directed or room, fresh or held — are written to its session within
 *   the budget that peer advertised (one that advertises nothing, 0.14.2 and older, is paced to the
 *   0.14.2 budget, with a margin: it drops past it). What does not fit waits in the peer's held list
 *   and is written as the budget refills. A record counts as dispatched only once it is written
 *   within the budget; a refused one goes back to the held list and is retried after the retry-after,
 *   and after HELD_REFUSALS_MAX refusals or HELD_MAX_AGE_MS it is reported undelivered.
 *
 * Nothing here changes what a record costs once it is admitted: the budget, and what it bounds, are
 * exactly as before. Only what happens past it changes.
 *
 * @copyright 2026 SYM.BOT. Apache 2.0 License.
 */

// ── The receiver's record budget, per session ──────────────────────────────────────────────────

/** Records one session has evaluated, at most: a burst, then a rate a second (security review D). */
const RECORDS_PER_SECOND = 8;
const RECORDS_BURST = 32;
/** The record lane by size (R2-3): characters of record text a second, after a burst. */
const RECORD_CHARS_PER_SECOND = 128 * 1024;
const RECORD_CHARS_BURST = 1536 * 1024;

/**
 * The queue in front of the budget holds at most QUEUE_SECONDS of it per session, by count and by
 * size, so a record that is queued waits at most about that long; and at most QUEUE_TOTAL_* in all,
 * whatever the number of sessions. (Characters, as the size budget counts them.)
 */
const QUEUE_SECONDS = 64;
const QUEUE_RECORDS = RECORDS_PER_SECOND * QUEUE_SECONDS;
const QUEUE_CHARS = RECORD_CHARS_PER_SECOND * QUEUE_SECONDS;
const QUEUE_TOTAL_RECORDS = 4096;
const QUEUE_TOTAL_CHARS = 32 * 1024 * 1024;

/**
 * A refusal notice (`cmb-refused`) goes to a peer at most once every REFUSAL_NOTICE_MS, naming at most
 * REFUSAL_IDS_MAX assertionIds; at most REFUSAL_PENDING_MAX wait for the next one (past it a refusal
 * is counted, not listed: only a sender past every bound gets there). Notices for a peer with no open
 * session wait at most REFUSAL_PENDING_MS for its next one.
 */
const REFUSAL_NOTICE_MS = 1000;
const REFUSAL_IDS_MAX = 256;
const REFUSAL_PENDING_MAX = 4 * REFUSAL_IDS_MAX;
const REFUSAL_PENDING_MS = 60_000;
const REFUSAL_PEERS_MAX = 1024;
/** The retry-after a refusal carries: the time the session's queue needs to drain, within these. */
const RETRY_AFTER_MIN_MS = 1000;
const RETRY_AFTER_MAX_MS = QUEUE_SECONDS * 1000;
/**
 * A peer told, and still sending past the bound by more than this many records before its queue has
 * drained, is cut (closed, and not admitted again for FLOOD_PENALTY_MS). An honest sender stops within
 * the records it had in flight when the notice reached it, far fewer.
 */
const REFUSALS_BEFORE_CUT = QUEUE_RECORDS;
const FLOOD_PENALTY_MS = 60_000;

/** The sealed control frames (lib/core/sealed-control.js carries them; a 0.14.2 node ignores both, §7.3). */
const BUDGET_FRAME = 'cmb-budget';
const REFUSED_FRAME = 'cmb-refused';
const BUDGET_MEMBERS = Object.freeze(['type', 'recordsPerSecond', 'recordsBurst', 'charsPerSecond', 'charsBurst', 'queueRecords', 'queueChars']);
const REFUSED_MEMBERS = Object.freeze(['type', 'assertionIds', 'retryAfterMs']);
const ASSERTION_ID = /^asrt-[0-9a-f]{64}$/;

// ── The sender ─────────────────────────────────────────────────────────────────────────────────

/**
 * What a sender paces a peer to before, or without, its advertisement: the 0.14.2 record budget (8 a
 * second, burst 32; 0.14.2 had no size budget) with a quarter of it kept as a margin. A 0.14.2
 * receiver DROPS past its budget, and a sender pacing exactly to it loses a record whenever two arrive
 * closer together than they were written (a relay's pacer, the network): the margin absorbs that. An
 * advertising receiver queues, so it is paced exactly to what it says.
 */
const LEGACY_BUDGET = Object.freeze({ recordsPerSecond: 6, recordsBurst: 24, charsPerSecond: Infinity, charsBurst: Infinity, queueRecords: 0, queueChars: 0 });
/** A refused record is retried at most this many times; a held one is given up at this age (signed). */
const HELD_REFUSALS_MAX = 8;
/** Below the receiver's 24 h window for a directed record's signed age (frame-handler DIRECTED_WINDOW_MS). */
const HELD_MAX_AGE_MS = 23 * 60 * 60 * 1000;
/**
 * A record written to a peer is remembered this long (and at most SENT_WINDOW_MAX of them in all), so
 * a refusal naming it can put it back on the held list. Refusals are sent within REFUSAL_NOTICE_MS of
 * the record's arrival; a minute covers a slow relay several times over.
 */
const SENT_WINDOW_MS = 60_000;
const SENT_WINDOW_MAX = 20_000;
/** The most undelivered records `undelivered()` lists (the newest kept). */
const UNDELIVERED_LOG_MAX = 256;

/** What a record weighs for the size budgets: its texts and application data, in characters. */
function recordChars(cmb) {
  let n = 512;
  const cats = cmb && typeof cmb === 'object' ? cmb.categories : null;
  if (cats && typeof cats === 'object') {
    for (const v of Object.values(cats)) {
      if (typeof v === 'string') n += v.length;
      else if (v && typeof v === 'object' && typeof v.text === 'string') n += v.text.length;
    }
  }
  const md = cmb && typeof cmb === 'object' ? cmb.metadata : null;
  if (md && typeof md === 'object') {
    if (md.application && typeof md.application === 'object' && typeof md.application.data === 'string') n += md.application.data.length;
    if (typeof md.createdBy === 'string') n += md.createdBy.length;
  }
  return n;
}

/** Refill a bucket {tokens, at} to `now` at `rate` a second up to `burst`. A clock stepped back refills nothing and takes nothing. */
function refillBucket(b, rate, burst, now) {
  const elapsed = now - b.at;
  if (elapsed > 0) b.tokens = Math.min(burst, b.tokens + (elapsed * rate) / 1000);
  b.at = Math.max(b.at, now);
  return b;
}

/** Milliseconds until bucket `b` holds `need` (at most its burst), refilled to `now`; 0 when it does. */
function bucketWait(b, rate, burst, need, now) {
  refillBucket(b, rate, burst, now);
  const n = Math.min(need, burst);
  if (b.tokens >= n) return 0;
  return Math.max(1, Math.ceil(((n - b.tokens) * 1000) / rate));
}

/** The advertisement this node sends: its record budget and its queue bound per session. */
function budgetFrame({ recordsPerSecond = RECORDS_PER_SECOND, recordsBurst = RECORDS_BURST, charsPerSecond = RECORD_CHARS_PER_SECOND, charsBurst = RECORD_CHARS_BURST, queueRecords = QUEUE_RECORDS, queueChars = QUEUE_CHARS } = {}) {
  return { type: BUDGET_FRAME, recordsPerSecond, recordsBurst, charsPerSecond, charsBurst, queueRecords, queueChars };
}

const finiteIn = (v, lo, hi) => typeof v === 'number' && Number.isFinite(v) && v >= lo && v <= hi;
/**
 * A peer's `cmb-budget`, checked: the frame's members exactly, each a finite number in range. A rate
 * below one record a minute is taken as one a minute (a receiver that advertises less only slows what
 * it is sent; the held list's age bound still gives the records up). @returns {object|null}
 */
function parseBudgetFrame(f) {
  if (!f || typeof f !== 'object' || Array.isArray(f)) return null;
  // No member outside the schema; each member is checked below (a missing one is not a finite number).
  if (!Object.keys(f).every((k) => BUDGET_MEMBERS.includes(k))) return null;
  if (!finiteIn(f.recordsPerSecond, 0, 1e6) || !finiteIn(f.recordsBurst, 1, 1e7)) return null;
  if (!finiteIn(f.charsPerSecond, 0, 1e12) || !finiteIn(f.charsBurst, 1, 1e12)) return null;
  if (!finiteIn(f.queueRecords, 0, 1e7) || !finiteIn(f.queueChars, 0, 1e12)) return null;
  return Object.freeze({
    recordsPerSecond: Math.max(f.recordsPerSecond, 1 / 60),
    recordsBurst: f.recordsBurst,
    charsPerSecond: Math.max(f.charsPerSecond, 1),
    charsBurst: f.charsBurst,
    queueRecords: f.queueRecords,
    queueChars: f.queueChars,
  });
}

/** A peer's `cmb-refused`, checked: the frame's members exactly. @returns {{ ids: string[], retryAfterMs: number }|null} */
function parseRefusedFrame(f) {
  if (!f || typeof f !== 'object' || Array.isArray(f)) return null;
  if (!Object.keys(f).every((k) => REFUSED_MEMBERS.includes(k))) return null;
  const ids = f.assertionIds;
  if (!Array.isArray(ids) || ids.length < 1 || ids.length > REFUSAL_IDS_MAX || !ids.every((id) => typeof id === 'string' && ASSERTION_ID.test(id))) return null;
  if (!Number.isInteger(f.retryAfterMs) || f.retryAfterMs < 0 || f.retryAfterMs > 3_600_000) return null;
  return { ids: [...new Set(ids)], retryAfterMs: Math.min(Math.max(f.retryAfterMs, RETRY_AFTER_MIN_MS), RETRY_AFTER_MAX_MS) };
}

/**
 * One session's outbound record budget, as its receiver sees it: two buckets (count and size), the
 * peer's advertised budget once it has said it (LEGACY_BUDGET until then), and a back-off a refusal
 * set. Both ends start a session with full buckets, so a sender that spends here never exceeds what
 * the receiver holds for it.
 */
class OutboundBudget {
  constructor(now = Date.now()) {
    this.budget = LEGACY_BUDGET;
    this.advertised = false;
    this.count = { tokens: LEGACY_BUDGET.recordsBurst, at: now };
    this.chars = { tokens: LEGACY_BUDGET.charsBurst, at: now };
    this.spent = { records: 0, chars: 0 };
    this.backoffUntil = 0;
  }

  /**
   * The peer said its budget. The first time, the buckets start from what the receiver can at least
   * hold now: its burst less everything sent on this session so far (it may hold more, never less).
   * A later one changes the rates and keeps what the buckets hold, within the new bursts.
   */
  apply(b, now = Date.now()) {
    if (!this.advertised) {
      this.count = { tokens: Math.max(0, b.recordsBurst - this.spent.records), at: now };
      this.chars = { tokens: Math.max(0, b.charsBurst - this.spent.chars), at: now };
    } else {
      this.count = { tokens: Math.min(refillBucket(this.count, this.budget.recordsPerSecond, this.budget.recordsBurst, now).tokens, b.recordsBurst), at: now };
      this.chars = { tokens: Math.min(refillBucket(this.chars, this.budget.charsPerSecond, this.budget.charsBurst, now).tokens, b.charsBurst), at: now };
    }
    this.budget = b;
    this.advertised = true;
  }

  /** Milliseconds until a record of `chars` may be written: 0 now. */
  wait(chars, now = Date.now()) {
    const b = this.budget;
    return Math.max(
      this.backoffUntil > now ? this.backoffUntil - now : 0,
      bucketWait(this.count, b.recordsPerSecond, b.recordsBurst, 1, now),
      Number.isFinite(b.charsBurst) ? bucketWait(this.chars, b.charsPerSecond, b.charsBurst, chars, now) : 0,
    );
  }

  /** Spend a record of `chars` (written). A record past what the buckets hold (an anchor) still spends. */
  take(chars, now = Date.now()) {
    const b = this.budget;
    refillBucket(this.count, b.recordsPerSecond, b.recordsBurst, now);
    this.count.tokens -= 1;
    if (Number.isFinite(b.charsBurst)) {
      refillBucket(this.chars, b.charsPerSecond, b.charsBurst, now);
      this.chars.tokens -= Math.min(chars, b.charsBurst);
    }
    this.spent.records += 1;
    this.spent.chars += chars;
  }

  /** The receiver refused records: nothing more is written to this session for `ms`. */
  backOff(ms, now = Date.now()) {
    this.backoffUntil = Math.max(this.backoffUntil, now + ms);
  }
}

// ── The receiver's admission queue ─────────────────────────────────────────────────────────────

/**
 * Records past a session's budget, waiting for it to refill (one FIFO per session), and the refusal
 * notices owed to peers. The owner (the frame handler) supplies the budget and the work:
 *
 *   wait(session, chars, now)   ms until the session's budget holds a record of `chars` (0: now)
 *   run(entry)                  admit one record now (spends the budget and processes it)
 *   admitted(entry)             whether its peer is still admitted (the door, a penalty): or dropped
 *   sessionFor(peerId)          the peer's open session for a notice, or null
 *   cut(session)                the penalty for a session that keeps sending past the bound
 *   fail(entry, err)            a record that threw while it was admitted from the queue
 *   metric(m), say(key, line)
 */
class RecordAdmission {
  constructor(o) {
    this._o = o;
    this.limits = { queueRecords: QUEUE_RECORDS, queueChars: QUEUE_CHARS, totalRecords: QUEUE_TOTAL_RECORDS, totalChars: QUEUE_TOTAL_CHARS, refusalsBeforeCut: REFUSALS_BEFORE_CUT };
    this._sessions = new Set();
    this._notices = new Map();
    this.total = { records: 0, chars: 0 };
    this.stats = { queued: 0, admittedLate: 0, refused: 0, dropped: 0, notices: 0, noticedIds: 0, unlisted: 0, unsent: 0, cut: 0, peakRecords: 0, peakChars: 0 };
  }

  _queueOf(session) {
    return session._admitQueue || (session._admitQueue = { items: [], head: 0, chars: 0, timer: null });
  }

  /**
   * A record arrived on `session`. Admitted now when nothing of the session's waits and its budget
   * holds it (what run returns is returned); otherwise queued behind what waits, or, past a bound,
   * refused and the sender told. @returns {*} run's result, or undefined
   */
  offer(session, peerId, peerName, msg, chars, now = Date.now()) {
    const q = this._queueOf(session);
    const waiting = q.items.length - q.head;
    const entry = { session, peerId, peerName, msg, chars };
    if (waiting === 0 && this._o.wait(session, chars, now) === 0) return this._o.run(entry);
    const L = this.limits;
    if (waiting >= L.queueRecords || q.chars + chars > L.queueChars) return this._refuse(entry, 'session-queue-full', now);
    if (this.total.records >= L.totalRecords || this.total.chars + chars > L.totalChars) return this._refuse(entry, 'queue-full', now);
    q.items.push(entry);
    q.chars += chars;
    this.total.records++;
    this.total.chars += chars;
    this.stats.queued++;
    if (this.total.records > this.stats.peakRecords) this.stats.peakRecords = this.total.records;
    if (this.total.chars > this.stats.peakChars) this.stats.peakChars = this.total.chars;
    this._sessions.add(session);
    this._o.metric({ type: 'cmb-queued', from: peerName, peer: peerId, key: keyOf(msg), waiting: waiting + 1 });
    if (!q.timer) this._arm(session, q, this._o.wait(session, q.items[q.head].chars, now));
    return undefined;
  }

  _arm(session, q, ms) {
    q.timer = setTimeout(() => { q.timer = null; this._drain(session); }, Math.max(ms, 1));
    if (q.timer.unref) q.timer.unref();
  }

  _shift(session, q) {
    const e = q.items[q.head];
    q.items[q.head] = undefined;
    q.head++;
    if (q.head > 64 && q.head * 2 > q.items.length) { q.items = q.items.slice(q.head); q.head = 0; }
    q.chars -= e.chars;
    this.total.records--;
    this.total.chars -= e.chars;
    return e;
  }

  /** Admit what the budget now holds, in order; re-arm for the next. */
  _drain(session) {
    const q = session._admitQueue;
    if (!q) return;
    while (q.items.length - q.head > 0) {
      const head = q.items[q.head];
      if (!this._o.admitted(head)) {
        this._shift(session, q);
        this.stats.dropped++;
        this._o.metric({ type: 'cmb-queue-dropped', from: head.peerName, peer: head.peerId, key: keyOf(head.msg), reason: 'not-admitted' });
        continue;
      }
      const now = Date.now();
      const w = this._o.wait(session, head.chars, now);
      if (w > 0) { this._arm(session, q, w); return; }
      const e = this._shift(session, q);
      this.stats.admittedLate++;
      try { this._o.run(e); } catch (err) { this._o.fail(e, err); }
    }
    q.items = [];
    q.head = 0;
    this._sessions.delete(session);
    // The session's queue drained: a peer told and back within its budget starts over.
    const n = this._notices.get(session.nodeId);
    if (n) { n.refusedSinceTold = 0; n.toldAt = 0; n.episode = false; }
  }

  _refuse(entry, reason, now) {
    const { session, peerId, peerName, msg } = entry;
    this.stats.refused++;
    this._o.metric({ type: 'cmb-queue-refused', from: peerName, peer: peerId, key: keyOf(msg), reason });
    this._o.say(`${peerId}|queue-refused`, `CMBs from ${peerName} refused: past ${reason === 'queue-full' ? 'this node\'s queue for all sessions' : 'its session\'s queue'} (${this.limits.queueRecords} records or ${this.limits.queueChars} characters a session, ${this.limits.totalRecords} in all); the sender is told to retry`);
    const n = this._noticeOf(peerId, now);
    const id = msg && msg.cmb && msg.cmb.metadata ? msg.cmb.metadata.assertionId : null;
    if (typeof id === 'string' && ASSERTION_ID.test(id)) {
      if (n.ids.length < REFUSAL_PENDING_MAX) n.ids.push(id);
      else this.stats.unlisted++;
    } else {
      this.stats.unlisted++;
    }
    // Only a peer past ITS OWN queue can be cut: it sent more than QUEUE_SECONDS of its budget ahead
    // of it. A paced sender never does; one refused because every session's queue together is full
    // (others filled it) is not at fault, and is only told when to retry. An EPISODE is the time a
    // peer's own queue is full: it starts with such a refusal and ends when the queue drains. Told
    // means a notice went out during the episode (one for its tail, sent after the queue drained,
    // tells nothing about the next), and what it sends past the bound after that counts.
    if (reason === 'queue-full') n.othersFull = true;
    if (reason === 'session-queue-full') n.episode = true;
    if (n.toldAt) {
      n.refusedSinceTold++;
      if (n.refusedSinceTold > this.limits.refusalsBeforeCut) {
        n.refusedSinceTold = 0;
        this.stats.cut++;
        this._o.cut(session);
      }
    }
    this._scheduleNotice(peerId, n, now);
    return undefined;
  }

  _noticeOf(peerId, now) {
    let n = this._notices.get(peerId);
    if (!n) {
      if (this._notices.size >= REFUSAL_PEERS_MAX) {
        const [oldId, old] = this._notices.entries().next().value;
        this._dropNotice(oldId, old, 'too-many-peers');
      }
      n = { ids: [], lastAt: 0, toldAt: 0, refusedSinceTold: 0, episode: false, othersFull: false, timer: null, since: now };
      this._notices.set(peerId, n);
    }
    return n;
  }

  _dropNotice(peerId, n, why) {
    if (n.timer) clearTimeout(n.timer);
    if (n.ids.length) {
      this.stats.unsent += n.ids.length;
      this._o.metric({ type: 'cmb-refusal-unsent', peer: peerId, count: n.ids.length, reason: why });
    }
    this._notices.delete(peerId);
  }

  _scheduleNotice(peerId, n, now) {
    if (n.timer || !n.ids.length) return;
    const due = Math.max(0, n.lastAt + REFUSAL_NOTICE_MS - now);
    n.timer = setTimeout(() => { n.timer = null; this.flush(peerId); }, due);
    if (n.timer.unref) n.timer.unref();
  }

  /**
   * The retry-after a notice carries: the time the session's own queue needs to drain at its budget,
   * or, when a record was refused because every session's queue together was full, the time the
   * longest one needs; within RETRY_AFTER_MIN_MS and RETRY_AFTER_MAX_MS.
   */
  _retryAfter(session, othersFull) {
    const drain = (q) => (q ? Math.max(((q.items.length - q.head) * 1000) / RECORDS_PER_SECOND, (q.chars * 1000) / RECORD_CHARS_PER_SECOND) : 0);
    let ms = drain(session && session._admitQueue);
    if (othersFull) for (const s of this._sessions) ms = Math.max(ms, drain(s._admitQueue));
    return Math.round(Math.min(Math.max(ms, RETRY_AFTER_MIN_MS), RETRY_AFTER_MAX_MS));
  }

  /**
   * Send `peerId` what it is owed: one `cmb-refused` frame naming up to REFUSAL_IDS_MAX refused
   * assertionIds, at most once every REFUSAL_NOTICE_MS (`force`: now, in as many frames as it takes).
   * With no open session for the peer the notice waits for its next one, at most REFUSAL_PENDING_MS.
   */
  flush(peerId, { force = false } = {}) {
    const n = this._notices.get(peerId);
    if (!n || !n.ids.length) return;
    const now = Date.now();
    if (!force && n.lastAt && now - n.lastAt < REFUSAL_NOTICE_MS) { this._scheduleNotice(peerId, n, now); return; }
    const session = this._o.sessionFor(peerId);
    if (!session) {
      if (now - n.since > REFUSAL_PENDING_MS) this._dropNotice(peerId, n, 'no-session');
      return;
    }
    do {
      const ids = n.ids.splice(0, REFUSAL_IDS_MAX);
      const retryAfterMs = this._retryAfter(session, n.othersFull);
      let sent = false;
      try { sent = session.trySend({ type: REFUSED_FRAME, assertionIds: ids, retryAfterMs }).ok === true; } catch { sent = false; }
      if (!sent) {
        this.stats.unsent += ids.length;
        this._o.metric({ type: 'cmb-refusal-unsent', peer: peerId, count: ids.length, reason: 'send-failed' });
        break;
      }
      this.stats.notices++;
      this.stats.noticedIds += ids.length;
      n.lastAt = now;
      n.since = now;
      n.othersFull = false;
      if (n.episode && !n.toldAt) n.toldAt = now;
      this._o.metric({ type: 'cmb-refusal-sent', peer: peerId, count: ids.length, retryAfterMs });
    } while (force && n.ids.length);
    if (n.ids.length) this._scheduleNotice(peerId, n, now);
  }

  /** Whatever waits for the peer goes on its new session (called when one is admitted). */
  flushFor(peerId) {
    const n = this._notices.get(peerId);
    if (n && n.ids.length && !n.timer) this.flush(peerId);
  }

  /**
   * The node stops: every queued record is refused — its sender told, where a session is still open,
   * so it offers the record again to this node's next session — and every timer cleared.
   * @returns {number} the records refused
   */
  stop() {
    let n = 0;
    for (const session of [...this._sessions]) {
      const q = session._admitQueue;
      if (!q) continue;
      if (q.timer) { clearTimeout(q.timer); q.timer = null; }
      while (q.items.length - q.head > 0) {
        const e = this._shift(session, q);
        n++;
        const notice = this._noticeOf(e.peerId, Date.now());
        const id = e.msg && e.msg.cmb && e.msg.cmb.metadata ? e.msg.cmb.metadata.assertionId : null;
        if (typeof id === 'string' && ASSERTION_ID.test(id)) notice.ids.push(id);
        this.stats.refused++;
        this._o.metric({ type: 'cmb-queue-refused', from: e.peerName, peer: e.peerId, key: keyOf(e.msg), reason: 'node-stopping' });
      }
      q.items = [];
      q.head = 0;
    }
    this._sessions.clear();
    for (const peerId of [...this._notices.keys()]) {
      const notice = this._notices.get(peerId);
      if (notice.timer) { clearTimeout(notice.timer); notice.timer = null; }
      this.flush(peerId, { force: true });
      const left = this._notices.get(peerId);
      if (left) this._dropNotice(peerId, left, 'node-stopped');
    }
    this._notices.clear();
    this.total = { records: 0, chars: 0 };
    return n;
  }

  /** What status() reports. */
  status() {
    return {
      queuedRecords: this.total.records,
      queuedChars: this.total.chars,
      queuedSessions: this._sessions.size,
      ...this.stats,
      limits: { ...this.limits },
    };
  }
}

function keyOf(msg) {
  const md = msg && msg.cmb && msg.cmb.metadata;
  return md && typeof md.key === 'string' ? md.key : null;
}

module.exports = {
  RECORDS_PER_SECOND, RECORDS_BURST, RECORD_CHARS_PER_SECOND, RECORD_CHARS_BURST,
  QUEUE_SECONDS, QUEUE_RECORDS, QUEUE_CHARS, QUEUE_TOTAL_RECORDS, QUEUE_TOTAL_CHARS,
  REFUSAL_NOTICE_MS, REFUSAL_IDS_MAX, REFUSAL_PENDING_MAX, RETRY_AFTER_MIN_MS, RETRY_AFTER_MAX_MS,
  REFUSALS_BEFORE_CUT, FLOOD_PENALTY_MS,
  BUDGET_FRAME, REFUSED_FRAME, LEGACY_BUDGET, HELD_REFUSALS_MAX, HELD_MAX_AGE_MS, SENT_WINDOW_MS, SENT_WINDOW_MAX, UNDELIVERED_LOG_MAX,
  recordChars, refillBucket, bucketWait, budgetFrame, parseBudgetFrame, parseRefusedFrame,
  OutboundBudget, RecordAdmission,
};
