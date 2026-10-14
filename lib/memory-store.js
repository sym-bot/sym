'use strict';

const { recordCreatedBy, recordCreatedAt, recordLineage, recordParents } = require('./record');

/**
 * Memory Store — Context Curation Engine for SYM Mesh.
 *
 * Not a database. The substrate of the remix graph — the growing DAG
 * of Cognitive Memory Blocks that constitutes collective intelligence.
 *
 * Primary operation: curate() — deliver the minimum context an agent's
 * LLM needs to reason correctly. ~500 tokens instead of 1M.
 *
 * Storage: flat JSON files + in-memory index. Zero dependencies.
 *
 * See MMP v0.2.0 Section 6 (Memory), Section 14 (Remix).
 *
 * Copyright (c) 2026 SYM.BOT. Apache 2.0 License.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { ensureDir } = require('./config');
const { isLineageSevered, wellFormedRecord, isWellFormedText, toWellFormedText, cutText } = require('./core');

// ── In-Memory Index ──────────────────────────────────────────

/**
 * In-memory index for fast CMB lookups by key, time, and ancestry.
 * @private
 */
/** A stored record file: every .json in the store except the one-off migration marker. */
const isStoreFile = (f) => f.endsWith('.json') && f !== 'migration-v1.json';

/**
 * The store's lineage for an entry whose lineage this node severed (§15.8): a root, marked as
 * severed so every walk of stored lineage knows not to follow the parents the record still names.
 */
function severedLineage() {
  return { parents: [], ancestors: [], method: null, severed: true };
}

/**
 * What this node records ABOUT a stored record, which lives on the entry beside the record: the
 * admission attestation, the §15.8 tether attestation, the fusion provenance, and whether the
 * record is the incoming block itself.
 */
const ENTRY_ANNOTATIONS = Object.freeze(['admission', 'tether', 'provenance', 'collapsed']);

/**
 * An entry whose record is exactly what was signed, for every entry the store writes or reads.
 *
 * A two-section record has exactly `categories` and `metadata` (§8.8.1). Stores before 0.14.0 put
 * more on it, and files they wrote still hold it:
 *
 *   lineage     the store's expanded lineage as a top-level member. Readers that take a top-level
 *               lineage as the record's own (the pre-boundary shape, e.g. classifyAddress) derived
 *               the wrong address from it and reported the record as a mismatch. The entry carries
 *               the same lineage on itself, so the copy is dropped.
 *   admission, tether, provenance, collapsed
 *               this node's own annotations (ENTRY_ANNOTATIONS). They move onto the entry, where
 *               they are kept; one the entry already has wins.
 *
 * Applied on write as well as on read, so a writer that still puts them on the record (an
 * injected admission engine, an older caller) cannot break the shape. A pre-boundary record (no
 * metadata) is left alone: its top-level members are its own sections.
 */
function asStored(entry) {
  // Every string the record signs, and the text rendered from it, in its well-formed spelling (review
  // M2): a store written by 0.14.2 can hold a lone surrogate a peer's record carried. Nothing signed changes.
  if (entry && typeof entry === 'object') {
    if (entry.cmb && typeof entry.cmb === 'object') entry.cmb = wellFormedRecord(entry.cmb);
    if (typeof entry.content === 'string' && !isWellFormedText(entry.content)) entry.content = toWellFormedText(entry.content);
  }
  const cmb = entry && entry.cmb;
  if (!cmb || typeof cmb !== 'object' || !cmb.metadata || typeof cmb.metadata !== 'object') return entry;
  const own = (k) => Object.prototype.hasOwnProperty.call(cmb, k);
  if (!own('lineage') && !ENTRY_ANNOTATIONS.some(own)) return entry;
  const record = { ...cmb };
  delete record.lineage;
  for (const k of ENTRY_ANNOTATIONS) {
    if (!own(k)) continue;
    if (entry[k] === undefined) entry[k] = cmb[k];
    delete record[k];
  }
  entry.cmb = record;
  return entry;
}

/**
 * The entry cache, BOUNDED (security review R2-3, 0.14.3): it held every entry the store had ever
 * seen, read at load or written since, so a peer's large records grew memory without bound. It is a
 * cache in front of the files (every entry it holds is persisted first; a miss reads the file), so it
 * keeps the most recently used entries only: at most CACHE_MAX_ENTRIES, and at most CACHE_MAX_CHARS
 * of text in all (the entry's content and category texts, measured in string length).
 */
const CACHE_MAX_ENTRIES = 2048;
const CACHE_MAX_CHARS = 32 * 1024 * 1024;

function entryWeight(e) {
  if (!e || typeof e !== 'object') return 1;
  let n = 256 + (typeof e.content === 'string' ? e.content.length : 0);
  const cats = e.cmb && e.cmb.categories;
  if (cats && typeof cats === 'object') {
    for (const v of Object.values(cats)) {
      if (typeof v === 'string') n += v.length;
      else if (v && typeof v.text === 'string') n += v.text.length;
    }
  }
  const app = e.cmb && e.cmb.metadata && e.cmb.metadata.application;
  if (app && typeof app.data === 'string') n += app.data.length;
  return n;
}

class EntryCache {
  constructor({ maxEntries = CACHE_MAX_ENTRIES, maxChars = CACHE_MAX_CHARS } = {}) {
    this._map = new Map(); // key -> { entry, weight }, least recently used first
    this._weight = 0;
    this._maxEntries = maxEntries;
    this._maxChars = maxChars;
  }
  get size() { return this._map.size; }
  get weight() { return this._weight; }
  has(key) { return this._map.has(key); }
  get(key) {
    const slot = this._map.get(key);
    if (!slot) return undefined;
    this._map.delete(key);
    this._map.set(key, slot);
    return slot.entry;
  }
  /** The entry, without making it the most recently used: a scan reads through the cache, never into it. */
  peek(key) {
    const slot = this._map.get(key);
    return slot ? slot.entry : undefined;
  }
  set(key, entry) {
    const old = this._map.get(key);
    if (old) { this._weight -= old.weight; this._map.delete(key); }
    const weight = entryWeight(entry);
    this._map.set(key, { entry, weight });
    this._weight += weight;
    while (this._map.size > 1 && (this._map.size > this._maxEntries || this._weight > this._maxChars)) {
      const [k, slot] = this._map.entries().next().value;
      this._map.delete(k);
      this._weight -= slot.weight;
    }
    return this;
  }
  delete(key) {
    const slot = this._map.get(key);
    if (!slot) return false;
    this._weight -= slot.weight;
    return this._map.delete(key);
  }
  clear() { this._map.clear(); this._weight = 0; }
  *keys() { yield* this._map.keys(); }
  *values() { for (const s of this._map.values()) yield s.entry; }
  *entries() { for (const [k, s] of this._map) yield [k, s.entry]; }
  [Symbol.iterator]() { return this.entries(); }
}

/**
 * THE SEARCH INDEX (review M1, 0.14.3), kept apart from the entry cache. recall() matches a query
 * against each entry's text; with the cache bounded (R2-3) that read a file for every entry the cache
 * did not hold, on every call, synchronously: 6,000 entries took 140 ms a call (0.14.2, everything in
 * memory: 4 ms). What a match needs is far smaller than an entry: its rendered text, lowercased. This
 * index holds only that, per entry at most SEARCH_ENTRY_CHARS (an entry longer than that is marked
 * `partial`, and only a query its indexed text does not match reads it), and SEARCH_MAX_CHARS in all
 * (past that the oldest entries' text is let go, and only those are read). Its text is the entry's
 * content (which renders every category that is not 'neutral', mood with its numbers), its tags, and any
 * category text the content does not contain; the key is matched as it is. A query matches within one
 * of those, never across two.
 */
const SEARCH_ENTRY_CHARS = 4096;
const SEARCH_MAX_CHARS = 32 * 1024 * 1024;
/** What one indexed entry costs beyond its text (the slot and the Map's own), counted against the bound. */
const SEARCH_SLOT_CHARS = 64;

/** The lowercased text recall() matches an entry by, before the per-entry cap (see SearchIndex). */
function searchText(entry) {
  const content = typeof entry.content === 'string' ? entry.content : '';
  const parts = [content];
  for (const t of entry.tags || []) if (typeof t === 'string' && t) parts.push(t);
  const cats = entry.cmb && entry.cmb.categories;
  if (cats && typeof cats === 'object') {
    const seen = new Set();
    for (const v of Object.values(cats)) {
      const t = v && typeof v.text === 'string' ? v.text : null;
      if (t && !seen.has(t) && !content.includes(t)) { seen.add(t); parts.push(t); }
    }
  }
  return parts.join('\n').toLowerCase();
}

class SearchIndex {
  constructor({ maxChars = SEARCH_MAX_CHARS, entryChars = SEARCH_ENTRY_CHARS } = {}) {
    this._map = new Map(); // key -> { text, partial }, the oldest stored first
    this._chars = 0;
    this._maxChars = maxChars;
    this._entryChars = entryChars;
    this._staged = null;
  }
  get size() { return this._map.size; }
  /** The characters held, slots included. */
  get chars() { return this._chars; }
  get(key) { return this._map.get(key); }
  /** @private An entry's slot: its text, at most its share, and whether that is all of it. */
  _slot(entry) {
    const full = searchText(entry);
    const text = cutText(full, this._entryChars);
    return { text, partial: text.length < full.length };
  }
  /** @private Put a slot in as the newest, then let the oldest go while over the bound. */
  _put(key, slot) {
    this.delete(key);
    this._map.set(key, slot);
    this._chars += slot.text.length + SEARCH_SLOT_CHARS;
    for (const k of this._map.keys()) {
      if (this._chars <= this._maxChars) break;
      this.delete(k);
    }
  }
  /** Index an entry just stored (the newest). */
  add(key, entry) { this._put(key, this._slot(entry)); }
  /**
   * Index an entry read while the store loads, in any order: held aside (its slot only) until commit(),
   * which puts them in the order they were stored, so the bound lets the oldest go.
   */
  stage(key, entry, storedAt) {
    const slot = this._slot(entry);
    (this._staged ||= []).push([storedAt || 0, key, slot]);
    this._stagedChars = (this._stagedChars || 0) + slot.text.length + SEARCH_SLOT_CHARS;
    // Held aside within twice the bound: past it, only the newest that fit the bound are kept.
    if (this._stagedChars > 2 * this._maxChars) this._keepNewestStaged();
  }
  /** @private */
  _keepNewestStaged() {
    this._staged.sort((a, b) => b[0] - a[0]);
    let n = 0; let i = 0;
    for (; i < this._staged.length; i++) {
      const c = this._staged[i][2].text.length + SEARCH_SLOT_CHARS;
      if (n + c > this._maxChars) break;
      n += c;
    }
    this._staged.length = i;
    this._stagedChars = n;
  }
  commit() {
    const staged = this._staged || [];
    this._staged = null;
    this._stagedChars = 0;
    staged.sort((a, b) => a[0] - b[0]);
    for (const [, key, slot] of staged) this._put(key, slot);
  }
  delete(key) {
    const slot = this._map.get(key);
    if (!slot) return false;
    this._chars -= slot.text.length + SEARCH_SLOT_CHARS;
    return this._map.delete(key);
  }
}

class MemoryIndex {
  /** Create an empty index. */
  constructor() {
    this.byKey = new Map();        // key → IndexEntry
    this.byTime = [];              // sorted by storedAt desc
    this.byAncestor = new Map();   // ancestorKey → Set<descendantKey>
  }

  /**
   * Add an entry to the index. Deduplicates by key.
   * @param {object} entry — index entry with key, storedAt, ancestors, etc.
   * @returns {boolean} true if added, false if duplicate
   */
  add(entry) {
    if (this.byKey.has(entry.key)) return false; // dedup

    this.byKey.set(entry.key, entry);

    // Insert into sorted time array (most recent first)
    const idx = this.byTime.findIndex(k => {
      const e = this.byKey.get(k);
      return e && e.storedAt <= entry.storedAt;
    });
    if (idx === -1) this.byTime.push(entry.key);
    else this.byTime.splice(idx, 0, entry.key);

    // Update reverse ancestor index
    for (const ancestorKey of entry.ancestors || []) {
      if (!this.byAncestor.has(ancestorKey)) {
        this.byAncestor.set(ancestorKey, new Set());
      }
      this.byAncestor.get(ancestorKey).add(entry.key);
    }

    return true;
  }

  /**
   * Remove an entry from the index.
   * @param {string} key — CMB key to remove
   */
  remove(key) {
    const entry = this.byKey.get(key);
    if (!entry) return;

    this.byKey.delete(key);
    const timeIdx = this.byTime.indexOf(key);
    if (timeIdx !== -1) this.byTime.splice(timeIdx, 1);

    for (const ancestorKey of entry.ancestors || []) {
      this.byAncestor.get(ancestorKey)?.delete(key);
    }
  }

  /** @param {string} key @returns {boolean} */
  has(key) { return this.byKey.has(key); }
  /** @param {string} key @returns {object|undefined} */
  get(key) { return this.byKey.get(key); }
  /** @returns {number} */
  get size() { return this.byKey.size; }

  /**
   * Most recent CMB keys.
   * @param {number} limit — max keys to return
   * @returns {Array<string>}
   */
  recentKeys(limit) {
    return this.byTime.slice(0, limit);
  }

  /**
   * All descendant keys of a CMB.
   * @param {string} key — ancestor CMB key
   * @returns {Set<string>}
   */
  descendants(key) {
    return this.byAncestor.get(key) || new Set();
  }
}

/**
 * The newest entries read while a store is loaded, at most `max` of them held at once (twice that
 * between trims): what the entry cache is filled with when the load ends, so it starts with the entries
 * read newest first (recall's order, the anchors', recent()'s), not with whichever files were read last.
 */
class NewestEntries {
  constructor(max) { this._max = max; this._list = []; }
  add(entry) {
    this._list.push(entry);
    if (this._list.length > 2 * this._max) this._trim();
  }
  _trim() {
    this._list.sort((a, b) => (b.storedAt || b.timestamp || 0) - (a.storedAt || a.timestamp || 0));
    this._list.length = Math.min(this._list.length, this._max);
  }
  /** Put them in `cache`, the oldest first, so the newest are the most recently used. */
  fill(cache) {
    this._trim();
    for (let i = this._list.length - 1; i >= 0; i--) cache.set(this._list[i].key, this._list[i]);
    this._list = [];
  }
}

// ── Memory Store ─────────────────────────────────────────────

class MemoryStore {
  /**
   * @param {string} cmbsDir — path to cmbs directory (flat, single dir)
   * @param {string} sourceName — this agent's name
   * @param {object} opts
   * @param {string} opts.legacyDir — old memories/ dir for one-time migration
   */
  constructor(cmbsDir, sourceName, opts = {}) {
    this._dir = cmbsDir;
    this._source = sourceName;
    this.__indexed = false;   // has the index been built (by either path)?
    this.__loading = null;    // the in-flight asynchronous load, if any
    this._index = new MemoryIndex();
    this._cache = new EntryCache(); // key → full entry (avoids disk reads); bounded (R2-3)
    this._search = new SearchIndex(); // key → the text recall() matches (review M1); bounded

    ensureDir(this._dir);

    // One-time migration from legacy layout
    if (opts.legacyDir && fs.existsSync(opts.legacyDir) && !this._migrated()) {
      this._migrate(opts.legacyDir);
    }

    // The index is NOT built here any more. It used to be — synchronously, reading and parsing
    // every file in the store — and a runtime that constructs several nodes at boot held its event
    // loop for minutes while doing it (core-team, 26 Sep 2026: the largest store was 3,237 files).
    // SymNode.start() now awaits load(), which builds it asynchronously. Anything that touches the
    // index before that builds it synchronously through _ensureIndex(), exactly as before, so no
    // caller can ever observe an unbuilt store.
  }

  /**
   * THE INDEX AND CACHE ARE ONLY REACHABLE THROUGH THESE ACCESSORS, and each guarantees they are
   * built. The alternative — calling _ensureIndex() at the top of every method — fails silently for
   * the one method somebody forgets, and it fails in the worst direction: an unbuilt index returns
   * nothing, which reads as an empty store rather than as a store nobody looked at. With the
   * accessors there is no method to forget, including the two in lib/node.js that reach in directly.
   */
  get _index() { this._ensureIndex(); return this.__index; }
  set _index(v) { this.__index = v; }
  get _cache() { this._ensureIndex(); return this.__cache; }
  set _cache(v) { this.__cache = v; }
  get _search() { this._ensureIndex(); return this.__search; }
  set _search(v) { this.__search = v; }

  /** Build the index synchronously if nothing has yet — the old behaviour, now the fallback. */
  _ensureIndex() {
    if (this.__indexed) return;
    this.__indexed = true;   // set first, so _buildIndex's own accessor use does not recurse
    this._buildIndex();
  }

  /**
   * Build the index WITHOUT holding the event loop: listing and reads go through fs.promises in
   * batches, yielding between them, into a fresh index and cache that are swapped in whole. If
   * anything touched the store while this ran, the synchronous fallback has already built an
   * authoritative index — possibly with writes applied since — so this result is discarded rather
   * than merged. Idempotent; concurrent callers share one load.
   */
  async load(opts = {}) {
    if (this.__indexed) return;
    if (this.__loading) return this.__loading;
    const batch = Math.max(1, opts.batch ?? 64);
    this.__loading = (async () => {
      const index = new MemoryIndex();
      const cache = new EntryCache();
      const search = new SearchIndex();
      const newest = new NewestEntries(CACHE_MAX_ENTRIES);
      let files = [];
      try { files = (await fs.promises.readdir(this._dir)).filter(isStoreFile); } catch { files = []; }
      for (let i = 0; i < files.length; i += batch) {
        const slice = files.slice(i, i + batch);
        const parsed = await Promise.all(slice.map(async (file) => {
          const filePath = path.join(this._dir, file);
          try { return { filePath, entry: asStored(JSON.parse(await fs.promises.readFile(filePath, 'utf8'))) }; }
          catch (e) { console.error(`[SYM] cmbs: failed to index ${file}: ${e.message}`); return null; }
        }));
        for (const p of parsed) {
          if (!p) continue;
          const ie = this._indexEntryFor(p.entry, p.filePath);
          if (!index.add(ie)) continue;
          search.stage(p.entry.key, p.entry, ie.storedAt);
          newest.add(p.entry);
        }
      }
      if (this.__indexed) return;   // a synchronous fallback won the race; its index is authoritative
      newest.fill(cache);
      search.commit();
      this.__index = index;
      this.__cache = cache;
      this.__search = search;
      this.__indexed = true;
    })();
    try { await this.__loading; } finally { this.__loading = null; }
  }

  /** One index entry from one stored record — shared by both build paths so they cannot drift. */
  _indexEntryFor(entry, filePath) {
    // A severed entry is a root to this store although its record still names parents as signed.
    const severed = isLineageSevered(entry);
    return {
      key: entry.key,
      storedAt: entry.storedAt || entry.timestamp || 0,
      createdAt: recordCreatedAt(entry.cmb),
      lifecycle: entry.lifecycle || 'observed',
      createdBy: recordCreatedBy(entry.cmb) || entry.source || this._source,
      peerId: entry.peerId || null,
      parents: severed ? [] : (entry.lineage?.parents || recordParents(entry.cmb)),
      ancestors: severed ? [] : (entry.lineage?.ancestors || recordLineage(entry.cmb)?.ancestors || []),
      tier: entry.tier || 'hot',
      filePath,
    };
  }

  // ── Write (append-only, immutable) ───────────────────────

  /**
   * Store a local CMB. Returns entry or null if duplicate.
   */
  write(content, opts = {}) {
    const cmb = opts.cmb || null;
    const key = this._cmbKey(cmb, content);

    // Dedup by CMB key
    if (this._index.has(key)) return null;

    // Compute lineage ancestors if parents provided
    const lineage = this._expandLineage(recordLineage(cmb));

    const now = Date.now();
    const entry = {
      key,
      content,
      source: this._source,
      tags: opts.tags || [],
      originTimestamp: opts.originTimestamp || now,
      storedAt: now,
      timestamp: now,
      peerId: null,
      tier: 'hot',
      lifecycle: 'observed',
      // The record as signed. The store's expanded lineage goes on the entry, never into the record:
      // a two-section record has exactly two members (§8.8.1).
      cmb: cmb ? { ...cmb } : null,
      lineage,
    };

    asStored(entry);
    if (!this._persist(entry)) return null;

    this._cache.set(key, entry);
    this._index.add({
      key,
      storedAt: now,
      createdAt: recordCreatedAt(entry.cmb),
      lifecycle: 'observed',
      createdBy: this._source,
      peerId: null,
      parents: lineage?.parents || [],
      ancestors: lineage?.ancestors || [],
      tier: 'hot',
      filePath: this._filePath(key),
    });
    this._searchAdd(key, entry);

    // Section 6.4: advance parent CMB lifecycle when lineage exists.
    // A CMB with parents = remix → parent advances to 'remixed'.
    // Validation authority (Section 6.5) is checked by the caller, not here.
    this._advanceParentLifecycle(lineage, 'remixed');

    return entry;
  }

  /**
   * Store a CMB received from a peer. Deduplicates by CMB key.
   * @param {string} peerId
   * @param {object} entry
   * @param {object} opts
   * @param {string} opts.creatorRole — the role the record's author counts with for THIS record (§6.4,
   *   §6.6.10: resolved by the node against its in-force set when the weight is applied)
   * @param {function(object): string} [opts.authorityOver] — the author's lifecycle authority over
   *   another CMB ('canonical' | 'validated' | 'none'), judged on that CMB's own fields (§6.5)
   * @param {boolean} [opts.severLineage] — the gate severed this record's lineage (§15.8): store it as a
   *   root although its record, kept as signed, still names parents
   * @returns {object|null} stored entry or null if duplicate
   */
  receiveFromPeer(peerId, entry, opts = {}) {
    const cmb = entry.cmb || null;
    const key = this._cmbKey(cmb, entry.content);

    // Dedup — same CMB from multiple peers stored once
    if (this._index.has(key)) return null;

    const lineage = opts.severLineage === true ? severedLineage() : this._expandLineage(recordLineage(cmb));
    const now = Date.now();

    // Section 6.4 + 11.1: validator/anchor-origin CMBs enter at weight 2.0.
    // The elevated weight reflects the authority of the producing node.
    const creatorRole = opts.creatorRole || 'participant';
    const isValidatorOrigin = creatorRole === 'validator' || creatorRole === 'admin' || creatorRole === 'anchor';

    const stored = {
      ...entry,
      key,
      peerId,
      tier: 'hot',
      lifecycle: 'observed',
      anchorWeight: isValidatorOrigin ? 2.0 : 1.0,
      storedAt: now,
      // The record as signed; the store's expanded lineage lives on the entry (see write()).
      cmb: cmb ? { ...cmb } : null,
      lineage,
    };

    asStored(stored);
    if (!this._persist(stored)) return null;

    this._cache.set(key, stored);
    this._index.add({
      key,
      storedAt: now,
      createdAt: recordCreatedAt(stored.cmb),
      lifecycle: 'observed',
      createdBy: recordCreatedBy(cmb) || entry.source || peerId,
      peerId,
      parents: lineage?.parents || [],
      ancestors: lineage?.ancestors || [],
      tier: 'hot',
      filePath: this._filePath(key),
    });
    this._searchAdd(key, stored);

    // Section 6.4: advance parent CMB lifecycle.
    this._advanceParentLifecycle(lineage, 'remixed');

    // Section 11.1: feedback recognition — check if this CMB's parents
    // reference our own CMBs. If so, this is feedback about our output.
    // Each parent is judged on its own (§6.5): the author's authority over THAT parent, from the
    // parent's own signed fields, never from this record's.
    const over = typeof opts.authorityOver === 'function' ? opts.authorityOver : null;
    if (over && lineage?.parents?.length > 0) {
      for (const parentKey of lineage.parents) {
        const pk = typeof parentKey === 'string' ? parentKey : parentKey.key;
        const parent = this.get(pk);
        if (parent && (!parent.peerId || parent.source === this._source) && over(parent.cmb) !== 'none') {
          stored._isFeedbackOnOwnCMB = true;
          stored._feedbackParentKey = pk;
          break;
        }
      }
    }

    return stored;
  }

  // ── Read ─────────────────────────────────────────────────

  /**
   * Get a single CMB by key. Loads from disk.
   */
  get(key) {
    if (this._cache.has(key)) return this._cache.get(key);
    const idx = this._index.get(key);
    if (!idx) return null;
    const entry = this._load(idx.filePath);
    if (entry) this._cache.set(key, entry);
    return entry;
  }

  /**
   * The most recent records as SVAF anchors: a VIEW of each record carrying what the gate weighs it
   * by, which lives on the entry rather than on the record (§9.2.1: w = max(cos,0) · exp(−age/τ) ·
   * conf).
   *
   *   storedAt    the entry's receiver-local storage time, from which the gate takes the age.
   *   confidence  the entry's anchorWeight, this store's own weight for the anchor (§6.4: 2.0 once
   *               validated, 0.5 once dismissed). Absent means no reduction was claimed. A frame's
   *               `confidence` is never used: it is the sender's unsigned claim about its own block.
   *
   * These used to be the bare records, which carry neither, so every anchor read as stored this
   * instant at full weight: memory never aged and a dismissal changed nothing. The view is a new
   * object whose sections are the record's own; nothing is written onto the record.
   */
  anchors(limit = 5) {
    const keys = this._index.recentKeys(limit);
    const views = [];
    for (const key of keys) {
      const entry = this.get(key);
      if (!entry) continue;
      let record = entry.cmb;
      if (!record) {
        // Legacy entry without CMB — create on demand
        try {
          const { createCMB } = require('./core');
          record = createCMB({ rawText: entry.content, createdBy: entry.source || this._source });
        } catch { continue; /* core not available — skip */ }
      }
      const storedAt = entry.storedAt ?? entry.timestamp;
      const weight = entry.anchorWeight;
      views.push({
        ...record,
        storedAt: typeof storedAt === 'number' && Number.isFinite(storedAt) ? storedAt : undefined,
        confidence: typeof weight === 'number' && Number.isFinite(weight) && weight >= 0 ? weight : undefined,
      });
    }
    return views;
  }

  /** Backward compat alias */
  recentCMBs(limit = 5) { return this.anchors(limit); }

  /**
   * Recent entries (for context building).
   */
  recent(limit = 20) {
    const keys = this._index.recentKeys(limit);
    return keys.map(k => this.get(k)).filter(Boolean);
  }

  /** Backward compat alias */
  allEntries() { return this.recent(20); }

  /**
   * The newest `createdTimestamp` among this node's own stored records (those no peer delivered), over
   * the whole index, not a recent window: the timestamp ratchet starts from it. Read from the index,
   * which holds each record's createdTimestamp: no file is read (review M1).
   * @returns {number} 0 when there is none
   */
  newestOwnCreatedAt() {
    let max = 0;
    for (const idx of this._index.byKey.values()) {
      if (idx.peerId != null) continue;
      const t = idx.createdAt;
      if (Number.isFinite(t) && t > max) max = t;
    }
    return max;
  }

  // ── Context Curation ─────────────────────────────────────

  /**
   * Core operation. Returns projected ancestor subgraph for LLM reasoning.
   *
   * @param {string} cmbKey — the CMB to trace ancestors of
   * @param {object} categoryWeights — α_f weights { focus: 2.0, mood: 0.8, ... }
   * @param {object} opts
   * @param {number} opts.weightThreshold — minimum α_f to include category (default 1.0)
   * @param {number} opts.tokenBudget — max estimated tokens (default 500)
   * @returns {Array<{key, createdBy, createdAt, categories}>} — projected CMBs
   */
  curate(cmbKey, categoryWeights = {}, opts = {}) {
    const { weightThreshold = 1.0, tokenBudget = 500 } = opts;

    const idx = this._index.get(cmbKey);
    if (!idx) return [];

    const ancestorKeys = idx.ancestors || [];
    if (ancestorKeys.length === 0) return [];

    // Load ancestors (closest first — reverse order)
    const projected = [];
    let tokens = 0;

    for (let i = ancestorKeys.length - 1; i >= 0; i--) {
      const entry = this.get(ancestorKeys[i]);
      if (!entry?.cmb?.categories) continue;

      // Project only categories above weight threshold
      const categories = {};
      for (const [category, value] of Object.entries(entry.cmb.categories)) {
        const weight = categoryWeights[category] || 0;
        if (weight >= weightThreshold && value?.text) {
          categories[category] = value.text;
        }
      }

      if (Object.keys(categories).length === 0) continue;

      const item = {
        key: entry.key,
        createdBy: recordCreatedBy(entry.cmb) || entry.source,
        createdAt: recordCreatedAt(entry.cmb) || entry.storedAt,
        categories,
      };

      // Estimate tokens (~4 chars per token)
      const itemTokens = JSON.stringify(item).length / 4;
      if (tokens + itemTokens > tokenBudget) break;

      projected.push(item);
      tokens += itemTokens;
    }

    return projected;
  }

  // ── Graph Queries ────────────────────────────────────────

  /**
   * Full ancestor chain of a CMB (O(1) — read from index).
   */
  ancestors(key) {
    return this._index.get(key)?.ancestors || [];
  }

  /**
   * All CMBs that have key as ancestor.
   */
  descendants(key) {
    return [...this._index.descendants(key)];
  }

  /**
   * Direct parents of a CMB.
   */
  parents(key) {
    return this._index.get(key)?.parents || [];
  }

  /**
   * Sever a stored entry's lineage after the fact (§15.8 retroactive audit), on the entry and in the
   * index, never in the record. The record is immutable once stored (§8) and usually the author's
   * signed block, whose signature covers its lineage, so it keeps naming its parents; the entry
   * records that this store no longer walks them (isLineageSevered).
   *
   * The index is left exactly as a rebuild from the severed entry would leave it: the entry drops
   * out of every ancestor's descendant set and has no parents or ancestors of its own. Until then
   * a severed remix kept its old ancestors hot and unpurgeable.
   * @param {string} key
   * @returns {boolean} true when the entry exists and was persisted
   */
  severLineage(key) {
    const entry = this.get(key);
    const idx = this._index.get(key);
    if (!entry || !idx) return false;
    for (const a of idx.ancestors || []) this._index.byAncestor.get(a)?.delete(key);
    idx.parents = [];
    idx.ancestors = [];
    entry.lineage = severedLineage();
    this._cache.set(key, entry);
    return this._persist(entry);
  }

  // ── Search (user-facing) ─────────────────────────────────

  /**
   * Keyword search across CMB category texts, content, and tags: the entries whose text contains the
   * query (case-insensitive), the newest stored first. For CLI `sym recall "..."` — not for LLM
   * context curation. No query returns every entry (the agent decides relevance, not the store).
   *
   * MATCHED IN MEMORY, READ ONLY FOR WHAT IS RETURNED (review M1): the match runs on the search index
   * (SearchIndex), so a query costs no file read for an entry it does not return; an entry is read
   * (when the cache does not hold it) only to be returned, and with `limit` only that many are. A scan
   * reads through the cache and never into it, so a recall does not push the working set out.
   *
   * @param {string} query
   * @param {{ limit?: number, where?: function(object): boolean }} [opts]
   *   limit — at most this many entries are returned (and read); `where` — only entries it accepts
   *   are returned (checked newest first, so only as many are read as it takes to fill `limit`)
   * @returns {object[]} the entries; the array's non-enumerable `total` is the number of entries the
   *   query matched, whatever the limit
   */
  recall(query, opts = {}) {
    // A query is text, or none at all (null, undefined, ''): anything else is the caller's error, said, never
    // read as "no query" (which returns every entry).
    if (query != null && typeof query !== 'string') throw new TypeError(`recall: the query must be a string (got ${typeof query})`);
    const q = typeof query === 'string' && query.trim() !== '' ? query.toLowerCase() : null;
    const limit = Number.isSafeInteger(opts.limit) && opts.limit > 0 ? opts.limit : Infinity;
    const where = typeof opts.where === 'function' ? opts.where : null;
    const hits = [];
    for (const [key, idx] of this._index.byKey) {
      if (q === null || this._matches(key, idx, q)) hits.push(idx);
    }
    // Newest stored first (a stable sort: entries stored in one millisecond keep the index's order).
    hits.sort((a, b) => (b.storedAt || 0) - (a.storedAt || 0));
    const results = [];
    for (const idx of hits) {
      if (results.length >= limit) break;
      const entry = this._cache.peek(idx.key) || this._load(idx.filePath);
      if (!entry) continue;
      if (where && !where(entry)) continue;
      results.push(entry);
    }
    Object.defineProperty(results, 'total', { value: hits.length, enumerable: false, configurable: true });
    return results;
  }

  /**
   * Whether an entry's text contains `q` (already lowercased): its key, then its indexed text. Only an
   * entry the index holds no text for (past SEARCH_MAX_CHARS), or holds a prefix of that does not
   * match, is read.
   * @private
   */
  _matches(key, idx, q) {
    if (key.toLowerCase().includes(q)) return true;
    const slot = this._search.get(key);
    if (slot && slot.text.includes(q)) return true;
    if (slot && !slot.partial) return false;
    const entry = this._cache.peek(key) || this._load(idx.filePath);
    return !!entry && searchText(entry).includes(q);
  }

  /** Index an entry just stored for recall(), within the search index's bound. @private */
  _searchAdd(key, entry) {
    this._search.add(key, entry);
  }

  /** Backward compat alias */
  search(query, opts) { return this.recall(query, opts); }

  /**
   * Check if a CMB key exists in local entries (authored by this node).
   * Used for echo loop prevention (MMP §15.7, anti-echo): incoming CMBs whose
   * lineage parents exist in our local store are derivatives of our own
   * broadcasts and should be silently dropped.
   *
   * @param {string} key — CMB key to check
   * @returns {boolean} true if a local entry with this key exists
   */
  hasLocalKey(key) {
    const idx = this._index.get(key);
    if (!idx) return false;
    // Local entries have no peerId (they were written by this node)
    return !idx.peerId;
  }

  // ── Metadata ─────────────────────────────────────────────

  /** @returns {number} total CMB count */
  count() { return this._index.size; }

  /**
   * Storage statistics breakdown.
   * @returns {{ total: number, local: number, peer: number, hot: number, cold: number }}
   */
  stats() {
    let local = 0, peer = 0, hot = 0, cold = 0;
    for (const entry of this._index.byKey.values()) {
      if (entry.peerId) peer++; else local++;
      if (entry.tier === 'hot') hot++; else cold++;
    }
    return { total: this._index.size, local, peer, hot, cold };
  }

  // ── Retention ────────────────────────────────────────────

  /**
   * Move old CMBs without hot descendants to cold tier.
   * @param {number} freshnessMs — age threshold in milliseconds
   * @returns {number} count of CMBs moved to cold tier
   */
  compact(freshnessMs) {
    return this.compactByOrigin(freshnessMs, freshnessMs);
  }

  /**
   * Origin-aware compaction. Locally-authored CMBs (peerId == null)
   * use `localFreshnessMs`; peer-received CMBs use `peerFreshnessMs`.
   * Lets callers retain self CMBs longer than peer CMBs — the agent's
   * own lineage chains are higher value for retrospective analysis,
   * peer CMBs go cold sooner since their value-to-this-agent is
   * already encoded in the SVAF-admission decision.
   *
   * Lineage chains are preserved across origins — a peer entry whose
   * self-descendant is still hot stays hot regardless of
   * `peerFreshnessMs`. This matches `compact()`'s hot-descendant
   * preservation rule and keeps lineage walks intact at retention
   * boundaries.
   *
   * Callers that don't need the discrimination keep using
   * `compact(freshnessMs)` — shimmed to call this with both values
   * equal. Apps that benefit from the split configure via
   * `localRetentionSeconds` + `peerRetentionSeconds` on the SymNode
   * constructor.
   *
   * @param {number} localFreshnessMs — age threshold for self CMBs
   * @param {number} peerFreshnessMs — age threshold for peer CMBs
   * @returns {number} count of CMBs moved to cold tier
   */
  compactByOrigin(localFreshnessMs, peerFreshnessMs) {
    const now = Date.now();
    const localCutoff = now - localFreshnessMs;
    const peerCutoff = now - peerFreshnessMs;
    let moved = 0;

    for (const [key, entry] of this._index.byKey) {
      if (entry.tier !== 'hot') continue;
      // Canon tier (validated/canonical) never ages out — the persistent Canon.
      // Lifecycle lives on the full entry (the index projection omits it), so resolve it
      // through getLifecycle (cache-backed) rather than the lightweight index entry.
      if (MemoryStore.CANON_LIFECYCLES.has(this.getLifecycle(key))) continue;
      // peerId is set for received CMBs, null for locally-authored.
      // Use `!= null` (not truthy) so 0 / '' / false peerIds — which
      // shouldn't occur today but might via test fixtures or future
      // relay edge cases — are correctly classified as peer rather
      // than silently mapped to self.
      const cutoff = (entry.peerId != null) ? peerCutoff : localCutoff;
      if (entry.storedAt >= cutoff) continue; // still fresh

      // Keep hot if any descendant is hot — preserves chains
      // regardless of origin (matches `compact()` semantics). This
      // is intentional: a peer entry whose self-descendant is still
      // hot stays hot regardless of `peerFreshnessMs`, so lineage
      // chains aren't broken at retention boundaries.
      const descs = this._index.descendants(key);
      let hasHotDesc = false;
      for (const dk of descs) {
        if (this._index.get(dk)?.tier === 'hot') { hasHotDesc = true; break; }
      }
      if (hasHotDesc) continue;

      entry.tier = 'cold';
      // Update file on disk
      try {
        const full = this._load(entry.filePath);
        if (full) {
          full.tier = 'cold';
          fs.writeFileSync(entry.filePath, JSON.stringify(full, null, 2));
        }
      } catch {}
      moved++;
    }
    return moved;
  }

  /**
   * Remove cold CMBs with no descendants. Graph-safe.
   * @returns {number} count of CMBs removed
   */
  purge() {
    let removed = 0;
    const toRemove = [];

    for (const [key, entry] of this._index.byKey) {
      if (entry.tier !== 'cold') continue;
      // Canon tier (validated/canonical) is never purged, even if somehow cold — the
      // persistent Canon. Belt-and-suspenders alongside the compaction exemption.
      if (MemoryStore.CANON_LIFECYCLES.has(this.getLifecycle(key))) continue;
      if (this._index.descendants(key).size > 0) continue; // has descendants — keep

      toRemove.push(key);
    }

    for (const key of toRemove) {
      const entry = this._index.get(key);
      if (entry?.filePath) {
        try { fs.unlinkSync(entry.filePath); } catch {}
      }
      this._index.remove(key);
      this._cache.delete(key); // fully evict — a purged CMB must not resurrect from cache via get()
      this._search.delete(key);
      removed++;
    }

    return removed;
  }

  // ── Internal ─────────────────────────────────────────────

  _cmbKey(cmb, content) {
    // A v2 record carries its address in metadata; a pre-boundary one at the top level. Read
    // whichever is there — the legacy DAG stays readable (§7.8) and is never re-keyed, because
    // recomputing history is rewriting it.
    if (cmb?.metadata?.key) return cmb.metadata.key;
    if (cmb?.key) return cmb.key;

    // One source of truth for addressing, in core. This called cmbKey(), the legacy 32-hex
    // minter, which the cmb-only cutover DELETED — so this path threw for every categories-bearing
    // record the moment core moved past 0.3.x. Now blockKeyV2: the Merkle root over the seven
    // categoryKeys, content-only.
    const { blockKeyV2 } = require('./core');
    if (cmb?.categories) {
      return blockKeyV2(cmb.categories);
    }

    // Fallback for a content-only entry with no CAT7 categories at all. Deliberately NOT a CMB
    // address: it is a local store handle for something that was never a record, so it must not
    // wear the `cmb-<64hex>` shape and be mistaken for one.
    return 'local-' + crypto.createHash('sha256').update(content || '').digest('hex').slice(0, 32);
  }

  // ── CMB Lifecycle (Section 6.4) ────────────────────────

  /**
   * Lifecycle progression order. Monotonically upward under activity.
   * observed → remixed → validated → canonical → archived
   */
  static LIFECYCLE_ORDER = ['observed', 'remixed', 'validated', 'canonical', 'archived'];

  /**
   * Canon tier — grounded cognition that MUST NOT expire. A Canon compounds across days;
   * cognition the mesh has earned to `validated` (validator-attested) or `canonical` (anchor-
   * attested) is exempt from age-based compaction and purge. Its lineage is preserved for free:
   * compaction keeps an entry hot while it has a hot descendant, so keeping a validated CMB hot
   * keeps its whole ancestor chain hot. `archived`/`dismissed` are NOT Canon tier — they fade.
   */
  static CANON_LIFECYCLES = new Set(['validated', 'canonical']);

  /**
   * Advance parent CMBs' lifecycle when a child CMB with lineage is stored.
   * Only advances forward (observed → remixed, etc.), never backward.
   * @private
   */
  _advanceParentLifecycle(lineage, targetLifecycle) {
    if (!lineage?.parents?.length) return;
    const order = MemoryStore.LIFECYCLE_ORDER;
    const targetIdx = order.indexOf(targetLifecycle);
    if (targetIdx < 0) return;

    for (const parentKey of lineage.parents) {
      const entry = this.get(parentKey);
      if (!entry) continue;

      const currentLifecycle = entry.lifecycle || 'observed';
      const currentIdx = order.indexOf(currentLifecycle);

      // Only advance forward, never backward. Archived can re-emerge to remixed.
      if (currentLifecycle === 'archived' || targetIdx > currentIdx) {
        entry.lifecycle = targetLifecycle;
        this._cache.set(parentKey, entry);
        this._persist(entry);
      }
    }
  }

  /**
   * Mark a CMB as validated. Per MMP §6.5 validation authority is identity-bound and
   * EARNED — only a node whose role resolves to validator-or-above may advance a CMB to
   * `validated`. The caller passes its lifecycle authority over THIS CMB (`lifecycle`); `none` (or a
   * missing/unknown role) is rejected and the CMB is left untouched. Authority is checked
   * here, by construction, so no future caller can validate without earned rank.
   * @param {string} key — CMB key to validate
   * @param {object} [opts]
   * @param {'none'|'validated'|'canonical'} [opts.lifecycle] the caller's lifecycle authority over THIS
   *   CMB (§6.5: resolved against the in-force set, a scoped grant only inside its scope)
   * @returns {{ ok: boolean, reason?: string }}
   */
  validateCMB(key, opts = {}) {
    if (opts.lifecycle !== 'validated' && opts.lifecycle !== 'canonical') {
      return { ok: false, reason: 'insufficient-authority' };
    }
    const entry = this.get(key);
    if (!entry) return { ok: false, reason: 'unknown-cmb' };
    entry.lifecycle = 'validated';
    entry.anchorWeight = 2.0;
    this._cache.set(key, entry);
    this._persist(entry);
    return { ok: true };
  }

  /**
   * Advance a validated CMB to `canonical` — the strongest lifecycle state. Per §6.5
   * canonization is reserved to anchor authority (the founder root or an anchor-rooted
   * grantee); validator rank is NOT enough. Same earned-authority gate as validateCMB.
   * @param {string} key
   * @param {object} [opts]
   * @param {'none'|'validated'|'canonical'} [opts.lifecycle] the caller's lifecycle authority over THIS CMB
   * @returns {{ ok: boolean, reason?: string }}
   */
  canonizeCMB(key, opts = {}) {
    if (opts.lifecycle !== 'canonical') {
      return { ok: false, reason: 'insufficient-authority' };
    }
    const entry = this.get(key);
    if (!entry) return { ok: false, reason: 'unknown-cmb' };
    entry.lifecycle = 'canonical';
    entry.anchorWeight = Math.max(entry.anchorWeight ?? 1.0, 2.0);
    this._cache.set(key, entry);
    this._persist(entry);
    return { ok: true };
  }

  /**
   * Dismiss a CMB — human rejected this signal. Anchor weight drops to 0.5.
   * Terminal state — does not advance to validated or canonical.
   * MMP Section 6.4. Per §6.5 dismissal takes the same earned authority as validation (validator or above), so
   * it takes the same argument: the caller passes its lifecycle authority over THIS CMB (`lifecycle`), and
   * `none` (or a missing/unknown value) is refused and leaves the CMB untouched.
   * @param {string} key
   * @param {object} [opts]
   * @param {'none'|'validated'|'canonical'} [opts.lifecycle] the caller's lifecycle authority over THIS CMB
   * @returns {{ ok: boolean, reason?: string }}
   */
  dismissCMB(key, opts = {}) {
    if (opts.lifecycle !== 'validated' && opts.lifecycle !== 'canonical') {
      return { ok: false, reason: 'insufficient-authority' };
    }
    const entry = this.get(key);
    if (!entry) return { ok: false, reason: 'unknown-cmb' };
    entry.lifecycle = 'dismissed';
    entry.anchorWeight = 0.5;
    this._cache.set(key, entry);
    this._persist(entry);
    return { ok: true };
  }

  /**
   * Get the lifecycle state of a CMB.
   * @param {string} key
   * @returns {string} lifecycle state or 'observed'
   */
  getLifecycle(key) {
    // The index holds it (kept by _persist), so compaction and purge read no file for it (review M1).
    const idx = this._index.get(key);
    if (idx && typeof idx.lifecycle === 'string') return idx.lifecycle;
    const entry = this.get(key);
    return entry?.lifecycle || 'observed';
  }

  _expandLineage(lineage) {
    if (!lineage) return { parents: [], ancestors: [], method: null };

    const parents = lineage.parents || [];
    const method = lineage.method || null;

    // Ancestors are a LOCAL, VERIFIED closure — walked from this node's own parents through the
    // local index, never seeded from the wire. MMP v2.0: metadata.lineage carries {parents,
    // method} ONLY (emit.js §7.5), so a record's own ancestors are the direct-parent-only signed
    // contract; the transitive closure is derived by verified graph traversal here, not carried.
    //
    // The old code seeded this Set from `lineage.ancestors` on the INCOMING record — trusting a
    // peer-supplied chain. That is the lineage-amplification vector: a non-conformant peer could
    // send a bloated ancestors array and inflate every downstream node's closure with unverified
    // keys. Removed. A root reachable only through a parent this node has never stored is honestly
    // absent (you cannot attest what you have not seen) rather than trusted from the sender.
    const ancestorSet = new Set();
    for (const parentKey of parents) {
      ancestorSet.add(parentKey);
      const parentIdx = this._index.get(parentKey);
      if (parentIdx?.ancestors) {
        for (const a of parentIdx.ancestors) ancestorSet.add(a);
      }
    }

    return {
      parents,
      ancestors: [...ancestorSet],
      method,
    };
  }

  _filePath(key) {
    return path.join(this._dir, `${key}.json`);
  }

  _persist(entry) {
    try {
      fs.writeFileSync(this._filePath(entry.key), JSON.stringify(entry, null, 2));
      // The index's copy of the lifecycle follows every write of it (validate, canonize, dismiss, remix).
      const idx = this.__index && this.__index.get(entry.key);
      if (idx) idx.lifecycle = entry.lifecycle || 'observed';
      return true;
    } catch (e) {
      console.error(`[SYM] cmbs: write failed: ${e.message}`);
      return false;
    }
  }

  _load(filePath) {
    try {
      return asStored(JSON.parse(fs.readFileSync(filePath, 'utf8')));
    } catch {
      return null;
    }
  }

  _buildIndex() {
    if (!fs.existsSync(this._dir)) return;

    const files = fs.readdirSync(this._dir).filter(isStoreFile);
    const newest = new NewestEntries(CACHE_MAX_ENTRIES);
    for (const file of files) {
      const filePath = path.join(this._dir, file);
      try {
        const entry = asStored(JSON.parse(fs.readFileSync(filePath, 'utf8')));
        const ie = this._indexEntryFor(entry, filePath);
        if (!this._index.add(ie)) continue;
        this._search.stage(entry.key, entry, ie.storedAt);
        newest.add(entry);
      } catch (e) {
        console.error(`[SYM] cmbs: failed to index ${file}: ${e.message}`);
      }
    }
    newest.fill(this._cache);
    this._search.commit();
  }

  // ── Migration ────────────────────────────────────────────

  _migrated() {
    return fs.existsSync(path.join(this._dir, 'migration-v1.json'));
  }

  _migrate(legacyDir) {
    console.log(`[SYM] cmbs: migrating from ${legacyDir}`);
    let count = 0;

    // Old category mapping
    const FIELD_MAP = {
      activity: 'focus',
      energy: 'motivation',
      context: 'perspective',
      domain: 'commitment',
      urgency: 'issue',
      mood: 'mood',
      intent: 'intent',
      // CAT7 categories map to themselves
      focus: 'focus',
      issue: 'issue',
      motivation: 'motivation',
      commitment: 'commitment',
      perspective: 'perspective',
    };

    const scanDir = (dir, peerId) => {
      if (!fs.existsSync(dir)) return;
      const files = fs.readdirSync(dir).filter(f => f.endsWith('.json'));
      for (const file of files) {
        try {
          const entry = JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8'));

          // Remap old CMB categories to CAT7
          let cmb = entry.cmb || null;
          if (cmb?.categories) {
            const newFields = {};
            for (const [oldField, value] of Object.entries(cmb.categories)) {
              const newField = FIELD_MAP[oldField] || oldField;
              if (['focus', 'issue', 'intent', 'motivation', 'commitment', 'perspective', 'mood'].includes(newField)) {
                newFields[newField] = value;
              }
            }
            cmb = { ...cmb, categories: newFields };
          }

          // Compute proper key
          const key = this._cmbKey(cmb, entry.content);

          // Skip if already migrated
          if (fs.existsSync(this._filePath(key))) continue;

          const migrated = {
            key,
            content: entry.content || '',
            source: entry.source || this._source,
            tags: entry.tags || [],
            originTimestamp: entry.originTimestamp || entry.timestamp || Date.now(),
            storedAt: entry.storedAt || entry.timestamp || Date.now(),
            timestamp: entry.timestamp || Date.now(),
            peerId: peerId || null,
            tier: 'cold',
            cmb: cmb ? { ...cmb, key } : null,
            lineage: { parents: [], ancestors: [], method: 'migrated' },
          };

          this._persist(migrated);
          count++;
        } catch (e) {
          console.error(`[SYM] cmbs: migration failed for ${file}: ${e.message}`);
        }
      }
    };

    // Scan local and peer directories
    const localDir = path.join(legacyDir, 'local');
    scanDir(localDir, null);

    if (fs.existsSync(legacyDir)) {
      const dirs = fs.readdirSync(legacyDir, { withFileTypes: true })
        .filter(d => d.isDirectory() && d.name !== 'local' && !d.name.startsWith('_'));
      for (const d of dirs) {
        scanDir(path.join(legacyDir, d.name), d.name);
      }
    }

    // Rename legacy dir
    const backupDir = legacyDir.replace(/\/?$/, '_backup');
    try {
      fs.renameSync(legacyDir, backupDir);
    } catch (e) {
      console.error(`[SYM] cmbs: could not rename legacy dir: ${e.message}`);
    }

    // Write migration marker
    fs.writeFileSync(
      path.join(this._dir, 'migration-v1.json'),
      JSON.stringify({ migratedAt: new Date().toISOString(), count, from: legacyDir })
    );

    console.log(`[SYM] cmbs: migrated ${count} entries`);
  }
}

module.exports = { MemoryStore, EntryCache, SearchIndex, CACHE_MAX_ENTRIES, CACHE_MAX_CHARS, SEARCH_ENTRY_CHARS, SEARCH_MAX_CHARS };
