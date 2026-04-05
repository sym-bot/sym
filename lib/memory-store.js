'use strict';

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
 * Copyright (c) 2026 SYM.BOT Ltd. Apache 2.0 License.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { ensureDir } = require('./config');

// ── In-Memory Index ──────────────────────────────────────────

/**
 * In-memory index for fast CMB lookups by key, time, and ancestry.
 * @private
 */
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

// ── Memory Store ─────────────────────────────────────────────

class MemoryStore {
  /**
   * @param {string} meshmemDir — path to meshmem directory (flat, single dir)
   * @param {string} sourceName — this agent's name
   * @param {object} opts
   * @param {string} opts.legacyDir — old memories/ dir for one-time migration
   */
  constructor(meshmemDir, sourceName, opts = {}) {
    this._dir = meshmemDir;
    this._source = sourceName;
    this._index = new MemoryIndex();
    this._cache = new Map(); // key → full entry (avoids disk reads on recall)

    ensureDir(this._dir);

    // One-time migration from legacy layout
    if (opts.legacyDir && fs.existsSync(opts.legacyDir) && !this._migrated()) {
      this._migrate(opts.legacyDir);
    }

    // Build index from flat files
    this._buildIndex();
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
    const lineage = this._expandLineage(cmb?.lineage);

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
      cmb: cmb ? { ...cmb, lineage } : null,
      lineage,
    };

    if (!this._persist(entry)) return null;

    this._cache.set(key, entry);
    this._index.add({
      key,
      storedAt: now,
      createdBy: this._source,
      peerId: null,
      parents: lineage?.parents || [],
      ancestors: lineage?.ancestors || [],
      tier: 'hot',
      filePath: this._filePath(key),
    });

    // Section 6.4: advance parent CMB lifecycle when lineage exists.
    // A CMB with parents = remix → parent advances to 'remixed'.
    // Validation authority (Section 6.5) is checked by the caller, not here.
    this._advanceParentLifecycle(lineage, 'remixed');

    return entry;
  }

  /**
   * Store a CMB received from a peer. Deduplicates by CMB key.
   * Returns entry or null if duplicate.
   */
  receiveFromPeer(peerId, entry) {
    const cmb = entry.cmb || null;
    const key = this._cmbKey(cmb, entry.content);

    // Dedup — same CMB from multiple peers stored once
    if (this._index.has(key)) return null;

    const lineage = this._expandLineage(cmb?.lineage);
    const now = Date.now();

    const stored = {
      ...entry,
      key,
      peerId,
      tier: 'hot',
      lifecycle: 'observed',
      storedAt: now,
      cmb: cmb ? { ...cmb, lineage } : null,
      lineage,
    };

    if (!this._persist(stored)) return null;

    this._cache.set(key, stored);
    this._index.add({
      key,
      storedAt: now,
      createdBy: cmb?.createdBy || entry.source || peerId,
      peerId,
      parents: lineage?.parents || [],
      ancestors: lineage?.ancestors || [],
      tier: 'hot',
      filePath: this._filePath(key),
    });

    // Section 6.4: advance parent CMB lifecycle.
    this._advanceParentLifecycle(lineage, 'remixed');

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
   * Recent CMBs with full data (for SVAF anchor retrieval).
   * Replaces old recentCMBs().
   */
  anchors(limit = 5) {
    const keys = this._index.recentKeys(limit);
    const cmbs = [];
    for (const key of keys) {
      const entry = this.get(key);
      if (!entry) continue;
      if (entry.cmb) {
        cmbs.push(entry.cmb);
      } else {
        // Legacy entry without CMB — create on demand
        try {
          const { createCMB } = require('@sym-bot/core');
          cmbs.push(createCMB({ rawText: entry.content, createdBy: entry.source || this._source }));
        } catch { /* core not available — skip */ }
      }
    }
    return cmbs;
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

  // ── Context Curation ─────────────────────────────────────

  /**
   * Core operation. Returns projected ancestor subgraph for LLM reasoning.
   *
   * @param {string} cmbKey — the CMB to trace ancestors of
   * @param {object} fieldWeights — α_f weights { focus: 2.0, mood: 0.8, ... }
   * @param {object} opts
   * @param {number} opts.weightThreshold — minimum α_f to include field (default 1.0)
   * @param {number} opts.tokenBudget — max estimated tokens (default 500)
   * @returns {Array<{key, createdBy, createdAt, fields}>} — projected CMBs
   */
  curate(cmbKey, fieldWeights = {}, opts = {}) {
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
      if (!entry?.cmb?.fields) continue;

      // Project only fields above weight threshold
      const fields = {};
      for (const [field, value] of Object.entries(entry.cmb.fields)) {
        const weight = fieldWeights[field] || 0;
        if (weight >= weightThreshold && value?.text) {
          fields[field] = value.text;
        }
      }

      if (Object.keys(fields).length === 0) continue;

      const item = {
        key: entry.key,
        createdBy: entry.cmb.createdBy || entry.source,
        createdAt: entry.cmb.createdAt || entry.storedAt,
        fields,
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

  // ── Search (user-facing) ─────────────────────────────────

  /**
   * Keyword search across CMB field texts, content, and tags.
   * For CLI `sym recall "..."` — not for LLM context curation.
   */
  recall(query) {
    const results = [];

    for (const [key, idx] of this._index.byKey) {
      const entry = this._cache.get(key) || this._load(idx.filePath);
      if (!entry) continue;

      // No query = return all (the agent decides relevance, not the store)
      if (!query || query.trim() === '') {
        results.push(entry);
        continue;
      }

      // Keyword filter when query provided
      const q = query.toLowerCase();
      const parts = [entry.content || '', entry.key || '', ...(entry.tags || [])];

      if (entry.cmb?.fields) {
        for (const value of Object.values(entry.cmb.fields)) {
          if (value?.text) parts.push(value.text);
        }
      }

      if (parts.join(' ').toLowerCase().includes(q)) {
        results.push(entry);
      }
    }

    return results.sort((a, b) => (b.storedAt || b.timestamp || 0) - (a.storedAt || a.timestamp || 0));
  }

  /** Backward compat alias */
  search(query) { return this.recall(query); }

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
    const cutoff = Date.now() - freshnessMs;
    let moved = 0;

    for (const [key, entry] of this._index.byKey) {
      if (entry.tier !== 'hot') continue;
      if (entry.storedAt >= cutoff) continue; // still fresh

      // Keep hot if any descendant is hot
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
      if (this._index.descendants(key).size > 0) continue; // has descendants — keep

      toRemove.push(key);
    }

    for (const key of toRemove) {
      const entry = this._index.get(key);
      if (entry?.filePath) {
        try { fs.unlinkSync(entry.filePath); } catch {}
      }
      this._index.remove(key);
      removed++;
    }

    return removed;
  }

  // ── Internal ─────────────────────────────────────────────

  _cmbKey(cmb, content) {
    if (cmb?.key) return cmb.key;

    // Content-addressable: cmb- + md5(field texts)
    if (cmb?.fields) {
      const fieldTexts = ['focus', 'issue', 'intent', 'motivation', 'commitment', 'perspective']
        .map(f => cmb.fields[f]?.text || '')
        .join('|') + '|' + (cmb.fields.mood?.text || '');
      return 'cmb-' + crypto.createHash('md5').update(fieldTexts).digest('hex');
    }

    // Fallback: hash raw content
    return 'cmb-' + crypto.createHash('md5').update(content || '').digest('hex');
  }

  // ── CMB Lifecycle (Section 6.4) ────────────────────────

  /**
   * Lifecycle progression order. Monotonically upward under activity.
   * observed → remixed → validated → canonical → archived
   */
  static LIFECYCLE_ORDER = ['observed', 'remixed', 'validated', 'canonical', 'archived'];

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
   * Mark a CMB as validated by a founder/validator node.
   * Called when a validation CMB (done/dismiss) is produced.
   * Per Section 6.5: validation authority is identity-bound.
   * @param {string} key — CMB key to validate
   */
  validateCMB(key) {
    const entry = this.get(key);
    if (!entry) return;
    entry.lifecycle = 'validated';
    entry.anchorWeight = 2.0;
    this._cache.set(key, entry);
    this._persist(entry);
  }

  /**
   * Dismiss a CMB — human rejected this signal. Anchor weight drops to 0.5.
   * Terminal state — does not advance to validated or canonical.
   * MMP Section 6.4.
   * @param {string} key
   */
  dismissCMB(key) {
    const entry = this.get(key);
    if (!entry) return;
    entry.lifecycle = 'dismissed';
    entry.anchorWeight = 0.5;
    this._cache.set(key, entry);
    this._persist(entry);
  }

  /**
   * Get the lifecycle state of a CMB.
   * @param {string} key
   * @returns {string} lifecycle state or 'observed'
   */
  getLifecycle(key) {
    const entry = this.get(key);
    return entry?.lifecycle || 'observed';
  }

  _expandLineage(lineage) {
    if (!lineage) return { parents: [], ancestors: [], method: null };

    const parents = lineage.parents || [];
    const method = lineage.method || null;

    // Compute ancestors: union of all parent ancestors + parent keys
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
      return true;
    } catch (e) {
      console.error(`[SYM] meshmem: write failed: ${e.message}`);
      return false;
    }
  }

  _load(filePath) {
    try {
      return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } catch {
      return null;
    }
  }

  _buildIndex() {
    if (!fs.existsSync(this._dir)) return;

    const files = fs.readdirSync(this._dir).filter(f => f.endsWith('.json') && f !== 'migration-v1.json');
    for (const file of files) {
      const filePath = path.join(this._dir, file);
      try {
        const entry = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        this._cache.set(entry.key, entry);
        this._index.add({
          key: entry.key,
          storedAt: entry.storedAt || entry.timestamp || 0,
          createdBy: entry.cmb?.createdBy || entry.source || this._source,
          peerId: entry.peerId || null,
          parents: entry.lineage?.parents || entry.cmb?.lineage?.parents || [],
          ancestors: entry.lineage?.ancestors || entry.cmb?.lineage?.ancestors || [],
          tier: entry.tier || 'hot',
          filePath,
        });
      } catch (e) {
        console.error(`[SYM] meshmem: failed to index ${file}: ${e.message}`);
      }
    }
  }

  // ── Migration ────────────────────────────────────────────

  _migrated() {
    return fs.existsSync(path.join(this._dir, 'migration-v1.json'));
  }

  _migrate(legacyDir) {
    console.log(`[SYM] meshmem: migrating from ${legacyDir}`);
    let count = 0;

    // Old field mapping
    const FIELD_MAP = {
      activity: 'focus',
      energy: 'motivation',
      context: 'perspective',
      domain: 'commitment',
      urgency: 'issue',
      mood: 'mood',
      intent: 'intent',
      // CAT7 fields map to themselves
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

          // Remap old CMB fields to CAT7
          let cmb = entry.cmb || null;
          if (cmb?.fields) {
            const newFields = {};
            for (const [oldField, value] of Object.entries(cmb.fields)) {
              const newField = FIELD_MAP[oldField] || oldField;
              if (['focus', 'issue', 'intent', 'motivation', 'commitment', 'perspective', 'mood'].includes(newField)) {
                newFields[newField] = value;
              }
            }
            cmb = { ...cmb, fields: newFields };
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
          console.error(`[SYM] meshmem: migration failed for ${file}: ${e.message}`);
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
      console.error(`[SYM] meshmem: could not rename legacy dir: ${e.message}`);
    }

    // Write migration marker
    fs.writeFileSync(
      path.join(this._dir, 'migration-v1.json'),
      JSON.stringify({ migratedAt: new Date().toISOString(), count, from: legacyDir })
    );

    console.log(`[SYM] meshmem: migrated ${count} entries`);
  }
}

module.exports = { MemoryStore };
