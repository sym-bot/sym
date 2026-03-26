'use strict';

const fs = require('fs');
const path = require('path');
const { ensureDir } = require('./config');

class MemoryStore {
  constructor(memoriesDir, sourceName) {
    this._dir = memoriesDir;
    this._source = sourceName;
    ensureDir(path.join(this._dir, 'local'));
  }

  write(content, opts = {}) {
    const dir = path.join(this._dir, 'local');
    ensureDir(dir);

    // Dedup: skip if identical content already stored
    const hash = require('crypto').createHash('md5').update(content).digest('hex');
    const hashFile = path.join(dir, `h-${hash}.json`);
    if (fs.existsSync(hashFile)) return null;

    const now = Date.now();
    const entry = {
      key: opts.key || `memory-${now}`,
      content,
      source: this._source,
      tags: opts.tags || [],
      originTimestamp: opts.originTimestamp || now,
      storedAt: now,
      timestamp: now,
      cmb: opts.cmb || null,
    };
    fs.writeFileSync(hashFile, JSON.stringify(entry, null, 2));
    return entry;
  }

  receiveFromPeer(peerId, entry) {
    const dir = path.join(this._dir, peerId);
    ensureDir(dir);
    const filename = `${entry.timestamp || Date.now()}.json`;
    fs.writeFileSync(path.join(dir, filename), JSON.stringify(entry, null, 2));
  }

  search(query) {
    const results = [];
    const q = query.toLowerCase();
    if (!fs.existsSync(this._dir)) return results;

    const dirs = fs.readdirSync(this._dir, { withFileTypes: true })
      .filter(d => d.isDirectory()).map(d => d.name);

    for (const dir of dirs) {
      const dirPath = path.join(this._dir, dir);
      const files = fs.readdirSync(dirPath).filter(f => f.endsWith('.json'));
      for (const file of files) {
        try {
          const entry = JSON.parse(fs.readFileSync(path.join(dirPath, file), 'utf8'));
          const searchable = [
            entry.content || '',
            entry.key || '',
            ...(entry.tags || []),
          ].join(' ').toLowerCase();
          if (searchable.includes(q)) {
            results.push({
              ...entry,
              _source: dir === 'local' ? this._source : dir.slice(0, 8),
              _dir: dir,
            });
          }
        } catch {}
      }
    }
    return results.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
  }

  count() {
    let total = 0;
    if (!fs.existsSync(this._dir)) return 0;
    const dirs = fs.readdirSync(this._dir, { withFileTypes: true })
      .filter(d => d.isDirectory()).map(d => d.name);
    for (const dir of dirs) {
      const dirPath = path.join(this._dir, dir);
      total += fs.readdirSync(dirPath).filter(f => f.endsWith('.json')).length;
    }
    return total;
  }

  /** Recent CMBs for SVAF v2 fusion anchors. */
  recentCMBs(limit = 5) {
    const entries = this.allEntries().slice(0, limit);
    const { createCMB } = require('@sym-bot/core');
    return entries.map(e => {
      if (e.cmb) return e.cmb;
      // On-demand extraction for legacy entries
      return createCMB(e.content, e.source || this._source, e.tags || [], e.originTimestamp || e.timestamp, 0.6);
    });
  }

  allEntries() {
    const entries = [];
    if (!fs.existsSync(this._dir)) return entries;
    const dirs = fs.readdirSync(this._dir, { withFileTypes: true })
      .filter(d => d.isDirectory()).map(d => d.name);
    for (const dir of dirs) {
      const dirPath = path.join(this._dir, dir);
      const files = fs.readdirSync(dirPath).filter(f => f.endsWith('.json'));
      for (const file of files.slice(-10)) {
        try {
          entries.push(JSON.parse(fs.readFileSync(path.join(dirPath, file), 'utf8')));
        } catch {}
      }
    }
    return entries.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
  }
}

module.exports = { MemoryStore };
