'use strict';

/**
 * @module @sym-bot/core/claude-memory-bridge
 * @description ClaudeMemoryBridge — connects Claude Code's memory system to the SYM mesh.
 *
 * Watches Claude Code's project memory directory for changes.
 * When Claude Code saves a memory, the bridge:
 *   1. Re-encodes the node's cognitive state from all Claude memories
 *   2. Shares the new memory with cognitively aligned peers
 *
 * When a peer memory arrives through the coupling engine:
 *   1. Writes it as a .md file in Claude Code's memory directory
 *   2. Updates MEMORY.md index so Claude Code sees it next conversation
 *
 * The user never types sym_remember. The mesh is invisible.
 *
 * @copyright 2026 SYM.BOT Ltd. All rights reserved.
 * @license Apache-2.0
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

/**
 * Bridges Claude Code's project memory directory with the SYM mesh.
 *
 * Watches for local memory file changes (outbound) and writes
 * peer memories as .md files (inbound).
 */
class ClaudeMemoryBridge {

  /**
   * @param {object} node - SymNode instance for mesh communication.
   * @param {object} [opts]
   * @param {string} [opts.projectDir] - Explicit project directory path.
   *   If omitted, auto-detected from CWD.
   */
  constructor(node, opts = {}) {
    this._node = node;
    this._projectDir = opts.projectDir;
    this._memoryDir = null;
    this._watcher = null;
    this._writtenByUs = new Set();
    this._knownFiles = new Map();
    this._started = false;
  }

  /**
   * Start watching Claude Code's memory directory and listening for mesh events.
   *
   * @returns {void}
   */
  start() {
    if (this._started) return;

    this._memoryDir = this._resolveMemoryDir();
    if (!this._memoryDir || !fs.existsSync(this._memoryDir)) return;

    this._started = true;

    // Build initial cognitive state from existing Claude memories
    this._syncCognitiveState();

    // Watch for new/changed memory files
    this._watcher = fs.watch(this._memoryDir, (eventType, filename) => {
      if (!filename || !filename.endsWith('.md') || filename === 'MEMORY.md') return;
      if (this._writtenByUs.has(filename)) {
        this._writtenByUs.delete(filename);
        return;
      }
      setTimeout(() => this._onMemoryChanged(filename), 300);
    });

    // Receive peer memories from mesh
    this._node.on('memory-received', ({ from, entry }) => {
      this._writePeerMemory(from, entry);
    });
  }

  /**
   * Stop watching and clean up.
   *
   * @returns {void}
   */
  stop() {
    if (this._watcher) {
      this._watcher.close();
      this._watcher = null;
    }
    this._started = false;
  }

  // ── Memory Directory Resolution ──────────────────────────────

  /**
   * Resolve the Claude Code memory directory path.
   * @returns {string|null}
   * @private
   */
  _resolveMemoryDir() {
    const projectDir = this._projectDir || this._detectProjectDir();
    if (!projectDir) return null;

    const key = projectDir.replace(/\//g, '-');
    return path.join(require('./state-root').claudeProjectsDir(), key, 'memory');
  }

  /**
   * Auto-detect the Claude Code project directory from CWD.
   * @returns {string|null}
   * @private
   */
  _detectProjectDir() {
    const claudeProjectsDir = require('./state-root').claudeProjectsDir();
    if (!fs.existsSync(claudeProjectsDir)) return null;

    const cwd = process.cwd();
    const cwdKey = cwd.replace(/\//g, '-');

    // Direct match: CWD maps to a project directory
    const directPath = path.join(claudeProjectsDir, cwdKey, 'memory');
    if (fs.existsSync(directPath)) return cwd;

    // Walk up: CWD might be a subdirectory of the Claude project
    let dir = cwd;
    while (dir !== path.dirname(dir)) {
      dir = path.dirname(dir);
      const key = dir.replace(/\//g, '-');
      const memDir = path.join(claudeProjectsDir, key, 'memory');
      if (fs.existsSync(memDir)) return dir;
    }

    return null;
  }

  // ── Cognitive State from Claude Memories ─────────────────────

  /**
   * Re-encode cognitive state from all Claude memory files.
   * @private
   */
  _syncCognitiveState() {
    const context = this._readAllMemories();
    if (context.length > 5) {
      this._node.updateContext(context);
    }
  }

  /**
   * Read and concatenate all .md memory files (excluding MEMORY.md).
   * @returns {string}
   * @private
   */
  _readAllMemories() {
    if (!fs.existsSync(this._memoryDir)) return '';

    const files = fs.readdirSync(this._memoryDir)
      .filter(f => f.endsWith('.md') && f !== 'MEMORY.md');

    const contents = [];
    for (const file of files) {
      try {
        const raw = fs.readFileSync(path.join(this._memoryDir, file), 'utf8');
        const content = this._extractContent(raw);
        if (content) contents.push(content);
        const stat = fs.statSync(path.join(this._memoryDir, file));
        this._knownFiles.set(file, stat.mtimeMs);
      } catch {}
    }
    return contents.join('\n');
  }

  /**
   * Extract body content from a memory file, stripping YAML frontmatter.
   * @param {string} raw - Raw file content.
   * @returns {string|null} Body content, or null if empty.
   * @private
   */
  _extractContent(raw) {
    const match = raw.match(/^---\n[\s\S]*?\n---\n([\s\S]*)$/);
    const body = match ? match[1].trim() : raw.trim();
    return body || null;
  }

  // ── Outbound: Claude Memory → Mesh ──────────────────────────

  /**
   * Handle a changed memory file: re-encode state and share with peers.
   * @param {string} filename - Changed memory filename.
   * @private
   */
  _onMemoryChanged(filename) {
    const filePath = path.join(this._memoryDir, filename);
    if (!fs.existsSync(filePath)) return;

    const stat = fs.statSync(filePath);
    const knownMtime = this._knownFiles.get(filename);
    if (knownMtime && Math.abs(stat.mtimeMs - knownMtime) < 100) return;
    this._knownFiles.set(filename, stat.mtimeMs);

    const raw = fs.readFileSync(filePath, 'utf8');
    const content = this._extractContent(raw);
    if (!content) return;

    // Re-encode cognitive state from all memories, then share this one
    this._syncCognitiveState();
    this._node.shareWithPeers(content, { source: filename });
  }

  // ── Inbound: Mesh → Claude Memory ──────────────────────────

  /**
   * Write a peer's memory as a .md file and update the MEMORY.md index.
   * @param {string} peerName - Display name of the sending peer.
   * @param {object} entry - Memory entry with .content category.
   * @private
   */
  _writePeerMemory(peerName, entry) {
    if (!this._memoryDir) return;
    if (!fs.existsSync(this._memoryDir)) {
      fs.mkdirSync(this._memoryDir, { recursive: true });
    }

    const safeName = peerName.replace(/[^a-zA-Z0-9_-]/g, '_');
    const ts = Date.now();
    const filename = `mesh_${safeName}_${ts}.md`;
    const filePath = path.join(this._memoryDir, filename);
    const preview = (entry.content || '').slice(0, 80).replace(/\n/g, ' ');

    const md = [
      '---',
      `name: mesh_${safeName}_${ts}`,
      `description: "[mesh: ${peerName}] ${preview}"`,
      'type: project',
      '---',
      '',
      `**[mesh: ${peerName}]** ${entry.content}`,
      '',
    ].join('\n');

    this._writtenByUs.add(filename);
    fs.writeFileSync(filePath, md);
    this._knownFiles.set(filename, ts);

    this._updateMemoryIndex(filename, peerName, entry);
  }

  /**
   * Append a peer memory entry to MEMORY.md under the ## Mesh section.
   * @param {string} filename - Memory filename.
   * @param {string} peerName - Display name of the sending peer.
   * @param {object} entry - Memory entry with .content category.
   * @private
   */
  _updateMemoryIndex(filename, peerName, entry) {
    const indexPath = path.join(this._memoryDir, 'MEMORY.md');
    if (!fs.existsSync(indexPath)) return;

    let index = fs.readFileSync(indexPath, 'utf8');

    // Add Mesh section if absent
    if (!index.includes('## Mesh')) {
      index = index.trimEnd() + '\n\n## Mesh\n';
    }

    const preview = (entry.content || '').slice(0, 60).replace(/\n/g, ' ');
    const line = `- [${filename}](${filename}) — [mesh: ${peerName}] ${preview}\n`;

    // Insert under ## Mesh
    const meshStart = index.indexOf('## Mesh');
    const sectionEnd = index.indexOf('\n## ', meshStart + 7);
    if (sectionEnd === -1) {
      index = index.trimEnd() + '\n' + line;
    } else {
      index = index.slice(0, sectionEnd) + line + index.slice(sectionEnd);
    }

    this._writtenByUs.add('MEMORY.md');
    fs.writeFileSync(indexPath, index);
  }
}

module.exports = { ClaudeMemoryBridge };
