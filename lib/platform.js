'use strict';

/**
 * platform.js — Cross-platform utilities for SYM SDK.
 *
 * Single module for all platform-specific logic. Agents, daemon, and CLI
 * import from here instead of hardcoding OS-specific commands or paths.
 *
 * Supports: macOS, Linux, Windows.
 *
 * Copyright (c) 2026 SYM.BOT Ltd. Apache 2.0 License.
 */

const os = require('os');
const path = require('path');
const fs = require('fs');
const { execSync, execFileSync } = require('child_process');

// ── Platform Detection ──────────────────────────────────────

const isWin = process.platform === 'win32';
const isMac = process.platform === 'darwin';
const isLinux = process.platform === 'linux';

// ── Python Resolution ───────────────────────────────────────

let _pythonBin = null;

/**
 * Resolve the Python binary path. Tries python3 first (Unix default),
 * falls back to python (Windows default), verifies version >= 3.8.
 * Caches result after first successful resolution.
 *
 * @returns {string|null} Path to Python binary or null if not found
 */
function resolvePython() {
  if (_pythonBin !== undefined && _pythonBin !== null) return _pythonBin;

  const candidates = isWin
    ? ['python', 'python3', 'py -3']
    : ['python3', 'python'];

  for (const cmd of candidates) {
    try {
      const version = execSync(`${cmd} --version 2>&1`, {
        encoding: 'utf8',
        timeout: 5000,
        windowsHide: true,
      }).trim();

      // Verify it's Python 3.x
      const match = version.match(/Python (\d+)\.(\d+)/);
      if (match && parseInt(match[1]) >= 3 && parseInt(match[2]) >= 8) {
        // Resolve full path
        const whichCmd = isWin ? `where ${cmd.split(' ')[0]}` : `which ${cmd}`;
        try {
          const fullPath = execSync(whichCmd, { encoding: 'utf8', timeout: 5000, windowsHide: true }).trim().split('\n')[0];
          // Skip Windows App Execution Alias (points to WindowsApps)
          if (isWin && fullPath.includes('WindowsApps')) continue;
          _pythonBin = fullPath;
          return _pythonBin;
        } catch {
          // which/where failed but python --version worked — use command name
          _pythonBin = cmd;
          return _pythonBin;
        }
      }
    } catch {
      // Command not found, try next
    }
  }

  _pythonBin = null;
  return null;
}

// ── Claude CLI Resolution ───────────────────────────────────

let _claudeBin = null;

/**
 * Resolve Claude CLI binary path. On Windows, resolves past .cmd wrapper
 * to the underlying cli.js for direct node invocation.
 *
 * @returns {{ bin: string, args: string[], useNode: boolean }}
 */
function resolveClaudeCLI() {
  if (_claudeBin) return _claudeBin;

  let claudePath = process.env.CLAUDE_BIN;

  if (!claudePath) {
    try {
      const cmd = isWin ? 'where claude' : 'which claude';
      const lines = execSync(cmd, { encoding: 'utf8', timeout: 5000, windowsHide: true }).trim().split('\n');
      // On Windows, prefer the .cmd shim so we can resolve to cli.js below
      claudePath = (isWin && lines.find(l => l.trim().endsWith('.cmd'))) || lines[0];
      claudePath = claudePath.trim();
    } catch {
      claudePath = isWin ? 'claude' : '/usr/local/bin/claude';
    }
  }

  // Windows: bypass .cmd wrapper — use node + cli.js directly.
  // .cmd batch files break when spawned by Node.js execFileSync because
  // %dp0% path resolution fails in the subprocess environment.
  if (isWin) {
    // Try resolving cli.js from the claude path (works for both .cmd and extensionless shims)
    const baseDir = path.dirname(claudePath);
    const cliJs = path.join(baseDir, 'node_modules', '@anthropic-ai', 'claude-code', 'cli.js');
    if (fs.existsSync(cliJs)) {
      _claudeBin = { bin: process.execPath, prefixArgs: [cliJs], useNode: true };
      return _claudeBin;
    }
  }

  _claudeBin = { bin: claudePath, prefixArgs: [], useNode: false };
  return _claudeBin;
}

// ── Process Utilities ───────────────────────────────────────

/**
 * Find process listening on a given port.
 *
 * @param {number} port
 * @returns {string|null} Process info string or null if not found
 */
function findProcessByPort(port) {
  try {
    if (isWin) {
      const result = execSync(
        `netstat -ano | findstr :${port} | findstr LISTENING`,
        { encoding: 'utf8', timeout: 5000, windowsHide: true }
      ).trim();
      return result || null;
    } else {
      const result = execSync(
        `lsof -i :${port} -t 2>/dev/null`,
        { encoding: 'utf8', timeout: 5000, windowsHide: true }
      ).trim();
      return result || null;
    }
  } catch {
    return null;
  }
}

/**
 * Find processes by name.
 *
 * @param {string} name - Process name to search for
 * @returns {string|null} Process info or null
 */
function findProcessByName(name) {
  try {
    if (isWin) {
      const result = execSync(
        `tasklist /fi "imagename eq ${name}" /fo csv /nh`,
        { encoding: 'utf8', timeout: 5000, windowsHide: true }
      ).trim();
      return result && !result.includes('No tasks') ? result : null;
    } else {
      const result = execSync(
        `pgrep -la "${name}" 2>/dev/null`,
        { encoding: 'utf8', timeout: 5000, windowsHide: true }
      ).trim();
      return result || null;
    }
  } catch {
    return null;
  }
}

// ── Path Utilities ──────────────────────────────────────────

/**
 * Get the SYM configuration directory.
 * @returns {string} ~/.sym
 */
function getSymDir() {
  return path.join(os.homedir(), '.sym');
}

/**
 * Get the IPC socket path.
 * Windows uses named pipes; Unix uses domain sockets.
 *
 * @returns {string}
 */
function getSocketPath() {
  return process.env.SYM_SOCKET || (isWin
    ? '\\\\.\\pipe\\sym-daemon'
    : path.join(getSymDir(), 'daemon.sock'));
}

/**
 * Get the log directory for a given service.
 *
 * @param {string} service - Service name (e.g., 'sym-daemon')
 * @returns {string}
 */
function getLogDir(service) {
  if (isWin || isLinux) {
    return path.join(getSymDir(), 'logs', service);
  }
  // macOS convention
  return path.join(os.homedir(), 'Library', 'Logs', service);
}

/**
 * Resolve a project path. Uses SYM_PROJECT_ROOT env var if set,
 * otherwise falls back to a default base directory.
 *
 * @param {...string} segments - Path segments relative to project root
 * @returns {string} Full resolved path
 */
function projectPath(...segments) {
  const root = process.env.SYM_PROJECT_ROOT || path.join(os.homedir(), 'Documents', 'dev');
  return path.join(root, ...segments);
}

/**
 * Safely read a file, returning null if it doesn't exist.
 * Agents should use this for optional data sources that may
 * not exist on all platforms.
 *
 * @param {string} filePath
 * @param {number} [maxLength] - Maximum characters to read
 * @returns {string|null}
 */
function safeReadFile(filePath, maxLength) {
  try {
    if (!fs.existsSync(filePath)) return null;
    let content = fs.readFileSync(filePath, 'utf8');
    if (maxLength) content = content.slice(0, maxLength);
    return content;
  } catch {
    return null;
  }
}

/**
 * Safely execute a shell command, returning null on failure.
 * Agents should use this for optional OS commands that may
 * not be available on all platforms.
 *
 * @param {string} cmd - Command to execute
 * @param {object} [opts] - execSync options
 * @returns {string|null}
 */
function safeExec(cmd, opts = {}) {
  try {
    return execSync(cmd, {
      encoding: 'utf8',
      timeout: opts.timeout || 10000,
      windowsHide: true,
      ...opts,
    }).trim();
  } catch {
    return null;
  }
}

/**
 * Execute a platform-specific command.
 *
 * @param {string} unixCmd - Command for macOS/Linux
 * @param {string} winCmd - Command for Windows
 * @param {object} [opts] - execSync options
 * @returns {string|null}
 */
function platformExec(unixCmd, winCmd, opts = {}) {
  return safeExec(isWin ? winCmd : unixCmd, opts);
}

// ── Git Utilities ───────────────────────────────────────────

/**
 * Get git info for a repository path. Returns null if path doesn't
 * exist or isn't a git repo.
 *
 * @param {string} repoPath - Path to git repository
 * @returns {{ branch: string, lastCommit: string, tag: string|null }|null}
 */
function getGitInfo(repoPath) {
  if (!fs.existsSync(repoPath)) return null;

  const branch = safeExec(`git -C "${repoPath}" branch --show-current`);
  const lastCommit = safeExec(`git -C "${repoPath}" log -1 --format="%s"`);
  const tag = safeExec(`git -C "${repoPath}" describe --tags --abbrev=0 2>${isWin ? 'NUL' : '/dev/null'}`);

  if (!branch && !lastCommit) return null;

  return {
    branch: branch || 'unknown',
    lastCommit: lastCommit ? lastCommit.slice(0, 60) : 'unknown',
    tag: tag || null,
  };
}

// ── npm Utilities ───────────────────────────────────────────

/**
 * Get the published version of an npm package.
 *
 * @param {string} packageName
 * @returns {string|null}
 */
function getNpmVersion(packageName) {
  return safeExec(`npm view ${packageName} version`, { timeout: 15000 });
}

// ── Exports ─────────────────────────────────────────────────

module.exports = {
  // Platform detection
  isWin,
  isMac,
  isLinux,

  // Binary resolution
  resolvePython,
  resolveClaudeCLI,

  // Process utilities
  findProcessByPort,
  findProcessByName,

  // Path utilities
  getSymDir,
  getSocketPath,
  getLogDir,
  projectPath,
  safeReadFile,
  safeExec,
  platformExec,

  // Git utilities
  getGitInfo,

  // npm utilities
  getNpmVersion,
};
