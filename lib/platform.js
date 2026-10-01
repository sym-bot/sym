'use strict';

/**
 * platform.js — Cross-platform utilities for SYM SDK.
 *
 * Single module for all platform-specific logic. Agents, daemon, and CLI
 * import from here instead of hardcoding OS-specific commands or paths.
 *
 * Supports: macOS, Linux, Windows.
 *
 * Copyright (c) 2026 SYM.BOT. Apache 2.0 License.
 */

const os = require('os');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
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
 * Get the SYM configuration directory — SYM_STATE_DIR, else ~/.sym.
 * The daemon socket and logs hang off it, so a rooted deployment keeps those inside its
 * root too rather than sharing one host-global socket with every other tenant.
 * @returns {string}
 */
function getSymDir() {
  return require('./core/state-root').SYM_STATE_DIR;
}

/** The Windows named-pipe namespace: `\\.\pipe\<name>` or `\\?\pipe\<name>`, either slash. */
function isWindowsPipe(address) {
  return /^[\\/]{2}[.?][\\/]pipe[\\/]./i.test(String(address));
}

/**
 * The endpoint `net.listen` / `net.createConnection` must use for a configured IPC address.
 *
 * On POSIX the address is a Unix domain socket path and is used as given. Windows has no domain
 * sockets at a filesystem path: listening on `C:\...\d.sock` fails (EACCES), and IPC must go
 * through a named pipe. So on Windows a filesystem path is mapped to a pipe name derived from
 * it, and a name already in the pipe namespace is used as given.
 *
 * The daemon (server) and every client — the CLI, SymDaemonClient — resolve the address
 * through this one function, so they agree on the pipe for the same SYM_SOCKET; a client that
 * dialled the raw path while the daemon listened on the pipe would find nothing there. The
 * name is a digest of the absolute path, lower-cased because Windows paths are
 * case-insensitive, so two spellings of one path reach one pipe and two paths never share one.
 *
 * @param {string} address — a socket path, or (on Windows) a pipe name
 * @param {string} [platform=process.platform]
 * @returns {string}
 */
function ipcEndpoint(address, platform = process.platform) {
  const a = String(address);
  if (platform !== 'win32' || isWindowsPipe(a)) return a;
  const abs = path.win32.resolve(a).toLowerCase();
  const base = path.win32.basename(abs).replace(/[^a-z0-9._-]/g, '_').slice(0, 40);
  const digest = crypto.createHash('sha256').update(abs, 'utf8').digest('hex').slice(0, 16);
  return `\\\\.\\pipe\\sym-${base}-${digest}`;
}

/**
 * Resolve the daemon's IPC endpoint from its inputs (see getSocketPath).
 * @param {object} o
 * @param {string} [o.configured] — SYM_SOCKET, when set
 * @param {string} o.symDir — the state root
 * @param {boolean} o.rooted — whether SYM_STATE_DIR re-rooted this process
 * @param {string} [o.platform=process.platform]
 * @returns {string}
 */
function resolveSocketPath({ configured, symDir, rooted, platform = process.platform }) {
  if (configured) return ipcEndpoint(configured, platform);
  // The long-standing Windows default, kept so an unrooted CLI and daemon of any version meet.
  if (platform === 'win32' && !rooted) return '\\\\.\\pipe\\sym-daemon';
  // A rooted deployment keeps its endpoint inside its root on every platform; on Windows that
  // is a pipe named for the root, not the one host-global pipe every tenant would share.
  return ipcEndpoint(path.join(symDir, 'daemon.sock'), platform);
}

/**
 * Get the IPC endpoint the daemon listens on and its clients dial: SYM_SOCKET if set, else
 * `<state root>/daemon.sock`, mapped to a named pipe on Windows (see ipcEndpoint).
 *
 * @returns {string}
 */
function getSocketPath() {
  const { SYM_STATE_DIR, IS_ROOTED } = require('./core/state-root');
  return resolveSocketPath({ configured: process.env.SYM_SOCKET, symDir: SYM_STATE_DIR, rooted: IS_ROOTED });
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
  resolveSocketPath,
  ipcEndpoint,
  isWindowsPipe,
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
