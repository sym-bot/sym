'use strict';

/**
 * IPC client for connecting to sym-daemon as a virtual node.
 *
 * Communicates via Unix socket with newline-delimited JSON.
 * Provides the same API surface as SymNode so consumers
 * (MCP server, etc.) can use either transparently.
 *
 * See MMP v0.2.0 Section 13 (Application).
 *
 * Copyright (c) 2026 SYM.BOT Ltd. Apache 2.0 License.
 */

const net = require('net');
const { EventEmitter } = require('events');

const DEFAULT_SOCKET = '/tmp/sym.sock';

/**
 * IPC client that connects to sym-daemon as a virtual node.
 * Provides a SymNode-compatible API over Unix socket IPC.
 */
class SymDaemonClient extends EventEmitter {

  /**
   * @param {object} [opts]
   * @param {string} [opts.socketPath='/tmp/sym.sock'] — daemon Unix socket path
   * @param {string} [opts.name='virtual-node'] — virtual node name
   * @param {string} [opts.cognitiveProfile] — cognitive profile for encoding
   */
  constructor(opts = {}) {
    super();
    this._socketPath = opts.socketPath || DEFAULT_SOCKET;
    this._name = opts.name || 'virtual-node';
    this._cognitiveProfile = opts.cognitiveProfile || null;
    this._socket = null;
    this._buffer = '';
    this._connected = false;
  }

  /** Whether the client is connected to the daemon. */
  get connected() { return this._connected; }

  /** Connect to the daemon and register as a virtual node. */
  async connect() {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection(this._socketPath, () => {
        this._socket = socket;
        this._connected = true;

        // Register as virtual node
        this._send({
          type: 'register',
          name: this._name,
          cognitiveProfile: this._cognitiveProfile,
        });

        // Wait for registered response
        const onFirstMessage = (msg) => {
          if (msg.type === 'registered') {
            this._nodeId = msg.nodeId;
            this._nodeName = msg.name;
            resolve({ nodeId: msg.nodeId, name: msg.name, relay: msg.relay });
          }
        };
        this.once('_raw', onFirstMessage);

        // Timeout registration
        setTimeout(() => {
          this.removeListener('_raw', onFirstMessage);
          reject(new Error('Daemon registration timeout'));
        }, 5000);
      });

      socket.on('data', (data) => this._onData(data));

      socket.on('close', () => {
        this._connected = false;
        this._socket = null;
        this.emit('disconnected');
      });

      socket.on('error', (err) => {
        this._connected = false;
        if (err.code === 'ENOENT' || err.code === 'ECONNREFUSED') {
          reject(new Error('sym-daemon not running'));
        } else {
          reject(err);
        }
      });
    });
  }

  /** Disconnect from the daemon. */
  disconnect() {
    if (this._socket) {
      this._socket.end();
      this._socket = null;
    }
    this._connected = false;
  }

  // ── SymNode-compatible API ─────────────────────────────────

  /**
   * Store a memory with structured CAT7 fields via daemon.
   * See MMP v0.2.0 Section 6 (Memory).
   *
   * @param {object} fields — CAT7 fields: focus, issue, intent, motivation, commitment, perspective, mood
   * @param {object} [opts]
   * @param {Array<string>} [opts.tags] — optional tags
   * @returns {{ key: string }} pending entry reference
   */
  remember(fields, opts = {}) {
    this._send({ type: 'remember', fields, tags: opts.tags });
    return { key: `pending-${Date.now()}` };
  }

  /**
   * Search memories via daemon.
   * @param {string} query — search keyword
   * @returns {Promise<Array<object>>} matching entries
   */
  async recall(query) {
    const result = await this._request({ type: 'recall', query });
    return result.results || [];
  }

  /**
   * Send a message to all peers via daemon.
   * @param {string} message — message content
   */
  send(message) {
    this._send({ type: 'send', message });
  }

  /**
   * Get connected peers via daemon.
   * @returns {Promise<Array<object>>} peer list
   */
  async peers() {
    const result = await this._request({ type: 'peers' });
    return result.peers || [];
  }

  /**
   * Get full node status via daemon.
   * @returns {Promise<object>} status snapshot
   */
  async status() {
    const result = await this._request({ type: 'status' });
    return result.status || {};
  }

  /**
   * Get xMesh synthesized context.
   * See MMP v0.2.0 Section 12 (xMesh).
   *
   * @param {object} [opts]
   * @param {number} [opts.timeWindow] — time window in ms
   * @returns {Promise<object>} xMesh context
   */
  async xmeshContext(opts = {}) {
    const result = await this._request({ type: 'xmesh-context', timeWindow: opts.timeWindow });
    return result.context || {};
  }

  /**
   * Search xMesh insights.
   * See MMP v0.2.0 Section 12 (xMesh).
   *
   * @param {string} query — search query
   * @returns {Promise<Array<object>>} matching insights
   */
  async xmeshSearch(query) {
    const result = await this._request({ type: 'xmesh-search', query });
    return result.insights || [];
  }

  /** No-op for SymNode compatibility. */
  start() {}

  /** Disconnect. */
  stop() { this.disconnect(); }

  // ── Internal ───────────────────────────────────────────────

  _send(msg) {
    if (!this._socket || !this._connected) return;
    try {
      this._socket.write(JSON.stringify(msg) + '\n');
    } catch {}
  }

  /** Send a request and wait for matching result. */
  _request(msg) {
    return new Promise((resolve, reject) => {
      const action = msg.type;
      this._send(msg);

      // Listen for next result with matching action
      const handler = (raw) => {
        if (raw.type === 'result' && raw.action === action) {
          this.removeListener('_raw', handler);
          clearTimeout(timer);
          resolve(raw);
        }
      };
      this.on('_raw', handler);

      const timer = setTimeout(() => {
        this.removeListener('_raw', handler);
        reject(new Error(`Daemon request timeout: ${action}`));
      }, 10000);
    });
  }

  _onData(data) {
    this._buffer += data.toString();
    let idx;
    while ((idx = this._buffer.indexOf('\n')) !== -1) {
      const line = this._buffer.slice(0, idx);
      this._buffer = this._buffer.slice(idx + 1);
      if (!line.trim()) continue;

      try {
        const msg = JSON.parse(line);
        this.emit('_raw', msg);

        // Forward mesh events as SymNode-compatible events
        if (msg.type === 'event') {
          switch (msg.event) {
            case 'mood-delivered':
              this.emit('mood-delivered', msg.data);
              break;
            case 'mood-rejected':
              this.emit('mood-rejected', msg.data);
              break;
            case 'message':
              this.emit('message', msg.data.from, msg.data.content, msg.data);
              break;
            case 'peer-joined':
              this.emit('peer-joined', msg.data);
              break;
            case 'peer-left':
              this.emit('peer-left', msg.data);
              break;
            case 'coupling-decision':
              this.emit('coupling-decision', msg.data);
              break;
            case 'memory-received':
              this.emit('memory-received', msg.data);
              break;
          }
        }
      } catch {}
    }
  }
}

/**
 * Connect to sym-daemon. Throws if daemon is not running.
 * The daemon MUST be running — there is no standalone fallback.
 * Install daemon: node bin/sym-daemon.js --install
 *
 * @param {object} [opts]
 * @param {string} [opts.socketPath] — daemon Unix socket path
 * @param {string} [opts.name='claude-code'] — virtual node name
 * @param {string} [opts.cognitiveProfile] — cognitive profile
 * @returns {Promise<SymDaemonClient>} connected client
 * @throws {Error} if daemon is not running
 */
async function connectToDaemon(opts = {}) {
  const client = new SymDaemonClient({
    socketPath: opts.socketPath || DEFAULT_SOCKET,
    name: opts.name || 'claude-code',
    cognitiveProfile: opts.cognitiveProfile,
  });

  await client.connect();
  return client;
}

module.exports = { SymDaemonClient, connectToDaemon };
