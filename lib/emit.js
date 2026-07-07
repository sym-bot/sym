'use strict';

/**
 * lib/emit.js — MMP Class 1 Emitter (spec §17.1).
 *
 * Emit CAT7 blocks into a running mesh without being a node: no daemon, no
 * store, no SVAF, no discovery, no identity lock. Connect, handshake, deliver
 * `cmb` frames, disconnect. The emitter carries its own persistent identity
 * (~/.sym/nodes/<name>/identity.json), so provenance, admission attestations,
 * and earned trust accrue to the actual source — a CI job, a sensor, a
 * script — rather than being laundered through a resident node's identity.
 *
 * The wire surface is exactly the Class 1 contract: cmb1- content address and
 * mmp-sig-v1 signature via @sym-bot/core (byte-identical to a full node's
 * emissions), the §5.2 handshake, and the §7 `cmb` frame over the §4.1
 * length-prefixed TCP transport. Unknown inbound frame types are silently
 * ignored (§7.3). LAN TCP only for now: the relay path requires end-to-end
 * field encryption (§18.2.1), which a one-shot emitter does not yet speak.
 *
 * Copyright (c) 2026 SYM.BOT. Apache 2.0 License.
 */

const net = require('net');
const { createCMB, signCMB, mintRemixKey } = require('@sym-bot/core');
const { TcpTransport } = require('./transport');
const { loadOrCreateIdentity } = require('./config');

const HANDSHAKE_TIMEOUT_MS = 8000;
const WIRE_VERSION = '0.2.3'; // the frozen MMP Core wire revision (§5.2)

/** Parse "host:port" (optional tcp:// prefix). */
function parseServer(server) {
  if (!server || typeof server !== 'string') {
    throw new Error('emit: server is required, e.g. "192.168.1.10:52781"');
  }
  const s = server.replace(/^tcp:\/\//, '');
  const i = s.lastIndexOf(':');
  const host = i > 0 ? s.slice(0, i) : '';
  const port = Number(s.slice(i + 1));
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`emit: server must be host:port (got "${server}")`);
  }
  return { host, port };
}

/** A connected emitter session. Create via connect(); reuse for many emits. */
class Emitter {
  constructor({ identity, transport, socket, group, name, peer }) {
    this.nodeId = identity.nodeId;
    this.name = name;
    this.group = group;
    /** The receiving peer's handshake (nodeId, name, publicKey…). */
    this.peer = peer;
    this._identity = identity;
    this._transport = transport;
    this._socket = socket;
  }

  /**
   * Emit one CAT7 block. Fields is the CAT7 map (absent fields normalize to
   * "neutral"); opts.to directs it to one node (§9.2.2 unconditional
   * delivery), opts.parents declares lineage (e.g. the CMB a grounding
   * outcome verifies — pair with fields.intent = 'ground' and a
   * `verified:`/`failed:`-prefixed fields.commitment, §6.7).
   * @returns {{ key: string, cmb: object }}
   */
  emit(fields, opts = {}) {
    const parents = Array.isArray(opts.parents) ? opts.parents.filter(Boolean) : [];
    const lineage = parents.length ? { parents: [...parents], ancestors: [...parents] } : null;
    const cmb = createCMB({ fields, createdBy: this.name, lineage });
    if (parents.length) {
      // §8.2.1 role dispatch: a lineage-bearing block is keyed under the REMIX
      // scheme (parents + author bound into the address). Receivers recompute
      // by role, so a root-keyed block with parents fails content verification.
      cmb.key = mintRemixKey(cmb.fields, parents, this.name);
    }
    // Audience binding (§18.3.1): group + directed recipient are covered by
    // the signature, so a cross-group or mis-directed replay fails.
    cmb.group = this.group;
    if (opts.to) cmb.to = opts.to;
    signCMB(cmb, this._identity.privateKey);
    this._transport.send({ type: 'cmb', timestamp: Date.now(), cmb });
    return { key: cmb.key, cmb };
  }

  /** Flush and disconnect. Safe to call once; resolves when the socket closes. */
  close() {
    return new Promise((resolve) => {
      if (this._socket.destroyed) return resolve();
      this._socket.once('close', resolve);
      this._socket.end();
      setTimeout(() => { this._socket.destroy(); resolve(); }, 1500).unref();
    });
  }
}

/**
 * Connect to a mesh endpoint and complete the §5.2 handshake.
 * @param {object} opts
 * @param {string} opts.server - "host:port" of a listening mesh node.
 * @param {string} [opts.group='default'] - the group this emitter authors for.
 * @param {string} [opts.name='emitter'] - stable emitter identity name.
 * @param {number} [opts.timeoutMs=8000] - connect + handshake deadline.
 * @returns {Promise<Emitter>}
 */
async function connect({ server, group = 'default', name = 'emitter', timeoutMs = HANDSHAKE_TIMEOUT_MS } = {}) {
  const identity = loadOrCreateIdentity(name);
  const { host, port } = parseServer(server);

  const socket = await new Promise((resolve, reject) => {
    const s = net.connect({ host, port });
    const t = setTimeout(() => { s.destroy(); reject(new Error(`emit: connect timeout to ${server}`)); }, timeoutMs);
    s.once('connect', () => { clearTimeout(t); resolve(s); });
    s.once('error', (e) => { clearTimeout(t); reject(e); });
  });

  const transport = new TcpTransport(socket);
  transport.send({
    type: 'handshake',
    nodeId: identity.nodeId,
    name,
    version: WIRE_VERSION,
    extensions: [],
    group,
    publicKey: identity.publicKey,
    lifecycleRole: 'participant',
  });

  const peer = await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`emit: no handshake from ${server} within ${timeoutMs}ms`)), timeoutMs);
    transport.on('message', (msg) => {
      // §7: silently ignore every frame type we don't understand.
      if (msg && msg.type === 'handshake') { clearTimeout(t); resolve(msg); }
    });
    transport.once('close', () => { clearTimeout(t); reject(new Error(`emit: ${server} closed before handshake`)); });
    transport.once('error', (e) => { clearTimeout(t); reject(e); });
  }).catch((e) => { socket.destroy(); throw e; });

  return new Emitter({ identity, transport, socket, group, name, peer });
}

/**
 * One-shot: connect, emit a single block, disconnect.
 * @returns {Promise<{ key: string, cmb: object }>}
 */
async function emitOnce(opts, fields, emitOpts = {}) {
  const emitter = await connect(opts);
  try {
    return emitter.emit(fields, emitOpts);
  } finally {
    await emitter.close();
  }
}

module.exports = { connect, emitOnce, Emitter, parseServer };
