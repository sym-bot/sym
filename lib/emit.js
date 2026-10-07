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
 * The wire surface is the Class 1 contract over Core Secure (sym 0.14): the §5.2 authenticated
 * handshake (client-hello → server-hello → client-finish, both proofs verified), then each record as
 * a signed mmp-sig-v2.0 CMB sealed in a `cmb-encrypted` frame (§18.2.1) over the §4.1
 * length-prefixed TCP transport. Unknown inbound frame types are silently ignored (§7.3). LAN TCP
 * only. The room is explicit (§5.8: absence is invalid in Core Secure): an emitter that names none
 * is in `default`, and a node in another room refuses it at the handshake (room mismatch).
 *
 * Copyright (c) 2026 SYM.BOT. Apache 2.0 License.
 */

const net = require('net');
const { createCMB, signCMB, assertionIdV2_0 } = require('./core');
const { TcpTransport } = require('./transport');
const { loadOrCreateIdentity, acquireIdentityLock, nodeDirById } = require('./config');
const { keyFingerprint } = require('./roster-keys');
const { MMP_EMIT_V2 } = require('./emit-policy'); // the single reader-first flip switch
const { PeerSession } = require('./session');
const { EXT_CMB_ENCRYPTED_V2 } = require('./core/mmp-extensions');

const HANDSHAKE_TIMEOUT_MS = 8000;
const IMPLEMENTATION = { name: 'sym-emit', version: require('../package.json').version };

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
  constructor({ identity, session, socket, room, name }) {
    this.nodeId = identity.nodeId;
    this.name = name;
    this.room = room;
    /** What the handshake proved about the receiving node: { nodeId, name, publicKey, room, sessionId }. */
    this.peer = { nodeId: session.nodeId, name: session.name, publicKey: session.identityKey, room: session.room, sessionId: session.sessionId };
    this._identity = identity;
    this._session = session;
    this._socket = socket;
  }

  /**
   * Emit one CAT7 block. Categories is the CAT7 map (absent categories normalize to
   * "neutral"); opts.to directs it to one node (§9.2.2 unconditional
   * delivery), opts.parents declares lineage (e.g. the CMB a grounding
   * outcome verifies — pair with categories.intent = 'ground' and a
   * `verified:`/`failed:`-prefixed categories.commitment, §6.7).
   * @returns {{ key: string, cmb: object }}
   */
  emit(categories, opts = {}) {
    const parents = Array.isArray(opts.parents) ? opts.parents.filter(Boolean) : [];
    // `ancestors` is RETIRED (§7.5): reachability is walked from refs, never carried. Writing a
    // transitive closure onto every block was the thing that made lineage expensive to keep
    // honest — it had to be recomputed and re-stored at every hop, and a wrong one was
    // indistinguishable from a right one.
    const lineage = parents.length ? { parents: [...parents], method: 'emit' } : null;

    // The record names the room the handshake proved: both sides signed it in the transcript.
    const cmb = createCMB({
      categories,
      createdBy: this.name,
      lineage,
      room: this.room,
      to: opts.to ?? null,
      // Reader-first gated: only populates the v2.0 preimage fields (and thus signs under
      // mmp-sig-v2.0) once MMP_EMIT_V2 is flipped on after reader deployment.
      emitV2: MMP_EMIT_V2,
      createdByNodeId: MMP_EMIT_V2 ? this._identity.nodeId : undefined,
    });

    // assertionId is derived from the full v2.0 preimage, so it is set after construction and
    // before signing. It is not part of the preimage itself (it is a hash OF it), so order
    // relative to signCMB does not matter for the signature — only that the emitted record
    // carries it for a downstream verified-record receipt.
    if (MMP_EMIT_V2) {
      cmb.metadata.assertionId = assertionIdV2_0(cmb);
    }

    // No remix re-key. The v2 address is the Merkle root over the seven categoryKeys and is
    // CONTENT-ONLY, so a lineage-bearing block is addressed exactly like any other block with
    // the same content — which is the collapse property, and it is what lets an agent's
    // re-assertion of its own HEAD cite rather than mint (Rule A's soundness condition).
    // Under the old scheme this line re-keyed the block under a name-bound remix derivation;
    // that derivation is gone.

    signCMB(cmb, this._identity.privateKey);
    const sent = this._session.trySend({ type: 'cmb', timestamp: Date.now(), cmb });
    if (!sent.ok) {
      const e = new Error(`emit: the record was not sent (${sent.reason})`);
      e.code = 'EEMITSEND';
      throw e;
    }
    return { key: cmb.metadata.key, cmb };
  }

  /** Flush and disconnect. Safe to call once; resolves when the socket closes. */
  close() {
    if (this._release) { try { this._release(); } catch { /* */ } this._release = null; }
    return new Promise((resolve) => {
      if (this._socket.destroyed) return resolve();
      // Let what was written drain, then end the session with the socket.
      this._socket.once('close', () => { try { this._session.close('emitter-closed', { notify: false, closeTransport: false }); } catch { /* */ } });
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
 * @param {{ nodeId: string, key?: string, fingerprint?: string }} opts.receiver - THE RECEIVER, PINNED
 *   (security review): the nodeId the endpoint must prove, and its identity key or `sha256:` key
 *   fingerprint. An address names nobody; without the pin anyone answering at host:port would take
 *   the record. Refused without it.
 * @param {string} [opts.room] - the room this emitter claims and authors for. Omitted, it claims
 *   none, and authors for the room the node it connects to admits it into.
 * @param {string} [opts.name='emitter'] - stable emitter identity name. Never a node that is live on
 *   this host: the emitter holds the identity's lock while it is connected (two processes would be
 *   one identity twice, §3.2).
 * @param {number} [opts.timeoutMs=8000] - connect + handshake deadline.
 * @returns {Promise<Emitter>}
 */
async function connect({ server, receiver, room, name = 'emitter', timeoutMs = HANDSHAKE_TIMEOUT_MS } = {}) {
  if (!receiver || typeof receiver.nodeId !== 'string' || !(typeof receiver.key === 'string' || typeof receiver.fingerprint === 'string')) {
    throw Object.assign(new Error('emit: the receiver must be pinned: { nodeId, key } or { nodeId, fingerprint } (sym emit --receiver <nodeId> --receiver-key <key|sha256:…>)'), { code: 'EEMITPIN' });
  }
  const identity = loadOrCreateIdentity(name);
  // The identity's lock, held while connected: a live node of this name refuses the emitter.
  const release = acquireIdentityLock(name, { dir: nodeDirById(identity.nodeId) });
  // §5.8: the room is explicit in Core Secure; the default room is the literal 'default'.
  const claimed = (typeof room === 'string' && room) ? room : 'default';

  // A bad address or a failed connect releases the identity's lock (final re-review, Low): the
  // emitter is not connected, so it holds nothing.
  let socket;
  try {
    const { host, port } = parseServer(server);
    socket = await new Promise((resolve, reject) => {
      const s = net.connect({ host, port });
      const t = setTimeout(() => { s.destroy(); reject(new Error(`emit: connect timeout to ${server}`)); }, timeoutMs);
      s.once('connect', () => { clearTimeout(t); resolve(s); });
      s.once('error', (e) => { clearTimeout(t); reject(e); });
    });
  } catch (err) {
    release();
    throw err;
  }

  const transport = new TcpTransport(socket);
  const session = new PeerSession({
    role: 'client', transport, kind: 'bonjour', room: claimed, expectNodeId: receiver.nodeId,
    local: { nodeId: identity.nodeId, name, publicKey: identity.publicKey, privateKey: identity.privateKey },
    extensions: [EXT_CMB_ENCRYPTED_V2], implementation: IMPLEMENTATION, timeoutMs,
  });
  transport.on('message', (f) => session.receiveWire(f)); // §7.3: anything else after the handshake is ignored
  transport.on('error', () => {});

  await new Promise((resolve, reject) => {
    session.once('confirmed', () => resolve());
    session.once('closed', (c) => reject(new Error(`emit: ${server} did not complete the Core Secure handshake (${c.reason}${c.detail ? `: ${c.detail}` : ''})`)));
    transport.once('close', () => { if (!session.confirmed) session.close('transport-closed', { notify: false }); });
    session.start();
  }).catch((e) => { socket.destroy(); release(); throw e; });
  // The endpoint proved the pinned nodeId (expectNodeId); now its key must be the pinned one too.
  const keyOk = typeof receiver.key === 'string' ? session.identityKey === receiver.key : keyFingerprint(session.identityKey) === receiver.fingerprint;
  if (!keyOk) {
    socket.destroy(); release();
    throw Object.assign(new Error(`emit: ${server} proved ${receiver.nodeId.slice(0, 8)} under a key that is not the pinned one`), { code: 'EEMITPIN' });
  }
  const emitter = new Emitter({ identity, session, socket, room: claimed, name });
  emitter._release = release;
  return emitter;
}

/**
 * One-shot: connect, emit a single block, disconnect.
 * @returns {Promise<{ key: string, cmb: object }>}
 */
async function emitOnce(opts, categories, emitOpts = {}) {
  const emitter = await connect(opts);
  try {
    return emitter.emit(categories, emitOpts);
  } finally {
    await emitter.close();
  }
}

module.exports = { connect, emitOnce, Emitter, parseServer };
