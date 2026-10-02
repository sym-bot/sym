'use strict';

/**
 * @module @sym-bot/sym/session
 * @description A Core Secure session over one transport: the MMP v2.0 §5.2 handshake driven over a
 * TCP connection, the loopback, or a relay channel, and then the sealed, ordered channel it opens
 * (design D1/D2, sym 0.14).
 *
 * THE SESSION IS THE UNIT OF TRUST. Before 0.14 a peer existed the moment a socket connected or the
 * relay announced a name, and its keys were pinned from an unproven hello. Here nothing about the
 * peer exists until both proofs validate: the identity proof (Ed25519 over the transcript) and the
 * key confirmation (HMAC under the X25519/HKDF schedule). A failure closes the transport and keeps no
 * peer state (§5.2). What a confirmed session knows — the proven nodeId, identity key, this session's
 * ephemeral X25519 key, sessionId, room, selected extensions — is all a peer is.
 *
 * Rules this module enforces:
 *   - The dialler is the client and sends `client-hello`; the listener accepts `client-hello` and
 *     nothing else, and no other frame before `client-finish` (§5.2, §5.3). 10 s timeout.
 *   - A fresh X25519 key pair per handshake, generated here. Private keys are never injectable
 *     through configuration: only the pure handshake functions take them, for the public vectors.
 *   - An all-zero shared secret aborts (§5.2.1).
 *   - Every hello field is checked at the door (types, lengths, encodings) before it is used.
 *   - `cmb-encrypted-v2` must be selected: a session that would carry records in the clear is not a
 *     Core Secure session, and a negotiation failure never falls back to anything (§17.3).
 *   - After confirmation every frame is sealed: records as `cmb-encrypted` (§18.2.1), every other
 *     frame but ping/pong/error as `control-encrypted` (lib/core/sealed-control.js). The receive
 *     counter advances only after the AEAD opens; a forged frame moves nothing; an authentic frame
 *     out of order (replay, rollback, gap) closes the session so the owner re-handshakes.
 *
 * The session emits:
 *   'confirmed' (session)            — both proofs valid; the facts are on the session
 *   'frame' (frame, session)         — one authenticated inner frame ({type:'cmb', cmb} for a record)
 *   'refused' (type, reason, session)— a wire frame this session does not take (counted by the owner)
 *   'closed' ({ reason, desync }, session)
 *
 * @copyright 2026 SYM.BOT. Apache 2.0 License.
 */

const crypto = require('crypto');
const { EventEmitter } = require('events');
const { clientHello, serverAccept, clientFinish, serverConfirm, PROTOCOL_VERSION } = require('./core/handshake-v2-flow');
const { EXT_CMB_ENCRYPTED_V2 } = require('./core/mmp-extensions');
const { buildEncryptedFrame, openEncryptedFrame, FRAME_TYPE: CMB_ENCRYPTED } = require('./core/cmb-encrypted-frame');
const { buildControlFrame, openControlFrame, FRAME_TYPE: CONTROL_ENCRYPTED } = require('./core/sealed-control');
const { SEND_FAILURE, MAX_FRAME_SIZE } = require('./frame-parser');

const HANDSHAKE_TIMEOUT_MS = 10_000;
const HANDSHAKE_TYPES = new Set(['client-hello', 'server-hello', 'client-finish']);
/** Room left for a relay envelope ({to, payload}) around a sealed frame. */
const ENVELOPE_ALLOWANCE = 4096;
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const B64_32 = /^[A-Za-z0-9_-]{43}$/;
const SIG_RE = /^[A-Za-z0-9_-]{86}$/;
const EXT_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
let SEQ = 0;

const b64 = (buf) => Buffer.from(buf).toString('base64url');

/** A fresh X25519 key pair for one handshake. */
function freshX25519() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  return { privateKey, publicKey: b64(publicKey.export({ type: 'spki', format: 'der' }).subarray(-32)) };
}

/**
 * X25519 against a raw base64url peer key. Throws for a key that is not 32 bytes, an agreement the
 * library refuses, and an all-zero result (a low-order point: §5.2.1 MUST abort).
 */
function agreeX25519(privateKey, peerRawB64url, dh = crypto.diffieHellman) {
  const raw = Buffer.from(String(peerRawB64url), 'base64url');
  if (raw.length !== 32) throw new Error('handshake: the peer X25519 key is not 32 bytes');
  let ss;
  try {
    // OpenSSL itself refuses the low-order points it knows; the all-zero check below does not rely on it.
    ss = dh({ privateKey, publicKey: crypto.createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' }) });
  } catch (e) {
    throw new Error(`handshake: X25519 agreement failed (${e.message}) — aborting`);
  }
  if (ss.length !== 32 || ss.every((b) => b === 0)) throw new Error('handshake: all-zero X25519 shared secret — aborting (§5.2.1)');
  return ss;
}

const is32 = (s) => typeof s === 'string' && B64_32.test(s) && Buffer.from(s, 'base64url').length === 32;

/** A hello's offer, checked field by field before anything uses it. Throws with what is wrong. */
function checkOffer(f, kind) {
  if (!f || typeof f !== 'object' || Array.isArray(f)) throw new Error(`handshake: ${kind} is not an object`);
  if (f.protocolVersion !== PROTOCOL_VERSION) throw new Error('handshake: unsupported protocolVersion');
  if (typeof f.room !== 'string' || !f.room || f.room.length > 128) throw new Error(`handshake: ${kind} room is not a room`);
  if (typeof f.nodeId !== 'string' || !UUID_RE.test(f.nodeId)) throw new Error(`handshake: ${kind} nodeId is not a UUID`);
  if (typeof f.name !== 'string' || !f.name || f.name.length > 256) throw new Error(`handshake: ${kind} name is not a name`);
  for (const k of ['identityPublicKey', 'e2ePublicKey', 'nonce']) {
    if (!is32(f[k])) throw new Error(`handshake: ${kind} ${k} is not 32 bytes of unpadded base64url`);
  }
  const impl = f.implementation;
  if (!impl || typeof impl !== 'object' || typeof impl.name !== 'string' || typeof impl.version !== 'string'
      || !impl.name || !impl.version || impl.name.length > 128 || impl.version.length > 128) {
    throw new Error(`handshake: ${kind} implementation is not {name, version}`);
  }
  checkExtensions(f.extensions, `${kind} extensions`);
}

function checkExtensions(list, what) {
  if (!Array.isArray(list) || list.length > 64) throw new Error(`handshake: ${what} is not a list`);
  const seen = new Set();
  for (const e of list) {
    if (typeof e !== 'string' || !EXT_RE.test(e) || seen.has(e)) throw new Error(`handshake: ${what} carries an invalid or repeated entry`);
    seen.add(e);
  }
}

class PeerSession extends EventEmitter {
  /**
   * @param {object} o
   * @param {'client'|'server'} o.role - the dialler is the client
   * @param {object} o.transport - { trySend(frame)|send(frame), close() }; inbound frames are fed in
   *   by the owner through receiveWire (a TCP owner wires transport 'message' to it)
   * @param {'bonjour'|'relay'} o.kind - the transport kind, for multi-transport peers (§4.6)
   * @param {{nodeId:string, name:string, publicKey:string, privateKey:string}} o.local - this node
   * @param {string} o.room
   * @param {string[]} o.extensions - what this node offers
   * @param {{name:string, version:string}} o.implementation
   * @param {string} [o.expectNodeId] - the nodeId a dialled candidate claimed, or (server) the relay `from` a
   *   relay session runs over; a session presenting another is refused
   * @param {string} [o.relayFrom] - the relay `from` a relay session is bound to
   * @param {number} [o.timeoutMs]
   */
  constructor(o) {
    super();
    if (o.role !== 'client' && o.role !== 'server') throw new Error('PeerSession: role must be client|server');
    this.role = o.role;
    this.kind = o.kind || 'bonjour';
    this.id = `${this.kind}:${o.role}:${++SEQ}`;
    this.transport = o.transport;
    this.relayFrom = o.relayFrom || null;
    this.expectNodeId = o.expectNodeId || null;
    this.room = o.room;
    this.state = 'authenticating';
    this.startedAt = Date.now();
    this.lastSeen = Date.now();
    this.closedReason = null;
    // Facts, set only on confirmation.
    this.nodeId = null; this.name = null; this.identityKey = null; this.peerE2EPublicKey = null;
    this.sessionId = null; this.selected = []; this.peerExtensions = []; this.peerImplementation = null;
    this.confirmedAt = null;
    this._local = o.local;
    this._offer = [...new Set(o.extensions || [])];
    this._implementation = o.implementation;
    this._x = freshX25519();
    this.localE2EPublicKey = this._x.publicKey;
    this._mmp = null;
    this._sharedSecret = null;
    this._clientHello = null;
    this._serverAccept = null;
    const ms = o.timeoutMs ?? HANDSHAKE_TIMEOUT_MS;
    this._timer = setTimeout(() => this._fail('timeout', `no confirmed handshake within ${ms} ms`), ms);
    if (this._timer.unref) this._timer.unref();
  }

  get confirmed() { return this.state === 'confirmed'; }
  get closed() { return this.state === 'closed'; }
  /** Transport-shaped: a closed session refuses frames (the peer table reads `_closed`). */
  get _closed() { return this.state === 'closed'; }

  /** Whether `ext` is active on this session (in both offers and selected, §16.3). */
  has(ext) { return this.selected.includes(ext); }

  _self() {
    return {
      room: this.room, nodeId: this._local.nodeId, name: this._local.name,
      identityPublicKey: this._local.publicKey, e2ePublicKey: this.localE2EPublicKey,
      implementation: this._implementation, extensions: this._offer, identityPrivateKey: this._local.privateKey,
    };
  }

  _agree() {
    return (peerKey) => {
      if (!this._sharedSecret) this._sharedSecret = agreeX25519(this._x.privateKey, peerKey);
      return this._sharedSecret;
    };
  }

  /** CLIENT: send the client-hello. */
  start() {
    if (this.role !== 'client' || this._clientHello || this.closed) return;
    const { frame } = clientHello(this._self());
    this._clientHello = frame;
    this._wire(frame);
  }

  /** Feed one frame from the transport. Never throws: a failure closes the session. */
  receiveWire(frame) {
    if (this.closed) return;
    try {
      if (!frame || typeof frame !== 'object' || typeof frame.type !== 'string') { this._refuse('?', 'not-a-frame'); return; }
      if (this.state === 'authenticating') this._handshakeFrame(frame);
      else this._sessionFrame(frame);
    } catch (err) {
      this._fail('error', err && err.message ? err.message : String(err));
    }
  }

  _handshakeFrame(f) {
    if (this.role === 'server') {
      if (!this._serverAccept) {
        // The Core Secure listener takes client-hello first and nothing else (§5.2, mmp-ingress).
        if (f.type !== 'client-hello') { this._fail('first-frame', `the first frame must be client-hello, got '${String(f.type).slice(0, 40)}'`); return; }
        checkOffer(f, 'client-hello');
        if (f.nodeId === this._local.nodeId) { this._fail('duplicate-node-id', 'the peer presented this node\'s own nodeId'); return; }
        // A relay session is bound to the relay `from` it runs over (design D2): a hello naming another
        // nodeId is refused before anything is computed (the transcript then binds the nodeId proven).
        if (this.expectNodeId && f.nodeId !== this.expectNodeId) {
          this._fail('node-id-mismatch', `the session is bound to ${String(this.expectNodeId).slice(0, 8)}, the hello names ${String(f.nodeId).slice(0, 8)}`); return;
        }
        if (f.room !== this.room) { this._fail('room-mismatch', `the peer is in '${String(f.room).slice(0, 64)}', this node in '${this.room}'`); return; }
        const sa = serverAccept({ clientHelloFrame: f, self: this._self(), agree: this._agree() });
        if (!sa.selected.includes(EXT_CMB_ENCRYPTED_V2)) { this._fail('no-core-secure', 'the client did not offer cmb-encrypted-v2'); return; }
        this._clientHelloSeen = f;
        this._serverAccept = sa;
        this._wire(sa.frame);
        return;
      }
      if (f.type !== 'client-finish') { this._fail('frame-before-finish', `'${String(f.type).slice(0, 40)}' before client-finish`); return; }
      if (typeof f.transcriptHash !== 'string' || !/^[0-9a-f]{64}$/.test(f.transcriptHash) || typeof f.proof !== 'string' || !SIG_RE.test(f.proof) || !is32(f.keyConfirmation)) {
        this._fail('error', 'client-finish fields are malformed'); return;
      }
      const ch = this._clientHelloSeen;
      const session = serverConfirm({
        clientFinishFrame: f, transcript: this._serverAccept.transcript, session: this._serverAccept.session,
        clientIdentityPublicKey: ch.identityPublicKey, sharedSecret: this._sharedSecret,
      });
      this._confirm(session, ch, this._serverAccept.selected);
      return;
    }
    // CLIENT
    if (f.type !== 'server-hello') { this._fail('frame-before-confirm', `'${String(f.type).slice(0, 40)}' before server-hello`); return; }
    checkOffer(f, 'server-hello');
    if (!is32(f.clientNonce) || typeof f.proof !== 'string' || !SIG_RE.test(f.proof) || !is32(f.keyConfirmation)) {
      this._fail('error', 'server-hello proof fields are malformed'); return;
    }
    checkExtensions(f.selectedExtensions, 'selectedExtensions');
    if (f.nodeId === this._local.nodeId) { this._fail('duplicate-node-id', 'the peer presented this node\'s own nodeId'); return; }
    if (this.expectNodeId && f.nodeId !== this.expectNodeId) {
      this._fail('node-id-mismatch', `dialled ${String(this.expectNodeId).slice(0, 8)}, the endpoint proved ${f.nodeId.slice(0, 8)}`); return;
    }
    const cf = clientFinish({ serverHelloFrame: f, clientHelloFrame: this._clientHello, self: this._self(), agree: this._agree() });
    if (!cf.selected.includes(EXT_CMB_ENCRYPTED_V2)) { this._fail('no-core-secure', 'the server did not select cmb-encrypted-v2'); return; }
    this._wire(cf.frame);
    this._confirm(cf.session, f, cf.selected);
  }

  _confirm(mmp, peerOffer, selected) {
    clearTimeout(this._timer);
    this._mmp = mmp;
    this.nodeId = peerOffer.nodeId;
    this.name = peerOffer.name;
    this.identityKey = peerOffer.identityPublicKey;
    this.peerE2EPublicKey = peerOffer.e2ePublicKey;
    this.peerExtensions = [...peerOffer.extensions];
    this.peerImplementation = { name: peerOffer.implementation.name, version: peerOffer.implementation.version };
    this.selected = [...selected];
    this.sessionId = mmp.sessionId;
    this.state = 'confirmed';
    this.confirmedAt = Date.now();
    this.lastSeen = this.confirmedAt;
    // The X25519 private key is not needed again: this session's keys are derived.
    this._x = null;
    this.emit('confirmed', this);
  }

  _sessionFrame(f) {
    switch (f.type) {
      case CMB_ENCRYPTED: return this._openRecord(f);
      case CONTROL_ENCRYPTED: return this._openControl(f);
      case 'ping': this.lastSeen = Date.now(); this._wire({ type: 'pong' }); return;
      case 'pong': this.lastSeen = Date.now(); return;
      case 'error':
        // §7.2: 2xxx errors are informational; anything else ends the session (the peer closed it).
        if (Number.isInteger(f.code) && f.code >= 2000 && f.code < 3000) return;
        this._fail('peer-closed', typeof f.message === 'string' ? f.message.slice(0, 200) : 'error frame', { notify: false });
        return;
      default:
        // A legacy `cmb`, a plaintext `mood`, a legacy `handshake`, `state-sync`, a stray hello: none
        // is taken on a Core Secure session (design D1's frame table).
        this._refuse(f.type, HANDSHAKE_TYPES.has(f.type) ? 'handshake-after-confirm' : 'not-sealed');
    }
  }

  _position(f, open, what) {
    if (f.sessionId !== this.sessionId) { this._refuse(f.type, 'other-session'); return undefined; }
    try {
      const out = this._mmp.receive(f.sequence, f.direction, open);
      this.lastSeen = Date.now();
      return out;
    } catch (err) {
      if (err && err.name === 'SessionDesyncError') {
        this._fail('desync', err.message, { desync: true });
      } else {
        this._refuse(f.type, `${what} did not authenticate`);
      }
      return undefined;
    }
  }

  _openRecord(f) {
    const out = this._position(f, (trafficKey) => openEncryptedFrame({ frame: f, trafficKey }), 'record');
    if (!out) return;
    const metadata = { ...out.cmb.metadata };
    // The clear metadata carries the application descriptor without its data; the bytes ride sealed
    // as applicationData (§18.2.1). The logical record has them back in metadata.application.data.
    if (metadata.application && typeof metadata.application === 'object') {
      if (!out.applicationBytes) { this._refuse(f.type, 'application-without-data'); return; }
      metadata.application = { ...metadata.application, data: b64(out.applicationBytes) };
    } else if (out.applicationBytes) {
      this._refuse(f.type, 'data-without-application'); return;
    }
    if (metadata.signatureSuite !== 'mmp-sig-v2.0') { this._refuse(f.type, 'not-a-v2.0-record'); return; }
    this.emit('frame', { type: 'cmb', cmb: { categories: out.cmb.categories, metadata } }, this);
  }

  _openControl(f) {
    const inner = this._position(f, (trafficKey) => openControlFrame({ frame: f, trafficKey }), 'control frame');
    if (!inner) return;
    this.emit('frame', inner, this);
  }

  /**
   * Transport-shaped send. Records go as `cmb-encrypted`, ping/pong/error as they are, everything
   * else as `control-encrypted`. Says why a frame was not taken.
   * @returns {{ ok: boolean, reason?: string, bytes?: number }}
   */
  trySend(frame) {
    if (this.state !== 'confirmed') return { ok: false, reason: SEND_FAILURE.NOT_CONNECTED };
    if (!frame || typeof frame.type !== 'string') return { ok: false, reason: 'not-a-frame' };
    if (frame.type === 'ping' || frame.type === 'pong' || frame.type === 'error') return this._wire(frame);
    let wire;
    let pos;
    try {
      pos = this._mmp.nextSend();
      wire = frame.type === 'cmb' ? this._sealRecord(frame.cmb, pos) : buildControlFrame({ frame, sessionId: this.sessionId, direction: pos.direction, sequence: pos.sequence, trafficKey: pos.trafficKey });
    } catch (err) {
      if (pos) this._mmp.cancelSend(pos.sequence);
      return { ok: false, reason: 'unsealable', error: err && err.message };
    }
    const bytes = Buffer.byteLength(JSON.stringify(wire), 'utf8');
    if (bytes + (this.kind === 'relay' ? ENVELOPE_ALLOWANCE : 0) > MAX_FRAME_SIZE) {
      // Never written, so its sequence is reused: the receiver sees no gap.
      this._mmp.cancelSend(pos.sequence);
      return { ok: false, reason: SEND_FAILURE.TOO_LARGE, bytes };
    }
    const r = this._wire(wire);
    // A frame the transport refused after its position was taken leaves a gap the peer cannot heal:
    // the session closes, and the owner re-handshakes.
    if (!r.ok && r.reason !== SEND_FAILURE.TOO_LARGE) this._fail('send-failed', `the transport refused a sealed frame (${r.reason})`);
    return r;
  }

  send(frame) { return this.trySend(frame).ok; }

  _sealRecord(cmb, pos) {
    if (!cmb || !cmb.metadata || !cmb.categories) throw new Error('not a record');
    if (cmb.metadata.signatureSuite !== 'mmp-sig-v2.0' || !cmb.metadata.sig) throw new Error('only signed v2.0 records travel in Core Secure (§18.3.1)');
    const metadata = { ...cmb.metadata };
    let applicationBytes = null;
    if (metadata.application && typeof metadata.application === 'object') {
      const { data, ...descriptor } = metadata.application;
      if (typeof data !== 'string') throw new Error('an application descriptor without its data');
      applicationBytes = Buffer.from(data, 'base64url');
      metadata.application = descriptor;
    }
    return buildEncryptedFrame({ cmb: { categories: cmb.categories, metadata }, applicationBytes, sessionId: this.sessionId, direction: pos.direction, sequence: pos.sequence, trafficKey: pos.trafficKey });
  }

  _wire(frame) {
    const t = this.transport;
    if (!t) return { ok: false, reason: SEND_FAILURE.NOT_CONNECTED };
    try {
      if (typeof t.trySend === 'function') return t.trySend(frame);
      return t.send(frame) !== false ? { ok: true } : { ok: false, reason: 'send-failed' };
    } catch {
      return { ok: false, reason: SEND_FAILURE.WRITE_FAILED };
    }
  }

  _refuse(type, reason) {
    try { this.emit('refused', String(type).slice(0, 40), reason, this); } catch { /* a listener must not fail the session */ }
  }

  _fail(reason, detail, { desync = false, notify = true } = {}) {
    if (this.closed) return;
    this.close(reason, { detail, desync, notify });
  }

  /**
   * Close the session. On a relay, closing means sending an `error` frame to the peer (design D2) and
   * dropping the session; on TCP the transport closes with it. Emits 'closed' once.
   */
  close(reason = 'closed', { detail = null, desync = false, notify = true, closeTransport = true } = {}) {
    if (this.closed) return;
    const wasConfirmed = this.state === 'confirmed';
    clearTimeout(this._timer);
    if (notify && this.kind === 'relay' && this.transport) {
      this._wire({ type: 'error', code: 4400, message: `session closed: ${reason}`, ...(this.sessionId ? { detail: `session:${this.sessionId}` } : {}) });
    }
    this.state = 'closed';
    this.closedReason = reason;
    this._x = null;
    if (closeTransport && this.transport && this.kind !== 'relay') { try { this.transport.close(); } catch { /* already gone */ } }
    this.emit('closed', { reason, detail, desync, wasConfirmed }, this);
  }
}

module.exports = { PeerSession, agreeX25519, freshX25519, checkOffer, HANDSHAKE_TIMEOUT_MS, HANDSHAKE_TYPES };
