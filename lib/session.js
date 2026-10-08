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
 *     frame but ping/pong as `control-encrypted` (lib/core/sealed-control.js), an `error` included
 *     (security review F). The receive counter advances only after the AEAD opens; a forged frame
 *     moves nothing; an authentic replay or rollback is discarded (a relay can repeat what it carried,
 *     draft spec PR #23); a gap closes the session so the owner re-handshakes.
 *   - ERRORS ARE INFORMATION, NEVER COMMANDS (security review F). A sealed `error` is the peer's:
 *     1010 SESSION_CLOSED and 1009 IDENTITY_CONFLICT end the session, anything else is noted. A clear
 *     `error` on a confirmed session is anyone's and is ignored, except 1011 UNKNOWN_SESSION ("I hold
 *     no session with you"), which prompts a new handshake (event 'unknown-session') and never a
 *     teardown: the session stays until a new one supersedes it.
 *
 * The session emits:
 *   'confirmed' (session)            — both proofs valid; the facts are on the session
 *   'frame' (frame, session)         — one authenticated inner frame ({type:'cmb', cmb} for a record)
 *   'refused' (type, reason, session)— a wire frame this session does not take (counted by the owner)
 *   'unknown-session' (session)      — a clear 1011: the peer says it holds no session with this node
 *   'closed' ({ reason, desync }, session)
 *
 * @copyright 2026 SYM.BOT. Apache 2.0 License.
 */

const crypto = require('crypto');
const { EventEmitter } = require('events');
const { clientHello, serverAccept, clientFinish, serverConfirm, PROTOCOL_VERSION } = require('./core/handshake-v2-flow');
const { EXT_CMB_ENCRYPTED_V2 } = require('./core/mmp-extensions');
const { buildEncryptedFrame, openEncryptedSealed, parseEncryptedPlain, FRAME_TYPE: CMB_ENCRYPTED } = require('./core/cmb-encrypted-frame');
const { buildControlFrame, openControlSealed, parseControlPlain, FRAME_TYPE: CONTROL_ENCRYPTED } = require('./core/sealed-control');
const { SEND_FAILURE, MAX_FRAME_SIZE } = require('./frame-parser');

const HANDSHAKE_TIMEOUT_MS = 10_000;
const HANDSHAKE_TYPES = new Set(['client-hello', 'server-hello', 'client-finish']);
/** MMP §7.2 error codes (draft spec PRs #21, #23, #31): a bound nodeId proving another key; the
 *  peer closed this session; the sender holds no session with the receiver. */
const IDENTITY_CONFLICT = 1009;
const SESSION_CLOSED = 1010;
const UNKNOWN_SESSION = 1011;
/**
 * MMP §7.2: the error codes whose action is Close. A SEALED error with one of these ends the session
 * at the receiver (it is the peer's own word); any other sealed code is information. A clear error
 * never changes a session's state (1011 only prompts a handshake).
 */
const CLOSE_CODES = new Set([1001, 1003, 1004, 1005, 1006, 1007, 1008, IDENTITY_CONFLICT, SESSION_CLOSED]);
/** Room left for a relay envelope ({to, payload}) around a sealed frame. */
const ENVELOPE_ALLOWANCE = 4096;
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
/** A record offered to a session its signed audience does not include (review finding A). */
class AudienceError extends Error {}
const { signedProjection } = require('./core/record-canonical');
const { MAX_SEALED_CHARS } = require('./core/cmb-encoder');
// nodeIds are canonical lowercase on the wire (§3.1.1; review finding B): an upper-case alias of a
// bound nodeId is not a second identity, it is refused at the door.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
// 32 bytes in canonical unpadded base64url (one spelling per key: the authority statements' PUBLIC_KEY).
const { PUBLIC_KEY: B64_32 } = require('./core/authority');
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
    if (!is32(f[k])) throw new Error(`handshake: ${kind} ${k} is not 32 bytes of canonical unpadded base64url`);
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
        // Rooms compare in NFC (§8.8.4 normalises the room it signs; review): two spellings of one
        // room are one room, and a lookalike in another normalisation is not let through either way.
        if (typeof f.room !== 'string' || f.room.normalize('NFC') !== String(this.room).normalize('NFC')) { this._fail('room-mismatch', `the peer is in '${String(f.room).slice(0, 64)}', this node in '${this.room}'`); return; }
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
      case 'pong': this.lastSeen = Date.now(); this.probeSince = 0; return;
      case 'error':
        // A CLEAR error on a confirmed session is anyone's to write (security review F): never a
        // command. Only 1011 UNKNOWN_SESSION means something — the peer holds no session with this
        // node (it restarted) — and it may prompt a new handshake while this session stays; the owner
        // decides whether it names this session (§5.2.2).
        if (f.code === UNKNOWN_SESSION) { this.emit('unknown-session', this, f); return; }
        this._refuse('error', 'clear-error-ignored');
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
      if (err && err.name === 'SessionDesyncError' && err.kind === 'replay') {
        // Authentic, but already received: a relay repeating what it carried (draft spec PR #23).
        // Discarded; the session is unharmed.
        this._refuse(f.type, 'replay');
      } else if (err && err.name === 'SessionDesyncError') {
        this._fail('desync', err.message, { desync: true });
      } else {
        this._refuse(f.type, `${what} did not authenticate`);
      }
      return undefined;
    }
  }

  _openRecord(f) {
    // MMP §8.8.6: a sealed value longer than a MAX_RECORD_BYTES plaintext can produce is refused
    // before it is opened. Nothing about the session changes (the frame is unauthenticated until it
    // opens, so anyone on a relay could have sent it); a genuine one from the peer leaves a gap that
    // the next frame's sequence closes the session on.
    if (typeof f.sealed === 'string' && f.sealed.length > MAX_SEALED_CHARS) { this._refuse(f.type, 'record-too-large'); return; }
    // MMP §18.2.1: a frame that opens advances the receive sequence, whatever it carries. Its plaintext
    // is parsed only after the position is taken, so refusing what it carries changes nothing else
    // (before, a refused plaintext left the counter behind, and the next frame closed the session as a gap).
    const plain = this._position(f, (trafficKey) => openEncryptedSealed({ frame: f, trafficKey }), 'record');
    if (!plain) return;
    let out;
    try { out = parseEncryptedPlain(f, plain); } catch (err) { this._refuse(f.type, `record refused: ${err && err.message}`); return; }
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
    // As for a record: the position is taken once the frame opens, and the inner frame parsed after.
    const plain = this._position(f, (trafficKey) => openControlSealed({ frame: f, trafficKey }), 'control frame');
    if (!plain) return;
    let inner;
    try { inner = parseControlPlain(plain); } catch (err) { this._refuse(f.type, `inner frame refused: ${err && err.message}`); return; }
    // ping and pong may travel sealed too (§7.1): liveness, exactly as in clear.
    if (inner.type === 'ping') { this._wire({ type: 'pong' }); return; }
    if (inner.type === 'pong') { this.probeSince = 0; return; }
    if (inner.type === 'error') {
      // A SEALED error is the peer's own word. One whose §7.2 action is Close ends the session: 1009
      // it binds this node's nodeId to another key, 1010 it closed this session, and the other Close
      // codes alike; anything else is information.
      const message = typeof inner.message === 'string' ? inner.message.slice(0, 200) : 'error frame';
      if (inner.code === IDENTITY_CONFLICT) { this._fail('identity-conflict', message, { notify: false }); return; }
      if (inner.code === SESSION_CLOSED) { this._fail('peer-closed', message, { notify: false }); return; }
      if (CLOSE_CODES.has(inner.code)) { this._fail('peer-closed', `${inner.code}: ${message}`, { notify: false }); return; }
      this._refuse('error', `peer-error-${Number.isInteger(inner.code) && inner.code >= 1000 && inner.code < 5000 ? inner.code : 'other'}`);
      return;
    }
    this.emit('frame', inner, this);
  }

  /**
   * Transport-shaped send. Records go as `cmb-encrypted`, ping/pong as they are, everything else
   * (an `error` included: security review F) as `control-encrypted`. Says why a frame was not taken.
   * @returns {{ ok: boolean, reason?: string, bytes?: number }}
   */
  trySend(frame) {
    if (this.state !== 'confirmed') return { ok: false, reason: SEND_FAILURE.NOT_CONNECTED };
    if (!frame || typeof frame.type !== 'string') return { ok: false, reason: 'not-a-frame' };
    if (frame.type === 'ping' || frame.type === 'pong') return this._wire(frame);
    let wire;
    let pos;
    try {
      pos = this._mmp.nextSend();
      wire = frame.type === 'cmb' ? this._sealRecord(frame.cmb, pos) : buildControlFrame({ frame, sessionId: this.sessionId, direction: pos.direction, sequence: pos.sequence, trafficKey: pos.trafficKey });
    } catch (err) {
      if (pos) this._mmp.cancelSend(pos.sequence);
      return { ok: false, reason: err instanceof AudienceError ? 'not-addressed' : 'unsealable', error: err && err.message };
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

  /** Bytes written to this session's transport and not yet sent (0 when the transport cannot say). */
  pendingBytes() {
    const t = this.transport;
    try { return t && typeof t.pendingBytes === 'function' ? t.pendingBytes() : 0; } catch { return 0; }
  }

  _sealRecord(cmb, pos) {
    if (!cmb || !cmb.metadata || !cmb.categories) throw new Error('not a record');
    if (cmb.metadata.signatureSuite !== 'mmp-sig-v2.0' || !cmb.metadata.sig) throw new Error('only signed v2.0 records travel in Core Secure (§18.3.1)');
    // THE SIGNED AUDIENCE GOVERNS EVERY SEND (review finding A): the one seal point refuses a record
    // whose signed `to` names anyone but this session's proven peer, whichever path offered it (an
    // anchor replay, a fetch answer, a broadcast, a queued frame). A directed record is sealed only to
    // the node it was signed to.
    const to = cmb.metadata.to;
    if (to !== null && to !== undefined && to !== this.nodeId) throw new AudienceError(`a record signed to ${String(to).slice(0, 8)} is never sealed to ${String(this.nodeId).slice(0, 8)}`);
    // The signed room governs too: a node's store is per node, not per room, so a record signed for
    // another room (one this node held before it moved rooms) is never sealed to this session's peer,
    // whichever path offered it (a fetch answer, an anchor replay). Its content would be disclosed
    // before the receiver refused it.
    const room = cmb.metadata.room;
    if (typeof room !== 'string' || room.normalize('NFC') !== String(this.room).normalize('NFC')) throw new AudienceError(`a record signed for room '${String(room).slice(0, 64)}' is never sealed to a session in '${String(this.room).slice(0, 64)}'`);
    // Only the signed projection travels (finding B): members no signature covers are not sent.
    cmb = signedProjection(cmb);
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
   * Close the session. On a relay, closing a CONFIRMED session means sending the peer a sealed 1010
   * SESSION_CLOSED (design D2; security review F) and dropping the session; a handshake that did not
   * confirm sends nothing (it leaves any confirmed session exactly as it was, draft spec PR #23); on
   * TCP the transport closes with it. Emits 'closed' once.
   */
  close(reason = 'closed', { detail = null, desync = false, notify = true, closeTransport = true } = {}) {
    if (this.closed || this._closing) return;
    this._closing = true; // the notice below may fail and close again: once is enough
    const wasConfirmed = this.state === 'confirmed';
    clearTimeout(this._timer);
    if (notify && wasConfirmed && this.kind === 'relay' && this.transport) {
      try { this.trySend({ type: 'error', code: SESSION_CLOSED, message: `session closed: ${String(reason).slice(0, 80)}` }); } catch { /* closing either way */ }
    }
    this.state = 'closed';
    this.closedReason = reason;
    this._x = null;
    if (closeTransport && this.transport && this.kind !== 'relay') { try { this.transport.close(); } catch { /* already gone */ } }
    this.emit('closed', { reason, detail, desync, wasConfirmed }, this);
  }
}

module.exports = { PeerSession, agreeX25519, freshX25519, checkOffer, HANDSHAKE_TIMEOUT_MS, HANDSHAKE_TYPES, IDENTITY_CONFLICT, SESSION_CLOSED, UNKNOWN_SESSION, CLOSE_CODES };
