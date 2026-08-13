'use strict';

/**
 * @module sym/core/mmp-session
 * @description An MMP v2.0 Core Secure session: the directional traffic keys, the session id, and
 * the per-direction sequence discipline that the cmb-encrypted transport rides on.
 *
 * A session becomes usable ONLY after the authenticated §5.2 exchange — the listener rejects any
 * non-handshake frame before it has validated the client's finish, and both sides confirm the key
 * schedule. This module models the session AFTER that point: it holds the two named directional
 * traffic keys and enforces, per direction, that sequences start at 0 and advance by exactly one
 * — replay, rollback and gaps are refused, never silently tolerated. A new authenticated
 * connection derives a new transcript, hence a new sessionId and fresh counters.
 *
 * Roles are the transport roles codex fixed: `client` is the TCP/WS DIALLER, `server` the
 * LISTENER. The dialler sends `client-to-server` (under clientToServerKey) and receives
 * `server-to-client`; the listener is the mirror. The session never picks a key by anything on the
 * wire — direction is a property of who you are, so a frame cannot ask to be decrypted with the
 * wrong key.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const { deriveSessionKeys, sessionIdFromTranscript, keyConfirmation } = require('./handshake-v2');

const C2S = 'client-to-server';
const S2C = 'server-to-client';

class MmpSession {
  /**
   * @param {'client'|'server'} role
   * @param {Buffer} sharedSecret     - the X25519 shared secret.
   * @param {Buffer} transcriptBytes  - the canonical §5.2 transcript both sides hashed.
   */
  constructor(role, sharedSecret, transcriptBytes) {
    if (role !== 'client' && role !== 'server') throw new Error('mmp-session: role must be client|server');
    const keys = deriveSessionKeys(sharedSecret, require('./handshake-v2').transcriptHash(transcriptBytes));
    this.role = role;
    this.sessionId = sessionIdFromTranscript(transcriptBytes);
    this._c2sKey = keys.clientToServerKey;
    this._s2cKey = keys.serverToClientKey;
    this._clientFinishedKey = keys.clientFinishedKey;
    this._serverFinishedKey = keys.serverFinishedKey;
    this._transcriptBytes = transcriptBytes;

    // Direction is fixed by role, and so is which key seals which way.
    this._sendDirection = role === 'client' ? C2S : S2C;
    this._recvDirection = role === 'client' ? S2C : C2S;
    this._sendKey = role === 'client' ? this._c2sKey : this._s2cKey;
    this._recvKey = role === 'client' ? this._s2cKey : this._c2sKey;

    // Per-direction counters. Both start at 0; the wire carries them as canonical decimal strings.
    this._nextSend = 0n;
    this._nextRecv = 0n;

    // A session is not usable until key confirmation has been verified (§5.2). Frames MUST NOT flow
    // before this — fail closed.
    this._confirmed = false;
  }

  /** The confirmation this side sends: HMAC over the transcript under this role's finished key. */
  ownKeyConfirmation() {
    const key = this.role === 'client' ? this._clientFinishedKey : this._serverFinishedKey;
    const { transcriptHash } = require('./handshake-v2');
    return keyConfirmation(this.role, key, transcriptHash(this._transcriptBytes));
  }

  /**
   * Verify the PEER's key confirmation and open the session. Constant-time compare; on success the
   * session may carry frames. Returns true iff confirmed — a false result MUST keep the session
   * closed.
   */
  confirmPeer(peerConfirmation) {
    const crypto = require('crypto');
    const peerRole = this.role === 'client' ? 'server' : 'client';
    const key = peerRole === 'client' ? this._clientFinishedKey : this._serverFinishedKey;
    const { transcriptHash } = require('./handshake-v2');
    const expected = keyConfirmation(peerRole, key, transcriptHash(this._transcriptBytes));
    const got = Buffer.isBuffer(peerConfirmation) ? peerConfirmation : Buffer.from(peerConfirmation ?? '', 'hex');
    if (got.length !== expected.length || !crypto.timingSafeEqual(got, expected)) return false;
    this._confirmed = true;
    return true;
  }

  get confirmed() { return this._confirmed; }

  /**
   * The next outbound position. Returns the sequence (decimal string), the send direction, and the
   * directional traffic key, then advances the send counter. Throws if the session is not yet
   * confirmed — a frame must never be emitted on an unconfirmed session.
   */
  nextSend() {
    if (!this._confirmed) throw new Error('mmp-session: cannot send on an unconfirmed session');
    const sequence = this._nextSend.toString(10);
    this._nextSend += 1n;
    return { sequence, direction: this._sendDirection, trafficKey: this._sendKey };
  }

  /**
   * Admit an inbound frame's position. The sequence MUST be exactly the next expected for the
   * receive direction — a replay (already consumed), a rollback (below the expected), or a gap
   * (above the expected) is refused. On success returns the recv direction and directional key and
   * advances the receive counter; the caller then opens the frame with that key.
   *
   * @param {string} sequence  - the frame's canonical decimal sequence.
   * @param {string} direction - the frame's declared direction; MUST equal this session's recv direction.
   */
  acceptRecv(sequence, direction) {
    if (!this._confirmed) throw new Error('mmp-session: cannot receive on an unconfirmed session');
    if (direction !== this._recvDirection) {
      throw new Error(`mmp-session: frame direction ${direction} is not this session's receive direction ${this._recvDirection}`);
    }
    if (!/^(0|[1-9][0-9]*)$/.test(String(sequence))) throw new Error('mmp-session: sequence must be a canonical decimal string');
    const seq = BigInt(sequence);
    if (seq < this._nextRecv) throw new Error(`mmp-session: replay/rollback — sequence ${sequence} already past ${this._nextRecv}`);
    if (seq > this._nextRecv) throw new Error(`mmp-session: gap — expected ${this._nextRecv}, got ${sequence}`);
    this._nextRecv += 1n;
    return { direction: this._recvDirection, trafficKey: this._recvKey };
  }
}

module.exports = { MmpSession, C2S, S2C };
