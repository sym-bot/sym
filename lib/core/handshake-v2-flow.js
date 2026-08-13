'use strict';

/**
 * @module sym/core/handshake-v2-flow
 * @description The MMP v2.0 §5.2 authenticated handshake state machine: client-hello →
 * server-hello → client-finish, producing an established MmpSession.
 *
 * Transport-free by design. It consumes and produces frame OBJECTS and takes the X25519 agreement
 * as an injected function, so the whole exchange — including every abort path — is testable
 * without a socket. `emit.js` and `node.js` drive it over their respective transports.
 *
 * What this closes (audit P0.3): the legacy handshake trusted the first frame's nodeId and keys
 * with no proof, so an active peer or relay could claim an unused nodeId with its own keys, or
 * substitute the X25519 key and become the endpoint for "encrypted" data. Here each side signs the
 * canonical transcript with its Ed25519 identity key and confirms the derived key schedule; a
 * handshake whose proof or confirmation does not verify is ABORTED before any key is pinned and
 * before any frame flows.
 *
 * Downgrade resistance (codex Option C): the offered and selected extensions are inside the signed
 * transcript, so stripping `cmb-encrypted-v2` changes the transcript hash and invalidates the
 * proofs. A selection that omits it when both sides offered it is refused outright.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const crypto = require('crypto');
const {
  buildTranscript, transcriptHash, signProof, verifyProof, deriveSessionKeys, keyConfirmation,
} = require('./handshake-v2');
const { selectExtensions, assertNoDowngrade } = require('./mmp-extensions');
const { MmpSession } = require('./mmp-session');

const PROTOCOL_VERSION = '2.0';

/** A fresh 32-byte handshake nonce, base64url — the shape the vector frames carry. */
function newNonce() { return crypto.randomBytes(32).toString('base64url'); }

const b64 = (buf) => Buffer.from(buf).toString('base64url');

/** The party block the transcript needs, from a hello frame. */
function partyFromHello(hello) {
  return {
    nonce: hello.nonce,
    nodeId: hello.nodeId,
    identityPublicKey: hello.identityPublicKey,
    e2ePublicKey: hello.e2ePublicKey,
    name: hello.name,
    implementation: hello.implementation,
    extensions: hello.extensions || [],
  };
}

/**
 * Build the client-hello frame. `self` is this node's identity/keys/capabilities.
 * @returns {{ frame: object, nonce: string }}
 */
function clientHello({ room, nodeId, name, identityPublicKey, e2ePublicKey, implementation, extensions, nonce }) {
  const n = nonce || newNonce();
  return {
    frame: {
      type: 'client-hello',
      protocolVersion: PROTOCOL_VERSION,
      room, nodeId, name, identityPublicKey, e2ePublicKey,
      nonce: n,
      implementation,
      extensions: [...(extensions || [])],
    },
    nonce: n,
  };
}

/**
 * SERVER: consume a client-hello, select extensions, and produce the server-hello carrying this
 * side's proof and key confirmation. The server can compute the full transcript here because the
 * client-hello supplies everything the client contributes.
 *
 * @param {object} o.clientHelloFrame
 * @param {object} o.self  - { room, nodeId, name, identityPublicKey, e2ePublicKey, implementation, extensions, identityPrivateKey }
 * @param {(peerE2EPublicKey: string) => Buffer} o.agree - X25519 agreement against this node's E2E private key.
 * @returns {{ frame: object, session: MmpSession, transcript: Buffer, selected: string[] }}
 */
function serverAccept({ clientHelloFrame, self, agree, nonce }) {
  if (!clientHelloFrame || clientHelloFrame.type !== 'client-hello') throw new Error('handshake: expected client-hello');
  if (clientHelloFrame.protocolVersion !== PROTOCOL_VERSION) throw new Error('handshake: unsupported protocolVersion');
  if (clientHelloFrame.room !== self.room) throw new Error('handshake: room mismatch');

  const serverNonce = nonce || newNonce();
  const { selected } = selectExtensions(clientHelloFrame.extensions, self.extensions);

  const client = partyFromHello(clientHelloFrame);
  const server = partyFromHello({ ...self, nonce: serverNonce });
  const transcript = buildTranscript({
    protocolVersion: PROTOCOL_VERSION, room: self.room, client, server, selectedExtensions: selected,
  });
  const th = transcriptHash(transcript);
  const sharedSecret = agree(clientHelloFrame.e2ePublicKey);
  const keys = deriveSessionKeys(sharedSecret, th);

  const session = new MmpSession('server', sharedSecret, transcript);

  return {
    frame: {
      type: 'server-hello',
      protocolVersion: PROTOCOL_VERSION,
      room: self.room,
      nodeId: self.nodeId,
      name: self.name,
      identityPublicKey: self.identityPublicKey,
      e2ePublicKey: self.e2ePublicKey,
      nonce: serverNonce,
      implementation: self.implementation,
      extensions: [...(self.extensions || [])],
      clientNonce: clientHelloFrame.nonce,
      selectedExtensions: selected,
      proof: signProof('server', transcript, self.identityPrivateKey),
      keyConfirmation: b64(keyConfirmation('server', keys.serverFinishedKey, th)),
    },
    session, transcript, selected,
  };
}

/**
 * CLIENT: consume the server-hello. Verifies the server proved possession of the identity key it
 * presented, that the key schedules agree (key confirmation), and that the selection is not a
 * downgrade. Only then is a session established and the client-finish produced.
 *
 * FAIL CLOSED at every step: a bad proof, a bad confirmation, a replayed nonce, or a stripped
 * capability aborts here — before any key is pinned and before any frame flows.
 *
 * @returns {{ frame: object, session: MmpSession, transcript: Buffer, selected: string[] }}
 */
function clientFinish({ serverHelloFrame, clientHelloFrame, self, agree }) {
  const s = serverHelloFrame;
  if (!s || s.type !== 'server-hello') throw new Error('handshake: expected server-hello');
  if (s.protocolVersion !== PROTOCOL_VERSION) throw new Error('handshake: unsupported protocolVersion');
  if (s.room !== clientHelloFrame.room) throw new Error('handshake: room mismatch');
  // The server MUST echo our nonce — binds this response to this request (anti-replay).
  if (s.clientNonce !== clientHelloFrame.nonce) throw new Error('handshake: server did not echo our nonce');

  // Downgrade check BEFORE trusting anything else about the selection.
  assertNoDowngrade(clientHelloFrame.extensions, s.extensions, s.selectedExtensions);

  const client = partyFromHello(clientHelloFrame);
  const server = partyFromHello(s);
  const transcript = buildTranscript({
    protocolVersion: PROTOCOL_VERSION, room: clientHelloFrame.room, client, server,
    selectedExtensions: s.selectedExtensions || [],
  });
  const th = transcriptHash(transcript);

  // Proof of possession, against the key the server PRESENTED IN THIS TRANSCRIPT.
  if (!verifyProof('server', transcript, s.proof, s.identityPublicKey)) {
    throw new Error('handshake: server proof did not verify — aborting before any key is pinned');
  }

  const sharedSecret = agree(s.e2ePublicKey);
  const keys = deriveSessionKeys(sharedSecret, th);

  // Key confirmation: both sides derived the same schedule, or there is a MITM / divergent transcript.
  const expected = keyConfirmation('server', keys.serverFinishedKey, th);
  const got = Buffer.from(s.keyConfirmation || '', 'base64url');
  if (got.length !== expected.length || !crypto.timingSafeEqual(got, expected)) {
    throw new Error('handshake: server key confirmation mismatch — aborting');
  }

  const session = new MmpSession('client', sharedSecret, transcript);
  session.confirmPeer(keyConfirmation('server', keys.serverFinishedKey, th));

  return {
    frame: {
      type: 'client-finish',
      transcriptHash: th.toString('hex'),
      proof: signProof('client', transcript, self.identityPrivateKey),
      keyConfirmation: b64(keyConfirmation('client', keys.clientFinishedKey, th)),
    },
    session, transcript, selected: s.selectedExtensions || [],
  };
}

/**
 * SERVER: consume the client-finish and open the session. Until this returns true the listener
 * MUST NOT accept any non-handshake frame (codex ruling). Verifies the client's proof over the same
 * transcript and its key confirmation.
 */
function serverConfirm({ clientFinishFrame, transcript, session, clientIdentityPublicKey, sharedSecret }) {
  const f = clientFinishFrame;
  if (!f || f.type !== 'client-finish') throw new Error('handshake: expected client-finish');
  const th = transcriptHash(transcript);
  if (f.transcriptHash !== th.toString('hex')) {
    throw new Error('handshake: client-finish transcript hash mismatch — divergent transcripts');
  }
  if (!verifyProof('client', transcript, f.proof, clientIdentityPublicKey)) {
    throw new Error('handshake: client proof did not verify — aborting');
  }
  const keys = deriveSessionKeys(sharedSecret, th);
  const expected = keyConfirmation('client', keys.clientFinishedKey, th);
  const got = Buffer.from(f.keyConfirmation || '', 'base64url');
  if (got.length !== expected.length || !crypto.timingSafeEqual(got, expected)) {
    throw new Error('handshake: client key confirmation mismatch — aborting');
  }
  if (!session.confirmPeer(expected)) throw new Error('handshake: session confirmation failed');
  return session;
}

module.exports = { PROTOCOL_VERSION, newNonce, clientHello, serverAccept, clientFinish, serverConfirm };
