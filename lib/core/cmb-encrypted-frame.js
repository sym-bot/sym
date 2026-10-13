'use strict';

/**
 * @module sym/core/cmb-encrypted-frame
 * @description The MMP v2.0 `cmb-encrypted` transport envelope (Core Secure §18.2), byte-exact
 * with meshcognition.org/spec/mmp/schema/encrypted-cmb-frame.schema.json and the published
 * e2e-v2.json vector.
 *
 * The relay carries ONLY this frame for peer content: clear routing/verification metadata (the
 * signed §7 metadata section, with the application section reduced to its descriptor — never its
 * data) plus a sealed blob. The sealed blob is the protected plaintext
 * `{"categories":…,"applicationData":…}` under ChaCha20-Poly1305, AEAD-bound to the session,
 * direction, sequence and the record's own routing identity. A router cannot read it; a relay
 * cannot move a valid ciphertext to another record, direction or position.
 *
 * This module is the codec only: it builds and opens one frame. Session establishment (§5.2
 * handshake → sessionId + directional traffic keys) and per-direction sequence enforcement live in
 * the session layer that drives it.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const { aeadAADv2, sealV2, openV2 } = require('./e2e-v2');
const { MAX_FRAME_DEPTH, nestedTooDeep } = require('./json-depth');

const FRAME_TYPE = 'cmb-encrypted';
const PROTOCOL_VERSION = '2.0';
const SUITE = 'X25519-HKDF-SHA256-ChaCha20-Poly1305';
const DIRECTIONS = new Set(['client-to-server', 'server-to-client']);

const b64urlUnpadded = (buf) => Buffer.from(buf).toString('base64url').replace(/=+$/, '');

/** The 96-bit big-endian nonce for a sequence — the canonical decimal string is the counter. */
/** A canonical decimal sequence of at most 29 digits (2^96 − 1 has 29); the nonce bounds it exactly. */
const SEQUENCE = /^(0|[1-9][0-9]{0,28})$/;
/** The longest sealed value a MAX_RECORD_BYTES plaintext can produce (§8.8.6): 983,062 characters. */
const { MAX_SEALED_CHARS } = require('./cmb-encoder');

function nonceForSequence(sequence) {
  const n = BigInt(sequence);
  if (n < 0n || n > 0xffffffffffffffffffffffffn) throw new Error('cmb-encrypted: sequence out of 96-bit range');
  const hex = n.toString(16).padStart(24, '0');
  return Buffer.from(hex, 'hex');
}

/**
 * The protected plaintext bytes. `categories` is the CAT7 section; when the record carries an
 * application section, its RAW bytes are sealed here as unpadded base64url under
 * `applicationData`. Key order (categories, then applicationData) is the vector's order and is
 * load-bearing for byte-exactness.
 *
 * NOTE (open wire detail, pending codex confirmation): the no-application shape — whether
 * `applicationData` is OMITTED (as here), null, or empty — is not yet fixed by a vector. sym
 * records are predominantly application-null, so this must be confirmed before the flip. Guarded:
 * pass applicationBytes to seal an application; omit for the null case.
 */
function protectedPlaintext(categories, applicationBytes) {
  const obj = { categories };
  if (applicationBytes != null) obj.applicationData = b64urlUnpadded(applicationBytes);
  return Buffer.from(JSON.stringify(obj), 'utf8');
}

/** The clear metadata object the schema requires — the signed §7 metadata, application as descriptor. */
function clearMetadata(metadata) {
  // Pass the signed metadata through unchanged: it already carries application as a descriptor
  // (or null) for a v2.0-emitted record. The signature covers it; the AEAD AAD binds the subset
  // that identifies the record. We never place application DATA here.
  return metadata;
}

/**
 * Build a `cmb-encrypted` frame from a v2.0 record and a session position.
 * @param {object} o
 * @param {object} o.cmb            - the v2.0 record ({ categories, metadata }).
 * @param {Buffer} [o.applicationBytes] - raw application section bytes, if any.
 * @param {string} o.sessionId      - 32 lowercase hex.
 * @param {'client-to-server'|'server-to-client'} o.direction
 * @param {string} o.sequence       - canonical decimal string.
 * @param {Buffer} o.trafficKey     - the 32-byte directional traffic key.
 * @returns {object} the wire frame (schema-shaped).
 */
function buildEncryptedFrame({ cmb, applicationBytes = null, sessionId, direction, sequence, trafficKey }) {
  if (!cmb || !cmb.metadata || !cmb.categories) throw new Error('cmb-encrypted: record must have categories and metadata');
  if (!/^[0-9a-f]{32}$/.test(sessionId || '')) throw new Error('cmb-encrypted: sessionId must be 32 lowercase hex');
  if (!DIRECTIONS.has(direction)) throw new Error('cmb-encrypted: direction must be client-to-server|server-to-client');
  if (!SEQUENCE.test(String(sequence))) throw new Error('cmb-encrypted: sequence must be a canonical decimal string below 2^96');

  const m = cmb.metadata;
  const aad = aeadAADv2({
    protocolVersion: PROTOCOL_VERSION, sessionId, direction, sequence: String(sequence),
    key: m.key, assertionId: m.assertionId, createdByNodeId: m.createdByNodeId, room: m.room, to: m.to,
  });
  const nonce = nonceForSequence(sequence);
  const sealed = sealV2(trafficKey, nonce, aad, protectedPlaintext(cmb.categories, applicationBytes));

  return {
    type: FRAME_TYPE,
    protocolVersion: PROTOCOL_VERSION,
    suite: SUITE,
    sessionId,
    sequence: String(sequence),
    direction,
    metadata: clearMetadata(m),
    sealed: b64urlUnpadded(sealed),
  };
}

/**
 * Authenticate and decrypt a `cmb-encrypted` frame with the directional traffic key: the AEAD alone.
 * Throws on any AEAD failure (a tampered frame, a wrong key, clear metadata altered: the AAD binds
 * key/assertionId/nodeId/room/to). A frame that opens advances the session's receive sequence
 * (MMP §18.2.1), so its plaintext is parsed by `parseEncryptedPlain` only after the position is taken.
 * @returns {Buffer} the plaintext
 */
function openEncryptedSealed({ frame, trafficKey }) {
  if (!frame || frame.type !== FRAME_TYPE) throw new Error('cmb-encrypted: not a cmb-encrypted frame');
  if (frame.protocolVersion !== PROTOCOL_VERSION) throw new Error('cmb-encrypted: unsupported protocolVersion');
  if (frame.suite !== SUITE) throw new Error('cmb-encrypted: unsupported suite');
  if (!DIRECTIONS.has(frame.direction)) throw new Error('cmb-encrypted: bad direction');
  // encrypted-cmb-frame.schema.json (MMP 2.0 update 1): a 32-hex sessionId, a sequence of at most 29
  // digits (the nonce bounds it exactly), a sealed value at least the 16-byte tag and at most what a
  // MAX_RECORD_BYTES plaintext produces.
  if (typeof frame.sessionId !== 'string' || !/^[0-9a-f]{32}$/.test(frame.sessionId)) throw new Error('cmb-encrypted: bad sessionId');
  if (typeof frame.sequence !== 'string' || !SEQUENCE.test(frame.sequence)) throw new Error('cmb-encrypted: bad sequence');
  if (typeof frame.sealed !== 'string' || frame.sealed.length < 22 || frame.sealed.length > MAX_SEALED_CHARS || !/^[A-Za-z0-9_-]+$/.test(frame.sealed)) throw new Error('cmb-encrypted: bad sealed value');
  const m = frame.metadata;
  if (!m || typeof m !== 'object') throw new Error('cmb-encrypted: missing metadata');
  const aad = aeadAADv2({
    protocolVersion: PROTOCOL_VERSION, sessionId: frame.sessionId, direction: frame.direction, sequence: String(frame.sequence),
    key: m.key, assertionId: m.assertionId, createdByNodeId: m.createdByNodeId, room: m.room, to: m.to,
  });
  return openV2(trafficKey, nonceForSequence(frame.sequence), aad, Buffer.from(frame.sealed, 'base64url'));
}

/**
 * The logical record of an opened `cmb-encrypted` frame. Throws when the plaintext is not one (not
 * JSON, too deep): the record is refused, and nothing else about the session changes. The caller
 * then runs §8.8.5's verification order.
 * @returns {{ cmb: object, applicationBytes: Buffer|null, sequence: string, direction: string }}
 */
function parseEncryptedPlain(frame, plaintext) {
  const text = Buffer.from(plaintext).toString('utf8');
  // The peer wrote this JSON as surely as a cleartext frame, so it meets the same nesting bound.
  if (nestedTooDeep(text)) throw new Error(`cmb-encrypted: plaintext nests deeper than ${MAX_FRAME_DEPTH} levels`);
  const parsed = JSON.parse(text);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('cmb-encrypted: the plaintext is not an object');
  const applicationBytes = (typeof parsed.applicationData === 'string')
    ? Buffer.from(parsed.applicationData, 'base64url') : null;
  return {
    cmb: { categories: parsed.categories, metadata: frame.metadata },
    applicationBytes,
    sequence: String(frame.sequence),
    direction: frame.direction,
  };
}

/** Open and parse in one step (tests, tools). A session opens first and parses after the position. */
function openEncryptedFrame({ frame, trafficKey }) {
  return parseEncryptedPlain(frame, openEncryptedSealed({ frame, trafficKey }));
}

module.exports = {
  FRAME_TYPE, PROTOCOL_VERSION, SUITE,
  nonceForSequence, protectedPlaintext, buildEncryptedFrame, openEncryptedFrame, openEncryptedSealed, parseEncryptedPlain,
};
