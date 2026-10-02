'use strict';

/**
 * @module sym/core/sealed-control
 * @description The sealed control frame, `control-encrypted` (sym 0.14, design D1; drafted for the
 * MMP spec as §7.1/§18.2.1 "sealed control frames", design §10 PR 7).
 *
 * MMP v2.0 binds only CMBs to the session: `cmb-encrypted` seals a record under the session's
 * directional key, and every other frame travels in the clear. Over a relay that leaves control
 * frames injectable by anyone who can address the relay envelope (design §9: "Only CMBs are bound
 * to the session"). A Core Secure session in sym therefore carries EVERY post-handshake frame except
 * `ping`, `pong` and `error` inside this envelope: `mood` (cognitive content, §9.3), `peer-info` and
 * `wake-channel` (so what is learned from a session is learned from the node that proved itself on
 * it), the signed gossip frames, `cmb-fetch` and `cmb-fetch-result` (its correlation id and key
 * lists; the fetched records themselves travel as `cmb-encrypted`), and the room-join grant.
 *
 * Wire shape (the `cmb-encrypted` envelope without the record metadata):
 *
 *   { type: 'control-encrypted', protocolVersion: '2.0', suite, sessionId, sequence, direction, sealed }
 *
 * The plaintext is the inner frame's JSON. It shares the session's ONE per-direction sequence with
 * `cmb-encrypted`, so a nonce never repeats under a traffic key, and ordering covers both kinds. The
 * AAD binds the domain, version, session, direction and sequence:
 *
 *   AAD = UTF8("mmp-aead-control-v2\n") || lp("2.0") || lp(sessionId) || lp(direction) || lp(sequence)
 *
 * The distinct domain means a sealed control frame can never be opened as a record and vice versa.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const { lp } = require('./cmb-encoder');
const { sealV2, openV2 } = require('./e2e-v2');
const { nonceForSequence, SUITE, PROTOCOL_VERSION } = require('./cmb-encrypted-frame');

const FRAME_TYPE = 'control-encrypted';
const AAD_DOMAIN = 'mmp-aead-control-v2\n';
const DIRECTIONS = new Set(['client-to-server', 'server-to-client']);

/** The frame types a sealed control frame may carry. Records, handshakes and envelopes never. */
const NEVER_INNER = new Set(['cmb', 'cmb-encrypted', 'control-encrypted', 'client-hello', 'server-hello', 'client-finish', 'handshake', 'state-sync']);

function controlAAD({ sessionId, direction, sequence }) {
  return Buffer.concat([
    Buffer.from(AAD_DOMAIN, 'utf8'),
    lp(PROTOCOL_VERSION),
    lp(String(sessionId)),
    lp(String(direction)),
    lp(String(sequence)),
  ]);
}

const b64urlUnpadded = (buf) => Buffer.from(buf).toString('base64url').replace(/=+$/, '');

/**
 * Seal one control frame at a session position.
 * @returns {object} the wire frame
 */
function buildControlFrame({ frame, sessionId, direction, sequence, trafficKey }) {
  if (!frame || typeof frame.type !== 'string' || NEVER_INNER.has(frame.type)) throw new Error(`control-encrypted: refusing to seal a '${frame && frame.type}' frame`);
  if (!/^[0-9a-f]{32}$/.test(sessionId || '')) throw new Error('control-encrypted: sessionId must be 32 lowercase hex');
  if (!DIRECTIONS.has(direction)) throw new Error('control-encrypted: bad direction');
  if (!/^(0|[1-9][0-9]*)$/.test(String(sequence))) throw new Error('control-encrypted: bad sequence');
  const sealed = sealV2(trafficKey, nonceForSequence(sequence), controlAAD({ sessionId, direction, sequence }), Buffer.from(JSON.stringify(frame), 'utf8'));
  return { type: FRAME_TYPE, protocolVersion: PROTOCOL_VERSION, suite: SUITE, sessionId, sequence: String(sequence), direction, sealed: b64urlUnpadded(sealed) };
}

/** Whether a wire frame is shaped as a sealed control frame (nothing about its authenticity). */
function isControlFrame(f) {
  return !!f && f.type === FRAME_TYPE && f.protocolVersion === PROTOCOL_VERSION && f.suite === SUITE
    && typeof f.sessionId === 'string' && DIRECTIONS.has(f.direction)
    && /^(0|[1-9][0-9]*)$/.test(String(f.sequence)) && typeof f.sealed === 'string' && /^[A-Za-z0-9_-]+$/.test(f.sealed);
}

/**
 * Open a sealed control frame. Throws on any AEAD failure or a malformed inner frame.
 * @returns {object} the inner frame
 */
function openControlFrame({ frame, trafficKey }) {
  if (!isControlFrame(frame)) throw new Error('control-encrypted: malformed frame');
  const plain = openV2(trafficKey, nonceForSequence(frame.sequence), controlAAD(frame), Buffer.from(frame.sealed, 'base64url'));
  const inner = JSON.parse(plain.toString('utf8'));
  if (!inner || typeof inner !== 'object' || Array.isArray(inner) || typeof inner.type !== 'string' || NEVER_INNER.has(inner.type)) {
    throw new Error('control-encrypted: the sealed frame is not a control frame');
  }
  return inner;
}

module.exports = { FRAME_TYPE, AAD_DOMAIN, controlAAD, buildControlFrame, openControlFrame, isControlFrame, NEVER_INNER };
