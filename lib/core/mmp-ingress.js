'use strict';

/**
 * @module sym/core/mmp-ingress
 * @description Ingress admission policy for the Core Secure listener and the separate Legacy
 * Import route (codex transport ruling: clean separation).
 *
 * THE RULE, and the reason it is not merely tidiness: a first-frame type MUST NOT choose security
 * policy. Before authentication that discriminator is attacker-controlled, so a listener that
 * accepted either a v2 `client-hello` or an unauthenticated legacy `handshake` would let a peer
 * pick the weaker path by simply sending the older frame — re-opening nodeId claiming and
 * downgrading around the authenticated §5.2 flow. Worse, the legacy nodeId used to authorize
 * Legacy Import is itself unproven at that moment, and the sticky floor cannot protect an identity
 * that has never been verified.
 *
 * So:
 *   - The Core Secure listener accepts `client-hello` and NOTHING else, and stays closed to
 *     non-handshake frames until a valid `client-finish`.
 *   - Legacy Import is a DISTINCT listener/adapter, selected by operator configuration before any
 *     peer-controlled byte is interpreted, and every route is pinned to an operator-configured
 *     endpoint + expected nodeId (and identity fingerprint where available).
 *   - A Legacy Import session is permanently labelled non-Core-Secure. It is never promoted, and a
 *     v2 negotiation failure never retries into it.
 *   - Once a verified nodeId has negotiated v2, its legacy route is disabled by the sticky floor
 *     until an explicit operator reset.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const CORE_SECURE_FIRST_FRAME = 'client-hello';

/**
 * Core Secure ingress: the ONLY admissible first frame is a v2 client-hello. Anything else — a
 * legacy `handshake`, a `cmb`, a `cmb-encrypted` arriving before the handshake completes — is
 * refused. Throws; the caller closes the connection.
 */
function admitCoreSecureFirstFrame(frame) {
  const type = frame && frame.type;
  if (type !== CORE_SECURE_FIRST_FRAME) {
    throw new Error(`mmp-ingress: Core Secure listener accepts only ${CORE_SECURE_FIRST_FRAME}; refusing first frame '${type}'`);
  }
  return true;
}

/**
 * Core Secure gating after the hello: until the handshake is confirmed by a valid client-finish,
 * no data frame may be processed. Fail-closed — an unconfirmed session carries nothing.
 */
function admitCoreSecureFrame(frame, session) {
  const type = frame && frame.type;
  if (type === 'client-hello' || type === 'server-hello' || type === 'client-finish') return true;
  if (!session || !session.confirmed) {
    throw new Error(`mmp-ingress: refusing '${type}' before the §5.2 handshake is confirmed`);
  }
  if (type === 'cmb') {
    // A Core Secure session that negotiated cmb-encrypted-v2 is v2-ONLY: a cleartext record frame
    // on it is a downgrade attempt, not a compatibility case.
    throw new Error("mmp-ingress: refusing legacy 'cmb' frame on a Core Secure session — v2-only");
  }
  return true;
}

/**
 * Legacy Import route resolution. The route must be named by operator configuration BEFORE any
 * peer bytes are interpreted: an entry pins the endpoint and the expected nodeId (optionally an
 * identity fingerprint). A connection that does not match a configured route is refused — there is
 * no ambient legacy ingress.
 *
 * @param {object} o
 * @param {string} o.endpoint   - the operator-pinned endpoint this connection arrived on.
 * @param {string} o.peerNodeId - the nodeId the peer claims (unproven — matched, never trusted).
 * @param {string} [o.identityFingerprint]
 * @param {Array}  o.routes     - [{ endpoint, nodeId, identityFingerprint? }]
 * @param {object} [o.stickyFloor] - StickyFloor; a nodeId that has spoken v2 has no legacy route.
 * @returns {{ transport: 'legacy', coreSecure: false, route: object }}
 */
function admitLegacyImport({ endpoint, peerNodeId, identityFingerprint, routes, stickyFloor }) {
  const configured = Array.isArray(routes) ? routes : [];
  if (configured.length === 0) {
    throw new Error('mmp-ingress: Legacy Import is not configured — refusing legacy ingress');
  }
  if (stickyFloor && stickyFloor.hasFloor(peerNodeId)) {
    throw new Error(`mmp-ingress: ${peerNodeId} has negotiated cmb-encrypted-v2; its legacy route is disabled until operator reset`);
  }
  const route = configured.find((r) => r.endpoint === endpoint && r.nodeId === peerNodeId);
  if (!route) {
    throw new Error('mmp-ingress: no configured Legacy Import route for this endpoint + nodeId — refusing');
  }
  if (route.identityFingerprint && identityFingerprint && route.identityFingerprint !== identityFingerprint) {
    throw new Error('mmp-ingress: Legacy Import identity fingerprint mismatch — refusing');
  }
  return { transport: 'legacy', coreSecure: false, route };
}

/**
 * A v2 negotiation failure MUST NOT retry into Legacy Import. Falling back on failure is exactly
 * the downgrade an active attacker induces by breaking the v2 handshake.
 */
function refuseFallbackAfterV2Failure(reason) {
  throw new Error(`mmp-ingress: v2 negotiation failed (${reason}); refusing — a v2 failure never falls back to legacy`);
}

/** A Legacy Import session can never be promoted into Core Secure state. */
function assertNoPromotion(sessionPosture) {
  if (sessionPosture && sessionPosture.transport === 'legacy' && sessionPosture.coreSecure) {
    throw new Error('mmp-ingress: a Legacy Import session cannot be promoted to Core Secure');
  }
  return true;
}

module.exports = {
  CORE_SECURE_FIRST_FRAME,
  admitCoreSecureFirstFrame,
  admitCoreSecureFrame,
  admitLegacyImport,
  refuseFallbackAfterV2Failure,
  assertNoPromotion,
};
