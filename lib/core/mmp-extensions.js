'use strict';

/**
 * @module sym/core/mmp-extensions
 * @description MMP v2.0 §5.2 extension negotiation for the Core Secure sealed-envelope migration.
 *
 * The `cmb-encrypted-v2` extension is how a peer says "I speak the sealed cmb-encrypted transport".
 * Codex's migration ruling (Option C) makes it downgrade-resistant, not merely a feature flag:
 *
 *   - It rides BOTH the §5.2 offer extensions AND selectedExtensions, all transcript-bound — so a
 *     relay cannot strip it without breaking the authenticated transcript.
 *   - If BOTH authenticated offers contain it, the server MUST select it. A selection that omits it
 *     when both offered is a DOWNGRADE and MUST abort the handshake.
 *   - Once selected, the session is v2-only: no legacy frame may be sent or accepted on it.
 *   - If either peer lacks it, legacy is permitted ONLY under an explicitly configured, named
 *     Legacy Import profile — never an automatic Core Secure fallback — and such a connection
 *     reports non-Core-Secure status.
 *   - Sticky floor: once a verified nodeId has negotiated cmb-encrypted-v2, a later handshake for
 *     that identity that lacks or refuses it MUST be rejected until an explicit operator reset. A
 *     peer cannot be walked back down to legacy.
 *
 * This module is the decision logic only — pure functions plus a sticky-floor store. The transcript
 * binding and frame gating are enforced by the handshake and transport layers that call it.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const EXT_CMB_ENCRYPTED_V2 = 'cmb-encrypted-v2';

/**
 * Decide the selected extensions from both authenticated offers. If both offer cmb-encrypted-v2 it
 * is selected (mandatory). This is what the SERVER computes; the client verifies it with
 * assertNoDowngrade below.
 * @returns {{ selected: string[], v2: boolean }}
 */
function selectExtensions(clientOffers, serverOffers) {
  const c = new Set(Array.isArray(clientOffers) ? clientOffers : []);
  const s = new Set(Array.isArray(serverOffers) ? serverOffers : []);
  const v2 = c.has(EXT_CMB_ENCRYPTED_V2) && s.has(EXT_CMB_ENCRYPTED_V2);
  const selected = v2 ? [EXT_CMB_ENCRYPTED_V2] : [];
  return { selected, v2 };
}

/**
 * Verify a received selection is not a downgrade. If both authenticated offers contained
 * cmb-encrypted-v2 but selectedExtensions omits it, the handshake MUST abort. Throws on downgrade.
 */
function assertNoDowngrade(clientOffers, serverOffers, selectedExtensions) {
  const bothOffered = new Set(clientOffers || []).has(EXT_CMB_ENCRYPTED_V2)
    && new Set(serverOffers || []).has(EXT_CMB_ENCRYPTED_V2);
  const selectedV2 = new Set(selectedExtensions || []).has(EXT_CMB_ENCRYPTED_V2);
  if (bothOffered && !selectedV2) {
    throw new Error('mmp-extensions: downgrade — both peers offered cmb-encrypted-v2 but it was not selected; aborting');
  }
  return { v2: selectedV2 };
}

/**
 * The negotiated security posture for a connection.
 *   - v2 selected           → Core Secure, v2-only.
 *   - not selected, legacy   → allowed ONLY if this exact peer is a configured Legacy Import peer;
 *                              the connection is NON-Core-Secure. Otherwise the connection is refused.
 * @param {object} o
 * @param {boolean} o.v2Selected
 * @param {string} o.peerNodeId
 * @param {object} [o.config] - { legacyImportNodeIds?: string[] } explicitly named legacy peers.
 * @returns {{ transport: 'cmb-encrypted-v2'|'legacy', coreSecure: boolean }}
 */
function connectionPosture({ v2Selected, peerNodeId, config }) {
  if (v2Selected) return { transport: EXT_CMB_ENCRYPTED_V2, coreSecure: true };
  const named = new Set((config && config.legacyImportNodeIds) || []);
  if (named.has(peerNodeId)) return { transport: 'legacy', coreSecure: false };
  throw new Error('mmp-extensions: refusing non-Core-Secure connection — peer did not select cmb-encrypted-v2 and is not a configured Legacy Import peer');
}

/**
 * The sticky floor: once a verified nodeId has spoken cmb-encrypted-v2, it may never be walked back
 * down to legacy for that identity — a stripped or refused capability on a later handshake is a
 * downgrade attack and is rejected until an explicit operator reset.
 */
class StickyFloor {
  constructor() { this._v2Nodes = new Set(); }

  /** Record a successful v2 negotiation for a verified nodeId. */
  recordV2(nodeId) { if (nodeId) this._v2Nodes.add(nodeId); }

  hasFloor(nodeId) { return this._v2Nodes.has(nodeId); }

  /**
   * Enforce the floor for an incoming negotiation. Throws if a nodeId known to speak v2 now lacks
   * it. Call before accepting a legacy/no-v2 posture for a verified identity.
   */
  enforce(nodeId, v2Selected) {
    if (this._v2Nodes.has(nodeId) && !v2Selected) {
      throw new Error(`mmp-extensions: sticky-floor downgrade — ${nodeId} previously negotiated cmb-encrypted-v2; refusing until operator reset`);
    }
  }

  /** Explicit operator reset — the only way to clear a floor. */
  reset(nodeId) { if (nodeId) this._v2Nodes.delete(nodeId); }
}

module.exports = {
  EXT_CMB_ENCRYPTED_V2,
  selectExtensions,
  assertNoDowngrade,
  connectionPosture,
  StickyFloor,
};
