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
 * Decide the selected extensions from both authenticated offers: their intersection (§16.1 "the
 * server selects their intersection", as the published handshake vector selects), in bytewise
 * order. cmb-encrypted-v2 is therefore selected whenever both offer it (mandatory). This is what the
 * SERVER computes; the client verifies it with assertNoDowngrade below. (Until sym 0.14 this
 * selected cmb-encrypted-v2 alone, so no other extension could ever be active on a session.)
 * @returns {{ selected: string[], v2: boolean }}
 */
function selectExtensions(clientOffers, serverOffers) {
  const c = new Set(Array.isArray(clientOffers) ? clientOffers.map(String) : []);
  const s = Array.isArray(serverOffers) ? [...new Set(serverOffers.map(String))] : [];
  const selected = s.filter((e) => c.has(e))
    .sort((a, b) => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8')));
  return { selected, v2: selected.includes(EXT_CMB_ENCRYPTED_V2) };
}

/**
 * Extensions whose removal from a selection is a DOWNGRADE ATTACK rather than a negotiation.
 *
 * THIS REGISTRY EXISTS BECAUSE THE CHECK BELOW READ AS GENERIC AND WAS NOT. `assertNoDowngrade`
 * is named for a property and tested for one — it compared exactly `cmb-encrypted-v2` and nothing
 * else, so any extension added later would have received NO protection while appearing to be
 * covered by a function whose name promises it. Found 2026-09-17 while pricing whether a
 * proof-of-possession extension could safely be negotiated: the honest answer was that the
 * existing protection would not have covered it, which is the opposite of what I had reported.
 *
 * Behaviour is UNCHANGED today: cmb-encrypted-v2 is the only member, so every existing peer
 * negotiates exactly as before. What changes is that the next extension has to make a decision —
 * add it here, or state why stripping it is survivable.
 */
const DOWNGRADE_CRITICAL = Object.freeze([EXT_CMB_ENCRYPTED_V2]);

/**
 * Verify a received selection is not a downgrade. For every downgrade-critical extension that
 * BOTH authenticated offers contained, omission from selectedExtensions means the handshake MUST
 * abort. Throws on downgrade.
 */
function assertNoDowngrade(clientOffers, serverOffers, selectedExtensions) {
  const c = new Set(clientOffers || []);
  const srv = new Set(serverOffers || []);
  const sel = new Set(selectedExtensions || []);
  // The server selects from what both offered, and nothing else (§16.3; review): a selection outside
  // the offers' intersection, or one that names an extension twice, is refused.
  if (sel.size !== (selectedExtensions || []).length) throw new Error('mmp-extensions: the selection names an extension twice; aborting');
  for (const ext of sel) {
    if (!c.has(ext) || !srv.has(ext)) throw new Error(`mmp-extensions: ${String(ext).slice(0, 40)} was selected but not offered by both peers; aborting`);
  }
  for (const ext of DOWNGRADE_CRITICAL) {
    if (c.has(ext) && srv.has(ext) && !sel.has(ext)) {
      throw new Error(`mmp-extensions: downgrade — both peers offered ${ext} but it was not selected; aborting`);
    }
  }
  return { v2: sel.has(EXT_CMB_ENCRYPTED_V2) };
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
  DOWNGRADE_CRITICAL,
  EXT_CMB_ENCRYPTED_V2,
  selectExtensions,
  assertNoDowngrade,
  connectionPosture,
  StickyFloor,
};
