'use strict';

/**
 * @module sym/core/lineage-tether
 * @description MMP §15.8 Lineage Tether — the root-anchored drift bound.
 *
 * Lineage guarantees provenance of descent, not semantic fidelity: a remix hop
 * can land nearly orthogonal to its root while carrying honest lineage, and
 * everything lineage is consumed for (grounded ancestry, source-novel
 * forwarding, Canon protection) silently assumes the descendant is still ABOUT
 * what its ancestors were about. The tether closes that gap at integration
 * time: a remix asserts lineage only where the descent claim would survive its
 * own anchor's scrutiny — evaluated as if against a store holding only the
 * nearest resolvable lineage root, severed (stored as a fresh root) when that
 * evaluation lands in the reject band.
 *
 * The check is CONTENT-ONLY: the temporal term of §9.2 does not apply, because
 * the tether tests fidelity, not freshness — so the floor is the α-weighted
 * per-category drift against the anchor exceeding T_guarded. Checks against the
 * anchor do not compound with depth (unlike per-hop bounds): every surviving
 * chain certifies every depth stays above the floor with respect to its root.
 *
 * A tether that CANNOT be evaluated (no comparable category vectors — e.g. the
 * anchor predates the current encoder, or shares no populated categories) is
 * UNCHECKED, not failed: unverifiable is a trust state, not a rejection,
 * mirroring the verify-if-resolvable posture of the signature layer.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const { cosineSimilarity, CAT7_CATEGORIES } = require('./cmb-encoder');
const { encodeForSVAF, isSemanticReady, kernelId } = require('./context-encoder');

/**
 * Evaluate the §15.8 lineage tether of a remix against its anchor.
 *
 * Pure function. Compares the remix's category vectors against the anchor's,
 * α-weighted over the categories BOTH carry with matching dimensions.
 *
 * @param {object} opts
 * @param {object} opts.remixCategories   - CAT7 categories of the remix ({ text, vector } per category).
 * @param {object} opts.anchorCategories  - CAT7 categories of the resolved anchor CMB.
 * @param {object} [opts.categoryWeights] - Per-category α weights (default 1.0 each).
 * @param {number} [opts.guardedThreshold=0.5] - §9.2 reject floor (T_guarded).
 * @returns {{ checked: boolean, tethered: boolean, drift: number|null, evaluableCategories: string[] }}
 *   checked=false → no comparable categories; tethered stays true (unverified, never severed on ignorance).
 */
function computeLineageTether({ remixCategories, anchorCategories, categoryWeights, guardedThreshold = 0.5 }) {
  const weights = categoryWeights || {};
  let driftSum = 0;
  let weightSum = 0;
  const evaluableCategories = [];

  for (const category of CAT7_CATEGORIES) {
    const r = remixCategories ? remixCategories[category] : null;
    const a = anchorCategories ? anchorCategories[category] : null;
    if (!r || !r.vector || !a || !a.vector) continue;
    if (r.vector.length !== a.vector.length) continue; // mixed encoders — not comparable
    const alphaF = weights[category] || 1.0;
    const drift = 1.0 - cosineSimilarity(r.vector, a.vector);
    driftSum += alphaF * drift;
    weightSum += alphaF;
    evaluableCategories.push(category);
  }

  if (weightSum <= 0) {
    return { checked: false, tethered: true, drift: null, evaluableCategories };
  }
  const drift = driftSum / weightSum;
  return { checked: true, tethered: drift <= guardedThreshold, drift, evaluableCategories };
}

/**
 * Resolve the §15.8 anchor for an incoming CMB: the EARLIEST-STORED lineage
 * ancestor the local store can resolve, falling back to the incoming block
 * itself when none resolves (a root is its own anchor).
 *
 * @param {object} incomingCMB - The incoming CMB (categories + lineage).
 * @param {(key: string) => object|undefined} getEntry - Store lookup: key → stored entry (with .cmb and .storedAt / .cmb.originTimestamp).
 * @returns {{ key: string|null, categories: object|null, resolvedFromStore: boolean }}
 */
function resolveTetherAnchor(incomingCMB, getEntry) {
  // Lineage lives in `metadata` on a §7 record and at the top level on a pre-boundary one.
  // Reading only the flat position returned undefined for EVERY current block, so the loop
  // below ran zero times, `best` stayed null, and the function fell through to "the block is
  // its own anchor" — resolvedFromStore:false. The caller reads that as an unresolvable anchor
  // and records the chain as UNCHECKED, so no tether was ever evaluated and nothing was ever
  // severed. A drift-laundered remix passed the gate untouched, and the report said "unchecked"
  // rather than anything alarming.
  const lin = incomingCMB?.metadata?.lineage ?? incomingCMB?.lineage ?? null;
  // Walk PARENTS. `ancestors` was a transitive closure stapled to every block; §7.5 retires it,
  // so a current record carries parents alone. Legacy blocks that still carry a closure are
  // still honoured — they are the only ones that have one.
  const candidates = [
    ...(Array.isArray(lin?.parents) ? lin.parents : []),
    ...(Array.isArray(lin?.ancestors) ? lin.ancestors : []),
  ];
  const seen = new Set();
  let best = null;
  let bestTime = Infinity;
  for (const key of candidates) {
    if (seen.has(key)) continue;
    seen.add(key);
    const entry = typeof getEntry === 'function' ? getEntry(key) : undefined;
    if (!entry) continue;
    const cmb = entry.cmb || entry;
    if (!cmb || !cmb.categories) continue;
    const t = cmb.originTimestamp ?? entry.storedAt ?? Infinity;
    if (t < bestTime) { bestTime = t; best = { key, categories: cmb.categories, resolvedFromStore: true }; }
  }
  if (best) return best;
  if (incomingCMB && incomingCMB.categories) {
    return { key: incomingCMB.metadata?.key ?? incomingCMB.key ?? null, categories: incomingCMB.categories, resolvedFromStore: false };
  }
  return { key: null, categories: null, resolvedFromStore: false };
}

/**
 * Text-based tether evaluation for RETROACTIVE audit (§15.8 applied to stored
 * chains). Unlike the in-gate evaluation — which compares the freshly fused
 * remix vectors against the re-encoded anchor — an audit holds two stored
 * rows whose persisted vectors may predate the current encoder, so BOTH
 * sides' category texts are re-encoded with the current kernel before the drift
 * check. Returns the §15.8 record shape including the kernelId the verdict
 * was made in.
 *
 * @param {object} opts
 * @param {object} opts.remixCategories  - stored remix CAT7 categories (text used).
 * @param {object} opts.anchorCategories - resolved/fetched anchor CAT7 categories (text used).
 * @param {object} [opts.categoryWeights]
 * @param {number} [opts.guardedThreshold=0.5]
 * @returns {Promise<{checked:boolean, tethered:boolean, drift:number|null,
 *           evaluableCategories:string[], kernelId:string}>}
 */
async function evaluateLineageTetherFromText({ remixCategories, anchorCategories, categoryWeights, guardedThreshold = 0.5 }) {
  async function reencode(categories) {
    const out = {};
    for (const category of CAT7_CATEGORIES) {
      const f = categories ? categories[category] : null;
      if (!f) continue;
      const text = typeof f === 'object' ? (f.text ?? '') : String(f ?? '');
      out[category] = { text };
      if (text) {
        const { h1 } = await encodeForSVAF(text);
        out[category].vector = h1;
      } else if (f && typeof f === 'object' && f.vector) {
        out[category].vector = f.vector;
      }
    }
    return out;
  }
  // With the semantic encoder ready both sides land in one kernel; on the
  // lexical fallback encodeForSVAF is the n-gram encoder, so the property
  // (single kernel per comparison) holds either way.
  const [r, a] = [await reencode(remixCategories), await reencode(anchorCategories)];
  return {
    kernelId: kernelId(),
    ...computeLineageTether({ remixCategories: r, anchorCategories: a, categoryWeights, guardedThreshold }),
  };
}

module.exports = { computeLineageTether, resolveTetherAnchor, evaluateLineageTetherFromText };
