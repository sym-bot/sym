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

const { cosineSimilarity, CAT7_CATEGORIES, blockKeyV2 } = require('./cmb-encoder');
const { encodeForSVAF, kernelId } = require('./context-encoder');
const { keyOf, verifyAddress, VERIFY } = require('./record-shape');

/**
 * Evaluate the §15.8 lineage tether of a remix against its anchor.
 *
 * Pure function. Compares the remix's category vectors against the anchor's,
 * α-weighted over the categories BOTH carry with matching dimensions.
 *
 * @param {object} opts
 * @param {object} opts.remixCategories   - CAT7 categories of the remix ({ text, vector } per category).
 * @param {object} opts.anchorCategories  - CAT7 categories of the resolved anchor CMB.
 * @param {object} [opts.categoryWeights] - Per-category α weights (default 1.0 each; 0 excludes the category).
 * @param {number} [opts.guardedThreshold=0.5] - §9.2 reject floor (T_guarded).
 * @returns {{ checked: boolean, tethered: boolean, drift: number|null, evaluableCategories: string[] }}
 *   checked=false → no comparable weighted categories; tethered stays true (unverified, never severed on ignorance).
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
    // `??`, not `||`: an explicit 0 DISABLES the category (§9.2.1), and `|| 1.0` read it as full
    // weight — so a category the receiver chose not to consult could still sever or keep a chain.
    const alphaF = weights[category] ?? 1.0;
    if (alphaF === 0) continue;
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
 * Does a STORED record verify, so a §15.8 walk may step onto it and follow its parents?
 *
 * §15.2: a verifier validates each parent's content address and signature, and repeats. Both
 * halves are needed here, for different reasons.
 *
 *   Address. The tether compares against the anchor's TEXT, and "any holder of the root re-encodes
 *   its text" only means something if that text is the content the key names. A stored record
 *   whose categories no longer recompute to the key it is held under is not the root it claims to
 *   be, whatever else is true of it.
 *
 *   Authorship. A record is a step only if this node knows who wrote it: either it wrote the
 *   record itself (the store's local entries carry no peerId), or it admitted the record after
 *   verifying the author's signature — the frame handler's verdict, `_cmbVerified`, which the
 *   store persists with the entry. Signature verification needs the author's key, which this pure
 *   module does not hold; the verdict reached when the key WAS at hand is the evidence that exists.
 *   An admission with no verdict, or a false one, proves nothing about who chose its content or
 *   its parents, and walking through it let the author of one unsigned block pick the anchor of
 *   every remix that cites it.
 *
 * A pre-boundary record (no metadata section) carries no v2 attestation and never verifies
 * (§7.8 unverified-legacy). A bare record with no store envelope has no verdict and does not either.
 *
 * @param {object} entry - stored entry ({ cmb, peerId, _cmbVerified, ... }).
 * @param {string} key   - the key the walk looked the entry up under.
 * @returns {boolean}
 */
function storedRecordVerifies(entry, key) {
  if (!entry || typeof entry !== 'object') return false;
  const cmb = entry.cmb;
  if (!cmb || !cmb.metadata) return false;
  if (keyOf(cmb) !== key) return false;
  if (verifyAddress(cmb, blockKeyV2).state !== VERIFY.VERIFIED) return false;
  // `== null`, the store's own test for a locally-written entry (hasLocalKey, compactByOrigin).
  // receiveFromPeer always overwrites peerId, so a peer frame cannot arrive claiming to be local.
  if (entry.peerId == null) return true;
  return entry._cmbVerified === true;
}

/**
 * Resolve the §15.8 anchor for an incoming CMB: the EARLIEST-STORED lineage ancestor reachable
 * through records that verify (storedRecordVerifies).
 *
 * Three outcomes, never collapsed into one another:
 *   - a verified ancestor was reached → it is the anchor (resolvedFromStore: true);
 *   - the incoming block is a ROOT (no parents) → it is its own anchor;
 *   - it is a remix and no verified ancestor is reachable → there is NO anchor: key and categories
 *     are null. The tether is then unverified, which §15.8 makes a trust state, never a severance.
 *     This used to fall back to the remix itself, so the gate measured a remix against its own
 *     text, always found it tethered, and the integrator signed that as a tether to a root.
 *
 * `complete` says whether every edge the walk met resolved to a verified record within bounds.
 * When it is false the anchor (if any) is the oldest VERIFIED record reached, not necessarily the
 * chain's true root — §15.2's incomplete lineage proof, which MUST NOT be presented as complete.
 *
 * @param {object} incomingCMB - The incoming CMB (categories + lineage).
 * @param {(key: string) => object|undefined} getEntry - Store lookup: key → stored entry (with .cmb, .storedAt and the store envelope).
 * @returns {{ key: string|null, categories: object|null, resolvedFromStore: boolean, complete: boolean }}
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
  // MMP v2.0: a record carries DIRECT PARENTS ONLY (§7.5 retires the transitive closure). The
  // earliest anchor is found by VERIFIED GRAPH TRAVERSAL — walk out from the direct parents
  // through records THIS NODE has actually stored AND can verify, following each such record's
  // own parents.
  //
  // The incoming `lineage.ancestors` is NEVER read. Seeding the walk from a sender-supplied
  // closure let a non-conformant peer inject arbitrary apparent roots into tether resolution —
  // lineage amplification. A parent this node has not stored, or holds but cannot verify, is
  // incomplete LOCAL proof: the walk cannot pass through it, and it is never permission to trust
  // the sender's claim about it.
  //
  // Bounded: MAX_HOPS depth and MAX_NODES visited cap the walk, and `seen` makes a cyclic or
  // repeated-key chain terminate. The earliest-stored reachable record wins.
  const MAX_HOPS = 64;
  const MAX_NODES = 4096;
  const parentsOf = (cmb) => {
    const l = cmb?.metadata?.lineage ?? cmb?.lineage ?? null;
    return Array.isArray(l?.parents) ? l.parents : [];
  };
  const seen = new Set();
  let best = null;
  let bestTime = Infinity;
  let visited = 0;
  let complete = true;
  // Frontier of {key, depth} starting at the incoming record's DIRECT parents only.
  const directParents = Array.isArray(lin?.parents) ? lin.parents : [];
  const frontier = directParents.map((key) => ({ key, depth: 1 }));
  while (frontier.length) {
    const { key, depth } = frontier.shift();
    if (seen.has(key)) continue;
    if (depth > MAX_HOPS || visited >= MAX_NODES) { complete = false; continue; }
    seen.add(key);
    const entry = typeof getEntry === 'function' ? getEntry(key) : undefined;
    // Not stored locally → cannot walk through it; never trust the wire.
    if (!entry) { complete = false; continue; }
    visited++;
    // Stored but unverifiable → this branch ends here. Its content and its parents are claims by
    // an author this node cannot name, so it is neither a candidate anchor nor a way past itself.
    if (!storedRecordVerifies(entry, key)) { complete = false; continue; }
    const cmb = entry.cmb;
    // Rank by RECEIVER-LOCAL storedAt — never author/transport `originTimestamp`, which is
    // unverified and backdatable: a nearer record carrying an artificially old author time must
    // not displace the locally-verified earliest-stored anchor. Tie-break deterministically by
    // key so the choice is stable across nodes. This is the 'earliest STORED' contract, kept.
    const t = entry.storedAt ?? Infinity;
    if (t < bestTime || (t === bestTime && best && key < best.key)) {
      bestTime = t; best = { key, categories: cmb.categories, resolvedFromStore: true };
    }
    // Continue the VERIFIED walk from this stored record's own parents (never its wire ancestors).
    for (const pk of parentsOf(cmb)) if (!seen.has(pk)) frontier.push({ key: pk, depth: depth + 1 });
  }
  if (best) return { ...best, complete };
  // Only a ROOT is its own anchor. A remix with no verified ancestor in reach has an unverifiable
  // root, and saying so is the honest answer — not substituting the remix for the root it cites.
  if (directParents.length === 0 && incomingCMB && incomingCMB.categories) {
    return { key: incomingCMB.metadata?.key ?? incomingCMB.key ?? null, categories: incomingCMB.categories, resolvedFromStore: false, complete: true };
  }
  return { key: null, categories: null, resolvedFromStore: false, complete: false };
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

module.exports = { computeLineageTether, resolveTetherAnchor, storedRecordVerifies, evaluateLineageTetherFromText };
