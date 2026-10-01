'use strict';

/**
 * @module sym/core/svaf-baseline
 * @description Reference SVAF admission — per-category drift evaluation (MMP §9.2).
 *
 * Computes weighted per-category cosine drift between an incoming CMB and
 * local memory anchors, applies temporal decay, and produces an
 * accept/reject decision with a fused CMB.
 *
 * This is the admission engine a stock node runs. It derives from the
 * Apache-2.0 admission core published in @sym-bot/core 0.10.0. A consumer may
 * inject a different engine with the same call contract at the frame handler
 * (`opts.admit`); this module neither knows nor needs to know what such an
 * engine does beyond that contract.
 *
 * See MMP v0.2.0 Section 9: Coupling & SVAF.
 * See MMP v0.2.0 Section 10: State Blending.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const { createCMB, renderContent: renderCMB, cosineSimilarity, l2Normalize, CAT7_CATEGORIES, categoryKeyV1, encodeCategory, blockKeyV2 } = require('./cmb-encoder');
const { encodeForSVAF, isSemanticReady, kernelId } = require('./context-encoder');
const { computeLineageTether } = require('./lineage-tether');

/** Per-category admission verdicts — the first-class gating output (MMP §9.2). */
const CATEGORY_VERDICT = Object.freeze({
  ADMIT: 'admit', GUARD: 'guard', REDUNDANT: 'redundant', REJECT: 'reject', SILENT: 'silent',
});

/**
 * T_redundant. One constant, because it was defaulted independently in two places — the
 * per-category band and the aggregate decision — and two copies of a threshold are two thresholds
 * the day someone edits one of them.
 */
const DEFAULT_REDUNDANCY_THRESHOLD = 0.10;
/** §9.2.1: a covered category is FOREIGN when Σ_a w(a,f) ≤ ε · cover_f — the coverage-weighted mean
 *  of max(cos,0) is ~0. Dimensionless, so it is independent of anchor age. */
const FOREIGN_EPSILON = 1e-8;

/**
 * Promote the per-category drift the gate already computes into an explicit per-CAT7
 * admission verdict, using the SAME thresholds as the overall decision. This is the
 * authoritative gating output the Admission Attestation persists — NOT a number to
 * be re-derived from drift downstream.
 *
 * Bands, per evaluable category (mirroring the aggregate decision in
 * `processHeuristicSVAF`):
 *   δ_f^near < T_redundant       → 'redundant'  (already in memory; zero info gain)
 *   T_redundant ≤ δ_f ≤ T_stable → 'admit'      (aligned — admitted)
 *   T_stable  <  δ_f ≤ T_guarded → 'guard'      (admitted with caution)
 *   δ_f > T_guarded              → 'reject'     (drifted out of domain)
 * The REDUNDANT band tests the nearest-anchor drift δ_f^near = 1 − max_a cos(x_f, v_a,f)
 * (MMP §9.2.1 redundancy limit): the fused attention readout does not satisfy the
 * redundancy invariant — a block identical to a stored anchor can score δ_f > T_redundant
 * once other anchors pull the readout — so redundancy is pinned to the basis that does.
 * The graded bands keep the fused-readout δ_f.
 * A category with NO measurable drift (no relevant anchor carries it — δ_f undefined,
 * MMP §9.2.1 cold-start / non-evaluable) is 'silent': the receiver had no basis to
 * gate it, which is distinct from a measured-low-drift 'redundant'. All seven CAT7
 * categories are always present in the returned map — the per-category verdict captures the
 * granularity the single overall decision discards.
 *
 * @param {object} categoryDrifts - measured per-category fused-readout drift (evaluable categories only)
 * @param {object} config - { redundancyThreshold?, stableThreshold, guardedThreshold }
 * @param {object} [nearestDrifts] - per-category nearest-anchor drift. NO fallback: a category with
 *   no value here is never called redundant (the fused readout may not stand in for δ^near).
 * @returns {Record<string,string>} verdict per CAT7 category
 */
function computeCategoryVerdicts(categoryDrifts, config, nearestDrifts) {
  const tRedundant = config.redundancyThreshold ?? DEFAULT_REDUNDANCY_THRESHOLD;
  const tStable = config.stableThreshold;
  const tGuarded = config.guardedThreshold;
  const verdicts = {};
  for (const category of CAT7_CATEGORIES) {
    const d = categoryDrifts ? categoryDrifts[category] : undefined;
    if (d === undefined) { verdicts[category] = CATEGORY_VERDICT.SILENT; continue; }
    // NO FALLBACK TO THE FUSED READOUT. This used to read `nearestDrifts?.[category] ?? d`, which
    // silently substituted the one basis §9.2.1 proves does NOT satisfy the redundancy
    // invariant — so a caller with no nearest-anchor basis got a `redundant` verdict that was
    // unsound BY CONSTRUCTION rather than merely absent, and nothing said so. A caller without
    // that basis now simply never reaches the redundancy band: the category is graded on the
    // fused readout like any other, and is never called redundant. Honest, and it degrades to
    // a weaker claim instead of a wrong one. The graded bands are unaffected — they are
    // defined on the fused readout.
    const dNear = nearestDrifts?.[category];
    if (dNear !== undefined && dNear < tRedundant) verdicts[category] = CATEGORY_VERDICT.REDUNDANT;
    else if (d <= tStable) verdicts[category] = CATEGORY_VERDICT.ADMIT;
    else if (d <= tGuarded) verdicts[category] = CATEGORY_VERDICT.GUARD;
    else verdicts[category] = CATEGORY_VERDICT.REJECT;
  }
  return verdicts;
}

/**
 * Embedding cache keyed by (kernel, categoryKey).
 *
 * categoryKey = H(domain ‖ categoryName ‖ NFC(text)), so identical category text yields an identical
 * key yields the same embedding, deterministically and forever. The collapse property that
 * makes dedup work amortises the re-encode: the cost of receiver-local vectors falls to NOVEL
 * category text only, which is exactly what the dedup machinery already identifies. The same fact
 * twice, not a coincidence.
 *
 * The kernel is part of the key because a semantic and an n-gram encoding of the same text are
 * different vectors and must never be served for one another.
 */
const _embedCache = new Map();
const _EMBED_CACHE_MAX = 4096;

async function _localVector(categoryName, text, useSemantic) {
  const k = `${kernelId()}|${categoryKeyV1(categoryName, text)}`;
  const hit = _embedCache.get(k);
  if (hit) return hit;
  const v = useSemantic ? (await encodeForSVAF(text)).h1 : encodeCategory(text);
  if (_embedCache.size >= _EMBED_CACHE_MAX) _embedCache.delete(_embedCache.keys().next().value);
  _embedCache.set(k, v);
  return v;
}

/**
 * Replace every category's vector with one this node computed from the category's own text.
 *
 * DELETES first, then recomputes — so a record that arrives carrying vectors is silently
 * ignored rather than rejected (interop), and is admitted on the re-encoded value. The delete
 * is the security-relevant line: without it a transmitted vector would survive for any category
 * whose text is empty.
 */
async function localiseVectors(categories, useSemantic) {
  if (!categories) return;
  for (const category of CAT7_CATEGORIES) {
    const f = categories[category];
    if (!f || typeof f !== 'object') continue;
    delete f.vector;
    if (f.text) f.vector = await _localVector(category, f.text, useSemantic);
  }
}

/**
 * The incoming block's address, metadata-first, or NULL.
 *
 * IT RETURNS NULL RATHER THAN INVENTING ONE, and that is the whole point. This read used to be
 *   msg.cmb?.key || msg.cmb?.id || `cmb-${now}-${random}`
 * which, once records carried their address in `metadata`, matched NOTHING and fell through to
 * the random arm for EVERY inbound block. The fused remix then recorded a parent key that had
 * never existed and could never be resolved — well-formed, unresolvable, and silent. Lineage
 * pointed into nowhere, anchors would not resolve, and reachability walks dead-ended.
 *
 * A remix with no parent is a ROOT, which is a true statement about what we know. A remix
 * citing a fabricated parent is a false one, and the falsehood is undetectable downstream.
 */
function incomingKeyOf(cmb) {
  const k = cmb?.metadata?.key ?? cmb?.key ?? cmb?.id;
  return typeof k === 'string' && k ? k : null;
}

/** Lineage, whichever section carries it. */
function incomingLineageOf(cmb) {
  return cmb?.metadata?.lineage ?? cmb?.lineage ?? null;
}

/**
 * Build the fused remix as a §7 two-section record.
 *
 * Addressed by CONTENT ALONE (blockKeyV2), not by mintRemixKey. Under content-only addressing a
 * lineage-bearing block is addressed exactly like any other block with the same content, so a
 * remix that changed nothing collapses onto the block it came from instead of minting a sibling.
 *
 * COLLAPSE IS ENFORCED HERE, AND IT INHERITS RATHER THAN ERASES. Heuristic fusion keeps the
 * incoming category TEXT verbatim and fuses only the vector; v2 addresses by text alone, so an
 * admitted block ALWAYS lands on the incoming block's address. Recording parents:[k] on a block
 * whose own address is k writes the edge k -> k, and a reachability walk never leaves it.
 *
 * But the answer is NOT to drop the lineage. When the content is identical the record IS the
 * incoming block, so it carries the lineage ITS AUTHOR gave it — the incoming block's own
 * parents. Nulling it instead would erase descent on the entire receive path: every admitted
 * peer block would store as a root, the chain back to its origin would vanish, and the tether
 * audit would have nothing left to check. That is the failure this comment exists to prevent,
 * because the first cut of this function did exactly that and the store still looked healthy.
 */
function buildFusedRecord({ categories, createdBy, parentKey, parentLineage, parentMetadata, parentCategories, parentCreatedBy, method, provenance }) {
  const key = blockKeyV2(categories);
  const selfEdge = parentKey && key === parentKey;
  // Same content ⇒ same block ⇒ the AUTHOR'S record, carried through as signed (MMP §8.8.4,
  // §15.2): the author's categories (including each category's signed `meta`, which fusion's
  // rebuilt categories do not carry) and the author's metadata and signature. Rewriting createdBy
  // to the receiver here made every admitted block claim the receiver as author at the author's
  // address, and cmb-fetch then served that to third parties (2026-10-01 audit, B-L1).
  if (selfEdge && parentMetadata && typeof parentMetadata === 'object') {
    return {
      categories: parentCategories ? strippedOfVectors(parentCategories) : categories,
      metadata: { ...parentMetadata, key },
      provenance,
      collapsed: true,
    };
  }
  // A pre-boundary record (§7.8, address and author at the top level) cannot be carried through
  // as signed in this shape, but its author is still its author, never the receiver.
  if (selfEdge && typeof parentCreatedBy === 'string' && parentCreatedBy) createdBy = parentCreatedBy;
  const inherited = selfEdge ? (parentLineage ?? null) : null;
  return {
    categories,
    metadata: {
      key,
      // The fusing agent AUTHORS the remix it mints. The composed "<receiver>+<author>" string
      // named a holder, not an author, and is gone from the record — it survives only on the
      // store envelope, where it is receiver-local bookkeeping rather than an authorship claim.
      createdBy,
      createdTimestamp: Date.now(),
      // `ancestors` is not written: reachability is walked from refs, and a transitive closure
      // stapled to every block had to be recomputed at every hop, where a wrong one was
      // indistinguishable from a right one.
      lineage: selfEdge ? inherited : (parentKey ? { parents: [parentKey], method } : null),
      room: null,
      to: null,
    },
    provenance,
    collapsed: selfEdge || undefined,
  };
}

/** A record-shaped projection of evaluated categories: text and meta, never the vector (§7.1). */
function strippedOfVectors(categories) {
  const out = {};
  for (const [name, f] of Object.entries(categories || {})) {
    if (!f) continue;
    // Everything but the vector: `meta` is signed, and mood carries valence/arousal (re-review F6).
    const { vector, ...rest } = f;
    out[name] = rest;
  }
  return out;
}

/**
 * The per-category drift arithmetic (§9.2/§9.2.1), as a PURE function of already-encoded vectors.
 *
 * Callers pass categories whose vectors are ALREADY receiver-local. This function does not fetch,
 * encode, or trust — it only measures.
 *
 * @returns {{categoryDrifts: object, nearestDrifts: object, fusedCategories: object, silentCauses: object}}
 */
function computeCategoryDrifts({ incomingCategories, anchors, config, now, tau }) {
  const categoryDrifts = {};
  const nearestDrifts = {};
  const fusedCategories = {};
  /**
   * WHY a `silent` verdict alone is not enough — §9.2.1 RECOMMENDS distinguishing these.
   *
   * Two unrelated situations produce an unevaluable category, and they mean opposite things:
   *
   *   no-text    the EMITTER carried nothing for this category, so there is nothing to encode.
   *              An upstream data-quality problem, and actionable at the source.
   *   no-anchor  the RECEIVER holds no anchor carrying this category, so δ_f is undefined.
   *              A normal cold start — the system working, and it resolves itself as memory fills.
   *
   * Collapsing them loses the only thing an operator needs: whether to go fix an emitter or wait.
   * The verdict stays `silent` in both cases (it is the same fact about the decision — no
   * judgement was made); the cause rides alongside it and never enters the signed payload.
   */
  const silentCauses = {};

  for (const category of CAT7_CATEGORIES) {
    const inCategory = incomingCategories[category];
    if (!inCategory || !inCategory.vector) { silentCauses[category] = 'no-text'; continue; }

    // α_f is NOT used here (MMP §9.2.1, 2026-09-26 draft). It is constant across a category's
    // anchors, so it cancelled in the normalized readout and changed no δ_f; its one effect was to
    // feed the evaluability threshold, where a small weight read as missing memory and
    // bootstrap-admitted records on a populated store. It acts only in the aggregate below.
    const dim = inCategory.vector.length;
    // MMP §9.2.1 anchors-only baseline: the receiver's memory readout for this category is
    // built from PRIOR ANCHORS ONLY. The incoming block MUST NOT seed its own comparison —
    // seeding it (the previous `inCategory.vector.slice()` + weight 1.0) collapses δ_f → 0 for
    // genuinely novel categories and mis-classifies them as redundant, leaving the node
    // inbound-blind. [attention-weighted memory readout — internal method]
    const weightedVec = new Array(dim).fill(0);
    let totalWeight = 0;   // Σ_a w(a,f): similarity-weighted, drives the readout direction
    let coverage = 0;      // cover_f = Σ_a decay·conf: how much live memory of f, independent of similarity
    let nearestSim = -1;

    for (const anchor of anchors) {
      const anchorCategory = anchor.categories ? anchor.categories[category] : null;
      if (!anchorCategory || !anchorCategory.vector) continue;
      // Vectors may have different dimensions if mixed encoders — skip if mismatched
      if (anchorCategory.vector.length !== dim) continue;
      const cosSim = cosineSimilarity(inCategory.vector, anchorCategory.vector);
      if (cosSim > nearestSim) nearestSim = cosSim;
      const anchorAge = (now - (anchor.storedAt || now)) / 1000;
      const anchorDecay = Math.exp(-anchorAge / tau);
      // NO INVENTED CONFIDENCE. This read `anchor.confidence || 0.6`, so an anchor that never
      // stated a confidence was silently weighted as though it had — and 0.6 is not a neutral
      // number, it pulls the fused readout toward anchors whose standing nobody asserted. An
      // anchor with no confidence now contributes at FULL weight, which is the honest reading of
      // "no reduction was claimed", and the absence stops being disguised as a measurement.
      const presence = anchorDecay * (typeof anchor.confidence === 'number' ? anchor.confidence : 1.0);
      coverage += presence;
      const w = Math.max(cosSim, 0) * presence;
      for (let d = 0; d < dim; d++) weightedVec[d] += w * anchorCategory.vector[d];
      totalWeight += w;
    }

    // MMP §9.2.1 cold-start / non-evaluable category: no relevant anchor carries this category,
    // so δ_f is undefined. Leave it UNSET (excluded from aggregation below) — do NOT treat
    // it as maximally novel, which would force false rejection of cold-start signals.
    // EVALUABILITY IS DECIDED BY COVERAGE, NEVER BY THE READOUT WEIGHT. The max(cos,0) clamp drives
    // totalWeight to ~0 in two opposite situations — no anchor carries f, and every anchor carrying
    // f points away — and reading both as "no anchor" admitted a record foreign to a populated
    // memory on the bootstrap rule. Coverage decays with age exactly as the readout always did.
    if (coverage < 1e-8) { silentCauses[category] = 'no-anchor'; continue; }

    // COVERED BUT FOREIGN: every carrying anchor points away. A DIRECTION test — the
    // coverage-weighted mean of max(cos,0) is ~0 — never an absolute floor, because totalWeight and
    // coverage share the same age decay and an absolute floor would read an old, aligned anchor as
    // foreign (cover 1.5e-8 at cos 0.5 is aligned, not foreign).
    if (totalWeight <= FOREIGN_EPSILON * coverage) {
      categoryDrifts[category] = 1.0;
      nearestDrifts[category] = 1.0 - Math.max(nearestSim, 0);
      fusedCategories[category] = { text: inCategory.text, vector: inCategory.vector.slice() };
      continue;
    }

    let fused = weightedVec.map(x => x / totalWeight);
    fused = l2Normalize(fused);
    categoryDrifts[category] = 1.0 - cosineSimilarity(fused, inCategory.vector);
    // MMP §9.2.1 redundancy limit (nearest-anchor basis): the redundancy decision reads
    // δ_f^near = 1 − max_a cos, NOT the fused readout — a block identical to a stored
    // anchor must score → 0 here regardless of what other anchors do to the readout.
    nearestDrifts[category] = 1.0 - Math.max(nearestSim, 0);
    fusedCategories[category] = { text: inCategory.text, vector: fused };
  }

  return { categoryDrifts, nearestDrifts, fusedCategories, silentCauses };
}

/**
 * Attach the per-category silent causes to EVERY outcome, whatever path produced it.
 *
 * Deliberately a wrapper rather than an addition to each `return`: the inner function has six
 * exits including two cold-start ones, and a member present on five of six reads as a
 * measurement on the sixth. Wrapping makes the omission unrepresentable instead of merely
 * unlikely.
 */
async function processHeuristicSVAF(opts) {
  const trace = {};
  const result = await _processHeuristicSVAF({ ...opts, _trace: trace });
  return {
    ...result,
    // §9.2.1: `silent` says no judgement was made; this says WHY, per category — 'no-text'
    // (emitter sent nothing), 'no-anchor' (receiver had nothing to compare against) or
    // 'zero-weight' (receiver holds memory of it but its policy disables the category). LOCAL
    // only: it MUST NOT enter the signed attestation payload, because a cause is a statement
    // about this receiver's store, not about the record being attested.
    silentCauses: trace.silentCauses ?? {},
  };
}

/**
 * Refuse an admission policy this node has not stated, rather than computing with a hole in it.
 *
 * These four steer a verdict, and every one of them reaches an arithmetic expression with no
 * fallback. An absent member is therefore not a small gap: `(1 - undefined) * x + undefined * y`
 * is NaN, `NaN <= T` is false for every T, and the band chain falls through to REJECT. So a host
 * that forgets one gets a node that silently rejects EVERY CMB, with no error, and with verdicts
 * indistinguishable from real ones. Measured by execution before this guard existed.
 *
 * Defaulting them here would be the wrong repair and not merely a lesser one. §9.2.1: the
 * thresholds and lambda ARE the receiver's admission policy — "no sender and no coordinator sets
 * them". A library that invents them is a library imposing an admission policy on a node that
 * never chose one. A node with no stated policy has no policy to apply, and must be told so.
 *
 * `redundancyThreshold` is deliberately NOT in this list: it has a documented in-file default
 * (§9.2 T_redundant), so its absence has a defined meaning rather than an arithmetic hole.
 *
 * This is `record-shape`'s rule reaching the config — absence is never silence. That rule was
 * applied to the CAT7 container and not to the policy that judges it.
 */
const REQUIRED_POLICY = ['stableThreshold', 'guardedThreshold', 'temporalLambda', 'freshnessSeconds'];

function requireAdmissionPolicy(config) {
  if (!config || typeof config !== 'object') {
    throw new Error(
      'SVAF: no admission policy supplied. §9.2.1 makes the thresholds and lambda the receiver\'s ' +
      'own policy, so this library will not invent them. Pass a config with: ' + REQUIRED_POLICY.join(', ') + '.');
  }
  const missing = REQUIRED_POLICY.filter(k => !Number.isFinite(config[k]));
  if (missing.length) {
    throw new Error(
      `SVAF: admission policy incomplete — ${missing.join(', ')} ${missing.length > 1 ? 'are' : 'is'} ` +
      'not a finite number. Every one of these reaches the drift arithmetic with no fallback, so ' +
      'continuing would make totalDrift NaN and silently REJECT every CMB. §9.2.1: these are the ' +
      'receiver\'s admission policy and no default is supplied for them.');
  }
  if (config.categoryWeights != null && typeof config.categoryWeights !== 'object') {
    throw new Error('SVAF: config.categoryWeights must be an object of per-category weights when present.');
  }
  // §9.2.1: weights are policy, and a policy is complete or refused. Each supplied α_f must be a
  // finite number ≥ 0; an unsupplied category weighs 1. At least one EFFECTIVE weight must be > 0 —
  // all-zero has no lens, and read literally makes every aggregate 0/0. Refused here, loudly, rather
  // than substituting a default: `|| 1.0` at the use site silently turned an explicit 0 into full
  // weight, a policy the receiver never chose.
  if (config.categoryWeights) {
    const bad = Object.entries(config.categoryWeights)
      .filter(([, v]) => !(typeof v === 'number' && Number.isFinite(v) && v >= 0));
    if (bad.length) {
      throw new Error(`SVAF: category weights must be finite numbers ≥ 0 — got ${bad.map(([k, v]) => `${k}=${String(v)}`).join(', ')}. §9.2.1: a policy is refused, never defaulted.`);
    }
    if (!CAT7_CATEGORIES.some((f) => (config.categoryWeights[f] ?? 1) > 0)) {
      throw new Error('SVAF: every category weight is 0 — a policy with no lens. §9.2.1 requires at least one weight > 0.');
    }
  }
}

async function _processHeuristicSVAF(opts) {
  const { msg, peerName, localName, originTs, now, ageSeconds, recentCMBs, config, groundingWaiver } = opts;

  // Before any arithmetic, and before either cold-start exit — both of them read temporalLambda too.
  requireAdmissionPolicy(config);

  // The integration timescale is the receiver's stated freshness window, exactly.
  const tau = config.freshnessSeconds;

  const temporalDecay = Math.exp(-ageSeconds / tau);
  const temporalDrift = 1 - temporalDecay;

  // The incoming record may be a v2 two-section CMB or a bare-categories message. Normalise to the
  // shape the rest of this function reads. createdBy is required now, and `peerName` is the
  // delivering peer rather than the author — the wrong identity to record, but the only one a
  // categories-only message carries, so it is used ONLY to synthesise a local evaluation subject
  // and never travels.
  const incomingCMB = msg.cmb
    || createCMB({ categories: msg.categories, createdBy: String(msg.source || peerName || 'peer') });
  const anchors = recentCMBs || [];

  // Vectors are RECEIVER-LOCAL and are recomputed here, unconditionally, from text.
  //
  // Any vector that arrived on the wire is DISCARDED before it can reach the drift
  // computation. This used to happen only when the semantic encoder was ready; on the
  // heuristic path a transmitted vector was consumed as-is, and that was the hole:
  //
  //   The vector is the only part of a CMB that admission consumes and the signature does
  //   NOT cover. categoryKey binds the TEXT, the signature binds the Merkle root over
  //   categoryKeys — so a vector can be rewritten in flight and the block still verifies, still
  //   recomputes its address, and still admits on the rewritten value.
  //
  // The decisive attack is suppression, not injection. Forcing an ADMIT is hard: drift is
  // measured against the receiver's own unpublished anchors, and in high dimension an
  // arbitrary vector is near-orthogonal to everything and gets refused. Forcing a REJECT is
  // trivial — a RELAYING peer nudges a third party's vector out of band, the block still
  // verifies, and the receiver silently refuses cognition its author sent in good faith.
  // Undetectable censorship, performed by someone who is not the author. A mesh whose claim
  // is receiver-autonomous admission cannot let a relay decide what a receiver never sees.
  //
  // kernelId gating was the tempting cheap fix and it is not a fix: kernelId is not in the
  // categoryKey either, so it is equally unsigned and equally alterable. Gating trust on an
  // attacker-supplied label tells the attacker which value to write.
  const useSemantic = isSemanticReady();
  await localiseVectors(incomingCMB.categories, useSemantic);
  for (const anchor of anchors) await localiseVectors(anchor.categories, useSemantic);

  const dr = computeCategoryDrifts({ incomingCategories: incomingCMB.categories, anchors, config, now, tau });
  const categoryDrifts = dr.categoryDrifts;
  const nearestDrifts = dr.nearestDrifts;
  const fusedCategories = dr.fusedCategories;
  // Hand the causes back to the wrapper. Done ONCE here rather than added to six return
  // literals: a member present on five exits and absent on the sixth reads as a measurement
  // rather than a gap, and a cold start is the case where the causes are most worth reading —
  // every category is silent there and the operator's question is precisely whether that is an
  // empty store or an empty emitter.
  if (opts._trace) {
    opts._trace.silentCauses = dr.silentCauses;
  }

  // MMP §9.2 / §9.2.1 Band-pass: aggregate over EVALUABLE categories only. A non-evaluable
  // category (no relevant anchor) is EXCLUDED, not counted as zero-drift.
  const evaluable = CAT7_CATEGORIES.filter(f => categoryDrifts[f] !== undefined);
  // WEIGHTED: evaluable AND α_f > 0. Only these enter the aggregate and the redundancy max. A
  // category the receiver weights at 0 is DISABLED — reported silent — but it never makes a covered
  // category count as uncovered, so it can never reach the empty-memory bootstrap below.
  const alphaOf = (f) => config.categoryWeights?.[f] ?? 1.0;
  const weighted = evaluable.filter((f) => alphaOf(f) > 0);
  for (const f of evaluable) if (alphaOf(f) === 0) dr.silentCauses[f] = 'zero-weight';
  const verdictDrifts = Object.fromEntries(weighted.map((f) => [f, categoryDrifts[f]]));

  // §9.2.1 cold-start bootstrap: if NO category is evaluable (empty or wholly-unrelated memory),
  // category drift is unmeasurable — but TEMPORAL drift still applies (signal age is
  // memory-independent). Admit the signal to bootstrap memory UNLESS it is too
  // stale (temporal drift alone exceeds the guarded threshold). There is nothing
  // to fuse against, so the receiver-side remix IS the incoming signal ingested
  // under a distinct remix key so lineage does not self-refer.
  // Bootstrap splits in two (§9.2.1). NOTHING covered — empty memory — admits as aligned, exactly as
  // before. Something covered but NOTHING WEIGHTED — a lens-level cold start — admits too, so a narrow
  // lens is not starved of its own categories, but as GUARDED: the receiver holds memory it chose not
  // to consult, and claiming alignment would assert an assessment it never made.
  const lensUncovered = evaluable.length > 0 && weighted.length === 0;
  // A LOCAL diagnostic: it rides on the result and never enters the signed payload or a stored record.
  const coldStartCause = lensUncovered ? 'lens-uncovered' : 'empty-memory';
  if (evaluable.length === 0 || lensUncovered) {
    const csTotalDrift = config.temporalLambda * temporalDrift;
    if (csTotalDrift > config.guardedThreshold) {
      return { accepted: false, totalDrift: csTotalDrift, decision: 'rejected', categoryVerdicts: computeCategoryVerdicts(verdictDrifts, config), effectiveTau: tau, changeSignal: 0, coldStartCause };
    }
    const csIncomingKey = incomingKeyOf(msg.cmb);
    const csCMB = buildFusedRecord({
      // Vectors are stripped on EVERY exit that stores a record, including this cold-start one.
      // Demonstrated rather than assumed: the first run of the store-none proof landed HERE and
      // persisted all seven vectors while the main path was already clean.
      categories: strippedOfVectors(incomingCMB.categories),
      createdBy: localName,
      parentKey: csIncomingKey,
      parentLineage: incomingLineageOf(msg.cmb),
      parentMetadata: msg.cmb?.metadata,
      parentCategories: msg.cmb?.categories,
      parentCreatedBy: msg.cmb?.createdBy,
      method: 'svaf-heuristic-coldstart',
      provenance: { categoryDrift: {}, totalDrift: csTotalDrift, temporalDrift, effectiveTau: tau, changeSignal: 0, fusionMethod: 'svaf-heuristic-coldstart', fusedAt: now },
    });
    const csKey = csCMB.metadata.key;
    const csContent = renderCMB(csCMB);
    const csEntry = { ...msg, key: csKey, content: csContent, source: `${localName}+${msg.source || peerName}`, cmb: csCMB, storedAt: now };
    const csDecision = (!lensUncovered && csTotalDrift <= config.stableThreshold) ? 'aligned' : 'guarded';
    // Cold-start: no category was evaluable, so every per-category verdict is `silent`
    // (admitted on temporal grounds to bootstrap memory, gated on no category).
    return { accepted: true, totalDrift: csTotalDrift, decision: csDecision, maxCategoryDrift: 0, categoryVerdicts: computeCategoryVerdicts(verdictDrifts, config), fusedEntry: csEntry, fusedContent: csContent, effectiveTau: tau, changeSignal: 0, coldStartCause };
  }

  let weightedDriftSum = 0, weightSum = 0;
  for (const category of weighted) {
    const alphaF = alphaOf(category);
    weightedDriftSum += alphaF * categoryDrifts[category];
    weightSum += alphaF;
  }
  // weightSum > 0 is GUARANTEED here: `weighted` is non-empty and every member has α > 0. The old
  // `weightSum > 0 ? … : 0` read an all-zero lens as drift 0 — perfectly aligned — a second admit path.
  const aggregateCategoryDrift = weightedDriftSum / weightSum;
  const totalDrift = (1 - config.temporalLambda) * aggregateCategoryDrift + config.temporalLambda * temporalDrift;

  // §9.2 redundancy: redundant iff EVERY evaluable category is below T_redundant — every category
  // already in memory. Shannon (1948): zero information gain. Berlyne (1970): Wundt-curve lower bound.
  // §9.2.1 nearest-anchor basis: the test reads δ_f^near (nearest stored anchor), not the
  // fused readout, so identical-to-stored content is redundant by construction.
  const redundancyThreshold = config.redundancyThreshold ?? DEFAULT_REDUNDANCY_THRESHOLD;
  const maxCategoryDrift = Math.max(...weighted.map(f => nearestDrifts[f]));
  // MMP §6.7 repeat verification: a recognised grounding CMB (caller-verified —
  // signed, intent=ground, outcome prefix, held target) MUST NOT be refused solely
  // for redundancy: a verification report about a row the receiver already holds is
  // near-duplicate BY NATURE, and refusing repeats self-quenches the outcome stream.
  // Only the redundancy band is waived; the reject band below stands unmodified.
  if (maxCategoryDrift < redundancyThreshold && !groundingWaiver) {
    return { accepted: false, totalDrift, decision: 'redundant', maxCategoryDrift, categoryVerdicts: computeCategoryVerdicts(verdictDrifts, config, nearestDrifts), effectiveTau: tau, changeSignal: 0 };
  }

  // Section 9.2: rejected if totalDrift > T_guarded (irrelevant domain)
  if (totalDrift > config.guardedThreshold) {
    return { accepted: false, totalDrift, decision: 'rejected', categoryVerdicts: computeCategoryVerdicts(verdictDrifts, config, nearestDrifts), effectiveTau: tau, changeSignal: 0 };
  }

  // Section 9.2: aligned or guarded
  const decision = totalDrift <= config.stableThreshold ? 'aligned' : 'guarded';

  const incomingKey = incomingKeyOf(msg.cmb);
  const fusedCMB = buildFusedRecord({
    // STORE NO VECTOR (§7.1). createCMB already refuses to put a vector in an emitted record —
    // "Emitters MUST NOT include embedding vectors" — and fusion was putting one back in on the
    // receiver side, so this applies the existing rule to the remix rather than inventing one.
    //
    // Stripped HERE and not in computeCategoryDrifts, because the in-call vectors are still load
    // bearing: computeLineageTether reads remixCategories[f].vector and silently degrades to
    // "not checked" without it. Computation keeps its vectors; the RECORD carries none.
    // `meta` is preserved — categoryParentsCommitment signs meta.parents.
    categories: strippedOfVectors(fusedCategories),
    createdBy: localName,
    parentKey: incomingKey,
    parentLineage: incomingLineageOf(msg.cmb),
    parentMetadata: msg.cmb?.metadata,
    parentCategories: msg.cmb?.categories,
    parentCreatedBy: msg.cmb?.createdBy,
    method: 'svaf-heuristic',
    provenance: { categoryDrift: categoryDrifts, totalDrift, temporalDrift, effectiveTau: tau, changeSignal: 0, fusionMethod: 'svaf-heuristic', fusedAt: now },
  });
  const fusedKey = fusedCMB.metadata.key;

  const fusedContent = renderCMB(fusedCMB);
  const fusedEntry = { ...msg, key: fusedKey, content: fusedContent, source: `${localName}+${msg.source || peerName}`, cmb: fusedCMB, storedAt: now };

  // MMP §15.8 lineage tether — evaluated HERE so both sides share one kernel:
  // the remix's fused vectors are current-encoder products, while a stored
  // anchor's vectors may predate the encoder (n-gram vs semantic occupy the
  // same 192 dims but different spaces, so a raw comparison is meaningless).
  // Re-encode the anchor's category texts exactly as the gate re-encodes its
  // anchors, then run the content-only drift check. The caller resolves the
  // anchor and applies severance; this only reports.
  let tether = null;
  const tetherAnchor = opts.tetherAnchor;
  if (tetherAnchor && tetherAnchor.categories) {
    let anchorCategories = tetherAnchor.categories;
    if (useSemantic) {
      anchorCategories = {};
      for (const category of CAT7_CATEGORIES) {
        const f = tetherAnchor.categories[category];
        if (!f) continue;
        anchorCategories[category] = { ...f };
        if (f.text) {
          const { h1 } = await encodeForSVAF(f.text);
          anchorCategories[category].vector = h1;
        }
      }
    }
    tether = {
      anchorKey: tetherAnchor.key ?? null,
      // §15.8 kernel identity — the kernel this evaluation was made in;
      // verdicts are comparable iff kernelId matches.
      kernelId: kernelId(),
      ...computeLineageTether({
        remixCategories: fusedCategories,
        anchorCategories,
        categoryWeights: config.categoryWeights,
        guardedThreshold: config.guardedThreshold,
      }),
    };
  }

  return { accepted: true, decision, totalDrift, categoryVerdicts: computeCategoryVerdicts(verdictDrifts, config, nearestDrifts), fusedEntry, fusedContent, effectiveTau: tau, changeSignal: 0, tether };
}

module.exports = {
  computeCategoryDrifts, processHeuristicSVAF, computeCategoryVerdicts,
  CATEGORY_VERDICT, DEFAULT_REDUNDANCY_THRESHOLD,
};
