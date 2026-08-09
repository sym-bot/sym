'use strict';

/**
 * record.js — read a CMB's metadata without caring which record generation it is.
 *
 * A block on the wire is now two sections: `categories` (what the agent said) and `metadata` (what
 * the mesh proves). Blocks minted before that boundary are FLAT — key, createdBy, createdAt and
 * lineage sit at the top level. Both shapes are live at once: legacy blocks are grandfathered
 * and still verify, so every read site has to handle both, forever.
 *
 * WHY THIS IS A MODULE AND NOT A ONE-LINER AT EACH SITE. It was a one-liner at each site, and
 * the sites drifted: some read `cmb.key` alone (undefined for every current block), some wrote
 * `cmb?.metadata?.key ?? cmb?.key`, one held it as a local const inside a single method. Each is
 * individually defensible and collectively they mean the same question has several answers.
 * Worse, the failures are SILENT — a flat read of a two-section record yields `undefined`, which
 * `||` then converts into a plausible fallback rather than an error.
 *
 * PRECEDENCE IS DELIBERATE AND IS NOT SYMMETRIC. `metadata` is consulted FIRST, always. The
 * metadata section is what the signature binds; a flat top-level field on a record that also has
 * metadata is either a leftover or something a relayer stapled on. Reading legacy-first would
 * mean a current record could be described by an unsigned field — the same defect class as
 * attributing a block by its envelope rather than by what its author signed.
 */

/** The block's address, or null. Never invents one. */
function recordKey(cmb) {
  return cmb?.metadata?.key ?? cmb?.key ?? null;
}

/**
 * The AUTHORING agent id, or null.
 *
 * Empty is absent: a blank byline renders as ownership, and `??` alone would pass "" through as
 * if it were a name. Callers that need a display string coalesce at the point of display, where
 * the reader can see that it is a placeholder — never here, where it becomes indistinguishable
 * from a real attribution.
 */
function recordCreatedBy(cmb) {
  const v = cmb?.metadata?.createdBy ?? cmb?.createdBy;
  return typeof v === 'string' && v.trim() ? v.trim() : null;
}

/** Creation time in ms, or null. `createdAt` was renamed to `createdTimestamp` at the boundary. */
function recordCreatedAt(cmb) {
  return cmb?.metadata?.createdTimestamp ?? cmb?.createdAt ?? null;
}

/** The block's lineage object, or null. */
function recordLineage(cmb) {
  return cmb?.metadata?.lineage ?? cmb?.lineage ?? null;
}

/** Parent keys, always an array — an absent lineage is no parents, not a crash. */
function recordParents(cmb) {
  const l = recordLineage(cmb);
  return Array.isArray(l?.parents) ? l.parents : [];
}

/**
 * Write lineage back, into whichever section this record actually carries.
 *
 * Severance needs this. Assigning `cmb.lineage = null` on a two-section record does not sever
 * anything — it adds a null top-level field that nothing reads while the real lineage stays in
 * metadata, so a severed block keeps its edges and the metric reports success.
 */
function setRecordLineage(cmb, value) {
  if (!cmb) return cmb;
  if (cmb.metadata) cmb.metadata.lineage = value;
  else cmb.lineage = value;
  return cmb;
}

module.exports = {
  recordKey, recordCreatedBy, recordCreatedAt, recordLineage, recordParents, setRecordLineage,
};
