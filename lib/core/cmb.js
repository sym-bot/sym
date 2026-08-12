'use strict';

/**
 * @module sym/core/cmb
 * @description Cognitive Memory Block — CAT7 universal category schema.
 *
 * 7 categories forming a minimal, near-orthogonal basis spanning
 * three axes of human communication. Universal and immutable —
 * domain-specific interpretation happens in category text, not category name.
 *
 * CMBs are immutable after creation. When an agent acts on a CMB,
 * it creates a NEW CMB with lineage pointing to the parent(s).
 *
 * See MMP v0.2.0 Section 8: CMBs (CAT7).
 *
 * Paper: SVAF — Symbolic-Vector Attention Fusion for Multi-Agent Memory Synthesis
 * Spec: why-cat7-cmb.md
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

/**
 * The 7 canonical CMB category names (CAT7 schema).
 * @type {string[]}
 */
const CAT7_CATEGORIES = ['focus', 'issue', 'intent', 'motivation', 'commitment', 'perspective', 'mood'];

/**
 * Per-agent category weight profiles (alpha_f from the SVAF paper).
 *
 * Higher weight = this category matters more for this agent type.
 * Mood is the only fast-coupling category — crosses all domain boundaries.
 *
 * See MMP v0.2.0 Section 9: Coupling & SVAF.
 *
 * @type {Object<string, Object<string, number>>}
 */
const FIELD_WEIGHT_PROFILES = {
  // Core personal agents
  coding:    { focus: 2.0, issue: 1.5, intent: 1.5, motivation: 1.0, commitment: 1.2, perspective: 1.0, mood: 0.8 },
  music:     { focus: 1.0, issue: 0.8, intent: 0.8, motivation: 0.8, commitment: 0.8, perspective: 1.2, mood: 2.0 },
  fitness:   { focus: 1.5, issue: 1.5, intent: 1.0, motivation: 1.5, commitment: 1.0, perspective: 1.0, mood: 2.0 },
  messaging: { focus: 1.0, issue: 1.2, intent: 1.5, motivation: 1.0, commitment: 1.0, perspective: 1.5, mood: 1.2 },
  knowledge: { focus: 2.0, issue: 1.5, intent: 1.5, motivation: 1.0, commitment: 0.5, perspective: 1.5, mood: 0.3 },
  // Regulated domains
  legal:     { focus: 2.0, issue: 2.0, intent: 1.5, motivation: 1.0, commitment: 2.0, perspective: 1.5, mood: 0.5 },
  health:    { focus: 1.5, issue: 2.0, intent: 1.0, motivation: 1.5, commitment: 1.0, perspective: 1.5, mood: 2.0 },
  finance:   { focus: 2.0, issue: 2.0, intent: 1.5, motivation: 1.0, commitment: 2.0, perspective: 2.0, mood: 0.3 },
  // One-person company agents
  support:   { focus: 1.5, issue: 2.0, intent: 1.5, motivation: 1.0, commitment: 1.5, perspective: 2.0, mood: 1.5 },
  analytics: { focus: 2.0, issue: 1.5, intent: 1.0, motivation: 1.5, commitment: 0.5, perspective: 1.5, mood: 0.3 },
  inventory: { focus: 1.5, issue: 2.0, intent: 1.0, motivation: 1.0, commitment: 2.0, perspective: 1.0, mood: 0.3 },
  writing:   { focus: 2.0, issue: 1.0, intent: 2.0, motivation: 1.5, commitment: 1.5, perspective: 1.5, mood: 0.8 },
  scheduling:{ focus: 1.0, issue: 1.5, intent: 1.5, motivation: 0.8, commitment: 2.0, perspective: 2.0, mood: 0.3 },
  sales:     { focus: 1.5, issue: 1.0, intent: 2.0, motivation: 1.5, commitment: 2.0, perspective: 1.0, mood: 1.5 },
  recruiting:{ focus: 1.5, issue: 1.0, intent: 1.0, motivation: 2.0, commitment: 1.5, perspective: 2.0, mood: 1.0 },
  marketing: { focus: 1.5, issue: 1.0, intent: 2.0, motivation: 1.0, commitment: 1.0, perspective: 1.5, mood: 2.0 },
  research:  { focus: 2.0, issue: 1.5, intent: 1.0, motivation: 1.0, commitment: 1.0, perspective: 2.0, mood: 0.3 },
  ops:       { focus: 1.5, issue: 2.0, intent: 1.5, motivation: 1.0, commitment: 2.0, perspective: 1.0, mood: 0.3 },
  design:    { focus: 1.5, issue: 0.8, intent: 1.5, motivation: 1.0, commitment: 1.0, perspective: 2.0, mood: 2.0 },
  'data-eng':{ focus: 1.5, issue: 2.0, intent: 1.0, motivation: 1.0, commitment: 2.0, perspective: 1.0, mood: 0.3 },
  // Default
  uniform:   { focus: 1.0, issue: 1.0, intent: 1.0, motivation: 1.0, commitment: 1.0, perspective: 1.0, mood: 1.0 },
};

module.exports = { CAT7_CATEGORIES, FIELD_WEIGHT_PROFILES };
