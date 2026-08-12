'use strict';

/**
 * @module @sym-bot/core/merkle
 * @description Minimal binary Merkle root over an ordered leaf list (SHA-256).
 *
 * Used by Admission Attestation checkpoints: a node commits a Merkle root over its
 * attestation chain (the ordered attestation signatures, seq 1..N). Once that root
 * is witnessed (countersigned) by roster peers, the attester cannot later serve a
 * chain that drops or reorders an attestation ≤ N without the recomputed root
 * diverging from the witnessed one — which is what turns silent omission into a
 * detectable contradiction.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const crypto = require('crypto');

/** SHA-256 of a buffer/string → buffer. */
function sha256(x) {
  return crypto.createHash('sha256').update(x).digest();
}

/**
 * Merkle root (hex) over an ordered list of leaves. Each leaf is hashed, then the
 * tree is built pairwise; an odd node at any level is paired with itself. The root
 * commits to BOTH the set and the order of the leaves. Empty list → the hash of the
 * empty string (a stable, well-defined empty root).
 * @param {Array<string|Buffer>} leaves - ordered leaves (e.g. attestation signatures)
 * @returns {string} hex Merkle root
 */
function merkleRoot(leaves) {
  if (!Array.isArray(leaves) || leaves.length === 0) return sha256('').toString('hex');
  let level = leaves.map((l) => sha256(typeof l === 'string' ? l : Buffer.from(l)));
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const a = level[i];
      const b = i + 1 < level.length ? level[i + 1] : level[i]; // duplicate last if odd
      next.push(sha256(Buffer.concat([a, b])));
    }
    level = next;
  }
  return level[0].toString('hex');
}

module.exports = { merkleRoot, sha256 };
