'use strict';
/**
 * record-shape.js — ONE accessor for a record's parts, so no call site reaches into shape.
 *
 * WHY THIS EXISTS, measured rather than argued (2026-08-07):
 *
 * 1. SIX GUARDS IN THIS PACKAGE CONDITION ON THE CONTAINER'S PRESENCE and therefore FAIL OPEN
 *    the moment it is renamed or absent. The worst is cmb-signing's content-integrity check:
 *
 *        if (cmb.categories && typeof cmb.categories === 'object') { ...verify the address... }
 *        return { signed: true, valid: true };
 *
 *    A record whose categories arrive under any other name does not FAIL that check — it never
 *    reaches it, and falls through to `valid: true`. A tampered category verifies as valid.
 *    Not one of the six throws, not one logs; each stops doing its job while the function
 *    around it returns success.
 *
 * 2. THE KEY IS NOT WHERE CALLERS LOOK. `recomputeKey` reads `cmb.key`, which is UNDEFINED on
 *    stored records — the key lives at `cmb.metadata.key`. So on a real stored record it
 *    returns null before attempting anything.
 *
 * 3. TWO DERIVATIONS ARE LIVE AND INDISTINGUISHABLE. createCMB mints with blockKeyV2 (Merkle);
 *    recomputeKey verifies with cmbKeyV1 (flat). Both emit the `cmb-` prefix, so `keyScheme`
 *    cannot tell them apart from the string. Measured across the live store: 3000/3000 sampled
 *    records address under Merkle; a captured sample split 134 Merkle / 16 flat.
 *
 * THE RULE THIS MODULE ENFORCES: absence is never silence. A caller asking for a record's
 * categories either gets them or gets an error naming the record — never `undefined` that a
 * conditional will read as "nothing to check".
 *
 * SCOPE: deliberately NOT the protocol half. Declaring the derivation inside the signed payload
 * changes the wire and belongs to the spec, which research owns. This module makes the call
 * sites honest with the record as it exists today.
 */

/** THE single answer to "where is this record's CAT7 container".
 *
 *  PRECEDENCE unchanged (`categories` before `categories`); the TEST is what changed. It was
 *  `record.categories ?? record.categories`, and `??` falls through only on null/undefined — so a
 *  non-null ciphertext STRING at `.categories` beat a perfectly valid container at `.categories`,
 *  and the module that exists to be the single answer answered wrongly. Fail-closed, so it was
 *  a false negative rather than a hole; but it is exactly the shape the reader migration puts
 *  in flight, where both keys live at once and one of them is ciphertext.
 *
 *  Returns null, never undefined — ONE absent value, so no caller can invent a distinction
 *  between two flavours of an absence that does not exist. */
function resolveCategories(record) {
  if (!record) return null;
  // ONE NAME. `categories` is the container and the only container. This used to walk a candidate
  // list so a record could carry it under either name — that is the name-check logic the founder
  // ruled out (2026-08-09, "remove all name check logic"), and removing it is what makes this
  // module's promise true rather than aspirational. With one name there is no precedence to get
  // wrong, and no second reader that can disagree with this one.
  //
  // A record carrying only the retired name does not resolve, and that refusal is the point: it
  // is legible at the boundary rather than half-read further in.
  const c = record.categories;
  return (c && typeof c === 'object') ? c : null;
}

/** The CAT7 container of a record, whatever level it sits at. Throws rather than returning
 *  undefined: a guard written as `if (categoriesOf(x))` would reintroduce the fail-open class,
 *  so there is nothing falsy to test. */
function requireCategories(record, where) {
  const cats = resolveCategories(record);
  if (!cats) {
    throw new Error(
      `${where}: record carries no CAT7 container (no .categories). ` +
      'Refusing rather than skipping — a check that silently does not run reports success it did not earn.',
    );
  }
  return cats;
}

/** Present-or-absent, for the callers that legitimately have both paths. Kept separate from
 *  requireCategories so that "I can cope with absence" is stated at the call site rather than
 *  implied by a truthiness test.
 *
 *  USAGE RULE — BINDING (CTO ruling, 2026-08-07). `hasCategories` MAY ONLY BE USED WHERE THE
 *  FALSE BRANCH RETURNS A VERDICT. It must NEVER guard a block that control can fall out of.
 *
 *      if (!hasCategories(r)) return { valid: false, error: 'cannot-verify: …' };   // CORRECT
 *      if (hasCategories(r)) { …verify… }   then control continues past it          // FORBIDDEN
 *
 *  The rule is named here rather than left to review because this accessor is the ONE thing
 *  this module exports that still has the shape the module exists to abolish: it returns a
 *  boolean, so a conditional can read absence as "nothing to check" and carry on. That is
 *  exactly the defect this file was written to close, and it is one refactor away from
 *  returning. requireCategories throws precisely so there is nothing falsy to skip on; reach
 *  for it unless you can state, at the call site, what the false branch RETURNS. */
function hasCategories(record) {
  return resolveCategories(record) !== null;
}

/** WHY the categories could not be read, as three distinct states rather than one falsy.
 *
 *  The distinction the CTO measured (2026-08-07): an E2E record verified BEFORE decryption
 *  carries its container as a base64 CIPHERTEXT STRING with `_e2e` attached. `hasCategories`
 *  correctly reports false — you must not be able to content-verify ciphertext — but reporting
 *  that as "record carries no CAT7 container" MISDESCRIBES it. The container is right there; it
 *  is merely unreadable yet, and the caller's remedy is "decrypt first", not "this record is
 *  malformed". A message that misdescribes why a check could not run is the smaller version of
 *  a check reporting success it did not earn, and it is the difference between a consumer
 *  debugging in five minutes or in an hour. */
function containerState(record) {
  // ONE ANSWER, DERIVED FROM THE RESOLVER — never re-derived here.
  //
  // This line was its own `??` lookup, and that is the defect this module's own header documents
  // as fixed: `??` falls through only on null/undefined, so a non-null ciphertext STRING under the
  // first name beat a perfectly valid object container under the second. The fix landed in
  // resolveCategories and was left live in the function beside it — so the module that exists to
  // be THE single answer had two, and they disagreed on exactly the record a migration puts in
  // flight, where both names are present and one of them is ciphertext.
  //
  // READABLE is now defined as "the resolver found an object", so the two cannot drift again.
  if (resolveCategories(record)) return 'readable';
  // The E2E path is IN PLACE ON ONE KEY: the container is either a ciphertext STRING or, once
  // decrypted, an object — the same key either way. So this asks about that one key, and cannot
  // reintroduce a second name by the back door.
  return typeof (record && record.categories) === 'string' ? 'ciphertext' : 'absent';
}

/** The `cannot-verify` reason for a record whose categories are not readable. Callers use this
 *  instead of writing the text, so the two states can never be collapsed back into one string. */
function unreadableReason(record) {
  return containerState(record) === 'ciphertext'
    ? 'cannot-verify: container is undecrypted ciphertext — decrypt before verifying, never after'
    : 'cannot-verify: record carries no CAT7 container';
}

/** A record's content address, from the ONE place it actually lives. Stored records carry it at
 *  `metadata.key`; wire records may carry it at the top level. Callers must never pick. */
function keyOf(record) {
  if (!record) return null;
  const k = record.metadata?.key ?? record.key;
  return typeof k === 'string' && k.length > 0 ? k : null;
}

/** Verification outcomes, as THREE states that never collapse.
 *  The collapse this prevents: `cannot-verify` falling into a falsy that a caller reads as
 *  "no mismatch", which is how an unverifiable record becomes an accepted one. */
const VERIFY = Object.freeze({
  VERIFIED: 'verified',
  MISMATCH: 'mismatch',
  CANNOT_VERIFY: 'cannot-verify',
});

/**
 * Check a record's address against a derivation, returning one of three states with a reason.
 * `derive` is supplied by the caller (blockKeyV2 / cmbKeyV1 / remixKeyV1) because THIS module
 * deliberately does not decide which scheme is authoritative — that is the open identity
 * question, and a module that guessed would be answering it by accident.
 */
function verifyAddress(record, derive) {
  const key = keyOf(record);
  if (!key) return { state: VERIFY.CANNOT_VERIFY, reason: 'record carries no key at metadata.key or key' };
  if (!hasCategories(record)) return { state: VERIFY.CANNOT_VERIFY, reason: unreadableReason(record) };
  let derived;
  try {
    derived = derive(resolveCategories(record));
  } catch (e) {
    return { state: VERIFY.CANNOT_VERIFY, reason: `derivation threw: ${e.message}` };
  }
  if (typeof derived !== 'string') return { state: VERIFY.CANNOT_VERIFY, reason: 'derivation returned no key' };
  return derived === key
    ? { state: VERIFY.VERIFIED, reason: null }
    : { state: VERIFY.MISMATCH, reason: `stored ${key.slice(0, 20)}… derived ${derived.slice(0, 20)}…` };
}

module.exports = { resolveCategories, requireCategories, hasCategories, containerState, unreadableReason, keyOf, verifyAddress, VERIFY };
