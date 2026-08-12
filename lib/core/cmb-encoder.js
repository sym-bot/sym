'use strict';


/**
 * @module @sym-bot/core/cmb-encoder
 * @description CMB Encoder — creates and encodes Cognitive Memory Blocks (CAT7).
 *
 * Agents extract structured CAT7 categories via their LLM, then pass them
 * to createCMB() for encoding and hashing. CMBs are immutable after
 * creation. Lineage tracks parent CMBs.
 *
 * See MMP v0.2.0 Section 8: CMBs (CAT7).
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const crypto = require('crypto');
const { encode, DIM } = require('./context-encoder');
const { CAT7_CATEGORIES } = require('./cmb');
// record-shape requires nothing, so this cannot cycle. It is the ONE answer to "where is the
// container" — the encoder must not re-derive it, or the answer and the check drift apart again.
const { resolveCategories, unreadableReason } = require('./record-shape');

// ── Content-Addressable Key ───────────────────────────────────

// Legacy content-only minter cmbKey() REMOVED at the cmb--only cutover (§19.1): the live
// path mints v1 only (cmbKeyV1). Legacy reading lives in the quarantined migration harness,
// not here. See the frozen-prefix note on the v1 section below.

// Legacy remix minter remixKey() REMOVED at the cmb--only cutover (§19.1). The receive/fuse
// path mints v1 remix keys only (remixKeyV1 via mintRemixKey).

// ── Content-Addressable Key, scheme v1 (`cmb1-`) ──────────────────
//
// Derivation: the MMP content-addressing derivation note (rev1).
// Fixes vs the legacy `cmb-` scheme. Identity scope: root = content; remix = content + parents.
// The remix scope NARROWED at the recompute fix — the receiver/author name term was removed, so
// an address is a function of what a block says and what it descends from, and of nothing else
// (see remixKeyV1). Authorship rides in mmp-sig-v2, which signs key + author + time + audience
// + parents:
//   - self-describing prefix `cmb1-` (legacy `cmb-` was NOT self-describing —
//     the md5→sha256 drift went undetected precisely because of that);
//   - full 256-bit SHA-256 (legacy truncated to 128 bits → 64-bit collision
//     resistance, which permits a ~2^64 validated-then-swap laundering attack);
//   - a fully specified, portable canonical serialization — NFC-normalised text,
//     netstring length-prefixing (injection-proof, no JSON/JCS dependency so
//     Node and Swift agree byte-for-byte), and a domain-separation tag;
//   - an explicit root/remix role tag so the two can never collide.
// Mood is text-only in the address (as in the legacy scheme), so the preimage
// contains no floating-point numbers and there is no number-formatting
// portability hazard. Vectors are excluded (local, encoder-specific artifacts).
const CMB_KEY_DOMAIN = 'mmp-cmb-v1\n';

/** Netstring length-prefix: `<utf8-byte-length>:<utf8 bytes>`. Injection-proof
 *  (a delimiter inside the text cannot shift a category boundary) and trivially
 *  identical across languages. */
function lp(s) {
  const b = Buffer.from(String(s ?? ''), 'utf8');
  return Buffer.concat([Buffer.from(`${b.length}:`, 'utf8'), b]);
}

/** Extract a category's text (string or `{text}`) and apply Unicode NFC. */
function categoryText(v) {
  const t = (typeof v === 'string' ? v : (v && v.text)) || '';
  return t.normalize('NFC');
}

/** The 7 CAT7 category texts, NFC-normalised, length-prefixed, in CAT7_CATEGORIES order. */
function categoriesPreimage(categories) {
  return CAT7_CATEGORIES.map(f => lp(categoryText(categories?.[f])));
}

/**
 * The prefix every key is minted with, FROZEN (founder canon §17). Post-cutover there is one
 * form — bare `cmb-` + 64-hex — and no dual-emit window (§19.1/§20): the freeze window plus the
 * fleet census make an emission flag unnecessary, and a flag IS the backcompat §19 forbids. The
 * prefix says only "this is a CMB"; the scheme lives inside the signed payload, and any future
 * scheme change rides there, NEVER the prefix.
 */
const V1_PREFIX = 'cmb-';

/**
 * Content-address key, scheme v1, for a ROOT CMB (no parents).
 * @param {object} categories - CAT7 category map (string or {text,...} per category).
 * @returns {string} V1_PREFIX + 64 hex chars.
 */
function cmbKeyV1(categories) {
  const parts = [Buffer.from(CMB_KEY_DOMAIN, 'utf8'), ...categoriesPreimage(categories), lp('root')];
  return V1_PREFIX + crypto.createHash('sha256').update(Buffer.concat(parts)).digest('hex');
}

/**
 * categoryKey — the content address of ONE CAT7 category (§7.4).
 *
 * `SHA-256(domain-tag ‖ lp(categoryName) ‖ lp(NFC(text)))`, full width. Untruncated because the
 * validated-then-swap analysis forbids it.
 *
 * THE FIELD NAME IS A PREIMAGE INPUT [MUST]. Omitting it collapses identical text across
 * positions — `focus:"done"` would share an address with `commitment:"done"`, and every empty
 * category everywhere would collapse together. That turns §7.3 corroboration into a category
 * error before any adversary exists: "two agents said the same thing" would silently include
 * "two agents said different things that happen to read alike". With the name bound in, dedup
 * still collapses within a category and corroboration is per-(category, text) — "the same `issue`".
 *
 * NOTE FOR THE SWIFT MIRROR: §7.4 writes the preimage as `domain-tag ‖ categoryName ‖
 * netstring(NFC(text))`, leaving open whether categoryName is itself length-prefixed. It is here,
 * because §7.6's categoryParentsCommitment writes `lp(categoryName)` explicitly and one convention
 * across the section is worth more than a literal reading of one line. Flagged to the CTO for
 * confirmation before Swift mirrors it.
 *
 * @param {string} categoryName - a CAT7 category name.
 * @param {string} text - the category's text (NFC-normalised here).
 * @returns {string} 64 lowercase hex — a digest, NOT a prefixed block key.
 */
function categoryKeyV1(categoryName, text) {
  const parts = [
    Buffer.from(CMB_KEY_DOMAIN, 'utf8'),
    lp(String(categoryName ?? '')),
    lp(String(text ?? '').normalize('NFC')),
  ];
  return crypto.createHash('sha256').update(Buffer.concat(parts)).digest('hex');
}

/** The seven categoryKeys of a CMB, in fixed CAT7 order. Absent categories contribute their empty text,
 *  which is a distinct value rather than a skipped leaf — the tree is always exactly seven wide. */
function categoryKeysV1(categories) {
  return CAT7_CATEGORIES.map((f) => categoryKeyV1(f, categoryText(categories?.[f])));
}

/**
 * Merkle root with PROMOTE-ODD [MUST, §7.4(b)] — deliberately NOT lib/merkle.js.
 *
 * lib/merkle.js pairs an odd node with itself (duplicate-the-last). That construction is fine
 * where it is used (attestation checkpoints) and MUST NOT be used here: §7.4(b) pins promotion
 * precisely so no duplicated-hash class exists at all. Seven is odd, so the rule fires on every
 * single block — an unpinned rule would mean two conformant implementations computing two
 * different addresses for the same content.
 *
 * The classic duplicate-leaf second-preimage (CVE-2012-2459 family) is closed by construction
 * rather than by this rule: the tree is fixed at seven leaves in fixed order, so its shape is
 * never attacker-chosen. Recorded here so it is not rediscovered as an open question.
 *
 * @param {string[]} leafHexes - ordered leaf digests as hex.
 * @returns {string} 64 lowercase hex root.
 */
const MERKLE_LEAF_PREFIX = Buffer.from([0x00]);
const MERKLE_NODE_PREFIX = Buffer.from([0x01]);

function merkleRootPromoteOdd(leafHexes) {
  // RFC 6962 domain separation [MUST]: leaves are hashed under 0x00 and internal nodes under
  // 0x01, so no value can be read as a leaf at one level and an internal node at another.
  //
  // Our leaves are already domain-tagged hashes, so that confusion is not obviously reachable
  // here — the separation is adopted anyway, because a construction safe by SHAPE is worth more
  // than one safe by an argument a future reader has to reconstruct.
  //
  // Operands are DECODED BYTES, not hex text, so the preimage is not a function of an encoding
  // choice. No lp() framing: both operands are fixed-width 32 bytes and therefore
  // self-delimiting — the only place in this file where length-prefixing is correctly absent.
  let level = leafHexes.map((h) =>
    crypto.createHash('sha256').update(Buffer.concat([MERKLE_LEAF_PREFIX, Buffer.from(h, 'hex')])).digest());
  if (level.length === 0) return crypto.createHash('sha256').update(Buffer.alloc(0)).digest('hex');
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        next.push(crypto.createHash('sha256')
          .update(Buffer.concat([MERKLE_NODE_PREFIX, level[i], level[i + 1]])).digest());
      } else {
        next.push(level[i]); // PROMOTE unchanged — never duplicate
      }
    }
    level = next;
  }
  return level[0].toString('hex');
}

/**
 * Block key, v2 record model (§7.4): the Merkle root over the seven categoryKeys in fixed CAT7
 * order, worn with the frozen `cmb-` prefix.
 *
 * Content-only, settled by Unit A. The formal collapse property holds and is strictly stronger
 * than WF-4: for any two blocks with byte-identical categories, key(C1) = key(C2) regardless of
 * author and time, so the later collapses to a citation. Time never enters, so retries are
 * idempotent. No assertion key sits beside it — the signature IS the assertion identity, and
 * the authored-event question lives in the descent ref.
 *
 * This also buys per-category serving for free: any single category is independently verifiable
 * against the root by its Merkle path. A receiver assembling several categories MUST verify every
 * path against ONE AND THE SAME root before treating them as one block [§7.4(c)] — per-category
 * proofs do not compose into block integrity, and verifying them in isolation would admit a
 * composite no one ever authored.
 */
function blockKeyV2(categories) {
  return V1_PREFIX + merkleRootPromoteOdd(categoryKeysV1(categories));
}

/**
 * Content-address key, scheme v1, for a REMIX CMB.
 *
 * Binds content + the parent SET (sorted, ascending UTF-8 byte order). NOTHING ELSE — and in
 * particular NO AGENT NAME. The address is a function of what the block SAYS and what it
 * DESCENDS FROM, so two agents that fuse the same content over the same parents produce the
 * same address, everywhere, forever.
 *
 * The name term this used to carry made the address a function of WHO computed it, which is
 * the reverse of what a content address is for. It also meant one slot with two meanings: the
 * mint site passed the AUTHOR, the fuse site passed the RECEIVER, and recompute passed
 * whichever of `createdBy`/`source` survived storage. A stored remix therefore could not
 * recompute its own address, and content-identical remixes forked.
 *
 * Authorship is not lost, it is relocated to where it can be proven: mmp-sig-v2 signs
 * key + author + time + audience + parents. The signature attests WHO; the address attests WHAT.
 *
 * @param {object} categories
 * @param {string[]} parents - parent CMB keys (order irrelevant; sorted here).
 * @returns {string} `cmb-` + 64 hex chars, distinct from any parent key.
 */
function remixKeyV1(categories, parents) {
  const ps = (Array.isArray(parents) ? parents.filter(Boolean) : [])
    .slice()
    .sort((a, b) => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8')));
  const parts = [
    Buffer.from(CMB_KEY_DOMAIN, 'utf8'),
    ...categoriesPreimage(categories),
    lp('remix'),
    lp(String(ps.length)),
    ...ps.map(p => lp(p)),
  ];
  return V1_PREFIX + crypto.createHash('sha256').update(Buffer.concat(parts)).digest('hex');
}

/**
 * Recompute the content-address key a CMB SHOULD have, dispatching on its key
 * scheme (prefix) and role (root vs remix, by lineage). Used by verification to
 * detect category-tampering. Returns null when the scheme is unknown (don't reject
 * on a scheme we can't recompute).
 */
/**
 * Which signing/keying scheme a key selects — BY STRUCTURE, not by prefix.
 *
 * The `cmb1-` prefix has been the scheme selector, and the cmb1- → cmb- migration removes it.
 * What survives the rename is the DIGEST LENGTH: scheme v1 is the full SHA-256 (64 hex), the
 * legacy scheme is its first 32 hex. Those can never be confused, so dispatching on length is
 * exactly as decisive as dispatching on the prefix was — and it keeps working for a rekeyed
 * `cmb-<64hex>` block, which under prefix dispatch would silently present as legacy and fail
 * every v1 verification.
 *
 * Both prefixes are accepted DURING and AFTER the migration: a key is v1 iff its digest is 64
 * hex, whichever prefix it wears.
 *
 * NON-HEX KEYS ARE LEGACY BY DEFAULT, and that is load-bearing rather than lazy: the heuristic
 * SVAF path mints synthetic fallback identifiers like `cmb-<base36>-<rand>` for blocks that
 * arrive without a key. Those are not content addresses and must never be routed into v1
 * verification, so anything that is not /^cmb1?-[0-9a-f]+$/ falls to legacy.
 *
 * @param {string} key
 * @returns {'v1'|'legacy'}
 */
// FAIL-CLOSED dispatch (§19.1): a key is v1 iff it is bare `cmb-` + EXACTLY 64 LOWERCASE hex.
// Everything else REJECTS — transitional `cmb1-`, legacy `cmb-<32hex>`, synthetic fallbacks,
// malformed, AND the uppercase-hex variant. Case-SENSITIVE deliberately: minting is always
// lowercase (digest('hex')), so an uppercase-hex key is unreachable by honest minting but,
// under a case-insensitive test, would be a SECOND accepted string for the same content —
// a distinct store filename / Map key / dedup entry that sameKey would fold to "same address".
// That aliasing/shadowing surface has no place in the release whose thesis is one frozen form.
// `keyScheme` returns 'v1' or 'reject' — never 'legacy'.
const CMB_V1_KEY_RE = /^cmb-[0-9a-f]{64}$/;
function keyScheme(key) {
  return (typeof key === 'string' && CMB_V1_KEY_RE.test(key)) ? 'v1' : 'reject';
}

/**
 * Do two keys denote the SAME content address, ignoring which prefix they wear?
 *
 * Content integrity compares a recomputed key against the stored one. That comparison was a
 * plain string equality, which the cmb1- → cmb- migration breaks for every rekeyed block: the
 * digest is identical, the prefix is not, and the block is rejected as 'content-mismatch' even
 * though its categories are untouched and its signature is valid. Found by the migration dry-run —
 * all 4,742 rekeyed blocks re-signed cleanly and then failed integrity for this reason alone.
 *
 * Same SCHEME and same DIGEST is the real question. Schemes are still compared strictly, so a
 * 32-hex legacy key can never satisfy a 64-hex v1 expectation.
 *
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function sameKey(a, b) {
  // Post-cutover a v1 key is the ONE canonical form — bare `cmb-<64hex>`, lowercase (keyScheme
  // is case-sensitive). So identity is plain string equality between two valid v1 keys: no
  // prefix variance to normalise, no case-folding (folding would re-open the uppercase alias).
  // Non-v1 keys never match anything (fail-closed).
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (keyScheme(a) !== 'v1' || keyScheme(b) !== 'v1') return false;
  return a === b;
}

/**
 * ADDRESS SCHEMES — the derivations a v1 `cmb-` key can have been minted under.
 *
 * THE PROBLEM THIS NAMES: the prefix does not identify the derivation. `keyScheme` reports 'v1'
 * for all of them because they are all bare `cmb-` + 64 hex — so a key cannot tell you how it
 * was computed, and a verifier that assumes one derivation silently disagrees with a record
 * minted under another. Measured on this library: createCMB mints `block-v2`, and recomputeKey
 * verified with `root-v1`, so NO record this library minted could be recomputed by its own
 * recompute function.
 *
 * These are stated as data rather than as branches so that "which derivations are live" is a
 * list someone can read, extend, and count — not a chain of ifs to reverse-engineer.
 */
const ADDRESS_SCHEMES = Object.freeze({
  /** Merkle root over per-category keys. What createCMB mints for a root today. */
  'block-v2': (categories) => blockKeyV2(categories),
  /** Flat hash over the category preimage. The pre-Merkle root derivation; still in the store. */
  'root-v1': (categories) => cmbKeyV1(categories),
  /** Binds content + the parent SET. What the receive/fuse path mints. */
  'remix-v1': (categories, parents) => remixKeyV1(categories, parents),
});

/** Which schemes can legitimately have produced a record of this STRUCTURAL ROLE, in the order
 *  a reader should prefer them. A record with parents is a remix and is never a root. */
function candidateSchemes(parents) {
  return parents.length ? ['remix-v1'] : ['block-v2', 'root-v1'];
}

/**
 * Recompute a record's content address under the PRIMARY derivation for its structural role.
 *
 * FIXED (2026-08-07), and both halves were wrong in a way that cancelled into silence:
 *
 *   1. It read `cmb.key`, which is UNDEFINED on every record createCMB mints — the key lives at
 *      `cmb.metadata.key`. So it returned null before attempting anything, and null read to
 *      callers as "not recomputable, do not reject". A verification that never ran.
 *   2. It recomputed a root with `cmbKeyV1` (flat) while createCMB mints `blockKeyV2` (Merkle).
 *      Had (1) not masked it, every minted record would have come back MISMATCHED — a tamper
 *      verdict on an untouched record.
 *
 * The reason this survived: the tests built records BY HAND with a top-level `key` and a flat
 * root address — a shape createCMB never produces. The function was verified against the record
 * it expected rather than the record the system mints.
 *
 * Returns null ONLY when the record carries no readable CAT7 container. For anything else, use
 * classifyAddress: a bare null cannot distinguish "could not check" from "did not match", and
 * that collapse is what let this go unnoticed.
 */
function recomputeKey(cmb) {
  const categories = resolveCategories(cmb);
  if (!categories) return null;
  const parents = (cmb.lineage && Array.isArray(cmb.lineage.parents)) ? cmb.lineage.parents : [];
  // AC-1.1: recompute reads FIELDS and PARENTS only. It must never consult `createdBy`,
  // `source`, or any other name-bearing slot — those are receiver-local, mutated by storage,
  // and were why a stored remix could not recompute the address it was minted under.
  return ADDRESS_SCHEMES[candidateSchemes(parents)[0]](categories, parents);
}

/**
 * Check a record against its own address and SAY WHICH DERIVATION reproduced it.
 *
 * Three states that never collapse — `verified` / `mismatch` / `cannot-verify` — because the
 * question "is this record's content the content it was addressed under" has three honest
 * answers and the old null had one. A record we cannot check must never read as a record that
 * did not mismatch.
 *
 * WHY IT TRIES MORE THAN ONE DERIVATION FOR A ROOT: the derivation is not declared anywhere in
 * the record, and the store genuinely holds both — `block-v2` from createCMB and `root-v1` from
 * before the Merkle cutover. Refusing every pre-cutover record would call a whole population
 * tampered, and hard-coding one derivation is precisely the defect being fixed. So the honest
 * answer names the scheme that matched, and a caller wanting strictness asserts on `.scheme`
 * rather than being silently given a choice someone else made.
 *
 * This does NOT weaken the check. Finding content that hashes to a stored key under ANY of two
 * derivations is 2^-255 rather than 2^-256; the guarantee is unchanged and the ambiguity is now
 * reported instead of resolved by assumption.
 *
 * SCOPE: declaring the derivation INSIDE the signed payload would remove the ambiguity at the
 * source. That changes the wire and belongs to the spec, not to this function.
 */
function classifyAddress(cmb) {
  const key = cmb && (cmb.metadata?.key ?? cmb.key);
  if (typeof key !== 'string' || !key) {
    return { state: 'cannot-verify', scheme: null, reason: 'record carries no key at metadata.key or key' };
  }
  if (keyScheme(key) !== 'v1') {
    return { state: 'cannot-verify', scheme: null, reason: `key is not a v1 address: ${key.slice(0, 16)}…` };
  }
  const categories = resolveCategories(cmb);
  if (!categories) {
    return { state: 'cannot-verify', scheme: null, reason: unreadableReason(cmb) };
  }
  const parents = (cmb.lineage && Array.isArray(cmb.lineage.parents)) ? cmb.lineage.parents : [];
  const tried = [];
  for (const name of candidateSchemes(parents)) {
    const derived = ADDRESS_SCHEMES[name](categories, parents);
    if (derived === key) return { state: 'verified', scheme: name, reason: null };
    tried.push(name);
  }
  return {
    state: 'mismatch',
    scheme: null,
    reason: `stored ${key.slice(0, 20)}… matches none of [${tried.join(', ')}] for a ` +
            `${parents.length ? 'remix' : 'root'} record`,
  };
}

// The one scheme new CMBs are minted under, FROZEN to v1 at the cutover (§19.1): no legacy
// option, no env override. Kept as an exported constant so a consumer can record provenance
// and the surface test can assert it — it will only ever read 'v1'.
const MINT_SCHEME = 'v1';

/**
 * Mint a v1 remix key (bare `cmb-` + 64-hex; binds content + the parent SET, and no name),
 * distinct from its parents. Used by the receive/fuse path. v1-only post-cutover (§19.1).
 * @param {object} categories
 * @param {string[]} parents - parent CMB keys (the incoming key, plus any others).
 * @returns {string}
 */
function mintRemixKey(categories, parents) {
  const ps = Array.isArray(parents) ? parents.filter(Boolean) : [];
  return remixKeyV1(categories, ps);
}

// ── Category Encoding ────────────────────────────────────────────

/**
 * Encode a single category's text into a unit-normalized vector.
 *
 * @param {string} text - Category text to encode.
 * @returns {number[]} Unit-normalized vector of dimension DIM.
 */
function encodeCategory(text) {
  const { h1 } = encode(text);
  return h1;
}

// ── CMB Creation ──────────────────────────────────────────────

/**
 * Create an immutable CMB from structured CAT7 categories.
 *
 * The agent LLM extracts the 7 categories; this function encodes them
 * into vectors and produces a content-addressed CMB key.
 *
 * See MMP v0.2.0 Section 8: CMBs (CAT7).
 *
 * @param {object} opts
 * @param {object} opts.categories - CAT7 category texts { focus, issue, intent, motivation, commitment, perspective, mood }.
 *   Mood may include { text, valence, arousal }.
 * @param {string} opts.createdBy - Agent name that created this CMB.
 * @param {object} [opts.lineage] - { parents: [key1, key2], method: 'SVAF-v1' }
 * @param {string} opts.createdBy - the author's agent id; REQUIRED (§7.2), never defaulted.
 * @param {object} [opts.categoryParents] - per-category descent refs, keyed by CAT7 category name (§7.3).
 * @param {string} [opts.room] - audience.
 * @param {string|null} [opts.to] - directed recipient's agent id, or null for a broadcast.
 * @returns {{categories: object, metadata: object}} The two-section record (§7.1): `categories` is what
 *   the agent says, `metadata` is what the mesh proves. No third section exists.
 */
function createCMB(opts = {}) {
  // §7.2 [MUST]: createdBy is the agent id and is REQUIRED. It used to default to the string
  // 'unknown', which minted a record whose author could never be resolved to a key — an
  // unverifiable block created silently, at the moment it was easiest to prevent. That is the
  // defect class this boundary exists to delete, so it fails closed.
  const createdBy = opts.createdBy;
  if (typeof createdBy !== 'string' || createdBy.length === 0) {
    throw new Error('createCMB requires createdBy — the author\'s agent id (§7.2); it is signature-bound and cannot be defaulted');
  }
  const createdTimestamp = Date.now();

  if (!opts.categories || typeof opts.categories !== 'object') {
    throw new Error('CMB requires categories — the agent LLM extracts the CAT7 categories, not the protocol');
  }

  // ── Section 1: what the agent SAYS ────────────────────────────────────────────
  const categories = {};
  for (const f of CAT7_CATEGORIES) {
    const value = opts.categories[f];
    // NO VECTOR. Emitters MUST NOT include embedding vectors (§7.1) — and the reason is
    // security, not tidiness.
    //
    // A vector is excluded from the address (v1.1 §8 says so too), and §7.6's signature binds
    // the Merkle root, which is over category TEXT. So a vector riding inside a signed record is
    // covered by NEITHER the address NOR the signature: it can be rewritten in flight and the
    // block still verifies and still recomputes its own address. SVAF then admits on drift
    // computed FROM THAT VECTOR, while a human reads the text. Text says one thing, vector says
    // another, the receiver admits on the vector.
    //
    // That is an admission-steering injection that needs no dishonest sender — any relay in the
    // path can do it. Demonstrated against this code before the change: rewriting every
    // component of a signed category's vector left verifyCMB returning {signed:true, valid:true}.
    //
    // Receiver-local encoding closes it by construction: there is nothing in transit to tamper
    // with. It is also the only encoding that MEANS anything to the receiver — SVAF is
    // receiver-autonomous and kernel-local, so drift is measured against the receiver's anchors
    // in the receiver's kernel, and a sender's vector is comparable only if kernels match,
    // which nothing guarantees.
    if (f === 'mood' && typeof value === 'object' && value.text) {
      categories[f] = {
        text: value.text,
        valence: value.valence ?? 0,
        arousal: value.arousal ?? 0,
      };
    } else {
      const text = (typeof value === 'string' ? value : value?.text) || 'neutral';
      categories[f] = { text };
    }
  }

  // Per-category metadata (§7.3): each category carries its own address and its own semantic
  // descent. This is the section's reason to exist — admission verdicts, anchors, membrane
  // weights and carry-forward are all per-category, so the record now matches the granularity
  // the rest of the system already works at. Block-level parents cannot express "issue
  // descends from the peer's issue while focus continues my own line".
  //
  // The agent's TIMELINE stays block-level [MUST]: one HEAD per agent, the block is the
  // emission event. These parents are semantic descent only, never a second timeline.
  const categoryParents = opts.categoryParents || {};
  for (const f of CAT7_CATEGORIES) {
    categories[f].meta = {
      key: categoryKeyV1(f, categories[f].text),
      parents: Array.isArray(categoryParents[f]) ? [...categoryParents[f]] : [],
    };
  }

  // ── Section 2: what the mesh PROVES ───────────────────────────────────────────
  // Placement rule (§7.1): if admission may paraphrase it, it is a category; if cryptography or
  // graph-walking needs it byte-exact, it is metadata. There is no third section.
  //
  // Normatively ABSENT [MUST NOT appear]: `source` (a receiver-composed name string — the
  // holder-vs-author defect), `originTimestamp` (transport-frame concern; the frame may carry
  // emission time, the record does not), `ancestors` (computed by reachability, never
  // carried), any uuid, any role marker, any kind token. Every time category carries the
  // `Timestamp` suffix.
  return {
    categories,
    metadata: {
      key: blockKeyV2(categories),
      createdBy,
      createdTimestamp,
      lineage: opts.lineage || null,
      room: opts.room ?? null,
      to: opts.to ?? null,
    },
  };
}

// ── Rendering ─────────────────────────────────────────────────

/**
 * Render a CMB to a human-readable string.
 *
 * ASKS THE RESOLVER rather than reaching for the container itself. This function read
 * `cmb.categories[f]` directly, which threw on any record handed to it in a shape it did not
 * expect — and a renderer that throws takes down the caller that was only trying to LOG. Going
 * through record-shape also means it cannot become the second module that resolves the container
 * its own way, which is the defect that whole module exists to prevent.
 *
 * A record with no readable container renders as empty rather than throwing: rendering is a
 * courtesy for humans, so it must never be the thing that fails a path.
 *
 * @param {object} cmb - A CMB record, or a bare CAT7 container.
 * @returns {string} Semicolon-delimited category summary.
 */
function renderContent(cmb) {
  const cats = resolveCategories(cmb) || (cmb && typeof cmb === 'object' ? cmb : null);
  if (!cats) return '';
  return CAT7_CATEGORIES
    .filter(f => cats[f] && cats[f].text && cats[f].text !== 'neutral')
    .map(f => {
      if (f === 'mood' && cats[f].valence !== undefined) {
        return `${f}: ${cats[f].text} (v:${cats[f].valence}, a:${cats[f].arousal})`;
      }
      return `${f}: ${cats[f].text}`;
    })
    .join('; ');
}

// ── Vector Math ───────────────────────────────────────────────

/**
 * Compute cosine similarity between two vectors.
 *
 * @param {number[]} a - First vector.
 * @param {number[]} b - Second vector.
 * @returns {number} Cosine similarity in [-1, 1], or 0 if inputs are invalid.
 */
function cosineSimilarity(a, b) {
  if (!a || !b || a.length !== b.length || a.length === 0) return 0;
  let dot = 0, normA = 0, normB = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  const denom = Math.sqrt(normA) * Math.sqrt(normB);
  return denom > 1e-8 ? dot / denom : 0;
}

/**
 * L2-normalize a vector in place (returns new array).
 *
 * @param {number[]} v - Input vector.
 * @returns {number[]} Unit-normalized copy, or original if near-zero norm.
 */
function l2Normalize(v) {
  let norm = 0;
  for (let i = 0; i < v.length; i++) norm += v[i] * v[i];
  norm = Math.sqrt(norm);
  if (norm < 1e-8) return v;
  return v.map(x => x / norm);
}

module.exports = {
  categoryKeyV1,
  categoryKeysV1,
  merkleRootPromoteOdd,
  blockKeyV2,
  keyScheme,
  sameKey,
  createCMB,
  cmbKeyV1,
  remixKeyV1,
  mintRemixKey,
  recomputeKey,
  classifyAddress,
  ADDRESS_SCHEMES,
  lp,
  CMB_KEY_DOMAIN,
  MINT_SCHEME,
  encodeCategory,
  renderContent,
  cosineSimilarity,
  l2Normalize,
  CAT7_CATEGORIES,
};
