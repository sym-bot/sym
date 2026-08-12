'use strict';
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { resolveCategories, unreadableReason } = require('./record-shape.js');

/**
 * @module @sym-bot/core/cmb-signing
 * @description Ed25519 CMB authentication — sign on author, verify on receive.
 *
 * Every CMB is signed by its author's Ed25519 identity key (the same key the
 * node announces in its handshake). The receiver verifies the signature against
 * the sending peer's announced public key; a CMB whose signature is malformed,
 * forged, or fails verification is rejected before it can reach the application
 * layer.
 *
 * The signed payload binds the content-address key (a SHA-256 hash of the CAT7
 * category texts — see `cmbKey`), the author, and the creation time. Tampering the
 * categories changes the key (so the signature no longer matches); forging the
 * author requires their private key. This is the end-to-end integrity +
 * authenticity layer above transport identity.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const crypto = require('crypto');
const { lp, keyScheme, sameKey, blockKeyV2 } = require('./cmb-encoder');
const { CAT7_CATEGORIES } = require('./cmb');

// Fixed ASN.1 DER prefixes for raw 32-byte Ed25519 keys (RFC 8410). The node
// identity stores keys as raw 32-byte values (base64url); Node's crypto needs
// them DER-wrapped to build KeyObjects.
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex'); // private
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex'); // public

function privateKeyObject(rawB64url) {
  const raw = Buffer.from(rawB64url, 'base64url');
  if (raw.length !== 32) throw new Error('Ed25519 private key must be 32 raw bytes');
  return crypto.createPrivateKey({ key: Buffer.concat([ED25519_PKCS8_PREFIX, raw]), format: 'der', type: 'pkcs8' });
}

function publicKeyObject(rawB64url) {
  const raw = Buffer.from(rawB64url, 'base64url');
  if (raw.length !== 32) throw new Error('Ed25519 public key must be 32 raw bytes');
  return crypto.createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
}

/**
 * Canonical decimal ASCII for an integer [MUST, §7.6(4)]: integer milliseconds, no leading
 * zeros, no sign, no separators, no exponent. JS `String(n)` gives exactly this for a safe
 * non-negative integer and something else for everything else, so the guard is not decorative —
 * a float or a negative reaching the payload would produce bytes Swift cannot reproduce.
 */
function decimal(n) {
  if (!Number.isSafeInteger(n) || n < 0) {
    throw new Error(`mmp-sig-v2: expected a non-negative safe integer, got ${JSON.stringify(n)}`);
  }
  return String(n);
}

/** Bytewise sort — descents and parents are SETS, so their order must not change the bytes.
 *  Buffer.compare is remixKeyV1's precedent and the one Swift mirrors. */
function sortedBytewise(list) {
  return [...list].map(String).sort((a, b) => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8')));
}

/**
 * categoryParentsCommitment (§7.6) — the parallel commitment that binds per-category descent.
 *
 * Category parents enter the signature HERE rather than through the Merkle root, and that is
 * REFUTED-not-dispreferred: folding lineage into the root would make the root
 * lineage-dependent, which negates the collapse property and thereby reopens the Rule A
 * self-loop. The root stays content-only; descent is attested alongside it.
 *
 * Its own domain tag, versioned independently: it is its own construction with its own
 * lifecycle, and sharing the payload's tag would put two different hashes in one preimage
 * space.
 *
 * Counts are length-prefixed at both levels so ["ab","c"] and ["a","bc"] cannot collide, and
 * an empty parent list (no descent asserted) stays distinguishable from an absent category.
 *
 * @returns {string} 64 lowercase hex.
 */
function categoryParentsCommitment(categories) {
  const parts = [Buffer.from('mmp-fp-v1\n', 'utf8')];
  for (const f of CAT7_CATEGORIES) {
    const refs = sortedBytewise(categories?.[f]?.meta?.parents || []);
    parts.push(lp(f), lp(decimal(refs.length)));
    for (const r of refs) parts.push(lp(r));
  }
  return crypto.createHash('sha256').update(Buffer.concat(parts)).digest('hex');
}

/**
 * The v2 signing payload (§7.6), byte-exact.
 *
 * THE FRAMING RULE [MUST]: after the domain tag the payload is UNIFORMLY netstring-framed
 * ASCII — no raw bytes anywhere, every hash as lowercase hex text. The domain tag itself is raw
 * with a trailing newline, because a fixed leading constant is self-delimiting; everything after
 * it is lp(). That one rule is what stops the next ten framing questions being asked.
 *
 * The key enters as the FULL PREFIXED WIRE KEY, not the raw root and not bare hex: it is what
 * actually travels in refs, parents and fetches, and it binds the SCHEME too, since digest
 * length is what distinguishes v1 from legacy.
 *
 * Parents are signature-bound, which closes v1.1's unsigned-lineage gap — lineage stops being
 * an unattested claim and becomes attested fact.
 */
function signingPayloadV2(cmb) {
  // NO DEFAULTS IN A PREIMAGE. Every substitution below used to be silent: an absent metadata
  // section became `{}`, an absent key became `''`, an absent author became `''`. The result was
  // a VALID SIGNATURE OVER VALUES NOBODY SUPPLIED — bytes that verify, attesting to a record that
  // was never asserted. A missing input to a signature is not a small gap to paper over; it is
  // the one place where guessing produces something indistinguishable from the real thing.
  //
  // `room` and `to` keep their `?? ''`: absent room means BROADCAST and absent `to` means
  // undirected. Those are the author's actual assertions, not gaps.
  if (!cmb || !cmb.metadata) {
    throw new Error('mmp-sig-v2: refusing to sign a record with no metadata section');
  }
  const m = cmb.metadata;
  if (typeof m.key !== 'string' || !m.key) {
    throw new Error('mmp-sig-v2: refusing to sign a record with no key');
  }
  const key = m.key;
  if (keyScheme(key) !== 'v1') {
    throw new Error('mmp-sig-v2: refusing a signing payload for a non-v1 key');
  }
  if (typeof m.createdBy !== 'string' || !m.createdBy) {
    throw new Error('mmp-sig-v2: refusing to sign a record with no author — an empty author is a signature attesting to nobody');
  }
  // An absent lineage is legitimately "no parents". A PRESENT lineage whose parents are not an
  // array is malformed, and defaulting it to [] would sign a claim of no-descent over a record
  // that asserted descent badly.
  if (m.lineage != null && m.lineage.parents != null && !Array.isArray(m.lineage.parents)) {
    throw new Error('mmp-sig-v2: lineage.parents must be an array when present');
  }
  const parents = sortedBytewise(m.lineage?.parents ?? []);
  const parts = [
    Buffer.from('mmp-sig-v2\n', 'utf8'),
    lp(key),
    lp(m.createdBy.normalize('NFC')),
    lp(decimal(m.createdTimestamp)),
    lp(String(m.room ?? '').normalize('NFC')),
    lp(String(m.to ?? '').normalize('NFC')),
    lp(decimal(parents.length)),
    ...parents.map((p) => lp(p)),
    lp(categoryParentsCommitment(cmb?.categories)),
  ];
  return Buffer.concat(parts);
}

/**
 * sigDigest — names WHICH assertion, for a descent ref (§7.5).
 *
 * A digest over the PAYLOAD, never over the signature bytes. Node's Ed25519 is deterministic
 * (RFC 8032) so a bytes-based digest would pass every test here; Apple CryptoKit's is
 * randomized, so the same assertion would produce a different ref on iOS. Hex text, because
 * refs are strings that travel in JSON, are compared, and are stored.
 *
 * It also buys a property worth naming: a ref is computable from metadata ALONE — no signature
 * fetch is needed to name an assertion.
 */
function sigDigestV2(cmb) {
  return crypto.createHash('sha256').update(signingPayloadV2(cmb)).digest('hex');
}

/**
 * Audience check: a record's signed `room` MUST match the receiver's room, and its signed `to`
 * MUST be empty (broadcast) or the receiver's nodeId.
 *
 * SEPARATE FROM SIGNATURE VERIFICATION, and both are required. The signature proves the audience
 * was not altered; this proves the record is addressed to THIS receiver. A valid signature over
 * someone else's audience is exactly what a replay looks like, so verifying alone would admit it.
 * Reported distinctly from tampering, because "not for you" and "forged" call for different
 * operator responses.
 * @param {object} cmb
 * @param {string} receiverRoom - the verifying node's room (the channel's room).
 * @param {string} receiverNodeId - the verifying node's nodeId.
 * @returns {{ ok: boolean, reason?: string }}
 */
function checkAudience(cmb, receiverRoom, receiverNodeId) {
  // ONE NAME: `room`. The audience moved into metadata with the two-section record, renamed
  // in the same signing-scheme change; this read used to fall back to the legacy audience key
  // for pre-boundary records. That fallback is REMOVED — measured 2026-08-09 across 6,773 stored
  // records: 0 carried the legacy key, 4,005 carried `room`, and no legacy write remains.
  // It was reading a name nothing produces.
  //
  // Note what the fallback would have cost if it HAD matched: a record whose audience lived under
  // the dead name would be checked against it and pass, while the signature binds `room` — so the
  // check and the signature would be asserting different things about the same record.
  // FAIL CLOSED WHEN THE AUDIENCE CANNOT BE READ. A pre-boundary record carries its audience
  // under the retired name, so after that read was removed there was nothing here to check — and
  // an absent room means BROADCAST, so such a record sailed through as addressed to everyone.
  // That is a cross-audience replay admitted by a check that thought it had nothing to do, and it
  // is strictly worse than the fallback it replaced: closing one hole while opening another.
  //
  // So an unreadable audience is refused rather than waved through. Note this is NOT a name
  // check — it never asks which name the audience sits under. It asks whether this record has the
  // section the audience is defined to live in, and refuses when it does not.
  if (!cmb || !cmb.metadata) return { ok: false, reason: 'unreadable-audience' };
  const m = cmb.metadata;

  // A KEY WE CANNOT CLASSIFY IS NOT AN AUDIENCE WE CAN CLEAR. This returned ok, which meant an
  // unrecognised or malformed key SKIPPED the audience check entirely — the permissive answer to
  // the case where we know least. verifyCMB rejects such records anyway, so this was defence in
  // depth pointed the wrong way: a second gate whose default was to open.
  if (typeof m.key !== 'string' || keyScheme(m.key) !== 'v1') {
    return { ok: false, reason: 'unclassifiable-key' };
  }

  // A RECEIVER THAT HAS NOT STATED ITS OWN ROOM CANNOT JUDGE AN AUDIENCE. The guard used to be
  // `receiverRoom != null`, so a caller that omitted it turned the comparison off and every
  // audience passed — the check silently became a no-op precisely when the receiver was
  // misconfigured. Refusing here makes that a visible error at the boundary instead of an
  // invisible acceptance.
  if (receiverRoom == null) return { ok: false, reason: 'receiver-room-unknown' };

  // An ABSENT room on the record still means BROADCAST, and that is semantics rather than a
  // fallback: the author addressed everyone. It is kept, and it is the only permissive path left.
  const room = m.room != null ? String(m.room).normalize('NFC') : '';
  if (room && room !== String(receiverRoom).normalize('NFC')) {
    return { ok: false, reason: 'wrong-audience' };
  }
  const to = m.to != null ? String(m.to).normalize('NFC') : '';
  if (to && to !== String(receiverNodeId ?? '').normalize('NFC')) {
    return { ok: false, reason: 'wrong-recipient' };
  }
  return { ok: true };
}

/**
 * Sign a CMB in place with the author's raw Ed25519 private key (base64url).
 * Sets `cmb.sig` (base64url) and `cmb.sigAlg = 'ed25519'`. Returns the CMB.
 */
function signCMB(cmb, privateKeyB64url) {
  // v2 record (§7.1 two sections): sign the v2 payload and put the signature where the rest of
  // the provable facts live. RE-SIGNING A v1 BLOCK IS FORBIDDEN — it would change what the
  // signature attests — so there is no path here that upgrades an old record.
  if (cmb && cmb.metadata) {
    const sig = crypto.sign(null, signingPayloadV2(cmb), privateKeyObject(privateKeyB64url));
    cmb.metadata.sig = sig.toString('base64url');
    cmb.metadata.sigAlg = 'ed25519';
    return cmb;
  }
  // No v1 signing path. Emitters produce the two-section record and nothing else, and §7.6
  // forbids re-signing a pre-boundary block — it would change what the signature attests.
  // A flat record reaching here is either an old caller or an attempt to mint under the retired
  // scheme; both are refused rather than quietly served.
  throw new Error(
    'signCMB: only the two-section record model is signable (§7.1). A pre-boundary record is ' +
    'READABLE and grandfathers as unverified-legacy, but re-signing it is forbidden (§7.6) — ' +
    'it would change what the signature attests.'
  );
}

/**
 * Verify a CMB's signature against the author's raw Ed25519 public key (base64url).
 * @returns {{ signed: boolean, valid: boolean, error?: string }}
 *   - signed=false             → no signature present (unsigned CMB).
 *   - signed=true, valid=false → signature present but failed → reject (tamper/spoof).
 *   - signed=true, valid=true  → authentic, untampered.
 */
function verifyCMB(cmb, publicKeyB64url) {
  // v2 record: verify against the v2 payload. Verification is against the AUTHOR's pinned key,
  // resolved by agent id — the caller's job, and never the delivering peer's [MUST §7.6].
  if (cmb && cmb.metadata) {
    const m = cmb.metadata;
    if (!m.sig || m.sigAlg !== 'ed25519') return { signed: false, valid: false };
    if (!publicKeyB64url) return { signed: true, valid: false, error: 'no-public-key' };
    if (keyScheme(m.key) !== 'v1') return { signed: true, valid: false, error: 'legacy-key-rejected' };
    try {
      const ok = crypto.verify(null, signingPayloadV2(cmb), publicKeyObject(publicKeyB64url), Buffer.from(m.sig, 'base64url'));
      if (!ok) return { signed: true, valid: false, error: 'bad-signature' };
      // Content integrity: the signed address MUST be the address of the categories actually
      // carried. Under content-only addressing this is a pure recompute — no author, no time.
      // FAIL-CLOSED. This was `if (cmb.categories && …) { verify }` — a check GUARDED BY THE
      // PRESENCE OF THE CONTAINER, so a record carrying its categories under any other name
      // never reached the verification and fell through to `valid: true`. A tampered category
      // verified as valid. Absence is now its own verdict, never a skip.
      // RESOLVE ONCE, THEN USE THE RESOLVED VALUE. This was two separate answers to one
      // question: the guard asked record-shape whether a container existed, then the next line
      // re-derived it locally with `cmb.categories ?? cmb.categories`. The answer and the check
      // drift apart — the same defect as a guard naming the container, one layer up. With a
      // mixed record (ciphertext at .categories, valid container at .categories) the guard passed
      // and the derivation then hashed the CIPHERTEXT, turning an untampered record into a
      // `content-mismatch` TAMPER verdict. A cannot-verify collapsed into an accusation, at
      // the one boundary where the three classes matter most.
      const cats = resolveCategories(cmb);
      if (!cats) {
        // Two reasons, never merged: an ABSENT container is a malformed record; a CIPHERTEXT
        // container is an E2E record being verified before decryption. Both are cannot-verify,
        // and telling the caller which one is the whole value of the message.
        return { signed: true, valid: false, error: unreadableReason(cmb) };
      }
      const expected = blockKeyV2(cats);
      if (!sameKey(expected, m.key)) return { signed: true, valid: false, error: 'content-mismatch' };
      return { signed: true, valid: true };
    } catch (e) {
      return { signed: true, valid: false, error: e.message };
    }
  }
  // Pre-boundary blocks GRANDFATHER as unverified-legacy (§7.8). They are readable and never
  // re-keyed — recomputing history is rewriting it — but they carry no v2 attestation.
  if (cmb && cmb.sig && cmb.sigAlg === 'ed25519' && !cmb.metadata) {
    // Two different pre-boundary populations, and collapsing them loses a guarantee.
    //
    //   A v1 KEY (bare cmb-<64hex>) was minted under a scheme we still recognise, so the record
    //   is GRANDFATHERED: readable, unattested, never re-signed (§7.6, §7.8).
    //
    //   A NON-v1 key (cmb1-, legacy cmb-<32hex>, uppercase-hex, malformed) was refused by the
    //   §19.1 fail-closed membrane before the boundary and is refused the same way after. That
    //   is a REJECTION, not a grandfathering, and reporting it as "unverified-legacy" would
    //   quietly promote a refused block into a merely-unattested one.
    return keyScheme(cmb.key) === 'v1'
      ? { signed: true, valid: false, error: 'unverified-legacy' }
      : { signed: true, valid: false, error: 'legacy-key-rejected' };
  }
  // UNREACHABLE BY MEASUREMENT — the legacy verification arm that stood here is DELETED
  // (CTO ruling, 2026-08-07). Every record with `.metadata` returns from the v2 branch above;
  // every record with a top-level `.sig` and no `.metadata` returns `unverified-legacy` from
  // the grandfather branch. Nothing could reach what followed, so nothing behind this line
  // ever ran.
  //
  // THE EVIDENCE, kept here because it must outlive the lines it removed: an append-to-file
  // marker at the arm's entry, with the full suite run, produced 0 hits — against a POSITIVE
  // CONTROL on the v2 branch entry that fired 27 times in the SAME run. Zero from a working
  // instrument, not zero from a dead one. Without that control, "we found no hits" is
  // unfalsifiable and this deletion would be unsafe.
  //
  // It was fail-CLOSED, so there was no exposure. It was deleted because ~26 lines DESCRIBED a
  // content-integrity recompute they never performed, and a reader of verifyCMB would believe
  // pre-boundary records get one. Code that lies by existing.
  return { signed: false, valid: false };
}

module.exports = { signingPayloadV2, categoryParentsCommitment, sigDigestV2, signCMB, verifyCMB, checkAudience, privateKeyObject, publicKeyObject };
