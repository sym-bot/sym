'use strict';

/**
 * @module sym/core/record-canonical
 * @description A record is its signed projection (sym 0.14 security review, finding B).
 *
 * One constructor, used at every ingress (a session's opened record, a fetched record), that
 * validates a received `mmp-sig-v2.0` record strictly against the published schema
 * (meshcognition.org/spec/mmp/schema/cmb.schema.json) — MMP §8.8.5 step 1 as draft spec PR
 * meshcognition-website#34 states it — and keeps only its signed projection:
 *
 *   - every object is closed: a member the schema does not define refuses the record, except an
 *     unrecognised CATEGORY, which is dropped (§8, forward compatibility);
 *   - every member has its schema's JSON type, checked before anything is length-prefixed: nothing
 *     is coerced (a number is not its decimal string, an array or object is not a string);
 *   - `metadata.to` is a lowercase UUID or null, `createdByNodeId` a lowercase UUID (§3.1.1);
 *   - each category's carried `meta.key` must equal its recomputation from the category name and
 *     the signed text (§8.8.5 step 4): a mismatch refuses the record;
 *   - the carried but unsigned members (§8.8.4) — the mood's `valence` and `arousal`, and
 *     `lineage.method` — are dropped.
 *
 * It returns a NEW object:
 *
 *   categories.<each of the seven>  { text, meta: { key, parents } }
 *   metadata  { key, addressScheme, assertionId, signatureSuite, createdByNodeId, createdBy,
 *               createdTimestamp, room, to, lineage: { parents } | null, application?, sigAlg, sig }
 *
 * The node stores, emits (the verified-record hook) and serves only what this returns.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const { CAT7_CATEGORIES } = require('./cmb');
const { categoryKeyV1, textBytes, MAX_CATEGORY_BYTES, MAX_RECORD_TEXT_BYTES, MAX_RECORD_BYTES } = require('./cmb-encoder');

const LOWER_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** A canonical nodeId: a lowercase UUID, or (tests and older hosts) another lowercase identifier. */
const LOWER_ID = /^[0-9a-z][0-9a-z._-]{0,127}$/;
const CMB_KEY = /^cmb-[0-9a-f]{64}$/;
const ASRT = /^asrt-[0-9a-f]{64}$/;
const SIG = /^[A-Za-z0-9_-]{86}$/;
const DIGEST = /^sha256-[0-9a-f]{64}$/;
const B64URL = /^[A-Za-z0-9_-]*$/;
const MEDIA = /^[a-z0-9][a-z0-9!#$&^_.+/-]*$/;

/**
 * The record size limits (MMP §8.8.6, draft spec PR meshcognition-website#37): a category's text at
 * most 256 KiB after NFC, the seven together at most 512 KiB, the record's minified JSON at most
 * 720 KiB. They are what this release mints (cmb-encoder), and a received record over any of them is
 * refused first, before schema validation, key recomputation or signature verification
 * (sizeRefusal). This reverses the 0.14.0 review's C-F4 acceptance of larger categories from other
 * implementations, by the later ruling.
 */
const MAX_PARENTS = 256;
const MAX_REF = 256;

const METADATA_MEMBERS = new Set(['key', 'addressScheme', 'assertionId', 'signatureSuite', 'createdByNodeId', 'createdBy',
  'createdTimestamp', 'room', 'to', 'lineage', 'application', 'sigAlg', 'sig']);
const APPLICATION_MEMBERS = ['mediaType', 'schema', 'encoding', 'byteLength', 'digest', 'data'];

const isPlain = (v) => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
const isNodeId = (v) => typeof v === 'string' && (LOWER_UUID.test(v) || LOWER_ID.test(v));
const isLowerUuid = (v) => typeof v === 'string' && LOWER_UUID.test(v);

class RecordShapeError extends Error {
  constructor(reason) { super(`record: ${reason}`); this.reason = reason; this.code = 'ERECORDSHAPE'; }
}

function refs(list, what, pattern) {
  if (!Array.isArray(list)) throw new RecordShapeError(`${what} is not an array`);
  if (list.length > MAX_PARENTS) throw new RecordShapeError(`${what} has more than ${MAX_PARENTS} entries`);
  const seen = new Set();
  for (const r of list) {
    if (typeof r !== 'string' || r.length === 0 || r.length > MAX_REF || (pattern && !pattern.test(r))) throw new RecordShapeError(`${what} holds a value that is not a reference`);
    if (seen.has(r)) throw new RecordShapeError(`${what} repeats an entry`);
    seen.add(r);
  }
  return [...list];
}

function category(name, v) {
  if (!isPlain(v)) throw new RecordShapeError(`category ${name} is not an object`);
  const allowed = name === 'mood' ? new Set(['text', 'meta', 'valence', 'arousal']) : new Set(['text', 'meta']);
  for (const k of Object.keys(v)) if (!allowed.has(k)) throw new RecordShapeError(`category ${name} carries an unknown member`);
  if (typeof v.text !== 'string') throw new RecordShapeError(`category ${name} has no text`);
  if (name === 'mood') {
    // Validated as the schema types them, then dropped: unsigned (§8.8.4).
    for (const k of ['valence', 'arousal']) {
      if (v[k] !== undefined && (typeof v[k] !== 'number' || !Number.isFinite(v[k]) || v[k] < -1 || v[k] > 1)) throw new RecordShapeError(`mood ${k} is not a number in [-1, 1]`);
    }
  }
  if (!isPlain(v.meta)) throw new RecordShapeError(`category ${name} has no meta object`);
  for (const k of Object.keys(v.meta)) if (k !== 'key' && k !== 'parents') throw new RecordShapeError(`category ${name} meta carries an unknown member`);
  if (typeof v.meta.key !== 'string' || !/^[0-9a-f]{64}$/.test(v.meta.key)) throw new RecordShapeError(`category ${name} meta.key is not a key`);
  const parents = refs(v.meta.parents, `category ${name} parents`);
  // The text is signed through the content address, the parents through the categoryParents
  // commitment; the category key is derived, so it is recomputed and a carried mismatch refused
  // (§8.8.5 step 4, draft spec PR #34).
  const key = categoryKeyV1(name, v.text);
  // Step 4's verdict, named as verifyCMB names a content address that does not match its content.
  if (v.meta.key !== key) throw new RecordShapeError('content-mismatch');
  return { text: v.text, meta: { key, parents } };
}

function application(a) {
  if (!isPlain(a)) throw new RecordShapeError('application is not an object');
  for (const k of Object.keys(a)) if (!APPLICATION_MEMBERS.includes(k)) throw new RecordShapeError('application carries an unknown member');
  if (typeof a.mediaType !== 'string' || !MEDIA.test(a.mediaType)) throw new RecordShapeError('application mediaType is malformed');
  if (typeof a.schema !== 'string' || a.schema.length > 2048) throw new RecordShapeError('application schema is not text');
  if (a.encoding !== 'base64url') throw new RecordShapeError('application encoding is not base64url');
  if (!Number.isSafeInteger(a.byteLength) || a.byteLength < 0 || a.byteLength > 524288) throw new RecordShapeError('application byteLength is malformed');
  if (typeof a.digest !== 'string' || !DIGEST.test(a.digest)) throw new RecordShapeError('application digest is malformed');
  if (typeof a.data !== 'string' || !B64URL.test(a.data)) throw new RecordShapeError('application data is not base64url');
  return { mediaType: a.mediaType, schema: a.schema, encoding: a.encoding, byteLength: a.byteLength, digest: a.digest, data: a.data };
}

/**
 * §8.8.6: refuse a record over a size limit before any other work on it (a RecordShapeError naming
 * the limit). The encoded size is the record as received, every member counted; texts are measured
 * where they are strings (the schema check that follows refuses any that is not).
 * @param {object} cmb - a plain object
 */
function sizeRefusal(cmb) {
  let encoded;
  try { encoded = Buffer.byteLength(JSON.stringify(cmb), 'utf8'); } catch { throw new RecordShapeError('not encodable'); }
  if (encoded > MAX_RECORD_BYTES) throw new RecordShapeError(`the record is too long (${encoded} bytes encoded; at most ${MAX_RECORD_BYTES})`);
  const c = isPlain(cmb.categories) ? cmb.categories : {};
  let total = 0;
  for (const f of CAT7_CATEGORIES) {
    const text = isPlain(c[f]) ? c[f].text : undefined;
    if (typeof text !== 'string') continue;
    const n = textBytes(text);
    if (n > MAX_CATEGORY_BYTES) throw new RecordShapeError(`category ${f} is too long (${n} bytes; at most ${MAX_CATEGORY_BYTES})`);
    total += n;
  }
  if (total > MAX_RECORD_TEXT_BYTES) throw new RecordShapeError(`the categories together are too long (${total} bytes; at most ${MAX_RECORD_TEXT_BYTES})`);
}

/**
 * The signed projection of a received v2.0 record, or a RecordShapeError (`.reason`).
 * @param {object} cmb
 * @returns {{ categories: object, metadata: object }}
 */
function canonicalRecordV2_0(cmb) {
  if (!isPlain(cmb)) throw new RecordShapeError('not an object');
  sizeRefusal(cmb);
  for (const k of Object.keys(cmb)) if (k !== 'categories' && k !== 'metadata') throw new RecordShapeError('carries a member outside categories and metadata');
  const c = cmb.categories;
  if (!isPlain(c)) throw new RecordShapeError('no categories section');
  // An unrecognised category is dropped, not refused (§8 forward compatibility, draft spec PR #34).
  const categories = {};
  for (const f of CAT7_CATEGORIES) {
    if (c[f] === undefined) throw new RecordShapeError(`category ${f} is missing`);
    categories[f] = category(f, c[f]);
  }
  const m = cmb.metadata;
  if (!isPlain(m)) throw new RecordShapeError('no metadata section');
  for (const k of Object.keys(m)) if (!METADATA_MEMBERS.has(k)) throw new RecordShapeError(`metadata carries an unknown member`);
  if (typeof m.key !== 'string' || !CMB_KEY.test(m.key)) throw new RecordShapeError('metadata.key is malformed');
  if (m.addressScheme !== 'mmp-cmb-merkle-v2') throw new RecordShapeError('addressScheme is not mmp-cmb-merkle-v2');
  if (typeof m.assertionId !== 'string' || !ASRT.test(m.assertionId)) throw new RecordShapeError('assertionId is malformed');
  if (m.signatureSuite !== 'mmp-sig-v2.0') throw new RecordShapeError('signatureSuite is not mmp-sig-v2.0');
  if (!isLowerUuid(m.createdByNodeId)) throw new RecordShapeError('createdByNodeId is not a lowercase UUID');
  if (typeof m.createdBy !== 'string' || m.createdBy.length === 0 || m.createdBy.length > 256) throw new RecordShapeError('createdBy is not a label');
  if (!Number.isSafeInteger(m.createdTimestamp) || m.createdTimestamp < 0) throw new RecordShapeError('createdTimestamp is not an integer');
  if (typeof m.room !== 'string' || m.room.length === 0 || m.room.length > 256) throw new RecordShapeError('room is not a room');
  if (!(m.to === null || isLowerUuid(m.to))) throw new RecordShapeError('to is not a lowercase UUID or null');
  let lineage = null;
  if (m.lineage === undefined) throw new RecordShapeError('lineage is missing (an object or null)');
  if (m.lineage !== null) {
    if (!isPlain(m.lineage)) throw new RecordShapeError('lineage is not an object');
    for (const k of Object.keys(m.lineage)) if (k !== 'parents' && k !== 'method') throw new RecordShapeError('lineage carries an unknown member');
    // Optional, unsigned and dropped (§8.8.4), but typed as the schema types it.
    if (m.lineage.method !== undefined && (typeof m.lineage.method !== 'string' || m.lineage.method.length === 0)) throw new RecordShapeError('lineage.method is not text');
    lineage = { parents: refs(m.lineage.parents, 'lineage.parents', CMB_KEY) };
  }
  if (m.sigAlg !== 'ed25519') throw new RecordShapeError('sigAlg is not ed25519');
  if (typeof m.sig !== 'string' || !SIG.test(m.sig)) throw new RecordShapeError('sig is not an unpadded Ed25519 signature');
  const metadata = {
    key: m.key, addressScheme: m.addressScheme, assertionId: m.assertionId, signatureSuite: m.signatureSuite,
    createdByNodeId: m.createdByNodeId, createdBy: m.createdBy, createdTimestamp: m.createdTimestamp,
    room: m.room, to: m.to, lineage,
  };
  if (m.application !== undefined && m.application !== null) metadata.application = application(m.application);
  metadata.sigAlg = m.sigAlg;
  metadata.sig = m.sig;
  return { categories, metadata };
}

/**
 * The signed projection of a record this node sends (its own, or one it stored): the same checks
 * and the same members, its own records' unsigned extras (valence, arousal, lineage.method)
 * dropped likewise, and any member outside `categories` and `metadata` (a store annotation)
 * left behind.
 */
function signedProjection(cmb) {
  return canonicalRecordV2_0({ categories: cmb.categories, metadata: cmb.metadata });
}

module.exports = { canonicalRecordV2_0, signedProjection, sizeRefusal, RecordShapeError, isCanonicalNodeId: isNodeId, isLowerUuid, LOWER_UUID };
