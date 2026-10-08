import crypto from 'node:crypto';

export const PROTOCOL_VERSION = '2.0';
export const SIGNATURE_SUITE = 'mmp-sig-v2.0';
export const ADDRESS_SCHEME = 'mmp-cmb-merkle-v2';
export const CAT7 = ['focus', 'issue', 'intent', 'motivation', 'commitment', 'perspective', 'mood'];

export function lp(value) {
  const bytes = Buffer.from(String(value), 'utf8');
  return Buffer.concat([Buffer.from(`${bytes.length}:`, 'ascii'), bytes]);
}

export function decimal(value) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`expected non-negative safe integer, got ${value}`);
  }
  return String(value);
}

export function sortedBytewise(values) {
  return [...values].map(String).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
}

export function framedList(values) {
  const items = sortedBytewise(new Set(values));
  return Buffer.concat([lp(decimal(items.length)), ...items.map(lp)]);
}

export function sha256(value) {
  return crypto.createHash('sha256').update(value).digest();
}

export function sha256Hex(value) {
  return sha256(value).toString('hex');
}

export function categoryKeyV1(name, text) {
  return sha256Hex(Buffer.concat([
    Buffer.from('mmp-cmb-v1\n', 'utf8'),
    lp(name),
    lp(String(text ?? '').normalize('NFC')),
  ]));
}

export function categoryParentsCommitment(categories) {
  const parts = [Buffer.from('mmp-fp-v1\n', 'utf8')];
  for (const name of CAT7) {
    const refs = sortedBytewise(categories?.[name]?.meta?.parents ?? []);
    parts.push(lp(name), lp(decimal(refs.length)), ...refs.map(lp));
  }
  return sha256Hex(Buffer.concat(parts));
}

export function blockKeyV2(categories) {
  let level = CAT7.map((name) => {
    const digest = Buffer.from(categoryKeyV1(name, categories?.[name]?.text ?? ''), 'hex');
    return sha256(Buffer.concat([Buffer.from([0]), digest]));
  });
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length
        ? sha256(Buffer.concat([Buffer.from([1]), level[i], level[i + 1]]))
        : level[i]);
    }
    level = next;
  }
  return `cmb-${level[0].toString('hex')}`;
}

export function applicationBytes(application) {
  if (application == null) return null;
  if (application.encoding !== 'base64url') throw new Error('application encoding must be base64url');
  if (typeof application.data !== 'string' || application.data.includes('=')) {
    throw new Error('application data must be unpadded base64url');
  }
  const bytes = Buffer.from(application.data, 'base64url');
  if (bytes.toString('base64url') !== application.data) throw new Error('application data is not canonical base64url');
  if (bytes.length !== application.byteLength) throw new Error('application byteLength mismatch');
  if (bytes.length > 524288) throw new Error('application exceeds 524288-byte limit');
  if (`sha256-${sha256Hex(bytes)}` !== application.digest) throw new Error('application digest mismatch');
  return bytes;
}

export function applicationCommitmentV1(application) {
  const domain = Buffer.from('mmp-app-v1\n', 'utf8');
  if (application == null) return sha256Hex(Buffer.concat([domain, lp('0')]));
  applicationBytes(application);
  if (!/^[a-z0-9][a-z0-9!#$&^_.+\/-]*$/.test(application.mediaType) || application.mediaType.includes(';')) {
    throw new Error('application mediaType must be canonical lowercase ASCII without parameters');
  }
  const schema = String(application.schema ?? '').normalize('NFC');
  return sha256Hex(Buffer.concat([
    domain,
    lp('1'),
    lp(application.mediaType),
    lp(schema),
    lp('base64url'),
    lp(decimal(application.byteLength)),
    lp(application.digest),
  ]));
}

// §8.8.6 record size limits, in bytes.
export const MAX_CATEGORY_TEXT = 262144;
export const MAX_RECORD_TEXT = 524288;
export const MAX_RECORD_BYTES = 737280;
// The longest sealed value a MAX_RECORD_BYTES plaintext can produce, the 16-byte tag included.
export const MAX_SEALED_RECORD_CHARS = Math.ceil((4 * (MAX_RECORD_BYTES + 16)) / 3);

// RFC 8785 (JCS) for the JSON a record holds: members sorted by UTF-16 code units, strings and
// numbers as ECMAScript writes them, no whitespace.
export function canonicalJSON(value) {
  if (value === null || typeof value !== 'object') {
    if (typeof value === 'number' && !Number.isFinite(value)) throw new Error('RFC 8785 has no non-finite numbers');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(',')}]`;
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJSON(value[k])}`).join(',')}}`;
}

// The §8.8.6 measures of one two-section record, and the limits it is over (none when it is within).
export function recordSize(record) {
  const categoryTextBytes = Object.fromEntries(CAT7.map((name) => {
    const text = record?.categories?.[name]?.text;
    return [name, typeof text === 'string' ? Buffer.byteLength(text.normalize('NFC'), 'utf8') : 0];
  }));
  const recordTextBytes = Object.values(categoryTextBytes).reduce((a, b) => a + b, 0);
  const recordBytes = Buffer.byteLength(canonicalJSON(record), 'utf8');
  const over = [];
  if (Object.values(categoryTextBytes).some((n) => n > MAX_CATEGORY_TEXT)) over.push('MAX_CATEGORY_TEXT');
  if (recordTextBytes > MAX_RECORD_TEXT) over.push('MAX_RECORD_TEXT');
  if (recordBytes > MAX_RECORD_BYTES) over.push('MAX_RECORD_BYTES');
  return { categoryTextBytes, recordTextBytes, recordBytes, over };
}

// §8.8.5 step 1 after the record schema (closed objects, types, lowercase nodeIds, caps): the NFC
// rule and the canonical signed projection, then the step 4 key checks. Returns the projection, or
// the rule that refused the record. The projection keeps only what mmp-sig-v2.0 binds, so every
// node holds one assertion as the same RFC 8785 bytes.
export function recordProjectionV2(record) {
  const isNFC = (v) => typeof v === 'string' && v === v.normalize('NFC');
  for (const name of CAT7) if (!isNFC(record.categories[name].text)) return { ok: false, refusedBy: 'not NFC', member: `categories.${name}.text` };
  for (const member of ['createdBy', 'room']) if (!isNFC(record.metadata[member])) return { ok: false, refusedBy: 'not NFC', member: `metadata.${member}` };
  if (record.metadata.application != null && !isNFC(record.metadata.application.schema)) return { ok: false, refusedBy: 'not NFC', member: 'metadata.application.schema' };
  const categories = Object.fromEntries(CAT7.map((name) => {
    const c = record.categories[name];
    return [name, { text: c.text, meta: { key: c.meta.key, parents: sortedBytewise(c.meta.parents) } }];
  }));
  const m = record.metadata;
  const parents = sortedBytewise(m.lineage?.parents ?? []);
  const metadata = {
    key: m.key,
    addressScheme: m.addressScheme,
    assertionId: m.assertionId,
    signatureSuite: m.signatureSuite,
    createdByNodeId: m.createdByNodeId,
    createdBy: m.createdBy,
    createdTimestamp: m.createdTimestamp,
    room: m.room,
    to: m.to,
    lineage: parents.length === 0 ? null : { parents },
    application: m.application ?? null,
    sigAlg: m.sigAlg,
    sig: m.sig,
  };
  for (const name of CAT7) if (categoryKeyV1(name, categories[name].text) !== categories[name].meta.key) return { ok: false, refusedBy: 'meta.key', member: `categories.${name}.meta.key` };
  if (blockKeyV2(categories) !== metadata.key) return { ok: false, refusedBy: 'metadata.key', member: 'metadata.key' };
  return { ok: true, projection: { categories, metadata } };
}

export function signingPayloadV2_0(record) {
  const m = record?.metadata;
  if (!m) throw new Error('metadata is required');
  if (m.signatureSuite !== SIGNATURE_SUITE) throw new Error(`signatureSuite must be ${SIGNATURE_SUITE}`);
  if (m.addressScheme !== ADDRESS_SCHEME) throw new Error(`addressScheme must be ${ADDRESS_SCHEME}`);
  const parents = sortedBytewise(m.lineage?.parents ?? []);
  return Buffer.concat([
    Buffer.from('mmp-sig-v2.0\n', 'utf8'),
    lp(PROTOCOL_VERSION),
    lp(ADDRESS_SCHEME),
    lp(m.key),
    lp(m.createdByNodeId),
    lp(String(m.createdBy).normalize('NFC')),
    lp(decimal(m.createdTimestamp)),
    lp(String(m.room).normalize('NFC')),
    lp(m.to ?? ''),
    lp(decimal(parents.length)),
    ...parents.map(lp),
    lp(categoryParentsCommitment(record.categories)),
    lp(applicationCommitmentV1(m.application ?? null)),
  ]);
}

export function assertionId(record) {
  return `asrt-${sha256Hex(signingPayloadV2_0(record))}`;
}

export function handshakeTranscriptV2(h) {
  if (h.protocolVersion !== PROTOCOL_VERSION) throw new Error('protocolVersion must be 2.0');
  return Buffer.concat([
    Buffer.from('mmp-handshake-transcript-v2\n', 'utf8'),
    lp(PROTOCOL_VERSION),
    lp(String(h.room).normalize('NFC')),
    lp(h.client.nonce),
    lp(h.server.nonce),
    lp(h.client.nodeId),
    lp(h.client.identityPublicKey),
    lp(h.client.e2ePublicKey),
    lp(String(h.client.name).normalize('NFC')),
    lp(h.client.implementation.name),
    lp(h.client.implementation.version),
    framedList(h.client.extensions),
    lp(h.server.nodeId),
    lp(h.server.identityPublicKey),
    lp(h.server.e2ePublicKey),
    lp(String(h.server.name).normalize('NFC')),
    lp(h.server.implementation.name),
    lp(h.server.implementation.version),
    framedList(h.server.extensions),
    framedList(h.selectedExtensions),
  ]);
}

export function handshakeProofV2(role, transcriptHash) {
  if (role !== 'client' && role !== 'server') throw new Error('handshake role must be client or server');
  return Buffer.concat([
    Buffer.from('mmp-handshake-proof-v2\n', 'utf8'),
    lp(role),
    lp(Buffer.from(transcriptHash).toString('hex')),
  ]);
}

export function hkdf(sharedSecret, salt, info) {
  return Buffer.from(crypto.hkdfSync('sha256', sharedSecret, salt, Buffer.from(info, 'utf8'), 32));
}

export function keyConfirmation(role, finishedKey, transcriptHash) {
  const payload = Buffer.concat([
    Buffer.from('mmp-key-confirm-v2\n', 'utf8'),
    lp(role),
    lp(Buffer.from(transcriptHash).toString('hex')),
  ]);
  return crypto.createHmac('sha256', finishedKey).update(payload).digest();
}

export function nonceFromSequence(sequence) {
  const n = BigInt(sequence);
  if (n < 0n || n >= (1n << 96n)) throw new RangeError('sequence outside unsigned 96-bit range');
  const nonce = Buffer.alloc(12);
  nonce.writeUInt32BE(Number((n >> 64n) & 0xffffffffn), 0);
  nonce.writeBigUInt64BE(n & 0xffffffffffffffffn, 4);
  return nonce;
}

export function requireNextSequence(expected, received) {
  const e = BigInt(expected);
  const r = BigInt(received);
  if (r !== e) throw new Error(`unexpected sequence: expected ${e}, received ${r}`);
  return (e + 1n).toString();
}

export function aeadAADV2({ sessionId, direction, sequence, metadata }) {
  if (direction !== 'client-to-server' && direction !== 'server-to-client') throw new Error('invalid direction');
  return Buffer.concat([
    Buffer.from('mmp-aead-aad-v2\n', 'utf8'),
    lp(PROTOCOL_VERSION),
    lp(sessionId),
    lp(direction),
    lp(String(sequence)),
    lp(metadata.key),
    lp(metadata.assertionId),
    lp(metadata.createdByNodeId),
    lp(String(metadata.room).normalize('NFC')),
    lp(metadata.to ?? ''),
  ]);
}

export const CONTROL_AAD_DOMAIN = 'mmp-aead-control-v2\n';

// §18.2.1 control-encrypted: the record AAD's session prefix under its own domain, with no record fields.
export function controlAADV2({ sessionId, direction, sequence }) {
  if (direction !== 'client-to-server' && direction !== 'server-to-client') throw new Error('invalid direction');
  return Buffer.concat([
    Buffer.from(CONTROL_AAD_DOMAIN, 'utf8'),
    lp(PROTOCOL_VERSION),
    lp(sessionId),
    lp(direction),
    lp(String(sequence)),
  ]);
}

// §7.1: what a control-encrypted envelope never carries. ping and pong may travel either way.
const CONTROL_NEVER_INNER = new Set(['client-hello', 'server-hello', 'client-finish', 'handshake', 'cmb', 'cmb-encrypted', 'control-encrypted', 'state-sync']);
export function controlInnerForbidden(type) {
  return typeof type !== 'string' || CONTROL_NEVER_INNER.has(type) || type.startsWith('relay-');
}

export function encryptChaChaPoly({ key, sequence, plaintext, aad }) {
  const nonce = nonceFromSequence(sequence);
  const cipher = crypto.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  cipher.setAAD(aad, { plaintextLength: plaintext.length });
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([ciphertext, cipher.getAuthTag()]);
}

export function decryptChaChaPoly({ key, sequence, sealed, aad }) {
  const nonce = nonceFromSequence(sequence);
  const ciphertext = sealed.subarray(0, -16);
  const tag = sealed.subarray(-16);
  const decipher = crypto.createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  decipher.setAAD(aad, { plaintextLength: ciphertext.length });
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

const ED25519_PRIVATE_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const ED25519_PUBLIC_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const X25519_PRIVATE_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
const X25519_PUBLIC_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

export function ed25519PrivateKey(raw) {
  return crypto.createPrivateKey({ key: Buffer.concat([ED25519_PRIVATE_PREFIX, raw]), format: 'der', type: 'pkcs8' });
}

export function ed25519PublicKey(raw) {
  return crypto.createPublicKey({ key: Buffer.concat([ED25519_PUBLIC_PREFIX, raw]), format: 'der', type: 'spki' });
}

export function x25519PrivateKey(raw) {
  return crypto.createPrivateKey({ key: Buffer.concat([X25519_PRIVATE_PREFIX, raw]), format: 'der', type: 'pkcs8' });
}

export function x25519PublicKey(raw) {
  return crypto.createPublicKey({ key: Buffer.concat([X25519_PUBLIC_PREFIX, raw]), format: 'der', type: 'spki' });
}

export function rawPublicKey(keyObject) {
  return keyObject.export({ format: 'der', type: 'spki' }).subarray(-32);
}


// ---------------------------------------------------------------------------------------------
// §18.3.2 Ed25519 verification for authority statements, pinned exactly.
// RFC 8032 §5.1.7 verification, cofactorless ([S]B = R + [k]A, compared as points), after four
// pre-checks: A and R are canonical encodings of points on the curve, both of prime order (in the
// prime-order subgroup and not the identity), and S < L. With A and R of prime order the
// cofactored and cofactorless equations give the same answer, so every conforming library agrees.
// Node's crypto.verify (OpenSSL) supplies the equation; the pre-checks below are what it lacks.
// ---------------------------------------------------------------------------------------------

const ED_P = 2n ** 255n - 19n;
export const ED25519_L = 2n ** 252n + 27742317777372353535851937790883648493n;
const edMod = (a) => { const r = a % ED_P; return r < 0n ? r + ED_P : r; };
const edPow = (b, e) => { let r = 1n; let x = edMod(b); let n = e; while (n > 0n) { if (n & 1n) r = (r * x) % ED_P; x = (x * x) % ED_P; n >>= 1n; } return r; };
const ED_D = edMod(-121665n * edPow(121666n, ED_P - 2n));
const ED_SQRT_M1 = edPow(2n, (ED_P - 1n) / 4n);
const ED_IDENTITY = { X: 0n, Y: 1n, Z: 1n, T: 0n };
const leInt = (bytes) => BigInt(`0x${Buffer.from(bytes).reverse().toString('hex') || '0'}`);

// Decode a 32-byte point. strict: reject y >= p and the encoding of x = 0 with the sign bit set
// (RFC 8032 §5.1.3 canonical encodings). lenient (ZIP-215 style) reduces y and ignores that sign bit;
// it is used only to show what an unchecked library would compute.
function edDecode(bytes, { lenient = false } = {}) {
  if (!bytes || bytes.length !== 32) return null;
  const b = Buffer.from(bytes);
  const sign = (b[31] >> 7) & 1;
  b[31] &= 0x7f;
  let y = leInt(b);
  if (y >= ED_P) { if (!lenient) return null; y = edMod(y); }
  const u = edMod(y * y - 1n);
  const v = edMod(ED_D * y * y + 1n);
  let x = edMod(u * edPow(v, 3n) * edPow(u * edPow(v, 7n), (ED_P - 5n) / 8n));
  const vx2 = edMod(v * x * x);
  if (vx2 === u) { /* root found */ } else if (vx2 === edMod(-u)) x = edMod(x * ED_SQRT_M1); else return null;
  if (x === 0n && sign === 1 && !lenient) return null;
  if (Number(x & 1n) !== sign) x = edMod(-x);
  return { X: x, Y: y, Z: 1n, T: edMod(x * y) };
}
function edAdd(p, q) {
  const A = edMod((p.Y - p.X) * (q.Y - q.X));
  const B = edMod((p.Y + p.X) * (q.Y + q.X));
  const C = edMod(2n * ED_D * p.T * q.T);
  const D2 = edMod(2n * p.Z * q.Z);
  const E = B - A; const F = D2 - C; const G = D2 + C; const H = B + A;
  return { X: edMod(E * F), Y: edMod(G * H), Z: edMod(F * G), T: edMod(E * H) };
}
const edNeg = (p) => ({ X: edMod(-p.X), Y: p.Y, Z: p.Z, T: edMod(-p.T) });
function edMul(p, k) {
  let r = ED_IDENTITY;
  for (let i = k.toString(2).length - 1; i >= 0; i--) {
    r = edAdd(r, r);
    if ((k >> BigInt(i)) & 1n) r = edAdd(r, p);
  }
  return r;
}
const edIsIdentity = (p) => edMod(p.X) === 0n && edMod(p.Y - p.Z) === 0n;
const edEqual = (p, q) => edMod(p.X * q.Z - q.X * p.Z) === 0n && edMod(p.Y * q.Z - q.Y * p.Z) === 0n;
const ED_BASE = edDecode(Buffer.from('5866666666666666666666666666666666666666666666666666666666666666', 'hex'));

// Prime order: a canonical point P with [L]P = O and P != O. Small-order points fail the first test
// (L = 5 mod 8, so [L]T = [5]T != O for torsion T != O), mixed-order points fail it too, and the
// identity fails the second. Cached per encoding: keys and signatures repeat across resolutions.
const primeOrderCache = new Map();
export function isPrimeOrderPoint(bytes) {
  const k = Buffer.from(bytes).toString('hex');
  if (primeOrderCache.has(k)) return primeOrderCache.get(k);
  const p = edDecode(bytes);
  const ok = p !== null && !edIsIdentity(p) && edIsIdentity(edMul(p, ED25519_L));
  primeOrderCache.set(k, ok);
  return ok;
}

// The reason a (key, signature) pair fails the pre-checks, or null when it passes them.
export function ed25519PrecheckFailure(publicKey, signature) {
  const A = Buffer.from(publicKey);
  const sig = Buffer.from(signature);
  if (A.length !== 32 || sig.length !== 64) return 'length';
  if (!edDecode(A)) return 'A is not a canonical encoding of a curve point';
  if (!isPrimeOrderPoint(A)) return 'A is not of prime order';
  const R = sig.subarray(0, 32);
  if (!edDecode(R)) return 'R is not a canonical encoding of a curve point';
  if (!isPrimeOrderPoint(R)) return 'R is not of prime order';
  if (leInt(sig.subarray(32)) >= ED25519_L) return 'S is not less than L';
  return null;
}

// Point arithmetic for building the edge-case vector (not used by verification itself).
function edEncode(p) {
  const zi = edPow(p.Z, ED_P - 2n);
  const x = edMod(p.X * zi);
  const y = edMod(p.Y * zi);
  const out = Buffer.from(y.toString(16).padStart(64, '0'), 'hex').reverse();
  if (x & 1n) out[31] |= 0x80;
  return out;
}
export const ed25519Points = {
  base: ED_BASE,
  identity: ED_IDENTITY,
  // A point of order 8 (from the torsion subgroup), checked below.
  torsion8: edDecode(Buffer.from('26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05', 'hex')),
  decode: (bytes) => edDecode(bytes),
  encode: edEncode,
  add: edAdd,
  mul: edMul,
  isIdentity: edIsIdentity,
  scalar: (bytes) => leInt(bytes) % ED25519_L,
  le32: (n) => Buffer.from(n.toString(16).padStart(64, '0'), 'hex').reverse(),
  challenge: (R, A, message) => leInt(crypto.createHash('sha512').update(Buffer.concat([Buffer.from(R), Buffer.from(A), Buffer.from(message)])).digest()) % ED25519_L,
};
if (!edIsIdentity(edMul(ed25519Points.torsion8, 8n)) || edIsIdentity(edMul(ed25519Points.torsion8, 4n))) throw new Error('torsion point is not of order 8');

// §18.3.2, the rule as written: the four pre-checks, then [S]B = R + [k]A, all computed here in
// BigInt, independently of any library. Slow; used to cross-check the edge-case vector.
export function verifyEd25519StrictFull(message, publicKey, signature) {
  if (ed25519PrecheckFailure(publicKey, signature) !== null) return false;
  return ed25519Equations(message, publicKey, signature).cofactorless;
}

// §18.3.2 as a cofactorless verifier that compares R by its bytes (OpenSSL, hence Node) implements
// it: check A (canonical, prime order: cached per key), S < L, and that R is not the identity's
// encoding, then call the library. This is the same rule. If the library accepts, R's bytes are the
// canonical encoding of R' = [S]B - [k]A, which lies in the prime-order subgroup because B and A do,
// and R' is not the identity, so R is canonical and of prime order. If the rule accepts, R' = R and
// the library's byte comparison succeeds. The edge-case vector checks both on every case.
const ED_IDENTITY_BYTES = Buffer.concat([Buffer.from([1]), Buffer.alloc(31)]);
export function verifyEd25519Strict(message, publicKey, signature) {
  const A = Buffer.from(publicKey);
  const sig = Buffer.from(signature);
  if (A.length !== 32 || sig.length !== 64) return false;
  if (!isPrimeOrderPoint(A)) return false;
  if (sig.subarray(0, 32).equals(ED_IDENTITY_BYTES)) return false;
  if (leInt(sig.subarray(32)) >= ED25519_L) return false;
  try {
    return crypto.verify(null, message, ed25519PublicKey(A), sig);
  } catch {
    return false;
  }
}

// Both RFC 8032 equations computed directly, without pre-checks and with lenient decoding, for the
// edge-case vector only: they show what an unchecked library may answer, and that once the
// pre-checks pass the two equations agree.
export function ed25519Equations(message, publicKey, signature) {
  const Araw = Buffer.from(publicKey);
  const sig = Buffer.from(signature);
  const A = edDecode(Araw, { lenient: true });
  const R = edDecode(sig.subarray(0, 32), { lenient: true });
  if (!A || !R) return { cofactorless: false, cofactored: false };
  const S = leInt(sig.subarray(32));
  const k = leInt(crypto.createHash('sha512').update(Buffer.concat([sig.subarray(0, 32), Araw, Buffer.from(message)])).digest()) % ED25519_L;
  const SB = edMul(ED_BASE, S);
  const RkA = edAdd(R, edMul(A, k));
  const diff = edAdd(SB, edNeg(RkA));
  return { cofactorless: edEqual(SB, RkA), cofactored: edIsIdentity(edMul(diff, 8n)) };
}

// ---------------------------------------------------------------------------------------------
// §6.6 authority statements: grant, revoke and endorse, linked by hash, resolved as a set.
// This is the reference construction the authority vector is generated from and checked against.
// Nothing here reads a clock or depends on the order statements arrive in.
// ---------------------------------------------------------------------------------------------

export const AUTHORITY_DOMAIN = 'mmp-authority-v1\n';
export const AUTHORITY_ROOT_DOMAIN = 'mmp-authority-root-v1\n';
export const ANCHOR_PIN_DOMAIN = 'mmp-anchor-pin-v1\n';
export const MAX_DELEGATION_DEPTH = 4;
export const AUTHORITY_QUOTA = 256;
export const AUTHORITY_ANCHOR_QUOTA = 4096;
export const AUTHORITY_DELEGATE_QUOTA = 16;
export const AUTHORITY_MAX_TARGETS = 64;
export const ANCHOR_MAX_KEYS = 16;
export const AUTHORITY_SCOPE_MAX = 256;
export const MAX_ISSUED_AT = Number.MAX_SAFE_INTEGER; // 2^53 - 1

const AUTHORITY_ID = /^auth-[0-9a-f]{64}$/;
const B64U_KEY = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;
const B64U_SIG = /^[A-Za-z0-9_-]{85}[AQgw]$/;
const B64U_NONCE = /^[A-Za-z0-9_-]{21}[AQgw]$/;
// Canonical RFC 4122 text form, lowercase only: the bytes signed are exactly these characters.
export const NODE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const EXTENSION_ROLE = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)+$/;
// namespace ":" path, path segments separated by "/". A narrower scope adds segments. A segment
// made only of dots ("." or "..") is forbidden: paths are opaque and compared exactly, never
// normalised, so nothing may look like a step up to anyone who would resolve it.
export const SCOPE = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*:(?!\.+(?:\/|$))[A-Za-z0-9._~-]+(?:\/(?!\.+(?:\/|$))[A-Za-z0-9._~-]+)*$/;
// Roles that may sign statements, hence are counted against the delegate quota.
export const DELEGATING_ROLES = new Set(['admin', 'validator', 'issuer']);
const CORE_ROLES = new Set(['admin', 'validator', 'issuer', 'participant']);
// The lifecycle a role may advance another CMB to (§3.5), inside its grant's scope.
export const LIFECYCLE_AUTHORITY = { anchor: 'canonical', admin: 'canonical', validator: 'validated' };

export function isNonAuthorityRole(role) {
  return role === 'participant' || (typeof role === 'string' && role.length <= 64 && EXTENSION_ROLE.test(role)
    && !CORE_ROLES.has(role));
}

export function isRole(role) {
  return DELEGATING_ROLES.has(role) || isNonAuthorityRole(role);
}

export function isScope(scope) {
  return typeof scope === 'string' && scope.length <= AUTHORITY_SCOPE_MAX && SCOPE.test(scope);
}

// A child's scope equals or narrows its parent's. No scope is the widest: the whole mesh.
export function scopeNarrows(parent, child) {
  if (parent === undefined) return true;
  if (child === undefined) return false;
  return child === parent || child.startsWith(`${parent}/`);
}

function canonicalB64u(value, pattern, bytes) {
  if (typeof value !== 'string' || !pattern.test(value)) return false;
  const decoded = Buffer.from(value, 'base64url');
  return decoded.length === bytes && decoded.toString('base64url') === value;
}

// The canonical signed bytes. Every field is length-prefixed (lp), so the encoding is injective;
// targets are a count-prefixed list in bytewise order, so their order on the wire does not matter.
export function authorityPayloadV1(s) {
  const parts = [Buffer.from(AUTHORITY_DOMAIN, 'utf8'), lp(s.kind), lp(s.authorisedBy)];
  if (s.kind === 'grant') parts.push(lp(s.subject.nodeId), lp(s.subject.key), lp(s.role), lp(s.scope ?? ''));
  else if (s.kind === 'revoke' || s.kind === 'endorse') parts.push(framedList(s.targets));
  else throw new Error(`unknown statement kind ${s.kind}`);
  parts.push(lp(s.nonce), lp(s.issuedAt === undefined ? '' : decimal(s.issuedAt)));
  return Buffer.concat(parts);
}

export function authorityId(s) {
  return `auth-${sha256Hex(authorityPayloadV1(s))}`;
}

// The anchor pin as bytes: threshold, then each member as its key. Under a threshold of 1 a member
// pinned with the nodeId of its holder is "key:nodeId", because only then does that nodeId change
// what resolves (the holder is the anchor, §6.6.1). A key is 43 base64url characters, so the colon
// is unambiguous.
export function anchorPinDigest(pin) {
  const members = pin.keys.map((m) => (pin.threshold === 1 && m.nodeId ? `${m.key}:${m.nodeId}` : m.key));
  return sha256Hex(Buffer.concat([Buffer.from(ANCHOR_PIN_DOMAIN, 'utf8'), lp(decimal(pin.threshold)), framedList(members)]));
}

// The authority root (§6.6.7): which in-force set, under which anchor. Two nodes with the same pin
// and the same in-force set have the same root, whatever else each happens to hold.
export function authorityRoot(pin, inForceIds) {
  return sha256Hex(Buffer.concat([
    Buffer.from(AUTHORITY_ROOT_DOMAIN, 'utf8'),
    lp(anchorPinDigest(pin)),
    framedList(inForceIds),
  ]));
}

// Shape checks that need no other statement (§6.6.3, rule 1).
export function authorityWellFormed(s) {
  if (!s || typeof s !== 'object') return false;
  const common = ['kind', 'authorisedBy', 'nonce', 'sigs'];
  const allowed = new Set([...common, 'issuedAt', ...(s.kind === 'grant' ? ['subject', 'role', 'scope'] : ['targets'])]);
  if (Object.keys(s).some((k) => !allowed.has(k)) || common.some((k) => !(k in s))) return false;
  if (s.authorisedBy !== 'anchor' && !AUTHORITY_ID.test(s.authorisedBy)) return false;
  if (!canonicalB64u(s.nonce, B64U_NONCE, 16)) return false;
  if (s.issuedAt !== undefined && !(Number.isSafeInteger(s.issuedAt) && s.issuedAt >= 0 && s.issuedAt <= MAX_ISSUED_AT)) return false;
  if (!Array.isArray(s.sigs) || s.sigs.length < 1) return false;
  if (s.authorisedBy !== 'anchor' && s.sigs.length !== 1) return false;
  if (s.sigs.length > ANCHOR_MAX_KEYS) return false;
  for (const e of s.sigs) {
    if (!e || typeof e !== 'object' || Object.keys(e).length !== 2 || !canonicalB64u(e.key, B64U_KEY, 32) || !canonicalB64u(e.sig, B64U_SIG, 64)) return false;
  }
  // Each entry's key is unique within the statement: a repeated key is a shape error, found here,
  // before any signature is checked, so a copy cannot buy repeated checks under one pinned key.
  if (new Set(s.sigs.map((e) => e.key)).size !== s.sigs.length) return false;
  if (s.kind === 'grant') {
    const sub = s.subject;
    if (!sub || typeof sub !== 'object' || Object.keys(sub).length !== 2 || typeof sub.nodeId !== 'string' || !NODE_ID.test(sub.nodeId)) return false;
    if (!canonicalB64u(sub.key, B64U_KEY, 32) || !isPrimeOrderPoint(Buffer.from(sub.key, 'base64url'))) return false;
    if (s.scope !== undefined && !isScope(s.scope)) return false;
    return isRole(s.role);
  }
  if (s.kind !== 'revoke' && s.kind !== 'endorse') return false;
  if (!Array.isArray(s.targets) || s.targets.length < 1 || s.targets.length > AUTHORITY_MAX_TARGETS) return false;
  if (new Set(s.targets).size !== s.targets.length) return false;
  return s.targets.every((t) => typeof t === 'string' && AUTHORITY_ID.test(t));
}

// Which statements the holder of the authorising role may sign (§6.6.2).
function permits(authorisingRole, s) {
  if (s.kind === 'grant') {
    if (authorisingRole === 'anchor' || authorisingRole === 'admin') return DELEGATING_ROLES.has(s.role) || isNonAuthorityRole(s.role);
    if (authorisingRole === 'validator' || authorisingRole === 'issuer') return isNonAuthorityRole(s.role);
    return false;
  }
  if (s.kind === 'revoke') return authorisingRole === 'anchor' || DELEGATING_ROLES.has(authorisingRole);
  return authorisingRole === 'anchor' || authorisingRole === 'admin';
}

const verifyEntry = (payload, e) => verifyEd25519Strict(payload, Buffer.from(e.key, 'base64url'), Buffer.from(e.sig, 'base64url'));

function anchorCopyValid(pin, payload, s, verify) {
  const pinned = new Set(pin.keys.map((m) => m.key));
  const counted = new Set();
  for (const e of s.sigs) {
    if (pinned.has(e.key) && !counted.has(e.key) && verify(payload, e)) counted.add(e.key);
  }
  return counted.size >= pin.threshold;
}

/**
 * Resolve a set of authority statements against a pinned anchor set (§6.6.4).
 * pin: { threshold, keys: [{ key, nodeId? }] }. statements: any array (order is irrelevant).
 * Returns the status of every distinct statement id, the in-force ids, the live set, the roles of
 * each (nodeId, key), the bucket that kept each in-force statement, and the authority root.
 * `verifySignature` exists only so the randomised bound check in the verifier can run thousands of
 * statements without signing them; every conformance case uses the §18.3.2 rule.
 */
export function resolveAuthority({
  pin, statements, quota = AUTHORITY_QUOTA, anchorQuota = AUTHORITY_ANCHOR_QUOTA,
  delegateQuota = AUTHORITY_DELEGATE_QUOTA, verifySignature = verifyEntry,
}) {
  if (!(pin && Number.isInteger(pin.threshold) && pin.threshold >= 1 && pin.threshold <= pin.keys.length
    && pin.keys.length <= ANCHOR_MAX_KEYS)) throw new Error('invalid anchor pin');
  // 1. Group copies by id. A copy that is not well formed is not a statement at all.
  const copies = new Map();
  const malformed = new Set(); // ids of copies that are not well formed, where an id can be computed
  for (const s of statements) {
    if (!authorityWellFormed(s)) {
      try { malformed.add(authorityId(s)); } catch { /* no id at all */ }
      continue;
    }
    const id = authorityId(s);
    if (!copies.has(id)) copies.set(id, []);
    copies.get(id).push(s);
  }
  // 2. Static validity (rules 2-4). Walk authorisedBy at most MAX_DELEGATION_DEPTH links: a chain
  // that reaches the anchor is validated top-down; one that names a statement not held is pending;
  // one that is still not at the anchor after MAX_DELEGATION_DEPTH links is too deep, hence invalid.
  const info = new Map(); // id -> { status, s, depth, chain: [grant ids above it, nearest first] }
  const validateOne = (id, parentId) => {
    if (info.has(id)) return;
    const all = copies.get(id);
    const payload = authorityPayloadV1(all[0]);
    if (parentId === null) {
      const good = all.find((c) => anchorCopyValid(pin, payload, c, verifySignature));
      info.set(id, good && permits('anchor', good) ? { status: 'valid', s: good, depth: 1, chain: [] } : { status: 'invalid', s: all[0] });
      return;
    }
    const up = info.get(parentId);
    if (up.status !== 'valid' || up.s.kind !== 'grant') { info.set(id, { status: 'invalid', s: all[0] }); return; }
    const good = all.find((c) => c.sigs[0].key === up.s.subject.key && verifySignature(payload, c.sigs[0]));
    const scoped = !good || good.kind !== 'grant' || scopeNarrows(up.s.scope, good.scope);
    info.set(id, good && scoped && permits(up.s.role, good)
      ? { status: 'valid', s: good, depth: up.depth + 1, chain: [parentId, ...up.chain] }
      : { status: 'invalid', s: all[0] });
  };
  const check = (id) => {
    if (info.has(id)) return;
    const walk = [id];
    let cur = copies.get(id)[0];
    while (cur.authorisedBy !== 'anchor') {
      if (walk.length === MAX_DELEGATION_DEPTH) { info.set(id, { status: 'invalid', s: copies.get(id)[0] }); return; }
      if (!copies.has(cur.authorisedBy)) { info.set(id, { status: 'pending', s: copies.get(id)[0] }); return; }
      walk.push(cur.authorisedBy);
      cur = copies.get(cur.authorisedBy)[0];
    }
    for (let i = walk.length - 1; i >= 0; i--) validateOne(walk[i], i === walk.length - 1 ? null : walk[i + 1]);
  };
  for (const id of copies.keys()) check(id);

  // 3. Index the valid statements: buckets by authorisedBy, and who names whom.
  const buckets = new Map(); // authorisedBy -> { key, depth, removals: [], grants: [] }
  const namedBy = new Map(); // target id -> [revoke/endorse ids naming it]
  for (const [id, x] of info) {
    if (x.status !== 'valid') continue;
    const key = x.s.authorisedBy;
    if (!buckets.has(key)) buckets.set(key, { key, depth: x.depth, removals: [], grants: [] });
    buckets.get(key)[x.s.kind === 'grant' ? 'grants' : 'removals'].push(id);
    if (x.s.kind !== 'grant') for (const t of x.s.targets) {
      if (!namedBy.has(t)) namedBy.set(t, []);
      namedBy.get(t).push(id);
    }
  }
  const bytewise = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b));
  for (const list of namedBy.values()) list.sort(bytewise);
  const status = new Map([...info].map(([id, x]) => [id, x.status]));
  for (const id of malformed) if (!status.has(id)) status.set(id, 'invalid');
  const inForce = new Set();
  const keptBy = new Map(); // in-force id -> the bucket that keeps it (its own, or its rescuer's)
  const charged = new Map(); // bucket -> statements kept by it, its own and those it rescued
  const delegates = new Map(); // bucket -> delegating grants kept by it, its own and rescued
  const kindOf = (id) => info.get(id).s.kind;
  const isDelegating = (id) => kindOf(id) === 'grant' && DELEGATING_ROLES.has(info.get(id).s.role);
  const quotaOf = (bucket) => (bucket === 'anchor' ? anchorQuota : quota);
  // Keep id in bucket if it has room: Q statements, and (unless it is the anchor's) the delegate quota.
  const keep = (bucket, id) => {
    if ((charged.get(bucket) ?? 0) >= quotaOf(bucket)) return false;
    if (isDelegating(id) && bucket !== 'anchor' && (delegates.get(bucket) ?? 0) >= delegateQuota) return false;
    charged.set(bucket, (charged.get(bucket) ?? 0) + 1);
    if (isDelegating(id)) delegates.set(bucket, (delegates.get(bucket) ?? 0) + 1);
    inForce.add(id);
    status.set(id, 'in-force');
    keptBy.set(id, bucket);
    return true;
  };
  // An endorse e may rescue s iff s is not anchor-level and e's authority lies strictly above the
  // grant that authorises s (e could remove that grant). A revoke r may remove grant g iff r's
  // authority is the anchor or lies on g's chain above g.
  const mayRescue = (e, s) => {
    const sa = info.get(s);
    return sa.s.authorisedBy !== 'anchor' && (info.get(e).s.authorisedBy === 'anchor' || sa.chain.slice(1).includes(info.get(e).s.authorisedBy));
  };
  const mayRemove = (r, g) => info.get(r).s.authorisedBy === 'anchor' || info.get(g).chain.includes(info.get(r).s.authorisedBy);
  const removed = (g) => (namedBy.get(g) ?? []).some((r) => kindOf(r) === 'revoke' && inForce.has(r) && mayRemove(r, g));
  // Cut by a revoke: past the dead grants on its chain, the first grant that is not dead is removed.
  // A statement cut by a quota (the first such grant is over quota) is never rescued.
  const cutByRevoke = (id) => {
    for (const up of info.get(id).chain) {
      const st = status.get(up);
      if (st !== 'dead') return st === 'removed';
    }
    return false;
  };
  // Rescue: charge s to the first in-force endorse naming it, in ascending id order, that may rescue
  // it and whose bucket has room. Endorses are never rescued, so the rescuer's bucket is in force.
  const rescue = (id) => {
    const rescuers = (namedBy.get(id) ?? []).filter((e) => kindOf(e) === 'endorse' && inForce.has(e) && mayRescue(e, id));
    for (const e of rescuers) if (keep(info.get(e).s.authorisedBy, id)) return;
    status.set(id, rescuers.length ? 'over-quota' : 'dead');
  };

  // 4. Depth by depth: revokes and endorses first (phase A), then grants (phase B). In each phase a
  // bucket whose authorising grant is in force keeps its own statements by ascending id; then the
  // statements of the other buckets that a revoke cut off are offered for rescue, by ascending id.
  for (let d = 1; d <= MAX_DELEGATION_DEPTH; d++) {
    const level = [...buckets.values()].filter((b) => b.depth === d);
    const up = (b) => b.key === 'anchor' || inForce.has(b.key);
    const candidates = [];
    for (const b of level) {
      if (up(b)) {
        for (const id of [...b.removals].sort(bytewise)) if (!keep(b.key, id)) status.set(id, 'over-quota');
      } else {
        for (const id of b.removals) {
          if (kindOf(id) === 'revoke' && cutByRevoke(id)) candidates.push(id); else status.set(id, 'dead');
        }
      }
    }
    for (const id of candidates.sort(bytewise)) rescue(id);
    const grantCandidates = [];
    for (const b of level) {
      if (up(b)) {
        const standing = [];
        for (const id of b.grants) if (removed(id)) status.set(id, 'removed'); else standing.push(id);
        for (const id of standing.sort(bytewise)) if (!keep(b.key, id)) status.set(id, 'over-quota');
      } else {
        for (const id of b.grants) {
          if (!cutByRevoke(id)) status.set(id, 'dead');
          else if (removed(id)) status.set(id, 'removed');
          else grantCandidates.push(id);
        }
      }
    }
    for (const id of grantCandidates.sort(bytewise)) rescue(id);
  }

  // 5. Roles follow the key: (nodeId, key) of every in-force grant, with its scope, plus every
  // member of a threshold-1 anchor that is pinned with its nodeId.
  const roles = new Map();
  const addRole = (nodeId, key, role, scope) => {
    const k = `${nodeId} ${key}`;
    if (!roles.has(k)) roles.set(k, []);
    roles.get(k).push({ role, scope: scope ?? null });
  };
  for (const id of inForce) {
    const s = info.get(id).s;
    if (s.kind === 'grant') addRole(s.subject.nodeId, s.subject.key, s.role, s.scope);
  }
  if (pin.threshold === 1) for (const m of pin.keys) if (m.nodeId) addRole(m.nodeId, m.key, 'anchor', null);
  for (const list of roles.values()) list.sort((a, b) => (`${a.role} ${a.scope ?? ''}` < `${b.role} ${b.scope ?? ''}` ? -1 : 1));
  const live = new Set(inForce);
  for (const id of inForce) for (const upId of info.get(id).chain) live.add(upId);
  const inForceIds = sortedBytewise(inForce);
  return {
    status,
    inForce: inForceIds,
    live: sortedBytewise(live),
    roles,
    keptBy,
    depthOf: (id) => info.get(id)?.depth,
    // The copy a node keeps for a valid statement: the one whose signatures it counted.
    statementOf: (id) => (info.get(id)?.status === 'valid' ? info.get(id).s : undefined),
    chainOf: (id) => info.get(id)?.chain,
    root: authorityRoot(pin, inForceIds),
  };
}

// The lifecycle a set of role entries lets a node advance a CMB to (§3.5), for a CMB the caller
// says is or is not inside each scope. An unscoped entry reaches every CMB; a scoped one only CMBs
// inside its scope. An extension defines what "inside" means for its namespace; a receiver that does
// not implement the namespace treats no CMB as inside it.
export function lifecycleAuthority(entries, inScope = () => false) {
  const rank = { none: 0, validated: 1, canonical: 2 };
  let best = 'none';
  for (const { role, scope } of entries ?? []) {
    const reach = LIFECYCLE_AUTHORITY[role] ?? 'none';
    if ((scope === null || scope === undefined || inScope(scope)) && rank[reach] > rank[best]) best = reach;
  }
  return best;
}

// The order in which a node sends a set: depth, then revokes and endorses before grants, then id.
// Every statement then arrives after everything that can change its standing (§6.6.8).
export function authorityOrder(entries) {
  const rank = (s) => (s.kind === 'grant' ? 1 : 0);
  return [...entries].sort((a, b) => a.depth - b.depth || rank(a.s) - rank(b.s) || Buffer.compare(Buffer.from(a.id), Buffer.from(b.id)));
}

// sym-attest-v1 (Draft Candidate Extension, /spec/mmp/extensions/sym-attest): the four signed
// constructions and the chained checkpoint root.
const ATTEST_DOMAIN = {
  attestation: 'mmp-attest-v1\n',
  checkpoint: 'mmp-attest-checkpoint-v1\n',
  witness: 'mmp-attest-witness-v1\n',
  leaf: 'mmp-attest-leaf-v1\n',
  node: 'mmp-attest-node-v1\n',
  chain: 'mmp-attest-chain-v1\n',
};
const nfcText = (v) => String(v).normalize('NFC');

export function attestationPayloadV1(a) {
  return Buffer.concat([
    Buffer.from(ATTEST_DOMAIN.attestation, 'utf8'),
    lp(a.of), lp(a.assertionId), lp(a.by), lp(decimal(a.at)), lp(nfcText(a.room)),
    lp(a.method), lp(a.verdict),
    ...CAT7.map((name) => lp(a.categories[name])),
    lp(a.role), lp(decimal(a.seq)), lp(a.prev),
  ]);
}

// prev of the next attestation: the lowercase hex SHA-256 of this one's signature bytes.
export function attestChainLink(sigBase64url) {
  return sha256Hex(Buffer.from(sigBase64url, 'base64url'));
}

// The promote-odd Merkle root over a segment's signature bytes, in seq order.
export function attestSegmentRoot(sigsBase64url) {
  if (sigsBase64url.length === 0) throw new Error('a segment holds at least one attestation');
  let level = sigsBase64url.map((s) => sha256(Buffer.concat([Buffer.from(ATTEST_DOMAIN.leaf, 'utf8'), Buffer.from(s, 'base64url')])));
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? sha256(Buffer.concat([Buffer.from(ATTEST_DOMAIN.node, 'utf8'), level[i], level[i + 1]])) : level[i]);
    }
    level = next;
  }
  return level[0].toString('hex');
}

export function attestCheckpointRoot({ prev, fromSeq, uptoSeq, segmentRoot }) {
  return sha256Hex(Buffer.concat([
    Buffer.from(ATTEST_DOMAIN.chain, 'utf8'),
    lp(prev), lp(decimal(fromSeq)), lp(decimal(uptoSeq)), lp(segmentRoot),
  ]));
}

export function attestCheckpointPayloadV1(cp) {
  return Buffer.concat([
    Buffer.from(ATTEST_DOMAIN.checkpoint, 'utf8'),
    lp(cp.by), lp(nfcText(cp.room)), lp(decimal(cp.fromSeq)), lp(decimal(cp.uptoSeq)),
    lp(cp.prev), lp(cp.root), lp(decimal(cp.at)),
  ]);
}

export function attestWitnessPayloadV1(w) {
  return Buffer.concat([
    Buffer.from(ATTEST_DOMAIN.witness, 'utf8'),
    lp(w.attester), lp(nfcText(w.room)), lp(decimal(w.fromSeq)), lp(decimal(w.uptoSeq)), lp(w.root),
    lp(w.by), lp(w.role), lp(decimal(w.at)),
  ]);
}

// §5.2: the same checkpoint is not a conflict; otherwise overlapping ranges, or one prev with two
// children, prove two histories. Returns the reasons, empty when the two can lie on one chain.
export function attestCheckpointConflict(a, b) {
  if (a.by !== b.by) return [];
  const same = a.fromSeq === b.fromSeq && a.uptoSeq === b.uptoSeq && a.prev === b.prev && a.root === b.root;
  if (same) return [];
  const reasons = [];
  if (a.fromSeq <= b.uptoSeq && b.fromSeq <= a.uptoSeq) reasons.push('overlapping ranges');
  if (a.prev === b.prev) reasons.push('same prev');
  return reasons;
}

// §5.2 link checks: the range is not reversed, and when the checkpoint named by prev is held, the new
// one starts right after it. A failure is malformed, not evidence.
export function attestCheckpointLinkValid(cp, prevCheckpoint = null) {
  if (cp.uptoSeq < cp.fromSeq) return false;
  if ((cp.fromSeq === 1) !== (cp.prev === 'genesis')) return false;
  if (prevCheckpoint && prevCheckpoint.root === cp.prev && cp.fromSeq !== prevCheckpoint.uptoSeq + 1) return false;
  return true;
}
