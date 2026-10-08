'use strict';

/**
 * MMP §6.6 against the attacks its reviews found, built here with fresh keys at full scale
 * (AUTHORITY_QUOTA 256, AUTHORITY_DELEGATE_QUOTA 16), and the old faces of the time-replay rule
 * (arrival order, backdating, floods, cycles), which the new rule removes by construction. The
 * published vectors (authority-vectors.test.js) hold the same attacks at test scale.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const A = require('../lib/core/authority');
const { AuthorityStore, lifecycleOf } = require('../lib/authority-store');

// ── A small builder ───────────────────────────────────────────────────────────

const PRIV = new Map(); // public key -> private key
function party() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const key = publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('base64url');
  PRIV.set(key, privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(16).toString('base64url'));
  const b = crypto.randomBytes(16).toString('hex');
  return { nodeId: `${b.slice(0, 8)}-${b.slice(8, 12)}-${b.slice(12, 16)}-${b.slice(16, 20)}-${b.slice(20)}`, key };
}
const anchorKey = party();
const PIN = A.parsePin({ threshold: 1, keys: [{ key: anchorKey.key, nodeId: anchorKey.nodeId }] });
const id = (s) => A.statementId(s);
/** A statement by `by` (a grant statement, or 'anchor'), signed by the key it must be signed by. */
function make(by, fields, extra = {}) {
  const s = { ...fields, authorisedBy: by === 'anchor' ? 'anchor' : id(by), nonce: A.freshNonce(), ...extra, sigs: [] };
  const key = by === 'anchor' ? anchorKey.key : by.subject.key;
  return A.signStatement(s, PRIV.get(key), key);
}
const grant = (by, subject, role, scope, extra) => make(by, { kind: 'grant', subject, role, ...(scope ? { scope } : {}) }, extra);
const revoke = (by, targets, extra) => make(by, { kind: 'revoke', targets: targets.map(id) }, extra);
const endorse = (by, targets, extra) => make(by, { kind: 'endorse', targets: targets.map(id) }, extra);
function store(statements, opts = {}) {
  const st = new AuthorityStore({ pin: PIN, ...opts });
  let left = statements;
  for (let progress = true; progress && left.length;) {
    progress = false;
    const next = [];
    for (const s of left) { const r = st.ingest(s); if (r.result === 'held') progress = true; else if (r.result === 'pending') next.push(s); }
    left = next;
  }
  return st;
}
const status = (st, s) => st.statusOf(id(s)) || 'not held';
const byId = (list) => [...list].sort((x, y) => (id(x) < id(y) ? -1 : 1));
function shuffled(list) { const a = [...list]; for (let i = a.length - 1; i > 0; i--) { const j = crypto.randomInt(i + 1); [a[i], a[j]] = [a[j], a[i]]; } return a; }
/** A statement whose id sorts below (or above) `than`'s, made by retrying nonces. */
function ordered(makeOne, than, below) {
  for (;;) { const s = makeOne(); if ((id(s) < id(than)) === below) return s; }
}

// ── The reviewers' attacks ────────────────────────────────────────────────────

describe('§6.6 against the review attacks, at full scale', () => {
  it('r2: admins hung under over-quota grants are dead, and an endorse cannot rescue a cut by a quota', () => {
    const gA = grant('anchor', party(), 'admin');
    const D = Array.from({ length: 20 }, () => grant(gA, party(), 'admin'));
    const [kept, over] = [byId(D).slice(0, 16), byId(D).slice(16)];
    const C = over.map((d) => grant(d, party(), 'admin'));
    const below = C.map((c) => grant(c, party(), 'validator'));
    const eAnchor = endorse('anchor', C);
    const st = store(shuffled([gA, ...D, ...C, ...below, eAnchor]));
    for (const d of kept) assert.strictEqual(status(st, d), 'in-force');
    for (const d of over) assert.strictEqual(status(st, d), 'over-quota', 'the delegate quota decides by id');
    for (const s of [...C, ...below]) assert.strictEqual(status(st, s), 'dead', 'cut by a quota, never rescued');
    const delegating = st.inForceStatements().filter((s) => s.authorisedBy === id(gA) && A.isDelegating(s.role));
    assert.strictEqual(delegating.length, 16);
  });

  it('r2 laundered: the admin revokes its own over-quota grants; their rescue is charged to the endorser\'s bucket, and the admin\'s is full', () => {
    const gA = grant('anchor', party(), 'admin');
    const D = Array.from({ length: 20 }, () => grant(gA, party(), 'admin'));
    const over = byId(D).slice(16);
    const C = over.map((d) => grant(d, party(), 'admin'));
    const launder = revoke(gA, over);
    const selfRescue = endorse(gA, C);
    const st = store(shuffled([gA, ...D, ...C, launder, selfRescue]));
    assert.strictEqual(status(st, launder), 'in-force');
    for (const d of over) assert.strictEqual(status(st, d), 'removed', 'the laundering revoke turns a cut by quota into a cut by revoke');
    for (const c of C) assert.strictEqual(status(st, c), 'over-quota', 'and the rescue it bought is charged to the admin\'s own full delegate quota');
    const inForceBelow = [...st.resolve().inForce].filter((x) => st._held.get(x).chain.includes(id(gA)));
    assert.strictEqual(inForceBelow.length, 16 + 2, 'sixteen admins, the revoke and the endorse: nothing more below gA');
    // The anchor can keep them, in its own bucket: authority it holds, spent where it is accounted.
    const eAnchor = endorse('anchor', C);
    const st2 = store(shuffled([gA, ...D, ...C, launder, selfRescue, eAnchor]));
    for (const c of C) {
      assert.strictEqual(status(st2, c), 'in-force');
      assert.strictEqual(st2.resolve().keptBy.get(id(c)), 'anchor');
    }
  });

  it('r1: depth-3 admins under an over-quota grant stay dead, with everything they sign; the root ignores them', () => {
    const gA = grant('anchor', party(), 'admin');
    const D = Array.from({ length: 17 }, () => grant(gA, party(), 'admin'));
    const overD = byId(D)[16];
    const C = grant(overD, party(), 'admin');
    const flood = Array.from({ length: 40 }, () => grant(C, party(), 'validator')); // depth 4
    const base = store([gA, ...D]);
    const st = store(shuffled([gA, ...D, C, ...flood, endorse('anchor', [C])]));
    assert.strictEqual(status(st, overD), 'over-quota');
    for (const s of [C, ...flood]) assert.strictEqual(status(st, s), 'dead');
    // Dead statements change nothing; the anchor's endorse of a quota cut is in force and keeps nothing.
    assert.strictEqual(st.inForceStatements().length, base.inForceStatements().length + 1);
    const withoutEndorse = store(shuffled([gA, ...D, C, ...flood]));
    assert.strictEqual(withoutEndorse.root(), base.root(), 'held but dead: no effect on the root');
  });

  it('self-revoke: a revoke naming its own authorising grant, or a grant above it, removes nothing', () => {
    const gA = grant('anchor', party(), 'admin');
    const gB = grant(gA, party(), 'admin');
    const gP = grant(gB, party(), 'participant');
    const selfRevoke = revoke(gB, [gB, gA]);
    const st = store([gA, gB, gP, selfRevoke]);
    for (const s of [gA, gB, gP, selfRevoke]) assert.strictEqual(status(st, s), 'in-force');
  });

  it('scope: w1/../w2 and w1/./x are not well formed, w10 is not inside w1, a dropped scope widens; w1/region-a narrows', () => {
    const W = grant('anchor', party(), 'admin', 'xmesh-world:w1');
    const attempts = {
      dotdot: grant(W, party(), 'issuer', 'xmesh-world:w1/../w2'),
      dot: grant(W, party(), 'issuer', 'xmesh-world:w1/./region-a'),
      w10: grant(W, party(), 'issuer', 'xmesh-world:w10'),
      sideways: grant(W, party(), 'issuer', 'xmesh-world:w2'),
      dropped: grant(W, party(), 'issuer'),
      prefix: grant(W, party(), 'issuer', 'xmesh-worlds:w1'),
    };
    const st = new AuthorityStore({ pin: PIN });
    assert.strictEqual(st.ingest(W).result, 'held');
    for (const [name, s] of Object.entries(attempts)) assert.strictEqual(st.ingest(s).result, 'invalid', name);
    const region = grant(W, party(), 'validator', 'xmesh-world:w1/region-a');
    assert.strictEqual(st.ingest(region).result, 'held');
    assert.strictEqual(st.statusOf(id(region)), 'in-force');
    // Lifecycle inside a scope is by whole segments: w1/region-a contains w1/region-a/x, never w1/region-ab or w10.
    const roles = st.rolesOf(region.subject.nodeId, region.subject.key);
    const inside = (cmbScope) => (scope) => A.scopeNarrows(scope, cmbScope);
    assert.strictEqual(lifecycleOf(roles, inside('xmesh-world:w1/region-a/x')), 'validated');
    assert.strictEqual(lifecycleOf(roles, inside('xmesh-world:w1/region-ab')), 'none');
    assert.strictEqual(lifecycleOf(roles, inside('xmesh-world:w10')), 'none');
    assert.strictEqual(lifecycleOf(roles, inside('xmesh-world:w1')), 'none', 'a narrower grant has nothing over the wider scope');
    assert.strictEqual(lifecycleOf(roles, () => false), 'none', 'and nothing outside every scope');
  });

  it('w10 under w1: a scoped admin\'s grant to xmesh-world:w10 is refused; one to w1 itself is accepted', () => {
    const W = grant('anchor', party(), 'admin', 'xmesh-world:w1');
    const w10 = grant(W, party(), 'admin', 'xmesh-world:w10');
    const same = grant(W, party(), 'admin', 'xmesh-world:w1');
    const st = store([W, w10, same]);
    assert.strictEqual(status(st, w10), 'not held');
    assert.strictEqual(status(st, same), 'in-force');
  });

  it('17 issuers in one bucket: 16 are in force, the highest id is over quota, in every order; its seats are dead', () => {
    const W = grant('anchor', party(), 'admin', 'xmesh-world:w1');
    const I = Array.from({ length: 17 }, () => grant(W, party(), 'issuer', 'xmesh-world:w1'));
    const top = byId(I)[16];
    const seats = Array.from({ length: 3 }, () => grant(top, party(), 'xmesh-seat', 'xmesh-world:w1'));
    let root = null;
    for (let round = 0; round < 5; round++) {
      const st = store(shuffled([W, ...I, ...seats]));
      for (const i of byId(I).slice(0, 16)) assert.strictEqual(status(st, i), 'in-force');
      assert.strictEqual(status(st, top), 'over-quota');
      for (const s of seats) assert.strictEqual(status(st, s), 'dead');
      if (root) assert.strictEqual(st.root(), root);
      root = st.root();
    }
  });

  it('rescue falls through: the lower endorser\'s bucket is full, so the next endorser by id keeps the grant', () => {
    const gA = grant('anchor', party(), 'admin');
    const gB = grant(gA, party(), 'admin');
    const gV = grant(gB, party(), 'validator');
    const gP = grant(gV, party(), 'participant');
    const rV = revoke(gA, [gV]);
    const eA = endorse(gA, [gP]);
    const eB = ordered(() => endorse(gB, [gP]), eA, true); // gB's endorse sorts first
    // Room in both buckets: the lower endorse by id keeps it, in its own bucket.
    let st = store(shuffled([gA, gB, gV, gP, rV, eA, eB]));
    assert.strictEqual(status(st, gV), 'removed');
    assert.strictEqual(status(st, gP), 'in-force');
    assert.strictEqual(st.resolve().keptBy.get(id(gP)), id(gB));
    // gB's bucket full (its endorse and 255 participants: the removed validator takes no place).
    const fill = Array.from({ length: 255 }, () => grant(gB, party(), 'participant'));
    st = store(shuffled([gA, gB, gV, gP, rV, eA, eB, ...fill]));
    assert.strictEqual(fill.filter((f) => status(st, f) === 'in-force').length, 255);
    assert.strictEqual(status(st, gP), 'in-force', 'it falls through to the next endorser');
    assert.strictEqual(st.resolve().keptBy.get(id(gP)), id(gA));
    // Both full: over quota (tried and failed), never in force.
    const fillA = Array.from({ length: 256 - 3 }, () => grant(gA, party(), 'participant')); // + gB, rV, eA
    st = store(shuffled([gA, gB, gV, gP, rV, eA, eB, ...fill, ...fillA]));
    assert.strictEqual(status(st, gP), 'over-quota');
  });

  it('an endorse does not override a revoke: the endorsed grant is removed while the revoke is in force', () => {
    const gA = grant('anchor', party(), 'admin');
    const gV = grant(gA, party(), 'validator');
    const rV = revoke(gA, [gV]);
    const eV = endorse('anchor', [gV]);
    const st = store(shuffled([gA, gV, rV, eV]));
    assert.strictEqual(status(st, gV), 'removed');
  });
});

// ── The old faces, impossible by construction ─────────────────────────────────

/** A random tree with revokes and endorses, every statement signed by the key it must be. */
function randomMesh(n = 60) {
  const grants = [grant('anchor', party(), 'admin'), grant('anchor', party(), 'admin')];
  const all = [...grants];
  for (let i = 0; i < n; i++) {
    const by = grants[crypto.randomInt(grants.length)];
    const depth = (s) => { let d = 1; let x = s; while (x.authorisedBy !== 'anchor') { d++; x = all.find((y) => id(y) === x.authorisedBy); } return d; };
    const roll = crypto.randomInt(10);
    if (by.role === 'admin' && depth(by) < 4 && roll < 5) {
      const g = grant(by, party(), ['admin', 'validator', 'participant'][crypto.randomInt(3)]);
      all.push(g); if (g.role !== 'participant') grants.push(g);
    } else if (roll < 7) {
      // A revoke of something below `by`, or of anything at all (off its chain: inert).
      const t = all[crypto.randomInt(all.length)];
      if (A.isDelegating(by.role) && id(t) !== id(by)) all.push(revoke(by, [t]));
    } else if (by.role === 'admin') {
      const t = all[crypto.randomInt(all.length)];
      if (id(t) !== id(by)) all.push(endorse(by, [t]));
    } else {
      all.push(grant(by, party(), 'participant'));
    }
  }
  return all;
}

describe('§6.6: the old faces of the time-replay rule are gone', () => {
  it('arrival order: random meshes resolve to the same statuses and root in every order', () => {
    for (let m = 0; m < 4; m++) {
      const all = randomMesh(70);
      const first = store(all);
      const want = new Map([...first.resolve().status]);
      for (let k = 0; k < 12; k++) {
        const st = store(shuffled(all));
        assert.strictEqual(st.root(), first.root());
        assert.deepStrictEqual(new Map([...st.resolve().status]), want);
      }
      // Two stores fed different halves, then each other's: the same root.
      const half = shuffled(all);
      const a = store(half.slice(0, 35)); const b = store(half.slice(35));
      for (const s of half.slice(35)) a.ingest(s);
      for (const s of half.slice(0, 35)) b.ingest(s);
      const settle = (x) => { for (let i = 0; i < 5; i++) for (const s of all) x.ingest(s); };
      settle(a); settle(b);
      assert.strictEqual(a.root(), first.root());
      assert.strictEqual(b.root(), first.root());
    }
  });

  it('backdating: issuedAt decides nothing; a revoke "dated" before its target still removes it; quotas decide by id', () => {
    const gA = grant('anchor', party(), 'admin', undefined, { issuedAt: 2_000_000_000_000 });
    const gV = grant(gA, party(), 'validator', undefined, { issuedAt: 1_900_000_000_000 });
    const rV = revoke(gA, [gV], { issuedAt: 0 });
    let st = store([gA, gV, rV]);
    assert.strictEqual(status(st, gV), 'removed', 'a revoke "older" than its target applies');
    // A bucket at quota (test quota 3) keeps by id, whatever the dates say.
    const G = Array.from({ length: 6 }, (_, i) => grant(gA, party(), 'participant', undefined, { issuedAt: i % 2 ? 0 : 9_000_000_000_000 }));
    st = store(shuffled([gA, ...G]), { quota: 3 });
    assert.deepStrictEqual(byId(G).map((g) => status(st, g)), ['in-force', 'in-force', 'in-force', 'over-quota', 'over-quota', 'over-quota']);
    // The same fields re-issued with another date are another statement: both stand side by side.
    const again = { ...A.canonicalStatement(gV, []), issuedAt: 5 };
    delete again.sigs;
    const re = A.signStatement({ ...again, sigs: [] }, PRIV.get(gA.subject.key), gA.subject.key);
    assert.notStrictEqual(id(re), id(gV));
    // And no clock is read: the same set resolves to the same root at any time of day.
    const realNow = Date.now;
    try {
      const roots = [0, 1e15].map((t) => { Date.now = () => t; return store([gA, gV, rV]).root(); });
      assert.strictEqual(roots[0], roots[1]);
    } finally { Date.now = realNow; }
  });

  it('floods: one bucket flooding keeps at most its quota and changes no other bucket; forged anchor floods are invalid', () => {
    const gA = grant('anchor', party(), 'admin');
    const gB = grant('anchor', party(), 'admin');
    const honest = Array.from({ length: 10 }, () => grant(gB, party(), 'validator'));
    const before = store([gA, gB, ...honest]);
    const flood = Array.from({ length: 1200 }, (_, i) => grant(gA, party(), i % 3 ? 'participant' : 'validator'));
    const st = store(shuffled([gA, gB, ...honest, ...flood]));
    const fromA = st.inForceStatements().filter((s) => s.authorisedBy === id(gA));
    assert.strictEqual(fromA.length, 256);
    assert.ok(fromA.filter((s) => A.isDelegating(s.role)).length <= 16);
    for (const h of honest) assert.strictEqual(status(st, h), status(before, h));
    // Anchor-level statements not signed by the pinned key: none is held.
    const intruder = party();
    const forged = Array.from({ length: 50 }, () => A.signStatement({ kind: 'grant', authorisedBy: 'anchor', subject: party(), role: 'admin', nonce: A.freshNonce(), sigs: [] }, PRIV.get(intruder.key), intruder.key));
    const st2 = new AuthorityStore({ pin: PIN });
    for (const f of forged) assert.strictEqual(st2.ingest(f).result, 'invalid');
    assert.strictEqual(st2.size(), 0);
  });

  it('cycles: authorisedBy is inside the hashed bytes, so a chain is fixed when signed; one that is not rooted stays pending and confers nothing', () => {
    const gA = grant('anchor', party(), 'admin');
    // A statement cannot name itself: its id is a hash over its own authorisedBy.
    const s = grant(gA, party(), 'admin');
    const selfNamed = { ...A.canonicalStatement(s, []), authorisedBy: id(s) };
    assert.notStrictEqual(A.statementId(selfNamed), id(s));
    // A chain of statements hanging from an id nobody holds: pending, then never in force.
    const ghost = `auth-${crypto.randomBytes(32).toString('hex')}`;
    const fake = { subject: party(), role: 'admin' };
    const g1 = A.signStatement({ kind: 'grant', authorisedBy: ghost, subject: fake.subject, role: 'admin', nonce: A.freshNonce(), sigs: [] }, PRIV.get(gA.subject.key), gA.subject.key);
    const g2 = grant(g1, party(), 'admin');
    const st = new AuthorityStore({ pin: PIN });
    st.ingest(gA);
    assert.strictEqual(st.ingest(g1).result, 'pending');
    assert.strictEqual(st.ingest(g2).result, 'pending');
    assert.strictEqual(st.size(), 1);
    // A fifth link is too deep however it is reached.
    const chain = [gA];
    for (let d = 2; d <= 5; d++) chain.push(grant(chain[chain.length - 1], party(), 'admin'));
    const st2 = store(chain);
    assert.deepStrictEqual(chain.map((c) => status(st2, c)), ['in-force', 'in-force', 'in-force', 'in-force', 'not held']);
  });
});

// ── Capacity (§6.6.6: removals first; one signer never displaces another) ─────

describe('§6.6 capacity: a full store keeps what comes first in authority order', () => {
  /** Two admins whose in-force subtrees fill a store of 600 (the release review's scene). */
  function flood() {
    const all = []; const admins = [];
    for (let c = 0; c < 2; c++) {
      const gA = grant('anchor', party(), 'admin'); all.push(gA); admins.push(gA);
      const subs = Array.from({ length: 16 }, () => grant(gA, party(), 'admin'));
      all.push(...subs);
      for (let i = 0; i < 240; i++) all.push(grant(gA, party(), 'participant'));
      for (const g of subs) for (let i = 0; i < 4; i++) all.push(grant(g, party(), 'participant'));
    }
    return { all, admins };
  }

  it('the anchor\'s revoke of the flooding admins is taken, and the store resolves as an unbounded one does', () => {
    const { all, admins } = flood();
    const st = new AuthorityStore({ pin: PIN, maxHeld: 600 });
    for (const x of all) st.ingest(x);
    assert.ok(st.size() <= 600);
    const r = revoke('anchor', admins);
    assert.strictEqual(st.ingest(r).result, 'held', 'a revoke is never refused for capacity');
    for (const g of admins) assert.strictEqual(st.statusOf(id(g)), 'removed');
    const unbounded = store([...all, r]);
    assert.deepStrictEqual([...st.resolve().inForce].sort(), [...unbounded.resolve().inForce].sort());
  });

  it('a deep grant that comes last in a full store is refused, as over capacity; an in-force anchor-level grant or revoke never is', () => {
    const gA = grant('anchor', party(), 'admin');
    const sub = grant(gA, party(), 'admin');
    const st = new AuthorityStore({ pin: PIN, maxHeld: 100 });
    st.ingest(gA); st.ingest(sub);
    for (let i = 0; i < 98; i++) st.ingest(grant(gA, party(), 'participant'));
    assert.strictEqual(st.size(), 100);
    const deep = grant(sub, party(), 'participant'); // depth 3: the last in authority order
    assert.strictEqual(st.ingest(deep).result, 'over-capacity');
    assert.strictEqual(st.has(id(deep)), false);
    while (st.size() < 100) st.ingest(grant(gA, party(), 'participant'));
    assert.strictEqual(st.ingest(grant('anchor', party(), 'validator')).result, 'held');
    while (st.size() < 100) st.ingest(grant(gA, party(), 'participant'));
    // A revoke in force in gA's bucket (sub itself may have gone in a pass: it is a live grant like any).
    const r = make(gA, { kind: 'revoke', targets: [`auth-${crypto.randomBytes(32).toString('hex')}`] });
    assert.strictEqual(st.ingest(r).result, 'held');
    assert.strictEqual(st.statusOf(id(r)), 'in-force');
  });

  it('in-force anchor-level statements and in-force revokes are kept past the bound; the quotas bound them', () => {
    const st = new AuthorityStore({ pin: PIN, maxHeld: 30 });
    const top = Array.from({ length: 25 }, () => grant('anchor', party(), 'admin'));
    for (const g of top) st.ingest(g);
    const revokes = top.slice(0, 10).map((g) => revoke(g, [g])); // in force, each in its own bucket
    for (const r of revokes) assert.strictEqual(st.ingest(r).result, 'held');
    for (const g of top.slice(10)) for (let i = 0; i < 3; i++) st.ingest(grant(g, party(), 'participant'));
    for (const x of [...top, ...revokes]) assert.strictEqual(st.has(id(x)), true, 'in-force removals and anchor-level statements stay');
    assert.ok(st.size() >= 35, 'past the bound, since nothing else is left to drop');
    assert.ok(st.capacityReport().liveDropped > 0 || st.capacityReport().refused > 0, 'the grants below went');
  });

  // The re-review of 390b4af (rr-capacity-revokes, rr-capacity-displace): validity is static, so a
  // removed admin can sign any number of valid, dead revokes, and an in-force one any number of
  // over-quota ones. They are ordinary candidates: outside the live set, the first to go.
  function capacityScene(variant) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'auth-cap-'));
    const st = new AuthorityStore({ pin: PIN, maxHeld: 200, dir });
    const gA = grant('anchor', party(), 'admin');
    st.ingest(gA);
    if (variant === 'dead') st.ingest(revoke('anchor', [gA]));
    let resolves = 0;
    const resolve = st.resolve.bind(st);
    st.resolve = () => { if (st.dirty) resolves++; return resolve(); };
    for (let i = 0; i < 2000; i++) {
      const r = make(gA, { kind: 'revoke', targets: [`auth-${crypto.randomBytes(32).toString('hex')}`] });
      st.ingest(r);
    }
    st.resolve = resolve;
    const lines = fs.readFileSync(path.join(dir, 'statements.jsonl'), 'utf8').trim().split('\n').length;
    const reloaded = new AuthorityStore({ pin: PIN, maxHeld: 200, dir });
    fs.rmSync(dir, { recursive: true, force: true });
    return { st, resolves, lines, reloaded, gA };
  }
  const SLACK = Math.ceil(200 / 64);

  it('2,000 dead revokes from a removed admin: the store stays at its bound, on disk too, and an arrival does not cost a resolve', () => {
    const { st, resolves, lines, reloaded } = capacityScene('dead');
    assert.ok(st.size() <= 200 + SLACK, `held ${st.size()}`);
    assert.ok(reloaded.size() <= 200 + SLACK, `after a reload ${reloaded.size()}`);
    // Compacted once it holds twice what the store keeps; appends run on until the next pass.
    assert.ok(lines <= 2 * (200 + SLACK) + 2 * SLACK + 2, `the file holds ${lines} lines: compacted, not growing`);
    assert.ok(resolves <= 2000 / SLACK + 5, `${resolves} resolves for 2,000 arrivals: one per eviction pass, not per arrival`);
  });

  it('2,000 over-quota revokes from an in-force admin: kept past the bound only as far as its bucket\'s quota', () => {
    const { st, lines, reloaded, gA, resolves } = capacityScene('over-quota');
    assert.ok(resolves <= 2000 / SLACK + 5, `${resolves} resolves for 2,000 arrivals: a full store of protected statements waits a batch between passes`);
    const inForce = [...st.resolve().inForce].filter((x) => st._held.get(x).authBy === id(gA)).length;
    assert.strictEqual(inForce, 256, 'the bucket keeps its quota of revokes in force');
    assert.ok(st.size() <= 1 + 256 + SLACK, `held ${st.size()}: the in-force revokes, bounded by the quota, and no more`);
    assert.ok(reloaded.size() <= 1 + 256 + SLACK);
    assert.ok(lines <= 2 * (1 + 256 + SLACK) + 2 * SLACK + 2, `the file holds ${lines} lines`);
  });

  it('dead revokes never displace an honest tree in force (one signer never displaces another)', () => {
    const st = new AuthorityStore({ pin: PIN, maxHeld: 300 });
    const honest = [];
    const gW = grant('anchor', party(), 'admin'); honest.push(gW);
    for (let i = 0; i < 15; i++) { const gI = grant(gW, party(), 'issuer'); honest.push(gI); for (let j = 0; j < 15; j++) honest.push(grant(gI, party(), 'participant')); }
    for (const x of honest) st.ingest(x);
    assert.strictEqual(honest.filter((x) => st.statusOf(id(x)) === 'in-force').length, 241);
    const gX = grant('anchor', party(), 'admin');
    st.ingest(gX); st.ingest(revoke('anchor', [gX]));
    for (let i = 0; i < 400; i++) st.ingest(make(gX, { kind: 'revoke', targets: [`auth-${crypto.randomBytes(32).toString('hex')}`] }));
    const r = st.resolve();
    assert.strictEqual(honest.filter((x) => r.inForce.has(id(x))).length, 241, 'every honest statement still in force');
    assert.ok(st.size() <= 300 + Math.ceil(300 / 64));
    assert.strictEqual(st.capacityReport().liveDropped, 0);
  });

  it('what is not live goes first, then the last in authority order; one sort frees a batch', () => {
    const gA = grant('anchor', party(), 'admin');
    const gB = grant('anchor', party(), 'admin');
    const dead = [];
    const rB = revoke('anchor', [gB]);
    const live = [gA, rB];
    for (let i = 0; i < 40; i++) live.push(grant(gA, party(), 'participant'));
    for (let i = 0; i < 40; i++) dead.push(grant(gB, party(), 'participant')); // under a removed grant
    const st = new AuthorityStore({ pin: PIN, maxHeld: 70 });
    for (const x of [gA, gB, rB, ...dead, ...live.slice(2)]) st.ingest(x);
    assert.ok(st.size() <= 70);
    for (const x of live) assert.strictEqual(st.has(id(x)), true, 'every live statement kept');
    const evicted = st.capacityReport().evicted;
    assert.ok(evicted >= 11, `the dead ones went (${evicted})`);
    // The batch: room was freed below the bound, so the next arrival needs no sort.
    const before = st.capacityReport().evicted;
    st.ingest(grant(gA, party(), 'participant'));
    assert.strictEqual(st.capacityReport().evicted, before);
  });
});
