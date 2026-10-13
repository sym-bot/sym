'use strict';

/**
 * MMP §6.6 and §18.3.2 conformance: every case of the published authority-v2 and ed25519-strict-v2
 * vectors, read from the copies vendored in tests/fixtures (their sha256 checked first against
 * SOURCES.json, which records the meshcognition-website commit they come from).
 *
 * Each authority case is resolved in many orders, and again with forged copies of its statements
 * mixed in (a copy re-signed by the wrong key, one with a flipped signature bit, an anchor copy short
 * of the threshold, an anchor copy padded with unpinned and repeated entries): the statuses, the
 * in-force set, the live set, which bucket keeps each statement, the roles, the lifecycle authority
 * each subject has inside and outside every scope, the stated bound, and the root must come out the
 * same every time.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const A = require('../lib/core/authority');
const { AuthorityStore, lifecycleOf } = require('../lib/authority-store');
const { verifyStrict, precheckFailure } = require('../lib/core/ed25519');

const FIX = path.join(__dirname, 'fixtures');
const sources = JSON.parse(fs.readFileSync(path.join(FIX, 'SOURCES.json'), 'utf8'));
function vendored(name) {
  const bytes = fs.readFileSync(path.join(FIX, name));
  assert.strictEqual(crypto.createHash('sha256').update(bytes).digest('hex'), sources.files[name].sha256, `${name}: the vendored copy is the published one`);
  return JSON.parse(bytes.toString('utf8'));
}
const av = vendored('authority-v2.json');
const ed = vendored('ed25519-strict-v2.json');

/** A deterministic shuffle. */
function shuffled(list, seed) {
  const a = [...list];
  let x = seed >>> 0 || 1;
  for (let i = a.length - 1; i > 0; i--) { x = (Math.imul(x, 1103515245) + 12345) >>> 0; const j = x % (i + 1); [a[i], a[j]] = [a[j], a[i]]; }
  return a;
}
/** Offer statements until a pass holds nothing more (what a node's pending holds and pulls do). */
function feed(store, statements) {
  const outcome = new Map();
  let left = statements;
  for (let progress = true; progress && left.length;) {
    progress = false;
    const next = [];
    for (const s of left) {
      const r = store.ingest(s);
      if (r.result !== 'duplicate') outcome.set(s, r); // the last word: pending, then held or invalid
      if (r.result === 'held') progress = true;
      else if (r.result === 'pending') next.push(s);
    }
    left = next;
  }
  return outcome;
}
const testKeys = av.testKeys;
const forgerSeed = Buffer.alloc(32, 0x5f);
const forger = (() => {
  const priv = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), forgerSeed]), format: 'der', type: 'pkcs8' });
  const pub = crypto.createPublicKey(priv).export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64url');
  return { priv: forgerSeed.toString('base64url'), pub };
})();
/** Copies of a statement that must change nothing: forged, short or padded. Same id, never valid alone. */
function forgedCopies(s) {
  const out = [];
  const flip = (sig) => { const b = Buffer.from(sig, 'base64url'); b[5] ^= 1; return b.toString('base64url'); };
  if (s.authorisedBy === 'anchor') {
    out.push({ ...s, sigs: s.sigs.map((e) => ({ key: e.key, sig: flip(e.sig) })) });
    out.push({ ...s, sigs: [...s.sigs, { key: forger.pub, sig: s.sigs[0].sig }, s.sigs[0]].slice(0, 16) });
  } else {
    out.push({ ...s, sigs: [{ key: s.sigs[0].key, sig: flip(s.sigs[0].sig) }] });
    const bare = A.canonicalStatement(s, []);
    out.push(A.signStatement(bare, forger.priv, forger.pub));
  }
  return out;
}

function resolveCase(c, order) {
  const pin = A.parsePin(av.pins[c.pin]);
  const store = new AuthorityStore({ pin, quota: c.testQuota, delegateQuota: c.testDelegateQuota });
  const outcome = feed(store, order);
  return { store, outcome, r: store.resolve() };
}
function statusOf(c, run) {
  const out = {};
  for (const l of c.statements) {
    const id = av.statements[l].expectedId;
    if (run.store.has(id)) out[l] = run.r.status.get(id);
    else {
      const r = run.outcome.get(av.statements[l].statement);
      out[l] = r && r.result === 'pending' ? 'pending' : 'invalid';
    }
  }
  return out;
}
function check(c, run, how) {
  assert.deepStrictEqual(statusOf(c, run), c.expected.status, `${c.label} (${how}): status`);
  assert.deepStrictEqual([...run.r.inForce].sort(), [...c.expected.inForce].sort(), `${c.label} (${how}): in force`);
  assert.deepStrictEqual([...run.r.live].sort(), [...c.expected.live].sort(), `${c.label} (${how}): live`);
  assert.deepStrictEqual(Object.fromEntries([...run.r.keptBy].sort()), Object.fromEntries(Object.entries(c.expected.keptBy).sort()), `${c.label} (${how}): kept by`);
  assert.strictEqual(run.r.root, c.expected.root, `${c.label} (${how}): root`);
  for (const row of c.expected.roles) {
    const got = run.store.rolesOf(row.nodeId, row.key).map((x) => ({ role: x.role, scope: x.scope }));
    const key = (x) => `${x.role}|${x.scope}`;
    assert.deepStrictEqual(got.map(key).sort(), row.roles.map(key).sort(), `${c.label} (${how}): roles of ${row.subject}`);
    assert.strictEqual(lifecycleOf(got, () => false), row.lifecycle.outsideEveryScope, `${c.label}: ${row.subject} outside every scope`);
    for (const [scope, level] of Object.entries(row.lifecycle.insideScope)) {
      assert.strictEqual(lifecycleOf(got, (s) => A.scopeNarrows(s, scope)), level, `${c.label}: ${row.subject} inside ${scope}`);
    }
  }
  if (c.expected.bound) {
    const top = av.statements[c.expected.bound.below].expectedId;
    const below = [...run.r.inForce].filter((id) => run.store._held.get(id).chain.includes(top));
    const delegating = below.filter((id) => { const e = run.store._held.get(id); return e.kind === 'grant' && A.isDelegating(e.role); });
    assert.strictEqual(below.length, c.expected.bound.inForceBelow, `${c.label}: in force below ${c.expected.bound.below}`);
    assert.strictEqual(delegating.length, c.expected.bound.delegatingBelow, `${c.label}: delegating below`);
    assert.ok(below.length <= c.expected.bound.maxStatements && delegating.length <= c.expected.bound.maxDelegating, `${c.label}: within the bound`);
  }
}

describe('authority-v2 (MMP §6.6): statements, ids and pins', () => {
  it('every statement\'s payload and id reproduce exactly; a mutated one is another statement that no longer verifies', () => {
    for (const [label, x] of Object.entries(av.statements)) {
      assert.strictEqual(A.payload(x.statement).toString('hex'), x.expectedPayloadHex, `${label}: payload`);
      assert.strictEqual(A.statementId(x.statement), x.expectedId, `${label}: id`);
    }
    const g = av.statements.gV.statement;
    const mutated = { ...g, role: 'admin' };
    assert.notStrictEqual(A.statementId(mutated), av.statements.gV.expectedId);
    assert.strictEqual(verifyStrict(A.payload(mutated), g.sigs[0].key, g.sigs[0].sig), false);
    assert.strictEqual(A.statementId({ ...g, sigs: [] }), av.statements.gV.expectedId, 'the id excludes the signatures');
  });

  it('every pin digest reproduces', () => {
    for (const [name, p] of Object.entries(av.pins)) assert.strictEqual(A.pinDigest(A.parsePin(p)), p.expectedPinDigest, name);
  });

  it('the constants are §19.1\'s', () => {
    assert.deepStrictEqual(av.constants, { MAX_DELEGATION_DEPTH: A.MAX_DELEGATION_DEPTH, AUTHORITY_QUOTA: A.AUTHORITY_QUOTA, AUTHORITY_ANCHOR_QUOTA: A.AUTHORITY_ANCHOR_QUOTA, AUTHORITY_DELEGATE_QUOTA: A.AUTHORITY_DELEGATE_QUOTA });
    void testKeys;
  });
});

describe('authority-v2 (MMP §6.6): every case, in every order, with forged copies', () => {
  for (const c of av.cases) {
    it(c.label, () => {
      const statements = c.statements.map((l) => av.statements[l].statement);
      check(c, resolveCase(c, statements), 'as listed');
      check(c, resolveCase(c, [...statements].reverse()), 'reversed');
      for (let seed = 1; seed <= 6; seed++) check(c, resolveCase(c, shuffled(statements, seed * 7919 + c.label.length)), `shuffle ${seed}`);
      // Forged copies first, then the genuine statements, shuffled: nothing a forgery says counts.
      const forged = statements.flatMap(forgedCopies);
      check(c, resolveCase(c, [...shuffled(forged, 3), ...shuffled(statements, 11)]), 'forged copies first');
      check(c, resolveCase(c, shuffled([...forged, ...statements], 17)), 'forged copies mixed in');
    });
  }
});

describe('authority-v2 (MMP §6.6.8): authority order and pages', () => {
  it('a page of the live set sends every statement after its chain, the revokes and endorses at a depth before its grants', () => {
    for (const c of av.cases) {
      const { store, r } = resolveCase(c, c.statements.map((l) => av.statements[l].statement));
      const seen = new Set();
      let after = '';
      let all = [];
      for (let guard = 0; guard < 100; guard++) {
        const p = store.page(after);
        all = all.concat(p.statements);
        if (!p.next) break;
        after = p.next;
      }
      assert.strictEqual(all.length, r.live.size, `${c.label}: the pages hold the live set`);
      let last = null;
      for (const s of all) {
        const id = A.statementId(s);
        if (s.authorisedBy !== 'anchor') assert.ok(seen.has(s.authorisedBy), `${c.label}: a chain comes first`);
        const k = [store.depthOf(id), s.kind === 'grant' ? 1 : 0, id];
        if (last) assert.ok(k[0] > last[0] || (k[0] === last[0] && (k[1] > last[1] || (k[1] === last[1] && k[2] > last[2]))), `${c.label}: authority order`);
        last = k;
        seen.add(id);
      }
      // A second node fed only the pages resolves the same root.
      const other = new AuthorityStore({ pin: A.parsePin(av.pins[c.pin]), quota: c.testQuota, delegateQuota: c.testDelegateQuota });
      for (const s of all) assert.strictEqual(other.ingest(s).result, 'held', `${c.label}: a page is ingested as it arrives`);
      assert.strictEqual(other.root(), r.root, `${c.label}: the live set is enough to recompute the root`);
    }
  });
});

describe('ed25519-strict-v2 (MMP §18.3.2): the one verification rule', () => {
  for (const c of ed.cases) {
    it(c.label, () => {
      const m = Buffer.from(c.messageHex, 'hex');
      const key = Buffer.from(c.publicKeyHex, 'hex');
      const sig = Buffer.from(c.signatureHex, 'hex');
      assert.strictEqual(verifyStrict(m, key, sig) ? 'accept' : 'reject', c.expected);
      assert.strictEqual(precheckFailure(key, sig), c.precheckFailure || null);
    });
  }
});
