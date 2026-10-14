'use strict';

process.env.SYM_SEMANTIC_ENCODER = process.env.SYM_SEMANTIC_ENCODER || 'off';
require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * Key-binding precedence (0.14.3, the certification design). A nodeId is self-chosen, so "nodeId X
 * has key K" is a statement some source makes, and precedence decides which key verifies:
 *
 *   the anchor pin and this node's own key > an operator's out-of-band pin > an anchor
 *   certification (an in-force key-binding grant: unscoped, its chain unscoped admins up to the
 *   anchor) > a proven session (trust on first proven use) > earned and legacy-claim bindings.
 *
 * The R2-1 fix on 9f6847c made the certification the WEAKEST source: a squatter that reached a
 * receiver first with its own key under a certified nodeId kept it. Each rule is a test here; the
 * ones that fail on 9f6847c say "fails before", the ones that already held there say "held before".
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const { RosterKeyRegistry } = require('../lib/roster-keys');
const A = require('../lib/core/authority');
const { identity, connectNodes, admitAs, deliver, signedRecord } = require('./_core-secure');
const { settle } = require('./_settle');

const uniq = (b) => `${b}-${process.pid}-${Math.random().toString(36).slice(2, 7)}`;
const made = [];
function mk(base, extra = {}) {
  const n = new SymNode({ name: extra.name || uniq(base), silent: true, discovery: new NullDiscovery(), room: 'cert', ...extra });
  made.push(n);
  return n;
}
async function stopAll() {
  for (const n of made.splice(0)) {
    try { await n.stop(); } catch { /* */ }
    try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ }
  }
}
const anchor = identity('anchor');
const PIN = { threshold: 1, keys: [{ key: anchor.publicKey }] };
const sign = (byId, by, fields) => A.signStatement({ ...fields, authorisedBy: byId, nonce: A.freshNonce(), sigs: [] }, by.privateKey, by.publicKey);
/** The anchor certifies nodeId -> key (an unscoped anchor grant: a key-binding source). */
function certify(R, nodeId, key, role = 'participant') {
  const g = sign('anchor', anchor, { kind: 'grant', subject: { nodeId, key }, role });
  assert.strictEqual(R.submitAuthority(g).status, 'in-force');
  return g;
}
function revoke(R, g) {
  assert.strictEqual(R.submitAuthority(sign('anchor', anchor, { kind: 'revoke', targets: [A.statementId(g)] })).status, 'in-force');
}
/** A node that claims `victim`'s nodeId under its own key (the attacker runs what it likes). */
function squatterOf(victim, base = 'squatter') {
  const S = mk(base, { anchor: PIN });
  S.nodeId = victim.nodeId; if (S._identity) S._identity.nodeId = victim.nodeId;
  return S;
}
const refusedConnect = async (a, b) => { await assert.rejects(connectNodes(a, b, { timeoutMs: 1500 }), /did not confirm/); };
/** Deliver a room record by `author` on `session`; resolve with the verified-record events for its nodeId. */
async function recordAs(R, session, author, focus) {
  const seen = [];
  const on = (e) => { if (e.verification && e.verification.authorNodeId === author.nodeId) seen.push(e); };
  R.on('verified-record', on);
  try {
    deliver(R, session, { type: 'cmb', timestamp: Date.now(), cmb: signedRecord(author, { categories: { focus }, room: 'cert' }) });
    await settle(60);
  } finally { R.off('verified-record', on); }
  return seen;
}
const key = () => identity().publicKey;
const DAY = 24 * 60 * 60 * 1000;

describe('rule 1 and 2: an anchor certification outranks a session and any earned binding', () => {
  it('R2-1 still holds: a scoped issuer seating one world binds no key, and the victim\'s handshake is admitted (held before)', async () => {
    try {
      const R = mk('c-r21', { anchor: PIN });
      const V = mk('c-r21-victim', { anchor: PIN });
      const I = identity('issuer');
      const gI = sign('anchor', anchor, { kind: 'grant', subject: { nodeId: I.nodeId, key: I.publicKey }, role: 'issuer', scope: 'xmesh-world:w1' });
      const gSquat = sign(A.statementId(gI), I, { kind: 'grant', subject: { nodeId: V.nodeId, key: I.publicKey }, role: 'participant', scope: 'xmesh-world:w1' });
      assert.strictEqual(R.submitAuthority(gI).status, 'in-force');
      assert.strictEqual(R.submitAuthority(gSquat).status, 'in-force');
      assert.strictEqual(R._identityKey(V.nodeId), undefined, 'a scoped grant certifies nothing');
      assert.strictEqual(R._authority.grantKey(V.nodeId), undefined);
      const carrier = admitAs(R, I);
      assert.strictEqual((await recordAs(R, carrier, { nodeId: V.nodeId, name: 'victim', privateKey: I.privateKey }, 'forged in the victim name')).length, 0, 'a record in the victim\'s name signed by the issuer is not verified');
      await connectNodes(V, R, { timeoutMs: 3000 });
      assert.ok(R._peers.has(V.nodeId), 'the victim connects');
      assert.strictEqual(R._roster.conflicts().length, 0, 'and a scoped grant fills no conflict record');
    } finally { await stopAll(); }
  });

  it('certified X -> K1, then a squatter proving X with K2 at a fresh receiver: refused, recorded, shown; the K1 session is admitted (fails before)', async () => {
    try {
      const R = mk('c-fresh', { anchor: PIN });
      const V = mk('c-fresh-victim', { anchor: PIN });
      const S = squatterOf(V);
      certify(R, V.nodeId, V._identity.publicKey);
      const metrics = []; R.on('metric', (m) => { if (m.type === 'identity-conflict') metrics.push(m); });
      await refusedConnect(S, R);
      assert.ok(!R._peers.has(V.nodeId), 'the squatter is not a peer');
      assert.ok(R._roster.conflicts().some((c) => c.nodeId === V.nodeId && c.had === V._identity.publicKey && c.hadSource === 'grant' && c.got === S._identity.publicKey), 'the conflict is recorded');
      assert.ok(R.status().coreSecure.keyConflicts.some((c) => c.nodeId === V.nodeId && c.got === S._identity.publicKey), 'and shown in status');
      assert.ok(metrics.some((m) => m.nodeId === V.nodeId && m.against === 'grant'), 'never silent');
      const carrier = admitAs(R, identity('carrier'));
      assert.strictEqual((await recordAs(R, carrier, { nodeId: V.nodeId, name: 'v', privateKey: S._identity.privateKey }, 'squatter speaks')).length, 0, 'a record claiming X signed by K2 is not verified as X');
      await connectNodes(V, R, { timeoutMs: 3000 });
      assert.strictEqual(R._peers.get(V.nodeId).identityKey, V._identity.publicKey, 'the certified key is admitted');
      assert.strictEqual(R._roster.durable(V.nodeId), undefined, 'and stores nothing on the grant\'s account');
    } finally { await stopAll(); }
  });

  it('a stored TOFU binding X -> K2, then a certification X -> K1: K2 is superseded (kept, marked, recorded), verifies nothing, and its live session is closed (fails before)', async () => {
    try {
      const R = mk('c-supersede', { anchor: PIN });
      if (typeof R._store.load === 'function') await R._store.load();
      const X = identity('x-honest');
      const squat = { ...identity('x-squat'), nodeId: X.nodeId };
      const s = admitAs(R, squat);
      assert.strictEqual((await recordAs(R, s, squat, 'first in')).length, 1);
      assert.strictEqual(R._roster.get(X.nodeId), squat.publicKey, 'the scene: the squatter earned a TOFU binding');
      assert.strictEqual(R._roster.source(X.nodeId), 'proven');
      const before = R._roster.entries().find((e) => e.nodeId === X.nodeId);
      certify(R, X.nodeId, X.publicKey);
      assert.strictEqual(R._identityKey(X.nodeId), X.publicKey, 'the certification decides');
      assert.strictEqual(R._keySource(X.nodeId), 'grant');
      assert.strictEqual(R._roster.durable(X.nodeId), squat.publicKey, 'the superseded binding is kept on disk');
      assert.strictEqual(R._roster.entries().find((e) => e.nodeId === X.nodeId).superseded, X.publicKey, 'and marked');
      assert.ok(R._roster.conflicts().some((c) => c.nodeId === X.nodeId && c.kind === 'superseded' && c.had === X.publicKey && c.got === squat.publicKey), 'and recorded');
      assert.ok(s.closed && s.sent.some((f) => f.type === 'error' && f.code === 1009), 'the squatter\'s live session is closed as an identity conflict');
      const carrier = admitAs(R, identity('carrier'));
      assert.strictEqual((await recordAs(R, carrier, squat, 'still me')).length, 0, 'a record by X signed with K2 is not verified');
      const sx = admitAs(R, X);
      const ok = await recordAs(R, sx, X, 'the real X');
      assert.strictEqual(ok.length, 1, 'one signed with K1 is');
      assert.strictEqual(ok[0].verification.authorKey, X.publicKey);
      const after = R._roster.entries().find((e) => e.nodeId === X.nodeId);
      assert.strictEqual(after.verified, before.verified, 'what verifies under the certification credits nothing to the binding it superseded');
      assert.deepStrictEqual(R.keyBindings().filter((b) => b.nodeId === X.nodeId).map((b) => [b.key, b.source]), [[X.publicKey, 'grant']], 'a host reading keyBindings sees the key that verifies, once');
    } finally { await stopAll(); }
  });

  it('a certification outranks a live session at once: between a resolution and its settle, nothing verifies under the session\'s key (fails before)', async () => {
    try {
      const R = mk('c-order', { anchor: PIN });
      const X = identity('x');
      const squat = { ...identity('x-squat'), nodeId: X.nodeId };
      admitAs(R, squat);
      assert.strictEqual(R._identityKey(X.nodeId), squat.publicKey, 'the scene: a live session-scoped binding');
      const g = sign('anchor', anchor, { kind: 'grant', subject: { nodeId: X.nodeId, key: X.publicKey }, role: 'participant' });
      assert.strictEqual(R._authority.ingest(g).result, 'held');
      R._authority.resolve(); // resolved, not yet settled: no session has been closed
      assert.strictEqual(R._identityKey(X.nodeId), X.publicKey);
    } finally { await stopAll(); }
  });

  it('a session admitted before the certification is closed when it enters, and the certified key connects (fails before)', async () => {
    try {
      const R = mk('c-live', { anchor: PIN });
      const V = mk('c-live-victim', { anchor: PIN });
      const S = squatterOf(V);
      await connectNodes(S, R, { timeoutMs: 3000 });
      assert.strictEqual(R._identityKey(V.nodeId), S._identity.publicKey, 'the scene: the squatter came first (session-scoped)');
      certify(R, V.nodeId, V._identity.publicKey);
      await settle(60);
      assert.ok(!R._peers.has(V.nodeId), 'its session is closed');
      assert.ok(R._roster.conflicts().some((c) => c.nodeId === V.nodeId && c.got === S._identity.publicKey));
      await connectNodes(V, R, { timeoutMs: 3000 });
      assert.strictEqual(R._peers.get(V.nodeId).identityKey, V._identity.publicKey);
    } finally { await stopAll(); }
  });
});

describe('rule 3: revoked, a superseded binding stays conflicted; a nodeId with nothing else is unbound', () => {
  it('after the revoke the superseded binding verifies nothing and every session for X is refused until the operator resolves it (fails before)', async () => {
    try {
      const R = mk('c-revoke', { anchor: PIN });
      const V = mk('c-revoke-victim', { anchor: PIN });
      const S = squatterOf(V);
      R._roster.bind(V.nodeId, S._identity.publicKey, 'proven'); // the squatter's earned binding
      const g = certify(R, V.nodeId, V._identity.publicKey);
      await connectNodes(V, R, { timeoutMs: 3000 });
      assert.ok(R._peers.has(V.nodeId), 'certified, the real key connects');
      revoke(R, g);
      await settle(60);
      assert.strictEqual(R._identityKey(V.nodeId), undefined, 'fail closed: the authority once said K2 was not X\'s');
      assert.strictEqual(R._roster.get(V.nodeId), undefined);
      assert.strictEqual(R._keySource(V.nodeId), 'conflicted');
      assert.ok(!R._peers.has(V.nodeId), 'the session the certification admitted is closed too: X is conflicted');
      assert.ok(!R.keyBindings().some((b) => b.nodeId === V.nodeId), 'no key is listed for a conflicted nodeId');
      await refusedConnect(S, R);
      await refusedConnect(V, R);
      assert.deepStrictEqual(R._roster.resolveConflict(V.nodeId, V._identity.publicKey), { resolved: true });
      assert.strictEqual(R._identityKey(V.nodeId), V._identity.publicKey, 'the operator resolved it');
    } finally { await stopAll(); }
  });

  it('a nodeId only a certification bound is unbound by the revoke: a later session binds it by first proven use (held before)', async () => {
    try {
      const R = mk('c-unbound', { anchor: PIN });
      const V = mk('c-unbound-victim', { anchor: PIN });
      const g = certify(R, V.nodeId, V._identity.publicKey);
      assert.strictEqual(R._keySource(V.nodeId), 'grant');
      revoke(R, g);
      assert.strictEqual(R._roster.source(V.nodeId), undefined, 'nothing binds it');
      assert.strictEqual(R._roster.size(), 0, 'nothing was stored on the grant\'s account');
      const S = squatterOf(V, 'later');
      await connectNodes(S, R, { timeoutMs: 3000 });
      assert.strictEqual(R._identityKey(V.nodeId), S._identity.publicKey, 'trust on first proven use');
    } finally { await stopAll(); }
  });

  it('a supersession survives a restart: a node that starts with a certification in force sets aside a stored binding of another key (fails before)', async () => {
    try {
      const R1 = mk('c-restart', { anchor: PIN });
      const X = identity('x'); const K2 = key();
      R1._roster.bind(X.nodeId, K2, 'proven');
      // The certification held, as a 0.14.3-base node left it: the registry was never told.
      const g = sign('anchor', anchor, { kind: 'grant', subject: { nodeId: X.nodeId, key: X.publicKey }, role: 'participant' });
      assert.strictEqual(R1._authority.ingest(g).result, 'held');
      const name = R1.name;
      await R1.stop();
      const R2 = new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: 'cert', anchor: PIN });
      made.push(R2);
      assert.strictEqual(R2._identityKey(X.nodeId), X.publicKey);
      assert.deepStrictEqual(R2._roster.superseded(X.nodeId), { key: K2, by: X.publicKey }, 'set aside at start');
      revoke(R2, g);
      assert.strictEqual(R2._identityKey(X.nodeId), undefined, 'and it stays conflicted after the revoke');
    } finally { await stopAll(); }
  });
});

describe('rule 4: a pin outranks a certification; the conflict is recorded and shown', () => {
  it('pin first, then a certification of another key: the pin verifies, its session is admitted, the conflict is recorded (held before)', async () => {
    try {
      const R = mk('c-pin1', { anchor: PIN });
      const V = mk('c-pin1-v', { anchor: PIN });
      assert.strictEqual(R.acceptInvite(V.inviteURL({ room: 'cert' })).pinned, true);
      const other = key();
      certify(R, V.nodeId, other);
      assert.strictEqual(R._identityKey(V.nodeId), V._identity.publicKey, 'the pin wins');
      assert.strictEqual(R._keySource(V.nodeId), 'pinned');
      const c = R.status().coreSecure.keyConflicts.find((x) => x.nodeId === V.nodeId);
      assert.ok(c && new Set([c.had, c.got]).has(other) && new Set([c.had, c.got]).has(V._identity.publicKey), 'recorded and shown');
      await connectNodes(V, R, { timeoutMs: 3000 });
      assert.ok(R._peers.has(V.nodeId));
    } finally { await stopAll(); }
  });

  it('a certification first, then a pin of another key: the pin binds and verifies, the conflict is recorded (held before)', async () => {
    try {
      const R = mk('c-pin2', { anchor: PIN });
      const V = mk('c-pin2-v', { anchor: PIN });
      const other = key();
      certify(R, V.nodeId, other);
      assert.strictEqual(R.acceptInvite(V.inviteURL({ room: 'cert' })).pinned, true);
      assert.strictEqual(R._identityKey(V.nodeId), V._identity.publicKey);
      const c = R.status().coreSecure.keyConflicts.find((x) => x.nodeId === V.nodeId);
      assert.ok(c && new Set([c.had, c.got]).has(other), 'recorded and shown');
      await connectNodes(V, R, { timeoutMs: 3000 });
      assert.ok(R._peers.has(V.nodeId));
    } finally { await stopAll(); }
  });

  it('a pin settles a binding a certification superseded (fails before)', () => {
    const view = new Map();
    const r = new RosterKeyRegistry({ grantView: (id) => view.get(id) });
    const K1 = key(); const K2 = key();
    r.bind('X', K2, 'proven');
    view.set('X', K1); r.bind('X', K1, 'grant');
    view.delete('X');
    assert.strictEqual(r.get('X'), undefined, 'conflicted');
    assert.strictEqual(r.bind('X', K1, 'pinned').bound, true, 'a pin of the certified key settles it');
    assert.strictEqual(r.get('X'), K1);
    assert.strictEqual(r.source('X'), 'pinned');
    // A pin of the superseded key itself settles it too (the operator's decision).
    r.bind('Y', K2, 'proven');
    view.set('Y', K1); r.bind('Y', K1, 'grant');
    view.delete('Y');
    assert.strictEqual(r.get('Y'), undefined);
    assert.strictEqual(r.bind('Y', K2, 'pinned').bound, true);
    assert.strictEqual(r.get('Y'), K2);
    assert.strictEqual(r.superseded('Y'), null, 'no longer set aside');
  });

  it('a pin made while a session holds the nodeId under another key closes that session (fails before)', async () => {
    try {
      const R = mk('c-pin-live', { anchor: PIN });
      const V = mk('c-pin-live-v', { anchor: PIN });
      const S = squatterOf(V);
      await connectNodes(S, R, { timeoutMs: 3000 });
      assert.strictEqual(R.acceptInvite(V.inviteURL({ room: 'cert' })).pinned, true);
      await new Promise((r) => setTimeout(r, 60));
      assert.ok(!R._peers.has(V.nodeId), 'the squatter\'s session is closed: the pin decides');
      await connectNodes(V, R, { timeoutMs: 3000 });
      assert.strictEqual(R._peers.get(V.nodeId).identityKey, V._identity.publicKey);
    } finally { await stopAll(); }
  });
});

describe('rule 5: a grant gives its role only to records verified under its subject key', () => {
  const scopes = { test: () => true };
  const cmb = { metadata: {}, categories: {} };

  it('a grant naming X with K2 gives nothing to X verified under K1, nor to another nodeId holding K2; a grant of K1 gives its role inside its scope only (held before)', async () => {
    try {
      const R = mk('c-roles', { anchor: PIN, authorityScopes: scopes });
      const X = identity('x'); const other = identity('other');
      R._roster.bind(X.nodeId, X.publicKey, 'pinned');
      // An unscoped validator grant naming X with K2 is a certification of K2, which the pin outranks;
      // a scoped one certifies nothing. Neither gives anything to X's real key.
      certify(R, X.nodeId, other.publicKey, 'validator');
      assert.strictEqual(R.submitAuthority(sign('anchor', anchor, { kind: 'grant', subject: { nodeId: X.nodeId, key: other.publicKey }, role: 'validator', scope: 'test:w' })).status, 'in-force');
      assert.strictEqual(R._identityKey(X.nodeId), X.publicKey);
      assert.strictEqual(R.resolveRole(X.nodeId), 'participant');
      assert.strictEqual(R.resolveRole(X.nodeId, { cmb }), 'participant');
      assert.strictEqual(R.lifecycleAuthority(X.nodeId, X.publicKey, cmb), 'none');
      assert.strictEqual(R._attesterRole({ by: X.nodeId, of: 'cmb-none' }, X.publicKey), 'participant');
      assert.strictEqual(R.resolveRole(other.nodeId, { key: other.publicKey, cmb }), 'participant', 'nothing to another nodeId holding K2');
      assert.strictEqual(R.lifecycleAuthority(other.nodeId, other.publicKey, cmb), 'none');
      assert.strictEqual(R.submitAuthority(sign('anchor', anchor, { kind: 'grant', subject: { nodeId: X.nodeId, key: X.publicKey }, role: 'validator', scope: 'test:w' })).status, 'in-force');
      assert.strictEqual(R.lifecycleAuthority(X.nodeId, X.publicKey, cmb), 'validated', 'the grant of K1, inside its scope');
      assert.strictEqual(R.resolveRole(X.nodeId), 'participant', 'and only there');
      assert.strictEqual(R._identityKey(X.nodeId), X.publicKey, 'a scoped grant binds no key');
    } finally { await stopAll(); }
  });

  it('an attestation is weighed under the key that verified it, not the key bound now (fails before: the role was judged under the bound key)', async () => {
    try {
      const R = mk('c-attkey', { anchor: PIN });
      const X = identity('x'); const other = identity('other');
      certify(R, X.nodeId, other.publicKey, 'validator');
      assert.strictEqual(R._identityKey(X.nodeId), other.publicKey, 'the scene: X is certified to K2 now');
      assert.strictEqual(R._attesterRole({ by: X.nodeId, of: 'cmb-none' }, X.publicKey), 'participant', 'one verified under K1 gets nothing from the grant of K2');
      assert.strictEqual(R._attesterRole({ by: X.nodeId, of: 'cmb-none' }, other.publicKey), 'validator');
    } finally { await stopAll(); }
  });
});

describe('a certified key is a key this node may grant a role to', () => {
  it('grantRole names the certified key of a nodeId with no session here (fails before)', async () => {
    try {
      const R = mk('c-grantrole', { anchor: PIN });
      certify(R, R.nodeId, R._identity.publicKey, 'admin'); // R signs below its own admin grant
      const X = identity('x');
      certify(R, X.nodeId, X.publicKey);
      const s = R.grantRole(X.nodeId, 'validator');
      assert.ok(s, 'made');
      assert.strictEqual(s.subject.key, X.publicKey);
    } finally { await stopAll(); }
  });
});

describe('rule 6: this node\'s own nodeId is never bound by a grant', () => {
  it('a certification naming this node with a foreign key binds nothing and is reported (held before)', async () => {
    try {
      const R = mk('c-self', { anchor: PIN });
      const metrics = []; R.on('metric', (m) => { if (m.type === 'authority-foreign-self-key') metrics.push(m); });
      certify(R, R.nodeId, key(), 'admin');
      assert.strictEqual(R._identityKey(R.nodeId), R._identity.publicKey);
      assert.strictEqual(R._roster.source(R.nodeId), 'self');
      assert.strictEqual(R._roster.size(), 0, 'nothing stored for it');
      assert.strictEqual(metrics.length, 1);
    } finally { await stopAll(); }
  });
});

describe('rule 7: a certification is no earned binding; a superseded one is outside the share and never expires', () => {
  it('a superseded binding leaves the new-binding share and never expires; a certification never ages out (fails before)', () => {
    let t = 1_000_000;
    const view = new Map();
    const r = new RosterKeyRegistry({ now: () => t, maxBindings: 16, grantView: (id) => view.get(id) }); // share: 4
    const keys = [key(), key(), key(), key()];
    keys.forEach((k, i) => assert.strictEqual(r.bind(`n${i}`, k, 'proven').created, true));
    assert.strictEqual(r.bind('late', key(), 'proven').reason, 'full', 'the scene: the share is full');
    const K1 = key();
    view.set('n0', K1); r.bind('n0', K1, 'grant');
    assert.strictEqual(r.bind('late', key(), 'proven').created, true, 'a superseded binding does not count against the share');
    const C = key(); view.set('c', C);
    t += 400 * DAY;
    r.expire();
    assert.strictEqual(r.durable('n0'), keys[0], 'the superseded binding never expires');
    assert.strictEqual(r.get('c'), C, 'a certification is a view: nothing to age out');
    assert.ok(!r.entries().some((e) => e.nodeId === 'c'), 'and nothing stored for it');
    r.noteVerified('n0');
    assert.strictEqual(r.entries().find((e) => e.nodeId === 'n0').verified, null, 'nothing credits a superseded binding');
    view.delete('n0');
    t += 400 * DAY;
    r.expire();
    assert.strictEqual(r.get('n0'), undefined, 'revoked, it is still conflicted');
    assert.strictEqual(r.bind('n0', key(), 'proven').reason, 'conflict', 'and no newcomer takes its nodeId');
  });
});

describe('the registry: certifications act only while in force, settle, persist and contradict', () => {
  it('a grant not in force supersedes nothing and records nothing (fails before: it recorded a conflict)', () => {
    const r = new RosterKeyRegistry();
    const K2 = key();
    r.bind('X', K2, 'proven');
    assert.strictEqual(r.bind('X', key(), 'grant').reason, 'not-in-effect');
    assert.strictEqual(r.get('X'), K2);
    assert.strictEqual(r.conflicts().length, 0);
  });

  it('fail closed: a superseded binding refuses every source but a pin, its own key included (fails before)', () => {
    const view = new Map();
    const r = new RosterKeyRegistry({ grantView: (id) => view.get(id) });
    const K1 = key(); const K2 = key();
    r.bind('X', K2, 'legacy-claim');
    view.set('X', K1); r.bind('X', K1, 'grant');
    assert.strictEqual(r.get('X'), K1, 'a certification outranks a legacy claim of another key');
    view.delete('X');
    for (const [k, src] of [[K2, 'proven'], [K1, 'proven'], [key(), 'proven'], [K2, 'legacy-claim']]) {
      const res = r.bind('X', k, src);
      assert.strictEqual(res.bound, false, `${src} refused`);
      assert.strictEqual(res.reason, 'conflict');
    }
    assert.strictEqual(r.get('X'), undefined);
  });

  it('a new certification naming the superseded key settles it (fails before)', () => {
    const view = new Map();
    const r = new RosterKeyRegistry({ grantView: (id) => view.get(id) });
    const K1 = key(); const K2 = key();
    r.bind('X', K2, 'proven');
    view.set('X', K1); r.bind('X', K1, 'grant');
    view.delete('X');
    assert.strictEqual(r.get('X'), undefined);
    view.set('X', K2); r.bind('X', K2, 'grant');
    assert.strictEqual(r.superseded('X'), null, 'settled');
    view.delete('X');
    assert.strictEqual(r.get('X'), K2, 'and it outlives that certification: it is its own binding');
  });

  it('certifications naming two keys for one nodeId certify neither: nothing verifies as it (fails before)', async () => {
    try {
      const R = mk('c-two', { anchor: PIN });
      const V = mk('c-two-v', { anchor: PIN });
      const Ad = identity('admin');
      const gAd = sign('anchor', anchor, { kind: 'grant', subject: { nodeId: Ad.nodeId, key: Ad.publicKey }, role: 'admin' });
      assert.strictEqual(R.submitAuthority(gAd).status, 'in-force');
      certify(R, V.nodeId, V._identity.publicKey);
      assert.strictEqual(R.submitAuthority(sign(A.statementId(gAd), Ad, { kind: 'grant', subject: { nodeId: V.nodeId, key: Ad.publicKey }, role: 'participant' })).status, 'in-force');
      assert.strictEqual(R._identityKey(V.nodeId), undefined, 'fail closed');
      await refusedConnect(V, R);
      assert.ok(R._roster.conflicts().some((c) => c.nodeId === V.nodeId && c.kind === 'certifications-disagree'), 'recorded');
    } finally { await stopAll(); }
  });

  it('a supersession is persisted: it reloads, and compacts (fails before)', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rk-cert-'));
    try {
      const view = new Map();
      const K1 = key(); const K2 = key();
      const r1 = new RosterKeyRegistry({ dir, grantView: (id) => view.get(id) });
      r1.bind('X', K2, 'proven');
      view.set('X', K1); r1.bind('X', K1, 'grant');
      const r2 = new RosterKeyRegistry({ dir }); // nothing certifies now
      assert.strictEqual(r2.get('X'), undefined, 'still conflicted after a reload');
      assert.deepStrictEqual(r2.superseded('X'), { key: K2, by: K1 });
      r2._compact();
      const r3 = new RosterKeyRegistry({ dir });
      assert.deepStrictEqual(r3.superseded('X'), { key: K2, by: K1 }, 'a compacted line carries it');
      r3.bind('X', K2, 'pinned');
      assert.strictEqual(new RosterKeyRegistry({ dir }).get('X'), K2, 'and a pin that settled it replays as settled');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
});
