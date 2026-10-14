'use strict';

process.env.SYM_SEMANTIC_ENCODER = process.env.SYM_SEMANTIC_ENCODER || 'off';
require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * The 0.14.3 security review (R2): each finding fixed here as a regression test that fails on the
 * 0.14.3 base (632b95d) for its own reason.
 *
 *   R2-1   a delegating grant, even a scoped one, bound any unbound nodeId to its holder's key (the
 *          precedence of the certification that remains: security-0.14.3-cert.test.js)
 *   R2-2   a relay editing a sealed record's clear metadata got an honest peer banned as a forger
 *   R2-3   one admitted peer's large records cost CPU, memory and disk without bound
 *   R2-6   actionable room records were de-duplicated by cognition key, not assertion identity
 *   R2-9   durable key bindings earned by one record never aged out, and nothing capped a source
 *   R2-22  the delivery ledger was never pruned
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const A = require('../lib/core/authority');
const { identity, connectNodes, admitAs, deliver, signedRecord, applicationFor, until } = require('./_core-secure');

const uniq = (b) => `${b}-${process.pid}-${Math.random().toString(36).slice(2, 7)}`;
const made = [];
function mk(base, extra = {}) {
  const n = new SymNode({ name: uniq(base), silent: true, discovery: new NullDiscovery(), room: 'sec', ...extra });
  made.push(n);
  return n;
}
async function stopAll() {
  for (const n of made.splice(0)) {
    try { await n.stop(); } catch { /* */ }
    try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ }
  }
}
const sign = (byId, by, fields) => A.signStatement({ ...fields, authorisedBy: byId, nonce: A.freshNonce(), sigs: [] }, by.privateKey, by.publicKey);

describe('R2-1: a grant binds a key only when it is unscoped and its chain is the anchor and admins', () => {
  const anchor = identity('anchor');
  const PIN = { threshold: 1, keys: [{ key: anchor.publicKey }] };

  it('R2-1: a scoped issuer seating one world binds no key: the victim nodeId stays unbound, a record forged in its name is not verified, and the victim connects', async () => {
    try {
      const R = mk('r21-recv', { anchor: PIN });
      const V = mk('r21-victim', { anchor: PIN });
      const I = identity('issuer');
      const gI = sign('anchor', anchor, { kind: 'grant', subject: { nodeId: I.nodeId, key: I.publicKey }, role: 'issuer', scope: 'xmesh-world:w1' });
      const gSquat = sign(A.statementId(gI), I, { kind: 'grant', subject: { nodeId: V.nodeId, key: I.publicKey }, role: 'participant', scope: 'xmesh-world:w1' });
      assert.strictEqual(R.submitAuthority(gI).status, 'in-force');
      assert.strictEqual(R.submitAuthority(gSquat).status, 'in-force', 'the scoped grant is in force (it confers its role in its scope)');
      assert.strictEqual(R._identityKey(V.nodeId), undefined, 'but binds no key for the victim nodeId');
      assert.strictEqual(R._keySource(V.nodeId), undefined);
      const sess = admitAs(R, { nodeId: I.nodeId, name: 'issuer', publicKey: I.publicKey });
      let accepted = null;
      R.on('verified-record', (e) => { accepted = e; });
      deliver(R, sess, { type: 'cmb', timestamp: Date.now(), cmb: signedRecord({ nodeId: V.nodeId, name: 'victim', privateKey: I.privateKey }, { categories: { focus: 'forged in the victim name' }, room: 'sec' }) });
      await until(() => accepted, 300);
      assert.strictEqual(accepted, null, 'a record in the victim\'s name signed by the issuer key is not verified');
      await connectNodes(V, R, { timeoutMs: 3000 });
      assert.ok(R._peers.has(V.nodeId), 'the victim\'s own session is admitted');
    } finally { await stopAll(); }
  });

  it('R2-1: an unscoped grant under an issuer (not an admin) binds no key either; one under the anchor or an admin does', async () => {
    try {
      const R = mk('r21-chain', { anchor: PIN });
      const I = identity('issuer'); const Ad = identity('admin');
      const x = identity('x'); const y = identity('y'); const z = identity('z');
      const gI = sign('anchor', anchor, { kind: 'grant', subject: { nodeId: I.nodeId, key: I.publicKey }, role: 'issuer' });
      const gAd = sign('anchor', anchor, { kind: 'grant', subject: { nodeId: Ad.nodeId, key: Ad.publicKey }, role: 'admin' });
      for (const s of [gI, gAd,
        sign(A.statementId(gI), I, { kind: 'grant', subject: { nodeId: x.nodeId, key: x.publicKey }, role: 'participant' }),
        sign(A.statementId(gAd), Ad, { kind: 'grant', subject: { nodeId: y.nodeId, key: y.publicKey }, role: 'participant' }),
        sign('anchor', anchor, { kind: 'grant', subject: { nodeId: z.nodeId, key: z.publicKey }, role: 'validator' })]) {
        assert.strictEqual(R.submitAuthority(s).status, 'in-force');
      }
      assert.strictEqual(R._identityKey(x.nodeId), undefined, 'issuer-chained: no binding');
      assert.strictEqual(R._identityKey(y.nodeId), y.publicKey, 'admin-chained, unscoped: a binding (a view)');
      assert.strictEqual(R._identityKey(z.nodeId), z.publicKey, 'anchor-issued, unscoped: a binding');
      assert.strictEqual(R._identityKey(I.nodeId), I.publicKey);
    } finally { await stopAll(); }
  });

  // Changed by the certification design (0.14.3): an anchor certification outranks a session's proof,
  // so a session proving another key is refused (security-0.14.3-cert.test.js has the rest).
  it('R2-1: an anchor certification refuses a session proving another key: refused, and the conflict recorded', async () => {
    try {
      const R = mk('r21-norefuse', { anchor: PIN });
      const V = mk('r21-victim2', { anchor: PIN });
      const evil = identity('evil');
      const g = sign('anchor', anchor, { kind: 'grant', subject: { nodeId: V.nodeId, key: evil.publicKey }, role: 'participant' });
      assert.strictEqual(R.submitAuthority(g).status, 'in-force');
      assert.strictEqual(R._identityKey(V.nodeId), evil.publicKey, 'the scene: the anchor certifies another key');
      await assert.rejects(connectNodes(V, R, { timeoutMs: 1500 }), /did not confirm/);
      assert.ok(!R._peers.has(V.nodeId), 'the certification decides which key is the nodeId\'s');
      assert.strictEqual(R._identityKey(V.nodeId), evil.publicKey);
      assert.ok(R._roster.conflicts().some((c) => c.nodeId === V.nodeId && c.hadSource === 'grant' && c.got === V._identity.publicKey), 'the conflict is recorded');
    } finally { await stopAll(); }
  });

  it('R2-1: a session proving the key a grant names is never promoted to proven; a revoke removes what the grant bound', async () => {
    try {
      const R = mk('r21-sticky', { anchor: PIN });
      const V = mk('r21-victim3', { anchor: PIN });
      const S = mk('r21-squatter', { anchor: PIN });
      S.nodeId = V.nodeId; if (S._identity) S._identity.nodeId = V.nodeId;
      const Ad = identity('admin');
      const gAd = sign('anchor', anchor, { kind: 'grant', subject: { nodeId: Ad.nodeId, key: Ad.publicKey }, role: 'admin' });
      const gSquat = sign(A.statementId(gAd), Ad, { kind: 'grant', subject: { nodeId: V.nodeId, key: S._identity.publicKey }, role: 'participant' });
      R.submitAuthority(gAd); R.submitAuthority(gSquat);
      assert.strictEqual(R._roster.source(V.nodeId), 'grant');
      await connectNodes(S, R, { timeoutMs: 3000 });
      assert.notStrictEqual(R._roster.source(V.nodeId), 'proven', 'never promoted to proven');
      assert.strictEqual(R._roster.durable(V.nodeId), undefined, 'nothing stored');
      assert.strictEqual(R.submitAuthority(sign('anchor', anchor, { kind: 'revoke', targets: [A.statementId(gAd)] })).status, 'in-force');
      for (const s of [...R._sessions]) s.close('test');
      await new Promise((r) => setTimeout(r, 100));
      assert.strictEqual(R._roster.source(V.nodeId), undefined, 'the revoke removed what the grant bound');
      await connectNodes(V, R, { timeoutMs: 3000 });
      assert.ok(R._peers.has(V.nodeId) && R._peers.get(V.nodeId).identityKey === V._identity.publicKey, 'the real owner of the nodeId connects');
    } finally { await stopAll(); }
  });
});

describe('R2-2: a record whose signed bytes the AEAD did not authenticate is dropped and counted, never charged', () => {
  const CATS = (focus) => ({ focus, issue: 'x', intent: 'y', motivation: 'z', commitment: 'none', perspective: 'p', mood: { text: 'calm', valence: 0, arousal: 0 } });
  for (const [what, edit] of [
    ['createdBy', (m) => { m.createdBy += 'X'; }],
    ['createdTimestamp', (m) => { m.createdTimestamp += 1; }],
    ['the signature', (m) => { m.sig = (m.sig[0] === 'A' ? 'B' : 'A') + m.sig.slice(1); }],
  ]) {
    it(`R2-2: a relay editing ${what} in a sealed record's clear metadata cannot get the honest sender closed or refused`, async () => {
      try {
        const a = mk('r22-a'); const b = mk('r22-b');
        const metrics = []; b.on('metric', (m) => metrics.push(m));
        await a.start(); await b.start();
        let tampered = 0;
        await connectNodes(a, b, { kind: 'relay', tap: (f, dir) => {
          if (dir === 'a→b' && f.type === 'cmb-encrypted' && f.metadata && f.metadata.createdBy) { edit(f.metadata); tampered++; }
        } });
        a.remember(CATS(`an honest observation from a (${what})`));
        await until(() => metrics.some((m) => m.type === 'cmb-signature-rejected'), 3000);
        assert.ok(tampered >= 1, 'the scene: the relay altered the frame');
        assert.ok(metrics.some((m) => m.type === 'cmb-signature-rejected'), 'the altered record is refused');
        assert.ok(!metrics.some((m) => m.type === 'forged-signature'), 'and nobody is called a forger');
        assert.ok(b._peers.has(a.nodeId), 'the honest peer keeps its session');
        assert.strictEqual(b._penalised(a.nodeId), false, 'and is not refused admission');
        if (what !== 'the signature') assert.ok(metrics.some((m) => m.type === 'cmb-clear-metadata-altered'), 'the assertion identity is checked first (§8.8.5)');
      } finally { await stopAll(); }
    });
  }
});

describe('R2-6: actionable delivery is de-duplicated by assertion identity (§8.8.2)', () => {
  const { settle } = require('./_settle');
  const appOf = (m) => (m.record && m.record.metadata.application ? Buffer.from(m.record.metadata.application.data, 'base64url').toString() : 'none');

  it('R2-6: two actionable room records with the same categories are both delivered; a replay of either is not', async () => {
    try {
      const node = mk('r26');
      if (typeof node._store.load === 'function') await node._store.load();
      const mallory = identity('mallory'); const alice = identity('alice');
      const sm = admitAs(node, mallory); const sa = admitAs(node, alice);
      const cats = { focus: 'release 0.14.3 approved', intent: 'deploy' };
      const front = signedRecord(mallory, { categories: cats, room: 'sec', application: applicationFor(Buffer.from('{"deploy":"mallory-build"}')) });
      const real = signedRecord(alice, { categories: cats, room: 'sec', application: applicationFor(Buffer.from('{"deploy":"official-build"}')) });
      deliver(node, sm, { type: 'cmb', cmb: front }); await settle(100);
      deliver(node, sa, { type: 'cmb', cmb: real }); await settle(100);
      const job1 = signedRecord(alice, { categories: { focus: 'run job', intent: 'act' }, room: 'sec', application: applicationFor(Buffer.from('{"job":1}')) });
      const job2 = signedRecord(alice, { categories: { focus: 'run job', intent: 'act' }, room: 'sec', application: applicationFor(Buffer.from('{"job":2}')) });
      deliver(node, sa, { type: 'cmb', cmb: job1 }); await settle(100);
      deliver(node, sa, { type: 'cmb', cmb: job2 }); await settle(100);
      // Replays of each, by the author and by a relay.
      for (const r of [front, real, job1, job2]) { deliver(node, sa, { type: 'cmb', cmb: JSON.parse(JSON.stringify(r)) }); await settle(30); }
      const got = node.inbox({ peek: true }).messages.map((m) => `${m.from}:${appOf(m)}`);
      assert.deepStrictEqual(got.sort(), ['alice:{"deploy":"official-build"}', 'alice:{"job":1}', 'alice:{"job":2}', 'mallory:{"deploy":"mallory-build"}'].sort());
    } finally { await stopAll(); }
  });
});

describe('R2-3: one admitted peer cannot buy CPU, memory or disk without bound', () => {
  const { settle } = require('./_settle');
  const { FrameHandler } = require('../lib/frame-handler');
  const big = (n, seed) => { let t = ''; let j = 0; while (t.length < n) t += `deploy pipeline status report build ${seed}_${j++} `; return t.slice(0, n); };

  it('R2-3: the record and verification budgets are charged by size: two of the largest records pass, a third waits', () => {
    const fh = new FrameHandler({ _log: () => {} }, {});
    const session = {};
    const largest = 720 * 1024;
    const r = [0, 1, 2].map(() => fh._recordBudget(session, largest));
    assert.deepStrictEqual(r, [true, true, false], 'the record lane spends the size');
    const small = {};
    for (let i = 0; i < 32; i++) assert.strictEqual(fh._recordBudget(small, 2048), true, 'small records are counted by number as before');
    const v = {};
    let passed = 0;
    for (let i = 0; i < 12; i++) if (fh._verifyBudget(v, 400 * 1024)) passed++;
    assert.ok(passed >= 8 && passed <= 11, `the verification lane spends the size too (${passed} of 12 passed)`);
  });

  it('R2-3: a burst of large records from one peer: only what its size budget holds reaches SVAF', async () => {
    try {
      const node = mk('r23-flood');
      if (typeof node._store.load === 'function') await node._store.load();
      const mallory = identity('mallory');
      const s = admitAs(node, mallory);
      const over = []; node.on('metric', (m) => { if (m.type === 'cmb-over-budget' || m.type === 'cmb-over-verify-budget') over.push(m.type); });
      let evaluated = 0;
      const admit = node._frameHandler._admit;
      node._frameHandler._admit = (...a) => { evaluated++; return admit(...a); };
      for (let i = 0; i < 12; i++) {
        const rec = signedRecord(mallory, { categories: { focus: big(200000, `f${i}`), issue: big(200000, `i${i}`) }, room: 'sec' });
        deliver(node, s, { type: 'cmb', cmb: rec });
      }
      await settle(300);
      assert.ok(evaluated <= 4, `at most what 1.5 MiB holds was evaluated (${evaluated})`);
      assert.ok(over.length >= 8, 'the rest was dropped and counted');
    } finally { await stopAll(); }
  });

  it('R2-3: the local-state context reads a bounded amount of each entry and in all', async () => {
    try {
      const node = mk('r23-context');
      if (typeof node._store.load === 'function') await node._store.load();
      node._store.allEntries = () => Array.from({ length: 20 }, (_, i) => ({ content: big(300000, `e${i}`) }));
      const ctx = node._buildContext();
      assert.ok(ctx.length <= 16 * 1024 + 64, `the context is bounded (${ctx.length} characters)`);
      assert.ok(ctx.length > 4096, 'and still reads several entries');
    } finally { await stopAll(); }
  });

  it('R2-3: the local state is re-encoded at most once a second, whatever the admits', async () => {
    const calls = [];
    const node = { _buildContext: () => 'context', _meshNode: { updateLocalState: () => calls.push(Date.now()) }, _log: () => {} };
    const fh = new FrameHandler(node, {});
    for (let i = 0; i < 50; i++) fh._reencodeLocalStateAfterAdmit();
    assert.strictEqual(calls.length, 1, 'the first admit re-encodes at once; the rest share one trailing re-encode');
    await until(() => calls.length >= 2, 2500);
    assert.strictEqual(calls.length, 2, 'one trailing re-encode, so the last admit is reflected');
  });

  it('R2-3: the SVAF kernel reads at most SVAF_TEXT_MAX characters of one text', async () => {
    const enc = require('../lib/core/context-encoder');
    const text = big(300000, 'svaf');
    const head = text.slice(0, 16 * 1024);
    const a = await enc.svafKernel().encode(text);
    const b = await enc.svafKernel().encode(head);
    assert.deepStrictEqual(a.h1, b.h1, 'a text longer than the cap encodes as its first SVAF_TEXT_MAX characters');
  });

  it('R2-3: the store\'s entry cache is bounded, by count and by text', async () => {
    try {
      const node = mk('r23-cache');
      if (typeof node._store.load === 'function') await node._store.load();
      const cache = node._store._cache;
      for (let i = 0; i < 3000; i++) cache.set(`cmb-${String(i).padStart(64, '0')}`, { key: `k${i}`, content: 'x' });
      assert.ok(cache.size <= 2048, `bounded by count (${cache.size})`);
      for (let i = 0; i < 40; i++) cache.set(`big-${i}`, { key: `b${i}`, content: big(1024 * 1024, `c${i}`) });
      let chars = 0; for (const [, e] of cache) chars += (e.content || '').length;
      assert.ok(chars <= 32 * 1024 * 1024 + 1024 * 1024, `bounded by text (${chars} characters)`);
      assert.ok(cache.has('big-39'), 'the most recent is kept');
    } finally { await stopAll(); }
  });
});

describe('R2-22: the delivery ledger is pruned', () => {
  const { FrameHandler } = require('../lib/frame-handler');
  const path = require('path');
  const os = require('os');

  it('R2-22: each mark carries its expiry; expired marks are dropped at load and the file is rewritten', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-ledger-'));
    try {
      const file = path.join(dir, '.delivered-marks');
      const now = Date.now();
      fs.writeFileSync(file, [
        'a|cmb-old-format-line',                        // a 0.14.2 line: protects from now on
        `a|cmb-expired\t${now - 1000}`,
        `a|cmb-live#asrt-x\t${now + 3600_000}`,
      ].join('\n') + '\n');
      const fh = new FrameHandler({ _log: () => {}, _store: { _dir: dir } }, {});
      assert.deepStrictEqual([...fh._ledger.keys()].sort(), ['a|cmb-live#asrt-x', 'a|cmb-old-format-line']);
      const lines = fs.readFileSync(file, 'utf8').trim().split('\n');
      assert.strictEqual(lines.length, 2, 'the file holds what is kept');
      assert.ok(lines.every((l) => /\t\d+$/.test(l)), 'each with its expiry');
      // A directed mark lasts the replay window past its signed time; any other LEDGER_TTL_MS.
      const msg = { _cmbVerified: true, _verifiedAuthorNodeId: 'b', _directedToMe: true, cmb: { metadata: { createdTimestamp: now } } };
      fh._markCmbSurfaced('cmb-d#asrt-d', msg);
      const at = fh._ledger.get('b|cmb-d#asrt-d');
      assert.ok(at > now + 24 * 3600_000 && at < now + 26 * 3600_000, 'a directed mark ends with its replay window');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('R2-22: the ledger is bounded, and one author\'s flood pushes out only its own marks', () => {
    const fh = new FrameHandler({ _log: () => {} }, {});
    fh._ledgerPath = null;
    const as = (author) => ({ _cmbVerified: true, _verifiedAuthorNodeId: author });
    for (let i = 0; i < 10; i++) fh._markCmbSurfaced(`cmb-alice-${i}`, as('alice'));
    for (let i = 0; i < 200_100; i++) fh._markCmbSurfaced(`cmb-m-${i}`, as('mallory'));
    assert.ok(fh._ledger.size <= 200_000, `bounded (${fh._ledger.size})`);
    for (let i = 0; i < 10; i++) assert.ok(fh._ledger.has(`alice|cmb-alice-${i}`), 'another author\'s marks are kept');
    assert.ok(fh._ledger.has('mallory|cmb-m-200099'), 'the flooder keeps its newest');
  });
});

describe('R2-9: earned key bindings age out, and new ones hold a share of the registry', () => {
  const { settle } = require('./_settle');
  const { RosterKeyRegistry } = require('../lib/roster-keys');
  const DAY = 24 * 60 * 60 * 1000;

  it('R2-9: identities that each sent one directed record hold at most a quarter and age out; an honest newcomer then earns a binding', async () => {
    try {
      const node = mk('r29', { maxKeyBindings: 8 });
      if (typeof node._store.load === 'function') await node._store.load();
      let clock = Date.now(); node._roster._now = () => clock;
      const leave = (id, s) => { s.close(); node._sessionKeys.delete(id.nodeId); node._peers.delete(id.nodeId); };
      for (let i = 0; i < 3; i++) {
        const sybil = identity('sybil' + i);
        const s = admitAs(node, sybil);
        deliver(node, s, { type: 'cmb', cmb: signedRecord(sybil, { categories: { focus: 'hi ' + i }, room: 'sec', to: node.nodeId }) });
        await settle(50);
        leave(sybil, s);
      }
      assert.strictEqual(node._roster.size(), 2, 'one-shot bindings hold their share (8 / 4) and no more');
      assert.ok(node._roster.refusedShareCount() >= 1);
      clock += 31 * DAY;
      assert.strictEqual(node._roster.expire(), 2, 'and age out after 30 days unseen, though each verified a record');
      const honest = identity('honest');
      const s = admitAs(node, honest);
      deliver(node, s, { type: 'cmb', cmb: signedRecord(honest, { categories: { focus: 'real work' }, room: 'sec', to: node.nodeId }) });
      await settle(50);
      assert.strictEqual(node._roster.get(honest.nodeId), honest.publicKey, 'the honest newcomer earns a durable binding');
    } finally { await stopAll(); }
  });

  it('R2-9: a binding established by records on two days ages out after EARNED_TTL_MS unseen', () => {
    let t = 1_000_000;
    const r = new RosterKeyRegistry({ now: () => t });
    const k = 'A'.repeat(42) + 'A';
    r.bind('peer', k, 'proven'); r.noteVerified('peer');
    t += DAY + 1; r.noteVerified('peer');
    t += 170 * DAY;
    assert.strictEqual(r.expire(), 0);
    t += 11 * DAY;
    assert.strictEqual(r.expire(), 1, 'an earned binding no longer lives for ever');
  });
});

describe('R2-3 (inbox): the inbox is bounded by size, never by dropping an unread delivery', () => {
  const big = (n, seed) => { let t = ''; let j = 0; while (t.length < n) t += `inbox ${seed}_${j++} `; return t.slice(0, n); };

  it('R2-3: large deliveries fill the inbox only up to its size; read ones make room, unread ones are kept', async () => {
    try {
      const node = mk('r23-inbox');
      const metrics = []; node.on('metric', (m) => { if (m.type === 'inbox-full-refused') metrics.push(m); });
      const text = big(700 * 1024, 'x');
      const deliver1 = (i) => node.emit('cmb-accepted', { key: `cmb-${String(i).padStart(64, '0')}`, content: text, cmb: { categories: { focus: { text } }, metadata: {} }, verified: false });
      for (let i = 0; i < 40; i++) deliver1(i);
      const chars = node._inbox.reduce((n, m) => n + (m.content || '').length + JSON.stringify(m.categories || '').length, 0);
      assert.ok(chars <= 34 * 1024 * 1024, `the inbox holds a bounded amount (${Math.round(chars / 1048576)} M)`);
      assert.ok(metrics.length > 0, 'a delivery that does not fit is refused, counted');
      const unread = node._inbox.length;
      node.inbox({ limit: 500 }); // read them all
      deliver1(1000);
      assert.ok(node._inbox.some((m) => m.key === `cmb-${String(1000).padStart(64, '0')}`), 'read items make room for a new delivery');
      assert.ok(node._inbox.length <= unread, 'what was read went');
    } finally { await stopAll(); }
  });
});
