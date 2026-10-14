'use strict';

require('../_isolate-home'); // sandbox HOME: node state must never land in the real ~/.sym
process.env.SYM_SEMANTIC_ENCODER = process.env.SYM_SEMANTIC_ENCODER || 'off';

/**
 * The four record defects of the 0.14.3 review (S3, B2, M2; tests/security-0.14.3-records.test.js) across
 * versions: 0.14.3 nodes and REAL 0.14.2 nodes in one process, joined through the real §5.2 handshake over
 * in-memory pipes. The 0.14.2 tree is SYM_0142_DIR (default: the sibling worktree …/wt/sym-0.14.2; a
 * `git archive` of the 0.14.2 tag with node_modules beside it will do). Skipped when it is absent.
 *
 *   npm run test:integration
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { SymNode } = require('../../lib/node');
const { NullDiscovery } = require('../../lib/discovery');
const { nodeDirById } = require('../../lib/config');
const { until } = require('../_core-secure');

const DIR = process.env.SYM_0142_DIR || path.resolve(__dirname, '..', '..', '..', 'sym-0.14.2');
let OLD = null;
try { if (JSON.parse(fs.readFileSync(path.join(DIR, 'package.json'), 'utf8')).version === '0.14.2') OLD = { SymNode: require(path.join(DIR, 'lib', 'node')).SymNode, NullDiscovery: require(path.join(DIR, 'lib', 'discovery')).NullDiscovery }; } catch { /* absent */ }
const skip = OLD ? false : `no 0.14.2 tree at ${DIR} (set SYM_0142_DIR)`;

const ROOM = 'mixed';
const made = [];
function mk(version, base, extra = {}) {
  const Impl = version === '0.14.2' ? OLD : { SymNode, NullDiscovery };
  const n = new Impl.SymNode({ name: `${base}-${process.pid}-${Math.random().toString(36).slice(2, 7)}`, silent: true, discovery: new Impl.NullDiscovery(), room: ROOM, checkpointInterval: 0, ...extra });
  made.push(n);
  return n;
}
async function stopAll() {
  for (const n of made.splice(0)) {
    try { await n.stop(); } catch { /* */ }
    try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ }
  }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** In-memory pipes sharing one wire: frames sent in one turn arrive in one later turn, as on a socket. */
function sharedWire() {
  const queue = [];
  let scheduled = false;
  const flush = () => { scheduled = false; for (const [end, frame] of queue.splice(0)) if (!end._closed) end.emit('message', frame); };
  const mkEnd = () => {
    const l = {};
    return {
      _closed: false,
      on(ev, fn) { (l[ev] ||= []).push(fn); return this; },
      once(ev, fn) { const w = (...a) => { this.off(ev, w); fn(...a); }; return this.on(ev, w); },
      off(ev, fn) { l[ev] = (l[ev] || []).filter((f) => f !== fn); return this; },
      removeListener(ev, fn) { return this.off(ev, fn); },
      removeAllListeners(ev) { if (ev) l[ev] = []; else for (const k of Object.keys(l)) l[k] = []; return this; },
      emit(ev, ...a) { for (const f of [...(l[ev] || [])]) f(...a); },
    };
  };
  return async function connect(client, server) {
    const a = mkEnd(); const b = mkEnd();
    for (const [self, other] of [[a, b], [b, a]]) {
      self.trySend = (frame) => {
        if (self._closed) return { ok: false, reason: 'not-connected' };
        queue.push([other, JSON.parse(JSON.stringify(frame))]);
        if (!scheduled) { scheduled = true; setImmediate(flush); }
        return { ok: true };
      };
      self.send = (frame) => self.trySend(frame).ok;
      self.close = () => { if (self._closed) return; self._closed = true; setImmediate(() => self.emit('close')); if (!other._closed) { other._closed = true; setImmediate(() => other.emit('close')); } };
      self.destroy = self.close;
      self.end = () => setImmediate(() => self.close());
    }
    server.connectTransport(b, { role: 'server' });
    client.connectTransport(a, { role: 'client', expectNodeId: server.nodeId });
    const up = (n, o) => { const p = n._peers.get(o.nodeId); return !!(p && p.transport); };
    await until(() => up(client, server) && up(server, client), 8000);
    if (!up(client, server) || !up(server, client)) throw new Error('the pair did not confirm');
  };
}
const CATS = { focus: 'deploy the build', issue: 'release', intent: 'act', motivation: 'ship', commitment: 'today', perspective: 'operator', mood: { text: 'calm', valence: 0, arousal: 0 } };
const authorOf = (e) => (e.author && e.author.name) || (e.cmb && e.cmb.metadata && e.cmb.metadata.createdBy);
function collect(node) {
  const got = [];
  node.on('cmb-accepted', (e) => got.push({ who: authorOf(e), payload: e.cmb && e.cmb.payload, text: e.cmb && e.cmb.categories && e.cmb.categories.focus && e.cmb.categories.focus.text, remixed: e.remixed, verified: e.verified }));
  return got;
}
function refusals(node) {
  const out = [];
  node.on('metric', (m) => { if (/refus|reject|forg|malformed|penal|closed|altered|unattributable/.test(m.type)) out.push(m.type); });
  return out;
}

describe('0.14.2 and 0.14.3 nodes, the four record defects (S3, B2, M2)', { skip }, () => {
  it('S3: two 0.14.2 authors under the same categories, different actions: a 0.14.3 receiver delivers both', async () => {
    try {
      const A = mk('0.14.2', 'old-a'); const C = mk('0.14.2', 'old-c'); const B = mk('0.14.3', 'new-b');
      await Promise.all([A, B, C].map((n) => n.start()));
      const connect = sharedWire();
      await connect(A, B); await connect(C, B);
      const got = collect(B);
      A.remember(CATS, { payload: { act: 'a' } });
      C.remember(CATS, { payload: { act: 'c' } });
      await until(() => got.length >= 2, 4000); await sleep(300);
      // 9f6847c: only A's (C's was admitted under the key A's record holds, and reached nobody).
      assert.deepStrictEqual(got.map((g) => `${g.who}:${JSON.stringify(g.payload)}`).sort(), [`${A.name}:{"act":"a"}`, `${C.name}:{"act":"c"}`].sort());
    } finally { await stopAll(); }
  });

  it('S3: a 0.14.3 author\'s two actions under one cognition reach a 0.14.2 receiver as signed records it verifies (it keeps the first: 0.14.2 de-duplicates by cognition key)', async () => {
    try {
      const X = mk('0.14.3', 'new-x'); const Y = mk('0.14.2', 'old-y');
      await Promise.all([X, Y].map((n) => n.start()));
      await sharedWire()(X, Y);
      const got = collect(Y); const bad = refusals(Y);
      const r1 = X.remember(CATS, { payload: { n: 1 } });
      const r2 = X.remember(CATS, { payload: { n: 2 } });
      assert.ok(r2.delivery && r2.delivery.dispatched === 1, 'the second action is sent');
      await until(() => got.length >= 1, 4000); await sleep(300);
      assert.deepStrictEqual(got.map((g) => JSON.stringify(g.payload)), ['{"n":1}']);
      assert.deepStrictEqual(bad, [], 'nothing refused or charged at the 0.14.2 receiver');
      assert.ok(Y._peers.get(X.nodeId) && Y._peers.get(X.nodeId).transport, 'the session stays up');
      assert.notStrictEqual(r1.cmb.metadata.assertionId, r2.cmb.metadata.assertionId);
    } finally { await stopAll(); }
  });

  it('B2: a 0.14.3 observer with no store weighs the attestation a 0.14.2 gater made about a 0.14.2 author\'s record', async () => {
    try {
      const P = mk('0.14.2', 'old-author'); const Q = mk('0.14.2', 'old-gater'); const O = mk('0.14.3', 'new-observer', { cliHostMode: true });
      await Promise.all([P, Q, O].map((n) => n.start()));
      const connect = sharedWire();
      await connect(P, Q); await connect(Q, O); await connect(P, O);
      const r = P.remember(CATS);
      await until(() => O.attestationsFor(r.key).length > 0, 6000); await sleep(300);
      const agg = O.aggregateAttestations(r.key);
      // 9f6847c: total 0 (assertion-unknown).
      assert.strictEqual(agg.total, 1, JSON.stringify(agg.excluded));
      assert.strictEqual(agg.basis, 'sole');
      assert.strictEqual(agg.assertionId, r.cmb.metadata.assertionId);
    } finally { await stopAll(); }
  });

  it('M2: a 0.14.2 author\'s text cut inside a surrogate pair is delivered by 0.14.3 (room and directed), as U+FFFD; and 0.14.3\'s reaches 0.14.2', async () => {
    try {
      const S = mk('0.14.2', 'old-sender'); const R = mk('0.14.3', 'new-recv');
      await Promise.all([S, R].map((n) => n.start()));
      await sharedWire()(S, R);
      const got = collect(R); const bad = refusals(R); const sbad = refusals(S);
      const cut = 'Release note 🚀🚀 deploy'.slice(0, 16);
      assert.ok(!cut.isWellFormed(), 'the scene: a 0.14.2 host cut a pair');
      const e1 = S.remember({ ...CATS, focus: `D ${cut}` }, { to: R.nodeId });
      S.remember({ ...CATS, focus: `R ${cut}` });
      assert.ok(!e1.cmb.categories.focus.text.isWellFormed(), 'and 0.14.2 signed it so');
      await until(() => got.length >= 2, 4000); await sleep(300);
      // 9f6847c: both dropped, as malformed (a lone surrogate).
      assert.deepStrictEqual(got.map((g) => g.text).sort(), ['D Release note 🚀�', 'R Release note 🚀�']);
      assert.ok(got.every((g) => g.verified === true));
      assert.deepStrictEqual(bad, []);
      assert.ok(R._peers.get(S.nodeId) && R._peers.get(S.nodeId).transport, 'the session stays up');
      // The other way: 0.14.3 mints the cut text as U+FFFD; 0.14.2 verifies and delivers it.
      const back = collect(S);
      R.remember({ ...CATS, focus: `B ${cut}` }, { to: S.nodeId });
      await until(() => back.length >= 1, 4000); await sleep(200);
      assert.deepStrictEqual(back.map((g) => g.text), ['B Release note 🚀�']);
      assert.deepStrictEqual(sbad, []);
    } finally { await stopAll(); }
  });
});
