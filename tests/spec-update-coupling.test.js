'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * Coupling as MMP 2.0 update 1 states it (PR #43 at 2660ab9): a record that cites the receiver's own
 * records is gated and delivered like any other, and kept out of the receiver's remix cycle at the
 * trigger (D3, #35); a collapsed integration gets no §15.8 tether (#17, §15.5); unsigned valence and
 * arousal never reach Layer 6; only gated remixes count as remixes (#35); and xmesh-insight-v1 is
 * offered only when a host adds it. Each test fails on 850136d unless it says it pins.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const { MeshAgent } = require('../lib/mesh-agent');
const { isLineageSevered } = require('../lib/core');
const { identity, signedRecord, admitAs, deliver } = require('./_core-secure');

const uniq = (b) => `${b}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
const made = [];
function node(base, opts = {}) {
  const n = new SymNode({ name: uniq(base), silent: true, discovery: new NullDiscovery(), room: 'coup', ...opts });
  made.push(n);
  return n;
}
async function stopAll() {
  for (const n of made.splice(0)) { try { await n.stop(); } catch { /* */ } try { fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } catch { /* */ } }
}
const ALIGNED = { decision: 'aligned', total_drift: 0.1, category_drifts: { focus: 0.1 }, gate_values: { g: 1 } };
const CATS = (focus) => ({ focus, issue: 'coupling test', intent: 'check', motivation: 'm', commitment: 'c', perspective: 'p', mood: { text: 'calm' } });
const settle = () => new Promise((r) => setTimeout(r, 150));

describe('D3: no echo skip at ingest (#35)', () => {
  it('a reply citing this node\'s record is admitted, stored and delivered', async () => {
    try {
      const A = node('d3-a');
      A._svafEvaluator.evaluate = async () => ALIGNED;
      const mine = A.remember(CATS('what A said first'));
      const P = identity('peer');
      const s = admitAs(A, P);
      const got = [];
      A.on('cmb-accepted', (e) => got.push(e));
      const reply = signedRecord(P, { room: 'coup', categories: CATS('a reply to what A said'), lineage: { parents: [mine.key] } });
      deliver(A, s, { type: 'cmb', cmb: reply });
      await settle();
      assert.strictEqual(got.length, 1);
      assert.ok(A._store.get(reply.metadata.key) || got[0].key, 'stored');
    } finally { await stopAll(); }
  });

  it('the remix trigger keeps it out of this node\'s remix cycle (pins the rule where it now sits)', async () => {
    try {
      const A = node('d3-trigger');
      const mine = A.remember(CATS('what A said'));
      let remixed = 0;
      // The trigger itself, on this node (a MeshAgent would build its own node from its cwd's .env).
      const agent = { _signingHalted: false, _shouldRemix: () => true, _name: 'a', _node: A, _remix: async () => { remixed++; return CATS('a remix'); }, _meshContext: () => ({}), _remember: () => null };
      const P = identity('peer');
      const reply = signedRecord(P, { room: 'coup', categories: CATS('reply'), lineage: { parents: [mine.key] } });
      await MeshAgent.prototype._onCMBAccepted.call(agent, { key: reply.metadata.key, cmb: reply, source: 'peer' });
      assert.strictEqual(remixed, 0);
    } finally { await stopAll(); }
  });
});

describe('a collapsed integration has no §15.8 tether (#17, §15.5)', () => {
  it('a record kept as signed is never severed, and no tether is signed about it', async () => {
    try {
      const A = node('col');
      A._svafEvaluator.evaluate = async () => ALIGNED;
      // A root this node holds, and a peer record that cites it with nothing in common: the tether
      // would sever a remix of it. The neural gate keeps the incoming text, so the record collapses.
      // The root is another peer's (so no echo rule of any release applies), held verified.
      const R = identity('root-author');
      const rootRec = signedRecord(R, { room: 'coup', categories: { focus: 'quarterly tax filing deadlines for small companies', issue: 'accounting', intent: 'inform', motivation: 'compliance', commitment: 'file on time', perspective: 'accountant', mood: { text: 'focused' } } });
      A._store.receiveFromPeer(R.nodeId, { key: rootRec.metadata.key, content: 'x', source: 'root-author', cmb: rootRec, _cmbVerified: true, verified: true });
      const root = { key: rootRec.metadata.key };
      const P = identity('peer');
      const s = admitAs(A, P);
      const rec = signedRecord(P, { room: 'coup', categories: { focus: 'alpine snow conditions on the north ridge this weekend', issue: 'avalanche risk', intent: 'warn', motivation: 'safety', commitment: 'stay off the ridge', perspective: 'mountain guide', mood: { text: 'wary' } }, lineage: { parents: [root.key] } });
      deliver(A, s, { type: 'cmb', cmb: rec });
      await settle();
      const e = A._store.get(rec.metadata.key);
      assert.ok(e, 'stored as signed under its own key (collapsed)');
      assert.strictEqual(e.collapsed, true);
      assert.strictEqual(isLineageSevered(e), false, 'not a severed root');
      assert.strictEqual(e.tether, undefined, 'no tether attestation');
      assert.strictEqual(e.provenance && e.provenance.tether, undefined);
    } finally { await stopAll(); }
  });
});

describe('Layer 6 is given no unsigned affect (§8.8.4)', () => {
  it('a Legacy Import record\'s valence and arousal never reach the engine', async () => {
    try {
      const A = node('l6');
      const fed = [];
      A._xmesh = { ingestSignal: (sig) => fed.push(sig) };
      const P = identity('legacy-peer');
      const rec = signedRecord(P, { room: 'coup', categories: CATS('an imported observation') });
      rec.categories.mood = { ...rec.categories.mood, valence: 0.9, arousal: -0.8 };
      const msg = { type: 'cmb', cmb: rec, _legacyImport: true, content: 'x', source: 'legacy' };
      await A._frameHandler._processNeuralSVAF(ALIGNED, msg, 'legacy', P.nodeId, Date.now(), Date.now());
      assert.ok(fed.length >= 1);
      for (const sig of fed) { assert.strictEqual(sig.valence, 0); assert.strictEqual(sig.arousal, 0); }
    } finally { await stopAll(); }
  });
});

describe('only a gated remix is a remix (#35)', () => {
  it('remember() with parents counts as a record, remix() as a remix', async () => {
    try {
      const A = node('cnt');
      const first = A.remember(CATS('an observation'));
      A.remember(CATS('a reply citing it'), { parents: [first.cmb] });
      assert.strictEqual(A.metrics().remixProduced, 0);
      A.remember(CATS('new domain data'));
      const r = A.remix(CATS('an integration of a peer record'), { parents: [first.cmb] });
      assert.ok(r && !r.refused);
      assert.strictEqual(A.metrics().remixProduced, 1);
    } finally { await stopAll(); }
  });
});

describe('xmesh-insight-v1 is offered only when a host adds it', () => {
  it('the default offer, and a host\'s addition', async () => {
    try {
      assert.deepStrictEqual(node('ext')._offeredExtensions, ['cmb-encrypted-v2', 'sym-attest-v1']);
      assert.deepStrictEqual(node('ext2', { extraExtensions: ['xmesh-insight-v1', 'xmesh-insight-v1', 'Bad Token'] })._offeredExtensions, ['cmb-encrypted-v2', 'sym-attest-v1', 'xmesh-insight-v1']);
    } finally { await stopAll(); }
  });
});
