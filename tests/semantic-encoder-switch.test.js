'use strict';

/**
 * The semantic encoder switch (0.14.1): `new SymNode({ semanticEncoder: 'off' })` and the environment
 * variable SYM_SEMANTIC_ENCODER=off. With either, nothing in the process loads the model: SVAF and §15.8
 * measure in the n-gram kernel, and remix() mints with its lineage, unverified, as it does when the calibrated
 * kernel is unavailable. Without them nothing changes: a node loads the model when it is built.
 *
 * Every case runs in a child process because the encoder is module state that loads once per process, with
 * the model library replaced by a counting stand-in, so no model is downloaded and "nothing loads" is a count
 * of zero rather than a guess. The child's HOME is a temp dir, as for any test that builds a node.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const LIB = path.resolve(__dirname, '..', 'lib');

/** Run `body` (async, in a script that has `loads()`, `out(obj)`, `mkNode(opts)` and the lib modules) and return what it passed to out(). */
function child(body, env = {}) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-enc-switch-'));
  const script = `
    const Module = require('module');
    let count = 0;
    // A stand-in model: a hashed bag of words, so texts with no word in common are far apart and the same text is not.
    const embed = async (text) => {
      const v = new Float32Array(384);
      for (const w of String(text).toLowerCase().split(/[^a-z0-9]+/).filter(Boolean)) {
        let h = 2166136261;
        for (const c of w) h = Math.imul(h ^ c.charCodeAt(0), 16777619) >>> 0;
        v[h % 384] += 1;
      }
      const n = Math.sqrt(v.reduce((a, b) => a + b * b, 0)) || 1;
      for (let i = 0; i < 384; i++) v[i] /= n;
      return { data: v };
    };
    const stand = { pipeline: () => { count++; return new Promise((r) => setTimeout(() => r(embed), 60)); } };
    const real = Module._load;
    Module._load = function (req, ...rest) { return req === '@huggingface/transformers' ? stand : real.call(this, req, ...rest); };
    const loads = () => count;
    const out = (o) => process.stdout.write('\\n@@' + JSON.stringify(o) + '\\n');
    const LIB = ${JSON.stringify(LIB)};
    const mkNode = (opts = {}) => {
      const { SymNode } = require(LIB + '/node.js');
      const { NullDiscovery } = require(LIB + '/discovery.js');
      return new SymNode({ name: 'enc-' + Math.random().toString(36).slice(2, 8), silent: true, discovery: new NullDiscovery(), ...opts });
    };
    (async () => { ${body} })().then(() => process.exit(0), (e) => { console.error(e); process.exit(1); });
  `;
  const childEnv = { ...process.env, HOME: home, USERPROFILE: home };
  delete childEnv.SYM_SEMANTIC_ENCODER;
  const r = spawnSync(process.execPath, ['-e', script], { encoding: 'utf8', env: { ...childEnv, ...env }, timeout: 60000 });
  fs.rmSync(home, { recursive: true, force: true });
  const line = r.stdout.split('\n').filter((l) => l.startsWith('@@')).pop();
  assert.ok(line, `the child printed no result (status ${r.status}):\n${r.stdout}\n${r.stderr}`);
  return { ...JSON.parse(line.slice(2)), stderr: r.stderr, stdout: r.stdout };
}

/** The child-side steps that make a remix with a verified root in reach (the shape spec-update-remix-tether.test.js uses). */
const REMIX = `
  const { createCMB } = require(LIB + '/core');
  const cat7 = (t) => ({ focus: t, issue: t, intent: t, motivation: t, commitment: t, perspective: 'peerA', mood: { text: 'neutral' } });
  const node = mkNode(NODE_OPTS);
  await node.start();
  const rootText = 'quarterly financial audit of the accounting ledger and tax filings';
  const root = createCMB({ categories: cat7(rootText), createdBy: 'peerR' });
  node._store.receiveFromPeer('peerR', { key: root.metadata.key, content: rootText, source: 'peerR', cmb: root, _cmbVerified: true });
  node.remember(cat7('new domain data of this node'));
  const metrics = [];
  node.on('metric', (m) => { if (m.type === 'tether-kernel-unavailable') metrics.push(m); });
  const t0 = Date.now();
  const e = await node.remix(cat7('fresh snowfall reported on the upper mountain trail sections'), { parents: [root] });
  const stored = node._store.get(e.key);
  out({ loads: loads(), ms: Date.now() - t0, parents: stored.cmb.metadata.lineage && stored.cmb.metadata.lineage.parents, rootKey: root.metadata.key,
        tether: stored.tether === undefined ? null : stored.tether, provenanceTether: stored.provenance && stored.provenance.tether || null, metrics });
  await node.stop();
`;

describe('semanticEncoder: the switch for the eager semantic encoder', () => {
  it('requiring sym starts no model load, and a node built without the option starts it (the default is unchanged)', () => {
    const r = child(`
      require(LIB + '/node.js'); require(LIB + '/core');
      const afterRequire = loads();
      const node = mkNode();
      const afterBuild = loads();
      const enc = require(LIB + '/core/context-encoder.js');
      const settled = await enc.semanticSettled();
      out({ afterRequire, afterBuild, settled, ready: enc.isSemanticReady(), kernel: enc.kernelId(), mode: enc.semanticMode() });
    `);
    assert.equal(r.afterRequire, 0, 'requiring the package is not a reason to load a model');
    assert.equal(r.afterBuild, 1, 'building a node starts the one load');
    assert.deepEqual([r.settled, r.ready, r.mode], [true, true, 'eager']);
    assert.match(r.kernel, /^minilm-/);
  });

  it("semanticEncoder: 'off' loads nothing, ever: the kernel is the n-gram one and the encoder never settles ready", () => {
    const r = child(`
      const node = mkNode({ semanticEncoder: 'off' });
      await node.start();
      const enc = require(LIB + '/core/context-encoder.js');
      const t0 = Date.now();
      const settled = await enc.semanticSettled();
      const vec = await enc.encodeForSVAF('a sentence');
      out({ loads: loads(), settled, ms: Date.now() - t0, ready: enc.isSemanticReady(), kernel: enc.kernelId(), dims: [vec.h1.length, vec.h2.length], mode: enc.semanticMode() });
      await node.stop();
    `);
    assert.equal(r.loads, 0, 'nothing loaded the model');
    assert.deepEqual([r.settled, r.ready, r.mode], [false, false, 'off']);
    assert.equal(r.kernel, 'ngram-h32');
    assert.deepEqual(r.dims, [32, 32], 'the n-gram encoder still answers');
    assert.ok(r.ms < 1000, 'settled false at once, not after a wait');
  });

  it('SYM_SEMANTIC_ENCODER=off does the same from the environment, for a node that was given no option', () => {
    const r = child(`
      const node = mkNode();
      await node.start();
      const enc = require(LIB + '/core/context-encoder.js');
      await enc.encodeForSVAF('x');
      out({ loads: loads(), kernel: enc.kernelId(), mode: enc.semanticMode() });
      await node.stop();
    `, { SYM_SEMANTIC_ENCODER: 'off' });
    assert.deepEqual([r.loads, r.kernel, r.mode], [0, 'ngram-h32', 'off']);
  });

  it('off wins and stays: a later node asking for eager in the same process does not turn the encoder on', () => {
    const r = child(`
      mkNode({ semanticEncoder: 'off' });
      const second = mkNode({ semanticEncoder: 'eager', silent: false });
      const enc = require(LIB + '/core/context-encoder.js');
      await enc.encodeForSVAF('x');
      out({ loads: loads(), mode: enc.semanticMode(), kernel: enc.kernelId() });
    `);
    assert.deepEqual([r.loads, r.mode, r.kernel], [0, 'off', 'ngram-h32']);
    assert.match(r.stdout, /semanticEncoder: 'eager' is ignored/, 'and the node says so');
  });

  it('off after the model has loaded switches the process to the n-gram kernel from then on', () => {
    const r = child(`
      const enc = require(LIB + '/core/context-encoder.js');
      mkNode();
      await enc.semanticSettled();
      const before = enc.kernelId();
      mkNode({ semanticEncoder: 'off' });
      out({ before, after: enc.kernelId(), ready: enc.isSemanticReady(), loads: loads() });
    `);
    assert.match(r.before, /^minilm-/);
    assert.equal(r.after, 'ngram-h32');
    assert.deepEqual([r.ready, r.loads], [false, 1]);
  });

  it("with it off, remix() mints with its lineage and unverified, at once, and says why (the same trust state as an unavailable kernel)", () => {
    const r = child(REMIX.replace('NODE_OPTS', "{ semanticEncoder: 'off', tetherKernelWaitMs: 30000 }"));
    assert.equal(r.loads, 0, 'nothing loaded the model');
    assert.deepEqual(r.parents, [r.rootKey], 'the remix keeps its lineage: a drifted topic was NOT severed from a measurement in the wrong kernel');
    assert.equal(r.tether, null, 'nothing is signed');
    assert.equal(r.provenanceTether, null, 'no verdict is recorded: unverified');
    assert.ok(r.ms < 2000, `it did not wait for the 30 s kernel bound (took ${r.ms} ms)`);
    assert.deepEqual(r.metrics, [{ type: 'tether-kernel-unavailable', reason: 'off' }]);
  });

  it('the same remix with the encoder on is evaluated and severed in the calibrated kernel (the control: the switch is what changes it)', () => {
    const r = child(REMIX.replace('NODE_OPTS', '{}'));
    assert.equal(r.loads, 1);
    assert.equal(r.parents, null, 'a topic with nothing in common is minted as a fresh root');
    assert.equal(r.tether.verdict, 'severed');
    assert.match(r.tether.kernelId, /^minilm-/);
    assert.deepEqual(r.metrics, []);
  });

  it('an option that is not eager or off is a TypeError (EBADENCODER) before the node touches the disk', () => {
    const r = child(`
      const fs = require('fs');
      const tries = {};
      for (const v of ['lazy', 'OFF', true, 0, '']) {
        try { mkNode({ semanticEncoder: v }); tries[String(v)] = 'built'; } catch (e) { tries[String(v)] = e.code + ' ' + e.constructor.name; }
      }
      const enc = require(LIB + '/core/context-encoder.js');
      out({ tries, loads: loads(), mode: enc.semanticMode(), nodes: fs.existsSync(process.env.HOME + '/.sym/nodes') ? fs.readdirSync(process.env.HOME + '/.sym/nodes') : [] });
    `);
    for (const k of ['lazy', 'OFF', 'true', '0', '']) assert.equal(r.tries[k], 'EBADENCODER TypeError', `semanticEncoder: ${JSON.stringify(k)}`);
    assert.equal(r.mode, 'eager', 'a refused value changes nothing');
    assert.equal(r.loads, 0, 'and starts nothing');
    assert.deepEqual(r.nodes, [], 'no node was created');
  });

  it('an environment value that is not eager or off is said and ignored: the encoder stays eager', () => {
    const r = child(`
      const node = mkNode();
      const enc = require(LIB + '/core/context-encoder.js');
      out({ loads: loads(), mode: enc.semanticMode() });
    `, { SYM_SEMANTIC_ENCODER: 'of' });
    assert.deepEqual([r.loads, r.mode], [1, 'eager']);
    assert.match(r.stderr, /SYM_SEMANTIC_ENCODER="of" is not 'eager' or 'off'/);
  });

  it("the environment value 'eager' (any case) is the default spelled out", () => {
    const r = child(`mkNode(); out({ loads: loads() });`, { SYM_SEMANTIC_ENCODER: 'Eager' });
    assert.equal(r.loads, 1);
  });
});
