'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * The gate's embedding cache must file every vector under the kernel that produced it.
 *
 * The semantic encoder loads asynchronously and replaces the lexical one while a node runs. The
 * gate picked its encoder once, at its start, but named each cache entry by the kernel in force at
 * the moment of the lookup. A gate that started lexical and was still encoding when the semantic
 * encoder finished loading therefore cached lexical vectors under the semantic kernel's name, and
 * every later gate was served them as semantic ones: two unrelated spaces compared as one, for as
 * long as the entries stayed in the cache.
 *
 * The switch is injected by standing a fake context-encoder in for the real one, the same seam
 * lineage-tether-reproducible uses, so the moment it lands is exact rather than a race.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { CAT7_CATEGORIES, createCMB } = require('../lib/core');

const POLICY = { stableThreshold: 0.35, guardedThreshold: 0.75, temporalLambda: 0.3, freshnessSeconds: 3600 };

/** Distinct text in every category, so each category's encode can be told apart. */
function cat7(prefix) {
  const c = {};
  for (const f of CAT7_CATEGORIES) c[f] = `${prefix} ${f}`;
  c.mood = { text: `${prefix} mood`, valence: 0, arousal: 0 };
  return c;
}

/**
 * A context-encoder whose semantic kernel becomes ready when the test says so. Its semantic encoder
 * maps every text to the same unit vector, so in that kernel any two records are paraphrases, and
 * it records each text it is asked to encode.
 */
function fakeEncoder(real) {
  const state = { semantic: false, semanticTexts: [] };
  const LEX = 'ngram-h32';
  const SEM = 'fake-semantic-h32';
  const unit = Array.from({ length: real.DIM }, (_, i) => (i === 0 ? 1 : 0));
  const semantic = async (text) => { state.semanticTexts.push(text); return { h1: unit.slice(), h2: [] }; };
  const lexical = async (text) => real.encode(text);
  const exports = {
    ...real,
    isSemanticReady: () => state.semantic,
    kernelId: () => (state.semantic ? SEM : LEX),
    encodeForSVAF: (text) => (state.semantic ? semantic(text) : lexical(text)),
    svafKernel: () => (state.semantic ? { id: SEM, encode: semantic } : { id: LEX, encode: lexical }),
  };
  return { state, exports };
}

describe('SVAF embedding cache: keyed by the kernel that produced the vector', () => {
  it('a gate that straddles the encoder switch does not poison the semantic kernel', async () => {
    const ctxPath = require.resolve('../lib/core/context-encoder');
    const sbPath = require.resolve('../lib/core/svaf-baseline');
    const realCtx = require.cache[ctxPath];
    const realSb = require.cache[sbPath];
    const fake = fakeEncoder(realCtx.exports);
    try {
      require.cache[ctxPath] = { id: ctxPath, filename: ctxPath, loaded: true, exports: fake.exports };
      delete require.cache[sbPath];
      const { processHeuristicSVAF } = require(sbPath); // a fresh gate, with a fresh cache, on the fake encoder

      const now = Date.now();
      const gate = (cmb, recentCMBs) => processHeuristicSVAF({
        msg: { type: 'cmb', cmb, content: 'incoming' },
        peerName: 'peer', localName: 'receiver', originTs: now, now, ageSeconds: 0, recentCMBs, config: POLICY,
      });

      // Gate 1 starts while only the lexical kernel exists. Its synchronous prefix runs inside the
      // call, so flipping the flag right after it returns lands the switch mid-gate.
      const pending = gate(createCMB({ categories: cat7('incoming'), createdBy: 'peer' }), []);
      fake.state.semantic = true;
      await pending;

      // Gate 2 runs wholly in the semantic kernel, on the same incoming text, against an anchor whose
      // text has never been encoded.
      fake.state.semanticTexts.length = 0;
      const anchor = createCMB({ categories: cat7('anchor'), createdBy: 'receiver' });
      const r = await gate(createCMB({ categories: cat7('incoming'), createdBy: 'peer' }), [anchor]);

      const encoded = new Set(fake.state.semanticTexts);
      const missed = CAT7_CATEGORIES.filter((f) => !encoded.has(f === 'mood' ? 'incoming mood' : `incoming ${f}`));
      assert.deepStrictEqual(missed, [],
        'every incoming category was encoded by the semantic kernel, never served a lexical vector cached under its name');
      assert.strictEqual(r.decision, 'redundant', 'in the semantic kernel the two records are indistinguishable');
    } finally {
      require.cache[ctxPath] = realCtx;
      require.cache[sbPath] = realSb;
    }
  });
});
