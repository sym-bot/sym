'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * §9.2.1: an anchor's weight in the memory readout is max(cos, 0) · exp(−age/τ) · conf. The age is
 * the anchor's time in THIS store and conf is the weight this store gives it (§6.4: a validated
 * anchor counts more, a dismissed one less). Both live on the store entry, not on the record.
 *
 * MemoryStore.anchors() handed the gate bare records, which carry neither, so the gate read
 * `storedAt` as now and conf as 1 for every anchor: memory never aged and a dismissal changed
 * nothing. The anchors are views carrying the entry's values; the record itself is not written to.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { tmpdir } = require('./_tmpdir');
const { MemoryStore } = require('../lib/memory-store');
const { createCMB, processHeuristicSVAF } = require('../lib/core');

const TAU = 3600;
const POLICY = { stableThreshold: 0.35, guardedThreshold: 0.75, temporalLambda: 0.3, freshnessSeconds: TAU };

// One kernel for every gate the test compares (§9.2.1: drifts compare only within a pinned
const { awaitSemantic } = require('./_semantic');

function cat7(t) {
  return {
    focus: t, issue: t, intent: t, motivation: t, commitment: t,
    perspective: 'observer', mood: { text: 'neutral', valence: 0, arousal: 0 },
  };
}

const AGREES = 'the build pipeline caches artifacts per commit';
const OTHER = 'the deploy job publishes container images every night';
const INCOMING = 'the build pipeline caches artifacts per commit hash';

/** A store holding the anchor the incoming block agrees with and one it does not; `age` the first. */
function storeWith(adjust) {
  const store = new MemoryStore(tmpdir('sym-anchor-weight-'), 'receiver');
  const agrees = store.write('agrees', { cmb: createCMB({ categories: cat7(AGREES), createdBy: 'receiver' }) });
  store.write('other', { cmb: createCMB({ categories: cat7(OTHER), createdBy: 'receiver' }) });
  if (adjust) adjust(store, agrees.key);
  return { store, agreesKey: agrees.key };
}

async function totalDriftAgainst(store) {
  const now = Date.now();
  const r = await processHeuristicSVAF({
    msg: { type: 'cmb', cmb: createCMB({ categories: cat7(INCOMING), createdBy: 'peer' }), content: 'incoming' },
    peerName: 'peer', localName: 'receiver', originTs: now, now, ageSeconds: 0,
    recentCMBs: store.recentCMBs(5), config: POLICY,
  });
  assert.strictEqual(r.coldStartCause, undefined, 'precondition: the anchors were consulted');
  return r.totalDrift;
}

describe('SVAF anchors carry the store\'s age and weight', () => {
  it('an old anchor weighs less than a fresh one, and a dismissed one less than an observed one', async () => {
    await awaitSemantic();
    const fresh = storeWith();
    const aged = storeWith((store, key) => { store.get(key).storedAt = Date.now() - 3 * TAU * 1000; });
    const dismissed = storeWith((store, key) => { store.dismissCMB(key); });

    const dFresh = await totalDriftAgainst(fresh.store);
    const dAged = await totalDriftAgainst(aged.store);
    const dDismissed = await totalDriftAgainst(dismissed.store);
    assert.ok(dAged > dFresh, `the anchor the incoming agrees with pulls less once it is old (${dAged} vs ${dFresh})`);
    assert.ok(dDismissed > dFresh, `and less once it is dismissed (${dDismissed} vs ${dFresh})`);

    for (const { store, agreesKey } of [fresh, aged, dismissed]) {
      const record = store.get(agreesKey).cmb;
      assert.deepStrictEqual(Object.keys(record).sort(), ['categories', 'metadata'], 'nothing was written onto the record');
    }
  });

  it('an anchor older than memory reaches is no anchor at all', async () => {
    const { store } = storeWith((s, key) => { s.get(key).storedAt = Date.now() - 30 * 24 * 3600 * 1000; });
    // Keep only the aged anchor in the window.
    const views = store.recentCMBs(5).filter((a) => a.categories.focus.text === AGREES);
    assert.strictEqual(views.length, 1);
    const now = Date.now();
    const r = await processHeuristicSVAF({
      msg: { type: 'cmb', cmb: createCMB({ categories: cat7(INCOMING), createdBy: 'peer' }), content: 'incoming' },
      peerName: 'peer', localName: 'receiver', originTs: now, now, ageSeconds: 0, recentCMBs: views, config: POLICY,
    });
    assert.strictEqual(r.coldStartCause, 'empty-memory', 'thirty days at τ = 1 h leaves no live memory of any category');
  });
});
