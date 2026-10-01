'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * Phase C — the node builds + signs an Admission Attestation when it gates a CMB,
 * and the store persists it on the remix.
 *
 * Deterministic (no encoder / no SVAF run): exercises node._buildAdmissionAttestation
 * directly and the memory-store preservation of cmb.admission. The full receive-path
 * wiring (frame-handler attaches it on admit) is covered by the integration test
 * tests/integration/e2e-admission.js.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const { verifyAttestation, verifyAttestationRole, signAttestation } = require('../lib/core');

// Construct (no start) — the builder needs only identity / room / role / chain state.
function withNode(baseName, opts, fn) {
  const name = `${baseName}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const node = new SymNode({ name, silent: true, discovery: new NullDiscovery(), ...opts });
  try { return fn(node); } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
}

const verdicts = { focus: 'admit', issue: 'reject', intent: 'guard', motivation: 'admit', commitment: 'silent', perspective: 'redundant', mood: 'admit' };

describe('node._buildAdmissionAttestation', () => {
  it('builds a signed attestation bound to the gated CMB, verifiable by this node', () => {
    withNode('att-sign', { lifecycleRole: 'validator', room: 'sym-bot-team' }, (node) => {
      const att = node._buildAdmissionAttestation('cmb-gated-1', 'guarded', verdicts, 'heuristic');
      assert.ok(att, 'returns an attestation');
      assert.strictEqual(att.of, 'cmb-gated-1');
      assert.strictEqual(att.by, node.nodeId);
      assert.strictEqual(att.roster, 'sym-bot-team');
      assert.strictEqual(att.role, 'validator');
      assert.strictEqual(att.method, 'heuristic');
      assert.strictEqual(att.verdict, 'guarded');
      assert.deepStrictEqual(att.categories, verdicts);
      assert.deepStrictEqual(verifyAttestation(att, node._identity.publicKey), { signed: true, valid: true });
    });
  });

  it('advances the per-attester hash-chain (seq monotonic, prev = hash of previous sig)', () => {
    withNode('att-chain', { lifecycleRole: 'participant', room: 'g' }, (node) => {
      const a1 = node._buildAdmissionAttestation('cmb-1', 'aligned', verdicts, 'heuristic');
      const a2 = node._buildAdmissionAttestation('cmb-2', 'aligned', verdicts, 'heuristic');
      assert.strictEqual(a1.seq, 1);
      assert.strictEqual(a1.prev, 'genesis');
      assert.strictEqual(a2.seq, 2);
      assert.strictEqual(a2.prev, crypto.createHash('sha256').update(a1.sig).digest('hex'), 'a2.prev links a1');
      assert.notStrictEqual(a1.sig, a2.sig);
    });
  });

  it('stamps the claimed role; verifyAttestationRole weights by the RESOLVED role, not the stamp', () => {
    withNode('att-role', { lifecycleRole: 'anchor', room: 'g' }, (node) => {
      const att = node._buildAdmissionAttestation('cmb-x', 'aligned', verdicts, 'heuristic');
      assert.strictEqual(att.role, 'anchor', 'node stamps its configured role');
      const r = verifyAttestationRole(att, () => 'participant'); // chain disagrees with the stamp
      assert.strictEqual(r.matches, false);
      assert.strictEqual(r.rank, 0, 'a self-stamped anchor weighs as the resolved participant');
    });
  });
});

describe('memory-store persists cmb.admission on the remix', () => {
  it('preserves a signed admission attestation through receiveFromPeer', () => {
    withNode('att-store', { lifecycleRole: 'participant', room: 'g' }, (node) => {
      const att = node._buildAdmissionAttestation('cmb-of', 'aligned', verdicts, 'heuristic');
      const entry = {
        source: `${node.name}+peer`, content: 'x',
        cmb: { key: 'remix-1', categories: { focus: { text: 'f' } }, admission: att },
        storedAt: Date.now(),
      };
      const stored = node._store.receiveFromPeer('peer-id', entry);
      assert.ok(stored && stored.cmb && stored.cmb.admission, 'admission preserved on the stored remix');
      assert.strictEqual(stored.cmb.admission.of, 'cmb-of');
      assert.deepStrictEqual(verifyAttestation(stored.cmb.admission, node._identity.publicKey), { signed: true, valid: true });
    });
  });
});

describe('node indexes its own attestations (every gating event)', () => {
  it('records each built attestation; chain verifies; CMB trail is queryable', () => {
    withNode('att-index', { lifecycleRole: 'participant', room: 'g' }, (node) => {
      const a1 = node._buildAdmissionAttestation('cmb-1', 'aligned', verdicts, 'heuristic');
      const a2 = node._buildAdmissionAttestation('cmb-2', 'rejected', verdicts, 'neural'); // reject is attested too
      const a3 = node._buildAdmissionAttestation('cmb-1', 'guarded', verdicts, 'heuristic'); // re-gate cmb-1
      assert.strictEqual(node.attestationsFor('cmb-1').length, 2, 'both gatings of cmb-1 are in its trail');
      assert.strictEqual(node.attestationsFor('cmb-2').length, 1);
      assert.deepStrictEqual([a1.seq, a2.seq, a3.seq], [1, 2, 3], 'one contiguous chain across admit + reject');
      assert.deepStrictEqual(node.verifyAttestationChain(), { ok: true, gaps: [], breaks: [] });
    });
  });
});

describe('attestation persistence — the audit trail survives a restart', () => {
  it('reloads the chain and continues seq/prev across a fresh node on the same dir', () => {
    const name = `att-restart-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    try {
      const n1 = new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: 'g' });
      const a1 = n1._buildAdmissionAttestation('cmb-1', 'aligned', verdicts, 'heuristic');
      const a2 = n1._buildAdmissionAttestation('cmb-2', 'rejected', verdicts, 'neural'); // reject attested too
      assert.deepStrictEqual([a1.seq, a2.seq], [1, 2]);

      // "Restart": a fresh node with the same name → same dir → reloads the trail.
      const n2 = new SymNode({ name, silent: true, discovery: new NullDiscovery(), room: 'g' });
      assert.strictEqual(n2.attestationsFor('cmb-1').length, 1, 'pre-restart attestation reloaded');
      assert.strictEqual(n2.attestationsFor('cmb-2').length, 1);

      // The chain cursor continued — the next attestation is seq 3 and links a2,
      // not a reset to seq 1 (which would read as a gap / false omission).
      const a3 = n2._buildAdmissionAttestation('cmb-3', 'aligned', verdicts, 'heuristic');
      assert.strictEqual(a3.seq, 3, 'seq continues across restart');
      assert.strictEqual(a3.prev, crypto.createHash('sha256').update(a2.sig).digest('hex'), 'prev links the pre-restart attestation');
      assert.deepStrictEqual(n2.verifyAttestationChain(), { ok: true, gaps: [], breaks: [] }, 'no gap/break across the restart boundary');
    } finally {
      fs.rmSync(nodeDir(name), { recursive: true, force: true });
    }
  });
});

describe('node checkpoints its chain; reconciliation catches omission (D3)', () => {
  it('commits a checkpoint at the interval; reconcile is consistent, then detects a dropped attestation', () => {
    withNode('att-cp', { lifecycleRole: 'participant', room: 'g', checkpointInterval: 4 }, (node) => {
      for (let i = 1; i <= 4; i++) node._buildAdmissionAttestation(`cmb-${i}`, 'aligned', verdicts, 'heuristic');
      const cp = node._attestations.latestCheckpoint(node.nodeId);
      assert.ok(cp, 'a checkpoint was committed at the interval');
      assert.strictEqual(cp.upto_seq, 4);

      let r = node.reconcileChain(node.nodeId);
      assert.strictEqual(r.consistent, true, 'committed root matches the held chain');
      assert.strictEqual(r.complete, true);
      assert.deepStrictEqual(r.gaps, []);

      // Suppress seq 2 from the held chain — the omission test must catch it.
      node._attestations._byAttester.get(node.nodeId).delete(2);
      r = node.reconcileChain(node.nodeId);
      assert.strictEqual(r.complete, false);
      assert.deepStrictEqual(r.gaps, [2], 'the dropped seq is a detectable gap');
      assert.strictEqual(r.consistent, false, 'recomputed root no longer matches the witnessed-committed root');
    });
  });
});

describe("'attestation-received' — a peer's verified verdict is observable as it lands", () => {
  // B ingests attestations A built, as it would from an `attestation` frame. B holds A's key the
  // way a handshake leaves it (_pinPeerKey), so verification runs for real; no transport is needed.
  function makePair({ aOpts = {}, aAsPeer = null } = {}) {
    const tag = () => `${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const A = new SymNode({ name: `att-rx-a-${tag()}`, silent: true, discovery: new NullDiscovery(), room: 'hotel', ...aOpts });
    const B = new SymNode({ name: `att-rx-b-${tag()}`, silent: true, discovery: new NullDiscovery(), room: 'hotel' });
    B._pinPeerKey(A.nodeId, A._identity.publicKey);
    // A direct peer is what gives the attester a name; the label is whatever it announced.
    if (aAsPeer) B._peers.set(A.nodeId, { peerId: A.nodeId, name: aAsPeer, transport: { send() {} } });
    const seen = [];
    const cleanup = () => { for (const n of [A, B]) fs.rmSync(nodeDir(n.name), { recursive: true, force: true }); };
    return { A, B, seen, cleanup, collect: () => B.on('attestation-received', (e) => seen.push(e)) };
  }
  function withPair(opts, fn) {
    const p = makePair(opts);
    try { p.collect(); return fn(p); } finally { p.cleanup(); }
  }

  it('emits once per verified attestation: who judged which CMB, how, where on the chain, re-verifiable', () => {
    withPair({}, ({ A, B, seen }) => {
      const first = A._buildAdmissionAttestation('cmb-request-1', 'aligned', verdicts, 'heuristic');
      const att = A._buildAdmissionAttestation('cmb-request-2', 'guarded', verdicts, 'neural');
      assert.deepStrictEqual(B._ingestAttestation(att, A.nodeId, 'concierge'), { ok: true, reason: undefined });
      assert.strictEqual(seen.length, 1);
      const e = seen[0];
      assert.strictEqual(e.of, 'cmb-request-2');
      assert.strictEqual(e.by, A.nodeId);
      assert.strictEqual(e.verdict, 'guarded');
      assert.deepStrictEqual({ ...e.categories }, verdicts);
      assert.strictEqual(e.methodUnsigned, 'neural');
      assert.strictEqual(e.roster, 'hotel');
      assert.strictEqual(e.seq, 2);
      assert.strictEqual(e.prev, crypto.createHash('sha256').update(first.sig).digest('hex'));
      assert.strictEqual(e.sig, att.sig);
      assert.strictEqual(e.sigAlg, 'ed25519');
      assert.strictEqual(e.verified, true);
      assert.strictEqual(e.keySource, 'handshake');
      assert.strictEqual(e.from, 'concierge');
      assert.strictEqual(e.fromPeerId, A.nodeId);
      assert.strictEqual(e.relayed, false);
      assert.strictEqual(typeof e.receivedAt, 'number');
      assert.deepStrictEqual(verifyAttestation(e, A._identity.publicKey), { signed: true, valid: true },
        'a consumer holding the key can re-check the event itself');
      assert.ok(Object.isFrozen(e) && Object.isFrozen(e.categories), 'the event is frozen');
    });
  });

  it('names the attester by its own peer entry, never by the peer that relayed the copy', () => {
    withPair({ aAsPeer: 'front-desk' }, ({ A, B, seen }) => {
      const att = A._buildAdmissionAttestation('cmb-request-3', 'aligned', verdicts, 'heuristic');
      assert.strictEqual(B._ingestAttestation(att, 'relay-node-id', 'housekeeping').ok, true);
      assert.strictEqual(seen.length, 1);
      assert.strictEqual(seen[0].by, A.nodeId);
      assert.strictEqual(seen[0].byName, 'front-desk');
      assert.strictEqual(seen[0].from, 'housekeeping');
      assert.strictEqual(seen[0].fromPeerId, 'relay-node-id');
      assert.strictEqual(seen[0].relayed, true);
    });
  });

  it('reports relayed as unknown, not direct, when the deliverer is unknown', () => {
    withPair({}, ({ A, B, seen }) => {
      const att = A._buildAdmissionAttestation('cmb-request-4', 'aligned', verdicts, 'heuristic');
      assert.strictEqual(B._ingestAttestation(att).ok, true);
      assert.strictEqual(seen[0].relayed, null);
      assert.strictEqual(seen[0].from, null);
      assert.strictEqual(seen[0].byName, null, 'not a direct peer, so no name');
    });
  });

  it('gives the claimed role beside the role this node resolves', () => {
    withPair({ aOpts: { lifecycleRole: 'anchor' } }, ({ A, B, seen }) => {
      const att = A._buildAdmissionAttestation('cmb-request-5', 'aligned', verdicts, 'heuristic');
      assert.strictEqual(B._ingestAttestation(att, A.nodeId, 'concierge').ok, true);
      assert.strictEqual(seen[0].role, 'anchor', 'what A stamped');
      assert.strictEqual(seen[0].roleClaimed, 'anchor');
      assert.strictEqual(seen[0].roleResolved, 'participant', 'B holds no grant that makes A an anchor');
      assert.strictEqual(seen[0].roleMatches, false);
    });
  });

  it('passes on only what the signature covers: CAT7 categories as signed strings, nothing a relay added', () => {
    withPair({}, ({ A, B, seen }) => {
      // A signs a nested object as a category value: the signature covers its string form only.
      const att = A._buildAdmissionAttestation('cmb-request-6', 'aligned', { ...verdicts, focus: { verdict: 'admit' } }, 'heuristic');
      // A relay adds a category key and rewrites the method; neither is in the signed bytes.
      const tampered = { ...att, method: 'neural', categories: { ...att.categories, recommendation: 'escalate' } };
      assert.strictEqual(B._ingestAttestation(tampered, 'relay-node-id', 'housekeeping').ok, true, 'still verifies');
      const e = seen[0];
      assert.deepStrictEqual(Object.keys(e.categories), ['focus', 'issue', 'intent', 'motivation', 'commitment', 'perspective', 'mood']);
      assert.strictEqual(e.categories.focus, '[object Object]', 'the signed form, not the object');
      assert.strictEqual('method' in e, false, 'an unsigned method is never presented as signed');
      assert.strictEqual(e.methodUnsigned, 'neural');
      assert.deepStrictEqual(verifyAttestation(e, A._identity.publicKey), { signed: true, valid: true });
    });
  });

  it('stays silent for a duplicate, a forgery, a foreign roster and an unknown attester', () => {
    withPair({}, ({ A, B, seen }) => {
      const att = A._buildAdmissionAttestation('cmb-request-7', 'aligned', verdicts, 'heuristic');
      assert.strictEqual(B._ingestAttestation(att, A.nodeId, 'concierge').ok, true);
      assert.strictEqual(B._ingestAttestation({ ...att }, A.nodeId, 'concierge').reason, 'duplicate');

      const forged = { ...A._buildAdmissionAttestation('cmb-request-8', 'rejected', verdicts, 'heuristic'), verdict: 'aligned' };
      assert.strictEqual(B._ingestAttestation(forged, A.nodeId, 'concierge').ok, false);

      const foreign = A._buildAdmissionAttestation('cmb-request-9', 'aligned', verdicts, 'heuristic');
      assert.strictEqual(B._ingestAttestation({ ...foreign, roster: 'other-room' }, A.nodeId, 'concierge').reason, 'roster-mismatch');

      withNode('att-rx-stranger', { room: 'hotel' }, (S) => {
        const unknown = S._buildAdmissionAttestation('cmb-request-10', 'aligned', verdicts, 'heuristic');
        assert.strictEqual(B._ingestAttestation(unknown, S.nodeId, 'stranger').reason, 'unknown-attester-key');
      });

      assert.strictEqual(seen.length, 1, 'only the first verified copy is announced');
      assert.strictEqual(seen[0].of, 'cmb-request-7');
    });
  });

  it('stays silent for a rate-limited copy: a flood about one CMB is not an event stream', () => {
    withPair({}, ({ A, B, seen }) => {
      const limit = B._attestations._ratePerWindow;
      const reasons = [];
      for (let i = 0; i <= limit; i++) {
        const att = A._buildAdmissionAttestation('cmb-flooded', 'aligned', verdicts, 'heuristic');
        reasons.push(B._ingestAttestation(att, A.nodeId, 'concierge').reason);
      }
      assert.strictEqual(reasons[limit], 'rate-limited');
      assert.strictEqual(seen.length, limit, 'one event per recorded attestation, none for the rate-limited one');
    });
  });

  it("gives a foreign attester's object-valued or missing fields in their signed form", () => {
    withPair({}, ({ A, B, seen }) => {
      // Validly signed but unusual: the canonicalizer signs an array through ToString, and no role.
      const base = A._buildAdmissionAttestation('cmb-request-13', 'aligned', verdicts, 'heuristic');
      const att = { ...base, prev: ['abc'] };
      delete att.role;
      signAttestation(att, A._identity.privateKey);
      assert.strictEqual(B._ingestAttestation(att, A.nodeId, 'concierge').ok, true);
      const e = seen[0];
      assert.strictEqual(e.prev, 'abc', 'a string, so no listener can change it under the next one');
      assert.strictEqual(e.role, null, 'no role was signed');
      assert.strictEqual(e.roleClaimed, 'participant', 'the claim roleMatches is computed against');
      assert.strictEqual(e.roleMatches, true);
      assert.deepStrictEqual(verifyAttestation(e, A._identity.publicKey), { signed: true, valid: true });
      for (const [k, v] of Object.entries(e)) {
        if (k !== 'categories') assert.ok(v === null || typeof v !== 'object', `${k} is a primitive`);
      }
    });
  });

  it("coerces an object-valued role claim, so it neither aliases the record nor fails to match", () => {
    withPair({ aOpts: { lifecycleRole: 'participant' } }, ({ A, B, seen }) => {
      const base = A._buildAdmissionAttestation('cmb-request-18', 'aligned', verdicts, 'heuristic');
      const att = { ...base, role: ['participant'] }; // signs exactly as 'participant' does
      signAttestation(att, A._identity.privateKey);
      assert.strictEqual(B._ingestAttestation(att, A.nodeId, 'concierge').ok, true);
      const e = seen[0];
      assert.strictEqual(e.role, 'participant');
      assert.strictEqual(e.roleClaimed, 'participant');
      assert.strictEqual(e.roleMatches, true, 'a byte-identical claim matches');
      for (const [k, v] of Object.entries(e)) {
        if (k !== 'categories') assert.ok(v === null || typeof v !== 'object', `${k} is a primitive`);
      }
      assert.deepStrictEqual(verifyAttestation(B.attestationsFor('cmb-request-18')[0], A._identity.publicKey), { signed: true, valid: true });
    });
  });

  it('matches a numeric role claim against the same role resolved as a string', () => {
    withPair({}, ({ A, B, seen }) => {
      const base = A._buildAdmissionAttestation('cmb-request-21', 'aligned', verdicts, 'heuristic');
      const att = { ...base, role: 2 }; // signs as '2'
      signAttestation(att, A._identity.privateKey);
      B.resolveRole = () => '2';
      assert.strictEqual(B._ingestAttestation(att, A.nodeId, 'concierge').ok, true);
      assert.strictEqual(seen[0].roleClaimed, '2');
      assert.strictEqual(seen[0].roleResolved, '2');
      assert.strictEqual(seen[0].roleMatches, true);
      assert.deepStrictEqual(verifyAttestation(seen[0], A._identity.publicKey), { signed: true, valid: true });
    });
  });

  it('does no work when nothing listens', () => {
    const { A, B, cleanup } = makePair();
    try {
      const metrics = [];
      B.on('metric', (m) => metrics.push(m));
      let called = false;
      B.resolveRole = () => { called = true; throw new Error('must not be called without a listener'); };
      const att = A._buildAdmissionAttestation('cmb-request-19', 'aligned', verdicts, 'heuristic');
      assert.strictEqual(B._ingestAttestation(att, A.nodeId, 'concierge').ok, true);
      assert.strictEqual(called, false, 'the grant chain is not walked with no listener');
      assert.strictEqual(metrics.filter((m) => m.type === 'attestation-event-dropped').length, 0);
    } finally { cleanup(); }
  });

  it('dispatches in listener order from a snapshot, like emit', () => {
    withPair({}, ({ A, B, seen }) => {
      const order = [];
      const collector = B.rawListeners('attestation-received')[0];
      const late = () => order.push('late');
      B.on('attestation-received', () => order.push('appended'));
      B.prependListener('attestation-received', () => {
        order.push('first');
        B.off('attestation-received', collector); // removed mid-dispatch: still sees this event
        B.on('attestation-received', late);       // added mid-dispatch: does not
      });
      const att = A._buildAdmissionAttestation('cmb-request-14', 'aligned', verdicts, 'heuristic');
      assert.strictEqual(B._ingestAttestation(att, A.nodeId, 'concierge').ok, true);
      assert.deepStrictEqual(order, ['first', 'appended'], 'the prepended listener runs first');
      assert.strictEqual(seen.length, 1, 'the collector removed during dispatch still got this event');
      const next = A._buildAdmissionAttestation('cmb-request-15', 'aligned', verdicts, 'heuristic');
      B._ingestAttestation(next, A.nodeId, 'concierge');
      assert.deepStrictEqual(order, ['first', 'appended', 'first', 'appended', 'late']);
      assert.strictEqual(seen.length, 1, 'and nothing after it was removed');
    });
  });

  it('reports an event it could not build on metric, and still records the attestation', () => {
    withPair({}, ({ A, B, seen }) => {
      const metrics = [];
      B.on('metric', () => { throw new Error('counter rejects an unknown type'); }); // must not starve the next
      B.on('metric', async () => { throw new Error('shipper offline'); });          // must not go unhandled
      B.on('metric', (m) => { m.node = 'b'; metrics.push(m); }); // stamps its payload, like the other 22 metrics allow
      B.resolveRole = () => { throw new Error('grant chain unreadable'); };
      const att = A._buildAdmissionAttestation('cmb-request-16', 'aligned', verdicts, 'heuristic');
      assert.strictEqual(B._ingestAttestation(att, A.nodeId, 'concierge').ok, true);
      assert.strictEqual(seen.length, 0);
      const dropped = metrics.filter((m) => m.type === 'attestation-event-dropped');
      assert.strictEqual(dropped.length, 1);
      assert.strictEqual(dropped[0].of, 'cmb-request-16');
      assert.strictEqual(dropped[0].reason, 'grant chain unreadable');
      assert.strictEqual(B.attestationsFor('cmb-request-16').length, 1);
    });
  });

  it('a log sink that throws does not turn a failing listener into a failed ingest', async () => {
    const { A, B, cleanup } = makePair();
    const unhandled = [];
    const onUnhandled = (r) => unhandled.push(r);
    process.on('unhandledRejection', onUnhandled);
    try {
      B._log = () => { throw new Error('log pipe closed'); };
      // Only an async listener first, so the rejection handler's own logging is what is under test.
      const onlyAsync = async () => { throw new Error('view socket closed'); };
      B.on('attestation-received', onlyAsync);
      const att = A._buildAdmissionAttestation('cmb-request-17', 'aligned', verdicts, 'heuristic');
      assert.strictEqual(B._ingestAttestation(att, A.nodeId, 'concierge').ok, true);
      await new Promise((r) => setTimeout(r, 20));
      assert.deepStrictEqual(unhandled, [], 'the rejection handler cannot itself reject');
      // Then a synchronous throw, whose catch block logs through the same failing sink.
      B.off('attestation-received', onlyAsync);
      B.on('attestation-received', () => { throw new Error('listener bug'); });
      const next = A._buildAdmissionAttestation('cmb-request-20', 'aligned', verdicts, 'heuristic');
      assert.strictEqual(B._ingestAttestation(next, A.nodeId, 'concierge').ok, true, 'the catch block cannot throw out');
    } finally {
      process.off('unhandledRejection', onUnhandled);
      cleanup();
    }
  });

  it('a failing listener cannot reach the stored record, starve a later listener, or undo the ingest', async () => {
    const { A, B, seen, cleanup, collect } = makePair();
    const unhandled = [];
    const onUnhandled = (r) => unhandled.push(r);
    process.on('unhandledRejection', onUnhandled);
    try {
      // Registered BEFORE the collector, so a throw that escaped would starve it.
      B.on('attestation-received', (e) => { e.categories.focus = 'reject'; });          // frozen: throws in strict mode
      B.on('attestation-received', () => { throw null; });                              // not an Error
      B.on('attestation-received', async () => { throw new Error('view socket closed'); });
      let once = 0;
      B.once('attestation-received', () => { once++; });
      collect();

      const att = A._buildAdmissionAttestation('cmb-request-11', 'aligned', verdicts, 'heuristic');
      assert.strictEqual(B._ingestAttestation(att, A.nodeId, 'concierge').ok, true, 'the ingest still reports success');
      const second = A._buildAdmissionAttestation('cmb-request-12', 'aligned', verdicts, 'heuristic');
      assert.strictEqual(B._ingestAttestation(second, A.nodeId, 'concierge').ok, true);
      await new Promise((r) => setTimeout(r, 20));

      assert.strictEqual(seen.length, 2, 'the later listener saw both events');
      assert.strictEqual(once, 1, 'a once-listener fired once and removed itself');
      assert.deepStrictEqual(unhandled, [], 'an async listener that rejects is not an unhandled rejection');
      const stored = B.attestationsFor('cmb-request-11');
      assert.strictEqual(stored.length, 1, 'the attestation is recorded');
      assert.strictEqual(stored[0].categories.focus, 'admit', 'the stored categories are untouched');
      assert.deepStrictEqual(verifyAttestation(stored[0], A._identity.publicKey), { signed: true, valid: true });
    } finally {
      process.off('unhandledRejection', onUnhandled);
      cleanup();
    }
  });
});

// The witness storm (2026-10-01): two signed copies of one witness were relayed back and forth by
// every node without end. A node relays a witness once, whatever copy arrives, witnesses a checkpoint
// once across restarts, and drops repeats before checking their signatures.
describe('the witness storm', () => {
  const { signCheckpoint, signWitness } = require('../lib/core');
  const kp = () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', { publicKeyEncoding: { type: 'spki', format: 'der' }, privateKeyEncoding: { type: 'pkcs8', format: 'der' } });
    return { pub: publicKey.slice(-32).toString('base64url'), priv: privateKey.slice(-32).toString('base64url') };
  };
  const signed = (fields, priv, sign) => { const o = { ...fields }; sign(o, priv); return o; };

  it('a second copy of a witness is not relayed, and a held checkpoint is not witnessed again', () => {
    const ATT = kp(), WIT = kp();
    withNode('att-storm', { lifecycleRole: 'participant', room: 'g' }, (node) => {
      node._pinPeerKey('node-att', ATT.pub);
      node._pinPeerKey('node-wit', WIT.pub);
      const relayed = [];
      node._gossipToRoster = (frame) => relayed.push(frame.type);
      const cp = signed({ type: 'checkpoint', by: 'node-att', roster: 'g', upto_seq: 8, root: 'r8', at: 1 }, ATT.priv, signCheckpoint);
      assert.strictEqual(node._ingestCheckpoint(cp, 'node-att').ok, true);
      assert.deepStrictEqual(relayed, ['checkpoint', 'witness'], 'relayed once and witnessed once');
      const copy = (at) => signed({ type: 'witness', attester: 'node-att', roster: 'g', upto_seq: 8, root: 'r8', by: 'node-wit', role: 'participant', at }, WIT.priv, signWitness);
      assert.strictEqual(node._ingestWitness(copy(1), 'node-wit').ok, true);
      assert.strictEqual(node._ingestWitness(copy(2), 'node-wit').ok, false, 'a second signing of the same witness is not new');
      assert.strictEqual(node._ingestWitness(copy(1), 'node-wit').ok, false, 'nor is the first one, again');
      assert.deepStrictEqual(relayed, ['checkpoint', 'witness', 'witness'], 'one relay per witness statement');
      node._witnessCheckpoint(cp);
      assert.strictEqual(relayed.length, 3, 'this node does not sign a second copy of its own witness');
    });
  });

  it('a repeat is dropped before its signature is checked; nothing unverified changes state', () => {
    const ATT = kp(), WIT = kp();
    withNode('att-early', { lifecycleRole: 'participant', room: 'g' }, (node) => {
      node._pinPeerKey('node-att', ATT.pub);
      node._pinPeerKey('node-wit', WIT.pub);
      node._gossipToRoster = () => {};
      const cp = signed({ type: 'checkpoint', by: 'node-att', roster: 'g', upto_seq: 8, root: 'r8', at: 1 }, ATT.priv, signCheckpoint);
      node._ingestCheckpoint(cp, 'node-att');
      assert.strictEqual(node._ingestCheckpoint({ ...cp, sig: 'not-a-signature' }, 'node-att').reason, 'duplicate', 'not even verified');
      assert.strictEqual(node._ingestCheckpoint({ ...cp, root: 'forged', sig: 'garbage' }, 'node-att').reason, 'bad-signature', 'a different root is verified first');
      assert.strictEqual(node._attestations.hasConflict('node-att', 8), false, 'and an unverified one marks nothing');
      const w = signed({ type: 'witness', attester: 'node-att', roster: 'g', upto_seq: 8, root: 'r8', by: 'node-wit', role: 'participant', at: 1 }, WIT.priv, signWitness);
      node._ingestWitness(w, 'node-wit');
      assert.strictEqual(node._ingestWitness({ ...w, sig: 'garbage' }, 'node-wit').reason, 'duplicate');
    });
  });

  it('a signed second root is a conflict: surfaced once, reported by reconcile, never relayed', () => {
    const ATT = kp();
    withNode('att-conflict', { lifecycleRole: 'participant', room: 'g' }, (node) => {
      node._pinPeerKey('node-att', ATT.pub);
      const relayed = [];
      node._gossipToRoster = (f) => relayed.push(f.type);
      const metrics = [];
      node.on('metric', (m) => metrics.push(m));
      const cp = (root, at) => signed({ type: 'checkpoint', by: 'node-att', roster: 'g', upto_seq: 8, root, at }, ATT.priv, signCheckpoint);
      node._ingestCheckpoint(cp('r8', 1), 'peer-x');
      const n = relayed.length;
      assert.strictEqual(node._ingestCheckpoint(cp('r-after-reset', 2), 'peer-x').reason, 'conflict');
      node._ingestCheckpoint(cp('r-after-reset', 3), 'peer-x');
      assert.strictEqual(relayed.length, n, 'a conflict is not relayed');
      const conflicts = metrics.filter((x) => x.type === 'attestation-conflict');
      assert.strictEqual(conflicts.length, 1, 'said once per position');
      assert.deepStrictEqual([conflicts[0].keptRoot, conflicts[0].otherRoot], ['r8', 'r-after-reset']);
      assert.strictEqual(node.reconcileChain('node-att').conflicted, true);
    });
  });

  it('a replayed checkpoint with its position spelled as text is refused', () => {
    const ATT = kp();
    withNode('att-text-seq', { lifecycleRole: 'participant', room: 'g' }, (node) => {
      node._pinPeerKey('node-att', ATT.pub);
      node._gossipToRoster = () => {};
      const cp = signed({ type: 'checkpoint', by: 'node-att', roster: 'g', upto_seq: 8, root: 'r8', at: 1 }, ATT.priv, signCheckpoint);
      node._ingestCheckpoint(cp, 'node-att');
      assert.strictEqual(node._ingestCheckpoint({ ...cp, upto_seq: '8' }, 'node-att').ok, false);
      assert.strictEqual(node._ingestCheckpoint({ ...cp, upto_seq: '08' }, 'node-att').ok, false);
      assert.deepStrictEqual(node._attestations.checkpointsOf('node-att').map((c) => c.upto_seq), [8]);
    });
  });
});
