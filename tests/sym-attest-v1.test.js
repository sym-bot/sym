'use strict';

require('./_isolate-home'); // redirect $HOME before lib/config loads

/**
 * The admission-attestation extension, `sym-attest-v1` (draft spec PR meshcognition-website#27):
 * the frame names, the wire fields, and the eight corrections to sym 0.13's constructions —
 *   1. frames named `sym-attest-<name>` and sent only where the extension is negotiated;
 *   2. every signature lp-encoded under its own domain tag (no `|`-joined string, no literal prefix);
 *   3. the room is `room` and the position `uptoSeq` on the wire;
 *   4. `assertionId` carried and signed;
 *   5. `method` signed;
 *   6. the checkpoint root a promote-odd Merkle tree with leaf and node tags (never pair-with-self);
 *   7. node statistics carry no self-asserted name or nodeId;
 *   8. keys only from the registry (not from hellos) — covered by the D3 tests.
 * The chain link `prev` is the SHA-256 of the previous signature's bytes.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const core = require('../lib/core');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDirById } = require('../lib/config');
const { connectNodes, until, admitAs, deliver, identity } = require('./_core-secure');

const lp = (s) => { const b = Buffer.from(String(s), 'utf8'); return Buffer.concat([Buffer.from(`${b.length}:`), b]); };
const sha = (...parts) => crypto.createHash('sha256').update(Buffer.concat(parts)).digest();
const hex = (c) => c.repeat(64);
const CATS = { focus: 'admit', issue: 'admit', intent: 'guard', motivation: 'admit', commitment: 'silent', perspective: 'admit', mood: 'redundant' };
const A = identity('attester');
const att = () => ({ of: `cmb-${hex('a')}`, assertionId: `asrt-${hex('b')}`, by: A.nodeId, at: 1786611600000, roster: 'room-é', method: 'neural', verdict: 'guarded', categories: { ...CATS }, role: 'participant', seq: 2, prev: hex('c') });

describe('the signed constructions (sym-attest-v1 §5)', () => {
  it('an attestation signs lp(every field) under mmp-attest-v1, method and assertionId included, room in NFC', () => {
    const a = att();
    const expected = Buffer.concat([
      Buffer.from('mmp-attest-v1\n'), lp(a.of), lp(a.assertionId), lp(a.by), lp('1786611600000'), lp('room-é'.normalize('NFC')),
      lp('neural'), lp('guarded'), ...['focus', 'issue', 'intent', 'motivation', 'commitment', 'perspective', 'mood'].map((f) => lp(CATS[f])),
      lp('participant'), lp('2'), lp(hex('c')),
    ]);
    assert.ok(core.attestationPayload(a).equals(expected));
    core.signAttestation(a, A.privateKey);
    assert.strictEqual(core.verifyAttestation(a, A.publicKey).valid, true);
    for (const [k, v] of [['method', 'heuristic'], ['assertionId', `asrt-${hex('d')}`], ['roster', 'other'], ['verdict', 'aligned'], ['prev', hex('e')]]) {
      assert.strictEqual(core.verifyAttestation({ ...a, [k]: v }, A.publicKey).valid, false, `${k} is signed`);
    }
    assert.strictEqual(core.verifyAttestation({ ...a, categories: { ...CATS, mood: 'admit' } }, A.publicKey).valid, false, 'each category verdict is signed');
  });

  it('a checkpoint and a witness sign under their own tags; no signature verifies as another construction', () => {
    // The chained checkpoint (MMP 2.0 update 1): fromSeq and prev are signed; so is a witness's fromSeq.
    const cp = { by: A.nodeId, roster: 'r', from_seq: 5, upto_seq: 8, prev: hex('0'), root: hex('1'), at: 5 };
    assert.ok(core.checkpointPayload(cp).equals(Buffer.concat([Buffer.from('mmp-attest-checkpoint-v1\n'), lp(A.nodeId), lp('r'), lp('5'), lp('8'), lp(hex('0')), lp(hex('1')), lp('5')])));
    const W = identity('witness');
    const w = { attester: A.nodeId, roster: 'r', from_seq: 5, upto_seq: 8, root: hex('1'), by: W.nodeId, role: 'validator', at: 6 };
    assert.ok(core.witnessPayload(w).equals(Buffer.concat([Buffer.from('mmp-attest-witness-v1\n'), lp(A.nodeId), lp('r'), lp('5'), lp('8'), lp(hex('1')), lp(W.nodeId), lp('validator'), lp('6')])));
    core.signCheckpoint(cp, A.privateKey);
    assert.strictEqual(core.verifyCheckpoint(cp, A.publicKey).valid, true);
    // Domain separation: a checkpoint's signature is no witness's, and no attestation's.
    assert.strictEqual(core.verifyWitness({ ...w, by: A.nodeId, sig: cp.sig, sigAlg: 'ed25519' }, A.publicKey).valid, false);
    const a = core.signAttestation(att(), A.privateKey);
    assert.strictEqual(core.verifyCheckpoint({ ...cp, sig: a.sig }, A.publicKey).valid, false);
    // The 0.13 bytes no longer verify.
    const old = Buffer.from(`checkpoint|${cp.by}|r|8|${cp.root}|5`);
    const oldSig = crypto.sign(null, old, crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(A.privateKey, 'base64url')]), format: 'der', type: 'pkcs8' })).toString('base64url');
    assert.strictEqual(core.verifyCheckpoint({ ...cp, sig: oldSig }, A.publicKey).valid, false);
  });

  it('the checkpoint root is promote-odd with leaf and node tags; the chain link hashes the signature bytes', () => {
    const sigs = [1, 2, 3].map((i) => crypto.randomBytes(64).toString('base64url'));
    const leaf = (s) => sha(Buffer.from('mmp-attest-leaf-v1\n'), Buffer.from(s, 'base64url'));
    const node = (l, r) => sha(Buffer.from('mmp-attest-node-v1\n'), l, r);
    assert.strictEqual(core.attestMerkleRoot(sigs.slice(0, 1)), leaf(sigs[0]).toString('hex'));
    assert.strictEqual(core.attestMerkleRoot(sigs.slice(0, 2)), node(leaf(sigs[0]), leaf(sigs[1])).toString('hex'));
    const three = node(node(leaf(sigs[0]), leaf(sigs[1])), leaf(sigs[2]));
    assert.strictEqual(core.attestMerkleRoot(sigs), three.toString('hex'), 'the odd node is promoted');
    const dup = node(node(leaf(sigs[0]), leaf(sigs[1])), node(leaf(sigs[2]), leaf(sigs[2])));
    assert.notStrictEqual(core.attestMerkleRoot(sigs), dup.toString('hex'), 'never paired with itself (0.13)');
    assert.notStrictEqual(core.attestMerkleRoot([...sigs, sigs[2]]), core.attestMerkleRoot(sigs), 'so [a,b,c] and [a,b,c,c] differ');
    assert.strictEqual(core.chainLink(sigs[0]), crypto.createHash('sha256').update(Buffer.from(sigs[0], 'base64url')).digest('hex'));
  });
});

describe('the wire form (sym-attest-v1 §5, §6 step 1)', () => {
  it('toWire uses the extension\'s names; fromWire takes only a well-formed frame', () => {
    // On the wire a room is a §5.8 identifier (sym-attest-frame.schema.json, MMP 2.0 update 1).
    const a = core.signAttestation({ ...att(), roster: 'room-e' }, A.privateKey);
    const w = core.toWireAttestation(a);
    assert.strictEqual(core.fromWireAttestation(core.toWireAttestation(core.signAttestation(att(), A.privateKey))), null, 'a room outside §5.8 is refused');
    assert.deepStrictEqual(Object.keys(w).sort(), ['assertionId', 'at', 'by', 'categories', 'method', 'of', 'prev', 'role', 'room', 'seq', 'sig', 'sigAlg', 'verdict']);
    assert.strictEqual(w.room, 'room-e');
    assert.strictEqual(core.verifyAttestation(core.fromWireAttestation(w), A.publicKey).valid, true, 'round trip verifies');
    const bad = [
      { ...w, assertionId: undefined }, { ...w, of: 'cmb-1' }, { ...w, room: undefined, roster: 'room-e' },
      { ...w, method: { toString: 1 } }, { ...w, verdict: 'maybe' }, { ...w, categories: { ...CATS, focus: 'stable' } },
      { ...w, categories: { focus: 'admit' } }, { ...w, categories: { ...CATS, extra: 'admit' } }, { ...w, role: 2 },
      { ...w, seq: 1, prev: hex('c') }, { ...w, seq: 2, prev: 'genesis' }, { ...w, seq: 0 }, { ...w, sig: `${w.sig}=` }, { ...w, sigAlg: 'rsa' },
    ];
    for (const b of bad) assert.strictEqual(core.fromWireAttestation(b), null, JSON.stringify(Object.keys(b)));
    const cp = core.signCheckpoint({ by: A.nodeId, roster: 'room-e', from_seq: 5, upto_seq: 8, prev: hex('0'), root: hex('1'), at: 5 }, A.privateKey);
    const wc = core.toWireCheckpoint(cp);
    assert.deepStrictEqual(Object.keys(wc).sort(), ['at', 'by', 'fromSeq', 'prev', 'room', 'root', 'sig', 'sigAlg', 'uptoSeq']);
    assert.strictEqual(core.fromWireCheckpoint({ ...wc, uptoSeq: undefined, upto_seq: 8 }), null, '0.13\'s field name is not read');
    assert.strictEqual(core.fromWireCheckpoint({ ...wc, note: 'x' }), null, 'closed');
    assert.strictEqual(core.fromWireCheckpoint({ ...wc, prev: 'genesis' }), null, 'genesis exactly when fromSeq is 1');
    assert.strictEqual(core.fromWireCheckpoint({ ...wc, fromSeq: 1 }), null);
    assert.strictEqual(core.verifyCheckpoint(core.fromWireCheckpoint(wc), A.publicKey).valid, true);
  });

  it('two nodes exchange sym-attest-attestation and -checkpoint frames that verify on receipt', async () => {
    const mk = (n) => new SymNode({ name: `sa-${n}-${Date.now()}`, silent: true, discovery: new NullDiscovery(), room: 'sa-room', checkpointInterval: 2 });
    const a = mk('a'); const b = mk('b');
    try {
      await a.start(); await b.start();
      await connectNodes(a, b);
      const sent = [];
      const orig = a._gossipToRoster.bind(a);
      a._gossipToRoster = (f, x) => { sent.push(f); return orig(f, x); };
      const got = [];
      b.on('attestation-received', (e) => got.push(e));
      const verdicts = { ...CATS };
      a._buildAdmissionAttestation(`cmb-${hex('7')}`, 'aligned', verdicts, 'heuristic', `asrt-${hex('8')}`);
      a._buildAdmissionAttestation(`cmb-${hex('9')}`, 'rejected', verdicts, 'neural', `asrt-${hex('6')}`);
      await until(() => got.length === 2 && b._attestations.checkpointAt(a.nodeId, 2), 3000);
      const types = new Set(sent.map((f) => f.type));
      assert.ok(types.has('sym-attest-attestation') && types.has('sym-attest-checkpoint'), [...types].join(','));
      assert.ok([...types].every((t) => t.startsWith('sym-attest-')), 'only the extension\'s frames (a peer\'s witness, relayed once, among them)');
      assert.ok(sent.every((f) => { const o = f.attestation || f.checkpoint || f.witness; return !('roster' in o) && !('upto_seq' in o) && !('from_seq' in o); }));
      assert.deepStrictEqual(got.map((e) => [e.method, e.assertionId, e.room]), [['heuristic', `asrt-${hex('8')}`, 'sa-room'], ['neural', `asrt-${hex('6')}`, 'sa-room']]);
      assert.strictEqual(got[1].prev, core.chainLink(a._attestations.chainOf(a.nodeId)[0].sig));
      // The first checkpoint is chained to genesis over seq 1..2 (MMP 2.0 update 1).
      const segmentRoot = core.attestMerkleRoot(a._attestations.chainOf(a.nodeId).map((x) => x.sig));
      assert.strictEqual(b._attestations.checkpointAt(a.nodeId, 2).root, core.attestCheckpointRoot({ prev: 'genesis', fromSeq: 1, uptoSeq: 2, segmentRoot }));
      const rec = a.reconcileChain(a.nodeId);
      assert.strictEqual(rec.consistent, true, 'the attester reconciles its own v1 checkpoint');
    } finally { for (const n of [a, b]) { await n.stop(); fs.rmSync(nodeDirById(n.nodeId), { recursive: true, force: true }); } }
  });

  it('a frame whose fields are not the extension\'s is refused before anything is spent', async () => {
    const node = new SymNode({ name: `sa-bad-${Date.now()}`, silent: true, discovery: new NullDiscovery(), room: 'sa-room' });
    try {
      const s = admitAs(node, identity('peer'));
      const refused = [];
      node.on('metric', (m) => { if (m.type === 'session-frame-refused') refused.push(m.reason); });
      deliver(node, s, { type: 'sym-attest-attestation', attestation: { of: 'cmb-1', by: 'x' } });
      deliver(node, s, { type: 'sym-attest-checkpoint', checkpoint: { by: 'x', roster: 'sa-room', upto_seq: 8 } });
      deliver(node, s, { type: 'sym-attest-witness', witness: {} });
      assert.deepStrictEqual(refused, ['malformed', 'malformed', 'malformed']);
      assert.strictEqual(node._gossipBuckets.size, 0, 'no budget spent');
    } finally { await node.stop(); fs.rmSync(nodeDirById(node.nodeId), { recursive: true, force: true }); }
  });
});
