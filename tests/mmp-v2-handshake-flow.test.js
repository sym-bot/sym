'use strict';

// MMP v2.0 §5.2 authenticated handshake flow: the full client-hello → server-hello → client-finish
// exchange producing an established session, plus every abort path that makes it worth doing —
// forged proof, X25519 key substitution, stripped cmb-encrypted-v2 (downgrade), nonce replay, and
// a divergent transcript. Transport-free: frames are objects, agreement is injected.

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { clientHello, serverAccept, clientFinish, serverConfirm } = require('../lib/core/handshake-v2-flow');
const { EXT_CMB_ENCRYPTED_V2 } = require('../lib/core/mmp-extensions');
const { buildEncryptedFrame, openEncryptedFrame } = require('../lib/core/cmb-encrypted-frame');

// Ed25519 identity + X25519 E2E material for a party.
function party(name, nodeId, extensions) {
  const id = crypto.generateKeyPairSync('ed25519');
  const e2e = crypto.generateKeyPairSync('x25519');
  return {
    room: 'conformance-room', nodeId, name,
    identityPrivateKey: id.privateKey.export({ format: 'jwk' }).d,
    identityPublicKey: crypto.createPublicKey(id.privateKey).export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64url'),
    e2ePrivate: e2e.privateKey,
    e2ePublicKey: e2e.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64url'),
    implementation: { name: 'sym', version: '0.11.3' },
    extensions,
  };
}
// X25519 agreement against a raw base64url peer public key.
function agreeWith(self) {
  return (peerPubB64url) => {
    const der = Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), Buffer.from(peerPubB64url, 'base64url')]);
    return crypto.diffieHellman({ privateKey: self.e2ePrivate, publicKey: crypto.createPublicKey({ key: der, format: 'der', type: 'spki' }) });
  };
}

const EXTS = [EXT_CMB_ENCRYPTED_V2, 'admission-attestation-v1'];
function pair(clientExts = EXTS, serverExts = EXTS) {
  const C = party('client-node', '018f47a0-7b21-7abc-8def-111111111111', clientExts);
  const S = party('server-node', '018f47a0-7b21-7abc-8def-222222222222', serverExts);
  return { C, S };
}

// Drive a complete exchange; returns both established sessions.
function handshake({ C, S }) {
  const { frame: ch } = clientHello(C);
  const sa = serverAccept({ clientHelloFrame: ch, self: S, agree: agreeWith(S) });
  const cf = clientFinish({ serverHelloFrame: sa.frame, clientHelloFrame: ch, self: C, agree: agreeWith(C) });
  const serverSession = serverConfirm({
    clientFinishFrame: cf.frame, transcript: sa.transcript, session: sa.session,
    clientIdentityPublicKey: ch.identityPublicKey, sharedSecret: agreeWith(S)(ch.e2ePublicKey),
  });
  return { clientHelloFrame: ch, serverHello: sa, clientFinishResult: cf, clientSession: cf.session, serverSession };
}

describe('MMP v2.0 §5.2 authenticated handshake flow', () => {
  it('completes: both sides derive the same session and select cmb-encrypted-v2', () => {
    const { clientSession, serverSession, clientFinishResult } = handshake(pair());
    assert.strictEqual(clientSession.sessionId, serverSession.sessionId);
    assert.ok(clientSession.confirmed && serverSession.confirmed, 'both sessions are confirmed');
    assert.deepStrictEqual(clientFinishResult.selected, [EXT_CMB_ENCRYPTED_V2]);
  });

  it('the established session immediately carries a sealed frame end to end', () => {
    const { clientSession, serverSession } = handshake(pair());
    const cmb = {
      categories: { focus: { text: 'post-handshake', meta: { key: 'k', parents: [] } } },
      metadata: {
        key: 'cmb-' + '0'.repeat(64), addressScheme: 'mmp-cmb-merkle-v2', signatureSuite: 'mmp-sig-v2.0',
        assertionId: 'asrt-' + '0'.repeat(64), createdByNodeId: '018f47a0-7b21-7abc-8def-111111111111',
        createdBy: 'a', createdTimestamp: 1, room: 'conformance-room', to: null, lineage: null,
        application: null, sigAlg: 'ed25519', sig: 'x',
      },
    };
    const s = clientSession.nextSend();
    const frame = buildEncryptedFrame({ cmb, sessionId: clientSession.sessionId, direction: s.direction, sequence: s.sequence, trafficKey: s.trafficKey });
    const r = serverSession.acceptRecv(frame.sequence, frame.direction);
    const out = openEncryptedFrame({ frame, trafficKey: r.trafficKey });
    assert.deepStrictEqual(out.cmb.categories, cmb.categories);
  });

  it('aborts on a forged server proof (impersonation, P0.3)', () => {
    const { C, S } = pair();
    const { frame: ch } = clientHello(C);
    const sa = serverAccept({ clientHelloFrame: ch, self: S, agree: agreeWith(S) });
    const forged = { ...sa.frame, proof: crypto.randomBytes(64).toString('base64url') };
    assert.throws(() => clientFinish({ serverHelloFrame: forged, clientHelloFrame: ch, self: C, agree: agreeWith(C) }),
      /proof did not verify/);
  });

  it('aborts on X25519 key substitution (a relay swaps the E2E key)', () => {
    const { C, S } = pair();
    const attacker = party('mitm', '018f47a0-7b21-7abc-8def-333333333333', EXTS);
    const { frame: ch } = clientHello(C);
    const sa = serverAccept({ clientHelloFrame: ch, self: S, agree: agreeWith(S) });
    // Substitute the server's E2E key; the proof no longer covers this transcript.
    const swapped = { ...sa.frame, e2ePublicKey: attacker.e2ePublicKey };
    assert.throws(() => clientFinish({ serverHelloFrame: swapped, clientHelloFrame: ch, self: C, agree: agreeWith(C) }),
      /proof did not verify/);
  });

  it('aborts when the server strips cmb-encrypted-v2 from the selection (downgrade)', () => {
    const { C, S } = pair();
    const { frame: ch } = clientHello(C);
    const sa = serverAccept({ clientHelloFrame: ch, self: S, agree: agreeWith(S) });
    const stripped = { ...sa.frame, selectedExtensions: sa.frame.selectedExtensions.filter((e) => e !== EXT_CMB_ENCRYPTED_V2) };
    assert.throws(() => clientFinish({ serverHelloFrame: stripped, clientHelloFrame: ch, self: C, agree: agreeWith(C) }),
      /downgrade/);
  });

  it('aborts when the server does not echo our nonce (replayed server-hello)', () => {
    const { C, S } = pair();
    const { frame: ch } = clientHello(C);
    const sa = serverAccept({ clientHelloFrame: ch, self: S, agree: agreeWith(S) });
    const replayed = { ...sa.frame, clientNonce: crypto.randomBytes(32).toString('base64url') };
    assert.throws(() => clientFinish({ serverHelloFrame: replayed, clientHelloFrame: ch, self: C, agree: agreeWith(C) }),
      /did not echo our nonce/);
  });

  it('server aborts on a client-finish with a divergent transcript hash', () => {
    const { C, S } = pair();
    const { frame: ch } = clientHello(C);
    const sa = serverAccept({ clientHelloFrame: ch, self: S, agree: agreeWith(S) });
    const cf = clientFinish({ serverHelloFrame: sa.frame, clientHelloFrame: ch, self: C, agree: agreeWith(C) });
    const bad = { ...cf.frame, transcriptHash: '0'.repeat(64) };
    assert.throws(() => serverConfirm({
      clientFinishFrame: bad, transcript: sa.transcript, session: sa.session,
      clientIdentityPublicKey: ch.identityPublicKey, sharedSecret: agreeWith(S)(ch.e2ePublicKey),
    }), /transcript hash mismatch/);
  });

  it('server aborts on a forged client proof', () => {
    const { C, S } = pair();
    const { frame: ch } = clientHello(C);
    const sa = serverAccept({ clientHelloFrame: ch, self: S, agree: agreeWith(S) });
    const cf = clientFinish({ serverHelloFrame: sa.frame, clientHelloFrame: ch, self: C, agree: agreeWith(C) });
    const bad = { ...cf.frame, proof: crypto.randomBytes(64).toString('base64url') };
    assert.throws(() => serverConfirm({
      clientFinishFrame: bad, transcript: sa.transcript, session: sa.session,
      clientIdentityPublicKey: ch.identityPublicKey, sharedSecret: agreeWith(S)(ch.e2ePublicKey),
    }), /proof did not verify/);
  });

  it('a peer without cmb-encrypted-v2 negotiates no v2 (legacy posture decided upstream)', () => {
    const { clientFinishResult } = handshake(pair(EXTS, ['admission-attestation-v1']));
    assert.deepStrictEqual(clientFinishResult.selected, []);
  });
});
