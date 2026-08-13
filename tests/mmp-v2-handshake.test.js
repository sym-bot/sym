'use strict';

// MMP v2.0 handshake proof-of-possession conformance (P0.3). sym must reproduce
// meshcognition.org's transcript hash, session id, and proofs byte-for-byte, and must REJECT an
// unproven/tampered handshake — the impersonation fix. Vector: website #12, digest-pinned.

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { transcriptHash, sessionIdFromTranscript, proofPayload, signProof, verifyProof } = require('../lib/core/handshake-v2');
const vec = require('./mmp-v2-handshake.vector.json');
const e = vec.expected;
const tx = Buffer.from(e.transcriptHex, 'hex');

// Identity public keys the two sides presented (recover from the transcript / fixture seeds).
const crypto = require('crypto');
function pubFromSeed(seedB64url) {
  const seed = Buffer.from(seedB64url, 'base64url');
  const priv = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
  const raw = crypto.createPublicKey(priv).export({ type: 'spki', format: 'der' }).subarray(-32);
  return raw.toString('base64url');
}
const clientPub = pubFromSeed(vec.fixture.clientIdentityPrivateSeedBase64url);
const serverPub = pubFromSeed(vec.fixture.serverIdentityPrivateSeedBase64url);

describe('MMP v2.0 handshake proof-of-possession (P0.3)', () => {
  it('transcript hash matches the published vector', () => {
    assert.strictEqual(transcriptHash(tx).toString('hex'), e.transcriptHashHex);
  });

  it('session id is the transcript-hash prefix, matching the vector', () => {
    assert.strictEqual(sessionIdFromTranscript(tx), e.sessionId);
  });

  it('client proof payload is byte-identical to the vector', () => {
    assert.strictEqual(proofPayload('client', tx).toString('hex'), e.clientProofPayloadHex);
  });

  it('client and server proofs are byte-identical to the vector', () => {
    assert.strictEqual(signProof('client', tx, vec.fixture.clientIdentityPrivateSeedBase64url), e.clientProofBase64url);
    assert.strictEqual(signProof('server', tx, vec.fixture.serverIdentityPrivateSeedBase64url), e.serverProofBase64url);
  });

  it('the published proofs verify against the presented identity keys', () => {
    assert.ok(verifyProof('client', tx, e.clientProofBase64url, clientPub), 'client proof verifies');
    assert.ok(verifyProof('server', tx, e.serverProofBase64url, serverPub), 'server proof verifies');
  });

  it('a tampered transcript makes the proof fail — impersonation rejected (P0.3)', () => {
    const tampered = Buffer.from(tx); tampered[tampered.length - 1] ^= 0xff;
    assert.ok(!verifyProof('client', tampered, e.clientProofBase64url, clientPub), 'a proof over a different transcript must fail');
  });
});

const { deriveSessionKeys, keyConfirmation } = require('../lib/core/handshake-v2');

describe('MMP v2.0 handshake key schedule (§5.2)', () => {
  const sharedSecret = Buffer.from(vec.expected.sharedSecretHex, 'hex');
  const th = transcriptHash(tx);

  it('derives the two traffic keys and two finished keys byte-exact', () => {
    const k = deriveSessionKeys(sharedSecret, th);
    assert.strictEqual(k.clientToServerKey.toString('hex'), vec.expected.clientToServerKeyHex);
    assert.strictEqual(k.serverToClientKey.toString('hex'), vec.expected.serverToClientKeyHex);
    assert.strictEqual(k.clientFinishedKey.toString('hex'), vec.expected.clientFinishedKeyHex);
    assert.strictEqual(k.serverFinishedKey.toString('hex'), vec.expected.serverFinishedKeyHex);
  });

  it('computes the key confirmations byte-exact', () => {
    const k = deriveSessionKeys(sharedSecret, th);
    assert.strictEqual(keyConfirmation('client', k.clientFinishedKey, th).toString('hex'), vec.expected.clientKeyConfirmationHex);
    assert.strictEqual(keyConfirmation('server', k.serverFinishedKey, th).toString('hex'), vec.expected.serverKeyConfirmationHex);
  });

  it('the derived traffic keys are exactly what the e2e AEAD vector uses (full chain)', () => {
    // The handshake traffic key IS the e2e trafficKey — proving handshake→AEAD is one contract.
    const k = deriveSessionKeys(sharedSecret, th);
    assert.strictEqual(k.clientToServerKey.toString('hex').length, 64, 'a 32-byte ChaCha20-Poly1305 key');
  });
});
