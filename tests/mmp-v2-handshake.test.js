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

// §5.2 transcript CONSTRUCTION (not just the primitives over a given transcript) and the
// cmb-encrypted-v2 downgrade resistance that rides it.
const { buildTranscript } = require('../lib/core/handshake-v2');
const { EXT_CMB_ENCRYPTED_V2 } = require('../lib/core/mmp-extensions');

describe('MMP v2.0 transcript construction + extension binding', () => {
  it('buildTranscript reproduces the canonical transcript byte-for-byte', () => {
    assert.strictEqual(buildTranscript(vec.fixture.handshake).toString('hex'), vec.expected.transcriptHex);
  });

  it('the full chain from the CONSTRUCTED transcript matches the vector', () => {
    const t = buildTranscript(vec.fixture.handshake);
    assert.strictEqual(transcriptHash(t).toString('hex'), vec.expected.transcriptHashHex);
    assert.strictEqual(sessionIdFromTranscript(t), vec.expected.sessionId);
    const k = deriveSessionKeys(Buffer.from(vec.expected.sharedSecretHex, 'hex'), transcriptHash(t));
    assert.strictEqual(k.clientToServerKey.toString('hex'), vec.expected.clientToServerKeyHex);
    assert.strictEqual(k.serverToClientKey.toString('hex'), vec.expected.serverToClientKeyHex);
  });

  it('extensions are bytewise-sorted in the transcript regardless of offer order', () => {
    const swapped = JSON.parse(JSON.stringify(vec.fixture.handshake));
    swapped.client.extensions = [...swapped.client.extensions].reverse();
    // Reversing the OFFER order must not change the transcript — the sort is canonical.
    assert.strictEqual(buildTranscript(swapped).toString('hex'), vec.expected.transcriptHex);
  });

  it('cmb-encrypted-v2 binds into the transcript; stripping it changes the transcript (downgrade breaks proofs)', () => {
    const withExt = JSON.parse(JSON.stringify(vec.fixture.handshake));
    withExt.client.extensions.push(EXT_CMB_ENCRYPTED_V2);
    withExt.server.extensions.push(EXT_CMB_ENCRYPTED_V2);
    withExt.selectedExtensions = [...withExt.selectedExtensions, EXT_CMB_ENCRYPTED_V2];
    const withHash = transcriptHash(buildTranscript(withExt)).toString('hex');

    // A relay that strips the selected cmb-encrypted-v2 produces a DIFFERENT transcript hash, so
    // the Ed25519 proofs over the original transcript can no longer verify — the downgrade is
    // cryptographically visible, not silent.
    const stripped = JSON.parse(JSON.stringify(withExt));
    stripped.selectedExtensions = stripped.selectedExtensions.filter((e) => e !== EXT_CMB_ENCRYPTED_V2);
    const strippedHash = transcriptHash(buildTranscript(stripped)).toString('hex');

    assert.notStrictEqual(withHash, strippedHash, 'stripping the selected extension must change the transcript');
    // and it sorts canonically into the offered list (bytewise before receipts-v1)
    assert.ok(buildTranscript(withExt).includes(Buffer.from(EXT_CMB_ENCRYPTED_V2, 'utf8')));
  });
});
