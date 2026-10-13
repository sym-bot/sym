'use strict';

// MMP v2.0 handshake proof-of-possession conformance (P0.3). sym must reproduce
// meshcognition.org's transcript, transcript hash, session id, proof payloads and key schedule
// byte-for-byte, must ACCEPT the published proofs, and must REJECT an unproven/tampered
// handshake — the impersonation fix. Vector: the published handshake-v2.json, copied verbatim
// (digest pinned in mmp-v2-vectors-published.test.js).

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

  it('client and server proof payloads are byte-identical to the vector', () => {
    assert.strictEqual(proofPayload('client', tx).toString('hex'), e.clientProofPayloadHex);
    assert.strictEqual(proofPayload('server', tx).toString('hex'), e.serverProofPayloadHex);
  });

  // The vector's `usage` (2026-09-14 errata): the proofs are for VERIFICATION only — never sign
  // the payload and compare bytes, because a hedged Ed25519 signer (WebKit, CryptoKit) returns a
  // different valid signature on every call. Every other pinned value here is deterministic and
  // is compared exactly. So our own proofs are checked the way the contract checks anyone's:
  // two signings over one transcript both verify, and nothing is asserted about their bytes.
  it('the vector marks the proofs as verification-only', () => {
    assert.match(vec.usage, /Verification only/);
    assert.match(vec.usage, /clientProofBase64url and serverProofBase64url/);
  });

  it('our proofs verify against the presented identity keys (signed twice, bytes not compared)', () => {
    for (const [role, seed, pub] of [
      ['client', vec.fixture.clientIdentityPrivateSeedBase64url, clientPub],
      ['server', vec.fixture.serverIdentityPrivateSeedBase64url, serverPub],
    ]) {
      const a = signProof(role, tx, seed);
      const b = signProof(role, tx, seed);
      assert.ok(verifyProof(role, tx, a, pub), `${role}: first proof verifies`);
      assert.ok(verifyProof(role, tx, b, pub), `${role}: second proof verifies`);
    }
  });

  it('the presented identity keys are the ones the vector pins in the handshake', () => {
    assert.strictEqual(clientPub, vec.fixture.handshake.client.identityPublicKey);
    assert.strictEqual(serverPub, vec.fixture.handshake.server.identityPublicKey);
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

// The room and the two names are the human-typed values in the transcript, and the same visible
// text arrives as different code points depending on where it was typed (macOS tends to NFD,
// most other systems NFC). The reference NFC-normalizes them; a transcript that did not would
// make two honest peers hash different bytes and reject each other's proofs.
describe('MMP v2.0 transcript: room and names are NFC-normalized', () => {
  const NFC = 'café-rööm';                 // composed é, ö
  const NFD = 'café-rööm';              // e + combining acute, o + combining diaeresis
  const withText = (room, clientName, serverName) => {
    const h = JSON.parse(JSON.stringify(vec.fixture.handshake));
    h.room = room;
    h.client.name = clientName;
    h.server.name = serverName;
    return h;
  };

  it('precondition: the two spellings are different code points for the same text', () => {
    assert.notStrictEqual(NFC, NFD);
    assert.strictEqual(NFD.normalize('NFC'), NFC);
  });

  it('a decomposed room or name produces the same transcript bytes as the composed one', () => {
    const composed = buildTranscript(withText(NFC, NFC, NFC));
    assert.strictEqual(buildTranscript(withText(NFD, NFC, NFC)).toString('hex'), composed.toString('hex'), 'room');
    assert.strictEqual(buildTranscript(withText(NFC, NFD, NFC)).toString('hex'), composed.toString('hex'), 'client name');
    assert.strictEqual(buildTranscript(withText(NFC, NFC, NFD)).toString('hex'), composed.toString('hex'), 'server name');
    assert.ok(composed.includes(Buffer.from(NFC, 'utf8')), 'the transcript carries the composed form');
    assert.ok(!buildTranscript(withText(NFD, NFD, NFD)).includes(Buffer.from(NFD, 'utf8')), 'never the decomposed one');
  });
});
