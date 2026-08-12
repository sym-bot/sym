'use strict';

/**
 * @module @sym-bot/core/context-encoder
 * @description Pluggable context encoder for SVAF per-category evaluation.
 *
 * Default: deterministic n-gram hashing (zero dependencies, instant).
 * Optional: semantic embeddings via @huggingface/transformers (requires install).
 *
 * The encoder quality directly affects SVAF drift accuracy:
 * - N-gram: lexical overlap only. Paraphrases score ~0.3 similarity.
 * - Semantic: meaning-level. Paraphrases score ~0.7 similarity.
 *
 * See MMP v0.2.1 Section 9: SVAF per-category evaluation.
 * See MMP v0.2.1 Section 17.7: Data Quality & Encoding Trade-offs.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

/** Hidden state dimension per vector. */
const DIM = 32;

// ── N-gram Encoder (default, zero-dependency) ────────────

/**
 * FNV-1a 32-bit hash, returned as a signed int32 (range: -2^31..2^31-1).
 *
 * MUST stay byte-identical to sym-core-swift `ContextEncoder.hashString`
 * (Sources/SYMCore/Encoder/ContextEncoder.swift:135). Cross-SDK n-gram
 * embedding parity depends on every node producing the same hash for the
 * same UTF-8 input. Math.imul performs signed 32-bit multiplication, and
 * `| 0` coerces back to int32 — together they mirror Swift's `&*` overflow
 * arithmetic on UInt32 followed by `Int32(bitPattern:)`.
 *
 * @param {string} str - input text
 * @returns {number} signed int32 FNV-1a hash
 */
function hashString(str) {
  let hash = 0x811c9dc5 | 0; // 2166136261 (FNV offset basis) as signed int32
  const bytes = Buffer.from(str, 'utf8');
  for (let i = 0; i < bytes.length; i++) {
    hash = (hash ^ bytes[i]) | 0;
    hash = Math.imul(hash, 16777619); // FNV prime, 32-bit signed mul
  }
  return hash | 0;
}

function encodeNgram(text) {
  if (!text || typeof text !== 'string') {
    return { h1: new Array(DIM).fill(0), h2: new Array(DIM).fill(0) };
  }
  const embDim = DIM * 2;
  const vec = new Float64Array(embDim);
  const normalized = text.toLowerCase().replace(/[^a-z0-9 ]/g, ' ');
  const words = normalized.split(/\s+/).filter(w => w.length > 0);

  for (const word of words) {
    const padded = ` ${word} `;
    for (let i = 0; i < padded.length - 2; i++) {
      const trigram = padded.slice(i, i + 3);
      const hash = hashString(trigram);
      const idx = Math.abs(hash) % embDim;
      vec[idx] += (hash > 0) ? 1 : -1;
    }
  }

  for (let i = 0; i < words.length; i++) {
    const hash = hashString(words[i]);
    const idx = Math.abs(hash) % embDim;
    vec[idx] += (hash > 0) ? 2 : -2;
    if (i < words.length - 1) {
      const bigramHash = hashString(`${words[i]}_${words[i + 1]}`);
      const biIdx = Math.abs(bigramHash) % embDim;
      vec[biIdx] += (bigramHash > 0) ? 1.5 : -1.5;
    }
  }

  let norm = 0;
  for (let i = 0; i < embDim; i++) norm += vec[i] * vec[i];
  norm = Math.sqrt(norm) || 1;

  const h1 = new Array(DIM);
  const h2 = new Array(DIM);
  for (let i = 0; i < DIM; i++) {
    h1[i] = vec[i] / norm;
    h2[i] = vec[DIM + i] / norm;
  }
  return { h1, h2 };
}

// ── Semantic Encoder (optional, via @huggingface/transformers) ─

let _semanticEncoder = null;
let _semanticDim = null;
let _semanticReady = false;
let _semanticFailed = false;

/**
 * Load the semantic encoder. Non-blocking — returns immediately.
 * Call once at startup. encode() uses semantic once loaded.
 */
function loadSemanticEncoder() {
  if (_semanticReady || _semanticFailed) return;
  try {
    const { pipeline } = require('@huggingface/transformers');
    pipeline('feature-extraction', 'Xenova/all-MiniLM-L6-v2').then(pipe => {
      _semanticEncoder = pipe;
      _semanticDim = 192; // 384 / 2
      _semanticReady = true;
      console.log('[encoder] Semantic encoder ready (all-MiniLM-L6-v2)');
    }).catch(err => {
      _semanticFailed = true;
      console.warn(`[encoder] Semantic encoder failed: ${err.message?.slice(0, 60)}`);
    });
  } catch {
    _semanticFailed = true;
  }
}

/**
 * Encode text using semantic embeddings (async).
 * @param {string} text
 * @returns {Promise<{ h1: number[], h2: number[] }>}
 */
async function encodeSemantic(text) {
  if (!_semanticEncoder) return encodeNgram(text);
  const result = await _semanticEncoder(text, { pooling: 'mean', normalize: true });
  const data = Array.from(result.data);
  return {
    h1: data.slice(0, _semanticDim),
    h2: data.slice(_semanticDim),
  };
}

// ── Public API ───────────────────────────────────────────

/**
 * Encode text synchronously. Uses n-gram encoder.
 * Used by createCMB() for key generation and CMB category vectors.
 *
 * @param {string} text
 * @returns {{ h1: number[], h2: number[] }}
 */
function encode(text) {
  return encodeNgram(text);
}

/**
 * Encode text with best available encoder (async).
 * Uses semantic embeddings if loaded, n-gram otherwise.
 * Used by SVAF evaluation for drift computation.
 *
 * @param {string} text
 * @returns {Promise<{ h1: number[], h2: number[] }>}
 */
async function encodeForSVAF(text) {
  if (_semanticReady) return encodeSemantic(text);
  return encodeNgram(text);
}

/**
 * @returns {boolean} true if semantic encoder is available
 */
function isSemanticReady() { return _semanticReady; }

/**
 * MMP §15.8 kernel identity: a short stable token naming the encoder and the
 * comparison dimensionality this node's φ-space judgements are made in.
 * Drifts and tether verdicts are comparable iff kernelId values are equal —
 * never compare across kernels.
 * @returns {string}
 */
function kernelId() {
  return _semanticReady ? `minilm-l6-v2-h${_semanticDim}` : `ngram-h${DIM}`;
}

// Auto-load semantic encoder at import time
loadSemanticEncoder();

module.exports = { encode, encodeForSVAF, isSemanticReady, kernelId, DIM };
