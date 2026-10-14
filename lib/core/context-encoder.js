'use strict';

/**
 * @module sym/core/context-encoder
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

/**
 * Whether the semantic encoder may load in this process: 'eager' (the default) or 'off'. One encoder
 * serves every node in a process, so this is a process setting, not a node's. 'off' is requested by
 * the SYM_SEMANTIC_ENCODER environment variable or by a node built with `semanticEncoder: 'off'`, and
 * once requested it stays: nothing loads the model, the kernel is the n-gram one (kernelId()
 * 'ngram-h32'), and semanticSettled() resolves false without waiting.
 */
const SEMANTIC_MODES = Object.freeze(['eager', 'off']);
let _off = false;

(function readEnvironment() {
  const v = process.env.SYM_SEMANTIC_ENCODER;
  if (v === undefined || v === '') return;
  const mode = String(v).trim().toLowerCase();
  if (mode === 'off') _off = true;
  else if (mode !== 'eager') {
    // Not an error that stops a process: say so, and keep the default, which is today's behaviour.
    console.warn(`[encoder] SYM_SEMANTIC_ENCODER=${JSON.stringify(String(v).slice(0, 20))} is not 'eager' or 'off': ignored, the encoder stays eager`);
  }
})();

/**
 * Apply a node's `semanticEncoder` option to the process. 'off' turns the encoder off for good in this
 * process; 'eager' leaves it as it is (a process that is off stays off).
 * @param {'eager'|'off'} mode
 * @returns {'eager'|'off'} the mode the process is in now
 * @throws {TypeError} code EBADENCODER, for any other value
 */
function configureSemanticEncoder(mode) {
  if (!SEMANTIC_MODES.includes(mode)) {
    const e = new TypeError(`semanticEncoder must be 'eager' or 'off' (got ${JSON.stringify(String(mode).slice(0, 40))})`);
    e.code = 'EBADENCODER';
    throw e;
  }
  if (mode === 'off') _off = true;
  return semanticMode();
}

/** @returns {'eager'|'off'} */
function semanticMode() { return _off ? 'off' : 'eager'; }

let _semanticEncoder = null;
let _semanticDim = null;
let _semanticReady = false;
let _semanticFailed = false;
/** The one load in flight, so a second call cannot start a second pipeline while the first loads. */
let _semanticLoading = null;

/**
 * Load the semantic encoder. Non-blocking — returns immediately. It starts when a node is built or when
 * the kernel is first used (encodeForSVAF, kernelId, semanticSettled), never as a side effect of
 * requiring this module, and not at all when the process is off. encode() uses it once loaded.
 */
function loadSemanticEncoder() {
  if (_off || _semanticReady || _semanticFailed || _semanticLoading) return;
  try {
    const { pipeline } = require('@huggingface/transformers');
    _semanticLoading = pipeline('feature-extraction', 'Xenova/all-MiniLM-L6-v2').then(pipe => {
      _semanticEncoder = pipe;
      _semanticDim = 192; // 384 / 2
      _semanticReady = true;
      console.log('[encoder] Semantic encoder ready (all-MiniLM-L6-v2)');
      return true;
    }).catch(err => {
      _semanticFailed = true;
      console.warn(`[encoder] Semantic encoder failed: ${err.message?.slice(0, 60)}`);
      return false;
    });
  } catch {
    _semanticFailed = true;
  }
}

/**
 * Resolves once the semantic encoder has settled: true when it is ready, false when it failed or
 * cannot be loaded here (the lexical encoder then stays in use). For callers that need the
 * semantic kernel, instead of polling isSemanticReady() against a guessed timeout.
 * @returns {Promise<boolean>}
 */
function semanticSettled() {
  if (_off) return Promise.resolve(false);
  if (_semanticReady) return Promise.resolve(true);
  if (_semanticFailed) return Promise.resolve(false);
  loadSemanticEncoder();
  return _semanticLoading || Promise.resolve(_semanticReady);
}

/**
 * Encode text with a given semantic pipeline (async). The pipeline and its dimensionality are
 * arguments rather than module state so a pinned kernel (svafKernel) encodes with exactly the
 * pipeline it names.
 * @param {Function} pipe - the feature-extraction pipeline.
 * @param {number} dim - the dimensionality of each half.
 * @param {string} text
 * @returns {Promise<{ h1: number[], h2: number[] }>}
 */
async function encodeWith(pipe, dim, text) {
  const result = await pipe(text, { pooling: 'mean', normalize: true });
  const data = Array.from(result.data);
  return {
    h1: data.slice(0, dim),
    h2: data.slice(dim),
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
  return svafKernel().encode(text);
}

/**
 * @returns {boolean} true if semantic encoder is available
 */
function isSemanticReady() { return _semanticReady && !_off; }

/**
 * The kernel SVAF encodes in right now, PINNED: its §15.8 identity and an encoder that keeps using
 * that kernel for as long as the caller holds it.
 *
 * The semantic encoder finishes loading while a node runs, so an evaluation that reads the kernel
 * identity and encodes in separate steps can name one kernel and encode in the other. One value
 * carrying both makes that unrepresentable: whatever `encode` returns was produced by the kernel
 * `id` names, even if the switch lands while the caller is still encoding.
 *
 * @returns {{ id: string, encode: (text: string) => Promise<{ h1: number[], h2: number[] }> }}
 */
function svafKernel() {
  loadSemanticEncoder(); // first use starts the load (a no-op when off, loading or settled)
  if (_semanticReady && !_off) {
    const pipe = _semanticEncoder;
    const dim = _semanticDim;
    return { id: `minilm-l6-v2-h${dim}`, encode: (text) => encodeWith(pipe, dim, svafText(text)) };
  }
  return { id: `ngram-h${DIM}`, encode: async (text) => encodeNgram(svafText(text)) };
}

/**
 * The most of one text the SVAF kernel reads (security review R2-3, 0.14.3): a category may hold
 * 256 KiB, and encoding all of it, for every category of every record a peer sends, let one peer buy
 * CPU without bound. The semantic model reads its first few hundred tokens anyway; the n-gram kernel
 * now reads the first SVAF_TEXT_MAX characters. A text no longer than this encodes as before.
 */
const { cutText } = require('./text');
const SVAF_TEXT_MAX = 16 * 1024;
function svafText(text) {
  // Cut on a code point boundary (review M2): the kernel never reads half a surrogate pair.
  return cutText(text, SVAF_TEXT_MAX);
}

/**
 * MMP §15.8 kernel identity: a short stable token naming the encoder and the
 * comparison dimensionality this node's φ-space judgements are made in.
 * Drifts and tether verdicts are comparable iff kernelId values are equal —
 * never compare across kernels.
 * @returns {string}
 */
function kernelId() {
  return svafKernel().id;
}

module.exports = { encode, encodeForSVAF, isSemanticReady, semanticSettled, kernelId, svafKernel, DIM, loadSemanticEncoder, configureSemanticEncoder, semanticMode, SVAF_TEXT_MAX };
