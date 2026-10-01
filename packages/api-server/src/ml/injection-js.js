'use strict';

/**
 * injection-js.js — in-process JS inference for the trained prompt-injection
 * classifier. Same JSON weights (src/ml/injection-classifier.json), same math
 * as injection_classifier.py: sigmoid(coef · normalize(embed(text)) + intercept).
 *
 * Embeddings come from the ONNX export of the identical model
 * (Xenova/all-MiniLM-L6-v2, fp32 — a faithful conversion of
 * sentence-transformers/all-MiniLM-L6-v2) via @huggingface/transformers, with
 * mean pooling + L2 normalization exactly as sentence-transformers does. No
 * Python, no subprocess — this is what lets the classifier run in the
 * node:alpine production image where the Python bridge never could.
 *
 * Loading is lazy and non-blocking: score() returns null until the model is
 * warm (callers already treat null as "no signal"), and warm() lets the server
 * pay the load cost at boot instead of on the first governed request.
 */

const path = require('path');
const WEIGHTS = require('./injection-classifier.json');

const MODEL_ID = process.env.KASBAH_ML_JS_MODEL || 'Xenova/all-MiniLM-L6-v2';
const CACHE_DIR = process.env.KASBAH_MODEL_DIR
  || path.join(__dirname, '..', '..', 'models');

let _pipe = null;      // ready pipeline
let _loading = null;   // Promise while loading
let _failed = false;   // permanent failure (package or model unavailable)

function _load() {
  if (_pipe) return Promise.resolve(_pipe);
  if (_failed) return Promise.resolve(null);
  if (_loading) return _loading;
  _loading = (async () => {
    try {
      const { pipeline, env } = await import('@huggingface/transformers');
      env.cacheDir = CACHE_DIR;
      const pipe = await pipeline('feature-extraction', MODEL_ID, { dtype: 'fp32' });
      _pipe = pipe;
      return pipe;
    } catch (err) {
      _failed = true;
      _loading = null;
      return null;
    }
  })();
  return _loading;
}

function isReady()     { return !!_pipe; }
function isAvailable() { return !_failed; }

// Resolve true once the model is loaded (or false if it can't be).
async function warm() { return !!(await _load()); }

// Score in [0,1], or null if the model isn't warm yet / can't load.
// Never blocks on model load — kicks it off and returns null instead.
async function score(text) {
  if (!_pipe) { _load(); return null; }
  const out = await _pipe(String(text || ''), { pooling: 'mean', normalize: true });
  const v = out.data; // Float32Array, dim 384
  const c = WEIGHTS.coef;
  if (v.length !== c.length) return null;
  let z = WEIGHTS.intercept;
  for (let i = 0; i < c.length; i++) z += c[i] * v[i];
  return 1 / (1 + Math.exp(-z));
}

// Raw normalized sentence embedding (Float32Array dim 384), or null if the
// model isn't warm. Reused by cross-modal consistency checks and any other
// consumer that needs real semantic similarity.
async function embed(text) {
  if (!_pipe) { _load(); return null; }
  const out = await _pipe(String(text || ''), { pooling: 'mean', normalize: true });
  return out.data;
}

module.exports = { score, embed, warm, isReady, isAvailable, threshold: WEIGHTS.default_threshold, MODEL_ID };
