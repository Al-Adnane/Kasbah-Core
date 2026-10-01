'use strict';

/**
 * ml-injection.js — warm bridge to the trained prompt-injection classifier
 * (packages/api-server/src/ml/injection_classifier.py).
 *
 * Opt-in: only active when KASBAH_ML_INJECTION is "1"/"true". When off, or when
 * Python / sentence-transformers is unavailable, or on any error/timeout,
 * score() resolves to null and the caller treats it as "no signal" — the
 * governance verdict is never blocked or degraded by this being missing.
 *
 * Protocol: the Python side answers exactly one line per request, strictly in
 * order (it is a synchronous serve loop). So we correlate by FIFO: a single
 * persistent stdout reader pops the oldest pending resolver for each line. No
 * per-call readline.once() listeners (which raced and mis-delivered responses
 * in an earlier version, causing intermittent nulls even when warm).
 *
 * Benchmarked: 0.84 accuracy on the public deepset/prompt-injections test split
 * vs 0.49 (chance) for the legacy regex/RTP path. See bench/injection-classifier/.
 */

const { spawn } = require('child_process');
const path = require('path');
const readline = require('readline');

// Engine selection (2026-07-11):
//   default              — pure-JS in-process ONNX engine (src/ml/injection-js.js),
//                          ON by default: it needs no Python and runs in the
//                          node:alpine production image. Warm it at boot via
//                          warm(); until warm, score() returns null (no signal).
//   KASBAH_ML_INJECTION=0/false/off — classifier fully disabled.
//   KASBAH_ML_ENGINE=python (or legacy KASBAH_ML_INJECTION=1) — prefer the
//                          Python bridge below; JS engine is the fallback.
// Both engines share the same JSON weights and produce identical scores
// (validated bit-for-bit + full deepset test-split benchmark parity,
// bench/injection-classifier/benchmark-js.js).
const DISABLED = /^(0|false|no|off)$/i.test(process.env.KASBAH_ML_INJECTION || '');
const PREFER_PYTHON = process.env.KASBAH_ML_ENGINE === 'python'
  || /^(1|true|yes)$/i.test(process.env.KASBAH_ML_INJECTION || '');
const ENABLED = !DISABLED;

const jsEngine = (() => {
  try { return require('./ml/injection-js.js'); }
  catch (_) { return null; }
})();
const SCRIPT = path.join(__dirname, 'ml', 'injection_classifier.py');
const PYTHON = process.env.KASBAH_PYTHON || 'python3';
const CALL_TIMEOUT_MS = Number(process.env.KASBAH_ML_TIMEOUT_MS || 4000);
const START_TIMEOUT_MS = Number(process.env.KASBAH_ML_START_MS || 30000); // torch cold-load + warmup

let _proc = null;
let _ready = false;
let _starting = null;            // Promise<boolean> while starting
let _pending = [];               // FIFO of { resolve } awaiting a response line
let _readyResolve = null;

function _reset() {
  try { if (_proc) _proc.kill(); } catch (_) {}
  // Fail every outstanding request so nothing hangs.
  const p = _pending; _pending = [];
  for (const w of p) { try { w.resolve(null); } catch (_) {} }
  if (_readyResolve) { const r = _readyResolve; _readyResolve = null; try { r(false); } catch (_) {} }
  _proc = null; _ready = false; _starting = null;
}

function _start() {
  if (_ready) return Promise.resolve(true);
  if (_starting) return _starting;

  _starting = new Promise((resolve) => {
    _readyResolve = resolve;
    let started = false;
    try {
      _proc = spawn(PYTHON, [SCRIPT], { stdio: ['pipe', 'pipe', 'pipe'] });
    } catch (_) { _reset(); return resolve(false); }

    const startTimer = setTimeout(() => { if (!started) _reset(); }, START_TIMEOUT_MS);
    _proc.on('error', () => { clearTimeout(startTimer); _reset(); });
    _proc.on('exit', () => { clearTimeout(startTimer); _reset(); });

    const rl = readline.createInterface({ input: _proc.stdout });
    rl.on('line', (line) => {
      let msg = null;
      try { msg = JSON.parse(line); } catch (_) { return; }
      if (!_ready) {
        if (msg && msg.ready) {
          started = true; _ready = true; clearTimeout(startTimer);
          const r = _readyResolve; _readyResolve = null;
          if (r) r(true);
        }
        return;
      }
      // Ready: this is a response to the oldest pending request.
      const w = _pending.shift();
      if (w) w.resolve(msg && typeof msg.score === 'number' ? msg.score : null);
    });
  });
  return _starting;
}

/**
 * Score `text` in [0,1] (probability it is a prompt injection), or null if the
 * classifier is disabled/unavailable/errored/timed out.
 * @returns {Promise<number|null>}
 */
async function _bridgeScore(text) {
  const ok = await _start().catch(() => false);
  if (!ok || !_proc || !_ready) return null;

  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; clearTimeout(timer); resolve(v); } };
    const timer = setTimeout(() => {
      // Drop this waiter and hard-reset: a timeout means the stream is out of
      // sync, so fail outstanding requests rather than mis-deliver later lines.
      _pending = _pending.filter((w) => w !== waiter);
      _reset();
      finish(null);
    }, CALL_TIMEOUT_MS);
    const waiter = { resolve: (v) => finish(v) };
    _pending.push(waiter);
    try {
      _proc.stdin.write(JSON.stringify({ text: String(text).slice(0, 8000) }) + '\n');
    } catch (_) {
      _pending = _pending.filter((w) => w !== waiter);
      _reset(); finish(null);
    }
  });
}

/**
 * Score `text` in [0,1] (probability it is a prompt injection), or null if the
 * classifier is disabled/unavailable/not yet warm/errored/timed out. Never
 * blocks the caller on engine startup: JS-engine loading happens in the
 * background (kick off via warm() at boot), and the Python bridge keeps its
 * own start/call timeouts.
 * @returns {Promise<number|null>}
 */
async function score(text) {
  if (!ENABLED || !text || typeof text !== 'string') return null;
  if (PREFER_PYTHON) {
    const s = await _bridgeScore(text);
    if (typeof s === 'number') return s;
    return jsEngine ? jsEngine.score(String(text).slice(0, 8000)) : null;
  }
  return jsEngine ? jsEngine.score(String(text).slice(0, 8000)) : null;
}

/**
 * Pre-load the active engine so the first governed request doesn't run
 * detector-blind. Resolves true when an engine is ready.
 */
async function warm() {
  if (!ENABLED) return false;
  if (PREFER_PYTHON) {
    const ok = await _start().catch(() => false);
    if (ok) return true;
  }
  return jsEngine ? jsEngine.warm() : false;
}

function isEnabled() { return ENABLED && (!!jsEngine || PREFER_PYTHON); }
function isReady()   { return (jsEngine && jsEngine.isReady()) || _ready; }

module.exports = { score, warm, isEnabled, isReady };
