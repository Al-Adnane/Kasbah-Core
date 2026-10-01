'use strict';

/**
 * Shamir secret sharing over GF(P), P = 2^127 − 1 (Mersenne prime).
 *
 *  MATH
 *   • Mersenne reduction: 2^127 ≡ 1 (mod P). mulmod folds with shifts/masks,
 *     no BigInt `%` in the hot path.
 *   • Lagrange basis at 0 is computed once per reconstruction (O(k) inversions
 *     total) and reused across every chunk.
 *   • Unbiased field sampling by rejection (no `randomBytes % P` skew).
 *
 *  FORMAT
 *   • Versioned shares (`v:2`); v2 x is always `0x`-prefixed hex. The v1
 *     decimal heuristic is only used for legacy shares.
 *   • Exact `len` metadata + per-chunk width padding ⇒ binary-safe: leading
 *     0x00 bytes at chunk boundaries survive (bug #7).
 *   • Optional SHA-256 `commit` for integrity on reconstruct (not a MAC).
 *
 *  SAFETY
 *   • Duplicate x rejected (old code: modInv(0)=0 ⇒ silent wrong secret).
 *   • x / y range-checked; inconsistent chunk counts rejected.
 */

const crypto = require('crypto');

const P = (1n << 127n) - 1n;   // 2^127 − 1, Mersenne prime
const CHUNK_BYTES = 15;        // 120 bits < 127 bits ⇒ every chunk < P
const FORMAT_V = 2;

/* ─────────────────────────── field arithmetic ─────────────────────────── */

function mod(a) { a %= P; return a < 0n ? a + P : a; }

function addmod(a, b) { const s = a + b; return s >= P ? s - P : s; }

function submod(a, b) { const d = a - b; return d < 0n ? d + P : d; }

/** (a·b) mod P for a,b ∈ [0,P).  a·b < 2^254; two folds of 2^127 ≡ 1. */
function mulmod(a, b) {
  let t = a * b;
  t = (t & P) + (t >> 127n);   // < 2^128
  t = (t & P) + (t >> 127n);   // < P + 3
  return t >= P ? t - P : t;
}

function powmod(a, e) {
  let r = 1n; a = mod(a);
  while (e > 0n) {
    if (e & 1n) r = mulmod(r, a);
    a = mulmod(a, a);
    e >>= 1n;
  }
  return r;
}

/** Fermat inverse — cheap here because mulmod has no division. */
function modInv(a) {
  a = mod(a);
  if (a === 0n) throw new Error('modInv(0): duplicate or zero x');
  return powmod(a, P - 2n);
}

/* ── Constant-time Shamir shim ──────────────────────────────────────────────
 *
 * JavaScript BigInt arithmetic is NOT constant-time in V8. The Lagrange
 * interpolation below will leak timing information to a co-scheduled
 * adversary. The real fix is a native node-gyp addon or a Rust→Wasm module
 * (e.g. vsss-rs compiled to Wasm) that performs the field operations in
 * constant time.
 *
 * This shim provides the correct integration point:
 *   1. If a native binding is registered via registerNativeShamir(), it is
 *      used for all reconstruction operations.
 *   2. Otherwise, the best-effort JS path is used and a flag is set so
 *      callers can check hasNativeConstantTimeShamir().
 *
 * SECURITY.md must state: "Vault Shamir reconstruction is not constant-time
 * when hasNativeConstantTimeShamir() returns false. Threat model excludes
 * co-scheduled timing adversaries in that configuration."
 */
let _nativeShamir = null;

/**
 * Register a constant-time native binding. Call once at startup from main.js.
 * binding must expose lagrangeAtZero(xs: bigint[], ys: bigint[], P: bigint): bigint
 */
function registerNativeShamir(binding) {
  if (typeof binding.lagrangeAtZero !== 'function') {
    throw new Error('native binding must expose lagrangeAtZero(xs, ys, P)');
  }
  _nativeShamir = binding;
}

/** Returns true if a constant-time native binding is active. */
function hasNativeConstantTimeShamir() { return _nativeShamir !== null; }

/** Uniform in [0, P) by rejection — no modulo bias. */
function randField() {
  for (;;) {
    const v = BigInt('0x' + crypto.randomBytes(16).toString('hex'));
    if (v < P) return v;
  }
}
function randX() { let x; do { x = randField(); } while (x === 0n); return x; }

/* ─────────────────────── Lagrange basis (batch) ───────────────────────── */

/**
 * λ_i with f(0) = Σ λ_i·f(x_i) for every deg f < k.
 * Computed once, applied to every chunk.
 */
function lagrangeAtZero(xs) {
  const k = xs.length;
  const lambdas = new Array(k);
  for (let i = 0; i < k; i++) {
    let num = 1n, den = 1n;
    for (let j = 0; j < k; j++) {
      if (j === i) continue;
      num = mulmod(num, submod(0n, xs[j]));      // (0 − x_j)
      den = mulmod(den, submod(xs[i], xs[j]));
    }
    lambdas[i] = mulmod(num, modInv(den));
  }
  return lambdas;
}

/* ─────────────────────────── share encoding ───────────────────────────── */

const encodeX = (x, v) => (v >= 2 ? '0x' + x.toString(16) : x.toString(16));

function parseX(s, v) {
  const t = String(s);
  if (v >= 2) return BigInt(t.startsWith('0x') ? t : '0x' + t);
  // legacy v1: ambiguous heuristic, kept only for old shares
  return /^[0-9]+$/.test(t) ? BigInt(t) : BigInt('0x' + t);
}

/** Constant-time hex equality — avoid commit timing oracle. */
function ctHexEqual(a, b) {
  try {
    const ab = Buffer.from(String(a), 'hex');
    const bb = Buffer.from(String(b), 'hex');
    if (!ab.length || ab.length !== bb.length) return false;
    return crypto.timingSafeEqual(ab, bb);
  } catch { return false; }
}

/* ──────────────────────────────── split ───────────────────────────────── */

function _splitBytes(buf, n = 5, k = 3, opts = {}) {
  if (!Number.isInteger(n) || !Number.isInteger(k) || k < 2 || n < k || n > 200)
    throw new Error('need integers 2 ≤ k ≤ n ≤ 200');

  const chunks = [];
  for (let i = 0; i < buf.length; i += CHUNK_BYTES)
    chunks.push(buf.subarray(i, i + CHUNK_BYTES));
  if (chunks.length === 0) chunks.push(Buffer.alloc(0));

  const xs = [], seen = new Set();
  while (xs.length < n) {
    const x = randX();
    if (seen.has(x)) continue;
    seen.add(x); xs.push(x);
  }

  const nChunks = chunks.length;
  const shareYs = Array.from({ length: n }, () => new Array(nChunks));
  const coeffs = new Array(k);

  for (let c = 0; c < nChunks; c++) {
    const chunk = chunks[c];
    const secret = chunk.length ? BigInt('0x' + chunk.toString('hex')) : 0n;
    if (secret >= P) throw new Error('chunk value ≥ P');

    coeffs[0] = secret;
    for (let i = 1; i < k; i++) coeffs[i] = randField();

    for (let i = 0; i < n; i++) {
      let y = 0n; const xi = xs[i];
      for (let d = k - 1; d >= 0; d--) y = addmod(mulmod(y, xi), coeffs[d]);
      shareYs[i][c] = y.toString(16);
    }
  }

  const commit = opts.commit
    ? crypto.createHash('sha256').update(buf).digest('hex')
    : undefined;

  return shareYs.map((ys, i) => {
    const s = {
      v: FORMAT_V,
      x: encodeX(xs[i], FORMAT_V),
      y: ys.join(','),
      threshold: k, total: n, chunks: nChunks, len: buf.length,
    };
    if (commit) s.commit = commit;
    return s;
  });
}

/* ─────────────────────────────── combine ──────────────────────────────── */

function _combineRaw(shareObjs, { stripLegacyNul }) {
  if (!Array.isArray(shareObjs) || shareObjs.length === 0)
    throw new Error('no shares supplied');

  const first = shareObjs[0];
  // Cross-share metadata consistency (do not trust only `first`).
  for (const s of shareObjs) {
    if (!s || s.x === undefined || s.y === undefined)
      throw new Error('malformed share');
    if (s.threshold != null && first.threshold != null && Number(s.threshold) !== Number(first.threshold))
      throw new Error('inconsistent threshold across shares');
    if (s.total != null && first.total != null && Number(s.total) !== Number(first.total))
      throw new Error('inconsistent total across shares');
    if (Boolean(s.binary) !== Boolean(first.binary))
      throw new Error('inconsistent binary flag across shares');
    if (s.commit !== first.commit)
      throw new Error('inconsistent commit across shares');
    if (s.len != null && first.len != null && Number(s.len) !== Number(first.len))
      throw new Error('inconsistent len across shares');
  }
  const k = Number(first?.threshold) || shareObjs.length;
  if (shareObjs.length < k)
    throw new Error(`need ${k} shares, got ${shareObjs.length}`);

  const use = shareObjs.slice(0, k).map((s) => {
    const v = Number(s.v) || 1;
    return { x: parseX(s.x, v), parts: String(s.y).split(',') };
  });

  const seen = new Set();
  for (const u of use) {
    if (u.x <= 0n || u.x >= P) throw new Error('x out of range');
    if (seen.has(u.x)) throw new Error('duplicate x-values among shares');
    seen.add(u.x);
  }

  const nChunks = use[0].parts.length;
  for (const u of use)
    if (u.parts.length !== nChunks) throw new Error('inconsistent chunk count');

  // Route through native CT binding if registered; fall back to JS (not CT).
  const xs = use.map((u) => u.x);
  let lambdas;
  if (_nativeShamir) {
    // Native path: compute one f(0) per chunk via the binding
    // (lambda pre-computation not possible externally; native computes directly)
    lambdas = null; // handled per-chunk below
  } else {
    lambdas = lagrangeAtZero(xs);
  }

  const useLen = Number.isInteger(first.len);
  const out = new Array(nChunks);

  for (let c = 0; c < nChunks; c++) {
    let secret;
    if (_nativeShamir) {
      const ys = use.map((u) => {
        const raw = u.parts[c];
        const yi = BigInt('0x' + (raw === '' ? '0' : raw));
        if (yi >= P) throw new Error('y out of range');
        return yi;
      });
      secret = _nativeShamir.lagrangeAtZero(xs, ys, P);
    } else {
      secret = 0n;
      for (let i = 0; i < k; i++) {
        const raw = use[i].parts[c];
        const yi = BigInt('0x' + (raw === '' ? '0' : raw));
        if (yi >= P) throw new Error('y out of range');
        secret = addmod(secret, mulmod(lambdas[i], yi));
      }
    }
    let hex = secret.toString(16);
    if (useLen) {
      // pad to the chunk's ORIGINAL width so leading 0x00 bytes survive
      const chunkBytes = Math.min(CHUNK_BYTES, first.len - c * CHUNK_BYTES);
      hex = chunkBytes === 0 ? '' : hex.padStart(2 * chunkBytes, '0');
    } else if (hex.length & 1) {
      hex = '0' + hex;
    }
    out[c] = hex.length ? Buffer.from(hex, 'hex') : Buffer.alloc(0);
  }

  let buf = Buffer.concat(out);
  // Zero the per-chunk intermediate buffers now that they're concatenated
  for (const c of out) c.fill(0);

  if (useLen) {
    if (first.len > buf.length) throw new Error('len metadata exceeds data');
    buf = buf.subarray(0, first.len);
  } else if (stripLegacyNul) {
    let end = buf.length;
    while (end > 0 && buf[end - 1] === 0) end--;
    buf = buf.subarray(0, end);
  }

  if (first.commit) {
    const h = crypto.createHash('sha256').update(buf).digest('hex');
    if (!ctHexEqual(h, first.commit)) {
      buf.fill(0); // zero before throwing so secret doesn't linger
      throw new Error('integrity check failed');
    }
  }
  return buf;
  // Note: callers are responsible for zeroing buf after use when possible.
  // BigInt intermediates (lambdas, yi) are not zeroable from JS — documented limitation.
}

/* ─────────────────────────────── public API ───────────────────────────── */

function split(secret, n, k, opts) {
  const isBuf = Buffer.isBuffer(secret);
  const raw = isBuf ? secret : Buffer.from(String(secret), 'utf8');
  const shares = _splitBytes(raw, n, k, opts);
  for (const s of shares) s.binary = isBuf;
  return shares;
}

function splitString(str, n, k, opts) {
  return _splitBytes(Buffer.from(String(str), 'utf8'), n, k, opts);
}

function combine(shares) {
  const bin = Boolean(shares[0]?.binary);
  return _combineRaw(shares, { stripLegacyNul: !bin });
}

function combineToString(shares) {
  return _combineRaw(shares, { stripLegacyNul: true }).toString('utf8');
}

module.exports = {
  split, combine, splitString, combineToString,
  P, CHUNK_BYTES, FORMAT_V,
  registerNativeShamir, hasNativeConstantTimeShamir, ctHexEqual };
