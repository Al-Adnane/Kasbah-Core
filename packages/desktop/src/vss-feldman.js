'use strict';

/**
 * Feldman VSS over secp256k1 — ported from packages/desktop/src/crypto-ref/vss.ts.
 * Shareholders verify their share against dealer commitments BEFORE combine.
 *
 * Honest scope: Feldman, not Pedersen (computational privacy of C0). Not proactive.
 */

let secp;
(function load() {
  const candidates = [
    '@noble/curves/secp256k1.js',
    require('path').join(__dirname, '..', '..', '..', '..', 'node_modules', '@noble/curves', 'secp256k1.js'),
    require('path').join(process.resourcesPath || '', 'app', 'node_modules', '@noble/curves', 'secp256k1.js'),
    '/Users/mac/Desktop/KasbahFinal/node_modules/@noble/curves/secp256k1.js',
  ];
  for (const c of candidates) {
    try { secp = require(c).secp256k1; if (secp) return; } catch (_) {}
  }
  secp = null;
})();

const INF = '00';
const CHUNK = 31;

function available() { return !!secp; }

function G() { return secp.Point.BASE; }
function ZERO() { return secp.Point.ZERO; }
function Q() { return secp.Point.CURVE().n; }

function modQ(a) { const q = Q(); a %= q; return a < 0n ? a + q : a; }

function commitToHex(a) {
  if (a === 0n) return INF;
  return G().multiply(a).toHex(true);
}

function parsePoint(hex) {
  if (!hex || hex === INF) return ZERO();
  return secp.Point.fromHex(hex);
}

function split(secret, n, k) {
  if (!secp) throw new Error('@noble/curves secp256k1 not found');
  if (!Buffer.isBuffer(secret)) secret = Buffer.from(String(secret), 'utf8');
  const q = Q();
  const chunks = [];
  for (let i = 0; i < secret.length; i += CHUNK) chunks.push(secret.subarray(i, i + CHUNK));
  if (!chunks.length) chunks.push(Buffer.alloc(0));

  const xs = [];
  const seen = new Set();
  while (xs.length < n) {
    let x;
    do { x = modQ(BigInt('0x' + require('crypto').randomBytes(32).toString('hex'))); } while (x === 0n || seen.has(x));
    seen.add(x); xs.push(x);
  }

  const commitments = chunks.map(() => []);
  const shareYs = Array.from({ length: n }, () => []);

  for (let c = 0; c < chunks.length; c++) {
    const chunk = chunks[c];
    const s0 = chunk.length ? BigInt('0x' + chunk.toString('hex')) : 0n;
    if (s0 >= q) throw new Error('chunk ≥ q');
    const coeffs = [s0];
    for (let i = 1; i < k; i++) {
      coeffs.push(modQ(BigInt('0x' + require('crypto').randomBytes(32).toString('hex'))));
    }
    commitments[c] = coeffs.map((a) => commitToHex(a));
    for (let i = 0; i < n; i++) {
      let y = 0n;
      const xi = xs[i];
      for (let d = k - 1; d >= 0; d--) y = modQ(y * xi + coeffs[d]);
      shareYs[i][c] = y.toString(16);
    }
  }

  return {
    version: 3,
    threshold: k,
    total: n,
    chunks: chunks.length,
    len: secret.length,
    commitments,
    shares: shareYs.map((ys, i) => ({
      v: 3,
      x: '0x' + xs[i].toString(16),
      y: ys.join(','),
      threshold: k,
      total: n,
      chunks: chunks.length,
      len: secret.length,
    })),
  };
}

/** Verify one share against Feldman commitments. */
function verifyShare(share, commitment) {
  if (!secp) return { ok: false, error: 'secp256k1 unavailable' };
  try {
    const q = Q();
    const x = BigInt(String(share.x).startsWith('0x') ? share.x : '0x' + share.x);
    const parts = String(share.y).split(',');
    const C = commitment.commitments || commitment;
    if (!Array.isArray(C) || C.length !== parts.length) return { ok: false, error: 'commitment/chunk mismatch' };
    for (let c = 0; c < parts.length; c++) {
      const y = BigInt('0x' + (parts[c] || '0'));
      const lhs = y === 0n ? ZERO() : G().multiply(modQ(y));
      // Horner in group: Σ x^i * C_i
      let acc = ZERO();
      const coeffs = C[c];
      for (let d = coeffs.length - 1; d >= 0; d--) {
        acc = acc.add(parsePoint(coeffs[d]));
        if (d > 0) acc = acc.multiply(modQ(x));
      }
      if (!lhs.equals(acc)) return { ok: false, error: `chunk ${c} fails Feldman check` };
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

function combine(result) {
  if (!secp) throw new Error('secp256k1 unavailable');
  const { shares, commitments, len, threshold: k } = result;
  const use = shares.slice(0, k).map((s) => ({
    x: BigInt(String(s.x).startsWith('0x') ? s.x : '0x' + s.x),
    parts: String(s.y).split(','),
  }));
  for (const u of use) {
    const v = verifyShare({ x: '0x' + u.x.toString(16), y: u.parts.join(',') }, { commitments });
    if (!v.ok) throw new Error(v.error || 'share verify failed');
  }
  // Lagrange at 0
  const xs = use.map((u) => u.x);
  const lambdas = xs.map((xi, i) => {
    let num = 1n, den = 1n;
    for (let j = 0; j < xs.length; j++) {
      if (j === i) continue;
      num = modQ(num * modQ(-xs[j]));
      den = modQ(den * modQ(xi - xs[j]));
    }
    // Fermat inverse
    let inv = 1n, e = Q() - 2n, b = den;
    while (e > 0n) { if (e & 1n) inv = modQ(inv * b); b = modQ(b * b); e >>= 1n; }
    return modQ(num * inv);
  });
  const nChunks = use[0].parts.length;
  const out = [];
  for (let c = 0; c < nChunks; c++) {
    let secret = 0n;
    for (let i = 0; i < k; i++) {
      const yi = BigInt('0x' + (use[i].parts[c] || '0'));
      secret = modQ(secret + modQ(lambdas[i] * yi));
    }
    let hex = secret.toString(16);
    const chunkBytes = Math.min(CHUNK, len - c * CHUNK);
    hex = chunkBytes <= 0 ? '' : hex.padStart(2 * chunkBytes, '0');
    out.push(hex.length ? Buffer.from(hex, 'hex') : Buffer.alloc(0));
  }
  let buf = Buffer.concat(out).subarray(0, len);
  // post-hoc: [chunk0]G == C0
  if (commitments[0] && commitments[0][0] && commitments[0][0] !== INF) {
    const s0 = out[0].length ? BigInt('0x' + out[0].toString('hex')) : 0n;
    const check = s0 === 0n ? INF : G().multiply(modQ(s0)).toHex(true);
    if (check !== commitments[0][0]) throw new Error('post-combine C0 mismatch');
  }
  return buf;
}

function selfTest() {
  if (!secp) return { ok: false, error: 'secp256k1 unavailable' };
  const cases = [];
  const secret = Buffer.from('launch-code-7357');
  const r = split(secret, 5, 3);
  for (const sh of r.shares) {
    const v = verifyShare(sh, r);
    if (!v.ok) throw new Error(v.error);
  }
  cases.push('all shares verify');
  const rec = combine(r);
  if (!rec.equals(secret)) throw new Error('roundtrip');
  cases.push('roundtrip');
  const bad = JSON.parse(JSON.stringify(r.shares[0]));
  const parts = bad.y.split(',');
  parts[0] = (BigInt('0x' + parts[0]) + 1n).toString(16);
  bad.y = parts.join(',');
  if (verifyShare(bad, r).ok) throw new Error('tampered share accepted');
  cases.push('tampered share rejected');
  return { ok: true, passed: cases.length, cases };
}

module.exports = { available, split, verifyShare, combine, selfTest, CHUNK, INF };
