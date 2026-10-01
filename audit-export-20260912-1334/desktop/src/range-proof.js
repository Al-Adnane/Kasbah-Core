'use strict';

/**
 * range-proof.js — Two-sided Chaum-Pedersen OR-proof range proofs.
 *
 * Proves 0 ≤ v ≤ w over ristretto255 Pedersen commitments, without
 * revealing v. Uses the same G, H generators as zk-protect.js so proofs
 * compose homomorphically.
 *
 * Construction:
 *   Lower bound (v ≥ 0): bit-decompose v into k bits, give each bit a
 *     Pedersen commitment, CDS OR-prove each bit ∈ {0,1}, show weighted
 *     sum equals C.
 *   Upper bound (v ≤ w): commit to slack s = w − v, prove s ≥ 0 the same
 *     way, show C + C_s = h^w (the homomorphic relation that binds both).
 *
 * What a verifier learns: only that 0 ≤ v ≤ w. v is never revealed.
 *
 * Proof size: 2 × k × 5 group elements (not succinct — Bulletproofs would
 * shrink this to O(log k) but require a separate reviewed library).
 */

const crypto = require('crypto');

/* ── load @noble/curves the same way zk-protect.js does ─────────────────── */
let _ristretto255, _ristretto255_hasher;
(function loadNoble() {
  const candidates = [
    '@noble/curves/ed25519.js',
    require('path').join(__dirname, '..', '..', '..', '..', 'node_modules', '@noble/curves', 'ed25519.js'),
    require('path').join(process.resourcesPath || '', 'app', 'node_modules', '@noble/curves', 'ed25519.js'),
  ];
  for (const c of candidates) {
    try {
      const m = require(c);
      _ristretto255 = m.ristretto255;
      _ristretto255_hasher = m.ristretto255_hasher;
      return;
    } catch (_) {}
  }
  throw new Error('@noble/curves not found');
})();

const Point  = _ristretto255.Point;
const ORDER  = Point.Fn.ORDER;
const G      = Point.BASE;
const H      = _ristretto255_hasher.hashToCurve(
  new TextEncoder().encode('KASBAH-ZK-H-GENERATOR-v1'),
  { DST: 'kasbah-pedersen-v1' },
);

const mod = (x) => ((x % ORDER) + ORDER) % ORDER;
const mul = (P, s) => { s = mod(s); return s === 0n ? Point.ZERO : P.multiply(s); };
const ph  = (P) => P.toHex();
const pp  = (hex) => Point.fromHex(hex);

function randScalar() {
  return mod(BigInt('0x' + crypto.randomBytes(64).toString('hex')));
}

function hashToChallenge(...parts) {
  const h = crypto.createHash('sha512');
  for (const p of parts) h.update(typeof p === 'string' ? p : JSON.stringify(p));
  return mod(BigInt('0x' + h.digest('hex')));
}

/* ── CDS OR-proof: C commits to 0 or 1 ─────────────────────────────────── */

/**
 * Prove C = bit·G + r·H with bit ∈ {0,1}.
 * Returns an OR-proof serialisable to JSON (all points as hex, scalars as hex).
 */
function proveBit(C, r, bit) {
  const C0 = C;             // statement if bit==0: C = 0·G + r·H
  const C1 = C.subtract(G); // statement if bit==1: (C−G) = 0·G + r·H

  let A0, A1, c0, c1, s0, s1;

  if (bit === 0n) {
    // Real branch (bit=0): A0 = s0·H, prove Schnorr for C0
    s0 = randScalar();
    A0 = mul(H, s0);
    // Simulated branch (bit=1): pick c1, s1 freely
    c1 = randScalar(); s1 = randScalar();
    A1 = mul(H, s1).subtract(mul(C1, c1));
  } else {
    // Real branch (bit=1): A1 = s1·H, prove Schnorr for C1
    s1 = randScalar();
    A1 = mul(H, s1);
    // Simulated branch (bit=0)
    c0 = randScalar(); s0 = randScalar();
    A0 = mul(H, s0).subtract(mul(C0, c0));
  }

  const cTotal = hashToChallenge('kasbah-zk-bit-v2', ph(C), ph(A0), ph(A1));

  if (bit === 0n) {
    c0 = mod(cTotal - c1);
    s0 = mod(s0 + c0 * r);
  } else {
    c1 = mod(cTotal - c0);
    s1 = mod(s1 + c1 * r);
  }

  return {
    C: ph(C),
    A0: ph(A0), A1: ph(A1),
    c0: c0.toString(16), c1: c1.toString(16),
    s0: s0.toString(16), s1: s1.toString(16),
  };
}

function verifyBit(proof) {
  try {
    const C  = pp(proof.C);
    const A0 = pp(proof.A0), A1 = pp(proof.A1);
    const c0 = BigInt('0x' + proof.c0), c1 = BigInt('0x' + proof.c1);
    const s0 = BigInt('0x' + proof.s0), s1 = BigInt('0x' + proof.s1);
    const cTotal = hashToChallenge('kasbah-zk-bit-v2', proof.C, proof.A0, proof.A1);
    if (mod(c0 + c1) !== cTotal) return false;
    // Branch 0: s0·H == A0 + c0·C
    if (!mul(H, s0).equals(A0.add(mul(C, c0)))) return false;
    // Branch 1: s1·H == A1 + c1·(C − G)
    if (!mul(H, s1).equals(A1.add(mul(C.subtract(G), c1)))) return false;
    return true;
  } catch { return false; }
}

/* ── One-sided range proof: v ∈ [0, 2^k) ───────────────────────────────── */

function proveOneSided(v, blinding, k) {
  const bound = 1n << BigInt(k);
  if (v < 0n || v >= bound) throw new Error(`value must be in [0, 2^${k})`);

  const bitProofs = [];
  let sumRi = 0n;
  for (let i = 0; i < k; i++) {
    const bit = (v >> BigInt(i)) & 1n;
    const ri  = randScalar();
    const Ci  = mul(G, bit).add(mul(H, ri));
    bitProofs.push(proveBit(Ci, ri, bit));
    sumRi = mod(sumRi + (1n << BigInt(i)) * ri);
  }
  const rPrime = mod(blinding - sumRi);
  return { bitProofs, rPrime: rPrime.toString(16), k };
}

function verifyOneSided(Chex, proof) {
  try {
    const C = pp(Chex);
    const { bitProofs, rPrime, k } = proof;
    if (!bitProofs || bitProofs.length !== k) return false;
    for (const bp of bitProofs) {
      if (!verifyBit(bp)) return false;
    }
    // C == g^{rPrime} + sum_i C_i * 2^i
    let rhs = mul(G, 0n); // Point.ZERO
    rhs = rhs.add(mul(H, BigInt('0x' + rPrime)));
    for (let i = 0; i < k; i++) {
      rhs = rhs.add(mul(pp(bitProofs[i].C), 1n << BigInt(i)));
    }
    return C.equals(rhs);
  } catch { return false; }
}

/* ── Two-sided bounded proof: 0 ≤ v ≤ w ────────────────────────────────── */

/**
 * Prove 0 ≤ value ≤ w, given C = value·G + blinding·H.
 *
 * @param {bigint} value     — the secret value
 * @param {bigint} blinding  — the commitment blinding factor
 * @param {bigint} w         — the public upper bound (edge capacity)
 * @returns {{ type, C, Cs, w, lower, upper, note }}
 */
function proveBounded(value, blinding, w) {
  if (value < 0n || value > w) {
    throw new Error(`value ${value} not in [0, ${w}]`);
  }
  let k = 1;
  while ((1n << BigInt(k)) <= w) k++;
  k += 1; // one bit of slack for the composition to hold

  const C      = mul(G, value).add(mul(H, blinding));
  const lower  = proveOneSided(value, blinding, k);

  const slack   = w - value;
  const rNeg    = mod(-blinding);
  const Cs      = mul(G, slack).add(mul(H, rNeg));
  const upper   = proveOneSided(slack, rNeg, k);

  return {
    type:  'zk-bounded-range-v1',
    C:     ph(C),
    Cs:    ph(Cs),
    w:     w.toString(),
    lower,
    upper,
    note:  'Chaum-Pedersen OR-proof; proves 0 ≤ v ≤ w; binding: C + Cs = w·G',
  };
}

/**
 * Verify a bounded range proof.
 * @param {object} proof — from proveBounded
 * @returns {{ isValid:boolean, error:string|null }}
 */
function verifyBounded(proof) {
  try {
    if (!proof || proof.type !== 'zk-bounded-range-v1') {
      return { isValid: false, error: 'unknown proof type' };
    }
    const C  = pp(proof.C);
    const Cs = pp(proof.Cs);
    const w  = BigInt(proof.w);
    // Homomorphic binding: C + Cs = (v + slack)·G + (r − r)·H = w·G
    if (!C.add(Cs).equals(mul(G, w))) {
      return { isValid: false, error: 'C + Cs ≠ w·G: bounds not consistent' };
    }
    if (!verifyOneSided(proof.C, proof.lower)) {
      return { isValid: false, error: 'lower bound proof failed' };
    }
    if (!verifyOneSided(proof.Cs, proof.upper)) {
      return { isValid: false, error: 'upper bound (slack) proof failed' };
    }
    return { isValid: true, error: null };
  } catch (e) {
    return { isValid: false, error: e.message };
  }
}

/* ── Commit helper (re-exports so callers don't need to touch noble) ─────── */

function commit(value, blinding) {
  return { point: mul(G, mod(BigInt(value))).add(mul(H, mod(BigInt(blinding)))), ph };
}

/* ── Self-test ──────────────────────────────────────────────────────────── */

function selfTest() {
  const cases = [
    [0n, 1n], [1n, 1n],
    [0n, 255n], [128n, 255n], [255n, 255n],
    [0n, 65535n], [12345n, 65535n], [65535n, 65535n],
    [2n, 5n], [5n, 5n],
  ];
  for (const [v, w] of cases) {
    const r = randScalar();
    const proof = proveBounded(v, r, w);
    const { isValid, error } = verifyBounded(proof);
    if (!isValid) throw new Error(`range proof failed v=${v} w=${w}: ${error}`);
  }
  // Negative: out-of-range must throw
  let threw = false;
  try { proveBounded(10n, randScalar(), 5n); } catch { threw = true; }
  if (!threw) throw new Error('out-of-range proof should throw');
  return { ok: true, cases: cases.length };
}

module.exports = { proveBounded, verifyBounded, proveBit, verifyBit, selfTest };
