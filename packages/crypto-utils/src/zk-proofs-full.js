'use strict';

/**
 * zk-proofs-full.js — real zero-knowledge proofs over ristretto255.
 *
 * This is standard, textbook sigma-protocol cryptography — no novel math:
 *   - Pedersen commitments  C = v·G + r·H  (computationally binding,
 *     perfectly hiding; H derived by hash-to-curve so log_G(H) is unknown).
 *   - Schnorr ZK proof of knowledge of a commitment opening (v, r), made
 *     non-interactive via Fiat–Shamir; public inputs are bound into the
 *     challenge hash so a proof can't be replayed against different claims.
 *   - Bit range proofs: each bit committed, proven ∈ {0,1} with a
 *     Chaum–Pedersen/CDS OR-proof, and the weighted sum of bit commitments
 *     shown equal to the value commitment. Non-succinct (proof size grows
 *     with bitSize) but genuinely zero-knowledge — this is NOT a SNARK and
 *     is not marketed as one.
 *
 * What a verifier learns: only that the prover knows an opening (and, for
 * range proofs, that the committed value lies in [0, 2^bitSize)). The value
 * itself is never revealed.
 */

const crypto = require('crypto');
const { ristretto255, ristretto255_hasher } = require('@noble/curves/ed25519.js');

const Point = ristretto255.Point;
const ORDER = Point.Fn.ORDER;
const G = Point.BASE;
// Second generator with unknown discrete log relative to G.
const H = ristretto255_hasher.hashToCurve(
  new TextEncoder().encode('KASBAH-ZK-H-GENERATOR-v1'),
  { DST: 'kasbah-pedersen-v1' }
);

// ── scalar / point helpers ───────────────────────────────────────────────────

const mod = (x) => ((x % ORDER) + ORDER) % ORDER;

function randScalar() {
  // 64 bytes reduced mod order — negligible bias.
  return mod(BigInt('0x' + crypto.randomBytes(64).toString('hex')));
}

// Point multiply that tolerates scalar 0 (noble rejects it).
function mul(P, s) {
  s = mod(s);
  return s === 0n ? Point.ZERO : P.multiply(s);
}

function toScalar(value) {
  if (typeof value === 'bigint') return mod(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('value must be finite');
    return mod(BigInt(Math.trunc(value)));
  }
  if (typeof value === 'string' && /^-?\d+$/.test(value)) return mod(BigInt(value));
  // Arbitrary data → deterministic scalar via hash
  const d = crypto.createHash('sha512').update(String(value)).digest('hex');
  return mod(BigInt('0x' + d));
}

function hashToChallenge(...parts) {
  const h = crypto.createHash('sha512');
  for (const p of parts) h.update(typeof p === 'string' ? p : JSON.stringify(p));
  return mod(BigInt('0x' + h.digest('hex')));
}

const ph = (P) => P.toHex();
const pp = (hex) => Point.fromHex(hex);

// ── the system ───────────────────────────────────────────────────────────────

class ZKProofSystem {
  constructor() {
    this.algorithm = 'pedersen-ristretto255 + schnorr-fiat-shamir';
  }

  /**
   * Pedersen commitment to a value. Returns the blinding — the caller must
   * keep it secret; it is what makes later proofs possible.
   */
  commit(value) {
    const v = toScalar(value);
    const r = randScalar();
    const C = mul(G, v).add(mul(H, r));
    return {
      commitment: ph(C),
      blinding: r.toString(16),
      algorithm: 'pedersen-ristretto255',
    };
  }

  /**
   * ZK proof of knowledge of the opening (v, r) of a Pedersen commitment,
   * with publicInputs bound into the Fiat–Shamir challenge.
   *
   * privateInputs: { value, blinding? }  — if blinding is omitted a fresh
   * commitment is created and returned inside the proof.
   */
  generateDetectionProof({ privateInputs = {}, publicInputs = {} } = {}) {
    if (privateInputs.value === undefined) {
      throw new Error('privateInputs.value required — there is nothing to prove without a witness');
    }
    const v = toScalar(privateInputs.value);
    const r = privateInputs.blinding !== undefined
      ? mod(BigInt('0x' + String(privateInputs.blinding)))
      : randScalar();
    const C = mul(G, v).add(mul(H, r));

    // Schnorr: A = a·G + b·H ; c = H(A, C, publicInputs) ; z1 = a+cv ; z2 = b+cr
    const a = randScalar(), b = randScalar();
    const A = mul(G, a).add(mul(H, b));
    const c = hashToChallenge('kasbah-zkpok-v1', ph(A), ph(C), publicInputs);
    return {
      type: 'zkpok-commitment-opening',
      commitment: ph(C),
      A: ph(A),
      z1: mod(a + c * v).toString(16),
      z2: mod(b + c * r).toString(16),
      publicInputsHash: crypto.createHash('sha256').update(JSON.stringify(publicInputs)).digest('hex'),
      algorithm: this.algorithm,
    };
  }

  /** Verify a detection proof against the same publicInputs. */
  verifyProof(proof, publicInputs = {}) {
    try {
      if (!proof || proof.type !== 'zkpok-commitment-opening') {
        return { isValid: false, error: 'unknown proof type' };
      }
      const pubHash = crypto.createHash('sha256').update(JSON.stringify(publicInputs)).digest('hex');
      if (proof.publicInputsHash && proof.publicInputsHash !== pubHash) {
        return { isValid: false, error: 'publicInputs do not match the ones bound into the proof' };
      }
      const C = pp(proof.commitment), A = pp(proof.A);
      const z1 = BigInt('0x' + proof.z1), z2 = BigInt('0x' + proof.z2);
      const c = hashToChallenge('kasbah-zkpok-v1', proof.A, proof.commitment, publicInputs);
      // Check z1·G + z2·H == A + c·C
      const lhs = mul(G, z1).add(mul(H, z2));
      const rhs = A.add(mul(C, c));
      return { isValid: lhs.equals(rhs), error: null };
    } catch (e) {
      return { isValid: false, error: e.message };
    }
  }

  /**
   * Bit-decomposition range proof: value ∈ [0, 2^bitSize).
   * Each bit gets a Pedersen commitment plus a CDS OR-proof that it opens to
   * 0 or 1; the 2^i-weighted sum of bit commitments equals the value
   * commitment (verifier recomputes this directly).
   */
  generateRangeProof(value, bitSize = 32) {
    if (!Number.isInteger(value) || value < 0) {
      throw new Error('range proof requires a non-negative integer value');
    }
    if (bitSize < 1 || bitSize > 64) throw new Error('bitSize must be 1..64');
    if (BigInt(value) >= (1n << BigInt(bitSize))) {
      throw new Error(`value ${value} is outside [0, 2^${bitSize}) — cannot prove a false statement`);
    }

    const built = this._proveRange(BigInt(value), bitSize);
    return {
      type: 'zk-range-bit-decomposition',
      bitSize,
      valueCommitment: ph(built.valueCommitment),
      bitProofs: built.bitProofs,
      algorithm: this.algorithm,
      note: `proves committed value ∈ [0, 2^${bitSize}) without revealing it; non-succinct sigma-protocol proof`,
    };
  }

  /**
   * Internal: build the bit-decomposition range proof and RETURN the value
   * commitment point together with its blinding (rTotal). Exposing the
   * blinding lets proveThresholdVerdict bind this commitment homomorphically
   * to another commitment — impossible if the blinding stayed hidden inside.
   */
  _proveRange(vBig, bitSize) {
    const bits = [];
    let rTotal = 0n;
    for (let i = 0; i < bitSize; i++) {
      const bit = (vBig >> BigInt(i)) & 1n;
      const r = randScalar();
      rTotal = mod(rTotal + r * (1n << BigInt(i)));
      const C = mul(G, bit).add(mul(H, r));
      bits.push({ bit, r, C });
    }
    const valueCommitment = mul(G, vBig).add(mul(H, rTotal));

    // CDS OR-proof per bit: prove C = 0·G + r·H  OR  C = 1·G + r·H.
    const bitProofs = bits.map(({ bit, r, C }) => {
      // Statement for b=0: C = r·H (dlog wrt H). For b=1: C − G = r·H.
      const C0 = C;               // target if bit==0
      const C1 = C.subtract(G);   // target if bit==1
      const real = bit === 0n ? 0 : 1;
      const targets = [C0, C1];

      // Simulate the false branch, run Schnorr honestly on the true one.
      const cFake = randScalar(), zFake = randScalar();
      const AFake = mul(H, zFake).subtract(mul(targets[1 - real], cFake));
      const a = randScalar();
      const AReal = mul(H, a);
      const As = real === 0 ? [AReal, AFake] : [AFake, AReal];
      const cTotal = hashToChallenge('kasbah-zk-bit-v1', ph(C), ph(As[0]), ph(As[1]));
      const cReal = mod(cTotal - cFake);
      const zReal = mod(a + cReal * r);
      const cs = real === 0 ? [cReal, cFake] : [cFake, cReal];
      const zs = real === 0 ? [zReal, zFake] : [zFake, zReal];
      return {
        C: ph(C),
        A0: ph(As[0]), A1: ph(As[1]),
        c0: cs[0].toString(16), c1: cs[1].toString(16),
        z0: zs[0].toString(16), z1: zs[1].toString(16),
      };
    });

    return { valueCommitment, blinding: rTotal, bitProofs };
  }

  /** Verify a range proof produced by generateRangeProof. */
  verifyRangeProof(proof) {
    try {
      if (!proof || proof.type !== 'zk-range-bit-decomposition') {
        return { isValid: false, error: 'unknown proof type' };
      }
      let sum = Point.ZERO;
      for (let i = 0; i < proof.bitProofs.length; i++) {
        const bp = proof.bitProofs[i];
        const C = pp(bp.C);
        const c0 = BigInt('0x' + bp.c0), c1 = BigInt('0x' + bp.c1);
        const z0 = BigInt('0x' + bp.z0), z1 = BigInt('0x' + bp.z1);
        const cTotal = hashToChallenge('kasbah-zk-bit-v1', bp.C, bp.A0, bp.A1);
        if (mod(c0 + c1) !== cTotal) return { isValid: false, error: `bit ${i}: challenge split invalid` };
        // Branch 0: z0·H == A0 + c0·C ; Branch 1: z1·H == A1 + c1·(C − G)
        if (!mul(H, z0).equals(pp(bp.A0).add(mul(C, c0)))) {
          return { isValid: false, error: `bit ${i}: branch-0 equation fails` };
        }
        if (!mul(H, z1).equals(pp(bp.A1).add(mul(C.subtract(G), c1)))) {
          return { isValid: false, error: `bit ${i}: branch-1 equation fails` };
        }
        sum = sum.add(mul(C, 1n << BigInt(i)));
      }
      if (!sum.equals(pp(proof.valueCommitment))) {
        return { isValid: false, error: 'bit commitments do not sum to the value commitment' };
      }
      return { isValid: true, error: null };
    } catch (e) {
      return { isValid: false, error: e.message };
    }
  }

  /**
   * THRESHOLD-VERDICT PROOF — the compliance moat primitive.
   *
   * Proves, in zero knowledge, that a hidden integer risk score `score`
   * (0..2^bits-1) stands on the claimed side of a PUBLIC threshold `T`, so the
   * emitted verdict is the correct threshold decision — WITHOUT revealing the
   * score.
   *
   *   below === true   ⇒  proves score <  T   (verdict ALLOW/WARN)
   *   below === false  ⇒  proves score >= T   (verdict DENY/REQUIRE_APPROVAL)
   *
   * Construction: commit C_s = score·G + b·H. Commit the non-negative gap
   *   d = below ? (T-1-score) : (score-T)
   * and range-prove d ∈ [0, 2^bits). Bind the two commitments homomorphically
   * by choosing the score blinding from the gap-commitment blinding, so the
   * verifier can check a public linear relation between C_s, C_d and T that
   * only holds when d is exactly that gap. A dishonest verdict would require a
   * negative d, which the range proof cannot produce — so it is refused here
   * rather than faked.
   *
   * What this proves: tamper-evidence + verdict-is-correct-under-T + score
   * privacy. What it does NOT prove: that `score` is the "true" risk of the
   * input — that is the detector's job, benchmarked separately. Stated plainly
   * so the guarantee is never oversold.
   */
  proveThresholdVerdict(score, T, below, bits = 16) {
    if (!Number.isInteger(score) || score < 0) throw new Error('score must be a non-negative integer');
    if (!Number.isInteger(T) || T < 0) throw new Error('threshold T must be a non-negative integer');
    if (bits < 1 || bits > 32) throw new Error('bits must be 1..32');
    if (score >= (1 << bits)) throw new Error(`score ${score} does not fit in ${bits} bits`);

    const consistent = below ? score < T : score >= T;
    if (!consistent) {
      throw new Error(`refusing to prove a false statement: score ${below ? '<' : '>='} T is not true for score=${score}, T=${T}`);
    }
    const gap = below ? BigInt(T - 1 - score) : BigInt(score - T);
    if (gap < 0n) throw new Error('internal: negative gap — verdict/threshold inconsistent');

    // Range proof over the gap; reuse its blinding to bind the score commitment.
    const rp = this._proveRange(gap, bits);
    const bGap = rp.blinding;
    // Choose score blinding so a PUBLIC relation ties C_s and C_gap together:
    //   below:  C_s + C_gap == (T-1)·G          (needs b_s = -b_gap)
    //   above:  C_s - C_gap == T·G              (needs b_s =  b_gap)
    const bScore = below ? mod(-bGap) : bGap;
    const C_s = mul(G, BigInt(score)).add(mul(H, bScore));

    return {
      type: 'zk-threshold-verdict',
      direction: below ? 'below' : 'at-or-above',
      threshold: T,
      bits,
      scoreCommitment: ph(C_s),
      gapRangeProof: {
        type: 'zk-range-bit-decomposition',
        bitSize: bits,
        valueCommitment: ph(rp.valueCommitment),
        bitProofs: rp.bitProofs,
      },
      algorithm: this.algorithm,
      note: `ZK proof that a hidden risk score is ${below ? 'below' : 'at/above'} public threshold ${T}; score never revealed`,
    };
  }

  /** Verify a threshold-verdict proof. Learns nothing about the score. */
  verifyThresholdVerdict(proof) {
    try {
      if (!proof || proof.type !== 'zk-threshold-verdict') return { isValid: false, error: 'unknown proof type' };
      const range = this.verifyRangeProof(proof.gapRangeProof);
      if (!range.isValid) return { isValid: false, error: 'gap range proof invalid: ' + range.error };

      const C_s = pp(proof.scoreCommitment);
      const C_gap = pp(proof.gapRangeProof.valueCommitment);
      const T = BigInt(proof.threshold);

      if (proof.direction === 'below') {
        // C_s + C_gap must equal (T-1)·G  (no H component ⇒ blindings cancel ⇒ d = T-1-score)
        if (!C_s.add(C_gap).equals(mul(G, mod(T - 1n)))) {
          return { isValid: false, error: 'homomorphic relation C_s + C_gap == (T-1)·G fails' };
        }
      } else if (proof.direction === 'at-or-above') {
        // C_s − C_gap must equal T·G
        if (!C_s.subtract(C_gap).equals(mul(G, T))) {
          return { isValid: false, error: 'homomorphic relation C_s − C_gap == T·G fails' };
        }
      } else {
        return { isValid: false, error: 'unknown direction' };
      }
      return { isValid: true, error: null, proves: `hidden risk score is ${proof.direction === 'below' ? 'below' : 'at/above'} threshold ${proof.threshold}` };
    } catch (e) {
      return { isValid: false, error: e.message };
    }
  }
}

module.exports = { ZKProofSystem };
