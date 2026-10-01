/**
 * Shamir's Secret Sharing — GF(256) Implementation
 *
 * Splits a secret into N shares, requiring any K shares to reconstruct.
 * Uses Galois Field GF(256) arithmetic with AES's irreducible polynomial
 * (0x11b) for byte-level operations. Each share is index-prefixed for
 * unambiguous identification during reconstruction.
 *
 * @package @kasbah/crypto-utils
 * @module shamir
 */

import { randomBytes as nodeRandomBytes } from 'crypto';

// ═══════════════════════════════════════════════════════════
// GF(256) Finite Field Arithmetic
// Irreducible polynomial: x^8 + x^4 + x^3 + x + 1 = 0x11b (AES)
// ═══════════════════════════════════════════════════════════

/** GF(256) multiplication using the Russian peasant algorithm. */
function gfMul(a: number, b: number): number {
  let product = 0;
  let aa = a & 0xff;
  let bb = b & 0xff;

  while (bb > 0) {
    if (bb & 1) {
      product ^= aa;
    }
    // Multiply aa by x (left shift), reduce mod 0x11b if overflow
    const hiBitSet = aa & 0x80;
    aa = (aa << 1) & 0xff;
    if (hiBitSet) {
      aa ^= 0x1b; // 0x11b mod 0x100 = 0x1b
    }
    bb >>= 1;
  }

  return product & 0xff;
}

/** GF(256) addition is XOR. Subtraction is the same as addition in GF(2^n). */
function gfAdd(a: number, b: number): number {
  return (a ^ b) & 0xff;
}

/**
 * GF(256) multiplicative inverse via Fermat's little theorem: a^(254) = a^(-1).
 * We compute this by repeated squaring.
 */
function gfInverse(a: number): number {
  if (a === 0) {
    throw new Error('GF(256) inverse of zero is undefined');
  }
  // a^254 in GF(256)
  let result = 1;
  let base = a & 0xff;
  let exp = 254;

  while (exp > 0) {
    if (exp & 1) {
      result = gfMul(result, base);
    }
    base = gfMul(base, base);
    exp >>= 1;
  }

  return result;
}

/** Evaluate a polynomial at point x over GF(256). Coefficients are per secret byte. */
function polyEval(coefficients: number[], x: number): number {
  // Horner's method: c[k-1]*x^(k-1) + ... + c[1]*x + c[0]
  let result = 0;
  for (let i = coefficients.length - 1; i >= 0; i--) {
    result = gfAdd(gfMul(result, x), coefficients[i]);
  }
  return result;
}

// ═══════════════════════════════════════════════════════════
// Shamir's Secret Sharing
// ═══════════════════════════════════════════════════════════

/**
 * Split a secret into `shares` shares, requiring `threshold` to reconstruct.
 *
 * Share format (per share Buffer):
 *   Byte 0      : share index (1-indexed, 1..255)
 *   Bytes 1..N  : polynomial evaluation at that index for each secret byte
 *
 * @param secret    - Secret to split; must be non-empty
 * @param shares    - Total number of shares to generate (1..255)
 * @param threshold - Minimum shares needed to reconstruct (1..shares)
 * @returns Array of `shares` Buffers, each of length secret.length + 1
 */
export function split(secret: Buffer, shares: number, threshold: number): Buffer[] {
  if (secret.length === 0) {
    throw new Error('Secret must not be empty');
  }
  if (threshold < 1) {
    throw new Error('Threshold must be >= 1');
  }
  if (threshold > shares) {
    throw new Error('Threshold must be <= shares');
  }
  if (shares > 255) {
    throw new Error('Shares must be <= 255');
  }

  const secretLen = secret.length;

  // Build a degree-(threshold-1) polynomial per secret byte.
  // coefficients[byteIdx] = [secret[byteIdx], r1, r2, ..., r(threshold-1)]
  // The constant term is the secret byte; higher coefficients are random.
  const randomCoeffs = nodeRandomBytes(secretLen * (threshold - 1));

  // Pre-build coefficient arrays: coefficients[byteIdx][coeffIdx]
  const coefficients: number[][] = new Array(secretLen);
  for (let byteIdx = 0; byteIdx < secretLen; byteIdx++) {
    const poly = new Array(threshold);
    poly[0] = secret[byteIdx]; // constant term = secret byte
    for (let t = 1; t < threshold; t++) {
      poly[t] = randomCoeffs[(threshold - 1) * byteIdx + (t - 1)];
    }
    coefficients[byteIdx] = poly;
  }

  // Evaluate each polynomial at x = 1, 2, ..., shares
  const result: Buffer[] = new Array(shares);
  for (let shareIdx = 0; shareIdx < shares; shareIdx++) {
    const x = shareIdx + 1; // x-coordinate in range [1, 255]
    const shareBuf = Buffer.allocUnsafe(1 + secretLen);
    shareBuf[0] = x;
    for (let byteIdx = 0; byteIdx < secretLen; byteIdx++) {
      shareBuf[1 + byteIdx] = polyEval(coefficients[byteIdx], x);
    }
    result[shareIdx] = shareBuf;
  }

  return result;
}

/**
 * Reconstruct a secret from K or more shares using Lagrange interpolation
 * over GF(256).
 *
 * @param shares - Array of share Buffers produced by `split()`; must have >= threshold entries
 * @returns Reconstructed secret Buffer
 */
export function combine(shares: Buffer[]): Buffer {
  if (shares.length === 0) {
    throw new Error('Must provide at least one share');
  }

  // Validate consistent lengths
  const shareLen = shares[0].length;
  if (shareLen < 2) {
    throw new Error('Each share must be at least 2 bytes (index + 1 secret byte)');
  }
  for (const s of shares) {
    if (s.length !== shareLen) {
      throw new Error('All shares must have the same length');
    }
  }

  const secretLen = shareLen - 1;

  // Extract x-coordinates (share indices) and check for duplicates
  const xs: number[] = shares.map((s) => s[0]);
  const seen = new Set<number>();
  for (const x of xs) {
    if (x === 0) {
      throw new Error('Share index 0 is reserved; indices must be in 1..255');
    }
    if (seen.has(x)) {
      throw new Error(`Duplicate share index ${x}`);
    }
    seen.add(x);
  }

  // Lagrange interpolation at x=0 (the constant term = the secret byte)
  const secret = Buffer.allocUnsafe(secretLen);

  for (let byteIdx = 0; byteIdx < secretLen; byteIdx++) {
    // y values for this byte position across all shares
    const ys: number[] = shares.map((s) => s[1 + byteIdx]);

    // Compute L(0) = sum_i y_i * prod_{j!=i} (0 - x_j) / (x_i - x_j)
    // In GF(256), subtraction is XOR.
    let value = 0;
    for (let i = 0; i < xs.length; i++) {
      let numerator = 1;   // prod of (0 - x_j) for j != i  →  prod of x_j (since 0^x_j = x_j in GF2)
      let denominator = 1; // prod of (x_i - x_j) for j != i
      for (let j = 0; j < xs.length; j++) {
        if (i === j) continue;
        numerator   = gfMul(numerator,   xs[j]);            // 0 XOR x_j = x_j
        denominator = gfMul(denominator, gfAdd(xs[i], xs[j])); // x_i XOR x_j
      }
      const lagrangeBasis = gfMul(numerator, gfInverse(denominator));
      value = gfAdd(value, gfMul(ys[i], lagrangeBasis));
    }

    secret[byteIdx] = value;
  }

  return secret;
}
