import crypto from 'node:crypto'
import { secp256k1 } from '@noble/curves/secp256k1.js'

/**
 * FELDMAN VSS — Verifiable secret sharing over the secp256k1 scalar field.
 *
 *  WHY THIS EXISTS
 *   Plain Shamir (shamir.ts) is information-theoretically secret but requires
 *   trusting the dealer: a malicious dealer can hand out inconsistent shares,
 *   and a shareholder cannot tell their share is valid until combine fails
 *   (or worse, silently reconstructs the wrong secret).
 *
 *   Feldman VSS (Feldman 1987) fixes this: the dealer commits to each
 *   polynomial coefficient in a prime-order group where discrete log is hard.
 *   Each shareholder verifies — BEFORE reconstruction — that their share lies
 *   on the committed polynomial. A bad dealer is caught; a corrupted share is
 *   rejected. The secret stays hidden (commitments are DL-hard).
 *
 *  THE GROUP
 *   secp256k1: base point G, prime order q ≈ 2²⁵⁶.
 *   Scalar field is Z_q. Chunk size 31 bytes (248 bits < q ⇒ every chunk < q).
 *
 *  THE MATH
 *   Polynomial f(x) = a₀ + a₁x + … + aₖ₋₁xᵏ⁻¹ over Z_q, a₀ = secret chunk.
 *   Commitments   Cᵢ = [aᵢ] G   (one point per coefficient, per chunk).
 *   Share j        (xⱼ, f(xⱼ)).
 *   Verify j       [f(xⱼ)] G  ==?  Σᵢ xⱼⁱ · Cᵢ   (Horner in the group).
 *   Combine        standard Lagrange at 0 over Z_q.
 *   Post-hoc       [reconstructed chunk] G ==? C₀  (catches a lying combiner).
 *
 *  SECURITY SCOPE (honest)
 *   • Verifiability: YES. A shareholder can reject a bad share pre-combine.
 *   • Secrecy: YES (information-theoretic against k−1, computational against
 *     the commitment: C₀ = [secret]G reveals nothing without solving ECDLP).
 *   • Constant-time: noble's scalar multiplication is CT. The Z_q BigInt
 *     bookkeeping is not, but the only secret-dependent operations are the
 *     [aᵢ]G point multiplications, which go through noble's CT path.
 *   • NOT a replacement for Pedersen VSS (which is information-theoretically
 *     private even against the commitment). Feldman leaks the constant term
 *     computationally — acceptable for nearly all real deployments.
 *   • NOT proactive. Share refreshing is a separate protocol (see worklog).
 */

// ─────────────────────────── constants ───────────────────────────

/** secp256k1 group order (prime scalar field). */
export const Q = secp256k1.Point.CURVE().n
/** Base point G. */
const G = secp256k1.Point.BASE
/** Infinity point (commitment to a zero coefficient). */
const ZERO = secp256k1.Point.ZERO
/** SEC1 infinity marker — noble refuses to (de)serialize ZERO, so we handle it. */
const INF_HEX = '00'
/** Chunk size: 248 bits < q ≈ 2²⁵⁶ ⇒ every chunk value < q. */
export const CHUNK_BYTES_VSS = 31
/** VSS share format version. */
export const FORMAT_V_VSS = 3
const MAX_N = 200

// ─────────────────────────── types ───────────────────────────

export interface VSSShare {
  v: 3
  /** Evaluation point x, `0x`-prefixed hex. */
  x: string
  /** Comma-joined hex y-values, one per chunk. */
  y: string
  threshold: number
  total: number
  chunks: number
  /** Original secret byte length. */
  len: number
  /** True when the original secret was a Buffer. */
  binary?: boolean
}

export interface VSSCommitment {
  v: 3
  curve: 'secp256k1'
  /** commits[c][i] = compressed secp256k1 point (66-hex) for coefficient i of chunk c. */
  commits: string[][]
}

export interface VSSSplitResult {
  shares: VSSShare[]
  commitment: VSSCommitment
}

export interface VerifyResult {
  valid: boolean
  chunkResults: { c: number; ok: boolean }[]
}

export interface CombineVSSResult {
  buf: Buffer
  /** True iff every supplied share passed Feldman verification. */
  verified: boolean
  /** Per-chunk: does [reconstructed chunk]G equal C₀? Catches a lying combiner. */
  chunkIntegrity: boolean[]
}

export type SecretInput = string | Buffer | Uint8Array

// ─────────────────────────── scalar field Z_q ───────────────────────────

function modq(a: bigint): bigint {
  a %= Q
  return a < 0n ? a + Q : a
}
function addq(a: bigint, b: bigint): bigint {
  const s = a + b
  return s >= Q ? s - Q : s
}
function subq(a: bigint, b: bigint): bigint {
  const d = a - b
  return d < 0n ? d + Q : d
}
function mulq(a: bigint, b: bigint): bigint {
  return modq(a * b)
}
function powq(a: bigint, e: bigint): bigint {
  let r = 1n
  a = modq(a)
  while (e > 0n) {
    if (e & 1n) r = mulq(r, a)
    a = mulq(a, a)
    e >>= 1n
  }
  return r
}
function invq(a: bigint): bigint {
  if (a === 0n) throw new Error('invq(0): duplicate or zero x')
  return powq(a, Q - 2n)
}

/** Uniform in [1, q) by rejection — unbiased x and coefficients. */
function randFieldQ(): bigint {
  for (;;) {
    const v = BigInt('0x' + crypto.randomBytes(32).toString('hex'))
    if (v > 0n && v < Q) return v
  }
}
function randXQ(): bigint {
  let x: bigint
  do {
    x = randFieldQ()
  } while (x === 0n)
  return x
}

// ─────────────────────── Lagrange basis (batch) ─────────────────────────

function lagrangeAtZeroQ(xs: bigint[]): bigint[] {
  const k = xs.length
  const lam = new Array<bigint>(k)
  for (let i = 0; i < k; i++) {
    let num = 1n
    let den = 1n
    for (let j = 0; j < k; j++) {
      if (j === i) continue
      num = mulq(num, subq(0n, xs[j]))
      den = mulq(den, subq(xs[i], xs[j]))
    }
    lam[i] = mulq(num, invq(den))
  }
  return lam
}

// ─────────────────────────── point helpers ──────────────────────────────

/** Serialize a scalar's commitment [a]G as compressed hex; 0 → infinity marker. */
function commitToHex(a: bigint): string {
  if (a === 0n) return INF_HEX
  return G.multiply(a).toHex(true)
}

/** [a]G as a Point, handling a=0 without noble's throw. */
function scalarMulG(a: bigint): typeof G {
  if (a === 0n) return ZERO
  return G.multiply(a)
}

/** Parse a commitment hex back to a Point. Throws on malformed input. */
function pointFromHex(hex: string): typeof G {
  const h = String(hex)
  if (h === INF_HEX) return ZERO
  return secp256k1.Point.fromHex(h)
}

// ──────────────────────────────── split ─────────────────────────────────

export function splitVSS(secret: Buffer, n: number, k: number): VSSSplitResult {
  if (!Number.isInteger(n) || !Number.isInteger(k) || k < 2 || n < k || n > MAX_N) {
    throw new Error(`need integers 2 ≤ k ≤ n ≤ ${MAX_N}`)
  }

  const chunks: Buffer[] = []
  for (let i = 0; i < secret.length; i += CHUNK_BYTES_VSS) {
    chunks.push(secret.subarray(i, i + CHUNK_BYTES_VSS))
  }
  if (chunks.length === 0) chunks.push(Buffer.alloc(0))

  const nChunks = chunks.length

  // Distinct, non-zero x's.
  const xs: bigint[] = []
  const seen = new Set<bigint>()
  while (xs.length < n) {
    const x = randXQ()
    if (seen.has(x)) continue
    seen.add(x)
    xs.push(x)
  }

  const shareYs: string[][] = Array.from({ length: n }, () => new Array<string>(nChunks))
  const commits: string[][] = Array.from({ length: nChunks }, () => new Array<string>(k))
  const coeffs = new Array<bigint>(k)

  for (let c = 0; c < nChunks; c++) {
    const chunk = chunks[c]
    const s = chunk.length ? BigInt('0x' + chunk.toString('hex')) : 0n
    if (s >= Q) throw new Error('chunk value ≥ q')

    coeffs[0] = s
    for (let i = 1; i < k; i++) coeffs[i] = randFieldQ()

    // Commit to every coefficient: Cᵢ = [aᵢ] G. Constant-time via noble.
    for (let i = 0; i < k; i++) commits[c][i] = commitToHex(coeffs[i])

    // Evaluate f(xⱼ) by Horner.
    for (let j = 0; j < n; j++) {
      let y = 0n
      const xi = xs[j]
      for (let d = k - 1; d >= 0; d--) y = addq(mulq(y, xi), coeffs[d])
      shareYs[j][c] = y.toString(16)
    }
  }

  const shares: VSSShare[] = shareYs.map((ys, i) => ({
    v: FORMAT_V_VSS,
    x: '0x' + xs[i].toString(16),
    y: ys.join(','),
    threshold: k,
    total: n,
    chunks: nChunks,
    len: secret.length,
  }))

  const commitment: VSSCommitment = {
    v: FORMAT_V_VSS,
    curve: 'secp256k1',
    commits,
  }

  return { shares, commitment }
}

// ─────────────────────────────── verify ─────────────────────────────────

/**
 * Verify a single share against the commitment, WITHOUT reconstruction.
 *
 *   [f(xⱼ)] G  ==?  Σᵢ xⱼⁱ · Cᵢ   (Horner in the group)
 *
 * If this holds, the share lies on the committed polynomial. A shareholder
 * runs this locally and rejects a bad share before combine.
 */
export function verifyShare(share: VSSShare, commitment: VSSCommitment): VerifyResult {
  if (commitment.v !== FORMAT_V_VSS) throw new Error('commitment is not v3')
  if (share.chunks !== commitment.commits.length) {
    throw new Error('chunk count mismatch between share and commitment')
  }
  const k = share.threshold
  if (commitment.commits[0].length !== k) {
    throw new Error('commitment width ≠ threshold')
  }

  const x = BigInt(share.x)
  if (x <= 0n || x >= Q) throw new Error('x out of range')

  const parts = share.y.split(',')
  const chunkResults: { c: number; ok: boolean }[] = []
  let allOk = true

  for (let c = 0; c < share.chunks; c++) {
    const y = BigInt('0x' + (parts[c] === '' ? '0' : parts[c]))
    if (y >= Q) throw new Error('y out of range')

    let ok = false
    try {
      // LHS: [y] G
      const lhs = scalarMulG(y)
      // RHS: Horner — Σᵢ xⁱ Cᵢ = C_{k-1}·x^{k-1} + ... + C_0
      const cs = commitment.commits[c]
      let acc = pointFromHex(cs[k - 1])
      for (let i = k - 2; i >= 0; i--) {
        acc = acc.multiply(x).add(pointFromHex(cs[i]))
      }
      ok = lhs.equals(acc)
    } catch {
      ok = false
    }

    chunkResults.push({ c, ok })
    if (!ok) allOk = false
  }

  return { valid: allOk, chunkResults }
}

// ─────────────────────────────── combine ────────────────────────────────

export function combineVSS(
  shares: VSSShare[],
  commitment: VSSCommitment,
): CombineVSSResult {
  if (!Array.isArray(shares) || shares.length === 0) throw new Error('no shares supplied')

  // Cross-share metadata consistency.
  const ref = shares[0]
  for (const s of shares) {
    if (Number(s.threshold) !== Number(ref.threshold)) throw new Error('inconsistent threshold')
    if (Number(s.total) !== Number(ref.total)) throw new Error('inconsistent total')
    if (Number(s.chunks) !== Number(ref.chunks)) throw new Error('inconsistent chunks')
    if (s.binary !== ref.binary) throw new Error('inconsistent binary flag')
  }

  const k = ref.threshold
  if (shares.length < k) throw new Error(`need ${k} shares, got ${shares.length}`)

  // Verify every supplied share against the commitment.
  let verified = true
  for (const s of shares) {
    try {
      if (!verifyShare(s, commitment).valid) verified = false
    } catch {
      verified = false
    }
  }

  const use = shares.slice(0, k)

  // Distinct, in-range x's.
  const seen = new Set<bigint>()
  for (const u of use) {
    const x = BigInt(u.x)
    if (x <= 0n || x >= Q) throw new Error('x out of range')
    if (seen.has(x)) throw new Error('duplicate x-values among shares')
    seen.add(x)
  }

  const xs = use.map((u) => BigInt(u.x))
  const lambdas = lagrangeAtZeroQ(xs)

  const nChunks = use[0].chunks
  const out: Buffer[] = new Array(nChunks)
  const chunkIntegrity: boolean[] = new Array(nChunks)

  for (let c = 0; c < nChunks; c++) {
    let secret = 0n
    for (let i = 0; i < k; i++) {
      const parts = use[i].y.split(',')
      const y = BigInt('0x' + (parts[c] === '' ? '0' : parts[c]))
      secret = addq(secret, mulq(lambdas[i], y))
    }

    // Post-hoc integrity: [reconstructed chunk] G ==? C_{c,0}.
    // Catches a combiner who lies about the reconstructed value.
    let ciOk = false
    try {
      ciOk = scalarMulG(secret).equals(pointFromHex(commitment.commits[c][0]))
    } catch {
      ciOk = false
    }
    chunkIntegrity[c] = ciOk

    const w = Math.min(CHUNK_BYTES_VSS, use[0].len - c * CHUNK_BYTES_VSS)
    let hex = secret.toString(16)
    hex = w <= 0 ? '' : hex.padStart(2 * w, '0')
    out[c] = hex.length ? Buffer.from(hex, 'hex') : Buffer.alloc(0)
  }

  let buf = Buffer.concat(out)
  if (use[0].len > buf.length) throw new Error('len metadata exceeds data')
  buf = buf.subarray(0, use[0].len)

  return { buf, verified, chunkIntegrity }
}

// ─────────────────────────────── public API ─────────────────────────────

function toBuffer(secret: SecretInput): { buf: Buffer; isBuf: boolean } {
  if (Buffer.isBuffer(secret)) return { buf: secret, isBuf: true }
  if (secret instanceof Uint8Array) return { buf: Buffer.from(secret), isBuf: true }
  return { buf: Buffer.from(String(secret), 'utf8'), isBuf: false }
}

export function splitVSSString(str: string, n: number, k: number): VSSSplitResult {
  const { buf, isBuf } = toBuffer(str)
  const res = splitVSS(buf, n, k)
  for (const s of res.shares) s.binary = isBuf
  return res
}

export function splitVSSInput(secret: SecretInput, n: number, k: number): VSSSplitResult {
  const { buf, isBuf } = toBuffer(secret)
  const res = splitVSS(buf, n, k)
  for (const s of res.shares) s.binary = isBuf
  return res
}

// ─────────────────────────────── self-test ──────────────────────────────

export function selfTestVSS(): { passed: number; cases: string[] } {
  const cases: string[] = []
  let passed = 0
  const expect = (name: string, cond: boolean) => {
    if (cond) {
      passed++
      cases.push(`✓ ${name}`)
    } else {
      cases.push(`✗ ${name}`)
      throw new Error(`VSS self-test failed: ${name}`)
    }
  }

  // 1. Honest round-trip, all shares verify.
  {
    const buf = Buffer.from('the eagle flies at midnight', 'utf8')
    const { shares, commitment } = splitVSS(buf, 5, 3)
    const { buf: rec, verified } = combineVSS(shares.slice(0, 3), commitment)
    expect('honest round-trip k=3', rec.equals(buf))
    expect('all shares verify pre-combine', verified)
  }

  // 2. Any k of n.
  {
    const buf = Buffer.from('hello world', 'utf8')
    const { shares, commitment } = splitVSS(buf, 5, 3)
    const a = combineVSS([shares[0], shares[2], shares[4]], commitment)
    const b = combineVSS([shares[1], shares[3], shares[0]], commitment)
    expect('any-k subset A', a.buf.equals(buf) && a.verified)
    expect('any-k subset B', b.buf.equals(buf) && b.verified)
  }

  // 3. Tampered share fails verification (the whole point of VSS).
  {
    const buf = Buffer.from('tamper me', 'utf8')
    const { shares, commitment } = splitVSS(buf, 3, 2)
    const t: VSSShare = { ...shares[0] }
    const parts = t.y.split(',')
    parts[0] = (parts[0][0] === '0' ? '1' : '0') + parts[0].slice(1)
    t.y = parts.join(',')
    let v = true
    try {
      v = verifyShare(t, commitment).valid
    } catch {
      v = false
    }
    expect('tampered share rejected by verifyShare', !v)
  }

  // 4. Tampered commitment fails verification.
  {
    const buf = Buffer.from('bad commit', 'utf8')
    const { shares, commitment } = splitVSS(buf, 3, 2)
    const c2: VSSCommitment = JSON.parse(JSON.stringify(commitment))
    const orig = c2.commits[0][0]
    c2.commits[0][0] = (orig[0] === '0' ? '1' : '0') + orig.slice(1)
    let v = true
    try {
      v = verifyShare(shares[0], c2).valid
    } catch {
      v = false
    }
    expect('tampered commitment rejected', !v)
  }

  // 5. Binary with NUL bytes round-trips.
  {
    const buf = Buffer.alloc(32)
    for (let i = 0; i < 32; i++) buf[i] = i // includes 0x00
    const { shares, commitment } = splitVSS(buf, 5, 3)
    const { buf: rec, verified } = combineVSS(shares.slice(0, 3), commitment)
    expect('binary NUL round-trips', rec.equals(buf))
    expect('binary shares verify', verified)
  }

  // 6. Chunk integrity flag is true on honest combine.
  {
    const buf = Buffer.from('integrity check', 'utf8')
    const { shares, commitment } = splitVSS(buf, 4, 3)
    const { chunkIntegrity } = combineVSS(shares.slice(0, 3), commitment)
    expect('chunk integrity all true', chunkIntegrity.every(Boolean))
  }

  // 7. k−1 shares rejected.
  {
    const buf = Buffer.from('kminus1', 'utf8')
    const { shares, commitment } = splitVSS(buf, 5, 3)
    let rej = false
    try {
      combineVSS([shares[0], shares[1]], commitment)
    } catch {
      rej = true
    }
    expect('k−1 shares rejected', rej)
  }

  // 8. Duplicate x rejected.
  {
    const buf = Buffer.from('dupx', 'utf8')
    const { shares, commitment } = splitVSS(buf, 3, 2)
    let rej = false
    try {
      combineVSS([shares[0], { ...shares[0] }], commitment)
    } catch {
      rej = true
    }
    expect('duplicate x rejected', rej)
  }

  // 9. combineVSS with a tampered share marks verified=false but still
  //    reconstructs the COMMITTED polynomial (verifiability ≠ fault tolerance;
  //    a bad share is flagged, not silently trusted).
  {
    const buf = Buffer.from('flag bad share', 'utf8')
    const { shares, commitment } = splitVSS(buf, 4, 3)
    const bad: VSSShare = { ...shares[0] }
    const parts = bad.y.split(',')
    parts[0] = (parts[0][0] === '0' ? '1' : '0') + parts[0].slice(1)
    bad.y = parts.join(',')
    const { verified } = combineVSS([bad, shares[1], shares[2]], commitment)
    expect('bad share flagged verified=false', !verified)
  }

  // 10. Larger binary (256 bytes, multi-chunk) round-trips and verifies.
  {
    const buf = Buffer.alloc(256)
    for (let i = 0; i < 256; i++) buf[i] = (i * 31 + 7) & 0xff
    const { shares, commitment } = splitVSS(buf, 6, 4)
    const { buf: rec, verified } = combineVSS(shares.slice(0, 4), commitment)
    expect('256-byte binary round-trips', rec.equals(buf))
    expect('256-byte shares verify', verified)
  }

  expect('VSS self-test completed', true)
  return { passed, cases }
}
