import crypto from 'node:crypto'

/**
 * THRESHOLD — Shamir secret sharing over GF(P), P = 2^127 − 1 (Mersenne prime).
 *
 *  MATH
 *   • Mersenne reduction: 2^127 ≡ 1 (mod P). mulmod folds with shifts/masks,
 *     no BigInt `%` in the hot path.
 *   • Lagrange basis at 0 is computed once per reconstruction (O(k) inversions
 *     total) and reused across every chunk. Naïve cost was O(k²) + k inversions
 *     *per chunk*.
 *   • Unbiased field sampling by rejection (no `randomBytes % P` skew).
 *
 *  FORMAT
 *   • Versioned shares (`v:2`); v2 x is always `0x`-prefixed hex. The v1
 *     decimal heuristic is only used for legacy shares.
 *   • Exact `len` metadata + per-chunk width padding ⇒ binary-safe, no
 *     UTF-8 guessing, no NUL stripping, no dropped leading zero bytes.
 *   • Optional SHA-256 `commit` for integrity on reconstruct.
 *
 *  SAFETY (hardened over the patch)
 *   • Duplicate x rejected (old code: modInv(0)=0 ⇒ silent wrong secret).
 *   • x / y range-checked; inconsistent chunk counts rejected.
 *   • Cross-share metadata consistency: threshold / total / len / commit /
 *     binary must agree across ALL supplied shares (the patch only consulted
 *     `first`).
 *   • Constant-time commit comparison via crypto.timingSafeEqual (the patch
 *     used `!==`, a timing oracle).
 */

// ─────────────────────────── constants ───────────────────────────

/** Field prime P = 2^127 − 1 (Mersenne). */
export const P = (1n << 127n) - 1n
/** Chunk size in bytes: 120 bits < 127 bits ⇒ every chunk value < P. */
export const CHUNK_BYTES = 15
/** Current share format version. */
export const FORMAT_V = 2
/** Hard cap on n (share count) to bound work. */
const MAX_N = 200

// ─────────────────────────── types ───────────────────────────

export interface Share {
  v: number
  /** Evaluation point x, `0x`-prefixed hex string for v ≥ 2. */
  x: string
  /** Comma-joined hex y-values, one per chunk. */
  y: string
  threshold: number
  total: number
  chunks: number
  /** Original secret byte length. */
  len: number
  /** Optional SHA-256 of the secret (integrity, NOT a MAC). */
  commit?: string
  /** True when the original secret was a Buffer (affects legacy NUL strip). */
  binary?: boolean
}

export interface SplitOptions {
  /** If true, attach a SHA-256 `commit` to every share. */
  commit?: boolean
}

export type SecretInput = string | Buffer | Uint8Array

export interface ShamirModule {
  split: (secret: SecretInput, n: number, k: number, opts?: SplitOptions) => Share[]
  combine: (shares: Share[]) => Buffer
  combineToString: (shares: Share[]) => string
  splitString: (str: string, n: number, k: number, opts?: SplitOptions) => Share[]
  /** Run known-answer + regression tests. Throws on failure. */
  selfTest: () => { passed: number; cases: string[] }
  P: typeof P
  CHUNK_BYTES: typeof CHUNK_BYTES
  FORMAT_V: typeof FORMAT_V
}

// ─────────────────────────── field arithmetic ───────────────────────────

function mod(a: bigint): bigint {
  a %= P
  return a < 0n ? a + P : a
}

function addmod(a: bigint, b: bigint): bigint {
  const s = a + b
  return s >= P ? s - P : s
}

function submod(a: bigint, b: bigint): bigint {
  const d = a - b
  return d < 0n ? d + P : d
}

/** (a·b) mod P for a,b ∈ [0,P). a·b < 2^254; two folds of 2^127 ≡ 1. */
function mulmod(a: bigint, b: bigint): bigint {
  let t = a * b
  t = (t & P) + (t >> 127n) // < 2^128
  t = (t & P) + (t >> 127n) // < P + 3
  return t >= P ? t - P : t
}

function powmod(a: bigint, e: bigint): bigint {
  let r = 1n
  a = mod(a)
  while (e > 0n) {
    if (e & 1n) r = mulmod(r, a)
    a = mulmod(a, a)
    e >>= 1n
  }
  return r
}

/** Fermat inverse — cheap here because mulmod has no division. */
function modInv(a: bigint): bigint {
  a = mod(a)
  if (a === 0n) throw new Error('modInv(0): duplicate or zero x')
  return powmod(a, P - 2n)
}

/** Uniform in [0, P) by rejection — no modulo bias. ~50% reject rate. */
function randField(): bigint {
  for (;;) {
    const v = BigInt('0x' + crypto.randomBytes(16).toString('hex'))
    if (v < P) return v
  }
}

function randX(): bigint {
  let x: bigint
  do {
    x = randField()
  } while (x === 0n) // x = 0 would leak the secret
  return x
}

// ─────────────────────── Lagrange basis (batch) ─────────────────────────

/**
 * λ_i with f(0) = Σ λ_i·f(x_i) for every deg f < k.
 * Computed once, applied to every chunk.
 */
function lagrangeAtZero(xs: bigint[]): bigint[] {
  const k = xs.length
  const lambdas = new Array<bigint>(k)
  for (let i = 0; i < k; i++) {
    let num = 1n
    let den = 1n
    for (let j = 0; j < k; j++) {
      if (j === i) continue
      num = mulmod(num, submod(0n, xs[j])) // (0 − x_j)
      den = mulmod(den, submod(xs[i], xs[j]))
    }
    lambdas[i] = mulmod(num, modInv(den))
  }
  return lambdas
}

// ─────────────────────────── share encoding ─────────────────────────────

const encodeX = (x: bigint, v: number): string =>
  v >= 2 ? '0x' + x.toString(16) : x.toString(16)

function parseX(s: string, v: number): bigint {
  const t = String(s)
  if (v >= 2) return BigInt(t.startsWith('0x') ? t : '0x' + t)
  // legacy v1: ambiguous heuristic, kept only for old shares
  return /^[0-9]+$/.test(t) ? BigInt(t) : BigInt('0x' + t)
}

// ─────────────────────────── helpers ─────────────────────────────

/** Constant-time hex string equality. Both must be equal-length hex. */
function ctHexEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'hex')
  const bb = Buffer.from(b, 'hex')
  if (ab.length !== bb.length || ab.length === 0) return false
  return crypto.timingSafeEqual(ab, bb)
}

// ──────────────────────────────── split ─────────────────────────────────

function _splitBytes(buf: Buffer, n: number, k: number, opts: SplitOptions = {}): Share[] {
  if (!Number.isInteger(n) || !Number.isInteger(k) || k < 2 || n < k || n > MAX_N) {
    throw new Error(`need integers 2 ≤ k ≤ n ≤ ${MAX_N}`)
  }

  const chunks: Buffer[] = []
  for (let i = 0; i < buf.length; i += CHUNK_BYTES) {
    chunks.push(buf.subarray(i, i + CHUNK_BYTES))
  }
  if (chunks.length === 0) chunks.push(Buffer.alloc(0))

  const xs: bigint[] = []
  const seen = new Set<bigint>()
  while (xs.length < n) {
    const x = randX()
    if (seen.has(x)) continue
    seen.add(x)
    xs.push(x)
  }

  const nChunks = chunks.length
  const shareYs: string[][] = Array.from({ length: n }, () => new Array<string>(nChunks))
  const coeffs = new Array<bigint>(k)

  for (let c = 0; c < nChunks; c++) {
    const chunk = chunks[c]
    const secret = chunk.length ? BigInt('0x' + chunk.toString('hex')) : 0n
    if (secret >= P) throw new Error('chunk value ≥ P')

    coeffs[0] = secret
    for (let i = 1; i < k; i++) coeffs[i] = randField()

    for (let i = 0; i < n; i++) {
      let y = 0n
      const xi = xs[i]
      for (let d = k - 1; d >= 0; d--) y = addmod(mulmod(y, xi), coeffs[d])
      shareYs[i][c] = y.toString(16)
    }
  }

  const commit = opts.commit
    ? crypto.createHash('sha256').update(buf).digest('hex')
    : undefined

  return shareYs.map((ys, i) => {
    const s: Share = {
      v: FORMAT_V,
      x: encodeX(xs[i], FORMAT_V),
      y: ys.join(','),
      threshold: k,
      total: n,
      chunks: nChunks,
      len: buf.length,
    }
    if (commit) s.commit = commit
    return s
  })
}

// ─────────────────────────────── combine ────────────────────────────────

interface ParsedShare {
  x: bigint
  parts: string[]
  v: number
  threshold: number
  total: number
  chunks: number
  len: number | undefined
  commit: string | undefined
  binary: boolean
}

function _combineRaw(shares: Share[], stripLegacyNul: boolean): Buffer {
  if (!Array.isArray(shares) || shares.length === 0) {
    throw new Error('no shares supplied')
  }

  const parsed: ParsedShare[] = shares.map((s) => {
    if (!s || s.x === undefined || s.y === undefined) throw new Error('malformed share')
    const v = Number(s.v) || 1
    return {
      x: parseX(s.x, v),
      parts: String(s.y).split(','),
      v,
      threshold: Number(s.threshold),
      total: Number(s.total),
      chunks: Number(s.chunks),
      len: Number.isInteger(s.len) ? s.len : undefined,
      commit: s.commit,
      binary: Boolean(s.binary),
    }
  })

  // Cross-share metadata consistency (hardened: patch only used `first`).
  const ref = parsed[0]
  for (const p of parsed) {
    if (p.threshold && p.threshold !== ref.threshold) {
      throw new Error('inconsistent threshold across shares')
    }
    if (p.total && p.total !== ref.total) {
      throw new Error('inconsistent total across shares')
    }
    if (p.binary !== ref.binary) {
      throw new Error('inconsistent binary flag across shares')
    }
    if (p.commit !== ref.commit) {
      throw new Error('inconsistent commit across shares')
    }
  }

  const k = ref.threshold || parsed.length
  if (parsed.length < k) {
    throw new Error(`need ${k} shares, got ${parsed.length}`)
  }

  const use = parsed.slice(0, k)

  const seen = new Set<bigint>()
  for (const u of use) {
    if (u.x <= 0n || u.x >= P) throw new Error('x out of range')
    if (seen.has(u.x)) throw new Error('duplicate x-values among shares')
    seen.add(u.x)
  }

  const nChunks = use[0].parts.length
  for (const u of use) {
    if (u.parts.length !== nChunks) throw new Error('inconsistent chunk count')
  }

  const lambdas = lagrangeAtZero(use.map((u) => u.x))

  const useLen = Number.isInteger(ref.len)
  const refLen = ref.len ?? 0
  const out: Buffer[] = new Array(nChunks)

  for (let c = 0; c < nChunks; c++) {
    let secret = 0n
    for (let i = 0; i < k; i++) {
      const raw = use[i].parts[c]
      const yi = BigInt('0x' + (raw === '' ? '0' : raw))
      if (yi >= P) throw new Error('y out of range')
      secret = addmod(secret, mulmod(lambdas[i], yi))
    }
    let hex = secret.toString(16)
    if (useLen) {
      // pad to the chunk's ORIGINAL width so leading 0x00 bytes survive (#7 fix)
      const chunkBytes = Math.min(CHUNK_BYTES, refLen - c * CHUNK_BYTES)
      hex = chunkBytes <= 0 ? '' : hex.padStart(2 * chunkBytes, '0')
    } else if (hex.length & 1) {
      hex = '0' + hex
    }
    out[c] = hex.length ? Buffer.from(hex, 'hex') : Buffer.alloc(0)
  }

  let buf = Buffer.concat(out)

  if (useLen) {
    if (refLen > buf.length) throw new Error('len metadata exceeds data')
    buf = buf.subarray(0, refLen)
  } else if (stripLegacyNul) {
    let end = buf.length
    while (end > 0 && buf[end - 1] === 0) end--
    buf = buf.subarray(0, end)
  }

  // Constant-time integrity check (hardened: patch used `!==`).
  if (ref.commit) {
    const h = crypto.createHash('sha256').update(buf).digest('hex')
    if (!ctHexEqual(h, ref.commit)) throw new Error('integrity check failed')
  }
  return buf
}

// ─────────────────────────────── public API ─────────────────────────────

function toBuffer(secret: SecretInput): { buf: Buffer; isBuf: boolean } {
  if (Buffer.isBuffer(secret)) return { buf: secret, isBuf: true }
  if (secret instanceof Uint8Array) {
    return { buf: Buffer.from(secret), isBuf: true }
  }
  return { buf: Buffer.from(String(secret), 'utf8'), isBuf: false }
}

function split(secret: SecretInput, n: number, k: number, opts?: SplitOptions): Share[] {
  const { buf, isBuf } = toBuffer(secret)
  const shares = _splitBytes(buf, n, k, opts)
  for (const s of shares) s.binary = isBuf
  return shares
}

function splitString(str: string, n: number, k: number, opts?: SplitOptions): Share[] {
  const shares = _splitBytes(Buffer.from(String(str), 'utf8'), n, k, opts)
  for (const s of shares) s.binary = false
  return shares
}

function combine(shares: Share[]): Buffer {
  const bin = Boolean(shares[0]?.binary)
  return _combineRaw(shares, !bin)
}

function combineToString(shares: Share[]): string {
  return _combineRaw(shares, true).toString('utf8')
}

// ─────────────────────────────── self-test ──────────────────────────────

/** Deterministic PRNG-seeded field sampler, for reproducible KAT. */
function detField(seed: { s: bigint }): bigint {
  // x_i = (a·seed + c) mod P  — a simple LCG over the field, good enough for KAT.
  seed.s = mod(seed.s * 6364136223846793005n + 1442695040888963407n)
  if (seed.s === 0n) seed.s = 1n
  return seed.s
}

function selfTest(): { passed: number; cases: string[] } {
  const cases: string[] = []
  let passed = 0
  const expect = (name: string, cond: boolean) => {
    if (cond) {
      passed++
      cases.push(`✓ ${name}`)
    } else {
      cases.push(`✗ ${name}`)
      throw new Error(`self-test failed: ${name}`)
    }
  }

  // 1. Basic string round-trip.
  {
    const shares = splitString('the eagle flies at midnight', 5, 3)
    const rec = combineToString(shares.slice(0, 3))
    expect('string round-trip k=3', rec === 'the eagle flies at midnight')
  }

  // 2. Any k of n reconstructs.
  {
    const shares = splitString('hello world', 5, 3)
    const a = combineToString([shares[0], shares[2], shares[4]])
    const b = combineToString([shares[1], shares[3], shares[0]])
    expect('any-k-of-n subset A', a === 'hello world')
    expect('any-k-of-n subset B', b === 'hello world')
  }

  // 3. k−1 shares reveal nothing (deterministically: cannot equal secret).
  {
    const shares = splitString('topsecret', 5, 3)
    let leaked = false
    try {
      combineToString([shares[0], shares[1]]) // only 2 of 3
    } catch {
      leaked = true
    }
    expect('k−1 shares rejected', leaked)
  }

  // 4. Regression #7: 16-byte secret with 0x00 at offset 15 (chunk boundary).
  {
    const buf = Buffer.alloc(16)
    for (let i = 0; i < 16; i++) buf[i] = i // 00 01 02 ... 0F
    const shares = split(buf, 5, 3)
    const rec = combine(shares.slice(0, 3))
    expect('#7 leading-zero-byte at boundary (len)', rec.length === 16)
    expect('#7 bytes match', rec.equals(buf))
  }

  // 5. Regression #7 variant: a chunk beginning with 0x00 mid-secret.
  {
    const buf = Buffer.from([0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x00, 0x11, 0x22])
    const shares = split(buf, 5, 3)
    const rec = combine(shares.slice(0, 3))
    expect('#7 mid-secret NUL preserved', rec.equals(buf))
  }

  // 6. All-zero secret (every chunk is 0x00).
  {
    const buf = Buffer.alloc(31)
    const shares = split(buf, 5, 3)
    const rec = combine(shares.slice(0, 3))
    expect('all-zero secret round-trips', rec.equals(buf))
  }

  // 7. Empty secret.
  {
    const shares = splitString('', 3, 2)
    const rec = combineToString(shares)
    expect('empty secret round-trips', rec === '')
  }

  // 8. Unicode / multi-byte UTF-8.
  {
    const s = '🔑 secret 密钥 セキュア 🔐'
    const shares = splitString(s, 5, 3)
    const rec = combineToString(shares.slice(0, 3))
    expect('unicode round-trips', rec === s)
  }

  // 9. Commit integrity: valid commit passes.
  {
    const shares = splitString('commit me', 3, 2, { commit: true })
    const rec = combineToString(shares.slice(0, 2))
    expect('commit valid passes', rec === 'commit me')
  }

  // 10. Commit integrity: tampered y fails (constant-time check).
  {
    const shares = splitString('commit me', 3, 2, { commit: true })
    const tampered: Share = { ...shares[0] }
    // flip a hex digit in the first chunk's y
    const parts = tampered.y.split(',')
    parts[0] = parts[0].length ? (parts[0][0] === '0' ? '1' : '0') + parts[0].slice(1) : '1'
    tampered.y = parts.join(',')
    let failed = false
    try {
      combineToString([tampered, shares[1]])
    } catch (e) {
      failed = (e as Error).message === 'integrity check failed'
    }
    expect('commit tamper detected', failed)
  }

  // 11. Duplicate x rejected.
  {
    const shares = splitString('dup check', 3, 2)
    let rejected = false
    try {
      combineToString([shares[0], { ...shares[0] }]) // same x twice
    } catch {
      rejected = true
    }
    expect('duplicate x rejected', rejected)
  }

  // 12. Cross-share commit consistency (hardened).
  {
    const a = splitString('x', 3, 2, { commit: true })
    const b = splitString('y', 3, 2, { commit: true })
    let rejected = false
    try {
      combineToString([a[0], b[1]]) // different secrets ⇒ different commits
    } catch (e) {
      rejected = (e as Error).message === 'inconsistent commit across shares'
    }
    expect('cross-share commit mismatch rejected', rejected)
  }

  // 13. Large secret (1 KiB) round-trips.
  {
    const buf = Buffer.alloc(1024)
    for (let i = 0; i < 1024; i++) buf[i] = (i * 7 + 3) & 0xff
    const shares = split(buf, 6, 4)
    const rec = combine(shares.slice(0, 4))
    expect('1 KiB binary round-trips', rec.equals(buf))
  }

  // 14. Deterministic Lagrange reference check.
  {
    // Build a polynomial by hand: f(x) = secret + a1·x over GF(P), k=2.
    const seed = { s: 12345n }
    const secret = detField(seed)
    const a1 = detField(seed)
    const x0 = detField(seed)
    const x1 = detField(seed)
    const f = (x: bigint) => addmod(secret, mulmod(a1, x))
    const s0: Share = { v: 2, x: '0x' + x0.toString(16), y: f(x0).toString(16), threshold: 2, total: 2, chunks: 1, len: 15 }
    const s1: Share = { v: 2, x: '0x' + x1.toString(16), y: f(x1).toString(16), threshold: 2, total: 2, chunks: 1, len: 15 }
    // combine recovers f(0) = secret, padded to 15 bytes
    const rec = combine([s0, s1])
    const recVal = BigInt('0x' + rec.toString('hex'))
    expect('Lagrange recovers f(0)', recVal === secret)
  }

  expect('self-test completed', true)
  return { passed, cases }
}

// ─────────────────────────────── exports ────────────────────────────────

export const shamir: ShamirModule = {
  split,
  combine,
  splitString,
  combineToString,
  selfTest,
  P,
  CHUNK_BYTES,
  FORMAT_V,
}

export { split, combine, splitString, combineToString, selfTest }

/** Internal helpers exported for the polynomial-visualization API only. */
export const _internals = { lagrangeAtZero, mulmod, addmod, submod, mod, powmod, modInv, randField, randX, P, CHUNK_BYTES }
