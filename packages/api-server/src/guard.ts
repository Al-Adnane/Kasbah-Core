// guard.ts — dependency-free per-IP token bucket rate limiter
//
// In-memory (single-instance). For multi-instance deployment, replace with
// Redis-backed rate limiting (see SECURITY.md).
//
// Usage in a route:
//   import { rateLimit, LIMITS } from '@/lib/guard'
//   const limited = rateLimit(req, LIMITS.SPLIT) // 20/min
//   if (limited) return limited
//
import { NextRequest, NextResponse } from 'next/server'

interface Bucket {
  tokens: number
  lastRefill: number
}

interface LimitConfig {
  /** Maximum tokens (requests) per window. */
  max: number
  /** Window in milliseconds. */
  windowMs: number
}

/** Graduated limits: expensive ops are stricter. */
export const LIMITS = {
  /** Split / refresh — heavy modexp, 20/min. */
  SPLIT: { max: 20, windowMs: 60_000 },
  /** Combine — Lagrange + verify, 30/min. */
  COMBINE: { max: 30, windowMs: 60_000 },
  /** Verify — lighter, 60/min. */
  VERIFY: { max: 60, windowMs: 60_000 },
  /** Prove — OR-Sigma, 30/min. */
  PROVE: { max: 30, windowMs: 60_000 },
  /** Fuzzy auth — range proof (heavy), 15/min. */
  FUZZY: { max: 15, windowMs: 60_000 },
  /** Default for misc POSTs. */
  DEFAULT: { max: 60, windowMs: 60_000 },
} as const

const buckets = new Map<string, Bucket>()

// Periodic cleanup to prevent memory growth from stale IPs.
const CLEANUP_INTERVAL = 5 * 60_000 // 5 min
let lastCleanup = Date.now()

function cleanup() {
  const now = Date.now()
  if (now - lastCleanup < CLEANUP_INTERVAL) return
  lastCleanup = now
  // Drop buckets that haven't been touched in 2x the longest window.
  const staleThreshold = now - 120_000
  for (const [key, bucket] of buckets) {
    if (bucket.lastRefill < staleThreshold) buckets.delete(key)
  }
}

/** Extract client IP from request, respecting X-Forwarded-For. */
function getClientIP(req: NextRequest): string {
  const xff = req.headers.get('x-forwarded-for')
  if (xff) return xff.split(',')[0].trim()
  const xreal = req.headers.get('x-real-ip')
  if (xreal) return xreal.trim()
  return '127.0.0.1'
}

/**
 * Check rate limit. Returns a 429 NextResponse if limited, null otherwise.
 * Call this at the top of your route handler:
 *
 *   const limited = rateLimit(req, LIMITS.SPLIT)
 *   if (limited) return limited
 */
export function rateLimit(req: NextRequest, config: LimitConfig): NextResponse | null {
  cleanup()
  const ip = getClientIP(req)
  const key = `${ip}:${config.max}:${config.windowMs}`
  const now = Date.now()

  const bucket = buckets.get(key)
  if (bucket && now - bucket.lastRefill < config.windowMs) {
    if (bucket.tokens <= 0) {
      return new NextResponse(
        JSON.stringify({ error: 'rate limited', limit: config.max, windowMs: config.windowMs }),
        { status: 429, headers: { 'Content-Type': 'application/json' } }
      )
    }
    bucket.tokens -= 1
    return null
  }

  // Refill bucket (future-proof: no use of possibly-undefined `bucket`)
  const fresh = { tokens: config.max, lastRefill: now };
  buckets.set(key, fresh);
  fresh.tokens -= 1;
  return null;
}
