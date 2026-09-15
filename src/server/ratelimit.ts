/**
 * Per-identity token-bucket rate limiter (in-memory — single machine, like the
 * locks in lock.ts; a multi-instance deployment would need a shared store).
 * Refills at `perMinute` tokens/min up to `burst` capacity. Each request costs
 * one token.
 *
 * Buckets are keyed by request DID, or by the shared 'anonymous' bucket before
 * authentication, so unauthenticated abuse cannot throttle authenticated
 * holders and each holder gets its own allowance.
 *
 * Time is injected so it's deterministic to test; the handler passes
 * Date.now().
 */

function envInt(name: string, fallback: number): number {
  const raw = process.env[name]
  if (raw === undefined || raw.trim() === '') return fallback
  const n = Number(raw)
  return Number.isFinite(n) ? n : fallback
}

const perMinute = envInt('PASSPORT_RATE_PER_MINUTE', 240)
const CAP = envInt('PASSPORT_RATE_BURST', 480)
const REFILL_PER_MS = perMinute / 60_000

type Bucket = { tokens: number; updatedAt: number }

const buckets = new Map<string, Bucket>()

export type RateResult = { ok: boolean; retryAfterSec: number }

/**
 * Consume one token for `key` (a request DID or 'anonymous'). Returns
 * ok=false with a Retry-After hint when the bucket is empty.
 * `perMinute <= 0` disables limiting entirely.
 */
export function take(key: string, now: number): RateResult {
  if (perMinute <= 0) return { ok: true, retryAfterSec: 0 }

  let b = buckets.get(key)
  if (!b) {
    b = { tokens: CAP, updatedAt: now }
    buckets.set(key, b)
  } else {
    const refill = (now - b.updatedAt) * REFILL_PER_MS
    if (refill > 0) {
      b.tokens = Math.min(CAP, b.tokens + refill)
      b.updatedAt = now
    }
  }

  if (b.tokens >= 1) {
    b.tokens -= 1
    return { ok: true, retryAfterSec: 0 }
  }
  // Seconds until one token is available again.
  const retryAfterSec = Math.max(1, Math.ceil((1 - b.tokens) / REFILL_PER_MS / 1000))
  return { ok: false, retryAfterSec }
}

/**
 * Drop every bucket. Tests only: buckets are in-process and bun shares one
 * process across test files, so a test that exhausts a bucket would otherwise
 * refuse requests in every later suite.
 */
export function _reset(): void {
  buckets.clear()
}
