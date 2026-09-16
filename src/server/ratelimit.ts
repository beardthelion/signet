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
 * The bucket map cannot grow without bound: entries idle for a few full
 * refill windows are evicted, which is unobservable because a bucket that
 * idle has already refilled to CAP anyway.
 *
 * Time is injected so it's deterministic to test; the handler passes
 * Date.now().
 */

import { envInt } from './env.ts'

const perMinute = envInt('PASSPORT_RATE_PER_MINUTE', 240)
const CAP = envInt('PASSPORT_RATE_BURST', 480)
const REFILL_PER_MS = perMinute / 60_000

/** Time for an empty bucket to refill to capacity — one refill window. */
const REFILL_WINDOW_MS = perMinute > 0 ? CAP / REFILL_PER_MS : 0
/** Buckets idle this long have certainly refilled to CAP; safe to drop. */
const IDLE_EVICT_MS = REFILL_WINDOW_MS * 3
/** Sweep for idle buckets only once the map is large enough to matter. */
const EVICT_THRESHOLD = 4096
/**
 * Hard ceiling on the bucket map. Idle eviction keeps the steady state
 * small; this is the stop-loss for a flood of distinct keys inside one idle
 * window — past it, NEW keys are refused rather than growing the map without
 * bound. Known keys keep their buckets.
 */
const MAX_BUCKETS = 100_000

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

  if (buckets.size > EVICT_THRESHOLD) {
    for (const [k, b] of buckets) {
      if (now - b.updatedAt > IDLE_EVICT_MS) buckets.delete(k)
    }
  }

  let b = buckets.get(key)
  if (!b) {
    if (buckets.size >= MAX_BUCKETS) {
      // Refusing a fresh key under map pressure must not throttle the keys
      // already tracked; this new caller is simply told to slow down.
      return { ok: false, retryAfterSec: 60 }
    }
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
