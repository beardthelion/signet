/**
 * Token-bucket rate limiter tests.
 *
 * Time is injected so burst, refill, and idle eviction are all deterministic:
 * the limiter refills at PASSPORT_RATE_PER_MINUTE (240 in test env = 4/sec),
 * caps each bucket at PASSPORT_RATE_BURST (480), and evicts buckets idle for
 * three full refill windows. The hard ceiling refuses NEW keys once the map
 * is full without touching the keys already tracked.
 */

import { describe, expect, test } from 'bun:test'
import { take } from '../src/server/ratelimit.ts'

// Env is frozen by tests/setup.ts before this module loads: perMinute=240
// (4 tokens/sec), burst=480.

describe('bucket basics', () => {
  test('a burst up to capacity is allowed, then requests are refused', () => {
    const key = 'rl-burst'
    const t0 = Date.now()
    // A fresh bucket holds CAP tokens; burning through them must eventually
    // refuse with a Retry-After hint.
    let refused: { ok: boolean; retryAfterSec: number } | null = null
    for (let i = 0; i < 481; i++) {
      const r = take(key, t0)
      if (!r.ok) {
        refused = r
        break
      }
    }
    expect(refused).not.toBeNull()
    expect(refused!.retryAfterSec).toBeGreaterThan(0)
  })

  test('an exhausted bucket refills over time', () => {
    const key = 'rl-refill'
    const t0 = Date.now()
    for (let i = 0; i < 480; i++) expect(take(key, t0).ok).toBe(true)
    expect(take(key, t0).ok).toBe(false)
    // 4 tokens/sec -> 1 second buys back 4 requests.
    for (let i = 0; i < 4; i++) expect(take(key, t0 + 1000).ok).toBe(true)
    expect(take(key, t0 + 1000).ok).toBe(false)
  })

  test('a bucket idle for three refill windows refills fully again', () => {
    const key = 'rl-evict'
    const t0 = Date.now()
    expect(take(key, t0).ok).toBe(true)
    // Burn the bucket almost dry.
    for (let i = 0; i < 479; i++) take(key, t0)
    // One refill window is 120 s (480 tokens at 4/sec); three windows idle
    // makes the bucket eligible for eviction — and either way it must
    // answer with a full allowance again.
    const later = t0 + 400_000
    for (let i = 0; i < 480; i++) expect(take(key, later).ok).toBe(true)
    expect(take(key, later).ok).toBe(false)
  })

  test('idle buckets are swept once the map is large, and a new key still works', () => {
    const t0 = Date.now()
    // Above EVICT_THRESHOLD (4096): the next take() must run the idle sweep,
    // and it must not refuse a fresh key whose own bucket is new.
    for (let i = 0; i < 5000; i++) take(`rl-idle-${i}`, t0)
    // All 5000 are idle past three refill windows at this later instant;
    // the sweep clears them and the trigger key gets a full bucket.
    const later = t0 + 400_000
    expect(take('rl-sweep', later).ok).toBe(true)
    for (let i = 0; i < 479; i++) expect(take('rl-sweep', later).ok).toBe(true)
    expect(take('rl-sweep', later).ok).toBe(false)
  })

  test('distinct keys get independent buckets', () => {
    const t0 = Date.now()
    for (let i = 0; i < 480; i++) take('rl-isolated-a', t0)
    expect(take('rl-isolated-a', t0).ok).toBe(false)
    expect(take('rl-isolated-b', t0).ok).toBe(true)
  })
})
