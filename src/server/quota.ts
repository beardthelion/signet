/**
 * Storage caps (PS-081).
 *
 * The spec bounds every section, every entry, and the namespace total so a
 * passport stays a bounded envelope rather than arbitrary file storage. The
 * defaults below are the spec values; PASSPORT_CAP_* env vars retune them for
 * a deployment. (The spec's section "floors" are the minimums a conformant
 * store must allow — a deployment SHOULD NOT set a cap below the spec
 * default. Tests deliberately set tiny caps.)
 *
 * Per-entry overage is a per-key skip (the caller is told, never a silent
 * drop); per-section and per-namespace overage fails the whole write before
 * any byte lands, because a partial commit there would be a cap breach.
 */

import type { Section } from '../types/index.ts'
import { envInt } from './env.ts'

const KiB = 1024
const MiB = 1024 * KiB

export const caps = {
  /** Ciphertext bytes any single entry may hold. */
  entry: envInt('PASSPORT_CAP_ENTRY', 1 * MiB),
  /** Ciphertext bytes per section, summed over that section's entries. */
  sections: {
    memory: envInt('PASSPORT_CAP_MEMORY', 5 * MiB),
    config: envInt('PASSPORT_CAP_CONFIG', 1 * MiB),
    sessions: envInt('PASSPORT_CAP_SESSIONS', 20 * MiB),
    grants: envInt('PASSPORT_CAP_GRANTS', 512 * KiB),
    identity: envInt('PASSPORT_CAP_IDENTITY', 256 * KiB),
  } as Record<Section, number>,
  /** Total ciphertext bytes in one namespace. */
  total: envInt('PASSPORT_CAP_TOTAL', 30 * MiB),
  /** Gateway cap on a whole PUT body (base64 inflates ciphertext ~4/3). */
  body: envInt('PASSPORT_MAX_BODY_BYTES', 48 * MiB),
} as const

/** Thrown when a projected write would exceed a cap. Surfaces as HTTP 413. */
export class QuotaError extends Error {
  readonly code: string
  readonly details: Record<string, unknown>
  constructor(code: string, message: string, details: Record<string, unknown>) {
    super(message)
    this.name = 'QuotaError'
    this.code = code
    this.details = details
  }
}

/** The section an entry key lives in. Callers must validate the key first. */
export function sectionOf(key: string): Section {
  return key.split('/', 1)[0] as Section
}

/**
 * Enforce per-section and per-namespace byte caps against a projected
 * post-write manifest (`entryKey -> {size}`). Runs after per-entry checks but
 * BEFORE any store write, so an over-cap request leaves the namespace
 * untouched — the all-or-nothing half of PS-081.
 */
export function checkProjectedCaps(entries: Record<string, { size: number }>): void {
  const sectionBytes = new Map<Section, number>()
  let total = 0
  for (const [key, meta] of Object.entries(entries)) {
    const section = sectionOf(key)
    sectionBytes.set(section, (sectionBytes.get(section) ?? 0) + meta.size)
    total += meta.size
  }
  for (const [section, bytes] of sectionBytes) {
    const cap = caps.sections[section]
    if (cap !== undefined && bytes > cap) {
      throw new QuotaError('section_cap_exceeded', `section "${section}" exceeds its cap`, {
        section,
        bytes,
        max_bytes: cap,
      })
    }
  }
  if (total > caps.total) {
    throw new QuotaError('namespace_too_large', 'namespace storage limit reached', {
      bytes: total,
      max_bytes: caps.total,
    })
  }
}
