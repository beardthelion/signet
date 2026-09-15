/**
 * Cap enforcement (PS-081).
 *
 * Caps come from tests/setup.ts and are small on purpose:
 *   PASSPORT_CAP_ENTRY=1024   PASSPORT_CAP_MEMORY=1024  PASSPORT_CAP_CONFIG=512
 *   PASSPORT_CAP_SESSIONS=4096  PASSPORT_CAP_GRANTS=256  PASSPORT_CAP_IDENTITY=512
 *   PASSPORT_CAP_TOTAL=3000 (below the section-cap sum, so it can bind)
 *
 * The two tiers matter: an oversized ENTRY is reported in `skipped` while the
 * rest of the write commits; a section or namespace-total breach fails the
 * WHOLE write before any byte lands — asserted here by re-reading the
 * namespace afterwards.
 */

import { describe, expect, test } from 'bun:test'
import { authed, blob, identity, mustToken, nsPath } from './setup.ts'

type PutResult = {
  accepted: string[]
  skipped: { key: string; reason: string }[]
}

async function put(token: string, ns: string, entries: Record<string, string>) {
  const res = await authed(token, 'PUT', nsPath(ns), { entries })
  const body = (await res.json()) as PutResult & { error?: { code: string } }
  return { status: res.status, body }
}

async function hashKeys(token: string, ns: string): Promise<string[]> {
  const res = await authed(token, 'GET', `${nsPath(ns)}?view=hashes`)
  if (res.status === 404) return []
  return Object.keys((await res.json()) as Record<string, string>).sort()
}

describe('per-entry cap -> skipped, never silently dropped', () => {
  const id = identity('quota-entry')

  test('an oversized entry is skipped while valid entries commit', async () => {
    const token = await mustToken(id)
    const { status, body } = await put(token, id.namespace, {
      'memory/big.md': blob(1500), // over PASSPORT_CAP_ENTRY=1024
      'memory/ok.md': blob(10),
    })
    expect(status).toBe(200)
    expect(body.accepted).toEqual(['memory/ok.md'])
    expect(body.skipped).toEqual([{ key: 'memory/big.md', reason: 'entry_too_large' }])
    expect(await hashKeys(token, id.namespace)).toEqual(['memory/ok.md'])
  })
})

describe('per-section caps -> all-or-nothing 413', () => {
  const id = identity('quota-section')

  test('exceeding the memory cap fails the whole write', async () => {
    const token = await mustToken(id)
    const { status, body } = await put(token, id.namespace, {
      'memory/a.md': blob(700),
      'memory/b.md': blob(700), // 1400 total > PASSPORT_CAP_MEMORY=1024
    })
    expect(status).toBe(413)
    expect(body.error?.code).toBe('section_cap_exceeded')
    // All-or-nothing: NOTHING from that request landed.
    expect(await hashKeys(token, id.namespace)).toEqual([])
  })

  test('section caps are independent', async () => {
    const token = await mustToken(id)
    // 700 of memory + 400 of config: each under its own cap, 1100 < total.
    const { status } = await put(token, id.namespace, {
      'memory/a.md': blob(700),
      'config/c.json': blob(400),
    })
    expect(status).toBe(200)
  })

  test('each section enforces its own ceiling', async () => {
    const gid = identity('quota-section-grants')
    const token = await mustToken(gid)
    const { status, body } = await put(token, gid.namespace, {
      'grants/g1.json': blob(300), // over PASSPORT_CAP_GRANTS=256
    })
    expect(status).toBe(413)
    expect(body.error?.code).toBe('section_cap_exceeded')
  })
})

describe('namespace total cap -> all-or-nothing 413', () => {
  const id = identity('quota-total')

  test('a write that would cross the total cap commits nothing', async () => {
    const token = await mustToken(id)
    // 900 + 900 + 900 = 2700 bytes, under PASSPORT_CAP_TOTAL=3000 and under
    // every per-section cap.
    const first = await put(token, id.namespace, {
      'memory/a.md': blob(900),
      'sessions/s/000001': blob(900),
      'sessions/s/000002': blob(900),
    })
    expect(first.status).toBe(200)

    // +900 more: sessions 2700 < 4096 section cap, but 3600 > 3000 total.
    const over = await put(token, id.namespace, { 'sessions/s/000003': blob(900) })
    expect(over.status).toBe(413)
    expect(over.body.error?.code).toBe('namespace_too_large')

    // The refused write left the namespace exactly as the accepted one did.
    expect(await hashKeys(token, id.namespace)).toEqual([
      'memory/a.md',
      'sessions/s/000001',
      'sessions/s/000002',
    ])
  })
})
