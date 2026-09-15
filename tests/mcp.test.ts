/**
 * MCP adapter tests: tools.ts is driven transport-free against a real
 * PassportClient wired to an in-process stub of the wire contract (SPEC §7),
 * so every tool call goes through the actual encrypt -> HTTP -> ciphertext
 * -> decrypt path with no socket and no stdio.
 *
 * Covered: save/recall round-trip, search, list, delete, config_get/set with
 * the PS-070 denylist, grant_list/grant_record with the PS-062 confirmation
 * gate and the PS-061 no-application guarantee, the secret-scan refusal
 * (PS-110), the ciphertext-only store boundary (PS-034), and stdout protocol
 * integrity: no tool path may write to stdout, which is the MCP channel.
 */

import { afterEach, describe, expect, spyOn, test } from 'bun:test'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { MANIFEST_ENTRY_KEY, PassportClient, PassportHttpError } from '../src/client/client.ts'
import { generateIdentity, verifyDidSignature } from '../src/client/identity.ts'
import { makeTools, type PassportToolClient } from '../src/mcp/tools.ts'

// ─── In-process wire stub ───────────────────────────────────────────────

function sha256Prefixed(bytes: Uint8Array): string {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`
}

function stubManifestHash(hashes: Record<string, string>): string {
  const lines = Object.keys(hashes)
    .sort()
    .map(k => `${k}\t${hashes[k]}`)
    .join('\n')
  return `sha256:${createHash('sha256').update(lines).digest('hex')}`
}

const json = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
const apiError = (code: string, status: number) => json({ error: { code, message: code } }, status)

/**
 * A minimal but honest store: challenge/verify auth (signatures really are
 * verified), the hashes and integrity views, single-entry reads, and a delta
 * upsert honoring the base precondition and deletions. Everything stored is
 * the ciphertext blob exactly as it arrived — which is what lets the leak
 * test below read it all back.
 */
function makeStub() {
  const manifests = new Map<string, Map<string, { hash: string; size: number }>>()
  const blobs = new Map<string, Buffer>() // `${ns}|${hash}` -> ciphertext
  const nonces = new Set<string>()
  const tokens = new Set<string>()
  let counter = 0

  const entryRead = (ns: string, key: string): Response => {
    const m = manifests.get(ns)
    if (!m) return apiError('empty', 404)
    const meta = m.get(key)
    if (!meta) return apiError('entry_not_found', 404)
    const bytes = blobs.get(`${ns}|${meta.hash}`)
    if (!bytes) return apiError('entry_unreadable', 503)
    return json({ namespace: ns, key, entry: bytes.toString('base64'), hash: meta.hash })
  }

  const fetchFn = async (input: string | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input))
    const path = url.pathname
    const method = init?.method ?? 'GET'
    const body = init?.body ? JSON.parse(String(init.body)) : undefined

    if (path === '/auth/challenge' && method === 'POST') {
      const nonce = `nonce-${++counter}`
      nonces.add(nonce)
      return json({ nonce, expiresAt: new Date(Date.now() + 120_000).toISOString() })
    }
    if (path === '/auth/verify' && method === 'POST') {
      const { did, nonce, sig } = body as { did: string; nonce: string; sig: string }
      if (!nonces.delete(nonce)) return apiError('invalid_nonce', 401)
      if (!verifyDidSignature(did, new TextEncoder().encode(nonce), sig)) {
        return apiError('invalid_signature', 401)
      }
      const token = `tok-${++counter}`
      tokens.add(token)
      return json({ token, expiresAt: new Date(Date.now() + 600_000).toISOString() })
    }

    if (!path.startsWith('/passport/')) return apiError('not_found', 404)
    const auth = /Bearer\s+(.+)/.exec(
      String((init?.headers as Record<string, string>)?.authorization ?? ''),
    )
    if (!auth || !tokens.has(auth[1]!)) return apiError('unauthorized', 401)

    const rest = decodeURIComponent(path.slice('/passport/'.length))
    const slash = rest.indexOf('/')
    const ns = slash === -1 ? rest : rest.slice(0, slash)
    const entryKey = slash === -1 ? null : rest.slice(slash + 1)

    if (method === 'GET') {
      if (entryKey !== null) return entryRead(ns, entryKey)
      const view = url.searchParams.get('view')
      const m = manifests.get(ns)
      if (view === 'hashes') {
        if (!m) return apiError('empty', 404)
        return json(Object.fromEntries([...m.entries()].map(([k, v]) => [k, v.hash])))
      }
      if (view === 'integrity') return entryRead(ns, MANIFEST_ENTRY_KEY)
      if (!m) return apiError('empty', 404)
      return json({ namespace: ns, base: stubManifestHash({}), entries: {} })
    }

    if (method === 'PUT' && entryKey === null) {
      const m = manifests.get(ns) ?? new Map<string, { hash: string; size: number }>()
      const currentHashes = Object.fromEntries([...m.entries()].map(([k, v]) => [k, v.hash]))
      if (body.base !== undefined) {
        const expected = body.base === null ? stubManifestHash({}) : body.base
        if (expected !== stubManifestHash(currentHashes)) {
          return apiError('stale_base', 409)
        }
      }
      const accepted: string[] = []
      const deleted: string[] = []
      for (const key of (body.deletions as string[] | undefined) ?? []) {
        if (m.delete(key)) deleted.push(key)
      }
      for (const [key, b64] of Object.entries(body.entries as Record<string, string>)) {
        const bytes = Buffer.from(b64, 'base64')
        const hash = sha256Prefixed(bytes)
        blobs.set(`${ns}|${hash}`, bytes)
        m.set(key, { hash, size: bytes.byteLength })
        accepted.push(key)
      }
      manifests.set(ns, m)
      const nextHashes = Object.fromEntries([...m.entries()].map(([k, v]) => [k, v.hash]))
      return json({
        namespace: ns,
        base: stubManifestHash(nextHashes),
        accepted,
        deleted,
        skipped: [],
      })
    }
    return apiError('method_not_allowed', 405)
  }

  return {
    fetchFn: fetchFn as typeof fetch,
    /** Every ciphertext byte the store holds — for the leak-boundary test. */
    allCiphertext(): string {
      return [...blobs.values()].map(b => b.toString('utf8')).join('\n')
    },
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────

const PASS = 'mcp test passphrase'

function rig() {
  const stub = makeStub()
  const id = generateIdentity()
  const client = new PassportClient({
    url: 'http://stub',
    fetchFn: stub.fetchFn,
    identity: id,
    passphrase: PASS,
  })
  const synced: number[] = []
  const tools = makeTools(client, {
    holderDid: id.did,
    onSync: () => {
      synced.push(client.manifestSeq)
    },
  })
  return { stub, id, client, tools, synced }
}

/**
 * The real client must satisfy the structural type the tools take. If it
 * drifts (a renamed method, a changed signature), this assignment is a
 * type-check error rather than a test that silently exercises a contract
 * nobody ships.
 */
export const clientSatisfiesToolClient: PassportToolClient = null as unknown as PassportClient

// ─── Round trips ────────────────────────────────────────────────────────

describe('passport tools over the real encrypted wire path', () => {
  test('save then recall returns the entry', async () => {
    const { tools } = rig()
    const saved = await tools.save(
      'memory/deploy.md',
      '---\ntype: note\nprovenance: test\n---\nDeploys go to Fly region sin.\n',
    )
    expect(saved.isError).toBeUndefined()
    expect(saved.text).toContain('saved')

    const r = await tools.recall('where does the project deploy')
    expect(r.isError).toBeUndefined()
    expect(r.text).toContain('memory/deploy.md')
    expect(r.text).toContain('Fly')
  })

  test('search finds entries by key and by content', async () => {
    const { tools } = rig()
    await tools.save('memory/prefs.md', 'The user prefers terse answers.\n')
    await tools.save('config/settings.json', '{"model":"m"}\n')

    const byContent = await tools.search('terse')
    expect(byContent.text).toContain('memory/prefs.md')
    const byKey = await tools.search('settings')
    expect(byKey.text).toContain('config/settings.json')
    const miss = await tools.search('nonexistent-needle')
    expect(miss.text).toContain('no matches')
  })

  test('list enumerates keys, and the section filter narrows it', async () => {
    const { tools } = rig()
    await tools.save('memory/a.md', 'a\n')
    await tools.configSet('settings.json', '{"x":1}\n')

    const all = await tools.list()
    expect(all.text).toContain('memory/a.md')
    expect(all.text).toContain('config/settings.json')

    const memoryOnly = await tools.list('memory')
    expect(memoryOnly.text).toContain('memory/a.md')
    expect(memoryOnly.text).not.toContain('config/settings.json')
  })

  test('delete requires a real key and removes exactly that entry', async () => {
    const { tools } = rig()
    await tools.save('memory/a.md', 'a\n')
    await tools.save('memory/b.md', 'b\n')

    const del = await tools.delete('memory/a.md')
    expect(del.isError).toBeUndefined()
    const after = await tools.list('memory')
    expect(after.text).not.toContain('memory/a.md')
    expect(after.text).toContain('memory/b.md')

    const missing = await tools.delete('memory/nope.md')
    expect(missing.text).toMatch(/unchanged|nothing named/i)

    const bad = await tools.delete('not-a-key')
    expect(bad.isError).toBe(true)
    const traversal = await tools.delete('memory/../x')
    expect(traversal.isError).toBe(true)
  })

  test('identity material cannot be written or deleted through tools', async () => {
    const { tools } = rig()
    const w = await tools.save('identity/did.json', 'forged\n')
    expect(w.isError).toBe(true)
    const d = await tools.delete('identity/manifest.json')
    expect(d.isError).toBe(true)
  })

  test('the store only ever holds ciphertext (PS-034)', async () => {
    const { stub, tools } = rig()
    await tools.save('memory/secret-sounding-note.md', 'the passphrase hint is unobtainium\n')
    await tools.configSet('settings.json', '{"marker":"cleartext-marker-123"}\n')
    const seen = stub.allCiphertext()
    expect(seen).not.toContain('unobtainium')
    expect(seen).not.toContain('cleartext-marker-123')
    expect(seen).not.toContain(PASS)
  })
})

// ─── Config (PS-070) ────────────────────────────────────────────────────

describe('config tools', () => {
  test('config_set then config_get round-trips, and bare get lists config/', async () => {
    const { tools } = rig()
    expect((await tools.configSet('settings.json', '{"theme":"dark"}\n')).isError).toBeUndefined()

    const one = await tools.configGet('settings.json')
    expect(one.text).toContain('"theme":"dark"')

    const all = await tools.configGet()
    expect(all.text).toContain('config/settings.json')
  })

  test('config_get of a missing key is a clean miss, not an error', async () => {
    const { tools } = rig()
    const r = await tools.configGet('absent.json')
    expect(r.isError).toBeUndefined()
    expect(r.text).toMatch(/no config entry/i)
  })

  test('config_set rejects the PS-070 denylist, on any segment', async () => {
    const { tools } = rig()
    for (const key of ['permissions.json', 'ui/sandbox.json', 'exec-policy.json', 'trust.list']) {
      const r = await tools.configSet(key, 'x')
      expect(r.isError).toBe(true)
      expect(r.text).toContain('PS-070')
    }
    // A lookalike key that carries none of the denied words still passes.
    expect((await tools.configSet('appearance.json', '{}\n')).isError).toBeUndefined()
  })

  test('passport_save cannot route around the denylist into config/', async () => {
    const { tools } = rig()
    const r = await tools.save('config/permissions.json', '{"all":true}\n')
    expect(r.isError).toBe(true)
  })
})

// ─── Grants (PS-060..062) ───────────────────────────────────────────────

describe('grant tools', () => {
  const grantInput = {
    id: 'g1',
    action: 'fs.read',
    scope: 'src/**',
    confirmed: true,
  }

  test('grant_record writes only with explicit confirmation', async () => {
    const { tools } = rig()
    const unconfirmed = await tools.grantRecord({ ...grantInput, confirmed: false })
    expect(unconfirmed.isError).toBe(true)
    const missing = await tools.grantRecord({ id: 'g1', action: 'fs.read', scope: 'src/**' })
    expect(missing.isError).toBe(true)

    const r = await tools.grantRecord(grantInput)
    expect(r.isError).toBeUndefined()
    expect(r.text).toContain('grants/g1.json')

    const listed = await tools.grantList()
    expect(listed.text).toContain('fs.read')
    expect(listed.text).toContain('src/**')
    // The listing itself must keep repeating that grants are records, not
    // permissions already in force.
    expect(listed.text).toMatch(/re-confirm|records only/i)
  })

  test('grant_record validates the PS-060 vocabulary and the entry key', async () => {
    const { tools } = rig()
    const badAction = await tools.grantRecord({ ...grantInput, action: 'shell.read' })
    expect(badAction.isError).toBe(true)
    const badId = await tools.grantRecord({ ...grantInput, id: 'a/b' })
    expect(badId.isError).toBe(true)
  })

  test('grants cannot be written through passport_save (PS-062)', async () => {
    const { tools } = rig()
    const r = await tools.save(
      'grants/sneaky.json',
      '{"id":"x","action":"shell.exec","scope":"*","granted_by":"e","granted_at":"t"}\n',
    )
    expect(r.isError).toBe(true)
    expect(r.text).toContain('passport_grant_record')
  })

  test('no tool exposes grant application (PS-061)', async () => {
    const { tools } = rig()
    // Exactly the nine specified verbs, and nothing that sounds like it could
    // honor, apply, enforce, or consume a grant.
    expect(Object.keys(tools).sort()).toEqual([
      'configGet',
      'configSet',
      'delete',
      'grantList',
      'grantRecord',
      'list',
      'recall',
      'save',
      'search',
    ])
    for (const name of Object.keys(tools)) {
      expect(name).not.toMatch(/apply|honor|enforce|consume|activate/i)
    }
  })
})

// ─── Refusals and diagnostics ───────────────────────────────────────────

describe('refusals and the stdout boundary', () => {
  test('the pre-encryption secret scan blocks a save (PS-110)', async () => {
    const { tools } = rig()
    const r = await tools.save('memory/leak.md', `token: ghp_${'a'.repeat(30)}\n`)
    expect(r.isError).toBe(true)
    expect(r.text).toMatch(/secret|credential/i)
  })

  test('a store refusal becomes a readable error, not a raw dump', async () => {
    const errClient: PassportToolClient = {
      namespace: 'passport:did_key_x',
      push: () => {
        throw new PassportHttpError(
          'passport 429: {"error":{"code":"rate_limited"}}',
          429,
          'rate_limited',
        )
      },
      pull: () => Promise.resolve({ namespace: 'x', seq: 0, entries: {} }),
      hashes: () => Promise.resolve({}),
      readEntry: () => Promise.resolve(null),
    }
    const tools = makeTools(errClient)
    const r = await tools.save('memory/a.md', 'x')
    expect(r.isError).toBe(true)
    expect(r.text).not.toContain('{"error"')
  })

  test('onSync fires after writes so PS-041 state can persist', async () => {
    const { tools, synced } = rig()
    await tools.save('memory/a.md', 'a\n')
    expect(synced.length).toBeGreaterThan(0)
    expect(synced[0]).toBeGreaterThanOrEqual(1)
  })
})

describe('stdout protocol integrity', () => {
  // stdout is the MCP channel: one stray byte there corrupts the protocol.
  // These spies prove neither the tool path nor importing the server module
  // writes to it.
  const spies: { mockRestore(): void }[] = []
  afterEach(() => {
    while (spies.length) spies.pop()!.mockRestore()
  })

  test('no tool call writes to stdout', async () => {
    const log = spyOn(console, 'log')
    const warn = spyOn(console, 'warn')
    const out = spyOn(process.stdout, 'write')
    spies.push(log, warn, out)

    const { tools } = rig()
    await tools.save('memory/a.md', 'a\n')
    await tools.recall('a')
    await tools.search('a')
    await tools.list()
    await tools.delete('memory/a.md')
    await tools.configSet('x.json', '{}\n')
    await tools.configGet()
    await tools.grantRecord({ id: 'g', action: 'fs.read', scope: '*', confirmed: true })
    await tools.grantList()
    // The error paths too.
    await tools.save('grants/x.json', '{}')
    await tools.configSet('permissions.json', '{}')

    expect(log).not.toHaveBeenCalled()
    expect(warn).not.toHaveBeenCalled()
    expect(out).not.toHaveBeenCalled()
  })

  test('importing the server module writes nothing to stdout and does not serve', async () => {
    const out = spyOn(process.stdout, 'write')
    const log = spyOn(console, 'log')
    spies.push(out, log)
    await import('../src/mcp/server.ts')
    expect(out).not.toHaveBeenCalled()
    expect(log).not.toHaveBeenCalled()
  })

  test('the adapter sources never write to stdout at all', () => {
    // Static belt-and-suspenders: grep the shipped modules for the two calls
    // that could put a byte on the protocol channel.
    for (const f of ['server.ts', 'tools.ts', 'relevance.ts', 'guide.ts']) {
      const src = readFileSync(new URL(`../src/mcp/${f}`, import.meta.url), 'utf8')
      expect(src).not.toContain('console.log')
      expect(src).not.toContain('process.stdout')
    }
  })
})
