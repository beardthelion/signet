/**
 * Learning capture tests (PS-120): distillation types learnings into the
 * memory taxonomy, capture renders them as `memory/<type>/<slug>.md` entries
 * with PS-120 frontmatter, the secret scan refuses credential-shaped
 * content before it can be written, identical content dedupes through the
 * manifest hash, and a learned entry written through capture is recallable
 * through the MCP tools layer in a later session — the cross-harness
 * compounding claim.
 *
 * The store is the same in-process wire-contract stub mcp.test.ts uses, so
 * every capture goes through the real encrypt -> HTTP -> ciphertext ->
 * decrypt path.
 */

import { describe, expect, test } from 'bun:test'
import { createHash } from 'node:crypto'
import { MANIFEST_ENTRY_KEY, PassportClient } from '../src/client/client.ts'
import { generateIdentity, verifyDidSignature } from '../src/client/identity.ts'
import { captureLearnings, captureSession, renderLearningEntry } from '../src/learn/capture.ts'
import { distillSession } from '../src/learn/distill.ts'
import { makeTools } from '../src/mcp/tools.ts'

// ─── In-process wire stub (same contract as tests/mcp.test.ts) ──────────

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

function makeStub() {
  const manifests = new Map<string, Map<string, { hash: string; size: number }>>()
  const blobs = new Map<string, Buffer>()
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

  return { fetchFn: fetchFn as typeof fetch }
}

// ─── Helpers ────────────────────────────────────────────────────────────

const PASS = 'learn test passphrase'

function rig() {
  const stub = makeStub()
  const id = generateIdentity()
  const client = new PassportClient({
    url: 'http://stub',
    fetchFn: stub.fetchFn,
    identity: id,
    passphrase: PASS,
  })
  return { stub, id, client }
}

/** A second client over the same stub — the later session / other harness. */
function secondClient(r: ReturnType<typeof rig>): PassportClient {
  return new PassportClient({
    url: 'http://stub',
    fetchFn: r.stub.fetchFn,
    identity: r.id,
    passphrase: PASS,
  })
}

const SESSION = [
  'user: how do I deploy this thing?',
  'assistant: You run the deploy script.',
  'user: I prefer pnpm over npm for all package management in this repo.',
  'assistant: noted.',
  'assistant: we decided to store agent state in the passport, not in vendor clouds.',
  'assistant: the root cause was a stale manifest seq; fixed by re-reading before push.',
  'assistant: the runbook for deploys is at https://internal.example.com/runbooks/deploy.',
  'user: thanks',
].join('\n')

// ─── Distillation ───────────────────────────────────────────────────────

describe('distillSession', () => {
  test('types learnings into the PS-120 memory taxonomy', () => {
    const learnings = distillSession(SESSION)
    const byType = new Map(learnings.map(l => [l.type, l]))
    expect(byType.get('user')?.body).toContain('pnpm')
    expect(byType.get('project')?.body).toContain('passport')
    expect(byType.get('feedback')?.body).toContain('root cause')
    expect(byType.get('reference')?.body).toContain('runbook')
  })

  test('distills nothing from content with no learnable signal', () => {
    expect(distillSession('user: hi\nassistant: hello\nuser: ok\nassistant: done.\n')).toEqual([])
    expect(distillSession([])).toEqual([])
    expect(distillSession('')).toEqual([])
  })

  test('skips fenced code and dedupes repeated lines', () => {
    const text = [
      'assistant: we decided the token goes in custody.',
      '```',
      'const decision = "we decided nothing; this is code"',
      '```',
      'assistant: we decided the token goes in custody.',
    ].join('\n')
    const learnings = distillSession(text)
    expect(learnings).toHaveLength(1)
    expect(learnings[0]!.body).toContain('token goes in custody')
  })

  test('accepts a list of session chunks', () => {
    const learnings = distillSession([
      'user: I prefer tabs over spaces in this project.',
      'assistant: acknowledged.',
    ])
    expect(learnings).toHaveLength(1)
    expect(learnings[0]!.type).toBe('user')
  })
})

// ─── Entry shape ────────────────────────────────────────────────────────

describe('renderLearningEntry', () => {
  test('renders memory/<type>/<slug>.md with PS-120 frontmatter', () => {
    const { key, content } = renderLearningEntry(
      {
        type: 'project',
        title: 'We decided to store agent state in the passport.',
        body: 'we decided to store agent state in the passport, not in vendor clouds.\n',
      },
      'fx',
    )
    expect(key).toMatch(/^memory\/project\/[a-z0-9][a-z0-9-]*\.md$/)
    expect(content).toContain('type: project')
    expect(content).toContain('provenance: learned:fx')
    expect(content).toContain('description:')
    expect(content).toContain('vendor clouds')
  })
})

// ─── Capture ────────────────────────────────────────────────────────────

describe('captureSession', () => {
  test('writes typed memory entries through the encrypted push', async () => {
    const { client } = rig()
    const outcome = await captureSession(client, SESSION, { harness: 'fx' })
    expect(outcome.uploaded.length).toBeGreaterThanOrEqual(3)
    for (const key of outcome.uploaded)
      expect(key).toMatch(/^memory\/(user|feedback|project|reference)\//)

    const pulled = await client.pull()
    for (const key of outcome.uploaded) {
      const entry = pulled.entries[key]
      expect(entry).toBeDefined()
      expect(entry).toContain('provenance: learned:fx')
      expect(entry).toMatch(/^---\n[\s\S]*type: (user|feedback|project|reference)\n[\s\S]*---/)
    }
  })

  test('writes nothing when the session has nothing worth learning', async () => {
    const { client } = rig()
    const seqBefore = client.manifestSeq
    const outcome = await captureSession(client, 'user: hi\nassistant: hello\nuser: ok\n')
    expect(outcome.uploaded).toEqual([])
    expect(outcome.unchanged).toEqual([])
    expect(outcome.blocked).toEqual([])
    // No push at all: the namespace stays empty and no manifest is burned.
    expect(client.manifestSeq).toBe(seqBefore)
    expect(await client.hashes()).toEqual({})
  })

  test('identical content across two captures produces one entry, not duplicates', async () => {
    const { client } = rig()
    const first = await captureSession(client, SESSION, { harness: 'fx' })
    const second = await captureSession(client, SESSION, { harness: 'fx' })
    expect(second.uploaded).toEqual([])
    expect(second.unchanged.sort()).toEqual(first.uploaded.sort())

    const tools = makeTools(client)
    const list = await tools.list('memory')
    const memoryKeys = list.text.split('\n').filter(l => l.startsWith('- '))
    expect(memoryKeys).toHaveLength(first.uploaded.length)
  })

  test('blocks credential-shaped learnings; clean learnings in the same batch still land', async () => {
    const { client } = rig()
    const outcome = await captureLearnings(
      client,
      [
        {
          type: 'user',
          title: 'I prefer pnpm over npm.',
          body: 'I prefer pnpm over npm for all package management.\n',
        },
        {
          type: 'feedback',
          title: 'The fix was rotating the token.',
          body: `the fix was rotating token ghp_${'a'.repeat(30)} which had expired.\n`,
        },
      ],
      { harness: 'fx' },
    )
    expect(outcome.blocked).toHaveLength(1)
    expect(outcome.blocked[0]!.rules).toContain('github-token')
    expect(outcome.uploaded).toHaveLength(1)
    expect(outcome.uploaded[0]).toContain('memory/user/')

    // The refused content never reached the store — ciphertext or plaintext.
    const pulled = await client.pull()
    expect(Object.keys(pulled.entries).some(k => k.includes('token'))).toBe(false)
    expect(Object.values(pulled.entries).join('\n')).not.toContain('ghp_')
  })
})

// ─── Recall across sessions ─────────────────────────────────────────────

describe('learned entries through the recall path', () => {
  test('a learning captured by one harness is recalled by the MCP tools in a later session', async () => {
    const r = rig()
    // Session one: the fx harness captures what it learned.
    const outcome = await captureSession(r.client, SESSION, { harness: 'fx' })
    expect(outcome.uploaded.length).toBeGreaterThan(0)

    // Session two: a different harness over the MCP adapter recalls it.
    const tools = makeTools(secondClient(r))
    const recalled = await tools.recall('which package manager does the user prefer')
    expect(recalled.isError).toBeUndefined()
    expect(recalled.text).toContain('memory/user/')
    expect(recalled.text).toContain('pnpm')
    expect(recalled.text).toContain('provenance: learned:fx')

    const searched = await tools.search('learned:fx')
    expect(searched.text).toContain('memory/')
  })
})
