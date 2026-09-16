/**
 * Wire-protocol tests for the passport store (SPEC §7, PS-080..082).
 *
 * Everything goes through handleRequest(new Request(...)) — no socket — with
 * real challenge/verify auth, so these tests cover routing, authorization,
 * manifest + blob storage, delta sync, the base precondition, and cap
 * rejection exactly as a client sees them.
 */

import { describe, expect, test } from 'bun:test'
import { handleRequest } from '../src/server/handler.ts'
import { manifestHash } from '../src/server/passport.ts'
import { authed, identity, mustToken, nsPath } from './setup.ts'

const b64 = (s: string) => Buffer.from(s).toString('base64')

type PutBody = { base?: string | null; entries?: Record<string, string>; deletions?: string[] }

async function put(token: string, ns: string, body: PutBody) {
  return authed(token, 'PUT', nsPath(ns), body)
}

async function putOk(token: string, ns: string, body: PutBody) {
  const res = await put(token, ns, body)
  const json = (await res.json()) as {
    base: string
    accepted: string[]
    deleted: string[]
    skipped: { key: string; reason: string }[]
  }
  if (res.status !== 200) throw new Error(`PUT failed: ${res.status} ${JSON.stringify(json)}`)
  return json
}

describe('manifest + blob round trip (PS-080)', () => {
  const id = identity('srv-roundtrip')

  test('PUT then GET returns the same ciphertext', async () => {
    const token = await mustToken(id)
    const r = await putOk(token, id.namespace, {
      entries: {
        'memory/MEMORY.md': b64('ct-memory'),
        'config/settings.json': b64('ct-config'),
        'sessions/demo/000001': b64('ct-session'),
      },
    })
    expect(r.accepted.sort()).toEqual([
      'config/settings.json',
      'memory/MEMORY.md',
      'sessions/demo/000001',
    ])
    expect(r.skipped).toEqual([])

    const manifest = (await (await authed(token, 'GET', nsPath(id.namespace))).json()) as {
      base: string
      entries: Record<string, { hash: string; size: number }>
    }
    expect(Object.keys(manifest.entries).sort()).toEqual([
      'config/settings.json',
      'memory/MEMORY.md',
      'sessions/demo/000001',
    ])
    expect(manifest.entries['memory/MEMORY.md']!.hash).toMatch(/^sha256:[0-9a-f]{64}$/)
    expect(manifest.entries['memory/MEMORY.md']!.size).toBe(
      Buffer.from(b64('ct-memory'), 'base64').byteLength,
    )

    const entry = (await (
      await authed(token, 'GET', `${nsPath(id.namespace)}/memory/MEMORY.md`)
    ).json()) as { key: string; entry: string; hash: string }
    expect(entry.entry).toBe(b64('ct-memory'))
    expect(entry.hash).toBe(manifest.entries['memory/MEMORY.md']!.hash)
  })

  test('a second PUT of identical content is a no-op delta', async () => {
    const token = await mustToken(id)
    const before = await putOk(token, id.namespace, { entries: { 'memory/x.md': b64('same') } })
    const after = await putOk(token, id.namespace, { entries: { 'memory/x.md': b64('same') } })
    expect(after.accepted).toEqual(['memory/x.md'])
    expect(after.base).toBe(before.base) // unchanged ciphertext -> unchanged manifest hash
  })
})

describe('?view=hashes delta sync', () => {
  const id = identity('srv-hashes')

  test('returns exactly {entryKey: sha256-hash} and tracks writes', async () => {
    const token = await mustToken(id)
    await putOk(token, id.namespace, {
      entries: { 'memory/a.md': b64('va'), 'config/c.json': b64('vc') },
    })
    const res = await authed(token, 'GET', `${nsPath(id.namespace)}?view=hashes`)
    expect(res.status).toBe(200)
    const hashes = (await res.json()) as Record<string, string>
    expect(Object.keys(hashes).sort()).toEqual(['config/c.json', 'memory/a.md'])
    expect(hashes['memory/a.md']).toMatch(/^sha256:[0-9a-f]{64}$/)

    // The client-side base is computable from the bare map alone.
    const next = await putOk(token, id.namespace, {
      base: manifestHash(hashes),
      entries: { 'memory/b.md': b64('vb') },
    })
    expect(next.accepted).toEqual(['memory/b.md'])
  })

  test('a never-written namespace is 404 empty', async () => {
    const fresh = identity('srv-fresh')
    const token = await mustToken(fresh)
    for (const suffix of ['', '?view=hashes', '?view=integrity']) {
      const res = await authed(token, 'GET', `${nsPath(fresh.namespace)}${suffix}`)
      expect(res.status).toBe(404)
      expect(((await res.json()) as { error: { code: string } }).error.code).toMatch(
        /empty|entry_not_found/,
      )
    }
  })
})

describe('base precondition (PS-081)', () => {
  const id = identity('srv-base')
  const WRONG = `sha256:${'0'.repeat(64)}`

  test('stale base -> 409 with no partial commit', async () => {
    const token = await mustToken(id)
    await putOk(token, id.namespace, { entries: { 'memory/a.md': b64('v1') } })
    const res = await put(token, id.namespace, {
      base: WRONG,
      entries: { 'memory/a.md': b64('v2'), 'memory/b.md': b64('new') },
    })
    expect(res.status).toBe(409)
    const body = (await res.json()) as { error: { code: string; details: { current: string } } }
    expect(body.error.code).toBe('stale_base')
    expect(body.error.details.current).toMatch(/^sha256:/)

    // Nothing committed: a.md still v1, b.md absent.
    const entry = (await (
      await authed(token, 'GET', `${nsPath(id.namespace)}/memory/a.md`)
    ).json()) as { entry: string }
    expect(Buffer.from(entry.entry, 'base64').toString()).toBe('v1')
    const missing = await authed(token, 'GET', `${nsPath(id.namespace)}/memory/b.md`)
    expect(missing.status).toBe(404)
  })

  test('the current base succeeds; null base on a nonempty namespace 409s', async () => {
    const token = await mustToken(id)
    const { base } = await putOk(token, id.namespace, { entries: { 'memory/c.md': b64('v1') } })
    const ok = await put(token, id.namespace, {
      base,
      entries: { 'memory/c.md': b64('v2') },
    })
    expect(ok.status).toBe(200)

    const stale = await put(token, id.namespace, {
      base: null, // "I built from empty" — but the namespace is not empty
      entries: { 'memory/d.md': b64('v1') },
    })
    expect(stale.status).toBe(409)
  })

  test('a malformed base is 400, not a phantom 409', async () => {
    const token = await mustToken(id)
    for (const bad of ['not-a-hash', 7, {}, []]) {
      const res = await put(token, id.namespace, {
        base: bad as string,
        entries: { 'memory/e.md': b64('v1') },
      })
      expect(res.status).toBe(400)
    }
  })
})

describe('entry-key rejection before storage (PS-021)', () => {
  const id = identity('srv-keys')

  test('traversal and unknown-section keys are skipped, never stored', async () => {
    const token = await mustToken(id)
    const r = await putOk(token, id.namespace, {
      entries: {
        'memory/../escape': b64('x'),
        'memory//double': b64('x'),
        'secrets/key.pem': b64('x'),
        'memory/ok.md': b64('fine'),
      },
    })
    expect(r.accepted).toEqual(['memory/ok.md'])
    expect(r.skipped.map(s => s.key).sort()).toEqual([
      'memory/../escape',
      'memory//double',
      'secrets/key.pem',
    ])
    for (const s of r.skipped) expect(s.reason).toBe('invalid_key')

    // And none of them reached storage: the manifest names only the good key.
    const hashes = (await (
      await authed(token, 'GET', `${nsPath(id.namespace)}?view=hashes`)
    ).json()) as Record<string, string>
    expect(Object.keys(hashes)).toEqual(['memory/ok.md'])
  })

  test('a traversal key in the URL is rejected at the route', async () => {
    const token = await mustToken(id)
    // %2E%2E survives URL normalization; the decoded '..' must fail key validation.
    const res = await authed(token, 'GET', `${nsPath(id.namespace)}/memory/%2E%2E/x`)
    expect(res.status).toBe(400)
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe('invalid_key')
  })

  test('a missing entry is a distinct 404 from a missing namespace', async () => {
    const token = await mustToken(id)
    const res = await authed(token, 'GET', `${nsPath(id.namespace)}/memory/absent.md`)
    expect(res.status).toBe(404)
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe('entry_not_found')
  })
})

describe('?view=integrity', () => {
  const id = identity('srv-integrity')

  test('returns the identity/manifest.json blob once written', async () => {
    const token = await mustToken(id)
    const before = await authed(token, 'GET', `${nsPath(id.namespace)}?view=integrity`)
    expect(before.status).toBe(404)

    await putOk(token, id.namespace, { entries: { 'identity/manifest.json': b64('signed-doc') } })
    const res = await authed(token, 'GET', `${nsPath(id.namespace)}?view=integrity`)
    expect(res.status).toBe(200)
    const body = (await res.json()) as { key: string; entry: string }
    expect(body.key).toBe('identity/manifest.json')
    expect(Buffer.from(body.entry, 'base64').toString()).toBe('signed-doc')
  })
})

describe('deletions', () => {
  const id = identity('srv-delete')

  test('a deleted entry is gone from hashes and unreadable', async () => {
    const token = await mustToken(id)
    const { base } = await putOk(token, id.namespace, {
      entries: { 'memory/a.md': b64('va'), 'memory/b.md': b64('vb') },
    })
    const r = await putOk(token, id.namespace, { base, deletions: ['memory/a.md'], entries: {} })
    expect(r.deleted).toEqual(['memory/a.md'])

    const hashes = (await (
      await authed(token, 'GET', `${nsPath(id.namespace)}?view=hashes`)
    ).json()) as Record<string, string>
    expect(Object.keys(hashes)).toEqual(['memory/b.md'])
    expect((await authed(token, 'GET', `${nsPath(id.namespace)}/memory/a.md`)).status).toBe(404)
  })
})

describe('protocol edges', () => {
  const id = identity('srv-edges')

  test('health needs no auth', async () => {
    const res = await handleRequest(new Request('http://x/health'))
    expect(res.status).toBe(200)
  })

  test('unknown routes are 404', async () => {
    const res = await handleRequest(new Request('http://x/nope'))
    expect(res.status).toBe(404)
  })

  test('unsupported methods are 405', async () => {
    const token = await mustToken(id)
    const res = await authed(token, 'DELETE', nsPath(id.namespace))
    expect(res.status).toBe(405)
  })

  test('PUT to an entry path is 405', async () => {
    const token = await mustToken(id)
    const res = await authed(token, 'PUT', `${nsPath(id.namespace)}/memory/x.md`, { entries: {} })
    expect(res.status).toBe(405)
  })

  test('a non-JSON PUT body is 400', async () => {
    const { handleRequest: hr } = await import('../src/server/handler.ts')
    const token = await mustToken(id)
    const res = await hr(
      new Request(`http://x${nsPath(id.namespace)}`, {
        method: 'PUT',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: '{not json',
      }),
    )
    expect(res.status).toBe(400)
  })

  test('an invalid namespace is 400 even with a valid token', async () => {
    const token = await mustToken(id)
    const res = await authed(token, 'GET', '/passport/user:alice')
    expect(res.status).toBe(400)
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe('invalid_namespace')
  })

  test('malformed percent-encoding under /passport/ is 400, not 404', async () => {
    const token = await mustToken(id)
    for (const suffix of [
      '/passport/%E0%A4%A',
      `${nsPath(id.namespace)}/memory/%zz`,
      '/passport/%',
    ]) {
      const res = await authed(token, 'GET', suffix)
      expect(res.status).toBe(400)
      expect(((await res.json()) as { error: { code: string } }).error.code).toBe('bad_request')
    }
  })

  test('a non-base64 entry body is skipped with invalid_base64', async () => {
    const token = await mustToken(id)
    const r = await putOk(token, id.namespace, {
      entries: { 'memory/ok.md': b64('fine'), 'memory/bad.md': '!!!not-base64!!!' },
    })
    expect(r.accepted).toEqual(['memory/ok.md'])
    expect(r.skipped).toEqual([{ key: 'memory/bad.md', reason: 'invalid_base64' }])
  })
})
