/**
 * SignetClient tests against an in-process stub of the wire contract
 * (SPEC §7). The stub implements challenge/verify auth, the hashes and
 * integrity views, single-entry reads, and the delta upsert with base
 * precondition - the same shapes src/server/handler.ts serves - so the
 * client is exercised end to end without a socket.
 *
 * Covered: init, push/pull round-trips across all five sections (including
 * chunked sessions), delta sync, `skipped` surfaced as an error (SN-081),
 * stale-base 409, and the fail-closed integrity checks (SN-041): a tampered
 * blob, a forged manifest signer, and a rolled-back seq must all reject.
 * Also the custody export/import round-trip (SN-102) and rotation auth
 * (SN-050..053).
 */

import { describe, expect, test } from 'bun:test'
import { createHash } from 'node:crypto'
import { mkdtempSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  MANIFEST_ENTRY_KEY,
  SignetClient,
  SignetDecryptError,
  SignetEntryMissing,
  SignetHttpError,
  SignetIntegrityError,
  SignetSkippedError,
  sessionEntryKey,
} from '../src/client/client.ts'
import { ciphertextHash, deriveKey, encryptEntry } from '../src/client/crypto.ts'
import { exportBundle, importBundle, loadCustody, saveCustody } from '../src/client/custody.ts'
import {
  canonicalJson,
  generateIdentity,
  type Identity,
  identityFromPkcs8,
  namespaceFor,
  sha256Hex,
  signMessage,
  verifyDidSignature,
} from '../src/client/identity.ts'
import type { RotationAttestation } from '../src/types/index.ts'

// ─── In-process wire stub ───────────────────────────────────────────────

const SPEC_VERSION = 'signet-spec/0.1'
const ENTRY_CAP = 1024 // decoded bytes; trips the skipped path in tests

function sha256Prefixed(bytes: Uint8Array): string {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`
}

/** The same base hash the server computes: sha256 over sorted k\thash lines. */
function stubManifestHash(hashes: Record<string, string>): string {
  const lines = Object.keys(hashes)
    .sort()
    .map(k => `${k}\t${hashes[k]}`)
    .join('\n')
  return `sha256:${sha256Hex(lines)}`
}
const EMPTY_BASE = stubManifestHash({})

/** Decode `signet:did_<method>_<id>` back to `did:<method>:<id>`. */
function genesisOf(ns: string): string {
  const enc = ns.slice('signet:'.length)
  const a = enc.indexOf('_')
  const b = enc.indexOf('_', a + 1)
  return `${enc.slice(0, a)}:${enc.slice(a + 1, b)}:${enc.slice(b + 1)}`
}

const SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]*$/
function validKey(key: string): boolean {
  const parts = key.split('/')
  if (parts.length < 2) return false
  if (!SECTIONS_SET.has(parts[0]!)) return false
  if (key.includes('..') || key.includes('//') || key.endsWith('/')) return false
  if (parts[0] === 'sessions') {
    return parts.length === 3 && SEGMENT.test(parts[1]!) && /^[0-9]{6,}$/.test(parts[2]!)
  }
  return parts.slice(1).every(p => SEGMENT.test(p))
}
const SECTIONS_SET = new Set(['memory', 'config', 'sessions', 'grants', 'identity'])

/** Verify a presented attestation chain; returns the terminal DID or null. */
function verifyChain(chain: RotationAttestation[]): string | null {
  for (let i = 0; i < chain.length; i++) {
    const att = chain[i]!
    if (att.seq !== i + 1) return null
    const expectedPrev = i === 0 ? '0'.repeat(64) : sha256Hex(canonicalJson(chain[i - 1]))
    if (att.prevHash !== expectedPrev) return null
    const signer = i === 0 ? att.genesisDid : chain[i - 1]!.newDid
    const body = {
      genesisDid: att.genesisDid,
      newDid: att.newDid,
      seq: att.seq,
      prevHash: att.prevHash,
    }
    if (!verifyDidSignature(signer, canonicalJson(body), att.sig)) return null
  }
  return chain[chain.length - 1]!.newDid
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}
const apiError = (code: string, status: number, details?: Record<string, unknown>) =>
  json({ error: { code, message: code, ...(details ? { details } : {}) } }, status)

/**
 * The stub store: per-namespace manifest (key -> {hash, size}) plus blobs
 * keyed by hash, mirroring the server's manifest-plus-blobs model. Test
 * hooks (`failNextPut`, direct map access) exist so tests can tamper with
 * stored state the way a hostile store would.
 */
function makeStub() {
  const manifests = new Map<
    string,
    Map<string, { hash: string; size: number; updatedAt: string }>
  >()
  const blobs = new Map<string, Buffer>() // `${ns}|${hash}` -> ciphertext
  const nonces = new Set<string>()
  const tokens = new Map<string, string>() // token -> did
  const chains = new Map<string, RotationAttestation[]>() // genesisDid -> chain
  let counter = 0
  let failNextPut = false
  let failAllPuts = false
  let onTrip: (() => void | Promise<void>) | null = null
  /** Requests still to answer 429 before serving normally. */
  let rateLimited = 0
  let rateLimitAll = false
  /** Every request seen, as `METHOD path`. */
  const requestLog: string[] = []

  const entryRead = (ns: string, key: string): Response => {
    const m = manifests.get(ns)
    if (!m) return apiError('empty', 404)
    const meta = m.get(key)
    if (!meta) return apiError('entry_not_found', 404)
    const bytes = blobs.get(`${ns}|${meta.hash}`)
    if (!bytes) return apiError('entry_unreadable', 503)
    return json({ namespace: ns, key, entry: bytes.toString('base64'), hash: meta.hash })
  }

  const fetchImpl = async (input: string | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input))
    const path = url.pathname
    const method = init?.method ?? 'GET'
    const body = init?.body ? JSON.parse(String(init.body)) : undefined
    requestLog.push(`${method} ${url.pathname}${url.search}`)

    if (rateLimitAll || rateLimited > 0) {
      if (rateLimited > 0) rateLimited--
      return new Response(JSON.stringify({ error: { code: 'rate_limited', message: 'x' } }), {
        status: 429,
        // A fractional second keeps the test fast; the client parses it as a
        // number rather than requiring an integer.
        headers: { 'content-type': 'application/json', 'retry-after': '0.01' },
      })
    }

    if (path === '/auth/challenge' && method === 'POST') {
      const nonce = `nonce-${++counter}`
      nonces.add(nonce)
      return json({ nonce, expiresAt: new Date(Date.now() + 120_000).toISOString() })
    }
    if (path === '/auth/verify' && method === 'POST') {
      const { did, nonce, sig, attestations } = body as {
        did: string
        nonce: string
        sig: string
        attestations?: RotationAttestation[]
      }
      if (!nonces.delete(nonce)) return apiError('invalid_nonce', 401)
      if (!verifyDidSignature(did, new TextEncoder().encode(`signet-auth:${nonce}`), sig)) {
        return apiError('invalid_signature', 401)
      }
      if (attestations !== undefined) {
        if (!Array.isArray(attestations) || attestations.length === 0) {
          return apiError('bad_request', 400)
        }
        if (verifyChain(attestations) !== did) return apiError('invalid_attestation', 401)
        chains.set(attestations[0]!.genesisDid, attestations)
      }
      const token = `tok-${++counter}`
      tokens.set(token, did)
      return json({ token, expiresAt: new Date(Date.now() + 600_000).toISOString() })
    }

    if (!path.startsWith('/signet/')) return apiError('not_found', 404)
    const auth = /Bearer\s+(.+)/.exec(
      String((init?.headers as Record<string, string>)?.authorization ?? ''),
    )
    const did = auth ? tokens.get(auth[1]!) : undefined
    if (!did) return apiError('unauthorized', 401)

    const rest = decodeURIComponent(path.slice('/signet/'.length))
    const slash = rest.indexOf('/')
    const ns = slash === -1 ? rest : rest.slice(0, slash)
    const entryKey = slash === -1 ? null : rest.slice(slash + 1)
    const genesis = genesisOf(ns)
    const chain = chains.get(genesis)
    if (did !== genesis && (!chain || verifyChain(chain) !== did)) {
      return apiError('forbidden', 403)
    }

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
      return json({
        namespace: ns,
        base: stubManifestHash(Object.fromEntries([...m.entries()].map(([k, v]) => [k, v.hash]))),
        entries: Object.fromEntries(
          [...m.entries()].map(([k, v]) => [k, { hash: v.hash, size: v.size, updatedAt: v.updatedAt }]),
        ),
      })
    }

    if (method === 'PUT' && entryKey === null) {
      if (failNextPut || failAllPuts) {
        failNextPut = false
        await onTrip?.()
        return apiError('stale_base', 409, { current: 'sha256:0' })
      }
      const m =
        manifests.get(ns) ??
        new Map<string, { hash: string; size: number; updatedAt: string }>()
      const currentHashes = Object.fromEntries([...m.entries()].map(([k, v]) => [k, v.hash]))
      if (body.base !== undefined) {
        const expected = body.base === null ? EMPTY_BASE : body.base
        if (expected !== stubManifestHash(currentHashes)) {
          return apiError('stale_base', 409, { current: stubManifestHash(currentHashes) })
        }
      }
      const accepted: string[] = []
      const deleted: string[] = []
      const skipped: { key: string; reason: string }[] = []
      for (const key of (body.deletions as string[] | undefined) ?? []) {
        if (!validKey(key)) {
          skipped.push({ key, reason: 'invalid_key' })
        } else if (m.delete(key)) {
          deleted.push(key)
        }
      }
      for (const [key, b64] of Object.entries(body.entries as Record<string, string>)) {
        if (!validKey(key)) {
          skipped.push({ key, reason: 'invalid_key' })
          continue
        }
        const bytes = Buffer.from(b64, 'base64')
        if (bytes.byteLength > ENTRY_CAP) {
          skipped.push({ key, reason: 'entry_too_large' })
          continue
        }
        const hash = sha256Prefixed(bytes)
        blobs.set(`${ns}|${hash}`, bytes)
        m.set(key, {
          hash,
          size: bytes.byteLength,
          updatedAt: `2026-01-01T00:00:${String(++counter).padStart(2, '0')}Z`,
        })
        accepted.push(key)
      }
      manifests.set(ns, m)
      const nextHashes = Object.fromEntries([...m.entries()].map(([k, v]) => [k, v.hash]))
      return json({
        namespace: ns,
        base: stubManifestHash(nextHashes),
        erasure: 'erases',
        accepted,
        deleted,
        skipped,
      })
    }
    return apiError('method_not_allowed', 405)
  }

  return {
    fetchFn: fetchImpl as typeof fetch,
    manifests,
    blobs,
    /** The live token map - tests clear it to force a 401/re-auth. */
    tokens,
    /** Force the next PUT to answer 409 stale_base; `effect` runs as it fires. */
    tripNextPut: (effect?: () => void | Promise<void>) => {
      failNextPut = true
      onTrip = effect ?? null
    },
    /** Force EVERY PUT to answer 409 stale_base (retry exhaustion). */
    tripAllPuts: () => {
      failAllPuts = true
    },
    /** Answer the next n requests (any route, auth included) with 429. */
    rateLimitNext: (n: number) => {
      rateLimited = n
    },
    /** Answer every request with 429 (retry exhaustion). */
    rateLimitAllRequests: () => {
      rateLimitAll = true
    },
    /** Point the manifest entry at different stored bytes (tamper). */
    repointEntry(ns: string, key: string, hash: string) {
      manifests.get(ns)!.set(key, { hash, size: 0, updatedAt: '2026-01-01T00:00:00Z' })
    },
    /** Every request the stub saw, as `METHOD path`. */
    requests(): string[] {
      return [...requestLog]
    },
    /** The hash currently stored under a key. */
    hashOf(ns: string, key: string): string | undefined {
      return manifests.get(ns)?.get(key)?.hash
    },
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────

const PASS = 'test passphrase'

function clientFor(
  stub: ReturnType<typeof makeStub>,
  identity: Identity,
  extra?: {
    genesisDid?: string
    attestations?: RotationAttestation[]
    lastSeq?: number
    rateLimitRetries?: number
  },
): SignetClient {
  return new SignetClient({
    url: 'http://stub',
    fetchFn: stub.fetchFn,
    identity,
    genesisDid: extra?.genesisDid,
    attestations: extra?.attestations,
    rateLimitRetries: extra?.rateLimitRetries,
    lastSeq: extra?.lastSeq,
    passphrase: PASS,
  })
}

// ─── Tests ──────────────────────────────────────────────────────────────

describe('init + push/pull round-trip', () => {
  test('init publishes did.json and a signed manifest; pull reads it back', async () => {
    const stub = makeStub()
    const id = generateIdentity()
    const client = clientFor(stub, id)
    await client.init()
    expect(client.manifestSeq).toBe(1)

    const out = await client.pull()
    expect(out.entries['identity/did.json']).toContain(id.did)
    expect(out.entries[MANIFEST_ENTRY_KEY]).toBeDefined()
  })

  test('init refuses to run over an existing signet', async () => {
    const stub = makeStub()
    const id = generateIdentity()
    await clientFor(stub, id).init()
    await expect(clientFor(stub, id).init()).rejects.toThrow(/already/)
  })

  test('push then pull across all five sections, including session chunks', async () => {
    const stub = makeStub()
    const id = generateIdentity()
    const client = clientFor(stub, id)
    await client.init()

    const entries = {
      'memory/MEMORY.md': '---\ntype: note\nprovenance: test\n---\nremember this\n',
      'config/settings.json': '{"model":"m"}\n',
      'grants/g1.json':
        '{"id":"g1","action":"fs.read","scope":"src/**","granted_by":"me","granted_at":"t"}\n',
      [sessionEntryKey('demo', 1)]: '{"role":"user","text":"hi"}\n',
      [sessionEntryKey('demo', 2)]: '{"role":"agent","text":"ok"}\n',
    }
    const pushed = await client.push(entries)
    expect(pushed.seq).toBe(2)
    expect(pushed.uploaded).toContain(MANIFEST_ENTRY_KEY)

    const out = await client.pull()
    for (const [k, v] of Object.entries(entries)) expect(out.entries[k]).toBe(v)
    // The manifest names every entry's ciphertext hash but not its own.
    const manifest = JSON.parse(out.entries[MANIFEST_ENTRY_KEY]!) as {
      manifest: { seq: number; entries: Record<string, string>; specVersion: string }
    }
    expect(manifest.manifest.seq).toBe(2)
    expect(manifest.manifest.specVersion).toBe(SPEC_VERSION)
    expect(Object.keys(manifest.manifest.entries).sort()).toEqual(
      [...Object.keys(entries), 'identity/did.json'].sort(),
    )
    expect(manifest.manifest.entries[MANIFEST_ENTRY_KEY]).toBeUndefined()
  })

  test('a no-change push is a no-op - no PUT, no seq burn', async () => {
    const stub = makeStub()
    const id = generateIdentity()
    const client = clientFor(stub, id)
    const first = await client.push({ 'memory/a.md': 'same\n' })
    const second = await client.push({ 'memory/a.md': 'same\n' })
    expect(second.seq).toBe(first.seq)
    expect(second.unchanged).toEqual(['memory/a.md'])
    expect(second.uploaded).toEqual([])
  })

  test('an invalid entry key is rejected client-side before any request', async () => {
    const stub = makeStub()
    const client = clientFor(stub, generateIdentity())
    await expect(client.push({ 'secrets/x.pem': 'nope' })).rejects.toThrow(/invalid entry key/)
  })
})

describe('integrity - fail closed (SN-041)', () => {
  test('a tampered blob fails the manifest hash check on pull', async () => {
    const stub = makeStub()
    const id = generateIdentity()
    const ns = namespaceFor(id.did)
    const client = clientFor(stub, id)
    await client.push({ 'memory/a.md': 'original\n' })
    // Corrupt the stored ciphertext under its manifest hash.
    const hash = stub.hashOf(ns, 'memory/a.md')!
    stub.blobs.set(`${ns}|${hash}`, Buffer.from('forged ciphertext'))
    await expect(client.pull()).rejects.toThrow(SignetIntegrityError)
  })

  test('a manifest signed by an unauthorized key is rejected', async () => {
    const stub = makeStub()
    const id = generateIdentity()
    const ns = namespaceFor(id.did)
    const client = clientFor(stub, id)
    await client.push({ 'memory/a.md': 'original\n' })

    // Forge a manifest at a higher seq signed by an attacker key.
    const attacker = generateIdentity()
    const forged = {
      seq: 99,
      specVersion: SPEC_VERSION,
      genesisDid: id.did,
      entries: {},
    }
    const forgedDoc = canonicalJson({
      manifest: forged,
      did: attacker.did,
      sig: signMessage(attacker.privateKey, canonicalJson(forged)),
    })
    const encKey = deriveKey(PASS, ns)
    const blob = encryptEntry(encKey, MANIFEST_ENTRY_KEY, forgedDoc)
    const hash = ciphertextHash(blob)
    stub.blobs.set(`${ns}|${hash}`, Buffer.from(blob, 'base64'))
    stub.repointEntry(ns, MANIFEST_ENTRY_KEY, hash)

    await expect(client.pull()).rejects.toThrow(SignetIntegrityError)
    // And the same tamper must block a push building on it.
    await expect(client.push({ 'memory/b.md': 'x\n' })).rejects.toThrow(SignetIntegrityError)
  })

  test('a rolled-back manifest seq is rejected', async () => {
    const stub = makeStub()
    const id = generateIdentity()
    const ns = namespaceFor(id.did)
    const client = clientFor(stub, id)
    await client.push({ 'memory/a.md': 'v1\n' })
    const oldHash = stub.hashOf(ns, MANIFEST_ENTRY_KEY)!
    await client.push({ 'memory/a.md': 'v2\n' }) // seq 2 verified
    // Store replays the seq-1 manifest.
    stub.repointEntry(ns, MANIFEST_ENTRY_KEY, oldHash)
    await expect(client.pull()).rejects.toThrow(/rolled back/)
  })

  test('a manifest replaced at the same seq is rejected', async () => {
    const stub = makeStub()
    const id = generateIdentity()
    const ns = namespaceFor(id.did)
    const client = clientFor(stub, id)
    await client.push({ 'memory/a.md': 'v1\n' })
    // Same seq, different entries, validly signed - still a replacement.
    const other = {
      seq: client.manifestSeq,
      specVersion: SPEC_VERSION,
      genesisDid: id.did,
      entries: {},
    }
    const doc = canonicalJson({
      manifest: other,
      did: id.did,
      sig: signMessage(id.privateKey, canonicalJson(other)),
    })
    const blob = encryptEntry(deriveKey(PASS, ns), MANIFEST_ENTRY_KEY, doc)
    const hash = ciphertextHash(blob)
    stub.blobs.set(`${ns}|${hash}`, Buffer.from(blob, 'base64'))
    stub.repointEntry(ns, MANIFEST_ENTRY_KEY, hash)
    await expect(client.pull()).rejects.toThrow(/differs/)
  })

  test('a wrong passphrase fails at the manifest decrypt', async () => {
    const stub = makeStub()
    const id = generateIdentity()
    await clientFor(stub, id).push({ 'memory/a.md': 'v1\n' })
    const wrong = new SignetClient({
      url: 'http://stub',
      fetchFn: stub.fetchFn,
      identity: id,
      passphrase: 'wrong passphrase',
    })
    await expect(wrong.pull()).rejects.toThrow(SignetDecryptError)
  })

  test('a push fails closed when the unsigned hashes view disagrees with the signed manifest', async () => {
    const stub = makeStub()
    const id = generateIdentity()
    const ns = namespaceFor(id.did)
    const client = clientFor(stub, id)
    await client.push({ 'memory/a.md': 'v1\n' })
    // The store plants a key in its unsigned view that the signed manifest
    // never named - the client must refuse to sign that view into the next
    // manifest rather than adopt it.
    stub.manifests
      .get(ns)!
      .set('memory/planted.md', {
        hash: `sha256:${'0'.repeat(64)}`,
        size: 1,
        updatedAt: '2026-01-01T00:00:00Z',
      })
    await expect(client.push({ 'memory/b.md': 'v2\n' })).rejects.toThrow(SignetIntegrityError)
    // The verified manifest is untouched; pull still works.
    const out = await client.pull()
    expect(out.entries['memory/a.md']).toBe('v1\n')
  })
})

describe('wire failures surface honestly', () => {
  test('skipped entries are thrown, never silently dropped (SN-081)', async () => {
    const stub = makeStub()
    const id = generateIdentity()
    const client = clientFor(stub, id)
    const big = 'x'.repeat(ENTRY_CAP) // plaintext 1024B -> ciphertext > cap
    try {
      await client.push({ 'memory/ok.md': 'fine\n', 'memory/big.md': big })
      expect.unreachable('push should have thrown')
    } catch (err) {
      expect(err).toBeInstanceOf(SignetSkippedError)
      expect((err as SignetSkippedError).skipped).toEqual([
        { key: 'memory/big.md', reason: 'entry_too_large' },
      ])
      expect((err as SignetSkippedError).accepted).toContain('memory/ok.md')
    }
    // The refusal must not leave the client's seq state pinned to a manifest
    // that was never published: the next pull verifies the corrected
    // manifest and adopts it cleanly.
    const out = await client.pull()
    expect(out.entries['memory/ok.md']).toBe('fine\n')
    expect(out.entries['memory/big.md']).toBeUndefined()
    const manifest = JSON.parse(out.entries[MANIFEST_ENTRY_KEY]!) as {
      manifest: { entries: Record<string, string> }
    }
    expect('memory/big.md' in manifest.manifest.entries).toBe(false)
  })

  test('a stale base rebases and commits transparently (SN-083)', async () => {
    const stub = makeStub()
    const id = generateIdentity()
    const client = clientFor(stub, id)
    await client.push({ 'memory/a.md': 'v1\n' })
    stub.tripNextPut()
    const r = await client.push({ 'memory/a.md': 'v2\n' })
    expect(r.uploaded).toContain('memory/a.md')
    const out = await client.pull()
    expect(out.entries['memory/a.md']).toBe('v2\n')
  })

  test('a persistently stale base exhausts bounded retries and surfaces 409', async () => {
    const stub = makeStub()
    const id = generateIdentity()
    const client = clientFor(stub, id)
    await client.push({ 'memory/a.md': 'v1\n' })
    stub.tripAllPuts()
    try {
      await client.push({ 'memory/a.md': 'v2\n' })
      expect.unreachable('push should have thrown')
    } catch (err) {
      expect(err).toBeInstanceOf(SignetHttpError)
      expect((err as SignetHttpError).status).toBe(409)
      expect((err as SignetHttpError).code).toBe('stale_base')
    }
  })

  test('429s are retried through, auth included, and the write still lands', async () => {
    const stub = makeStub()
    const id = generateIdentity()
    const client = clientFor(stub, id)
    // Three refusals span the auth challenge and the first data call; the
    // bucket in front of them refills before the client's attempt ceiling.
    stub.rateLimitNext(3)
    const r = await client.push({ 'memory/a.md': 'v1\n' })
    expect(r.uploaded).toContain('memory/a.md')
    const out = await client.pull()
    expect(out.entries['memory/a.md']).toBe('v1\n')
  })

  test('persistent 429s exhaust bounded retries and surface the error', async () => {
    const stub = makeStub()
    const id = generateIdentity()
    const client = clientFor(stub, id, { rateLimitRetries: 3 })
    stub.rateLimitAllRequests()
    try {
      await client.push({ 'memory/a.md': 'v1\n' })
      expect.unreachable('push should have thrown')
    } catch (err) {
      expect(err).toBeInstanceOf(SignetHttpError)
      expect((err as SignetHttpError).status).toBe(429)
      expect((err as SignetHttpError).code).toBe('rate_limited')
    }
  })

  test('concurrent pushes on different keys merge through rebase', async () => {
    const stub = makeStub()
    const id = generateIdentity()
    const a = clientFor(stub, id)
    const b = clientFor(stub, id)
    await a.push({ 'memory/a.md': 'from a\n' })
    // B writes on what becomes a stale base the moment A's commit lands.
    stub.tripNextPut(async () => {
      await a.push({ 'memory/b.md': 'from a too\n' })
    })
    const rb = await b.push({ 'memory/c.md': 'from b\n' })
    expect(rb.uploaded).toContain('memory/c.md')
    const out = await b.pull()
    expect(out.entries['memory/a.md']).toBe('from a\n')
    expect(out.entries['memory/b.md']).toBe('from a too\n')
    expect(out.entries['memory/c.md']).toBe('from b\n')
  })

  test('a deletion tombstone outranks a write issued before it (SN-084)', async () => {
    const stub = makeStub()
    const id = generateIdentity()
    const a = clientFor(stub, id)
    const b = clientFor(stub, id)
    await a.push({ 'memory/x.md': 'lives\n' })
    // B's re-write forms on the pre-delete base; A's delete lands mid-push.
    stub.tripNextPut(async () => {
      await a.push({}, { deletions: ['memory/x.md'] })
    })
    const r = await b.push({ 'memory/x.md': 'resurrected\n' })
    expect(r.tombstoned).toContain('memory/x.md')
    const out = await b.pull()
    expect(out.entries['memory/x.md']).toBeUndefined()
  })

  test('a writer who saw the deletion may deliberately re-add (SN-084)', async () => {
    const stub = makeStub()
    const id = generateIdentity()
    const a = clientFor(stub, id)
    await a.push({ 'memory/x.md': 'lives\n' })
    const r1 = await a.push({}, { deletions: ['memory/x.md'] })
    expect(r1.deleted).toContain('memory/x.md')
    // Fresh push, post-delete base: the tombstone is behind this intent.
    const r2 = await a.push({ 'memory/x.md': 'brought back\n' })
    expect(r2.tombstoned).toHaveLength(0)
    const out = await a.pull()
    expect(out.entries['memory/x.md']).toBe('brought back\n')
  })

  test('401 -> re-auth + retry is transparent', async () => {
    const stub = makeStub()
    const id = generateIdentity()
    const client = clientFor(stub, id)
    await client.push({ 'memory/a.md': 'v1\n' })
    // The client's cached token is now invalid server-side; the next call
    // must re-authenticate and retry rather than surface the 401.
    stub.tokens.clear()
    const out = await client.pull()
    expect(out.entries['memory/a.md']).toBe('v1\n')
  })
})

describe('rotation (SN-050..053)', () => {
  test('rotate records an attestation entry and the successor can auth + sync', async () => {
    const stub = makeStub()
    const genesis = generateIdentity()
    const client = clientFor(stub, genesis)
    await client.push({ 'memory/a.md': 'v1\n' })

    const { attestation, successor, seq, chain } = await client.rotate()
    expect(seq).toBe(1)
    expect(attestation.genesisDid).toBe(genesis.did)
    expect(attestation.newDid).toBe(successor.did)
    expect(attestation.prevHash).toBe('0'.repeat(64))
    // Signed by the predecessor (genesis) key, per SN-051.
    const body = {
      genesisDid: attestation.genesisDid,
      newDid: attestation.newDid,
      seq: attestation.seq,
      prevHash: attestation.prevHash,
    }
    expect(verifyDidSignature(genesis.did, canonicalJson(body), attestation.sig)).toBe(true)

    // The recorded entry landed in the signet.
    const out = await client.pull()
    expect(out.entries['identity/rotations/1.json']).toContain(successor.did)

    // A successor client authenticates by presenting the chain, and the
    // namespace stays bound to the genesis DID (SN-053).
    const next = clientFor(stub, successor, {
      genesisDid: genesis.did,
      attestations: chain,
      lastSeq: client.manifestSeq,
    })
    expect(next.namespace).toBe(client.namespace)
    const r = await next.push({ 'memory/b.md': 'after rotation\n' })
    // The successor's push publishes the next manifest seq.
    expect(r.seq).toBe(client.manifestSeq + 1)
    const pulled = await next.pull()
    expect(pulled.entries['memory/a.md']).toBe('v1\n')
    expect(pulled.entries['memory/b.md']).toBe('after rotation\n')
  })
})

describe('custody export/import (SN-102)', () => {
  test('bundle round-trips secrets; wrong export passphrase fails', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'signet-custody-'))
    const id = generateIdentity()
    const secrets = {
      version: 1 as const,
      genesisDid: id.did,
      passphrase: PASS,
      pkcs8: id.pkcs8.toString('base64'),
      attestations: [] as RotationAttestation[],
      manifestSeqs: { [namespaceFor(id.did)]: 3 },
    }
    await saveCustody(secrets, dir)
    // The custody file is owner-only (SN-101).
    expect(statSync(join(dir, 'custody.json')).mode & 0o777).toBe(0o600)

    const bundle = exportBundle(secrets, 'export pass')
    // The bundle carries no plaintext secrets.
    expect(bundle).not.toContain(PASS)
    expect(bundle).not.toContain(id.did)

    const restored = importBundle(bundle, 'export pass')
    expect(restored.genesisDid).toBe(id.did)
    expect(restored.passphrase).toBe(PASS)
    expect(identityFromPkcs8(Buffer.from(restored.pkcs8, 'base64')).did).toBe(id.did)
    // The SN-041 anti-rollback floor must cross machines with the secrets.
    expect(restored.manifestSeqs).toEqual({ [namespaceFor(id.did)]: 3 })

    expect(() => importBundle(bundle, 'wrong pass')).toThrow()
    expect(() => importBundle('{not json', 'export pass')).toThrow()

    // Loading the saved file returns the same secrets.
    const loaded = await loadCustody(dir)
    expect(loaded?.genesisDid).toBe(id.did)
  })
})

describe('session mirroring (SN-022)', () => {
  test('mirror writes index + chunks; hydrate reproduces the files', async () => {
    const { mirrorSession, hydrateSession } = await import('../src/client/session_mirror.ts')
    const stub = makeStub()
    const id = generateIdentity()
    const client = clientFor(stub, id)
    await client.init()

    const files = {
      'events.jsonl': '{"e":1}\n{"e":2}\n',
      'session.json': '{"id":"sess1"}\n',
      'authority.json': '{"a":1}\n',
    }
    const r = await mirrorSession(client, 'sess1', files)
    expect(r.uploaded.length).toBeGreaterThan(0)

    const hashes = await client.hashes()
    expect(hashes['sessions/sess1/000000']).toBeDefined()
    // Regions: authority.json stride 16 -> seq 1; events.jsonl stride
    // 1024 -> seq 17; session.json -> seq 1041.
    expect(hashes['sessions/sess1/000001']).toBeDefined()
    expect(hashes['sessions/sess1/000017']).toBeDefined()
    expect(hashes['sessions/sess1/001041']).toBeDefined()
    expect(hashes['sessions/sess1/000002']).toBeUndefined()

    const back = await hydrateSession(client, 'sess1')
    expect(back).not.toBeNull()
    expect(back!).toEqual(files)
  })

  test('a grown file keeps its region and does not shift neighbors', async () => {
    const { mirrorSession, hydrateSession } = await import('../src/client/session_mirror.ts')
    const stub = makeStub()
    const id = generateIdentity()
    const client = clientFor(stub, id)
    await client.init()

    // Small chunkBytes + caps so growth crosses a chunk boundary under
    // the stub's 1KB entry cap. Each file's region is 4 chunks (128/32).
    const caps = { 'authority.json': 128, 'display.json': 128, 'session.json': 128 }
    const mopts = { chunkBytes: 32, caps }
    const base = {
      'authority.json': 'a\n',
      'display.json': 'b\n',
      'session.json': 'c\n',
    }
    await mirrorSession(client, 'sess2', base, mopts)
    // Grow the first-sorted file past a chunk boundary: two chunks now.
    const grown = 'a'.repeat(48)
    await mirrorSession(client, 'sess2', { ...base, 'authority.json': grown }, mopts)

    const hashes = await client.hashes()
    expect(hashes['sessions/sess2/000001']).toBeDefined()
    expect(hashes['sessions/sess2/000002']).toBeDefined()
    // display and session keep their regions at seqs 5 and 9; nothing shifted.
    expect(hashes['sessions/sess2/000005']).toBeDefined()
    expect(hashes['sessions/sess2/000009']).toBeDefined()

    const back = await hydrateSession(client, 'sess2')
    expect(back!['authority.json']).toBe(grown)
  })

  test('a removed file leaves the index and its chunks are deleted', async () => {
    const { mirrorSession, hydrateSession } = await import('../src/client/session_mirror.ts')
    const stub = makeStub()
    const id = generateIdentity()
    const client = clientFor(stub, id)
    await client.init()

    await mirrorSession(client, 'sess3', {
      'authority.json': 'a\n',
      'checkpoint.json': 'b\n',
    })
    const r = await mirrorSession(client, 'sess3', { 'checkpoint.json': 'b\n' })
    // authority's chunk at seq 1 is deleted; checkpoint keeps region 17.
    expect(r.deleted).toContain('sessions/sess3/000001')
    const hashes = await client.hashes()
    expect(hashes['sessions/sess3/000001']).toBeUndefined()
    expect(hashes['sessions/sess3/000017']).toBeDefined()
    const back = await hydrateSession(client, 'sess3')
    expect(back).toEqual({ 'checkpoint.json': 'b\n' })
  })

  test('hydrate rejects a torn mirror', async () => {
    const { hydrateSession, SignetMirrorCorrupt } = await import('../src/client/session_mirror.ts')
    const stub = makeStub()
    const id = generateIdentity()
    const client = clientFor(stub, id)
    await client.init()
    // Hand-build a mirror whose index names a missing chunk.
    const sha = createHash('sha256').update('abcabc').digest('hex')
    await client.push({
      'sessions/torn/000000': `{"v":2,"files":[{"name":"events.jsonl","first":1,"chunks":2,"bytes":6,"sha256":"${sha}"}]}`,
      'sessions/torn/000001': 'abc',
    })
    await expect(hydrateSession(client, 'torn')).rejects.toBeInstanceOf(SignetMirrorCorrupt)
  })

  test('only fx-compatible session members mirror', async () => {
    const { mirrorSession, isMirroredSessionFile } = await import('../src/client/session_mirror.ts')
    const stub = makeStub()
    const id = generateIdentity()
    const client = clientFor(stub, id)
    await client.init()

    expect(isMirroredSessionFile('events.jsonl')).toBe(true)
    expect(isMirroredSessionFile('transcript.json')).toBe(true)
    expect(isMirroredSessionFile('commit.a1b2c3.json')).toBe(true)
    expect(isMirroredSessionFile('commit.pending.json')).toBe(false)
    expect(isMirroredSessionFile('notes.md')).toBe(false)
    expect(isMirroredSessionFile('commit.x/../../e.json')).toBe(false)

    // A member outside the interop set is rejected, never silently dropped.
    await expect(mirrorSession(client, 'sess4', { 'notes.md': 'x\n' })).rejects.toBeInstanceOf(
      Error,
    )
    // commit records mirror; the transient pending file does not.
    const r = await mirrorSession(client, 'sess4', {
      'commit.a1b2c3.json': '{}\n',
    })
    expect(r.uploaded.length).toBeGreaterThan(0)
  })

  test('a foreign transcript mirror round-trips verbatim (SN-023)', async () => {
    const { mirrorSession, hydrateSession } = await import('../src/client/session_mirror.ts')
    const stub = makeStub()
    const id = generateIdentity()
    const client = clientFor(stub, id)
    await client.init()

    const transcript = '{"schema_version":"1","session_id":"abc","steps":[{"message":"hi"}]}\n'
    const descriptor = '{"schema_version":1,"session_id":"devin-abc","source":"devin"}\n'
    await mirrorSession(client, 'devin-abc', {
      'session.json': descriptor,
      'transcript.json': transcript,
    })

    const files = await hydrateSession(client, 'devin-abc')
    expect(files).not.toBeNull()
    expect(files!['transcript.json']).toBe(transcript)
    expect(files!['session.json']).toBe(descriptor)
    expect(files!['events.jsonl']).toBeUndefined()
  })

  test('a displaced file re-uploads at its new region (packed-index migration)', async () => {
    const { mirrorSession, hydrateSession } = await import('../src/client/session_mirror.ts')
    const stub = makeStub()
    const id = generateIdentity()
    const client = clientFor(stub, id)
    await client.init()

    // An index in the old packed layout: every record at first=1,2,3
    // with stride 1. Re-mirroring must move these files into cap-sized
    // regions and re-upload the displaced chunks - not mark them
    // unchanged and leave the new seqs unwritten.
    const files = {
      'authority.json': '{"a":1}\n',
      'events.jsonl': '{"e":1}\n',
      'session.json': '{"s":1}\n',
    }
    const sha = (s: string) => createHash('sha256').update(s).digest('hex')
    const packed = {
      'sessions/mig/000000':
        `{"v":2,"files":[` +
        `{"name":"authority.json","first":1,"chunks":1,"bytes":8,"sha256":"${sha(files['authority.json'])}"},` +
        `{"name":"events.jsonl","first":2,"chunks":1,"bytes":8,"sha256":"${sha(files['events.jsonl'])}"},` +
        `{"name":"session.json","first":3,"chunks":1,"bytes":8,"sha256":"${sha(files['session.json'])}"}]}`,
      'sessions/mig/000001': files['authority.json'],
      'sessions/mig/000002': files['events.jsonl'],
      'sessions/mig/000003': files['session.json'],
    }
    await client.push(packed)

    await mirrorSession(client, 'mig', files)
    const back = await hydrateSession(client, 'mig')
    expect(back).toEqual(files)
  })

  test('hydrate rejects an index naming a non-mirrored member', async () => {
    const { hydrateSession, SignetMirrorCorrupt } = await import('../src/client/session_mirror.ts')
    const stub = makeStub()
    const id = generateIdentity()
    const client = clientFor(stub, id)
    await client.init()

    const sha = createHash('sha256').update('x').digest('hex')
    await client.push({
      'sessions/rogue/000000': `{"v":2,"files":[{"name":"evil.txt","first":1,"chunks":1,"bytes":1,"sha256":"${sha}"}]}`,
      'sessions/rogue/000001': 'x',
    })
    await expect(hydrateSession(client, 'rogue')).rejects.toBeInstanceOf(SignetMirrorCorrupt)
  })
})

describe('manifestView + readEntries (handoff selection reads)', () => {
  test('manifestView returns hash, size, and updatedAt per entry', async () => {
    const stub = makeStub()
    const id = generateIdentity()
    const client = clientFor(stub, id)
    await client.push({ 'memory/a.md': 'alpha\n', 'memory/b.md': 'beta\n' })
    const view = await client.manifestView()
    const keys = Object.keys(view).filter(k => k !== MANIFEST_ENTRY_KEY).sort()
    expect(keys).toEqual(['memory/a.md', 'memory/b.md'])
    for (const key of keys) {
      const meta = view[key]!
      expect(meta.hash).toMatch(/^sha256:[0-9a-f]{64}$/)
      expect(meta.size).toBeGreaterThan(0)
      expect(meta.updatedAt).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/)
      expect(stub.hashOf(client.namespace, key)).toBe(meta.hash)
    }
    // Ordering hint differs across entries: b was written second.
    expect(view['memory/b.md']!.updatedAt > view['memory/a.md']!.updatedAt).toBe(true)
  })

  test('manifestView returns {} for a never-written namespace', async () => {
    const stub = makeStub()
    const client = clientFor(stub, generateIdentity())
    expect(await client.manifestView()).toEqual({})
  })

  test('readEntries verifies the manifest once and returns every key', async () => {
    const stub = makeStub()
    const id = generateIdentity()
    const client = clientFor(stub, id)
    await client.push({
      'memory/one.md': '1\n',
      'memory/two.md': '2\n',
      'memory/three.md': '3\n',
      'memory/four.md': '4\n',
      'memory/five.md': '5\n',
    })
    const before = stub.requests().length
    const out = await client.readEntries([
      'memory/one.md',
      'memory/two.md',
      'memory/three.md',
      'memory/four.md',
      'memory/five.md',
    ])
    expect(out).toEqual({
      'memory/one.md': '1\n',
      'memory/two.md': '2\n',
      'memory/three.md': '3\n',
      'memory/four.md': '4\n',
      'memory/five.md': '5\n',
    })
    // Exactly one integrity-view request (signed manifest fetch + verify);
    // the remaining requests are the five authenticated blob reads.
    const hits = stub.requests().slice(before)
    const integrityGets = hits.filter(r => r.includes('view=integrity'))
    expect(integrityGets.length).toBe(1)
    const entryGets = hits.filter(r => /^GET \/signet\/[^/]+\/.+/.test(r))
    expect(entryGets.length).toBe(5)
    expect(client.manifestSeq).toBeGreaterThan(0)
  })

  test('readEntries rejects a key absent from the verified manifest', async () => {
    const stub = makeStub()
    const client = clientFor(stub, generateIdentity())
    await client.push({ 'memory/one.md': '1\n' })
    await expect(
      client.readEntries(['memory/one.md', 'memory/missing.md']),
    ).rejects.toBeInstanceOf(SignetEntryMissing)
    // Absence is not an integrity failure - the manifest was fine.
    await expect(client.readEntries(['memory/missing.md'])).rejects.not.toBeInstanceOf(
      SignetIntegrityError,
    )
  })

  test('readEntries keeps blob hash checks fail-closed', async () => {
    const stub = makeStub()
    const client = clientFor(stub, generateIdentity())
    await client.push({ 'memory/one.md': '1\n', 'memory/two.md': '2\n' })
    // Point two.md at one.md's blob: fetchable, but not the ciphertext the
    // signed manifest names for it.
    stub.repointEntry(
      client.namespace,
      'memory/two.md',
      stub.hashOf(client.namespace, 'memory/one.md')!,
    )
    await expect(client.readEntries(['memory/one.md', 'memory/two.md'])).rejects.toBeInstanceOf(
      SignetIntegrityError,
    )
  })

  test('readEntries([]) touches nothing', async () => {
    const stub = makeStub()
    const client = clientFor(stub, generateIdentity())
    await client.push({ 'memory/one.md': '1\n' })
    const before = stub.requests().length
    expect(await client.readEntries([])).toEqual({})
    expect(stub.requests().length).toBe(before)
  })
})

describe('hydrateSessionMember (member-scoped hydrate)', () => {
  const seedSession = async (client: SignetClient) => {
    const { mirrorSession } = await import('../src/client/session_mirror.ts')
    const transcript =
      '{"schema_version":1,"steps":[{"step_id":"s1","source":"user","message":"hi"}]}\n'
    const descriptor = '{"session_id":"devin-x","source":"devin","storage_format":"foreign_transcript_v1"}\n'
    await mirrorSession(client, 'devin-x', {
      'session.json': descriptor,
      'transcript.json': transcript,
      'events.jsonl': '{"e":1}\n',
    })
    return { transcript, descriptor }
  }

  test('hydrates only the requested member', async () => {
    const { hydrateSessionMember } = await import('../src/client/session_mirror.ts')
    const stub = makeStub()
    const client = clientFor(stub, generateIdentity())
    await client.init()
    const { transcript } = await seedSession(client)

    const before = stub.requests().length
    const out = await hydrateSessionMember(client, 'devin-x', 'transcript.json')
    expect(out).not.toBeNull()
    expect(out!.content).toBe(transcript)
    // Exactly one entry read beyond the index: transcript.json is 1 chunk.
    const entryReads = stub
      .requests()
      .slice(before)
      .filter(r => /^GET \/signet\/[^/]+\/.+/.test(r))
    expect(entryReads.length).toBe(2) // index + the single transcript chunk
  })

  test('returns null for an absent member and for a missing mirror', async () => {
    const { hydrateSessionMember } = await import('../src/client/session_mirror.ts')
    const stub = makeStub()
    const client = clientFor(stub, generateIdentity())
    await client.init()
    await seedSession(client)
    expect(await hydrateSessionMember(client, 'devin-x', 'authority.json')).toBeNull()
    expect(await hydrateSessionMember(client, 'devin-nope', 'transcript.json')).toBeNull()
  })

  test('a corrupt sibling member does not block transcript hydration', async () => {
    const { hydrateSessionMember } = await import('../src/client/session_mirror.ts')
    const stub = makeStub()
    const client = clientFor(stub, generateIdentity())
    await client.init()
    const { transcript } = await seedSession(client)

    // Corrupt events.jsonl's chunk: transcript hydration must not notice.
    const index = JSON.parse(
      (await client.readEntries(['sessions/devin-x/000000']))['sessions/devin-x/000000']!,
    )
    const eventsRec = index.files.find((f: { name: string }) => f.name === 'events.jsonl')
    stub.repointEntry(
      client.namespace,
      `sessions/devin-x/${String(eventsRec.first).padStart(6, '0')}`,
      `sha256:${'a'.repeat(64)}`,
    )
    const out = await hydrateSessionMember(client, 'devin-x', 'transcript.json')
    expect(out!.content).toBe(transcript)
  })

  test('a missing transcript chunk fails closed as mirror corruption', async () => {
    const { hydrateSessionMember, SignetMirrorCorrupt } = await import(
      '../src/client/session_mirror.ts'
    )
    const stub = makeStub()
    const client = clientFor(stub, generateIdentity())
    await client.init()
    await seedSession(client)
    const index = JSON.parse(
      (await client.readEntries(['sessions/devin-x/000000']))['sessions/devin-x/000000']!,
    )
    const tRec = index.files.find((f: { name: string }) => f.name === 'transcript.json')
    const chunkKey = `sessions/devin-x/${String(tRec.first).padStart(6, '0')}`
    // The verified manifest stops naming the chunk - a torn mirror.
    await client.push({}, { deletions: [chunkKey] })
    await expect(
      hydrateSessionMember(client, 'devin-x', 'transcript.json'),
    ).rejects.toBeInstanceOf(SignetMirrorCorrupt)
  })

  test('a malformed index fails closed', async () => {
    const { hydrateSessionMember, SignetMirrorCorrupt } = await import(
      '../src/client/session_mirror.ts'
    )
    const stub = makeStub()
    const client = clientFor(stub, generateIdentity())
    await client.init()
    await client.push({
      'sessions/bad/000000': '{"v":2,"files":[{"name":"transcript.json"}]}',
    })
    await expect(
      hydrateSessionMember(client, 'bad', 'transcript.json'),
    ).rejects.toBeInstanceOf(SignetMirrorCorrupt)
  })
})
