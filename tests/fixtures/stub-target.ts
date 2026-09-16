/**
 * Fault-injecting stub target - the checker's own conformance proof.
 *
 * Implements the SPEC §7 wire contract faithfully (challenge/verify with
 * real Ed25519 signature checks, namespace + entry-key grammar, manifest +
 * content-addressed blobs, the base precondition, and caps), backed by an
 * in-memory object map laid out exactly like the fs store. Each fault flag
 * disables one piece of conformant behavior, and tests prove the checker
 * fails exactly the clauses that fault violates:
 *
 *   skipAuth        -> SN-090 (no bearer required, reusable nonces, any sig)
 *   acceptStaleBase -> SN-081 (base precondition ignored; stale writes land)
 *   allowTraversal  -> SN-021 ('..'/'//'/absolute keys pass validation)
 *   leakAccessLog   -> SN-034 (store persists an access.log of bearer tokens)
 *   trustAnyChain   -> SN-052 (attestation chains accepted unchecked)
 *
 * Deterministic by construction: nonces and tokens are counters, so nothing
 * random reaches the report.
 */

import { createHash } from 'node:crypto'
import type { CheckTarget } from '../../src/check/index.ts'
import { canonicalJson, verifyDidSignature } from '../../src/client/identity.ts'
import {
  DidKey,
  EntryKey,
  Namespace,
  RotationAttestation,
  SECTIONS,
} from '../../src/types/index.ts'

// The same grammars types/index.ts encodes, duplicated so the relaxed
// traversal fault can drop exactly the traversal rules and nothing else.
const SEGMENT_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/
const CHUNK_SEQ_RE = /^[0-9]{6,}$/

export type StubFaults = {
  skipAuth?: boolean
  acceptStaleBase?: boolean
  allowTraversal?: boolean
  leakAccessLog?: boolean
  trustAnyChain?: boolean
}

// Same style of small caps the test env uses; reported through the target's
// `caps` field so the SN-081 probes size themselves correctly.
const ENTRY_CAP = 4096
const SECTION_CAP = 8192
const IDENTITY_CAP = 65_536
const TOTAL_CAP = 262_144

const sha256Hex = (s: string) => createHash('sha256').update(s).digest('hex')
const sha256Prefixed = (bytes: Uint8Array) =>
  `sha256:${createHash('sha256').update(bytes).digest('hex')}`

function stubManifestHash(hashes: Record<string, string>): string {
  const lines = Object.keys(hashes)
    .sort()
    .map(k => `${k}\t${hashes[k]}`)
    .join('\n')
  return `sha256:${sha256Hex(lines)}`
}
const EMPTY_BASE = stubManifestHash({})

const json = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
const apiError = (code: string, status: number, details?: Record<string, unknown>): Response =>
  json({ error: { code, message: code, ...(details ? { details } : {}) } }, status)

/** Decode `signet:did_<method>_<id>` back to `did:<method>:<id>`. */
function genesisOf(ns: string): string {
  const enc = ns.slice('signet:'.length)
  const a = enc.indexOf('_')
  const b = enc.indexOf('_', a + 1)
  return `${enc.slice(0, a)}:${enc.slice(a + 1, b)}:${enc.slice(b + 1)}`
}

/** Verify a presented rotation chain; returns the terminal DID or null. */
function verifyChain(raw: unknown): string | null {
  if (!Array.isArray(raw) || raw.length === 0) return null
  const chain: RotationAttestation[] = []
  for (const item of raw) {
    const parsed = RotationAttestation.safeParse(item)
    if (!parsed.success) return null
    chain.push(parsed.data)
  }
  const genesis = chain[0]!.genesisDid
  for (let i = 0; i < chain.length; i++) {
    const att = chain[i]!
    if (att.genesisDid !== genesis) return null
    if (att.seq !== i + 1) return null
    const expectedPrev = i === 0 ? '0'.repeat(64) : sha256Hex(canonicalJson(chain[i - 1]))
    if (att.prevHash !== expectedPrev) return null
    const signer = i === 0 ? genesis : chain[i - 1]!.newDid
    const body = canonicalJson({
      genesisDid: att.genesisDid,
      newDid: att.newDid,
      seq: att.seq,
      prevHash: att.prevHash,
    })
    if (!verifyDidSignature(signer, body, att.sig)) return null
  }
  return chain[chain.length - 1]!.newDid
}

export function makeStubTarget(faults: StubFaults = {}, name = 'stub'): CheckTarget {
  const objects = new Map<string, Uint8Array>()
  const nonces = new Set<string>()
  const tokens = new Map<string, string>()
  let counter = 0

  const manifestPath = (slug: string) => `ns/${slug}/manifest.json`
  const attPath = (slug: string) => `ns/${slug}/attestations.json`
  const blobPath = (slug: string, hash: string) => `ns/${slug}/blobs/${hash.slice(7)}`

  type Meta = { hash: string; size: number; updatedAt: string }
  const readManifest = (slug: string): Map<string, Meta> | null => {
    const raw = objects.get(manifestPath(slug))
    if (!raw) return null
    try {
      const parsed = JSON.parse(new TextDecoder().decode(raw)) as {
        entries?: Record<string, Meta>
      }
      return new Map(Object.entries(parsed.entries ?? {}))
    } catch {
      return null
    }
  }
  const writeManifest = (slug: string, m: Map<string, Meta>) => {
    objects.set(
      manifestPath(slug),
      new TextEncoder().encode(JSON.stringify({ entries: Object.fromEntries(m.entries()) })),
    )
  }
  const readChain = (slug: string): RotationAttestation[] | null => {
    const raw = objects.get(attPath(slug))
    if (!raw) return null
    try {
      const parsed = JSON.parse(new TextDecoder().decode(raw))
      return Array.isArray(parsed) ? (parsed as RotationAttestation[]) : null
    } catch {
      return null
    }
  }
  const writeChain = (genesis: string, chain: RotationAttestation[]) => {
    const slug = sha256Hex(`signet:${genesis.replaceAll(':', '_')}`)
    const stored = readChain(slug)
    // The longer valid chain wins; a shorter one never truncates history.
    if (stored === null || verifyChain(stored) === null || chain.length > stored.length) {
      objects.set(attPath(slug), new TextEncoder().encode(JSON.stringify(chain)))
    }
  }

  /** Entry-key validation; the allowTraversal fault drops only the
   *  traversal/separator rules ('..', '//', leading/trailing '/', '\', NUL)
   *  and additionally tolerates '.'/'..' path parts - the realistic shape of
   *  a validator that forgot dot-segments. Section, segment charset, and the
   *  sessions structure still apply. */
  const validKey = (key: string): boolean => {
    if (EntryKey.safeParse(key).success) return true
    if (!faults.allowTraversal) return false
    if (key.length < 1 || key.length > 255) return false
    const parts = key.split('/')
    if (parts.length < 2) return false
    if (!(SECTIONS as readonly string[]).includes(parts[0]!)) return false
    const okPart = (p: string) => SEGMENT_RE.test(p) || p === '.' || p === '..'
    if (parts[0] === 'sessions') {
      if (parts.length !== 3) return false
      return okPart(parts[1]!) && (CHUNK_SEQ_RE.test(parts[2]!) || /^\.\.?$/.test(parts[2]!))
    }
    return parts.slice(1).every(okPart)
  }

  const entryRead = (slug: string, ns: string, key: string): Response => {
    const m = readManifest(slug)
    if (!m) return apiError('empty', 404)
    const meta = m.get(key)
    if (!meta) return apiError('entry_not_found', 404)
    const bytes = objects.get(blobPath(slug, meta.hash))
    if (!bytes) return apiError('entry_unreadable', 503)
    return json({
      namespace: ns,
      key,
      entry: Buffer.from(bytes).toString('base64'),
      hash: meta.hash,
    })
  }

  const handle = async (req: Request): Promise<Response> => {
    const url = new URL(req.url)
    const path = url.pathname
    const method = req.method

    if (path === '/health') return json({ ok: true, service: 'signet-store-stub' })

    if (path === '/auth/challenge' && method === 'POST') {
      const nonce = `nonce-${++counter}`
      nonces.add(nonce)
      return json({ nonce, expiresAt: new Date(Date.now() + 120_000).toISOString() })
    }

    if (path === '/auth/verify' && method === 'POST') {
      const body = (await req.json().catch(() => null)) as {
        did?: string
        nonce?: string
        sig?: string
        attestations?: RotationAttestation[]
      } | null
      if (
        !body ||
        typeof body.did !== 'string' ||
        typeof body.nonce !== 'string' ||
        typeof body.sig !== 'string'
      ) {
        return apiError('bad_request', 400)
      }
      if (!DidKey.safeParse(body.did).success) return apiError('invalid_did', 400)
      if (!faults.skipAuth) {
        // The fault skips both the single-use nonce and the signature check.
        if (!nonces.delete(body.nonce)) return apiError('invalid_nonce', 401)
        if (
          !verifyDidSignature(
            body.did,
            new TextEncoder().encode(`signet-auth:${body.nonce}`),
            body.sig,
          )
        ) {
          return apiError('invalid_signature', 401)
        }
      }
      if (body.attestations !== undefined) {
        if (!Array.isArray(body.attestations) || body.attestations.length === 0) {
          return apiError('bad_request', 400)
        }
        // The trustAnyChain fault skips chain verification; the terminal
        // DID of whatever was presented is trusted on sight.
        const terminal = faults.trustAnyChain
          ? (body.attestations[body.attestations.length - 1] as RotationAttestation)?.newDid
          : verifyChain(body.attestations)
        if (terminal !== body.did) return apiError('invalid_attestation', 401)
        writeChain(body.attestations[0]!.genesisDid, body.attestations)
      }
      const token = `tok-${++counter}`
      tokens.set(token, body.did)
      return json({ token, expiresAt: new Date(Date.now() + 600_000).toISOString() })
    }

    if (!path.startsWith('/signet/')) return apiError('not_found', 404)

    let rest: string
    try {
      rest = decodeURIComponent(path.slice('/signet/'.length))
    } catch {
      return apiError('not_found', 404)
    }
    const slash = rest.indexOf('/')
    const ns = slash === -1 ? rest : rest.slice(0, slash)
    const entryKey = slash === -1 ? null : rest.slice(slash + 1)

    const auth = /Bearer\s+(.+)/i.exec(req.headers.get('authorization') ?? '')
    let did = auth ? tokens.get(auth[1].trim()) : undefined
    if (!did) {
      if (!faults.skipAuth) return apiError('unauthorized', 401)
      // The skipAuth fault: an absent or unknown bearer is silently treated
      // as the namespace's genesis DID.
      did = genesisOf(ns)
    }

    if (!Namespace.safeParse(ns).success || !DidKey.safeParse(genesisOf(ns)).success) {
      return apiError('invalid_namespace', 400)
    }
    const slug = sha256Hex(ns)
    if (did !== genesisOf(ns)) {
      const stored = readChain(slug)
      if (!stored || verifyChain(stored) !== did) return apiError('forbidden', 403)
    }

    // The leakAccessLog fault: persist the caller's bearer token alongside
    // the signet data - outside the manifest-plus-blobs layout.
    if (faults.leakAccessLog && auth) {
      const logPath = `ns/${slug}/access.log`
      const prior = objects.get(logPath) ?? new Uint8Array()
      objects.set(logPath, Buffer.concat([prior, Buffer.from(`${auth[1]!.trim()}\n`)]))
    }

    if (method === 'GET') {
      if (entryKey !== null) {
        if (!validKey(entryKey)) return apiError('invalid_key', 400)
        return entryRead(slug, ns, entryKey)
      }
      const view = url.searchParams.get('view')
      const m = readManifest(slug)
      if (view === 'hashes') {
        if (!m) return apiError('empty', 404)
        return json(Object.fromEntries([...m.entries()].map(([k, v]) => [k, v.hash])))
      }
      if (view === 'integrity') return entryRead(slug, ns, 'identity/manifest.json')
      if (view !== null) return apiError('bad_request', 400)
      if (!m) return apiError('empty', 404)
      const current = Object.fromEntries([...m.entries()].map(([k, v]) => [k, v.hash]))
      return json({
        namespace: ns,
        base: stubManifestHash(current),
        erasure: 'erases',
        entries: Object.fromEntries(m.entries()),
      })
    }

    if (method === 'PUT' && entryKey === null) {
      const body = (await req.json().catch(() => null)) as {
        entries?: Record<string, string>
        deletions?: string[]
        base?: string | null
      } | null
      if (!body || typeof body.entries !== 'object' || body.entries === null) {
        return apiError('bad_request', 400)
      }
      const m = readManifest(slug) ?? new Map<string, Meta>()
      const currentHashes = Object.fromEntries([...m.entries()].map(([k, v]) => [k, v.hash]))
      // The acceptStaleBase fault skips the base precondition entirely.
      if (!faults.acceptStaleBase && body.base !== undefined) {
        const current = stubManifestHash(currentHashes)
        const expected = body.base === null ? EMPTY_BASE : body.base
        if (expected !== current) return apiError('stale_base', 409, { current })
      }
      const accepted: string[] = []
      const deleted: string[] = []
      const skipped: { key: string; reason: string }[] = []
      const blobWrites: { path: string; bytes: Uint8Array }[] = []
      for (const key of body.deletions ?? []) {
        if (!validKey(key)) {
          skipped.push({ key, reason: 'invalid_key' })
          continue
        }
        if (m.delete(key)) deleted.push(key)
      }
      for (const [key, entryB64] of Object.entries(body.entries)) {
        if (!validKey(key)) {
          skipped.push({ key, reason: 'invalid_key' })
          continue
        }
        const bytes = Buffer.from(entryB64, 'base64')
        if (bytes.byteLength > ENTRY_CAP) {
          skipped.push({ key, reason: 'entry_too_large' })
          continue
        }
        const hash = sha256Prefixed(bytes)
        if (m.get(key)?.hash === hash) {
          accepted.push(key)
          continue
        }
        blobWrites.push({ path: blobPath(slug, hash), bytes: new Uint8Array(bytes) })
        m.set(key, { hash, size: bytes.byteLength, updatedAt: 'stub' })
        accepted.push(key)
      }
      // All-or-nothing caps: projected before any write lands.
      const sectionBytes = new Map<string, number>()
      let total = 0
      for (const [key, meta] of m.entries()) {
        const section = key.split('/')[0]!
        sectionBytes.set(section, (sectionBytes.get(section) ?? 0) + meta.size)
        total += meta.size
      }
      for (const [section, bytesSum] of sectionBytes) {
        const cap = section === 'identity' ? IDENTITY_CAP : SECTION_CAP
        if (bytesSum > cap) {
          return apiError('section_cap_exceeded', 413, { section, max_bytes: cap })
        }
      }
      if (total > TOTAL_CAP) return apiError('namespace_too_large', 413, { max_bytes: TOTAL_CAP })
      for (const w of blobWrites) objects.set(w.path, w.bytes)
      writeManifest(slug, m)
      const nextHashes = Object.fromEntries([...m.entries()].map(([k, v]) => [k, v.hash]))
      return json({
        namespace: ns,
        base: stubManifestHash(nextHashes),
        erasure: 'erases',
        accepted,
        deleted: deleted.filter(k => !m.has(k)),
        skipped,
      })
    }
    return apiError('method_not_allowed', 405)
  }

  return {
    name,
    url: 'http://stub',
    fetch: req => handle(req),
    clientFetch: ((input: RequestInfo | URL, init?: RequestInit) =>
      handle(new Request(input, init))) as typeof fetch,
    store: {
      paths: async () => [...objects.keys()].sort(),
      get: async path => objects.get(path) ?? null,
    },
    caps: { entry: ENTRY_CAP, memory: SECTION_CAP },
  }
}
