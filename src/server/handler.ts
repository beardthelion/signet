/**
 * HTTP request handler for the passport wire protocol (SPEC §7). Extracted
 * from index.ts so it can be unit-tested via handleRequest(new Request(...))
 * without binding a socket.
 *
 * Routes:
 *   GET  /health
 *   POST /auth/challenge               → {nonce, expiresAt} (single-use, 120 s)
 *   POST /auth/verify                  → {token, expiresAt} bearer bound to a DID
 *   GET  /passport/<ns>                → manifest view (entry metadata)
 *   GET  /passport/<ns>?view=hashes    → {entryKey: sha256-hash} for delta sync
 *   GET  /passport/<ns>?view=integrity → the identity/manifest.json blob
 *   GET  /passport/<ns>/<entryKey>     → one ciphertext blob
 *   PUT  /passport/<ns>                → delta upsert {base, entries, deletions?}
 *
 * Every /passport/ request needs a bearer bound to a DID authorized for the
 * namespace: the genesis DID, or the terminal DID of a valid rotation chain
 * (PS-090, PS-052). Unauthenticated → 401; wrong DID → 403.
 *
 * The namespace is always a single path segment (its charset has no '/'), so
 * everything after `/passport/<ns>/` is the entry key.
 */

import { DidKey, RotationAttestation } from '../types/index.ts'
import {
  consumeNonce,
  isAuthorizedDid,
  issueChallenge,
  issueToken,
  persistAttestationChain,
  resolveBearer,
  verifyAttestationChain,
  verifyDidSignature,
} from './auth.ts'
import { logJsonLine } from './log.ts'
import { InvalidNameError, validateEntryKey, validateNamespace } from './namespace.ts'
import {
  type EntryRead,
  getEntry,
  getHashes,
  getIntegrityManifest,
  getManifest,
  parseUpsertBody,
  StaleBaseError,
  UnreadableManifestError,
  upsert,
} from './passport.ts'
import { caps, QuotaError } from './quota.ts'
import { take } from './ratelimit.ts'

// Applied to every response. The API serves only JSON and is consumed by
// programmatic clients, so we lock down sniffing/caching/referrer leakage.
const SECURITY_HEADERS = {
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'cache-control': 'no-store',
}

function json(body: unknown, status = 200, extraHeaders?: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...SECURITY_HEADERS, ...extraHeaders },
  })
}

/**
 * Internal marker carrying a refusal's error code on the Response itself, so
 * the rejection logger never has to clone and re-parse the body.
 */
const ERROR_CODE: unique symbol = Symbol('passport.errorCode')

function apiError(
  code: string,
  message: string,
  status: number,
  details?: Record<string, unknown>,
  extraHeaders?: Record<string, string>,
) {
  const res = json(
    { error: { code, message, ...(details ? { details } : {}) } },
    status,
    extraHeaders,
  )
  ;(res as unknown as Record<symbol, unknown>)[ERROR_CODE] = code
  return res
}

const PASSPORT_PREFIX = '/passport/'

/** Path decode outcome: off-route, malformed escape, or the parsed parts. */
type PassportPath = { namespace: string; entryKey: string | null } | 'malformed' | null

/**
 * Split `/passport/<ns>/<entryKey...>` into its parts. The namespace is a
 * single segment (no '/' survives its grammar); the rest is the entry key,
 * which may itself contain '/'. Returns null off-route and 'malformed' when
 * the percent-encoding itself is broken — that is a 400, not a 404: the
 * route matched but the path is not decodable.
 */
function parsePassportPath(pathname: string): PassportPath {
  if (!pathname.startsWith(PASSPORT_PREFIX)) return null
  let rest: string
  try {
    rest = decodeURIComponent(pathname.slice(PASSPORT_PREFIX.length))
  } catch {
    return 'malformed'
  }
  if (!rest) return { namespace: '', entryKey: null }
  const slash = rest.indexOf('/')
  if (slash === -1) return { namespace: rest, entryKey: null }
  return { namespace: rest.slice(0, slash), entryKey: rest.slice(slash + 1) }
}

/**
 * Map the two refusals `upsert` can raise. Deliberately not folded into the
 * outer catch: that would widen these statuses to cover every read path in
 * the handler. Returns null for anything else, which the caller rethrows.
 */
function upsertFailure(err: unknown): Response | null {
  if (err instanceof QuotaError) return apiError(err.code, err.message, 413, err.details)
  if (err instanceof StaleBaseError) return apiError(err.code, err.message, 409, err.details)
  return null
}

/**
 * A namespace whose index cannot be parsed answers 503 with its own code
 * rather than a generic 500: "internal error" tells a caller to retry
 * something no retry can fix.
 */
function manifestFailure(err: unknown): Response | null {
  if (err instanceof UnreadableManifestError) return apiError(err.code, err.message, 503)
  return null
}

/**
 * One line per refused request, after the response is built, so the recorded
 * code is literally the code the caller received. The field set is a fixed
 * allowlist: the space of things that must never appear in a log on a
 * crypto-blind server (entry keys, raw namespaces, ciphertext, tokens) is
 * open-ended, and a fixed set of fields has nowhere for any of it to go.
 */
function logRejection(fields: {
  owner: string
  code: string
  status: number
  route: string
}): void {
  logJsonLine(fields)
}

/** Per-request facts the rejection log needs, filled in as they become known. */
type RequestContext = { owner: string; route: string }

export async function handleRequest(req: Request): Promise<Response> {
  const ctx: RequestContext = { owner: 'anonymous', route: 'other' }
  let res: Response
  try {
    res = await respond(req, ctx)
  } catch (err) {
    console.error(`[passport] handler error (${(err as Error)?.constructor?.name ?? 'unknown'})`)
    res = apiError('internal', 'internal error', 500)
  }
  if (res.status >= 400) {
    // The code rides on the response via ERROR_CODE; a >=400 response built
    // outside apiError (there is none today) logs 'unknown', as before.
    const marked = (res as unknown as Record<symbol, unknown>)[ERROR_CODE]
    logRejection({
      owner: ctx.owner,
      code: typeof marked === 'string' ? marked : 'unknown',
      status: res.status,
      route: ctx.route,
    })
  }
  return res
}

async function respond(req: Request, ctx: RequestContext): Promise<Response> {
  const url = new URL(req.url)
  const { pathname } = url

  if (pathname === '/health') {
    return json({ ok: true, service: 'passport-store' })
  }

  // Resolve the bearer before refusing anything so the throttle below keys
  // on the caller when there is one. Every refusal writes a log line; leaving
  // pre-auth branches unthrottled would let an anonymous caller turn a cheap
  // request into unbounded log volume on the machine holding ciphertext.
  const did = resolveBearer(req)
  ctx.owner = did ?? 'anonymous'

  const rate = take(ctx.owner, Date.now())
  if (!rate.ok) {
    return apiError('rate_limited', 'too many requests', 429, undefined, {
      'retry-after': String(rate.retryAfterSec),
    })
  }

  // ── Auth endpoints (no bearer required) ──────────────────────────────
  if (pathname === '/auth/challenge') {
    if (req.method !== 'POST') return apiError('method_not_allowed', 'POST only', 405)
    const challenge = issueChallenge()
    if (!challenge) return apiError('rate_limited', 'too many outstanding challenges', 429)
    return json(challenge)
  }

  if (pathname === '/auth/verify') {
    ctx.route = 'auth'
    if (req.method !== 'POST') return apiError('method_not_allowed', 'POST only', 405)
    return verify(req)
  }

  // ── Passport data endpoints ──────────────────────────────────────────
  const parsed = parsePassportPath(pathname)
  if (parsed === 'malformed') {
    return apiError('bad_request', 'malformed percent-encoding in path', 400)
  }
  if (!parsed) return apiError('not_found', 'unknown route', 404)
  ctx.route = 'passport'

  if (!did) return apiError('unauthorized', 'missing or invalid bearer token', 401)

  let namespace: string
  try {
    namespace = validateNamespace(parsed.namespace)
  } catch (err) {
    if (err instanceof InvalidNameError) return apiError('invalid_namespace', err.message, 400)
    throw err
  }
  if (!(await isAuthorizedDid(did, namespace))) {
    return apiError('forbidden', 'did is not authorized for this namespace', 403)
  }

  try {
    if (req.method === 'GET') {
      if (parsed.entryKey !== null) {
        // The key is attacker-controlled; it is validated before it can
        // reach a storage path (PS-021).
        try {
          validateEntryKey(parsed.entryKey)
        } catch (err) {
          return apiError('invalid_key', (err as Error).message, 400)
        }
        return entryResponse(await getEntry(namespace, parsed.entryKey))
      }
      const view = url.searchParams.get('view')
      if (view === 'hashes') {
        const hashes = await getHashes(namespace)
        if (hashes === null) return apiError('empty', 'no passport for this namespace yet', 404)
        return json(hashes)
      }
      if (view === 'integrity') {
        return entryResponse(await getIntegrityManifest(namespace))
      }
      if (view !== null) return apiError('bad_request', `unknown view "${view}"`, 400)
      const manifest = await getManifest(namespace)
      if (manifest === null) return apiError('empty', 'no passport for this namespace yet', 404)
      return json(manifest)
    }

    if (req.method === 'PUT') {
      if (parsed.entryKey !== null) {
        return apiError('method_not_allowed', 'PUT targets the namespace, not an entry', 405)
      }
      const len = Number(req.headers.get('content-length') ?? 0)
      if (len > caps.body) {
        return apiError('payload_too_large', 'request body too large', 413, {
          max_bytes: caps.body,
        })
      }
      let body: unknown
      try {
        body = await req.json()
      } catch {
        return apiError('bad_request', 'body is not valid JSON', 400)
      }
      let parsedReq: ReturnType<typeof parseUpsertBody>
      try {
        parsedReq = parseUpsertBody(body)
      } catch (err) {
        return apiError('bad_request', (err as Error).message, 400)
      }
      try {
        return json(await upsert(namespace, parsedReq, new Date().toISOString()))
      } catch (err) {
        const mapped = upsertFailure(err)
        if (mapped) return mapped
        throw err
      }
    }

    return apiError('method_not_allowed', `${req.method} not supported`, 405)
  } catch (err) {
    const manifest = manifestFailure(err)
    if (manifest) return manifest
    // The error's class only. A store error commonly carries an endpoint, a
    // bucket and an object path, and that path carries a namespace slug.
    console.error(`[passport] handler error (${(err as Error)?.constructor?.name ?? 'unknown'})`)
    return apiError('internal', 'internal error', 500)
  }
}

/** Map a single-entry read's four outcomes to four distinct responses. */
function entryResponse(found: EntryRead): Response {
  if (found.status === 'no_namespace') {
    return apiError('empty', 'no passport for this namespace yet', 404)
  }
  if (found.status === 'no_entry') {
    return apiError('entry_not_found', 'no such entry in this namespace', 404)
  }
  if (found.status === 'unreadable') {
    // The manifest names this key and the store cannot produce its body. Not
    // a 404: the entry is not absent, it is unserveable.
    return apiError('entry_unreadable', 'entry body is missing from the store', 503)
  }
  return json(found.entry)
}

/**
 * POST /auth/verify — {did, nonce, sig, attestations?}.
 *
 * The nonce is consumed before the signature check: single-use means a
 * failed verify must not leave it live for a retry race. `sig` is the
 * base64 Ed25519 signature over the nonce's UTF-8 bytes by `did`'s key.
 * `attestations`, when present, must form a valid rotation chain rooted at
 * their declared genesisDid and terminating at `did` (PS-051/052); a valid
 * chain is persisted under that genesis namespace so later requests from
 * `did` are authorized against it.
 */
async function verify(req: Request): Promise<Response> {
  let body: unknown
  try {
    body = await req.json()
  } catch {
    return apiError('bad_request', 'body is not valid JSON', 400)
  }
  const obj = body as Record<string, unknown>
  if (
    typeof obj?.did !== 'string' ||
    typeof obj.nonce !== 'string' ||
    typeof obj.sig !== 'string'
  ) {
    return apiError('bad_request', 'body must be {did, nonce, sig, attestations?}', 400)
  }
  if (!DidKey.safeParse(obj.did).success) {
    return apiError('invalid_did', 'did must be a did:key', 400)
  }
  const did = obj.did
  if (!consumeNonce(obj.nonce)) {
    return apiError('invalid_nonce', 'nonce is unknown, expired, or already used', 401)
  }
  // The preimage is domain-separated: the same key signs attestations and
  // manifests, so the nonce is never signed bare (SPEC §7.1).
  if (!verifyDidSignature(did, new TextEncoder().encode(`passport-auth:${obj.nonce}`), obj.sig)) {
    return apiError('invalid_signature', 'signature does not verify against the DID key', 401)
  }

  if (obj.attestations !== undefined) {
    if (!Array.isArray(obj.attestations) || obj.attestations.length === 0) {
      return apiError('bad_request', '`attestations` must be a non-empty array', 400)
    }
    // The chain verifier schema-validates every attestation itself; a
    // malformed element fails closed inside it rather than being pre-parsed
    // here. The declared genesis comes from the first attestation alone.
    const first = RotationAttestation.safeParse(obj.attestations[0])
    const genesis = first.success ? first.data.genesisDid : ''
    if (verifyAttestationChain(genesis, obj.attestations) !== did) {
      return apiError('invalid_attestation', 'attestation chain does not authorize this DID', 401)
    }
    // Verified, so every element parses; persist the normalized objects.
    const chain = obj.attestations.map(item => RotationAttestation.parse(item))
    await persistAttestationChain(genesis, chain)
  }

  const issued = issueToken(did)
  if (!issued) return apiError('rate_limited', 'too many outstanding tokens', 429)
  return json(issued)
}
