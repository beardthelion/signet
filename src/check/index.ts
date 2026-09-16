/**
 * passport-check — the deterministic clause-level conformance checker
 * (SPEC §8). Runs every check registered in spec/clauses.json against a
 * target and emits the sorted, spec-version-stamped report defined by
 * spec/report-schema.json.
 *
 * Trust boundary: a target is attacker-controlled infrastructure. Every
 * response it returns is untrusted input — checks assert on status codes and
 * structural shapes, and detail strings carried into the report are passed
 * through sanitizeDetail so a hostile target cannot plant DIDs, digests, or
 * local paths in a shareable artifact. The checker itself holds real secrets
 * (a passphrase, Ed25519 keys) to exercise the wire contract; those never
 * appear in the report either.
 *
 * Targets:
 *   - localTarget(): the reference server in-process via handleRequest, with
 *     raw store access and process-level bind probes. The most thorough mode.
 *   - httpTarget(url): a live store over a socket. Store-internal and
 *     process-startup clauses report `unsupported` rather than fake a pass.
 *   - A test fixture can build a CheckTarget over a fault-injecting stub to
 *     prove each clause fails exactly when its behavior is violated.
 */

import { mkdtempSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { PassportClient } from '../client/client.ts'
import {
  AUTH_PREIMAGE_PREFIX,
  generateIdentity,
  type Identity,
  signMessage,
} from '../client/identity.ts'
import { CHECK_PASSPHRASE, checks } from './clauses.ts'
import {
  buildReport,
  type ClauseResult,
  type ConformanceReport,
  type ReportResult,
} from './report.ts'
import { cleanupTmpDirs, trackTmpDir } from './tmpdirs.ts'

export { trackTmpDir }

// ─── Target model ───────────────────────────────────────────────────────

/** Raw access to everything the store persists — needed by the leak-boundary
 *  and blob-inspection clauses (PS-034/035). Absent for socket targets. */
export type StoreAccess = {
  /** Every object path the store holds, posix-style (e.g. ns/<slug>/manifest.json). */
  paths(): Promise<string[]>
  /** Raw bytes of one stored object, null if absent. */
  get(path: string): Promise<Uint8Array | null>
}

export type CheckTarget = {
  /** Copied verbatim into the report's `target` field. */
  name: string
  /** Base URL used to build Request objects (cosmetic for in-process). */
  url: string
  /** The wire boundary: one Request in, one Response out. */
  fetch(req: Request): Promise<Response>
  /** fetch-shaped adapter for PassportClient. */
  clientFetch: typeof fetch
  /** Raw store access; undefined when the backend is opaque to the harness. */
  store?: StoreAccess
  /** Byte caps the PS-081 probes are sized against; undefined if unknown. */
  caps?: { entry: number; memory: number }
  /** Process-startup probes only an in-process local harness can run. */
  bindProbe?(): Promise<ClauseResult>
  localModeProbe?(): Promise<ClauseResult>
}

/** A provisioned passport: a real client that has completed init + auth. */
export type Session = {
  client: PassportClient
  identity: Identity
  namespace: string
  /** A bearer token for raw wire probes. */
  token: string
}

/** Everything a check function needs. Wire responses are untrusted input. */
export type CheckContext = {
  target: CheckTarget
  specVersion: string
  /** POST /auth/challenge -> nonce string. Throws if the endpoint misbehaves. */
  challenge(): Promise<string>
  /** POST /auth/verify with a caller-built body; returns the HTTP status. */
  tryVerify(body: Record<string, unknown>): Promise<number>
  /** Full challenge -> verify for a real identity; returns the bearer token. */
  tokenFor(identity: Identity, attestations?: unknown[]): Promise<string>
  /** One wire request. `path` is appended verbatim after the base URL. */
  wire(method: string, path: string, opts?: { token?: string; body?: unknown }): Promise<Response>
  /** Fresh identity + initialized passport + bearer token. */
  provision(): Promise<Session>
}

export type CheckFn = (ctx: CheckContext) => Promise<ClauseResult>

// ─── Registry ───────────────────────────────────────────────────────────

type ClauseRegistry = {
  specVersion: string
  clauses: { id: string; title: string; check: string }[]
}

/** spec/clauses.json — the registry the implementation must stay in sync with. */
export function loadRegistry(): ClauseRegistry {
  const url = new URL('../../spec/clauses.json', import.meta.url)
  return JSON.parse(readFileSync(url, 'utf8')) as ClauseRegistry
}

// ─── Context implementation ─────────────────────────────────────────────

/** Per-request budget on the wire; a hung target must not freeze the run. */
const WIRE_TIMEOUT_MS = 30_000
/** Per-check deadline; a check that outlives it is recorded as a fail. */
const CHECK_DEADLINE_MS = 120_000

function makeContext(target: CheckTarget, specVersion: string): CheckContext {
  const wire: CheckContext['wire'] = (method, path, opts) => {
    const headers: Record<string, string> = {}
    if (opts?.token) headers.authorization = `Bearer ${opts.token}`
    if (opts?.body !== undefined) headers['content-type'] = 'application/json'
    return target.fetch(
      new Request(`${target.url}${path}`, {
        method,
        headers,
        signal: AbortSignal.timeout(WIRE_TIMEOUT_MS),
        ...(opts?.body !== undefined ? { body: JSON.stringify(opts.body) } : {}),
      }),
    )
  }

  const challenge: CheckContext['challenge'] = async () => {
    const res = await wire('POST', '/auth/challenge', { body: {} })
    const body = (await res.json().catch(() => ({}))) as { nonce?: unknown }
    if (res.status !== 200 || typeof body.nonce !== 'string') {
      throw new Error(`challenge answered ${res.status} without a nonce`)
    }
    return body.nonce
  }

  const tryVerify: CheckContext['tryVerify'] = async body =>
    (await wire('POST', '/auth/verify', { body })).status

  const tokenFor: CheckContext['tokenFor'] = async (identity, attestations) => {
    const nonce = await challenge()
    const res = await wire('POST', '/auth/verify', {
      body: {
        did: identity.did,
        nonce,
        sig: signMessage(identity.privateKey, `${AUTH_PREIMAGE_PREFIX}${nonce}`),
        ...(attestations ? { attestations } : {}),
      },
    })
    const body = (await res.json().catch(() => ({}))) as { token?: unknown }
    if (res.status !== 200 || typeof body.token !== 'string') {
      throw new Error(`verify answered ${res.status} without a token`)
    }
    return body.token
  }

  const provision: CheckContext['provision'] = async () => {
    const identity = generateIdentity()
    const client = new PassportClient({
      url: target.url,
      fetchFn: target.clientFetch,
      identity,
      passphrase: CHECK_PASSPHRASE,
    })
    await client.init()
    const token = await tokenFor(identity)
    return { client, identity, namespace: client.namespace, token }
  }

  return { target, specVersion, challenge, tryVerify, tokenFor, wire, provision }
}

// ─── Detail sanitizer ───────────────────────────────────────────────────

const MAX_DETAIL = 240

/**
 * Scrub anything that could make two runs differ or leak target internals
 * into a shareable report: DIDs, sha256 digests, bearer-token-length base64
 * runs, and this machine's temp paths.
 */
export function sanitizeDetail(detail: string): string {
  const clean = detail
    .replace(/did:key:z[1-9A-HJ-NP-Za-km-z]+/g, 'did:key:z*')
    .replace(/\b[0-9a-f]{64}\b/g, '<sha256>')
    .replace(/\b[A-Za-z0-9_-]{40,}\b/g, '<token>')
    .replaceAll(tmpdir(), '<tmp>')
    .replace(/\s+/g, ' ')
    .trim()
  return clean.length > MAX_DETAIL ? `${clean.slice(0, MAX_DETAIL)}...` : clean
}

// ─── Runner ─────────────────────────────────────────────────────────────

/**
 * Run every clause in the registry against the target, in clause-id order.
 * A check that throws is a fail, not a crash — the report must always be
 * complete and sorted.
 */
export async function runCheck(target: CheckTarget): Promise<ConformanceReport> {
  const registry = loadRegistry()
  const ctx = makeContext(target, registry.specVersion)
  const results: ReportResult[] = []
  try {
    for (const clause of registry.clauses) {
      const fn = (checks as Record<string, CheckFn>)[clause.check]
      if (!fn) {
        results.push({
          clause: clause.id,
          status: 'unsupported',
          detail: `no checker function registered as ${clause.check}`,
        })
        continue
      }
      let r: ClauseResult
      let timer: ReturnType<typeof setTimeout> | undefined
      try {
        // A target that hangs a check must not freeze the report: the check
        // races a deadline and loses.
        r = await Promise.race([
          fn(ctx),
          new Promise<ClauseResult>(resolve => {
            timer = setTimeout(
              () =>
                resolve({
                  status: 'fail',
                  detail: `check exceeded the ${CHECK_DEADLINE_MS}ms deadline`,
                }),
              CHECK_DEADLINE_MS,
            )
          }),
        ])
      } catch (err) {
        r = {
          status: 'fail',
          detail: `check threw: ${(err as Error)?.message ?? String(err)}`,
        }
      } finally {
        clearTimeout(timer)
      }
      results.push({
        clause: clause.id,
        status: r.status,
        ...(r.detail ? { detail: sanitizeDetail(r.detail) } : {}),
      })
    }
  } finally {
    // Temp dirs the harness created (store roots, custody dirs) are run
    // scratch, not artifacts; remove them once the checks are done.
    cleanupTmpDirs()
  }
  return buildReport(registry.specVersion, target.name, results)
}

/** Whether the report should exit nonzero: any clause failed. */
export function reportHasFailures(report: ConformanceReport): boolean {
  return report.summary.fail > 0
}

// ─── Targets ────────────────────────────────────────────────────────────

/** Recursively list every file under dir as posix-style relative paths. */
async function* walkFiles(dir: string, prefix = ''): AsyncGenerator<string> {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const rel = prefix ? `${prefix}/${e.name}` : e.name
    if (e.isDirectory()) yield* walkFiles(join(dir, e.name), rel)
    else if (e.isFile()) yield rel
  }
}

/** StoreAccess over a local filesystem store root. */
function fsStoreAccess(root: string): StoreAccess {
  return {
    async paths() {
      const out: string[] = []
      try {
        for await (const rel of walkFiles(root)) out.push(rel)
      } catch {
        // An unreadable store dir means there is nothing to inspect.
      }
      return out.sort()
    },
    async get(path) {
      try {
        if (statSync(join(root, path)).isDirectory()) return null
      } catch {
        return null
      }
      try {
        return new Uint8Array(readFileSync(join(root, path)))
      } catch {
        return null
      }
    },
  }
}

const SERVER_ENTRY = new URL('../server/index.ts', import.meta.url).pathname

type Spawned = {
  code: number | null // null = still running when we stopped waiting
  stdout: string
  stderr: string
  kill(): void
}

/**
 * Spawn the real server entrypoint as a child process. Only meaningful for a
 * local target: it exercises startup policy, which the wire cannot reach.
 */
async function spawnServer(env: Record<string, string>, waitMs: number): Promise<Spawned> {
  const proc = Bun.spawn([process.execPath, SERVER_ENTRY], {
    env: {
      ...process.env,
      STORE: 'fs',
      PASSPORT_DATA_DIR: trackTmpDir(mkdtempSync(join(tmpdir(), 'passport-check-serve-'))),
      ...env,
    },
    stdout: 'pipe',
    stderr: 'pipe',
  })
  let stdout = ''
  let stderr = ''
  const decoder = new TextDecoder()
  const pump = async (stream: ReadableStream<Uint8Array>, into: (s: string) => void) => {
    const reader = stream.getReader()
    for (;;) {
      const { value, done } = await reader.read()
      if (done) break
      into(decoder.decode(value))
    }
  }
  void pump(proc.stdout, s => {
    stdout += s
  })
  void pump(proc.stderr, s => {
    stderr += s
  })
  const deadline = Date.now() + waitMs
  let code: number | null = null
  while (Date.now() < deadline) {
    const done = await Promise.race([
      proc.exited.then(c => c),
      new Promise<null>(r => setTimeout(() => r(null), 50)),
    ])
    if (done !== null) {
      code = done
      break
    }
    if (stdout.includes('listening')) break
  }
  return { code, stdout, stderr, kill: () => proc.kill() }
}

/**
 * PS-091: a non-loopback bind without TLS must refuse to start; a loopback
 * bind must come up. Probed by actually starting the server entrypoint.
 */
async function probeBindPolicy(): Promise<ClauseResult> {
  if (typeof Bun === 'undefined') {
    return { status: 'unsupported', detail: 'bind probe needs the Bun runtime' }
  }
  const refused = await spawnServer(
    { PASSPORT_MODE: 'hosted', PASSPORT_HOST: '0.0.0.0', PORT: '0' },
    10_000,
  )
  refused.kill()
  if (refused.code === null) {
    return { status: 'fail', detail: 'non-loopback bind without TLS stayed up' }
  }
  if (refused.code === 0 || !/tls/i.test(refused.stderr)) {
    return { status: 'fail', detail: 'non-loopback bind without TLS exited without a TLS refusal' }
  }
  const loopback = await spawnServer({ PASSPORT_HOST: '127.0.0.1', PORT: '0' }, 10_000)
  loopback.kill()
  if (!loopback.stdout.includes('listening') || loopback.code !== null) {
    return { status: 'fail', detail: 'loopback bind did not come up' }
  }
  return { status: 'pass' }
}

/** PS-092: local mode refuses a non-loopback bind even with TLS configured. */
async function probeLocalMode(): Promise<ClauseResult> {
  if (typeof Bun === 'undefined') {
    return { status: 'unsupported', detail: 'local-mode probe needs the Bun runtime' }
  }
  const res = await spawnServer(
    {
      PASSPORT_MODE: 'local',
      PASSPORT_HOST: '0.0.0.0',
      PORT: '0',
      PASSPORT_TLS_CERT: '/nonexistent-cert.pem',
      PASSPORT_TLS_KEY: '/nonexistent-key.pem',
    },
    10_000,
  )
  res.kill()
  if (res.code === null) {
    return { status: 'fail', detail: 'local mode bound non-loopback instead of refusing' }
  }
  if (res.code === 0 || !/local mode|loopback/i.test(res.stderr)) {
    return { status: 'fail', detail: 'local-mode non-loopback refusal missing' }
  }
  return { status: 'pass' }
}

/**
 * The reference target: the suite's own server driven in-process through
 * handleRequest, backed by a fresh filesystem store. Env defaults are set
 * before the server modules load (they freeze env reads at import time), so
 * callers can override caps/data-dir through the environment.
 */
export async function localTarget(opts?: {
  name?: string
  dataDir?: string
}): Promise<CheckTarget> {
  // Isolation is the default: without an explicit dataDir the checker gets a
  // fresh mkdtemp store, and the ambient PASSPORT_DATA_DIR is never honored.
  // Callers that want a specific store pass it in.
  const dataDir = opts?.dataDir ?? trackTmpDir(mkdtempSync(join(tmpdir(), 'passport-check-')))
  process.env.STORE ??= 'fs'
  process.env.PASSPORT_DATA_DIR = dataDir
  process.env.PASSPORT_MODE ??= 'local'
  const storeDir = dataDir
  const { handleRequest } = await import('../server/handler.ts')
  const { setStore } = await import('../server/store/blob.ts')
  const { FsBlobStore } = await import('../server/store/fs.ts')
  const { caps } = await import('../server/quota.ts')
  const store = new FsBlobStore(storeDir)
  setStore(store)
  return {
    name: opts?.name ?? 'local',
    url: 'http://passport-check.local',
    fetch: req => handleRequest(req),
    clientFetch: ((input: RequestInfo | URL, init?: RequestInit) =>
      handleRequest(new Request(input, init))) as typeof fetch,
    store: fsStoreAccess(storeDir),
    caps: { entry: caps.entry, memory: caps.sections.memory },
    bindProbe: probeBindPolicy,
    localModeProbe: probeLocalMode,
  }
}

/** A live store over a socket. Store internals and startup policy are
 *  unreachable here; the affected clauses report unsupported. Every fetch
 *  carries a timeout so a hung target cannot freeze the run. */
export function httpTarget(url: string, name?: string): CheckTarget {
  const base = url.replace(/\/$/, '')
  // Honor a caller-supplied signal (wire() sets its own); add one otherwise.
  const timedFetch = ((input: RequestInfo | URL, init?: RequestInit) =>
    fetch(input, {
      ...init,
      signal: init?.signal ?? AbortSignal.timeout(WIRE_TIMEOUT_MS),
    })) as typeof fetch
  return {
    name: name ?? base,
    url: base,
    fetch: req => (req.signal ? fetch(req) : timedFetch(req)),
    clientFetch: timedFetch,
  }
}
