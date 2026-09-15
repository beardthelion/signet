/**
 * PassportClient — the zero-knowledge sync client (SPEC §7).
 *
 * Wraps the crypto, the identity, and the HTTP contract so callers (the CLI,
 * the MCP adapter, a harness) work in plaintext and never touch ciphertext
 * or the wire format. Encryption and signing happen in-process with keys
 * from the custody store; the passphrase and private key never leave this
 * machine. Everything the server can see stays inside the PS-034 metadata
 * boundary: entry keys, ciphertext, sizes/hashes, the signed integrity
 * manifest, and rotation attestations.
 *
 * The wire protocol (SPEC §7.1):
 *   POST /auth/challenge            → {nonce, expiresAt}
 *   POST /auth/verify {did, nonce, sig, attestations?} → {token, expiresAt}
 *   GET  /passport/<ns>             → manifest view (entry metadata)
 *   GET  /passport/<ns>?view=hashes → {entryKey: sha256-hash} for delta sync
 *   GET  /passport/<ns>?view=integrity → the signed identity/manifest.json blob
 *   GET  /passport/<ns>/<entryKey>  → one ciphertext blob
 *   PUT  /passport/<ns>             → {base, entries} delta upsert
 *
 * Integrity (PS-040/041): the client writes `identity/manifest.json`, a
 * signed {seq, specVersion, genesisDid, entries} document mapping each entry
 * key to its ciphertext hash (the manifest's own key is excluded — a
 * self-referential hash cannot exist). On pull the client verifies the
 * signature against the currently authorized DID and fails closed on a
 * tampered, unsigned, or rolled-back manifest; on push it refuses to build
 * on top of a manifest that fails those checks.
 *
 * The boundary is deliberately thin: `fetch` is injectable so tests can
 * stand up the wire contract in-process.
 */

import { createHash } from 'node:crypto'
import { EntryKey, type RotationAttestation, SignedManifest } from '../types/index.ts'
import { ciphertextHash, decryptEntry, deriveKey, encryptEntry } from './crypto.ts'
import {
  attestationHash,
  buildRotationAttestation,
  canonicalJson,
  GENESIS_PREV_HASH,
  generateIdentity,
  type Identity,
  namespaceFor,
  signMessage,
  verifyDidSignature,
} from './identity.ts'
import { enforce, type Finding, type ScanMode } from './secretscan.ts'

const SPEC_VERSION = 'passport-spec/0.1'

/** The entry carrying the signed integrity manifest (PS-040). */
export const MANIFEST_ENTRY_KEY = 'identity/manifest.json'

/** did.json payload — the same shape scripts/gen-vectors.ts emits. */
export function didDocument(did: string): string {
  return `${JSON.stringify({ did, method: 'did:key' })}\n`
}

/**
 * The manifest hash a PUT's `base` refers to: `sha256:` hex over the sorted
 * `key\thash` lines of the entry-hash map. Both sides compute it from the
 * bare ?view=hashes map, so the wire never needs a second digest field.
 * Reimplemented here rather than imported from src/server — the client is
 * the other side of the trust boundary and does not depend on server modules.
 */
export function manifestHash(entryHashes: Record<string, string>): string {
  const lines = Object.keys(entryHashes)
    .sort()
    .map(k => `${k}\t${entryHashes[k]}`)
    .join('\n')
  return `sha256:${sha256HexLocal(lines)}`
}

function sha256HexLocal(s: string): string {
  return createHash('sha256').update(s).digest('hex')
}

/** A session chunk's entry key: `sessions/<id>/<zero-padded seq>` (PS-022). */
export function sessionEntryKey(id: string, seq: number): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(id)) {
    throw new Error(`invalid session id: ${JSON.stringify(id)}`)
  }
  if (!Number.isInteger(seq) || seq < 1) throw new Error(`invalid session seq: ${seq}`)
  return `sessions/${id}/${String(seq).padStart(6, '0')}`
}

export type PassportClientOptions = {
  /** Base URL, e.g. http://localhost:8080 (no trailing slash needed). */
  url: string
  /** Active signing identity. Equals genesis until a rotation lands. */
  identity: Identity
  /** The passport's immutable root DID. Defaults to identity.did. */
  genesisDid?: string
  /** Rotation chain to present at /auth/verify (post-rotation auth). */
  attestations?: RotationAttestation[]
  /** Passphrase the entry key is derived from. Never sent to the server. */
  passphrase: string
  /** Secret-scan policy before encryption. Default `block` (PS-110). */
  scanMode?: ScanMode
  onScanWarning?: (findings: Finding[]) => void
  /** Per-request budget in ms. Default 120s. */
  timeoutMs?: number
  /** Last verified manifest seq, e.g. from custody (PS-041 anti-rollback). */
  lastSeq?: number
  /** Injectable fetch — the wire boundary, mocked in tests. */
  fetchFn?: typeof fetch
}

export type PullResult = {
  namespace: string
  /** The verified manifest seq (0 when the passport does not exist yet). */
  seq: number
  /** entryKey -> decrypted plaintext. */
  entries: Record<string, string>
}

export type PushResult = {
  namespace: string
  /** The manifest seq this push published (unchanged when it was a no-op). */
  seq: number
  uploaded: string[]
  unchanged: string[]
  deleted: string[]
}

/** A refusal from the server, carrying its error code and details verbatim. */
export class PassportHttpError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string,
    readonly details?: Record<string, unknown>,
  ) {
    super(message)
    this.name = 'PassportHttpError'
  }
}

/** The integrity manifest failed verification or rollback checks (PS-041). */
export class PassportIntegrityError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'PassportIntegrityError'
  }
}

/** A blob did not decrypt with this client's key or hash-check failed. */
export class PassportDecryptError extends Error {
  constructor(
    readonly entryKey: string,
    readonly reason: string,
  ) {
    super(`passport: could not decrypt "${entryKey}": ${reason}`)
    this.name = 'PassportDecryptError'
  }
}

/** The server refused some entries of a push (PS-081: skipped, not dropped). */
export class PassportSkippedError extends Error {
  constructor(
    readonly skipped: { key: string; reason: string }[],
    readonly accepted: string[],
  ) {
    super(
      `passport: server refused ${skipped.length} entr${skipped.length === 1 ? 'y' : 'ies'}: ` +
        skipped.map(s => `${s.key} (${s.reason})`).join(', ') +
        (accepted.length ? `. ${accepted.length} other entries were stored` : ''),
    )
    this.name = 'PassportSkippedError'
  }
}

/** The server accepted the connection and then did not answer in time. */
export class PassportTimeoutError extends Error {
  constructor(
    readonly operation: string,
    readonly timeoutMs: number,
  ) {
    super(`passport: ${operation} got no answer within ${timeoutMs}ms`)
    this.name = 'PassportTimeoutError'
  }
}

const DEFAULT_TIMEOUT_MS = 120_000

/** One answered request: the status line plus the body, already read. */
type Answer = { ok: boolean; status: number; statusText: string; raw: string }

type VerifiedManifest = {
  seq: number
  canonical: string
  signed: SignedManifest
  /** The decrypted manifest entry — passport state, exposed on pull. */
  plaintext: string
}

export class PassportClient {
  private readonly url: string
  private readonly identity: Identity
  private readonly genesisDid: string
  private readonly attestations: RotationAttestation[]
  private readonly scanMode: ScanMode
  private readonly onScanWarning?: (findings: Finding[]) => void
  private readonly timeoutMs: number
  private readonly fetchFn: typeof fetch
  /** Derived once: the namespace is fixed for the life of this client. */
  private readonly encKey: Buffer
  private token: { value: string; expiresAt: number } | null = null
  /** PS-041 state: last verified seq and the manifest bytes it belonged to. */
  private lastSeq: number
  private lastManifestCanonical: string | null = null

  constructor(opts: PassportClientOptions) {
    this.url = opts.url.replace(/\/$/, '')
    this.identity = opts.identity
    this.genesisDid = opts.genesisDid ?? opts.identity.did
    this.attestations = opts.attestations ?? []
    this.scanMode = opts.scanMode ?? 'block'
    this.onScanWarning = opts.onScanWarning
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS
    this.fetchFn = opts.fetchFn ?? fetch
    this.lastSeq = opts.lastSeq ?? 0
    this.encKey = deriveKey(opts.passphrase, this.namespace)
  }

  /** The passport namespace — bound to the genesis DID forever (PS-010/053). */
  get namespace(): string {
    return namespaceFor(this.genesisDid)
  }

  /** The seq of the last manifest this client verified or published. */
  get manifestSeq(): number {
    return this.lastSeq
  }

  /**
   * The DIDs allowed to have signed an integrity manifest: the genesis DID
   * plus every successor named by the presented rotation chain. Wire auth is
   * stricter — the server authorizes only the chain's terminal DID (PS-052) —
   * but a manifest signed while an earlier key still held authority stays
   * valid after rotation, so the check here is "a key that held authority",
   * not "the current key".
   */
  private authorizedDids(): Set<string> {
    const s = new Set<string>([this.genesisDid])
    for (const att of this.attestations) s.add(att.newDid)
    return s
  }

  // ─── Transport ────────────────────────────────────────────────────────

  /**
   * Challenge/response auth (PS-090): a fresh nonce, signed by the active
   * key, exchanged for a bearer. The rotation chain rides along whenever the
   * active key is a successor, so the server can re-root authorization at
   * the genesis DID (PS-052).
   */
  private async authenticate(): Promise<void> {
    const challenge = await this.rawRequest('POST', `${this.url}/auth/challenge`)
    if (!challenge.ok) throw httpError(challenge)
    const { nonce } = JSON.parse(challenge.raw) as { nonce?: string }
    if (typeof nonce !== 'string') throw new Error('passport: challenge returned no nonce')
    const body: Record<string, unknown> = {
      did: this.identity.did,
      nonce,
      sig: signMessage(this.identity.privateKey, new TextEncoder().encode(nonce)),
    }
    if (this.attestations.length) body.attestations = this.attestations
    const verified = await this.rawRequest(
      'POST',
      `${this.url}/auth/verify`,
      {
        'content-type': 'application/json',
      },
      JSON.stringify(body),
    )
    if (!verified.ok) throw httpError(verified)
    const data = JSON.parse(verified.raw) as { token?: string; expiresAt?: string }
    if (typeof data.token !== 'string') throw new Error('passport: verify returned no token')
    const expMs = data.expiresAt ? Date.parse(data.expiresAt) : Number.NaN
    this.token = {
      value: data.token,
      expiresAt: Number.isFinite(expMs) ? expMs : Date.now() + 60_000,
    }
  }

  /** Bare fetch on a clock, no auth. */
  private async rawRequest(
    method: string,
    url: string,
    headers?: Record<string, string>,
    body?: string,
  ): Promise<Answer> {
    try {
      const res = await this.fetchFn(url, {
        method,
        headers,
        body,
        signal: AbortSignal.timeout(this.timeoutMs),
      })
      const raw = await res.text().catch((err: unknown) => {
        if ((err as Error)?.name === 'TimeoutError') throw err
        return ''
      })
      return { ok: res.ok, status: res.status, statusText: res.statusText, raw }
    } catch (err) {
      if ((err as Error)?.name === 'TimeoutError') {
        throw new PassportTimeoutError(`${method} ${url}`, this.timeoutMs)
      }
      throw err
    }
  }

  /**
   * An authenticated request: bearer attached, and a single re-auth + retry
   * on 401 so an expired token mid-session is transparent.
   */
  private async request(
    method: string,
    path: string,
    opts?: { body?: unknown; retried?: boolean },
  ): Promise<Answer> {
    if (!this.token || this.token.expiresAt <= Date.now()) await this.authenticate()
    const headers: Record<string, string> = { authorization: `Bearer ${this.token!.value}` }
    if (opts?.body !== undefined) headers['content-type'] = 'application/json'
    const res = await this.rawRequest(
      method,
      `${this.url}${path}`,
      headers,
      opts?.body !== undefined ? JSON.stringify(opts.body) : undefined,
    )
    if (res.status === 401 && !opts?.retried) {
      this.token = null
      return this.request(method, path, { ...opts, retried: true })
    }
    return res
  }

  private endpoint(): string {
    return `/passport/${encodeURIComponent(this.namespace)}`
  }

  private entryPath(entryKey: string): string {
    return `${this.endpoint()}/${entryKey.split('/').map(encodeURIComponent).join('/')}`
  }

  /** The ?view=hashes map, or null when the passport does not exist yet. */
  private async hashesView(): Promise<Record<string, string> | null> {
    const res = await this.request('GET', `${this.endpoint()}?view=hashes`)
    if (res.status === 404) {
      const err = httpError(res)
      // Only the server's own "nothing here" is emptiness; any other 404 is
      // a wrong URL or a proxy, not an empty passport.
      if (err.code !== 'empty') throw err
      return null
    }
    if (!res.ok) throw httpError(res)
    return JSON.parse(res.raw) as Record<string, string>
  }

  /** The ?view=integrity entry, or a status explaining its absence. */
  private async integrityView(): Promise<
    { status: 'ok'; blob: string } | { status: 'no_namespace' } | { status: 'no_entry' }
  > {
    const res = await this.request('GET', `${this.endpoint()}?view=integrity`)
    if (res.status === 404) {
      const code = httpError(res).code
      if (code === 'empty') return { status: 'no_namespace' }
      if (code === 'entry_not_found') return { status: 'no_entry' }
      throw httpError(res)
    }
    if (!res.ok) throw httpError(res)
    const body = JSON.parse(res.raw) as { entry?: unknown }
    if (typeof body.entry !== 'string') {
      throw new Error('passport: integrity view carried no entry')
    }
    return { status: 'ok', blob: body.entry }
  }

  // ─── Integrity manifest (PS-040/041) ──────────────────────────────────

  /**
   * Decrypt, parse, and verify a signed manifest blob. Fail closed on every
   * defect: bad signature, wrong signer, wrong genesis, or a seq that went
   * backwards. A manifest re-presented at the same seq must be byte-identical
   * to the one already verified — equal seq is not a rollback, but equal seq
   * with different bytes is a replacement and fails.
   */
  private verifyManifestBlob(blob: string): VerifiedManifest {
    let plaintext: string
    try {
      plaintext = decryptEntry(this.encKey, MANIFEST_ENTRY_KEY, blob)
    } catch (err) {
      throw new PassportDecryptError(MANIFEST_ENTRY_KEY, (err as Error).message)
    }
    let parsedJson: unknown
    try {
      parsedJson = JSON.parse(plaintext)
    } catch {
      throw new PassportIntegrityError('passport: integrity manifest is not JSON')
    }
    const parsed = SignedManifest.safeParse(parsedJson)
    if (!parsed.success) {
      throw new PassportIntegrityError('passport: integrity manifest is malformed')
    }
    const signed = parsed.data
    if (signed.manifest.genesisDid !== this.genesisDid) {
      throw new PassportIntegrityError('passport: manifest names a different genesis DID')
    }
    if (!this.authorizedDids().has(signed.did)) {
      throw new PassportIntegrityError(
        `passport: manifest signed by ${signed.did}, which held no authority for this passport`,
      )
    }
    if (!verifyDidSignature(signed.did, canonicalJson(signed.manifest), signed.sig)) {
      throw new PassportIntegrityError('passport: integrity manifest signature is invalid')
    }
    const canonical = canonicalJson(signed.manifest)
    const seq = signed.manifest.seq
    if (seq < this.lastSeq) {
      throw new PassportIntegrityError(
        `passport: manifest seq rolled back (${seq} < ${this.lastSeq})`,
      )
    }
    if (
      seq === this.lastSeq &&
      this.lastManifestCanonical !== null &&
      canonical !== this.lastManifestCanonical
    ) {
      throw new PassportIntegrityError(
        `passport: manifest at seq ${seq} differs from the manifest already verified`,
      )
    }
    return { seq, canonical, signed, plaintext }
  }

  /**
   * Build + sign the next manifest over a projected entry-hash map. The
   * manifest's own key is never listed — a self-hash cannot exist.
   * Returns both the encrypted-entry plaintext and the canonical form the
   * PS-041 same-seq check compares against later.
   */
  private signManifest(
    entries: Record<string, string>,
    seq: number,
  ): { plaintext: string; canonical: string } {
    const manifest = {
      seq,
      specVersion: SPEC_VERSION,
      genesisDid: this.genesisDid,
      entries,
    }
    const signed: SignedManifest = {
      manifest,
      did: this.identity.did,
      sig: signMessage(this.identity.privateKey, canonicalJson(manifest)),
    }
    return { plaintext: canonicalJson(signed), canonical: canonicalJson(manifest) }
  }

  /** Fetch + verify the remote manifest. Null when the passport is empty. */
  private async remoteManifest(): Promise<VerifiedManifest | null> {
    const view = await this.integrityView()
    if (view.status === 'no_namespace') return null
    if (view.status === 'no_entry') {
      // Entries exist (the namespace does) but nothing signed them — a state
      // this client never produces. Fail closed rather than build on it.
      throw new PassportIntegrityError(
        'passport: namespace has entries but no signed integrity manifest',
      )
    }
    return this.verifyManifestBlob(view.blob)
  }

  private adoptManifest(v: VerifiedManifest): void {
    this.lastSeq = v.seq
    this.lastManifestCanonical = v.canonical
  }

  // ─── Public operations ────────────────────────────────────────────────

  /**
   * Publish a new passport: `identity/did.json` plus the first signed
   * integrity manifest. Refuses to run against a namespace that already
   * holds a passport — re-init would look identical to a wipe.
   */
  async init(): Promise<PushResult> {
    if ((await this.hashesView()) !== null) {
      throw new Error('passport: namespace already holds a passport; refusing to re-init')
    }
    return this.push({ 'identity/did.json': didDocument(this.genesisDid) })
  }

  /**
   * Encrypt + delta-push entries, then publish the next signed manifest.
   *
   * Plaintext is scanned for credential shapes BEFORE encryption (PS-110).
   * Deterministic encryption makes unchanged entries produce identical
   * ciphertext, so only entries whose ciphertext hash differs are uploaded.
   * `identity/manifest.json` is client-managed: a caller-supplied entry under
   * that key is dropped and replaced by the manifest this push signs.
   *
   * A push that changes nothing sends no PUT and does not burn a manifest
   * seq. A `skipped` response from the server is surfaced as a thrown
   * PassportSkippedError — never a silent drop (PS-081).
   */
  async push(
    entries: Record<string, string>,
    opts?: { deletions?: string[] },
  ): Promise<PushResult> {
    // Strip the client-managed key before scanning/uploading user content.
    const userEntries = Object.fromEntries(
      Object.entries(entries).filter(([k]) => k !== MANIFEST_ENTRY_KEY),
    )
    for (const key of Object.keys(userEntries)) {
      if (!EntryKey.safeParse(key).success) {
        throw new Error(`passport: invalid entry key ${JSON.stringify(key)}`)
      }
    }
    const findings = enforce(userEntries, this.scanMode)
    if (findings.length) {
      if (this.onScanWarning) this.onScanWarning(findings)
      else console.warn(`[passport] ${findings.length} potential secret(s) in pushed entries`)
    }

    const [hashes, remote] = await Promise.all([this.hashesView(), this.remoteManifest()])
    const serverHashes = hashes ?? {}
    if (remote) this.adoptManifest(remote)
    const baseSeq = remote?.seq ?? 0

    const deletions = (opts?.deletions ?? []).filter(k => k !== MANIFEST_ENTRY_KEY)
    const toUpload: Record<string, string> = {}
    const uploaded: string[] = []
    const unchanged: string[] = []
    const nextHashes: Record<string, string> = {}
    for (const [k, h] of Object.entries(serverHashes)) {
      if (k !== MANIFEST_ENTRY_KEY) nextHashes[k] = h
    }
    for (const k of deletions) delete nextHashes[k]

    for (const [entryKey, plaintext] of Object.entries(userEntries)) {
      const b64 = encryptEntry(this.encKey, entryKey, plaintext)
      const hash = ciphertextHash(b64)
      if (!deletions.includes(entryKey) && serverHashes[entryKey] === hash) {
        unchanged.push(entryKey)
        continue
      }
      nextHashes[entryKey] = hash
      toUpload[entryKey] = b64
      uploaded.push(entryKey)
    }

    const changed = uploaded.length > 0 || deletions.some(k => serverHashes[k] !== undefined)
    if (!changed) {
      return { namespace: this.namespace, seq: baseSeq, uploaded, unchanged, deleted: [] }
    }

    const seq = baseSeq + 1
    const { plaintext: manifestPlaintext, canonical: manifestCanonical } = this.signManifest(
      nextHashes,
      seq,
    )
    toUpload[MANIFEST_ENTRY_KEY] = encryptEntry(this.encKey, MANIFEST_ENTRY_KEY, manifestPlaintext)
    uploaded.push(MANIFEST_ENTRY_KEY)

    const res = await this.request('PUT', this.endpoint(), {
      body: {
        base: hashes === null ? null : manifestHash(hashes),
        entries: toUpload,
        ...(deletions.length ? { deletions } : {}),
      },
    })
    if (!res.ok) throw httpError(res)
    const result = JSON.parse(res.raw) as {
      base?: string
      accepted?: string[]
      deleted?: string[]
      skipped?: { key: string; reason: string }[]
    }
    this.lastSeq = seq
    this.lastManifestCanonical = manifestCanonical
    const skipped = result.skipped ?? []
    if (skipped.length) throw new PassportSkippedError(skipped, result.accepted ?? [])
    return {
      namespace: this.namespace,
      seq,
      uploaded,
      unchanged,
      deleted: result.deleted ?? [],
    }
  }

  /**
   * Pull + decrypt every entry. The signed manifest is verified first
   * (PS-041), then each blob's ciphertext hash is checked against it before
   * decryption — a blob the manifest does not name, or that fails GCM, is a
   * hard error, never a silent skip.
   */
  async pull(): Promise<PullResult> {
    const remote = await this.remoteManifest()
    if (!remote) return { namespace: this.namespace, seq: 0, entries: {} }
    this.adoptManifest(remote)

    const entries: Record<string, string> = {}
    for (const [entryKey, expectedHash] of Object.entries(remote.signed.manifest.entries)) {
      const res = await this.request('GET', this.entryPath(entryKey))
      if (!res.ok) throw httpError(res)
      const body = JSON.parse(res.raw) as { entry?: unknown; hash?: unknown }
      if (typeof body.entry !== 'string') {
        throw new PassportIntegrityError(`passport: no blob in the response for "${entryKey}"`)
      }
      if (body.hash !== expectedHash || ciphertextHash(body.entry) !== expectedHash) {
        throw new PassportIntegrityError(
          `passport: ciphertext hash mismatch for "${entryKey}" — blob does not match the manifest`,
        )
      }
      try {
        entries[entryKey] = decryptEntry(this.encKey, entryKey, body.entry)
      } catch (err) {
        throw new PassportDecryptError(entryKey, (err as Error).message)
      }
    }
    // The manifest itself is passport state too; expose it as an entry so a
    // pulled directory carries the complete document set.
    entries[MANIFEST_ENTRY_KEY] = remote.plaintext
    return { namespace: this.namespace, seq: remote.seq, entries }
  }

  /**
   * The ?view=hashes map: every stored entry key with its ciphertext hash,
   * no bodies. Empty object when the passport does not exist yet. This is
   * the cheap enumeration path for callers (the MCP adapter's list tool)
   * that need keys without downloading and decrypting every entry.
   */
  async hashes(): Promise<Record<string, string>> {
    return (await this.hashesView()) ?? {}
  }

  /**
   * Read and decrypt one entry, verified against the signed manifest
   * (PS-041): the fetched blob's ciphertext hash must equal the hash the
   * verified manifest names for the key, and GCM must authenticate under
   * that key. Returns null when the passport does not exist or the manifest
   * does not name the key; a blob the manifest does not name can never reach
   * decryption.
   */
  async readEntry(entryKey: string): Promise<string | null> {
    const remote = await this.remoteManifest()
    if (!remote) return null
    this.adoptManifest(remote)
    const expectedHash = remote.signed.manifest.entries[entryKey]
    if (expectedHash === undefined) return null
    const res = await this.request('GET', this.entryPath(entryKey))
    if (!res.ok) throw httpError(res)
    const body = JSON.parse(res.raw) as { entry?: unknown; hash?: unknown }
    if (typeof body.entry !== 'string') {
      throw new PassportIntegrityError(`passport: no blob in the response for "${entryKey}"`)
    }
    if (body.hash !== expectedHash || ciphertextHash(body.entry) !== expectedHash) {
      throw new PassportIntegrityError(
        `passport: ciphertext hash mismatch for "${entryKey}" — blob does not match the manifest`,
      )
    }
    try {
      return decryptEntry(this.encKey, entryKey, body.entry)
    } catch (err) {
      throw new PassportDecryptError(entryKey, (err as Error).message)
    }
  }

  /**
   * Rotate the signing key (PS-050/051): generate the successor, sign the
   * attestation with the CURRENT key, and record it under
   * `identity/rotations/<seq>.json` in the passport. Returns everything the
   * caller needs to update custody — the successor key's PKCS8 and the
   * extended chain to present on the next auth.
   */
  async rotate(): Promise<{
    attestation: RotationAttestation
    successor: Identity
    seq: number
    chain: RotationAttestation[]
  }> {
    const successor = generateIdentity()
    const seq = this.attestations.length + 1
    const prevHash =
      seq === 1
        ? GENESIS_PREV_HASH
        : attestationHash(this.attestations[this.attestations.length - 1]!)
    const attestation = buildRotationAttestation({
      genesisDid: this.genesisDid,
      signer: this.identity.privateKey,
      newDid: successor.did,
      seq,
      prevHash,
    })
    await this.push({ [`identity/rotations/${seq}.json`]: `${canonicalJson(attestation)}\n` })
    return { attestation, successor, seq, chain: [...this.attestations, attestation] }
  }
}

// ─── Error mapping ──────────────────────────────────────────────────────

function httpError(res: Answer): PassportHttpError {
  let code = 'unknown'
  let details: Record<string, unknown> | undefined
  try {
    const body = JSON.parse(res.raw) as {
      error?: { code?: string; details?: Record<string, unknown> }
    }
    if (body.error?.code) code = body.error.code
    details = body.error?.details
  } catch {
    // Not JSON — the raw text is all there is to report.
  }
  return new PassportHttpError(
    `passport ${res.status} ${safeText(res.statusText)}: ${safeText(res.raw)}`,
    res.status,
    code,
    details,
  )
}

const MAX_SERVER_TEXT = 200

/**
 * Bound and de-fang text the server chose before it lands in an Error
 * message — a hostile or broken server could otherwise plant an escape
 * sequence or a fake instruction where a human (or a model) reads it.
 */
function safeText(text: string): string {
  const clean = text
    // biome-ignore lint/suspicious/noControlCharactersInRegex: removing them is the point
    .replace(/\u001b\[[0-9;?]*[ -/]*[@-~]/g, '')
    // biome-ignore lint/suspicious/noControlCharactersInRegex: removing them is the point
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  return clean.length > MAX_SERVER_TEXT ? `${clean.slice(0, MAX_SERVER_TEXT)}...` : clean
}

export { ciphertextHash, decryptEntry, deriveKey, encryptEntry } from './crypto.ts'
export {
  type Finding,
  type ScanMode,
  SecretFoundError,
  scanEntries,
  scanEntry,
} from './secretscan.ts'
