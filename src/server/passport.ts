/**
 * Passport repository operations — the heart of the store.
 *
 * Reads/writes the per-namespace manifest + ciphertext entry blobs through
 * the BlobStore (PS-080). Implements the manifest view, the hashes view for
 * delta sync, single-entry fetch, the integrity-manifest view, and delta
 * upsert. All values flowing through here are ciphertext; this module cannot
 * and does not decrypt anything.
 *
 * Concurrency note: writes to a single namespace are serialized with an
 * in-process async lock (PS-082) so two concurrent PUTs can't clobber each
 * other's read-modify-write. Correct for a single instance; a multi-instance
 * deployment moves the manifest behind a conditional write.
 */

import { createHash } from 'node:crypto'
import { ContentHash, Manifest, type ManifestEntry } from '../types/index.ts'
import { withLock } from './lock.ts'
import { logJsonLine } from './log.ts'
import { namespaceSlug, sha256Hex, validateEntryKey } from './namespace.ts'
import { caps, checkProjectedCaps } from './quota.ts'
import { blobPath, blobPrefix, type Erasure, getStore, manifestPath } from './store/blob.ts'

/** Thrown when a namespace's manifest cannot be parsed. Surfaces as HTTP 503. */
export class UnreadableManifestError extends Error {
  readonly code = 'manifest_unreadable'
  constructor() {
    super('namespace index cannot be read')
    this.name = 'UnreadableManifestError'
  }
}

/**
 * Thrown when a write's `base` disagrees with the manifest it would mutate.
 * Surfaces as HTTP 409; `details.current` carries the manifest hash the
 * caller should have built from, so it can rebase without a second round
 * trip. (The bare hashes view stays a pure {entryKey: hash} map; `base` is
 * the manifest hash defined by `manifestHash` below.)
 */
export class StaleBaseError extends Error {
  readonly code = 'stale_base'
  readonly details: { current: string }
  constructor(current: string) {
    super('write base is out of date')
    this.name = 'StaleBaseError'
    this.details = { current }
  }
}

/** PUT /passport/<ns> body (validated). */
export type UpsertRequest = {
  /** entryKey -> ciphertext (base64). Upsert semantics. */
  entries: Record<string, string>
  /** entryKeys to remove (optional). */
  deletions?: string[]
  /**
   * The manifest hash the writer built from: `manifestHash` of the
   * ?view=hashes map the writer last saw, or null for "the namespace is
   * empty". Optional — a request without it is accepted unconditionally.
   */
  base?: string | null
}

export type UpsertResponse = {
  namespace: string
  /** Manifest hash after this write — the base for the next delta. */
  base: string
  /** Whether this deployment's store actually erases on delete. */
  erasure: Erasure
  accepted: string[]
  deleted: string[]
  skipped: { key: string; reason: string }[]
}

/**
 * The manifest hash a PUT's `base` refers to: sha256 over the sorted
 * `key\thash` lines of the entry-hash map. Both sides can compute it from
 * the bare ?view=hashes map, so the wire never needs a second digest field.
 */
export function manifestHash(entryHashes: Record<string, string>): string {
  const lines = Object.keys(entryHashes)
    .sort()
    .map(k => `${k}\t${entryHashes[k]}`)
    .join('\n')
  return `sha256:${sha256Hex(lines)}`
}

/** The base a writer uses when the namespace does not exist yet. */
const EMPTY_BASE = manifestHash({})

// ─── Manifest helpers ───────────────────────────────────────────────────

/** The namespace's manifest, or null when no manifest blob exists. */
async function readManifest(nsSlug: string): Promise<Manifest | null> {
  const raw = await getStore().get(manifestPath(nsSlug))
  if (!raw) return null
  let parsed: unknown
  try {
    parsed = JSON.parse(new TextDecoder().decode(raw))
  } catch {
    // Absent and unreadable are different. Absent is a new namespace;
    // unreadable is a namespace whose index we cannot see, and starting clean
    // there would now be destructive: the commit path reclaims blobs the new
    // manifest does not reference, so an empty manifest would delete every
    // live entry. Refuse and let an operator look.
    throw new UnreadableManifestError()
  }
  const m = Manifest.safeParse(parsed)
  if (!m.success) throw new UnreadableManifestError()
  return m.data
}

async function writeManifest(nsSlug: string, m: Manifest): Promise<void> {
  await getStore().put(manifestPath(nsSlug), new TextEncoder().encode(JSON.stringify(m)))
}

function hashesFrom(m: Manifest): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [k, meta] of Object.entries(m.entries)) out[k] = meta.hash
  return out
}

// ─── Read paths ─────────────────────────────────────────────────────────

/** Manifest view: entry metadata, no ciphertext bodies. Null if never written. */
export async function getManifest(namespace: string): Promise<{
  namespace: string
  base: string
  erasure: Erasure
  entries: Record<string, ManifestEntry>
} | null> {
  const m = await readManifest(namespaceSlug(namespace))
  if (m === null) return null
  return {
    namespace,
    base: manifestHash(hashesFrom(m)),
    erasure: getStore().erasure,
    entries: m.entries,
  }
}

/**
 * Hashes view: exactly `{entryKey: sha256-hash}` — the delta-sync contract of
 * SPEC §7.1. Kept as a bare map on purpose: any extra field would be
 * indistinguishable from an entry key to a client iterating it. Null if the
 * namespace was never written.
 */
export async function getHashes(namespace: string): Promise<Record<string, string> | null> {
  const m = await readManifest(namespaceSlug(namespace))
  return m === null ? null : hashesFrom(m)
}

export type EntryRead =
  | { status: 'ok'; entry: { namespace: string; key: string; entry: string; hash: string } }
  | { status: 'no_namespace' }
  | { status: 'no_entry' }
  | { status: 'unreadable' }

/**
 * One entry's ciphertext blob, selected by key. Deliberately not "fetch all
 * and filter": the store is asked for one blob, so a caller proving it can
 * decrypt what is stored pays for one entry instead of the whole namespace.
 *
 * A named-but-missing body is its own refusal (`unreadable`), not `no_entry`:
 * the manifest naming the key is evidence the entry exists, and answering
 * "not found" would tell a client the write never happened.
 */
export async function getEntry(namespace: string, key: string): Promise<EntryRead> {
  const nsSlug = namespaceSlug(namespace)
  const m = await readManifest(nsSlug)
  if (m === null) return { status: 'no_namespace' }
  const meta = m.entries[key]
  if (!meta) return { status: 'no_entry' }
  let bytes: Uint8Array | null = null
  try {
    bytes = await getStore().get(blobPath(nsSlug, meta.hash))
  } catch {
    // A hash that is not a digest cannot name a blob; the read fails below.
  }
  if (!bytes) return { status: 'unreadable' }
  return {
    status: 'ok',
    entry: {
      namespace,
      key,
      entry: Buffer.from(bytes).toString('base64'),
      hash: meta.hash,
    },
  }
}

/** `?view=integrity`: the blob stored under `identity/manifest.json` (PS-040). */
export function getIntegrityManifest(namespace: string): Promise<EntryRead> {
  return getEntry(namespace, 'identity/manifest.json')
}

// ─── Write path ─────────────────────────────────────────────────────────

/**
 * Validate and narrow a PUT body parsed from JSON. Throws on malformed input.
 * Entry-key validation happens per key in `upsert` so bad keys land in the
 * `skipped` list rather than failing the whole batch.
 */
export function parseUpsertBody(raw: unknown): UpsertRequest {
  if (typeof raw !== 'object' || raw === null) {
    throw new Error('body must be a JSON object')
  }
  const obj = raw as Record<string, unknown>
  const entries = obj.entries
  if (typeof entries !== 'object' || entries === null || Array.isArray(entries)) {
    throw new Error('`entries` must be an object map of key -> ciphertext')
  }
  for (const [k, v] of Object.entries(entries)) {
    if (typeof v !== 'string') throw new Error(`entry ${JSON.stringify(k)} must be a base64 string`)
  }
  let base: string | null | undefined
  if (obj.base !== undefined) {
    if (
      obj.base !== null &&
      (typeof obj.base !== 'string' || !ContentHash.safeParse(obj.base).success)
    ) {
      throw new Error('`base` must be a sha256:<hex> manifest hash or null')
    }
    base = obj.base
  }
  let deletions: string[] | undefined
  if (obj.deletions !== undefined) {
    if (!Array.isArray(obj.deletions) || obj.deletions.some(d => typeof d !== 'string')) {
      throw new Error('`deletions` must be an array of strings')
    }
    deletions = obj.deletions as string[]
  }
  return { entries: entries as Record<string, string>, deletions, base }
}

/**
 * Apply a delta upsert. Each entry value is base64 ciphertext. We:
 *   - compare `base` to the live manifest hash first — stale base, 409, and
 *     NOTHING commits (PS-081)
 *   - validate each key before it can touch a storage path, skip bad entries
 *   - skip writes whose ciphertext hash already matches (true delta)
 *   - project the resulting manifest in memory and enforce every cap —
 *     per-section and namespace-total breaches fail the WHOLE write before
 *     any byte lands; an oversized entry alone is reported in `skipped`
 *   - commit blobs, then the manifest that publishes them
 *
 * Runs under the per-namespace lock so concurrent PUTs serialize (PS-082).
 */
export async function upsert(
  namespace: string,
  req: UpsertRequest,
  nowIso: string,
): Promise<UpsertResponse> {
  const nsSlug = namespaceSlug(namespace)
  return withLock(`ns:${nsSlug}`, async () => {
    const store = getStore()
    const m = (await readManifest(nsSlug)) ?? { entries: {} }

    // The write precondition, checked before any projection. `base` is the
    // manifest hash the writer built from: a single digest, not a per-entry
    // map, because what a writer needs to know is "did anything move under
    // me", and one hash answers that.
    if (req.base !== undefined) {
      const current = manifestHash(hashesFrom(m))
      const expected = req.base === null ? EMPTY_BASE : req.base
      if (expected !== current) throw new StaleBaseError(current)
    }

    const accepted: string[] = []
    const deleted: string[] = []
    const skipped: { key: string; reason: string }[] = []
    // Defer all mutations so a cap breach can reject the whole request.
    const blobWrites: { path: string; bytes: Uint8Array }[] = []
    const touched = new Set<string>()

    // Deletions first (projected; store.delete deferred to commit).
    for (const key of req.deletions ?? []) {
      try {
        validateEntryKey(key)
      } catch {
        skipped.push({ key, reason: 'invalid_key' })
        continue
      }
      if (m.entries[key]) {
        touched.add(key)
        delete m.entries[key]
        deleted.push(key)
      }
    }

    for (const [key, b64] of Object.entries(req.entries)) {
      try {
        validateEntryKey(key)
      } catch {
        skipped.push({ key, reason: 'invalid_key' })
        continue
      }
      const bytes = decodeBase64(b64)
      if (!bytes) {
        skipped.push({ key, reason: 'invalid_base64' })
        continue
      }
      if (bytes.byteLength > caps.entry) {
        skipped.push({ key, reason: 'entry_too_large' })
        continue
      }
      const hash = sha256Prefixed(bytes)
      if (m.entries[key]?.hash === hash) {
        // Unchanged ciphertext — true delta, nothing to write.
        accepted.push(key)
        continue
      }
      blobWrites.push({ path: blobPath(nsSlug, hash), bytes })
      touched.add(key)
      m.entries[key] = { hash, size: bytes.byteLength, updatedAt: nowIso }
      accepted.push(key)
    }

    const mutated = touched.size > 0
    if (mutated) {
      // All-or-nothing: every cap is enforced against the projected manifest
      // before a single byte is written (PS-081).
      checkProjectedCaps(m.entries)

      // Blobs first, then the manifest that publishes them. A crash before
      // the manifest write leaves orphans no reader can see; a crash after it
      // leaves stale extras no reader can see. Either way the visible state
      // is consistent. Reclaim runs after the write is durable, because a
      // failure to collect garbage must not fail a write that already landed.
      await Promise.all(blobWrites.map(w => store.put(w.path, w.bytes)))
      await writeManifest(nsSlug, m)

      await reclaim(nsSlug, m)
    }

    return {
      namespace,
      base: manifestHash(hashesFrom(m)),
      erasure: store.erasure,
      accepted,
      // A key listed in both deletions and entries is projected as a delete
      // then re-added; reporting it as deleted too would tell a client
      // mirroring `deleted` to drop an entry this response says it stored.
      deleted: deleted.filter(k => !(k in m.entries)),
      skipped,
    }
  })
}

/**
 * Delete ciphertext no visible manifest names.
 *
 * Driven by a listing rather than by the keys this request touched, because
 * the orphans that matter are the ones no key can reach: a write that died
 * before publishing left blobs the next manifest never mentions, and a delete
 * whose collection failed removed the key from the manifest, so nothing can
 * name its hash again. Sweeping the namespace's blob directory against the
 * live hash set finds both.
 *
 * Never throws. This runs after the write is durable and collects garbage
 * already invisible to every reader, so a store hiccup here must not turn a
 * landed write into a failure. Single-instance only, like the lock it runs
 * under.
 */
async function reclaim(nsSlug: string, m: Manifest): Promise<void> {
  try {
    const store = getStore()
    const live = new Set<string>()
    for (const meta of Object.values(m.entries)) live.add(blobPath(nsSlug, meta.hash))
    const orphans = (await store.list(blobPrefix(nsSlug))).filter(p => !live.has(p))
    await Promise.all(orphans.map(p => store.delete(p)))
  } catch (err) {
    // The slug is what makes this actionable: without it an operator only
    // knows collection failed somewhere. It is already every storage path's
    // own directory name, so it discloses nothing a reader of the store lacks.
    logEvent({
      event: 'reclaim_failed',
      nsSlug,
      reason: (err as Error)?.constructor?.name ?? 'unknown',
    })
  }
}

/**
 * One operational log line — not a request refusal. The field set is fixed
 * and small on purpose: on a crypto-blind server the space of things that
 * must never appear in a log (entry keys, raw namespaces, ciphertext, tokens)
 * is open-ended, so a fixed shape is the only safe one. The slug is a sha256
 * of a namespace, already the directory name anyone reading the store sees.
 */
function logEvent(fields: { event: string; nsSlug: string; reason: string }): void {
  logJsonLine(fields)
}

/** sha256:<hex> of raw ciphertext bytes — over ciphertext only, never plaintext. */
function sha256Prefixed(bytes: Uint8Array): string {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`
}

const B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

/**
 * Decode base64 without a re-encode validation pass. Accepts exactly what
 * the old decode-then-re-encode check accepted: alphabet characters, then
 * any run of trailing '=' padding, with the last data char of a partial
 * group carrying no bits the decoder would silently drop.
 */
function decodeBase64(b64: string): Uint8Array | null {
  const m = /^([A-Za-z0-9+/]*)=*$/.exec(b64)
  if (!m) return null
  const body = m[1]!
  const rem = body.length % 4
  if (rem === 1) return null
  if (rem === 2 && B64_ALPHABET.indexOf(body[body.length - 1]!) % 16 !== 0) return null
  if (rem === 3 && B64_ALPHABET.indexOf(body[body.length - 1]!) % 4 !== 0) return null
  try {
    return new Uint8Array(Buffer.from(b64, 'base64'))
  } catch {
    return null
  }
}
