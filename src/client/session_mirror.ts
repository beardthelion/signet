/**
 * Session mirroring: a set of plaintext files <-> `sessions/<id>/<seq>`
 * chunked entries (SN-022), interoperable with the fx fork's mirror.
 *
 * Layout:
 *   sessions/<id>/000000   mirror index (JSON, v2)
 *   sessions/<id>/<seq>    content chunks; each file occupies the
 *                          contiguous seq range its index record names
 *
 * Every file owns a cap-sized chunk region that persists via the prior
 * index: a kept file retains its seqs, so an append uploads only new
 * tail chunks and a removal frees only its own keys. New or displaced
 * files take the smallest unclaimed range. The index records
 * {name, first, chunks, bytes, sha256} per file, which makes torn
 * mirrors detectable: hydration reads the index first and any remote
 * key it does not name is ignored.
 *
 * Trust boundary: assembled file bytes are secret-scanned HERE, before
 * chunking - a credential straddling a chunk boundary would pass as two
 * clean halves under the per-entry scan the client applies inside push
 * (SN-110). Scanning runs under a synthetic surface key that mirrors the
 * source path, matching the fx fork.
 */

import { createHash } from 'node:crypto'
import type { SignetClient } from './client.ts'
import { SecretFoundError, scanEntry } from './secretscan.ts'

/** Plaintext bytes per chunk entry (SN-081: under the 1 MiB entry cap). */
export const SESSION_CHUNK_BYTES = 512 * 1024
/** A chunk can never exceed the spec's decoded entry cap. */
const MAX_CHUNK_PAYLOAD = 1024 * 1024
/** Chunk seq width in entry keys (SN-022). */
const SEQ_WIDTH = 6
/** The index entry always sits at seq 0. */
const INDEX_SEQ = 0
/** Whole-file caps bounding one mirrored file's plaintext. */
const DEFAULT_FILE_CAP = 8 * 1024 * 1024
const DEFAULT_CAPS: Record<string, number> = {
  'events.jsonl': 512 * 1024 * 1024,
}
const MAX_INDEX_BYTES = 256 * 1024
const MAX_MIRRORED_FILES = 64

const seqKey = (id: string, seq: number) => `sessions/${id}/${String(seq).padStart(SEQ_WIDTH, '0')}`
const chunksFor = (bytes: number, chunkBytes: number) => Math.ceil(bytes / chunkBytes)

const SESSION_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/
const FILE_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/
const CHUNK_SEG_RE = /^\d{6}$/

/** Metadata members mirrored alongside events.jsonl. */
const MIRRORED_META = new Set([
  'session.json',
  'checkpoint.json',
  'display.json',
  'authority.json',
  'usage-v2.json',
])

/**
 * Top-level session members eligible for mirroring. Same predicate the
 * fx reference writer applies: both sides must accept exactly this set
 * or an index one writes carries records the other rejects as corrupt.
 * The shape regex runs first because the commit.*.json prefix/suffix
 * test alone would admit names containing slashes or traversal.
 */
export function isMirroredSessionFile(name: string): boolean {
  if (!FILE_NAME_RE.test(name)) return false
  if (name === 'events.jsonl') return true
  if (MIRRORED_META.has(name)) return true
  // commit.<hex>.json records; the pending intent file is transient.
  return name.startsWith('commit.') && name.endsWith('.json') && name !== 'commit.pending.json'
}

/** A file record as the v2 index encodes it. */
export type MirrorFileRecord = {
  name: string
  first: number
  chunks: number
  bytes: number
  sha256: string
}

export type MirrorIndex = { files: MirrorFileRecord[] }

export class SignetMirrorCorrupt extends Error {
  constructor(detail: string) {
    super(`signet: session mirror corrupt - ${detail}`)
    this.name = 'SignetMirrorCorrupt'
  }
}

export class SignetMirrorOversize extends Error {
  constructor(detail: string) {
    super(`signet: session mirror oversized - ${detail}`)
    this.name = 'SignetMirrorOversize'
  }
}

function parseIndex(bytes: string): MirrorIndex {
  let root: unknown
  try {
    root = JSON.parse(bytes)
  } catch {
    throw new SignetMirrorCorrupt('index is not JSON')
  }
  if (typeof root !== 'object' || root === null)
    throw new SignetMirrorCorrupt('index is not an object')
  const v = (root as { v?: unknown }).v
  if (v !== 2) throw new SignetMirrorCorrupt(`index version ${JSON.stringify(v)}`)
  const filesV = (root as { files?: unknown }).files
  if (!Array.isArray(filesV)) throw new SignetMirrorCorrupt('index files is not an array')
  if (filesV.length > MAX_MIRRORED_FILES)
    throw new SignetMirrorCorrupt('index names too many files')
  const files: MirrorFileRecord[] = []
  const seen = new Set<string>()
  for (const item of filesV) {
    const f = item as Record<string, unknown>
    if (
      typeof f.name !== 'string' ||
      !isMirroredSessionFile(f.name) ||
      typeof f.first !== 'number' ||
      !Number.isInteger(f.first) ||
      f.first <= 0 ||
      typeof f.chunks !== 'number' ||
      !Number.isInteger(f.chunks) ||
      f.chunks < 0 ||
      typeof f.bytes !== 'number' ||
      !Number.isInteger(f.bytes) ||
      f.bytes < 0 ||
      typeof f.sha256 !== 'string' ||
      !/^[0-9a-f]{64}$/.test(f.sha256)
    ) {
      throw new SignetMirrorCorrupt('index file record is malformed')
    }
    // Chunk size is a writer choice the index does not record, so the
    // check bounds plausibility instead of recomputing it: the byte count
    // must fit in `chunks` entries of at most the spec entry cap, and a
    // zero-byte file owns no chunks. Torn contents are caught by the
    // sha256 the hydration path verifies.
    if (f.chunks > 0 && f.bytes > f.chunks * MAX_CHUNK_PAYLOAD) {
      throw new SignetMirrorCorrupt(`index ${f.name} chunk count cannot span its byte count`)
    }
    if (f.bytes === 0 && f.chunks !== 0) {
      throw new SignetMirrorCorrupt(`index ${f.name} names chunks for an empty file`)
    }
    if (seen.has(f.name)) throw new SignetMirrorCorrupt(`index names ${f.name} twice`)
    seen.add(f.name)
    files.push({ name: f.name, first: f.first, chunks: f.chunks, bytes: f.bytes, sha256: f.sha256 })
  }
  // Chunk ranges must not overlap or collide with the index entry.
  for (let i = 0; i < files.length; i++) {
    for (let j = i + 1; j < files.length; j++) {
      const a = files[i]!
      const b = files[j]!
      if (a.first < b.first + b.chunks && b.first < a.first + a.chunks) {
        throw new SignetMirrorCorrupt('index chunk ranges overlap')
      }
    }
    if (files[i]!.first <= INDEX_SEQ && INDEX_SEQ < files[i]!.first + files[i]!.chunks) {
      throw new SignetMirrorCorrupt('a file range collides with the index entry')
    }
  }
  return { files }
}

function encodeIndex(index: MirrorIndex): string {
  const files = index.files
    .map(
      f =>
        `{"name":${JSON.stringify(f.name)},"first":${f.first},"chunks":${f.chunks},` +
        `"bytes":${f.bytes},"sha256":"${f.sha256}"}`,
    )
    .join(',')
  return `{"v":2,"files":[${files}]}`
}

export type MirrorOptions = {
  /** Per-file plaintext caps; falls back to DEFAULT_FILE_CAP. */
  caps?: Record<string, number>
  /** Plaintext bytes per chunk entry. Default SESSION_CHUNK_BYTES. */
  chunkBytes?: number
  /** Scan mode for assembled file content. Default 'block'. */
  scan?: 'block' | 'warn' | 'off'
}

export type MirrorOutcome = {
  uploaded: string[]
  unchanged: string[]
  deleted: string[]
  tombstoned: string[]
}

function capFor(name: string, caps?: Record<string, number>): number {
  return caps?.[name] ?? DEFAULT_CAPS[name] ?? DEFAULT_FILE_CAP
}

/**
 * Mirror `files` into the store under `sessions/<id>/`. Files are the
 * complete desired set: names not present locally keep their remote
 * chunks only while their records still appear in the new index... they
 * do not - this writer owns the mirror, and remote chunk keys outside
 * the new index ranges are deleted. Prior-index matches skip re-upload.
 */
export async function mirrorSession(
  client: SignetClient,
  sessionId: string,
  files: Record<string, string>,
  opts: MirrorOptions = {},
): Promise<MirrorOutcome> {
  if (!SESSION_ID_RE.test(sessionId)) {
    throw new SignetMirrorCorrupt(`invalid session id ${JSON.stringify(sessionId)}`)
  }
  const names = Object.keys(files).sort()
  if (names.length > MAX_MIRRORED_FILES) {
    throw new SignetMirrorOversize(`more than ${MAX_MIRRORED_FILES} files`)
  }
  for (const name of names) {
    if (!isMirroredSessionFile(name)) {
      throw new SignetMirrorCorrupt(`not a mirrored session member: ${name}`)
    }
  }

  let prior: MirrorIndex | null = null
  const indexKey = seqKey(sessionId, INDEX_SEQ)
  const indexBytes = await client.readEntry(indexKey)
  if (indexBytes !== null && indexBytes.length <= MAX_INDEX_BYTES) {
    try {
      prior = parseIndex(indexBytes)
    } catch {
      prior = null
    }
  }

  const chunkBytes = opts.chunkBytes ?? SESSION_CHUNK_BYTES
  if (!Number.isInteger(chunkBytes) || chunkBytes <= 0 || chunkBytes > MAX_CHUNK_PAYLOAD) {
    throw new SignetMirrorCorrupt(`invalid chunkBytes ${chunkBytes}`)
  }
  const scan = opts.scan ?? 'block'
  const priorByName = new Map((prior?.files ?? []).map(f => [f.name, f]))
  const records: MirrorFileRecord[] = []
  const entries: Record<string, string> = {}
  // Region assignment: a file that appeared in the prior index keeps its
  // region when it still fits; a new or displaced file takes the smallest
  // unclaimed range. Regions therefore survive removals as well as growth:
  // deleting a file shrinks its remote footprint through the stale-key
  // sweep below without moving anything else.
  const claimed: [number, number][] = []
  const overlaps = (first: number, end: number) => claimed.some(([s, e]) => first < e && s < end)
  for (const name of names) {
    const cap = capFor(name, opts.caps)
    const stride = chunksFor(cap, chunkBytes)
    const priorRec = priorByName.get(name)
    let first: number
    if (priorRec && !overlaps(priorRec.first, priorRec.first + stride)) {
      first = priorRec.first
    } else {
      first = 1
      while (overlaps(first, first + stride)) first++
    }
    claimed.push([first, first + stride])
    const bytes = Buffer.from(files[name]!, 'utf8')
    if (bytes.length > cap) {
      throw new SignetMirrorOversize(`${name} exceeds its ${cap}-byte cap`)
    }
    if (scan !== 'off') {
      const findings = scanEntry(`sessions/${sessionId}/${name}`, bytes.toString('utf8'))
      if (findings.length > 0) {
        if (scan === 'block') {
          throw new SecretFoundError(findings)
        }
      }
    }
    const sha256 = createHash('sha256').update(bytes).digest('hex')
    const chunks = chunksFor(bytes.length, chunkBytes)
    if (priorRec && chunks > stride) {
      // Cannot happen while cap bounds bytes, but the region contract is
      // what the comment above promises - fail loudly, never overlap.
      throw new SignetMirrorCorrupt(`${name} outgrew its region`)
    }
    const record: MirrorFileRecord = { name, first, chunks, bytes: bytes.length, sha256 }
    records.push(record)
    const unchanged =
      priorRec !== undefined &&
      priorRec.chunks === record.chunks &&
      priorRec.bytes === record.bytes &&
      priorRec.sha256 === record.sha256
    if (!unchanged) {
      for (let i = 0; i < chunks; i++) {
        entries[seqKey(sessionId, first + i)] = bytes
          .subarray(i * chunkBytes, (i + 1) * chunkBytes)
          .toString('utf8')
      }
    }
  }
  entries[indexKey] = encodeIndex({ files: records })

  // Remote chunk keys this mirror does not name get deleted. Non-chunk
  // keys under the prefix are left alone: another writer may own them.
  const remoteHashes = await client.hashes()
  const prefix = `sessions/${sessionId}/`
  const expected = new Set<number>([INDEX_SEQ])
  for (const r of records) {
    for (let s = r.first; s < r.first + r.chunks; s++) expected.add(s)
  }
  const deletions: string[] = []
  for (const key of Object.keys(remoteHashes)) {
    if (!key.startsWith(prefix)) continue
    const seg = key.slice(prefix.length)
    if (!CHUNK_SEG_RE.test(seg)) continue
    const seq = Number.parseInt(seg, 10)
    if (!expected.has(seq)) deletions.push(key)
  }

  const result = await client.push(entries, { deletions })
  return {
    uploaded: result.uploaded,
    unchanged: result.unchanged,
    deleted: result.deleted,
    tombstoned: result.tombstoned,
  }
}

/**
 * Reassemble the mirrored files for `sessionId`. Returns null when no
 * index exists; throws SignetMirrorCorrupt on a torn or malformed mirror.
 */
export async function hydrateSession(
  client: SignetClient,
  sessionId: string,
): Promise<Record<string, string> | null> {
  if (!SESSION_ID_RE.test(sessionId)) {
    throw new SignetMirrorCorrupt(`invalid session id ${JSON.stringify(sessionId)}`)
  }
  const indexBytes = await client.readEntry(seqKey(sessionId, INDEX_SEQ))
  if (indexBytes === null) return null
  if (indexBytes.length > MAX_INDEX_BYTES) throw new SignetMirrorCorrupt('index too large')
  const index = parseIndex(indexBytes)

  const files: Record<string, string> = {}
  for (const record of index.files) {
    const chunks: string[] = []
    for (let s = record.first; s < record.first + record.chunks; s++) {
      const chunk = await client.readEntry(seqKey(sessionId, s))
      if (chunk === null) {
        throw new SignetMirrorCorrupt(`index names chunk ${s} of ${record.name}, which is absent`)
      }
      chunks.push(chunk)
    }
    const bytes = Buffer.concat(chunks.map(c => Buffer.from(c, 'utf8')))
    if (bytes.length !== record.bytes) {
      throw new SignetMirrorCorrupt(
        `${record.name} reassembled to ${bytes.length} bytes, not ${record.bytes}`,
      )
    }
    if (createHash('sha256').update(bytes).digest('hex') !== record.sha256) {
      throw new SignetMirrorCorrupt(`${record.name} reassembled content fails its sha256`)
    }
    files[record.name] = bytes.toString('utf8')
  }
  return files
}
