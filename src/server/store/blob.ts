/**
 * BlobStore — the pluggable persistence interface, the storage-path grammar,
 * and the STORE-env driver factory.
 *
 * The store holds only opaque bytes (PS-034): per namespace slug there is one
 * `manifest.json` (`entryKey -> {hash, size, updatedAt}`), one content-
 * addressed ciphertext blob per entry, and one `attestations.json` holding
 * the persisted rotation chain. The store has no idea what an "entry" is and
 * could not decrypt one if it wanted to.
 *
 * Keys passed to adapters are already validated (see namespace.ts), so paths
 * are built without re-checking traversal — the one exception is `bareHash`,
 * which re-checks a manifest-carried digest before it becomes a filename,
 * because a manifest is parsed JSON, not validated input.
 *
 * Adapters: fs (self-host default) and s3 (Tigris/R2/AWS/minio).
 */

import { FsBlobStore } from './fs.ts'
import { S3BlobStore } from './s3.ts'

export interface BlobStore {
  /** Read raw bytes. Returns null if the object does not exist. */
  get(path: string): Promise<Uint8Array | null>
  /** Write raw bytes, overwriting any existing object. */
  put(path: string, bytes: Uint8Array): Promise<void>
  /** Delete an object. No-op if it does not exist. */
  delete(path: string): Promise<void>
  /**
   * Every object path under `prefix`. Needed because reclaim has to find
   * blobs no manifest names: a write that dies before publishing leaves
   * ciphertext no later request can reach by key, so a reclaim driven only
   * from the previous manifest can never see it.
   */
  list(prefix: string): Promise<string[]>
  /** A short label for logs/health (e.g. "fs:/data", "s3:passports"). */
  describe(): string
  /**
   * Whether `delete` actually removes the bytes. A store that keeps history
   * retains them, and a holder choosing a backend can refuse one a secret
   * could never be removed from. Constant per store.
   */
  readonly erasure: Erasure
}

/** Whether a store's delete is destructive. */
export type Erasure = 'erases' | 'retains'

/** Build the storage path for a namespace's manifest. */
export function manifestPath(nsSlug: string): string {
  return `ns/${nsSlug}/manifest.json`
}

/** Build the storage path for a namespace's persisted rotation chain. */
export function attestationsPath(nsSlug: string): string {
  return `ns/${nsSlug}/attestations.json`
}

/**
 * Build the storage path for one entry's ciphertext, named by that
 * ciphertext's own hash. Writing to a content-addressed path means an
 * overwrite never mutates a blob the currently-visible manifest still points
 * at, which is what makes a crash mid-commit leave the previous state
 * readable and self-consistent. Encryption is deterministic, so two entries
 * holding identical ciphertext share one blob — cleanup must check the live
 * hash set before removing one, never assume one entry owns it.
 */
export function blobPath(nsSlug: string, ciphertextHash: string): string {
  return `ns/${nsSlug}/blobs/${bareHash(ciphertextHash)}`
}

/** The directory every content-addressed blob for a namespace lives under. */
export function blobPrefix(nsSlug: string): string {
  return `ns/${nsSlug}/blobs/`
}

/**
 * Strip the `sha256:` prefix and prove what remains is a bare hex digest.
 * A manifest hash reaches a storage path here, and a manifest is parsed JSON
 * rather than validated input — without the check a hash carrying path
 * separators would escape the namespace directory.
 */
function bareHash(ciphertextHash: string): string {
  const bare = ciphertextHash.startsWith('sha256:') ? ciphertextHash.slice(7) : ciphertextHash
  if (!/^[0-9a-f]{64}$/.test(bare)) throw new Error('ciphertext hash is not a sha256 digest')
  return bare
}

// ─── Driver factory ─────────────────────────────────────────────────────

const storeDriver = (process.env.STORE ?? 'fs').trim().toLowerCase()
const dataDir = (process.env.PASSPORT_DATA_DIR ?? './data').trim()
const s3 = {
  bucket: (process.env.S3_BUCKET ?? '').trim(),
  endpoint: (process.env.S3_ENDPOINT ?? '').trim().replace(/\/$/, ''),
  region: (process.env.S3_REGION ?? 'auto').trim(),
  accessKeyId: (process.env.S3_ACCESS_KEY_ID ?? '').trim(),
  secretAccessKey: (process.env.S3_SECRET_ACCESS_KEY ?? '').trim(),
}

/**
 * Build the driver one name selects. Unknown names refuse rather than fall
 * through to the filesystem: the driver name is an unvalidated env read, so
 * `s3x` would otherwise serve local disk silently while reporting a healthy
 * store.
 */
export function createStore(driver: string = storeDriver): BlobStore {
  switch (driver) {
    case 'fs':
      return new FsBlobStore(dataDir)
    case 's3':
      return new S3BlobStore(s3)
    default:
      throw new Error(`unknown store driver "${driver}"; STORE must be fs or s3`)
  }
}

let cached: BlobStore | null = null

export function getStore(): BlobStore {
  if (cached) return cached
  cached = createStore()
  return cached
}

/**
 * Install a store for the rest of the process. Tests only: the cache above is
 * process-lifetime by design, so a fault-injecting store or a second driver
 * has no other way in. Nothing the server imports may call this.
 */
export function setStore(store: BlobStore): void {
  cached = store
}

/** Drop any installed or memoized store so the next getStore() rebuilds. */
export function resetStore(): void {
  cached = null
}
