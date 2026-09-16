/**
 * Zod schemas for the signet wire and storage formats.
 *
 * These types describe documents that cross a trust boundary: they arrive from
 * the wire or the store and are attacker-influenced until validated. Parsing
 * them through these schemas is the first gate, before crypto or storage.
 */

import { z } from 'zod'

export const SECTIONS = ['memory', 'config', 'sessions', 'grants', 'identity'] as const
export type Section = (typeof SECTIONS)[number]

const segment = /^[A-Za-z0-9][A-Za-z0-9._-]*$/
const chunkSeq = /^[0-9]{6,}$/

/** One path segment of an entry key (also a grants/<id> atom). */
export function isKeySegment(s: string): boolean {
  return segment.test(s)
}

/** An entry key is `<section>/<segments>`; sessions chunk as `sessions/<id>/<seq>`. */
export const EntryKey = z
  .string()
  .min(1)
  .max(255)
  .refine(
    key => {
      const parts = key.split('/')
      if (parts.length < 2) return false
      if (!(SECTIONS as readonly string[]).includes(parts[0])) return false
      if (key.includes('..') || key.includes('//') || key.startsWith('/') || key.endsWith('/'))
        return false
      if (key.includes('\\') || key.includes('\0')) return false
      if (parts[0] === 'sessions') {
        if (parts.length !== 3) return false
        return isKeySegment(parts[1]) && chunkSeq.test(parts[2])
      }
      return parts.slice(1).every(isKeySegment)
    },
    { message: 'invalid entry key' },
  )
export type EntryKey = z.infer<typeof EntryKey>

/** Encoded genesis DID namespace: `signet:` + DID with `:` -> `_`. */
export const Namespace = z
  .string()
  .regex(
    /^signet:did_[a-z]+_[A-Za-z0-9._-]{1,240}$/,
    'namespace must be signet:<encoded genesis DID>',
  )
export type Namespace = z.infer<typeof Namespace>

/** did:key with the Ed25519 multicodec prefix (0xed01) in base58btc. */
export const DidKey = z.string().regex(/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/, 'invalid did:key')
export type DidKey = z.infer<typeof DidKey>

export const DidWeb = z.string().regex(/^did:web:[A-Za-z0-9._~%-]+(:[A-Za-z0-9._~%/-]+)?$/)
export type DidWeb = z.infer<typeof DidWeb>

export const Did = z.union([DidKey, DidWeb])
export type Did = z.infer<typeof Did>

/** `sha256:<64-hex>` content hash of a ciphertext blob. */
export const ContentHash = z.string().regex(/^sha256:[0-9a-f]{64}$/)
export type ContentHash = z.infer<typeof ContentHash>

export const GRANT_ACTIONS = [
  'fs.read',
  'fs.write',
  'shell.exec',
  'net.fetch',
  'agent.spawn',
] as const
export type GrantAction = (typeof GRANT_ACTIONS)[number]

/** A holder-confirmed permission grant. Never auto-applied by a consumer. */
export const Grant = z.object({
  id: z.string().min(1),
  action: z.enum(GRANT_ACTIONS),
  scope: z.string().min(1),
  constraints: z.record(z.string(), z.unknown()).optional(),
  granted_by: z.string().min(1),
  granted_at: z.string().min(1),
  expires_at: z.string().optional(),
})
export type Grant = z.infer<typeof Grant>

/** Holder-signed integrity manifest; `seq` strictly increases per push. */
export const IntegrityManifest = z.object({
  seq: z.number().int().positive(),
  specVersion: z.string().min(1),
  genesisDid: DidKey,
  entries: z.record(z.string(), ContentHash),
})
export type IntegrityManifest = z.infer<typeof IntegrityManifest>

/** Signed wrapper for the integrity manifest. */
export const SignedManifest = z.object({
  manifest: IntegrityManifest,
  did: DidKey,
  sig: z.string().min(1),
})
export type SignedManifest = z.infer<typeof SignedManifest>

/** Rotation attestation: successor key authorized by predecessor signature. */
export const RotationAttestation = z.object({
  genesisDid: DidKey,
  newDid: DidKey,
  seq: z.number().int().positive(),
  prevHash: z.string().regex(/^[0-9a-f]{64}$/),
  sig: z.string().min(1),
})
export type RotationAttestation = z.infer<typeof RotationAttestation>

/** Server manifest entry metadata - the documented plaintext leak boundary. */
export const ManifestEntry = z.object({
  hash: ContentHash,
  size: z.number().int().nonnegative(),
  updatedAt: z.string(),
})
export type ManifestEntry = z.infer<typeof ManifestEntry>

export const Manifest = z.object({
  entries: z.record(z.string(), ManifestEntry),
})
export type Manifest = z.infer<typeof Manifest>

/** Keys a consumer may not set through `config/` - they belong in `grants/`. */
const DENIED_CONFIG_RE = /permission|grant|allow|deny|trust|sandbox|exec|approve|policy/i

export function isDeniedConfigKey(key: string): boolean {
  return key.split('/').some(p => DENIED_CONFIG_RE.test(p))
}
