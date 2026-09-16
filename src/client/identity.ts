/**
 * Holder identity: did:key generation, signing, and rotation attestations.
 *
 * A signet is rooted at exactly one genesis DID (SN-010): a `did:key`
 * Ed25519 identity created at `signet init`. The private key is one of the
 * two secrets that govern the signet (SN-100) - it lives client-side only,
 * inside the custody store, and is never sent to a server. What crosses the
 * wire is the DID itself (public), Ed25519 signatures over server nonces and
 * canonical-JSON documents, and rotation attestations.
 *
 * The DID encoding (SN-001) is `did:key:z` + base58btc(0xed01 || pubkey).
 * base58btc is implemented locally - zero dependencies - and matches the
 * encoder in scripts/gen-vectors.ts byte for byte, so the shared vectors in
 * spec/vectors/{identity,rotation}.json reproduce exactly.
 *
 * Signatures are over canonical JSON: object keys sorted at every level, no
 * whitespace. This is the same canonicalization the spec's vector generator
 * signs, which is what makes the attestations verifiable by any conformant
 * implementation.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
  sign as nodeSign,
  verify as nodeVerify,
} from 'node:crypto'
import type { RotationAttestation } from '../types/index.ts'

// ─── base58btc (did:key multibase) ──────────────────────────────────────

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

/** base58btc encode with the multibase 'z' prefix (SN-001). */
export function base58btc(bytes: Uint8Array): string {
  const digits = [0]
  for (const b of bytes) {
    let carry = b
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i] << 8
      digits[i] = carry % 58
      carry = (carry / 58) | 0
    }
    while (carry > 0) {
      digits.push(carry % 58)
      carry = (carry / 58) | 0
    }
  }
  let zeros = 0
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++
  return (
    'z' +
    '1'.repeat(zeros) +
    digits
      .reverse()
      .map(d => B58[d])
      .join('')
  )
}

/** base58btc decode (no multibase prefix). Null on a bad character. */
export function base58btcDecode(s: string): Uint8Array | null {
  const digits = [0]
  for (const ch of s) {
    const v = B58.indexOf(ch)
    if (v < 0) return null
    let carry = v
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i] * 58
      digits[i] = carry & 0xff
      carry >>= 8
    }
    while (carry > 0) {
      digits.push(carry & 0xff)
      carry >>= 8
    }
  }
  let zeros = 0
  while (zeros < s.length && s[zeros] === '1') zeros++
  const out = new Uint8Array(zeros + digits.length)
  for (let i = 0; i < digits.length; i++) out[zeros + i] = digits[digits.length - 1 - i]
  return out
}

// ─── Ed25519 identities ─────────────────────────────────────────────────

const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')
const ED25519_MULTICODEC = Buffer.from([0xed, 0x01])

export type Identity = {
  /** did:key form: `did:key:z` + base58btc(0xed01 || pubkey). */
  did: string
  /** Ed25519 private key (never leaves the custody store). */
  privateKey: KeyObject
  publicKey: KeyObject
  /** Raw 32-byte public key - what the DID carries. */
  publicKeyRaw: Buffer
  /** PKCS8 DER of the private key - the custody/export encoding (SN-100). */
  pkcs8: Buffer
}

function identityFromKeyObject(privateKey: KeyObject): Identity {
  const publicKey = createPublicKey(privateKey)
  const publicKeyRaw = Buffer.from(publicKey.export({ format: 'der', type: 'spki' })).subarray(
    SPKI_PREFIX.length,
  )
  const did = `did:key:${base58btc(Buffer.concat([ED25519_MULTICODEC, publicKeyRaw]))}`
  const pkcs8 = Buffer.from(privateKey.export({ format: 'der', type: 'pkcs8' }))
  return { did, privateKey, publicKey, publicKeyRaw, pkcs8 }
}

/** Generate a fresh Ed25519 identity - the genesis key of a new signet. */
export function generateIdentity(): Identity {
  const { privateKey } = generateKeyPairSync('ed25519')
  return identityFromKeyObject(privateKey)
}

/** Rebuild an identity from its PKCS8 DER custody encoding. */
export function identityFromPkcs8(der: Buffer | Uint8Array): Identity {
  return identityFromKeyObject(
    createPrivateKey({ key: Buffer.from(der), format: 'der', type: 'pkcs8' }),
  )
}

/**
 * Rebuild an identity from a raw 32-byte Ed25519 seed. Deterministic - the
 * path spec vectors and tests use to pin identities.
 */
export function identityFromSeed(seed: Buffer | Uint8Array): Identity {
  if (seed.length !== 32) throw new Error('ed25519 seed must be 32 bytes')
  return identityFromKeyObject(
    createPrivateKey({
      key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seed)]),
      format: 'der',
      type: 'pkcs8',
    }),
  )
}

/**
 * Extract the Ed25519 public key a did:key carries. Returns null for anything
 * that is not exactly `did:key:z<base58btc(0xed01 || 32-byte pubkey)>`.
 */
export function publicKeyFromDid(did: string): KeyObject | null {
  const m = /^did:key:z([1-9A-HJ-NP-Za-km-z]+)$/.exec(did)
  if (!m) return null
  const bytes = base58btcDecode(m[1]!)
  if (bytes?.length !== 34) return null
  if (bytes[0] !== ED25519_MULTICODEC[0] || bytes[1] !== ED25519_MULTICODEC[1]) return null
  try {
    return createPublicKey({
      key: Buffer.concat([SPKI_PREFIX, Buffer.from(bytes.subarray(2))]),
      format: 'der',
      type: 'spki',
    })
  } catch {
    return null
  }
}

// ─── Canonical JSON + signatures ────────────────────────────────────────

/**
 * Deterministic JSON: object keys sorted at every level, no whitespace.
 * This is the exact encoding scripts/gen-vectors.ts signs, so attestations
 * and manifests produced here verify against the shared vectors.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  const entries = Object.entries(value as Record<string, unknown>)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`)
  return `{${entries.join(',')}}`
}

/**
 * Domain-separation prefix for /auth/verify signatures (SPEC §7.1). The same
 * Ed25519 key signs rotation attestations and integrity manifests, so the
 * challenge preimage is the UTF-8 bytes of `signet-auth:` + nonce - a
 * server-chosen nonce can then never collide with a document this key would
 * sign for another purpose.
 */
export const AUTH_PREIMAGE_PREFIX = 'signet-auth:'

/** Ed25519-sign a message (string = UTF-8 bytes), base64 result. */
export function signMessage(privateKey: KeyObject, message: string | Uint8Array): string {
  return nodeSign(null, Buffer.from(message), privateKey).toString('base64')
}

/** Verify a base64 Ed25519 signature over `message` against a did:key. */
export function verifyDidSignature(
  did: string,
  message: string | Uint8Array,
  sigB64: string,
): boolean {
  const key = publicKeyFromDid(did)
  if (!key) return false
  let sig: Buffer
  try {
    sig = Buffer.from(sigB64, 'base64')
    if (sig.length !== 64) return false
    if (sig.toString('base64').replace(/=+$/, '') !== sigB64.replace(/=+$/, '')) return false
  } catch {
    return false
  }
  try {
    return nodeVerify(null, Buffer.from(message), key, sig)
  } catch {
    return false
  }
}

// ─── Namespaces (SN-011) ────────────────────────────────────────────────

/** `did:key:z6Mk...` -> `did_key_z6Mk...` - the injective namespace encoding. */
export function encodeDid(did: string): string {
  return did.replaceAll(':', '_')
}

/** The namespace a genesis DID owns: `signet:<encoded did>` (SN-011). */
export function namespaceFor(did: string): string {
  return `signet:${encodeDid(did)}`
}

// ─── Rotation attestations (SN-050/051) ─────────────────────────────────

/** prevHash of the first attestation in a chain (SN-051). */
export const GENESIS_PREV_HASH = '0'.repeat(64)

/** sha256 hex of a string - the attestation hash linkage. */
export function sha256Hex(s: string): string {
  return createHash('sha256').update(s).digest('hex')
}

/** sha256 hex of an attestation's canonical JSON - the next link's prevHash. */
export function attestationHash(att: RotationAttestation): string {
  return sha256Hex(canonicalJson(att))
}

/**
 * Build a rotation attestation (SN-051): the predecessor key signs the
 * canonical JSON of `{genesisDid, newDid, seq, prevHash}`. The successor's
 * own signature is not part of the document - control of the old key is the
 * whole authorization.
 */
export function buildRotationAttestation(opts: {
  genesisDid: string
  /** The key retiring: the genesis key for seq 1, else the previous newDid. */
  signer: KeyObject
  newDid: string
  seq: number
  prevHash: string
}): RotationAttestation {
  const body = {
    genesisDid: opts.genesisDid,
    newDid: opts.newDid,
    seq: opts.seq,
    prevHash: opts.prevHash,
  }
  return { ...body, sig: signMessage(opts.signer, canonicalJson(body)) }
}
