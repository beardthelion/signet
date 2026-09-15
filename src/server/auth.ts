/**
 * DID authentication and namespace authorization (PS-090, PS-050..053).
 *
 * Challenge/response: POST /auth/challenge issues a random, single-use nonce
 * (120 s expiry, PS-090); POST /auth/verify checks an Ed25519 signature over
 * the nonce's UTF-8 bytes against the request's did:key and returns a
 * short-lived bearer bound to that DID. Every /passport/ request then needs a
 * bearer whose DID is authorized for the target namespace: the genesis DID
 * encoded in the namespace itself, or the terminal DID of a valid rotation-
 * attestation chain rooted at that genesis (PS-052).
 *
 * Rotation chains arrive on the /auth/verify request (the client presents its
 * chain) and, once verified, are persisted under the namespace so later
 * requests can be authorized without re-presenting them. The stored chain is
 * re-verified on every authorization — persistence is a cache, not a trust
 * decision, so a tampered store cannot mint authority.
 *
 * The signed message for /auth/verify is the UTF-8 bytes of the nonce string
 * itself (SPEC §7.1: "the Ed25519 signature over `nonce`").
 */

import type { KeyObject } from 'node:crypto'
import { createPublicKey, randomBytes, verify } from 'node:crypto'
import { RotationAttestation } from '../types/index.ts'
import { withLock } from './lock.ts'
import { genesisDid, namespaceForDid, namespaceSlug, sha256Hex } from './namespace.ts'
import { attestationsPath, getStore } from './store/blob.ts'

function envInt(name: string, fallback: number): number {
  const raw = process.env[name]
  if (raw === undefined || raw.trim() === '') return fallback
  const n = Number(raw)
  return Number.isFinite(n) ? n : fallback
}

// ─── Challenges (single-use, 120 s) ─────────────────────────────────────

const NONCE_TTL_MS = 120_000 // fixed by the wire contract, not a tunable
const nonces = new Map<string, number>() // nonce -> expiresAt ms

export function issueChallenge(now = Date.now()): { nonce: string; expiresAt: string } {
  sweep(nonces, now)
  const nonce = randomBytes(32).toString('base64url')
  nonces.set(nonce, now + NONCE_TTL_MS)
  return { nonce, expiresAt: new Date(now + NONCE_TTL_MS).toISOString() }
}

/**
 * Consume a nonce. Single-use: it is deleted even when the signature check
 * that follows fails, so a replayed or raced nonce is always rejected
 * (PS-090). Returns false for unknown or expired nonces.
 */
export function consumeNonce(nonce: string, now = Date.now()): boolean {
  const expiresAt = nonces.get(nonce)
  if (expiresAt === undefined) return false
  nonces.delete(nonce)
  return expiresAt > now
}

// ─── Bearer tokens ──────────────────────────────────────────────────────

const TOKEN_TTL_MS = envInt('PASSPORT_TOKEN_TTL_SEC', 600) * 1000
const tokens = new Map<string, { did: string; expiresAt: number }>()

export function issueToken(did: string, now = Date.now()): { token: string; expiresAt: string } {
  sweepTokens(now)
  const token = randomBytes(32).toString('base64url')
  tokens.set(token, { did, expiresAt: now + TOKEN_TTL_MS })
  return { token, expiresAt: new Date(now + TOKEN_TTL_MS).toISOString() }
}

/** Resolve a bearer token to its DID, or null if unknown/expired. */
export function resolveBearer(req: Request, now = Date.now()): string | null {
  const h = req.headers.get('authorization') ?? ''
  const m = /^Bearer\s+(.+)$/i.exec(h.trim())
  if (!m) return null
  const t = tokens.get(m[1].trim())
  if (!t) return null
  if (t.expiresAt <= now) {
    tokens.delete(m[1].trim())
    return null
  }
  return t.did
}

function sweep(map: Map<string, number>, now: number): void {
  if (map.size < 10_000) return
  for (const [k, exp] of map) if (exp <= now) map.delete(k)
}

function sweepTokens(now: number): void {
  if (tokens.size < 10_000) return
  for (const [k, t] of tokens) if (t.expiresAt <= now) tokens.delete(k)
}

// ─── did:key -> Ed25519 public key ──────────────────────────────────────

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')
const ED25519_MULTICODEC = [0xed, 0x01]

/** base58btc decode. Returns null on any character outside the alphabet. */
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

/**
 * Extract the Ed25519 public key a did:key carries:
 * `did:key:z` + base58btc(`0xed01 || pubkey`). Returns null for anything that
 * is not exactly that shape (34-byte payload with the Ed25519 multicodec).
 */
export function publicKeyFromDid(did: string): KeyObject | null {
  const m = /^did:key:z([1-9A-HJ-NP-Za-km-z]+)$/.exec(did)
  if (!m) return null
  const bytes = base58btcDecode(m[1])
  if (bytes?.length !== 34) return null
  if (bytes[0] !== ED25519_MULTICODEC[0] || bytes[1] !== ED25519_MULTICODEC[1]) return null
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(bytes.subarray(2))]),
    format: 'der',
    type: 'spki',
  })
}

/** Verify an Ed25519 signature (base64) over `message` against a did:key. */
export function verifyDidSignature(did: string, message: Uint8Array, sigB64: string): boolean {
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
    return verify(null, message, key, sig)
  } catch {
    return false
  }
}

// ─── Canonical JSON ─────────────────────────────────────────────────────

/**
 * Deterministic JSON: object keys sorted at every level, no whitespace.
 * This is the exact encoding scripts/gen-vectors.ts signs, so the
 * spec/vectors attestations verify under it.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  const entries = Object.entries(value as Record<string, unknown>)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`)
  return `{${entries.join(',')}}`
}

/** sha256 hex of an attestation's canonical JSON — the prevHash link (PS-051). */
export function attestationHash(att: RotationAttestation): string {
  return sha256Hex(canonicalJson(att))
}

// ─── Rotation attestation chains (PS-051/PS-052) ────────────────────────

const GENESIS_PREV_HASH = '0'.repeat(64)

/**
 * Verify a presented chain of rotation attestations rooted at `genesis`.
 *
 * Returns the DID the chain terminates at — the currently authorized
 * successor — or null if any link fails. Every attestation must name the same
 * genesis DID, carry seq = position (1-based, strictly increasing), link
 * prevHash to the previous attestation's canonical-JSON hash ("0"*64 at
 * seq=1), and be signed by its predecessor's key (the genesis key for seq=1).
 * Forged, unsigned, misordered, or mis-linked chains all fail closed.
 */
export function verifyAttestationChain(genesis: string, raw: unknown): string | null {
  if (!Array.isArray(raw) || raw.length === 0) return null
  const chain: RotationAttestation[] = []
  for (const item of raw) {
    const parsed = RotationAttestation.safeParse(item)
    if (!parsed.success) return null
    chain.push(parsed.data)
  }
  for (let i = 0; i < chain.length; i++) {
    const att = chain[i]
    if (att.genesisDid !== genesis) return null
    if (att.seq !== i + 1) return null
    const expectedPrev = i === 0 ? GENESIS_PREV_HASH : attestationHash(chain[i - 1])
    if (att.prevHash !== expectedPrev) return null
    const signer = i === 0 ? genesis : chain[i - 1].newDid
    const body = {
      genesisDid: att.genesisDid,
      newDid: att.newDid,
      seq: att.seq,
      prevHash: att.prevHash,
    }
    const msg = new TextEncoder().encode(canonicalJson(body))
    if (!verifyDidSignature(signer, msg, att.sig)) return null
  }
  return chain[chain.length - 1].newDid
}

async function readStoredChain(nsSlug: string): Promise<RotationAttestation[] | null> {
  const raw = await getStore().get(attestationsPath(nsSlug))
  if (!raw) return null
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(raw))
    if (!Array.isArray(parsed)) return null
    const out: RotationAttestation[] = []
    for (const item of parsed) {
      const p = RotationAttestation.safeParse(item)
      // Fail closed: one malformed entry invalidates the stored chain rather
      // than letting a partial read pick a different terminal.
      if (!p.success) return null
      out.push(p.data)
    }
    return out
  } catch {
    return null
  }
}

/**
 * Persist a verified chain under the namespace its genesis DID owns. Called
 * from /auth/verify after the chain has passed `verifyAttestationChain`.
 * The longer valid chain wins so a further rotation extends rather than
 * truncates history; an equal-or-shorter valid chain never overwrites a
 * longer stored one.
 */
export async function persistAttestationChain(
  genesis: string,
  chain: RotationAttestation[],
): Promise<void> {
  const nsSlug = namespaceSlug(namespaceForDid(genesis))
  await withLock(`ns:${nsSlug}`, async () => {
    const stored = await readStoredChain(nsSlug)
    const storedValid = stored !== null && verifyAttestationChain(genesis, stored) !== null
    if (!storedValid || chain.length > stored.length) {
      await getStore().put(
        attestationsPath(nsSlug),
        new TextEncoder().encode(JSON.stringify(chain)),
      )
    }
  })
}

/**
 * Is `did` authorized for `ns`? True iff it is the genesis DID encoded in the
 * namespace (PS-010/PS-011) or terminates the stored valid attestation chain
 * rooted at that genesis (PS-052). A mid-chain key is NOT authorized:
 * rotation replaces the active key, so only the terminal successor counts.
 */
export async function isAuthorizedDid(did: string, ns: string): Promise<boolean> {
  const genesis = genesisDid(ns)
  if (did === genesis) return true
  const stored = await readStoredChain(namespaceSlug(ns))
  if (!stored) return false
  return verifyAttestationChain(genesis, stored) === did
}
