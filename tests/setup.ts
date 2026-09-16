/**
 * Test preload + shared helpers.
 *
 * The server modules freeze their env reads at import time, and bun shares
 * the module cache across all test files in one process - so the env must be
 * set HERE, before any src module loads, or whichever test file imports first
 * wins. Using `??=` lets an individual env override still apply.
 *
 * The byte caps are small on purpose so quota tests can trip them with tiny
 * payloads; they're well above anything the other suites push.
 *
 * This module must NOT statically import anything under src/: that import
 * would resolve before this file's body runs, freezing the real env. Helpers
 * that need server modules use dynamic import, which runs after preload.
 */

import type { KeyObject } from 'node:crypto'
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

process.env.STORE ??= 'fs'
process.env.SIGNET_DATA_DIR ??= mkdtempSync(join(tmpdir(), 'signet-test-'))
process.env.SIGNET_MODE ??= 'local'
process.env.SIGNET_CAP_MEMORY ??= '1024'
process.env.SIGNET_CAP_CONFIG ??= '512'
process.env.SIGNET_CAP_SESSIONS ??= '4096'
process.env.SIGNET_CAP_GRANTS ??= '256'
process.env.SIGNET_CAP_IDENTITY ??= '512'
process.env.SIGNET_CAP_ENTRY ??= '1024'
process.env.SIGNET_CAP_TOTAL ??= '3000'
process.env.SIGNET_MAX_BODY_BYTES ??= '1048576'

// ─── did:key identities from fixed seeds ─────────────────────────────────

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

/** base58btc encode - the mirror of the decoder under test in auth.ts. */
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

const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

export type TestIdentity = {
  label: string
  did: string
  namespace: string
  priv: KeyObject
  rawPub: Buffer
}

/** A deterministic Ed25519 identity: seed = sha256(label). */
export function identity(label: string): TestIdentity {
  const seed = createHash('sha256').update(`signet-test:${label}`).digest()
  const priv = createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  })
  const pub = createPublicKey(priv)
  const rawPub = pub.export({ format: 'der', type: 'spki' }).subarray(SPKI_PREFIX.length)
  const did = `did:key:${base58btc(Buffer.concat([Buffer.from([0xed, 0x01]), rawPub]))}`
  return { label, did, namespace: `signet:${did.replaceAll(':', '_')}`, priv, rawPub }
}

/** Ed25519-sign a message, base64 result - the wire sig format. */
export function signB64(priv: KeyObject, message: string | Uint8Array): string {
  return sign(null, Buffer.from(message), priv).toString('base64')
}

/** The /auth/verify preimage prefix (SPEC §7.1): sigs cover "signet-auth:"+nonce. */
export const AUTH_PREFIX = 'signet-auth:'

/** Sign a challenge nonce for /auth/verify under the domain-separated preimage. */
export function signNonceB64(priv: KeyObject, nonce: string): string {
  return signB64(priv, `${AUTH_PREFIX}${nonce}`)
}

/**
 * Canonical JSON for building attestations - deliberately reimplemented here
 * rather than imported, so the test oracle stays independent of the code it
 * checks (it also matches scripts/gen-vectors.ts byte for byte).
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  const entries = Object.entries(value as Record<string, unknown>)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`)
  return `{${entries.join(',')}}`
}

export type TestAttestation = {
  genesisDid: string
  newDid: string
  seq: number
  prevHash: string
  sig: string
}

/** Build a correctly-shaped, correctly-signed rotation attestation. */
export function makeAttestation(
  genesis: TestIdentity,
  signer: KeyObject,
  next: TestIdentity,
  seq: number,
  prevHash: string,
): TestAttestation {
  const body = { genesisDid: genesis.did, newDid: next.did, seq, prevHash }
  return { ...body, sig: signB64(signer, canonicalJson(body)) }
}

/** sha256 hex of an attestation's canonical JSON - the next link's prevHash. */
export function attestationHash(att: TestAttestation): string {
  return createHash('sha256').update(canonicalJson(att)).digest('hex')
}

// ─── HTTP helpers (handleRequest injection - no socket) ──────────────────

export async function post(path: string, body: unknown): Promise<Response> {
  const { handleRequest } = await import('../src/server/handler.ts')
  return handleRequest(
    new Request(`http://x${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }),
  )
}

/** POST /auth/challenge -> {nonce, expiresAt}. Throws if it fails. */
export async function challenge(): Promise<{ nonce: string; expiresAt: string }> {
  const res = await post('/auth/challenge', {})
  const body = (await res.json()) as { nonce?: string; expiresAt?: string }
  if (res.status !== 200 || !body.nonce) throw new Error(`challenge failed: ${res.status}`)
  return { nonce: body.nonce, expiresAt: body.expiresAt! }
}

/**
 * Run the full challenge -> verify flow and return the bearer token.
 * `overrides` mutates the verify body for negative tests.
 */
export async function tokenFor(
  id: TestIdentity,
  attestations?: TestAttestation[],
  overrides?: { nonce?: string; sig?: string; did?: string },
): Promise<Response> {
  const { nonce } = await challenge()
  return post('/auth/verify', {
    did: overrides?.did ?? id.did,
    nonce: overrides?.nonce ?? nonce,
    sig: overrides?.sig ?? signNonceB64(id.priv, overrides?.nonce ?? nonce),
    ...(attestations ? { attestations } : {}),
  })
}

/** A bearer token for `id`; fails the test loudly if verify rejects. */
export async function mustToken(
  id: TestIdentity,
  attestations?: TestAttestation[],
): Promise<string> {
  const res = await tokenFor(id, attestations)
  const body = (await res.json()) as { token?: string }
  if (res.status !== 200 || !body.token) throw new Error(`verify failed: ${res.status}`)
  return body.token
}

/** An authenticated request against the handler. */
export async function authed(
  token: string,
  method: string,
  path: string,
  body?: unknown,
): Promise<Response> {
  const { handleRequest } = await import('../src/server/handler.ts')
  return handleRequest(
    new Request(`http://x${path}`, {
      method,
      headers: {
        authorization: `Bearer ${token}`,
        ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
      },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    }),
  )
}

/** /signet/<ns> path with the namespace URL-encoded. */
export function nsPath(ns: string, suffix = ''): string {
  return `/signet/${encodeURIComponent(ns)}${suffix}`
}

/** A base64 "ciphertext" blob of roughly n bytes (content is opaque here). */
export function blob(n: number, ch = 'x'): string {
  return Buffer.from(ch.repeat(n)).toString('base64')
}
