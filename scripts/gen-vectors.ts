/**
 * Generates spec/vectors/*.json — the shared conformance vectors that both the
 * TypeScript client and the Zig fx passport layer must pass.
 *
 * Everything is deterministic: fixed Ed25519 seeds, fixed passphrase, the
 * spec's deterministic nonce. Regenerate with `bun run scripts/gen-vectors.ts`
 * after any intentional change to the crypto contract; a diff that appears
 * without such a change means an implementation drifted from the spec.
 */

import {
  createCipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  scryptSync,
  sign,
} from 'node:crypto'
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const SPEC_VERSION = 'passport-spec/0.1'
const OUT = join(import.meta.dir, '..', 'spec', 'vectors')

// ---- base58btc (did:key multibase) ----------------------------------------

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

function base58btc(bytes: Uint8Array): string {
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

// ---- did:key from a fixed seed ---------------------------------------------

const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

function keypairFromSeed(seed: Buffer) {
  const priv = createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  })
  const pub = createPublicKey(priv)
  const rawPub = pub.export({ format: 'der', type: 'spki' }).subarray(SPKI_PREFIX.length)
  return { priv, pub, rawPub }
}

function didKey(rawPub: Buffer): string {
  return `did:key:${base58btc(Buffer.concat([Buffer.from([0xed, 0x01]), rawPub]))}`
}

function encodeDid(did: string): string {
  return did.replaceAll(':', '_')
}

// ---- spec crypto ------------------------------------------------------------

const KEY_LEN = 32
const NONCE_LEN = 12
const SCRYPT = { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }

function deriveKey(passphrase: string, namespace: string): Buffer {
  const salt = createHash('sha256').update(`passport-suite:${namespace}`).digest()
  return scryptSync(passphrase, salt, KEY_LEN, SCRYPT)
}

function encryptEntry(key: Buffer, entryKey: string, plaintext: string): string {
  const pt = Buffer.from(plaintext, 'utf8')
  const nonce = createHmac('sha256', key)
    .update(entryKey)
    .update(Buffer.from([0]))
    .update(pt)
    .digest()
    .subarray(0, NONCE_LEN)
  const cipher = createCipheriv('aes-256-gcm', key, nonce)
  cipher.setAAD(Buffer.from(entryKey, 'utf8'))
  const ct = Buffer.concat([cipher.update(pt), cipher.final()])
  return Buffer.concat([Buffer.from([0x01]), nonce, cipher.getAuthTag(), ct]).toString('base64')
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  const entries = Object.entries(value as Record<string, unknown>)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`)
  return `{${entries.join(',')}}`
}

// ---- emit vectors ------------------------------------------------------------

const genesisSeed = createHash('sha256').update('passport-spec vector genesis').digest()
const successorSeed = createHash('sha256').update('passport-spec vector successor').digest()
const genesis = keypairFromSeed(genesisSeed)
const successor = keypairFromSeed(successorSeed)
const genesisDid = didKey(genesis.rawPub)
const successorDid = didKey(successor.rawPub)
const namespace = `passport:${encodeDid(genesisDid)}`

const passphrase = 'correct horse battery staple'
const encKey = deriveKey(passphrase, namespace)

const entries: Record<string, string> = {
  'memory/MEMORY.md': '---\ntype: note\nprovenance: spec/vector\n---\nRemember the spec.\n',
  'config/settings.json': '{"model":"test-model","theme":"dark"}\n',
  'grants/grant-001.json':
    '{"id":"g1","action":"fs.read","scope":"src/**","granted_by":"holder","granted_at":"2026-01-01T00:00:00Z"}\n',
  'identity/did.json': `${JSON.stringify({ did: genesisDid, method: 'did:key' })}\n`,
  'sessions/demo/000001': '{"role":"user","text":"hello passport"}\n',
  'sessions/demo/000002': '{"role":"agent","text":"state is yours now"}\n',
}

const ciphertexts: Record<string, string> = {}
for (const [k, v] of Object.entries(entries)) ciphertexts[k] = encryptEntry(encKey, k, v)

const manifest = {
  seq: 1,
  specVersion: SPEC_VERSION,
  genesisDid,
  entries: Object.fromEntries(
    Object.entries(ciphertexts).map(([k, b64]) => [
      k,
      `sha256:${createHash('sha256').update(Buffer.from(b64, 'base64')).digest('hex')}`,
    ]),
  ),
}
const manifestSig = sign(null, Buffer.from(canonicalJson(manifest)), genesis.priv).toString(
  'base64',
)

const attestationBody = {
  genesisDid,
  newDid: successorDid,
  seq: 1,
  prevHash: '0'.repeat(64),
}
const attestation = {
  ...attestationBody,
  sig: sign(null, Buffer.from(canonicalJson(attestationBody)), genesis.priv).toString('base64'),
}
const attestationHash = createHash('sha256').update(canonicalJson(attestation)).digest('hex')

mkdirSync(OUT, { recursive: true })

writeFileSync(
  join(OUT, 'crypto.json'),
  `${JSON.stringify(
    {
      specVersion: SPEC_VERSION,
      passphrase,
      namespace,
      keyHex: encKey.toString('hex'),
      entries: Object.fromEntries(
        Object.entries(entries).map(([k, pt]) => [k, { plaintext: pt, blob: ciphertexts[k] }]),
      ),
    },
    null,
    2,
  )}\n`,
)

writeFileSync(
  join(OUT, 'identity.json'),
  `${JSON.stringify(
    {
      specVersion: SPEC_VERSION,
      genesisSeedHex: genesisSeed.toString('hex'),
      genesisDid,
      successorSeedHex: successorSeed.toString('hex'),
      successorDid,
      namespace,
      signMessage: canonicalJson({ proof: 'did:key signs' }),
      signature: sign(
        null,
        Buffer.from(canonicalJson({ proof: 'did:key signs' })),
        genesis.priv,
      ).toString('base64'),
      // The /auth/verify preimage is domain-separated: UTF-8 bytes of
      // "passport-auth:" + nonce (SPEC §7.1). Pinned here so an
      // implementation that signs the bare nonce drifts loudly.
      authNonce: 'vector-auth-nonce-0001',
      authSignature: sign(
        null,
        Buffer.from('passport-auth:vector-auth-nonce-0001', 'utf8'),
        genesis.priv,
      ).toString('base64'),
      publicKeyHex: genesis.rawPub.toString('hex'),
    },
    null,
    2,
  )}\n`,
)

writeFileSync(
  join(OUT, 'rotation.json'),
  `${JSON.stringify(
    { specVersion: SPEC_VERSION, attestation, attestationHash, genesisDid, successorDid },
    null,
    2,
  )}\n`,
)

// The manifest vector is a SignedManifest wire object ({manifest, did, sig})
// exactly as identity/manifest.json carries it.
writeFileSync(
  join(OUT, 'manifest.json'),
  `${JSON.stringify(
    { specVersion: SPEC_VERSION, manifest, did: genesisDid, sig: manifestSig },
    null,
    2,
  )}\n`,
)

console.log('wrote vectors to spec/vectors/')
