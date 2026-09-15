/**
 * Client-side end-to-end encryption for the AI Passport (PS-030..035).
 *
 * This module is the trust boundary made concrete: plaintext is encrypted
 * HERE, on the holder's machine, before anything crosses the wire. A
 * conformant store sees only ciphertext plus the bounded metadata of PS-034 —
 * it cannot read a passport even if it wants to, and nothing under src/server/
 * is permitted to help it try.
 *
 * Crypto choices (native node:crypto, zero dependencies, runs in Bun/Node):
 *   - Key derivation: scrypt(passphrase, salt = sha256("passport-suite:" +
 *     namespace), 32, {N: 2^15, r: 8, p: 1}) (PS-031). The namespace-bound
 *     salt makes derivation deterministic and stateless — there is no salt
 *     file to lose — while keeping keys distinct per passport.
 *   - Cipher: AES-256-GCM with the entry key as AEAD AAD (PS-032), so a
 *     ciphertext blob is cryptographically bound to its key and cannot be
 *     moved or replayed under another.
 *   - Nonce: DETERMINISTIC (synthetic-IV style): HMAC-SHA256(encKey,
 *     entryKey || 0x00 || plaintext)[0:12] (PS-033). Identical plaintext
 *     produces identical ciphertext, which is what enables delta sync by
 *     ciphertext hash. The accepted leak is "are two entries byte-identical";
 *     random nonces MUST NOT be substituted without a spec revision.
 *
 * Wire/storage blob layout, then base64 (PS-030):
 *   [ 0x01 version ][ 12-byte nonce ][ 16-byte GCM tag ][ ciphertext ]
 *
 * The version byte is the migration hook: 0x01 is AES-256-GCM; 0x02 is
 * reserved for XChaCha20-Poly1305 on constrained platforms (PS-035).
 *
 * Everything here MUST reproduce spec/vectors/crypto.json byte for byte; the
 * vector is the contract other implementations (e.g. the Zig layer) check
 * against.
 */

import { createCipheriv, createDecipheriv, createHash, createHmac, scryptSync } from 'node:crypto'

const VERSION = 0x01
const NONCE_LEN = 12
const TAG_LEN = 16
const KEY_LEN = 32
const SCRYPT_PARAMS = { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }
const SALT_PREFIX = 'passport-suite:'

/** Derive the 32-byte passport key from a passphrase + namespace (PS-031). */
export function deriveKey(passphrase: string, namespace: string): Buffer {
  const salt = createHash('sha256').update(`${SALT_PREFIX}${namespace}`).digest()
  return scryptSync(passphrase, salt, KEY_LEN, SCRYPT_PARAMS)
}

/** HMAC-SHA256(key, entryKey || 0x00 || plaintext)[0:12] (PS-033). */
function deterministicNonce(key: Buffer, entryKey: string, plaintext: Buffer): Buffer {
  return createHmac('sha256', key)
    .update(entryKey)
    .update(Buffer.from([0]))
    .update(plaintext)
    .digest()
    .subarray(0, NONCE_LEN)
}

/** Encrypt one entry's plaintext -> base64 ciphertext blob (PS-030/032/033). */
export function encryptEntry(key: Buffer, entryKey: string, plaintext: string): string {
  const pt = Buffer.from(plaintext, 'utf8')
  const nonce = deterministicNonce(key, entryKey, pt)
  const cipher = createCipheriv('aes-256-gcm', key, nonce)
  cipher.setAAD(Buffer.from(entryKey, 'utf8'))
  const ct = Buffer.concat([cipher.update(pt), cipher.final()])
  const tag = cipher.getAuthTag()
  return Buffer.concat([Buffer.from([VERSION]), nonce, tag, ct]).toString('base64')
}

/** Decrypt a base64 blob -> plaintext. Throws on tamper, wrong key, bad AAD. */
export function decryptEntry(key: Buffer, entryKey: string, b64: string): string {
  const blob = Buffer.from(b64, 'base64')
  if (blob.length < 1 + NONCE_LEN + TAG_LEN) throw new Error('ciphertext too short')
  const version = blob[0]
  if (version !== VERSION) throw new Error(`unsupported ciphertext version ${version}`)
  const nonce = blob.subarray(1, 1 + NONCE_LEN)
  const tag = blob.subarray(1 + NONCE_LEN, 1 + NONCE_LEN + TAG_LEN)
  const ct = blob.subarray(1 + NONCE_LEN + TAG_LEN)
  const decipher = createDecipheriv('aes-256-gcm', key, nonce)
  decipher.setAAD(Buffer.from(entryKey, 'utf8'))
  decipher.setAuthTag(tag)
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8')
}

/** `sha256:<hex>` of the base64-decoded blob — the hash the manifest records. */
export function ciphertextHash(b64: string): string {
  return `sha256:${createHash('sha256').update(Buffer.from(b64, 'base64')).digest('hex')}`
}
