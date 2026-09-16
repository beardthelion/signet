/**
 * Crypto conformance tests (SN-030..033).
 *
 * The hard gate: every vector in spec/vectors/crypto.json must reproduce
 * byte-for-byte - the same passphrase + namespace must yield the same
 * keyHex, and the same plaintext the same blob. That is what makes the
 * TypeScript client interchangeable with any other conformant
 * implementation. Then the negative cases: tampered ciphertext, a wrong
 * key, a wrong entry key (AAD), and a bad version byte must all fail.
 */

import { describe, expect, test } from 'bun:test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { ciphertextHash, decryptEntry, deriveKey, encryptEntry } from '../src/client/crypto.ts'

const vectors = JSON.parse(
  readFileSync(join(import.meta.dir, '../spec/vectors/crypto.json'), 'utf8'),
) as {
  passphrase: string
  namespace: string
  keyHex: string
  entries: Record<string, { plaintext: string; blob: string }>
}

const key = () => deriveKey(vectors.passphrase, vectors.namespace)

describe('spec vectors (crypto.json)', () => {
  test('deriveKey reproduces keyHex exactly (SN-031)', () => {
    expect(key().toString('hex')).toBe(vectors.keyHex)
  })

  test('encryptEntry reproduces every blob exactly (SN-030/032/033)', () => {
    for (const [entryKey, v] of Object.entries(vectors.entries)) {
      expect(encryptEntry(key(), entryKey, v.plaintext)).toBe(v.blob)
    }
  })

  test('decryptEntry round-trips every vector blob', () => {
    for (const [entryKey, v] of Object.entries(vectors.entries)) {
      expect(decryptEntry(key(), entryKey, v.blob)).toBe(v.plaintext)
    }
  })

  test('ciphertextHash is sha256:<hex> of the decoded blob', () => {
    for (const v of Object.values(vectors.entries)) {
      expect(ciphertextHash(v.blob)).toMatch(/^sha256:[0-9a-f]{64}$/)
    }
  })
})

describe('round-trip and fail-closed decryption', () => {
  const k = key()
  const entryKey = 'memory/MEMORY.md'
  const blob = encryptEntry(k, entryKey, 'state is yours now\n')

  test('round-trip on fresh plaintext', () => {
    expect(decryptEntry(k, entryKey, blob)).toBe('state is yours now\n')
  })

  test('encryption is deterministic - same plaintext, same blob', () => {
    expect(encryptEntry(k, entryKey, 'state is yours now\n')).toBe(blob)
  })

  test('a flipped ciphertext byte fails the GCM tag', () => {
    const raw = Buffer.from(blob, 'base64')
    raw[raw.length - 1] = raw[raw.length - 1]! ^ 0xff
    expect(() => decryptEntry(k, entryKey, raw.toString('base64'))).toThrow()
  })

  test('a wrong key fails (SN-031: passphrase or namespace differs)', () => {
    const wrong = deriveKey(vectors.passphrase, 'signet:did_key_someoneelse')
    expect(() => decryptEntry(wrong, entryKey, blob)).toThrow()
    const wrongPass = deriveKey('not the passphrase', vectors.namespace)
    expect(() => decryptEntry(wrongPass, entryKey, blob)).toThrow()
  })

  test('a wrong entry key fails - the key is the AAD (SN-032)', () => {
    expect(() => decryptEntry(k, 'memory/other.md', blob)).toThrow()
  })

  test('an unknown version byte is rejected', () => {
    const raw = Buffer.from(blob, 'base64')
    raw[0] = 0x7f
    expect(() => decryptEntry(k, entryKey, raw.toString('base64'))).toThrow(/version/)
  })

  test('a truncated blob is rejected', () => {
    const raw = Buffer.from(blob, 'base64').subarray(0, 10)
    expect(() => decryptEntry(k, entryKey, raw.toString('base64'))).toThrow()
  })
})
