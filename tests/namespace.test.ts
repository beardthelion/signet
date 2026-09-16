/**
 * Namespace and entry-key grammar tests (SN-011/012, SN-020/021).
 *
 * These guard the boundary between attacker-controlled names and storage
 * paths, plus the namespace→DID binding that authorization depends on - a
 * regression here is a cross-holder leak or a forgeable namespace.
 */

import { describe, expect, test } from 'bun:test'
import { createHash } from 'node:crypto'
import {
  encodeDid,
  genesisDid,
  InvalidNameError,
  namespaceForDid,
  namespaceSlug,
  validateEntryKey,
  validateNamespace,
} from '../src/server/namespace.ts'
import { identity } from './setup.ts'

const alice = identity('ns-alice')

describe('namespace grammar (SN-011/SN-012)', () => {
  test('accepts an encoded did:key genesis namespace', () => {
    expect(validateNamespace(alice.namespace)).toBe(alice.namespace)
  })

  test('rejects colons, non-signet prefixes, and bare junk', () => {
    for (const ns of [
      'signet:did:key:z6Mk', // unencoded DID - colons must not survive
      `signet:${alice.did}`, // same: raw did:key string
      'user:alice',
      'signet:',
      'signet:rawdid',
      '../etc/passwd',
      '',
      'SIGNET:did_key_z6Mk',
    ]) {
      expect(() => validateNamespace(ns)).toThrow(InvalidNameError)
    }
  })

  test('rejects non-did:key methods even when the grammar matches', () => {
    // SN-002: did:web MUST NOT be a namespace root; no other method exists.
    for (const ns of [
      'signet:did_web_example.com',
      'signet:did_foo_xyz',
      'signet:did_key_', // empty identifier
    ]) {
      expect(() => validateNamespace(ns)).toThrow(InvalidNameError)
    }
  })
})

describe('genesis DID binding', () => {
  test('decodes the namespace back to the genesis DID', () => {
    expect(genesisDid(alice.namespace)).toBe(alice.did)
  })

  test('encode/decode round-trips', () => {
    expect(encodeDid(alice.did)).toBe(alice.namespace.slice('signet:'.length))
    expect(namespaceForDid(alice.did)).toBe(alice.namespace)
  })
})

describe('entry-key grammar (SN-020/SN-021)', () => {
  test('accepts section-scoped keys', () => {
    for (const k of [
      'memory/MEMORY.md',
      'memory/feedback/testing.md',
      'config/settings.json',
      'grants/grant-001.json',
      'identity/did.json',
      'identity/rotations/1.json',
      'sessions/abc/000001',
    ]) {
      expect(validateEntryKey(k)).toBe(k)
    }
  })

  test('rejects unknown sections and sectionless keys', () => {
    for (const k of ['secrets/key.pem', 'MEMORY.md', 'etc/passwd', 'memory/']) {
      expect(() => validateEntryKey(k)).toThrow(InvalidNameError)
    }
  })

  test('rejects traversal, separators, backslash, NUL', () => {
    for (const k of [
      'memory/../etc/passwd',
      'memory//x',
      '/memory/x',
      'memory/x\\y',
      'memory/x\0y',
      'memory/x ',
      'memory/a/./b',
    ]) {
      expect(() => validateEntryKey(k)).toThrow(InvalidNameError)
    }
  })

  test('session chunks require exactly <id>/<numeric seq>', () => {
    expect(validateEntryKey('sessions/abc/000042')).toBe('sessions/abc/000042')
    for (const k of ['sessions/abc/xyz', 'sessions/abc', 'sessions/a/b/c', 'sessions//000001']) {
      expect(() => validateEntryKey(k)).toThrow(InvalidNameError)
    }
  })
})

describe('namespaceSlug (injective storage key)', () => {
  test('distinct namespaces never share a slug', () => {
    const slugs = new Set(
      ['ns-alice', 'ns-bob', 'ns-carol'].map(l => namespaceSlug(identity(l).namespace)),
    )
    expect(slugs.size).toBe(3)
  })

  test('produces a flat, path-safe 64-char lowercase-hex segment', () => {
    expect(namespaceSlug(alice.namespace)).toMatch(/^[0-9a-f]{64}$/)
  })

  test('pins the slug to sha256 of the namespace', () => {
    expect(namespaceSlug(alice.namespace)).toBe(
      createHash('sha256').update(alice.namespace).digest('hex'),
    )
  })
})
