/**
 * Secret-scan tests (PS-110).
 *
 * The scan runs on every entry's plaintext before encryption — session
 * chunks included. These tests pin both halves of the contract: credential-
 * shaped values are blocked, and plausible non-secret lookalikes pass.
 */

import { describe, expect, test } from 'bun:test'
import {
  enforce,
  type Finding,
  SecretFoundError,
  scanEntries,
  scanEntry,
} from '../src/client/secretscan.ts'

const scan = (text: string, key = 'memory/note.md'): Finding[] => scanEntry(key, text)

describe('credential shapes are blocked', () => {
  const cases: [string, string][] = [
    ['pem private key', '-----BEGIN PRIVATE KEY-----\nMIIE...'],
    ['rsa private key', '-----BEGIN RSA PRIVATE KEY-----'],
    ['encrypted private key', '-----BEGIN ENCRYPTED PRIVATE KEY-----'],
    ['openai key', 'openai key is sk-proj-abc123def456ghi789jkl012mno345'],
    ['anthropic key', 'sk-ant-api03-abcdef0123456789abcd'],
    ['github pat', 'ghp_abcdefghijklmnopqrstuvwxyz0123456789'],
    ['github fine-grained', 'github_pat_11ABCDEFG0_abcdefghijklmnopqrstuvwxyz0123'],
    ['aws key id', 'AKIAIOSFODNN7EXAMPLE'],
    ['slack token', 'xoxb-123456789012-abcdefghijkl'],
    ['stripe live key', 'sk_live_abcdefghijklmnopqrstuvwxyz'],
    ['bearer token', 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abc'],
    ['jwt', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.somesignaturevalue'],
    ['quoted password', 'password = "correct-horse-battery"'],
    ['quoted api key', "api_key: 'abcdef0123456789'"],
    ['unquoted high-entropy token', 'token = a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6'],
  ]
  for (const [name, text] of cases) {
    test(name, () => {
      expect(scan(text).length).toBeGreaterThan(0)
    })
  }

  test('findings carry key, rule, line, and a redacted match', () => {
    const f = scan('line one\nkey: ghp_abcdefghijklmnopqrstuvwxyz0123456789')
    expect(f.length).toBeGreaterThan(0)
    const g = f.find(x => x.rule === 'github-token')!
    expect(g.entryKey).toBe('memory/note.md')
    expect(g.line).toBe(2)
    expect(g.match).not.toContain('cdefghijklmnop')
  })
})

describe('plausible non-secret lookalikes pass', () => {
  const cases: [string, string][] = [
    ['short sk- string', 'the id is sk-abc123'],
    ['short ghp_ string', 'saw ghp_tooshort in a log line'],
    ['short AKIA string', 'AKIA123 is not a key id'],
    ['short bearer', 'Authorization: Bearer abc'],
    ['short quoted password', 'password = "hunter2"'],
    ['unquoted short token', 'token = none'],
    ['prose about secrets', 'remember to rotate the api key stored in the vault'],
    ['normal config', '{"theme":"dark","model":"test-model"}'],
    ['session transcript chunk', '{"role":"agent","text":"state is yours now"}'],
    [
      'a sha256 hash is not a token',
      'integrity sha256:9e1da45000e3246fc4996be51f3425e6f2b0c91868a6e9e15528960ddbf97719',
    ],
  ]
  for (const [name, text] of cases) {
    test(name, () => {
      expect(scan(text)).toEqual([])
    })
  }
})

describe('enforce policy', () => {
  const clean = { 'memory/a.md': 'just a note\n' }
  const dirty = { 'sessions/s/000001': 'ghp_abcdefghijklmnopqrstuvwxyz0123456789' }

  test('block throws SecretFoundError', () => {
    expect(() => enforce(dirty, 'block')).toThrow(SecretFoundError)
    expect(() => enforce(clean, 'block')).not.toThrow()
  })

  test('warn returns findings without throwing', () => {
    expect(enforce(dirty, 'warn').length).toBeGreaterThan(0)
  })

  test('off scans nothing', () => {
    expect(enforce(dirty, 'off')).toEqual([])
  })

  test('session chunks are scanned too (PS-110)', () => {
    const findings = scanEntries({
      'sessions/s/000001': 'xoxb-123456789012-abcdefghijkl',
    })
    expect(findings.length).toBeGreaterThan(0)
    expect(findings[0]!.entryKey).toBe('sessions/s/000001')
  })
})
