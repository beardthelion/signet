import { describe, expect, test } from 'bun:test'
import {
  DidKey,
  EntryKey,
  Grant,
  IntegrityManifest,
  isDeniedConfigKey,
  Namespace,
  RotationAttestation,
} from '../src/types/index.ts'

describe('Namespace', () => {
  test('accepts encoded did:key genesis namespace', () => {
    expect(Namespace.safeParse('passport:did_key_z6MkExampleKey123').success).toBe(true)
  })

  test('rejects colons in namespace', () => {
    expect(Namespace.safeParse('passport:did:key:z6Mk').success).toBe(false)
  })

  test('rejects non-passport namespaces', () => {
    expect(Namespace.safeParse('user:alice').success).toBe(false)
    expect(Namespace.safeParse('passport:rawdid').success).toBe(false)
  })
})

describe('EntryKey', () => {
  test('accepts section-scoped keys', () => {
    for (const k of [
      'memory/MEMORY.md',
      'memory/feedback/testing.md',
      'config/settings.json',
      'grants/grant-001.json',
      'identity/did.json',
      'sessions/abc/000001',
    ]) {
      expect(EntryKey.safeParse(k).success).toBe(true)
    }
  })

  test('rejects unknown sections', () => {
    expect(EntryKey.safeParse('secrets/key.pem').success).toBe(false)
    expect(EntryKey.safeParse('MEMORY.md').success).toBe(false)
  })

  test('rejects traversal and unsafe keys', () => {
    for (const k of [
      'memory/../etc/passwd',
      'memory//x',
      '/memory/x',
      'memory/x\\y',
      'memory/x ',
      'memory/x/',
    ]) {
      expect(EntryKey.safeParse(k).success).toBe(false)
    }
  })

  test('session chunks require numeric seq segment', () => {
    expect(EntryKey.safeParse('sessions/abc/000042').success).toBe(true)
    expect(EntryKey.safeParse('sessions/abc/xyz').success).toBe(false)
    expect(EntryKey.safeParse('sessions/abc').success).toBe(false)
    expect(EntryKey.safeParse('sessions/a/b/c').success).toBe(false)
  })
})

describe('Grant', () => {
  const base = {
    id: 'g1',
    scope: 'src/**',
    granted_by: 'holder',
    granted_at: '2026-09-15T00:00:00Z',
  }

  test('accepts each action class', () => {
    for (const action of ['fs.read', 'fs.write', 'shell.exec', 'net.fetch', 'agent.spawn']) {
      expect(Grant.safeParse({ ...base, action }).success).toBe(true)
    }
  })

  test('rejects unknown actions', () => {
    expect(Grant.safeParse({ ...base, action: 'admin.root' }).success).toBe(false)
  })
})

describe('isDeniedConfigKey', () => {
  test('denies permission-affecting keys', () => {
    for (const k of ['permissions.fs', 'tool.allow.list', 'auto-approve', 'sandbox.mode']) {
      expect(isDeniedConfigKey(k)).toBe(true)
    }
  })

  test('allows ordinary config keys', () => {
    for (const k of ['model', 'theme', 'history.max']) {
      expect(isDeniedConfigKey(k)).toBe(false)
    }
  })
})

describe('identity documents', () => {
  const did = 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH'

  test('did:key shape', () => {
    expect(DidKey.safeParse(did).success).toBe(true)
    expect(DidKey.safeParse('did:web:example.com').success).toBe(false)
  })

  test('integrity manifest', () => {
    const m = {
      seq: 3,
      specVersion: 'passport-spec/0.1',
      genesisDid: did,
      entries: { 'memory/x.md': `sha256:${'a'.repeat(64)}` },
    }
    expect(IntegrityManifest.safeParse(m).success).toBe(true)
    m.seq = 0
    expect(IntegrityManifest.safeParse(m).success).toBe(false)
  })

  test('rotation attestation', () => {
    const r = {
      genesisDid: did,
      newDid: did,
      seq: 1,
      prevHash: '0'.repeat(64),
      sig: 'c2ln',
    }
    expect(RotationAttestation.safeParse(r).success).toBe(true)
    r.prevHash = 'xyz'
    expect(RotationAttestation.safeParse(r).success).toBe(false)
  })
})
