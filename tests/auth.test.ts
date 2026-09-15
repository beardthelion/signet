/**
 * DID auth and rotation-chain authorization (PS-090, PS-050..053).
 *
 * The cases are deliberately adversarial: replayed nonces, signatures by the
 * wrong key, chains that are forged, misordered, mis-linked, or terminate at
 * a different DID than the requester's. A regression here is a cross-holder
 * passport leak.
 */

import { describe, expect, test } from 'bun:test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { verifyAttestationChain } from '../src/server/auth.ts'
import {
  attestationHash,
  authed,
  challenge,
  identity,
  makeAttestation,
  mustToken,
  nsPath,
  post,
  signB64,
  tokenFor,
} from './setup.ts'

const ZERO = '0'.repeat(64)

async function verifyRaw(did: string, nonce: string, sig: string, attestations?: unknown) {
  return post('/auth/verify', { did, nonce, sig, ...(attestations ? { attestations } : {}) })
}

describe('challenge/verify', () => {
  const id = identity('auth-basic')

  test('challenge returns a nonce with an expiry', async () => {
    const res = await post('/auth/challenge', {})
    expect(res.status).toBe(200)
    const body = (await res.json()) as { nonce: string; expiresAt: string }
    expect(body.nonce.length).toBeGreaterThan(16)
    expect(Date.parse(body.expiresAt)).toBeGreaterThan(Date.now())
  })

  test('a valid signature issues a bearer that authorizes the namespace', async () => {
    const token = await mustToken(id)
    const res = await authed(token, 'GET', nsPath(id.namespace))
    expect(res.status).toBe(404) // authorized; namespace simply has no data yet
  })

  test('a replayed nonce is rejected (single-use)', async () => {
    const { nonce } = await challenge()
    const sig = signB64(id.priv, nonce)
    const first = await verifyRaw(id.did, nonce, sig)
    expect(first.status).toBe(200)
    // The SAME nonce a second time — even with a fresh valid signature.
    const replay = await verifyRaw(id.did, nonce, signB64(id.priv, nonce))
    expect(replay.status).toBe(401)
    expect(((await replay.json()) as { error: { code: string } }).error.code).toBe('invalid_nonce')
  })

  test('an unknown nonce is rejected', async () => {
    const res = await verifyRaw(id.did, 'never-issued', signB64(id.priv, 'never-issued'))
    expect(res.status).toBe(401)
  })

  test('a signature by another key is rejected', async () => {
    const other = identity('auth-other')
    const { nonce } = await challenge()
    const res = await verifyRaw(id.did, nonce, signB64(other.priv, nonce))
    expect(res.status).toBe(401)
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe('invalid_signature')
  })

  test('a non-did:key identity is rejected outright', async () => {
    const { nonce } = await challenge()
    const res = await verifyRaw('did:web:example.com', nonce, 'AAAA')
    expect(res.status).toBe(400)
  })

  test('a did:key string that is not an Ed25519 key cannot verify', async () => {
    const { nonce } = await challenge()
    // Grammar-valid did:key, garbage payload — no key to verify against.
    const res = await verifyRaw('did:key:z6Mk', nonce, signB64(id.priv, nonce))
    expect(res.status).toBe(401)
  })
})

describe('bearer authorization on /passport/', () => {
  const owner = identity('authz-owner')
  const intruder = identity('authz-intruder')

  test('no bearer -> 401', async () => {
    const res = await authed('', 'GET', nsPath(owner.namespace))
    // authed('') still sends `Bearer ` — also cover a request with no header.
    const { handleRequest } = await import('../src/server/handler.ts')
    const bare = await handleRequest(new Request(`http://x${nsPath(owner.namespace)}`))
    for (const r of [res, bare]) {
      expect(r.status).toBe(401)
      expect(((await r.json()) as { error: { code: string } }).error.code).toBe('unauthorized')
    }
  })

  test('a token bound to another DID -> 403', async () => {
    const token = await mustToken(intruder)
    const res = await authed(token, 'GET', nsPath(owner.namespace))
    expect(res.status).toBe(403)
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe('forbidden')
  })

  test('PS-053: a successor key cannot open the namespace without its chain', async () => {
    // The successor DID is not the genesis DID; with no stored/presented
    // attestation it is just another unauthorized key.
    const successor = identity('authz-successor')
    const token = await mustToken(successor)
    const res = await authed(token, 'GET', nsPath(owner.namespace))
    expect(res.status).toBe(403)
  })
})

describe('rotation attestation chains (PS-051/PS-052)', () => {
  const genesis = identity('rot-genesis')
  const r1 = identity('rot-successor-1')
  const r2 = identity('rot-successor-2')

  function chain(): {
    a1: ReturnType<typeof makeAttestation>
    a2: ReturnType<typeof makeAttestation>
  } {
    const a1 = makeAttestation(genesis, genesis.priv, r1, 1, ZERO)
    const a2 = makeAttestation(genesis, r1.priv, r2, 2, attestationHash(a1))
    return { a1, a2 }
  }

  test('a valid one-link chain authorizes the successor', async () => {
    const { a1 } = chain()
    const res = await tokenFor(r1, [a1])
    expect(res.status).toBe(200)
    const { token } = (await res.json()) as { token: string }
    const get = await authed(token, 'GET', nsPath(genesis.namespace))
    expect(get.status).toBe(404) // authorized; namespace has no data yet
  })

  test('a persisted chain keeps authorizing without re-presentation', async () => {
    // Self-contained: verify once WITH the chain (persists it), then a fresh
    // token carrying no attestations must still be authorized (PS-052 via
    // the stored chain).
    const g = identity('rot-persisted-genesis')
    const s = identity('rot-persisted-successor')
    const a = makeAttestation(g, g.priv, s, 1, ZERO)
    expect((await tokenFor(s, [a])).status).toBe(200)
    const token = await mustToken(s)
    const res = await authed(token, 'GET', nsPath(g.namespace))
    expect(res.status).toBe(404)
  })

  test('a forged attestation (signed by the wrong key) is rejected', async () => {
    const forged = makeAttestation(genesis, r1.priv, r1, 1, ZERO) // seq-1 must be genesis-signed
    const res = await tokenFor(r1, [forged])
    expect(res.status).toBe(401)
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe(
      'invalid_attestation',
    )
  })

  test('a misordered chain (seq starting at 2) is rejected', async () => {
    const bad = makeAttestation(genesis, genesis.priv, r1, 2, ZERO)
    const res = await tokenFor(r1, [bad])
    expect(res.status).toBe(401)
  })

  test('a mis-linked prevHash is rejected', async () => {
    const { a1 } = chain()
    const a2 = makeAttestation(genesis, r1.priv, r2, 2, 'f'.repeat(64)) // wrong prevHash
    const res = await tokenFor(r2, [a1, a2])
    expect(res.status).toBe(401)
  })

  test('a chain terminating at a different DID does not authorize the caller', async () => {
    const { a1 } = chain()
    // r2 presents a chain that ends at r1 — proves r1's authority, not r2's.
    const res = await tokenFor(r2, [a1])
    expect(res.status).toBe(401)
  })

  test('a chain rooted at a different genesis authorizes only that namespace', async () => {
    // Fresh identities: r1 is already the stored terminal of `genesis`'s
    // namespace from the earlier test, so this needs a clean namespace to
    // prove the chain does not leak authority sideways.
    const g = identity('rot-cross-genesis')
    const otherGenesis = identity('rot-other-genesis')
    const s = identity('rot-cross-successor')
    const a = makeAttestation(otherGenesis, otherGenesis.priv, s, 1, ZERO)
    const res = await tokenFor(s, [a])
    // The chain is valid — but rooted at otherGenesis, so it persists under
    // otherGenesis's namespace and authorizes s THERE, never at g.
    expect(res.status).toBe(200)
    const { token } = (await res.json()) as { token: string }
    expect((await authed(token, 'GET', nsPath(g.namespace))).status).toBe(403)
    expect((await authed(token, 'GET', nsPath(otherGenesis.namespace))).status).toBe(404)
  })

  test('a two-link chain authorizes only its terminal key', async () => {
    const g = identity('rot-two-genesis')
    const s1 = identity('rot-two-s1')
    const s2 = identity('rot-two-s2')
    const a1 = makeAttestation(g, g.priv, s1, 1, ZERO)
    const a2 = makeAttestation(g, s1.priv, s2, 2, attestationHash(a1))

    const res = await tokenFor(s2, [a1, a2])
    expect(res.status).toBe(200)
    const { token } = (await res.json()) as { token: string }
    expect((await authed(token, 'GET', nsPath(g.namespace))).status).toBe(404)

    // The rotated-out predecessor is NOT authorized: rotation replaces the
    // active key, so only the chain's terminal DID counts.
    const old = await mustToken(s1, [a1])
    expect((await authed(old, 'GET', nsPath(g.namespace))).status).toBe(403)
  })

  test('verifyAttestationChain accepts the published spec vector', async () => {
    const vector = JSON.parse(
      readFileSync(join(import.meta.dir, '..', 'spec', 'vectors', 'rotation.json'), 'utf8'),
    ) as {
      attestation: unknown
      genesisDid: string
      successorDid: string
    }
    expect(verifyAttestationChain(vector.genesisDid, [vector.attestation])).toBe(
      vector.successorDid,
    )
    // And the same document with the signature field stripped must fail.
    const unsigned = { ...(vector.attestation as object), sig: 'AAAA' } as unknown
    expect(verifyAttestationChain(vector.genesisDid, [unsigned])).toBe(null)
  })
})
