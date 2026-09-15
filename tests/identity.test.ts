/**
 * Identity tests (PS-001, PS-010/011, PS-050/051).
 *
 * Covers did:key generation and decoding, canonical-JSON sign/verify, the
 * namespace encoding, and rotation attestations — plus byte-exact
 * reproduction of spec/vectors/identity.json and rotation.json, which pin
 * the wire formats every conformant implementation shares.
 */

import { describe, expect, test } from 'bun:test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  attestationHash,
  buildRotationAttestation,
  canonicalJson,
  encodeDid,
  GENESIS_PREV_HASH,
  generateIdentity,
  identityFromPkcs8,
  identityFromSeed,
  namespaceFor,
  publicKeyFromDid,
  signMessage,
  verifyDidSignature,
} from '../src/client/identity.ts'

const identityVector = JSON.parse(
  readFileSync(join(import.meta.dir, '../spec/vectors/identity.json'), 'utf8'),
) as {
  genesisSeedHex: string
  genesisDid: string
  successorSeedHex: string
  successorDid: string
  namespace: string
  signMessage: string
  signature: string
  publicKeyHex: string
}

const rotationVector = JSON.parse(
  readFileSync(join(import.meta.dir, '../spec/vectors/rotation.json'), 'utf8'),
) as {
  attestation: {
    genesisDid: string
    newDid: string
    seq: number
    prevHash: string
    sig: string
  }
  attestationHash: string
  genesisDid: string
  successorDid: string
}

describe('did:key generation (PS-001)', () => {
  test('generateIdentity produces a well-formed did:key', () => {
    const id = generateIdentity()
    expect(id.did).toMatch(/^did:key:z[1-9A-HJ-NP-Za-km-z]{40,}$/)
    expect(id.pkcs8.length).toBeGreaterThan(0)
    expect(id.publicKeyRaw.length).toBe(32)
  })

  test('publicKeyFromDid round-trips the raw public key', () => {
    const id = generateIdentity()
    const pub = publicKeyFromDid(id.did)
    expect(pub).not.toBeNull()
    const raw = Buffer.from(pub!.export({ format: 'der', type: 'spki' })).subarray(12)
    expect(raw.equals(id.publicKeyRaw)).toBe(true)
  })

  test('identityFromPkcs8 restores the same DID (custody round-trip)', () => {
    const id = generateIdentity()
    expect(identityFromPkcs8(id.pkcs8).did).toBe(id.did)
  })

  test('publicKeyFromDid rejects malformed DIDs', () => {
    for (const bad of [
      'did:web:example.com',
      'did:key:z!!!',
      'did:key:z6Mk', // too short to carry a key
      'not-a-did',
    ]) {
      expect(publicKeyFromDid(bad)).toBeNull()
    }
  })
})

describe('sign/verify over canonical JSON', () => {
  test('a signature verifies against the signer DID', () => {
    const id = generateIdentity()
    const msg = canonicalJson({ b: 2, a: { d: [1, 2], c: 'x' } })
    expect(msg).toBe('{"a":{"c":"x","d":[1,2]},"b":2}')
    const sig = signMessage(id.privateKey, msg)
    expect(verifyDidSignature(id.did, msg, sig)).toBe(true)
  })

  test('wrong key, tampered message, and bad sig all fail', () => {
    const a = generateIdentity()
    const b = generateIdentity()
    const msg = canonicalJson({ proof: 'x' })
    const sig = signMessage(a.privateKey, msg)
    expect(verifyDidSignature(b.did, msg, sig)).toBe(false)
    expect(verifyDidSignature(a.did, canonicalJson({ proof: 'y' }), sig)).toBe(false)
    expect(verifyDidSignature(a.did, msg, 'not base64 !!')).toBe(false)
  })
})

describe('namespace encoding (PS-011)', () => {
  test('encodeDid is did with : -> _', () => {
    expect(encodeDid('did:key:z6Mkabc')).toBe('did_key_z6Mkabc')
  })

  test('namespaceFor produces passport:<encoded did>', () => {
    expect(namespaceFor('did:key:z6Mkabc')).toBe('passport:did_key_z6Mkabc')
  })
})

describe('spec vectors (identity.json, rotation.json)', () => {
  test('identityFromSeed reproduces the genesis DID and public key', () => {
    const genesis = identityFromSeed(Buffer.from(identityVector.genesisSeedHex, 'hex'))
    expect(genesis.did).toBe(identityVector.genesisDid)
    expect(genesis.publicKeyRaw.toString('hex')).toBe(identityVector.publicKeyHex)
    expect(identityFromSeed(Buffer.from(identityVector.successorSeedHex, 'hex')).did).toBe(
      identityVector.successorDid,
    )
  })

  test('the vector signature reproduces (Ed25519 is deterministic)', () => {
    const genesis = identityFromSeed(Buffer.from(identityVector.genesisSeedHex, 'hex'))
    expect(identityVector.signMessage).toBe(canonicalJson({ proof: 'did:key signs' }))
    expect(signMessage(genesis.privateKey, identityVector.signMessage)).toBe(
      identityVector.signature,
    )
    expect(
      verifyDidSignature(genesis.did, identityVector.signMessage, identityVector.signature),
    ).toBe(true)
  })

  test('namespaceFor matches the vector namespace', () => {
    expect(namespaceFor(identityVector.genesisDid)).toBe(identityVector.namespace)
  })

  test('buildRotationAttestation reproduces the rotation vector (PS-051)', () => {
    const genesis = identityFromSeed(Buffer.from(identityVector.genesisSeedHex, 'hex'))
    const attestation = buildRotationAttestation({
      genesisDid: rotationVector.genesisDid,
      signer: genesis.privateKey,
      newDid: rotationVector.successorDid,
      seq: 1,
      prevHash: GENESIS_PREV_HASH,
    })
    expect(attestation).toEqual(rotationVector.attestation)
    expect(attestationHash(attestation)).toBe(rotationVector.attestationHash)
  })

  test('a chained seq-2 attestation links prevHash and is signed by the predecessor', () => {
    const genesis = identityFromSeed(Buffer.from(identityVector.genesisSeedHex, 'hex'))
    const first = rotationVector.attestation
    const second = generateIdentity()
    const att2 = buildRotationAttestation({
      genesisDid: first.genesisDid,
      signer: identityFromSeed(Buffer.from(identityVector.successorSeedHex, 'hex')).privateKey,
      newDid: second.did,
      seq: 2,
      prevHash: attestationHash(first),
    })
    expect(att2.seq).toBe(2)
    expect(att2.prevHash).toBe(attestationHash(first))
    // Signed by the predecessor (seq-1 successor), not the genesis key.
    const body = {
      genesisDid: att2.genesisDid,
      newDid: att2.newDid,
      seq: att2.seq,
      prevHash: att2.prevHash,
    }
    expect(verifyDidSignature(first.newDid, canonicalJson(body), att2.sig)).toBe(true)
    expect(verifyDidSignature(genesis.did, canonicalJson(body), att2.sig)).toBe(false)
  })
})
