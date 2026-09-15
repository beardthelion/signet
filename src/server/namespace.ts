/**
 * Namespace and entry-key validation.
 *
 * A passport namespace is `passport:<encoded-genesis-did>` (PS-011): the
 * genesis DID with every ':' replaced by '_'. The encoding is injective — the
 * method-id charset contains no '_' — so one DID can never alias another's
 * storage. Entry keys are `<section>/<segments>` paths inside the passport
 * (PS-020).
 *
 * Both arrive from the wire and are attacker-controlled, so they are
 * validated here — through the shared Zod grammars — before either can reach
 * a storage path (PS-012, PS-021). Anything the grammar accepts but the spec
 * forbids (a did:web root, an undefined method) is rejected by decoding the
 * namespace and re-validating it as a did:key.
 */

import { createHash } from 'node:crypto'
import { DidKey, EntryKey, Namespace } from '../types/index.ts'

export class InvalidNameError extends Error {}

/**
 * Validate a namespace id. Throws InvalidNameError on anything outside the
 * PS-012 grammar or rooted at a non-did:key method. Returns the namespace
 * unchanged so it can be used inline.
 */
export function validateNamespace(ns: string): string {
  if (typeof ns !== 'string' || !Namespace.safeParse(ns).success) {
    throw new InvalidNameError(`invalid namespace: ${JSON.stringify(ns)}`)
  }
  // The grammar accepts any lowercase method segment (`did_[a-z]+_`), but the
  // spec defines only did:key, and did:web MUST NOT be a namespace root
  // (PS-002). Decoding and re-validating as a did:key rejects both.
  if (!DidKey.safeParse(genesisDid(ns)).success) {
    throw new InvalidNameError('namespace must be rooted at a did:key genesis DID')
  }
  return ns
}

/**
 * Decode `passport:did_<method>_<id>` back to `did:<method>:<id>`.
 *
 * The method-id charset ([A-Za-z0-9._-]) contains no '_', so the encoded form
 * has exactly two underscores and the split is unambiguous. Callers must run
 * validateNamespace first — this assumes the grammar already held.
 */
export function genesisDid(ns: string): string {
  const enc = ns.slice('passport:'.length)
  const a = enc.indexOf('_')
  const b = enc.indexOf('_', a + 1)
  return `${enc.slice(0, a)}:${enc.slice(a + 1, b)}:${enc.slice(b + 1)}`
}

/** `did:key:z6Mk...` -> `did_key_z6Mk...` (PS-011). */
export function encodeDid(did: string): string {
  return did.replaceAll(':', '_')
}

/** The namespace a DID is genesis of — also where its rotation chain lives. */
export function namespaceForDid(did: string): string {
  return `passport:${encodeDid(did)}`
}

/**
 * Validate an entry key (`<section>/<segments>`). Throws InvalidNameError on
 * unknown sections, traversal, separators, backslash or NUL (PS-020/PS-021).
 */
export function validateEntryKey(key: string): string {
  if (typeof key !== 'string' || !EntryKey.safeParse(key).success) {
    throw new InvalidNameError(`invalid entry key: ${JSON.stringify(key)}`)
  }
  return key
}

/** sha256 hex (no prefix) of a string. */
export function sha256Hex(s: string): string {
  return createHash('sha256').update(s).digest('hex')
}

/**
 * Turn a namespace into a single flat, path-safe storage segment.
 *
 * The slug is the ONLY thing separating one holder's `ns/<slug>/...` storage
 * (and its `ns:<slug>` write lock) from another's, so it must be injective:
 * two distinct namespaces must never share a slug. sha256 is
 * collision-resistant, produces all-lowercase hex (safe on case-insensitive
 * filesystems), and needs no per-grammar reasoning. The tradeoff is that
 * namespace→dir is one-way: a bare `ns/<slug>/` directory cannot be mapped
 * back to its namespace without a known namespace list.
 */
export function namespaceSlug(ns: string): string {
  return sha256Hex(ns)
}
