/**
 * Two-secret custody (PS-100..103).
 *
 * A passport is governed by two secrets: the encryption passphrase and the
 * holder's Ed25519 signing key. Both live client-side only — a conformant
 * store MUST NEVER receive either, and nothing in this module sends them
 * anywhere. Custody is a local-state problem, so the boundary this file
 * defends is the filesystem: secrets go into exactly one `0600` file under
 * the passport state dir (default `~/.passport/`, `PASSPORT_HOME` override),
 * never into the workspace, a dotfile the harness might commit, or the store.
 *
 * The backend is a narrow interface (`CustodyBackend`) so an OS keychain can
 * slot in later; the `0600` file is the required v1 backend and the only one
 * implemented here. Writes are atomic (tmp file + rename) and the tmp
 * file's mode is re-asserted before it lands, since `writeFile`'s mode only
 * applies at creation.
 *
 * Export/import (PS-102) moves custody between machines as an encrypted
 * bundle: the secrets JSON is encrypted with a user-supplied export
 * passphrase through the same crypto as passport entries, domain-separated
 * by the KDF namespace `custody/export` (not a passport namespace — it can
 * never collide with real entry encryption). The bundle is safe to put on
 * a flash drive or in a password manager; it is still a secret and is
 * written `0600` by the CLI.
 *
 * PS-103: key loss is total loss. There is deliberately no recovery path.
 */

import { chmodSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { z } from 'zod'
import { DidKey, RotationAttestation } from '../types/index.ts'
import { decryptEntry, deriveKey, encryptEntry } from './crypto.ts'

/** What custody protects: both secrets, plus the rotation/auth state. */
export const CustodySecrets = z.object({
  version: z.literal(1),
  /** The passport's immutable root; the namespace is derived from it. */
  genesisDid: DidKey,
  /** Encryption secret (PS-100). */
  passphrase: z.string().min(1),
  /** Active signing key, PKCS8 DER base64 (PS-100). Equals genesis until a rotation lands. */
  pkcs8: z.string().min(1),
  /** Rotation attestations in chain order — presented at /auth/verify. */
  attestations: z.array(RotationAttestation).default([]),
  /** Last verified integrity-manifest seq per namespace (PS-041 anti-rollback). */
  manifestSeqs: z.record(z.string(), z.number().int().nonnegative()).default({}),
})
export type CustodySecrets = z.infer<typeof CustodySecrets>

/**
 * The custody persistence contract. v1 ships only the file backend below;
 * an OS-keychain backend implements this same three-method surface so the
 * swap touches nothing else.
 */
export interface CustodyBackend {
  /** The stored secrets, or null when this machine holds none. */
  load(): Promise<CustodySecrets | null>
  /** Persist secrets atomically, owner-only. */
  save(secrets: CustodySecrets): Promise<void>
  /** Where the secrets live, for messages to the operator. */
  describe(): string
}

/** The passport state dir: $PASSPORT_HOME or ~/.passport. */
export function passportHome(): string {
  return process.env.PASSPORT_HOME ?? join(homedir(), '.passport')
}

const CUSTODY_FILE = 'custody.json'

/** `0600` custody file under the state dir — never a committable path. */
export class FileCustodyBackend implements CustodyBackend {
  readonly dir: string
  readonly path: string

  constructor(dir?: string) {
    this.dir = dir ?? passportHome()
    this.path = join(this.dir, CUSTODY_FILE)
  }

  async load(): Promise<CustodySecrets | null> {
    let raw: string
    try {
      raw = readFileSync(this.path, 'utf8')
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null
      throw err
    }
    // Invalid JSON lands in the same fail-closed refusal as a schema miss —
    // a bare SyntaxError would leak a parse detail, not an instruction.
    let json: unknown
    try {
      json = JSON.parse(raw)
    } catch {
      json = undefined
    }
    const parsed = CustodySecrets.safeParse(json)
    if (!parsed.success) {
      throw new Error(
        `custody file ${this.path} is unreadable or malformed; refusing to guess. ` +
          'Restore it with `passport import`.',
      )
    }
    return parsed.data
  }

  async save(secrets: CustodySecrets): Promise<void> {
    mkdirSync(this.dir, { recursive: true, mode: 0o700 })
    // Write-then-rename so a crash never leaves a half-written secrets file.
    // The tmp file's mode is re-asserted before it lands, since writeFile's
    // mode only applies at creation; the rename carries it onto the target.
    const tmp = `${this.path}.tmp`
    writeFileSync(tmp, `${JSON.stringify(secrets, null, 2)}\n`, { mode: 0o600 })
    chmodSync(tmp, 0o600)
    renameSync(tmp, this.path)
  }

  describe(): string {
    return this.path
  }
}

/** The v1 backend (file). The keychain backend, when it lands, slots in here. */
export function defaultCustodyBackend(dir?: string): CustodyBackend {
  return new FileCustodyBackend(dir)
}

export async function loadCustody(dir?: string): Promise<CustodySecrets | null> {
  return defaultCustodyBackend(dir).load()
}

export async function saveCustody(secrets: CustodySecrets, dir?: string): Promise<void> {
  await defaultCustodyBackend(dir).save(secrets)
}

// ─── Passphrase generation ──────────────────────────────────────────────

/**
 * 32 characters: a-z without l and o, digits 2-9. Ambiguous glyphs are out
 * because people retype this off a screen. 32 is a power of two, so a random
 * byte maps to an index with no modulo bias and no rejection loop.
 */
export const PASSPHRASE_ALPHABET = 'abcdefghijkmnpqrstuvwxyz23456789'

/** 26 characters over a 32-character alphabet is 26 * 5 = 130 bits. */
export const PASSPHRASE_LENGTH = 26

/**
 * Generate a passphrase from platform randomness. Local only — the caller
 * shows it to the holder once; nothing sends it anywhere (PS-100).
 */
export function generatePassphrase(): string {
  const bytes = new Uint8Array(PASSPHRASE_LENGTH)
  globalThis.crypto.getRandomValues(bytes)
  let out = ''
  for (const b of bytes) out += PASSPHRASE_ALPHABET[b % PASSPHRASE_ALPHABET.length]!
  return out
}

// ─── Export / import (PS-102) ───────────────────────────────────────────

/**
 * KDF domain for export bundles. Deliberately NOT a passport namespace (it
 * fails the PS-012 grammar), so bundle encryption can never collide with or
 * be replayed as passport entry encryption.
 */
const EXPORT_NS = 'custody/export'
const EXPORT_ENTRY_KEY = 'custody/export'

/**
 * The cleartext a bundle protects — the two secrets, the rotation chain, and
 * the PS-041 anti-rollback floors. manifestSeqs must round-trip: without it
 * the destination machine forgets the last verified seq and a replayed old
 * manifest would pass the rollback check.
 */
type BundlePayload = {
  genesisDid: string
  passphrase: string
  pkcs8: string
  attestations: RotationAttestation[]
  manifestSeqs: Record<string, number>
}

/**
 * Produce an encrypted custody bundle (PS-102): JSON text carrying a single
 * base64 blob — the secrets encrypted with `exportPassphrase` through the
 * same AES-256-GCM scheme as entries, under a domain-separated KDF salt.
 */
export function exportBundle(secrets: CustodySecrets, exportPassphrase: string): string {
  const payload: BundlePayload = {
    genesisDid: secrets.genesisDid,
    passphrase: secrets.passphrase,
    pkcs8: secrets.pkcs8,
    attestations: secrets.attestations,
    manifestSeqs: secrets.manifestSeqs,
  }
  const key = deriveKey(exportPassphrase, EXPORT_NS)
  const blob = encryptEntry(key, EXPORT_ENTRY_KEY, JSON.stringify(payload))
  return `${JSON.stringify(
    { version: 1, kind: 'passport-custody', kdf: 'scrypt', cipher: 'aes-256-gcm', blob },
    null,
    2,
  )}\n`
}

/**
 * Decrypt a custody bundle back into secrets. Throws on a wrong export
 * passphrase or a malformed/tampered bundle — there is no partial import.
 */
export function importBundle(bundleText: string, exportPassphrase: string): CustodySecrets {
  let outer: { blob?: unknown }
  try {
    outer = JSON.parse(bundleText)
  } catch {
    throw new Error('custody bundle is not valid JSON')
  }
  if (typeof outer?.blob !== 'string') {
    throw new Error('custody bundle has no encrypted blob')
  }
  let payload: BundlePayload
  try {
    const key = deriveKey(exportPassphrase, EXPORT_NS)
    payload = JSON.parse(decryptEntry(key, EXPORT_ENTRY_KEY, outer.blob))
  } catch {
    throw new Error('custody bundle did not decrypt — wrong export passphrase or tampered file')
  }
  const parsed = CustodySecrets.safeParse({ version: 1, ...payload })
  if (!parsed.success) throw new Error('custody bundle decrypted but is malformed')
  return parsed.data
}
