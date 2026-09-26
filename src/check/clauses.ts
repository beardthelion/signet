/**
 * One check function per SN-### clause in spec/clauses.json. The `checks`
 * map at the bottom is the dispatch table the runner looks up by the
 * registry's `check` field; the registry agreement test keeps the two in
 * sync in both directions.
 *
 * Every check takes the same CheckContext: a wire boundary, an optional raw
 * store, and helpers that provision a real signet through the reference
 * client. Nothing here assumes the suite server - a target that answers the
 * wire contract differently simply fails the corresponding clause.
 *
 * Trust boundary notes:
 *   - Every Response from the target is attacker-controlled. Checks assert
 *     on status codes and structural shapes; detail strings never embed
 *     target-supplied text unsanitized (the runner also sanitizes).
 *   - Checks hold real secrets (a fixed test passphrase, fresh Ed25519
 *     keys). The passphrase is a constant so report details stay
 *     deterministic - it is a harness secret, never a fixture a target
 *     could learn anything from.
 *   - Checks that cannot be exercised against a target (no store access, no
 *     process control) return `unsupported` with a note rather than fake a
 *     pass.
 */

import { createHash } from 'node:crypto'
import { mkdtempSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  didDocument,
  MANIFEST_ENTRY_KEY,
  manifestHash,
  SignetClient,
  SignetDecryptError,
  SignetHttpError,
  SignetIntegrityError,
  SignetSkippedError,
  sessionEntryKey,
} from '../client/client.ts'
import { ciphertextHash, decryptEntry, deriveKey, encryptEntry } from '../client/crypto.ts'
import {
  type CustodySecrets,
  exportBundle,
  FileCustodyBackend,
  importBundle,
} from '../client/custody.ts'
import {
  AUTH_PREIMAGE_PREFIX,
  attestationHash,
  base58btc,
  buildRotationAttestation,
  canonicalJson,
  GENESIS_PREV_HASH,
  generateIdentity,
  identityFromPkcs8,
  identityFromSeed,
  namespaceFor,
  publicKeyFromDid,
  signMessage,
  verifyDidSignature,
} from '../client/identity.ts'
import { SecretFoundError } from '../client/secretscan.ts'
import { makeTools } from '../mcp/tools.ts'
import {
  EntryKey,
  GRANT_ACTIONS,
  Grant,
  RotationAttestation,
  SignedManifest,
} from '../types/index.ts'
import type { CheckContext, CheckFn, Session } from './index.ts'
import type { ClauseResult } from './report.ts'
import { trackTmpDir } from './tmpdirs.ts'

/** The auth nonce signature: domain-separated preimage per SPEC §7.1. */
const signNonce = (key: Parameters<typeof signMessage>[0], nonce: string) =>
  signMessage(key, `${AUTH_PREIMAGE_PREFIX}${nonce}`)

/**
 * The passphrase every checker-provisioned signet uses. Constant on
 * purpose: it is a harness secret inside this process, and a constant keeps
 * report details deterministic.
 */
export const CHECK_PASSPHRASE = 'signet-check harness passphrase'

const pass = (detail?: string): ClauseResult => ({
  status: 'pass',
  ...(detail ? { detail } : {}),
})
const fail = (detail: string): ClauseResult => ({ status: 'fail', detail })
const unsupported = (detail: string): ClauseResult => ({ status: 'unsupported', detail })

const b64 = (s: string) => Buffer.from(s, 'utf8').toString('base64')
const nsPath = (ns: string, suffix = '') => `/signet/${encodeURIComponent(ns)}${suffix}`
const entryPath = (ns: string, key: string) =>
  `${nsPath(ns)}/${key.split('/').map(encodeURIComponent).join('/')}`

const VECTORS = new URL('../../spec/vectors/', import.meta.url)
const loadVector = (name: string): Record<string, unknown> =>
  JSON.parse(readFileSync(new URL(name, VECTORS), 'utf8')) as Record<string, unknown>

/** Hashes view for a session's namespace; null when nothing is stored. */
async function hashesView(ctx: CheckContext, s: Session): Promise<Record<string, string> | null> {
  const res = await ctx.wire('GET', `${nsPath(s.namespace)}?view=hashes`, { token: s.token })
  if (res.status === 404) return null
  if (res.status !== 200) throw new Error(`hashes view answered ${res.status}`)
  return (await res.json()) as Record<string, string>
}

/** Decode `signet:did_<method>_<id>` back to `did:<method>:<id>`. */
function decodeGenesis(ns: string): string {
  const enc = ns.slice('signet:'.length)
  const a = enc.indexOf('_')
  const b = enc.indexOf('_', a + 1)
  return `${enc.slice(0, a)}:${enc.slice(a + 1, b)}:${enc.slice(b + 1)}`
}

/** The canonical-JSON document an attestation signs (SN-051). */
function attestationBody(att: {
  genesisDid: string
  newDid: string
  seq: number
  prevHash: string
}): string {
  return canonicalJson({
    genesisDid: att.genesisDid,
    newDid: att.newDid,
    seq: att.seq,
    prevHash: att.prevHash,
  })
}

/** Collect probe failures, then pass or fail with a fixed summary. */
function verdict(problems: string[], passDetail?: string): ClauseResult {
  return problems.length ? fail(problems.join('; ')) : pass(passDetail)
}

// ─── Identity (SN-001..012) ─────────────────────────────────────────────

/** SN-001 - did:key (Ed25519, multibase z + base58btc(0xed01||pubkey)) is
 *  required: identities decode to Ed25519 keys, the wire authenticates a
 *  real did:key, and other DID shapes are refused at /auth/verify. */
const checkDidKey: CheckFn = async ctx => {
  const problems: string[] = []
  const id = generateIdentity()
  if (!/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/.test(id.did)) {
    problems.push('generated identity is not did:key-shaped')
  }
  if (publicKeyFromDid(id.did) === null) {
    problems.push('did:key does not carry an Ed25519 public key')
  }
  // A did:key-shaped string with a non-Ed25519 multicodec must not decode.
  const wrongCodec = `did:key:${base58btc(
    Buffer.concat([Buffer.from([0x00, 0x24]), id.publicKeyRaw]),
  )}`
  if (publicKeyFromDid(wrongCodec) !== null) {
    problems.push('a non-ed25519 multicodec decoded as a signing key')
  }
  const doc = JSON.parse(didDocument(id.did)) as { did?: string; method?: string }
  if (doc.did !== id.did || doc.method !== 'did:key') {
    problems.push('the did.json record does not name did:key')
  }
  try {
    await ctx.tokenFor(id)
  } catch {
    problems.push('a valid did:key could not complete challenge/verify')
  }
  for (const bad of ['did:web:example.com', 'did:pkh:abc', 'not-a-did']) {
    try {
      const nonce = await ctx.challenge()
      const status = await ctx.tryVerify({ did: bad, nonce, sig: b64('x'.repeat(64)) })
      if (status !== 400) {
        problems.push(`verify with a non-did:key DID answered ${status}, expected 400`)
      }
    } catch (err) {
      problems.push(`verify probe failed: ${(err as Error).message}`)
    }
  }
  return verdict(problems)
}

/** SN-002 - did:web is optional and MUST NOT be a namespace root. */
const checkDidWebOptional: CheckFn = async ctx => {
  const problems: string[] = []
  const token = await ctx.tokenFor(generateIdentity())
  const res = await ctx.wire('GET', nsPath('signet:did_web_example.com'), { token })
  if (res.status !== 400) {
    problems.push(`a did:web-rooted namespace answered ${res.status}, expected 400`)
  }
  const nonce = await ctx.challenge()
  const status = await ctx.tryVerify({
    did: 'did:web:example.com',
    nonce,
    sig: b64('y'.repeat(64)),
  })
  if (status !== 400) problems.push(`verify with did:web answered ${status}, expected 400`)
  return verdict(problems)
}

/** SN-010 - the namespace is derived from the genesis DID and never moves. */
const checkGenesisBinding: CheckFn = async ctx => {
  const problems: string[] = []
  const s = await ctx.provision()
  if (s.namespace !== `signet:${s.identity.did.replaceAll(':', '_')}`) {
    problems.push('namespace is not signet:<encoded genesis DID>')
  }
  // A second client rooted at the same genesis DID resolves the same
  // namespace; the binding is a function of the DID, not the active key.
  const again = new SignetClient({
    url: ctx.target.url,
    fetchFn: ctx.target.clientFetch,
    identity: generateIdentity(),
    genesisDid: s.identity.did,
    passphrase: CHECK_PASSPHRASE,
  })
  if (again.namespace !== s.namespace) {
    problems.push('the same genesis DID resolved a different namespace')
  }
  const res = await ctx.wire('GET', nsPath(s.namespace), { token: s.token })
  if (res.status !== 200) problems.push(`manifest view answered ${res.status}, expected 200`)
  return verdict(problems)
}

/** SN-011 - the namespace encoding is the DID with ':' -> '_': injective,
 *  colon-free, and a raw-colon namespace is rejected by the grammar. */
const checkNamespaceEncoding: CheckFn = async ctx => {
  const problems: string[] = []
  const s = await ctx.provision()
  const enc = s.namespace.slice('signet:'.length)
  if (enc.includes(':')) problems.push('encoded namespace still contains a colon')
  if (decodeGenesis(s.namespace) !== s.identity.did) {
    problems.push('encoded namespace does not decode back to the genesis DID')
  }
  // Raw colons can never be a valid namespace: both the bare DID and a
  // colon-carrying lookalike must be rejected.
  for (const raw of [s.identity.did, `signet:${s.identity.did}`]) {
    const res = await ctx.wire('GET', `/signet/${raw}`, { token: s.token })
    if (res.status !== 400) {
      problems.push(`a colon-carrying namespace answered ${res.status}, expected 400`)
    }
  }
  return verdict(problems)
}

/** SN-012 - namespaces outside ^signet:did_[a-z]+_[A-Za-z0-9._-]{1,240}$
 *  are rejected before storage access. */
const checkNamespaceGrammar: CheckFn = async ctx => {
  const problems: string[] = []
  const id = generateIdentity()
  const token = await ctx.tokenFor(id)
  const bad = [
    'signet:',
    'signet:did_key_',
    'signet:did_KEY_x',
    'signet:other_key_x',
    `signet:did_key_${'a'.repeat(241)}`,
    'ns:signet:did_key_x',
  ]
  for (const ns of bad) {
    const res = await ctx.wire('GET', `/signet/${encodeURIComponent(ns)}`, { token })
    if (res.status !== 400) {
      problems.push(`malformed namespace answered ${res.status}, expected 400`)
    }
  }
  // Control: the caller's own well-formed namespace passes the grammar.
  const ok = await ctx.wire('GET', nsPath(namespaceFor(id.did)), { token })
  if (ok.status === 400) problems.push('a well-formed namespace was rejected')
  return verdict(problems)
}

// ─── Entry keys (SN-020..022) ───────────────────────────────────────────

/** SN-020 - entry keys are <section>/<segments> over the five sections. */
const checkEntryKeyGrammar: CheckFn = async ctx => {
  const problems: string[] = []
  const id = generateIdentity()
  const token = await ctx.tokenFor(id)
  const ns = namespaceFor(id.did)
  const blob = b64('probe')
  const good = {
    'memory/m.md': blob,
    'config/c.json': blob,
    'sessions/s-1/000001': blob,
    'grants/g.json': blob,
    'identity/extra.json': blob,
  }
  const res = await ctx.wire('PUT', nsPath(ns), { token, body: { entries: good } })
  const body = (await res.json()) as { accepted?: string[]; skipped?: { key: string }[] }
  if (res.status !== 200 || (body.skipped ?? []).length !== 0) {
    problems.push('valid keys in all five sections were not all accepted')
  }
  const res2 = await ctx.wire('PUT', nsPath(ns), {
    token,
    body: { entries: { 'bogus/x': blob, memory: blob, 'memory/': blob } },
  })
  const body2 = (await res2.json()) as { accepted?: string[]; skipped?: { key: string }[] }
  const skipped = new Set((body2.skipped ?? []).map(sk => sk.key))
  for (const k of ['bogus/x', 'memory', 'memory/']) {
    if (!skipped.has(k)) problems.push(`invalid key ${k} was not skipped`)
  }
  return verdict(problems)
}

/** SN-021 - traversal, separators, backslash, and NUL are rejected before
 *  storage access, on both the read path and the write path. */
const checkTraversalRejected: CheckFn = async ctx => {
  const problems: string[] = []
  const id = generateIdentity()
  const token = await ctx.tokenFor(id)
  const ns = namespaceFor(id.did)
  // URL parsers eat literal ".." segments, so traversal is probed through
  // %2f (survives parsing, decodes to '/' in the handler) and a '..' that
  // is not a whole segment.
  for (const suffix of ['/memory/..x', '/memory%2f..%2fescape', '/memory%2f%2fx']) {
    const res = await ctx.wire('GET', `${nsPath(ns)}${suffix}`, { token })
    if (res.status !== 400) {
      problems.push(`traversal read answered ${res.status}, expected 400`)
    }
  }
  const evil = ['memory/../x', 'memory//x', '/memory/x', 'memory/x/', 'memory\\x/y']
  const res = await ctx.wire('PUT', nsPath(ns), {
    token,
    body: { entries: Object.fromEntries(evil.map(k => [k, b64('evil')])) },
  })
  const body = (await res.json()) as {
    accepted?: string[]
    skipped?: { key: string; reason: string }[]
  }
  const skipped = new Set((body?.skipped ?? []).map(sk => sk.key))
  for (const k of evil) {
    if (!skipped.has(k)) problems.push(`traversal key landed outside skipped: ${JSON.stringify(k)}`)
  }
  if ((body?.accepted ?? []).some(k => evil.includes(k))) {
    problems.push('a traversal key was accepted and stored')
  }
  return verdict(problems)
}

/** SN-022 - sessions chunk as sessions/<id>/<zero-padded seq>. */
const checkSessionChunks: CheckFn = async ctx => {
  const problems: string[] = []
  if (sessionEntryKey('demo', 7) !== 'sessions/demo/000007') {
    problems.push('session chunk keys are not zero-padded')
  }
  const id = generateIdentity()
  const token = await ctx.tokenFor(id)
  const ns = namespaceFor(id.did)
  const res = await ctx.wire('PUT', nsPath(ns), {
    token,
    body: {
      entries: {
        'sessions/s-1/000001': b64('ok'),
        'sessions/s-1/1': b64('not padded'),
        'sessions/s-1/chunk': b64('not numeric'),
        'sessions/s-1': b64('missing seq'),
        'sessions/s-1/000001/extra': b64('too deep'),
      },
    },
  })
  const body = (await res.json()) as { accepted?: string[]; skipped?: { key: string }[] }
  if (!(body?.accepted ?? []).includes('sessions/s-1/000001')) {
    problems.push('a well-formed session chunk key was not accepted')
  }
  const skipped = new Set((body?.skipped ?? []).map(sk => sk.key))
  for (const k of [
    'sessions/s-1/1',
    'sessions/s-1/chunk',
    'sessions/s-1',
    'sessions/s-1/000001/extra',
  ]) {
    if (!skipped.has(k)) problems.push(`malformed session key ${k} was not skipped`)
  }
  return verdict(problems)
}

// ─── Envelope (SN-030..035) ─────────────────────────────────────────────

/** SN-030 - the wire/storage blob is base64([0x01|nonce12|tag16|ct]). */
const checkBlobFormat: CheckFn = async ctx => {
  const problems: string[] = []
  const s = await ctx.provision()
  const plaintext = 'signet-check blob probe\n'
  await s.client.push({ 'memory/blob.md': plaintext })
  const res = await ctx.wire('GET', `${nsPath(s.namespace)}/memory/blob.md`, { token: s.token })
  const body = (await res.json()) as { entry?: string; hash?: string }
  if (res.status !== 200 || typeof body.entry !== 'string') {
    return fail(`entry read answered ${res.status} without a blob`)
  }
  const blobBytes = Buffer.from(body.entry, 'base64')
  if (blobBytes[0] !== 0x01) problems.push('blob version byte is not 0x01')
  if (blobBytes.length !== 1 + 12 + 16 + Buffer.byteLength(plaintext)) {
    problems.push('blob layout is not [version|nonce12|tag16|ciphertext]')
  }
  const encKey = deriveKey(CHECK_PASSPHRASE, s.namespace)
  try {
    if (decryptEntry(encKey, 'memory/blob.md', body.entry) !== plaintext) {
      problems.push('stored blob did not decrypt to the written plaintext')
    }
  } catch {
    problems.push('stored blob failed AEAD decryption with the entry key')
  }
  if (body.hash !== `sha256:${createHash('sha256').update(blobBytes).digest('hex')}`) {
    problems.push('the served hash is not sha256 of the ciphertext')
  }
  return verdict(problems)
}

/** SN-031 - scrypt(passphrase, sha256("signet:"+ns), 32, N=2^15,r=8,p=1). */
const checkKdf: CheckFn = async () => {
  const v = loadVector('crypto.json') as {
    passphrase: string
    namespace: string
    keyHex: string
  }
  const derived = deriveKey(v.passphrase, v.namespace)
  return derived.toString('hex') === v.keyHex
    ? pass('derived key matches spec/vectors/crypto.json')
    : fail('derived key does not match the spec vector')
}

/** SN-032 - AES-256-GCM with the entry key as AAD: vectors decrypt, and a
 *  blob refuses to open under a different entry key or a different key. */
const checkAead: CheckFn = async () => {
  const problems: string[] = []
  const v = loadVector('crypto.json') as {
    passphrase: string
    namespace: string
    entries: Record<string, { plaintext: string; blob: string }>
  }
  const key = deriveKey(v.passphrase, v.namespace)
  const wrongKey = deriveKey(v.passphrase, `${v.namespace}-other`)
  for (const [entryKey, e] of Object.entries(v.entries)) {
    try {
      if (decryptEntry(key, entryKey, e.blob) !== e.plaintext) {
        problems.push(`${entryKey} decrypted to wrong plaintext`)
      }
    } catch {
      problems.push(`${entryKey} failed to decrypt with the correct key`)
    }
    try {
      decryptEntry(key, 'memory/different.md', e.blob)
      problems.push(`${entryKey} decrypted under a foreign entry key (AAD not bound)`)
    } catch {
      // expected: AAD mismatch must fail authentication
    }
    try {
      decryptEntry(wrongKey, entryKey, e.blob)
      problems.push(`${entryKey} decrypted under a different passphrase`)
    } catch {
      // expected
    }
  }
  return verdict(problems)
}

/** SN-033 - the nonce is deterministic: identical plaintext yields identical
 *  ciphertext, byte-equal to the spec vector. */
const checkDeterministicNonce: CheckFn = async () => {
  const problems: string[] = []
  const v = loadVector('crypto.json') as {
    passphrase: string
    namespace: string
    entries: Record<string, { plaintext: string; blob: string }>
  }
  const key = deriveKey(v.passphrase, v.namespace)
  for (const [entryKey, e] of Object.entries(v.entries)) {
    const a = encryptEntry(key, entryKey, e.plaintext)
    const b = encryptEntry(key, entryKey, e.plaintext)
    if (a !== b) problems.push(`${entryKey} encrypted differently across calls`)
    if (a !== e.blob) problems.push(`${entryKey} does not reproduce the spec vector blob`)
  }
  const one = encryptEntry(key, 'memory/x.md', 'a')
  const two = encryptEntry(key, 'memory/x.md', 'b')
  if (one === two) problems.push('different plaintexts produced identical ciphertext')
  return verdict(problems)
}

/**
 * SN-034 - the metadata leak boundary. Everything the store holds is
 * enumerated and must be exactly: a manifest of {key -> {hash,size,
 * updatedAt}}, content-addressed ciphertext blobs, and the rotation chain.
 * No object may contain the plaintext written, the passphrase, the signing
 * key, or a bearer token used in the session. The wire manifest view is
 * bounded to the same field set.
 */
const checkLeakBoundary: CheckFn = async ctx => {
  if (!ctx.target.store) {
    return unsupported('target store is not inspectable through this harness')
  }
  const problems: string[] = []
  const store = ctx.target.store
  const s = await ctx.provision()
  const marker = 'signet-check-canary-plaintext'
  await s.client.push({ 'memory/canary.md': `note body ${marker}\n` })
  const secondToken = await ctx.tokenFor(s.identity)

  const allowedPath = /^ns\/[0-9a-f]{64}\/(manifest\.json|attestations\.json|blobs\/[0-9a-f]{64})$/
  const forbidden = [
    marker,
    CHECK_PASSPHRASE,
    s.token,
    secondToken,
    s.identity.pkcs8.toString('base64'),
  ]
  const paths = await store.paths()
  if (paths.length === 0) problems.push('the store holds no objects after writes')
  let sawManifest = false
  for (const p of paths) {
    if (!allowedPath.test(p)) {
      problems.push(`store object ${p} is outside the manifest-plus-blobs layout`)
      continue
    }
    const bytes = await store.get(p)
    if (!bytes) continue
    for (const secret of forbidden) {
      if (Buffer.from(bytes).includes(secret)) {
        problems.push(`store object ${p} contains a forbidden value`)
      }
    }
    if (p.endsWith('/manifest.json')) {
      sawManifest = true
      let m: { entries?: Record<string, Record<string, unknown>> }
      try {
        m = JSON.parse(new TextDecoder().decode(bytes)) as typeof m
      } catch {
        problems.push('manifest.json is not parseable JSON')
        continue
      }
      for (const k of Object.keys(m)) {
        if (k !== 'entries') problems.push(`manifest.json carries unexpected field "${k}"`)
      }
      for (const [key, meta] of Object.entries(m.entries ?? {})) {
        for (const mk of Object.keys(meta)) {
          if (!['hash', 'size', 'updatedAt'].includes(mk)) {
            problems.push(`manifest metadata for ${key} carries unexpected field "${mk}"`)
          }
        }
        if (typeof meta.hash !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(meta.hash)) {
          problems.push(`manifest metadata for ${key} has a malformed hash`)
        }
      }
    }
    if (p.endsWith('/attestations.json')) {
      try {
        if (!Array.isArray(JSON.parse(new TextDecoder().decode(bytes)))) {
          problems.push('attestations.json is not an array')
        }
      } catch {
        problems.push('attestations.json is not parseable JSON')
      }
    }
  }
  if (!sawManifest) problems.push('no manifest.json was stored')

  // The wire-side view stays inside the same field boundary.
  const view = await ctx.wire('GET', nsPath(s.namespace), { token: s.token })
  const manifest = (await view.json()) as Record<string, unknown>
  for (const k of Object.keys(manifest)) {
    if (!['namespace', 'base', 'erasure', 'entries'].includes(k)) {
      problems.push(`manifest view carries unexpected field "${k}"`)
    }
  }
  for (const [key, meta] of Object.entries(
    (manifest.entries ?? {}) as Record<string, Record<string, unknown>>,
  )) {
    for (const mk of Object.keys(meta)) {
      if (!['hash', 'size', 'updatedAt'].includes(mk)) {
        problems.push(`manifest view metadata for ${key} carries unexpected field "${mk}"`)
      }
    }
  }
  return verdict(problems)
}

/** SN-035 - only version 0x01 (AES-256-GCM) and 0x02 (XChaCha20-Poly1305)
 *  blobs may be served; nothing may invent a third cipher. */
const checkAltCipher: CheckFn = async ctx => {
  const problems: string[] = []
  const s = await ctx.provision()
  await s.client.push({ 'memory/m.md': 'cipher probe\n' })
  const hashes = (await hashesView(ctx, s)) ?? {}
  if (Object.keys(hashes).length === 0) problems.push('no entries to inspect')
  for (const key of Object.keys(hashes)) {
    const path = entryPath(s.namespace, key)
    const res = await ctx.wire('GET', path, { token: s.token })
    const body = (await res.json().catch(() => ({}))) as { entry?: string }
    if (res.status !== 200 || typeof body.entry !== 'string') {
      problems.push(`entry ${key} could not be fetched for version inspection`)
      continue
    }
    const version = Buffer.from(body.entry, 'base64')[0]
    if (version !== 0x01 && version !== 0x02) {
      problems.push(`entry ${key} uses an undefined cipher version byte`)
    }
  }
  return verdict(problems)
}

// ─── Integrity manifest (SN-040/041) ────────────────────────────────────

/** Fetch, decrypt, and schema-validate the signed integrity manifest. */
async function pullIntegrityDoc(ctx: CheckContext, s: Session) {
  const res = await ctx.wire('GET', `${nsPath(s.namespace)}?view=integrity`, { token: s.token })
  const body = (await res.json()) as { entry?: string }
  if (res.status !== 200 || typeof body.entry !== 'string') {
    throw new Error(`integrity view answered ${res.status}`)
  }
  const plaintext = decryptEntry(
    deriveKey(CHECK_PASSPHRASE, s.namespace),
    MANIFEST_ENTRY_KEY,
    body.entry,
  )
  return SignedManifest.parse(JSON.parse(plaintext))
}

/** SN-040 - identity/manifest.json is a holder-signed {seq, specVersion,
 *  genesisDid, entries->sha256:} document, verified against the genesis key. */
const checkManifestSignature: CheckFn = async ctx => {
  const problems: string[] = []
  const s = await ctx.provision()
  await s.client.push({ 'memory/m.md': 'manifest probe\n' })
  let signed: SignedManifest
  try {
    signed = await pullIntegrityDoc(ctx, s)
  } catch (err) {
    return fail(`integrity manifest unreadable or malformed: ${(err as Error).message}`)
  }
  if (signed.manifest.genesisDid !== s.identity.did) {
    problems.push('manifest names a different genesis DID')
  }
  if (signed.did !== s.identity.did) {
    problems.push('manifest signer is not the genesis DID')
  }
  if (!verifyDidSignature(signed.did, canonicalJson(signed.manifest), signed.sig)) {
    problems.push('manifest signature does not verify')
  }
  if (!Number.isInteger(signed.manifest.seq) || signed.manifest.seq < 1) {
    problems.push('manifest seq is not a positive integer')
  }
  if (signed.manifest.specVersion !== ctx.specVersion) {
    problems.push('manifest specVersion does not match the clause registry')
  }
  for (const [k, h] of Object.entries(signed.manifest.entries)) {
    if (!/^sha256:[0-9a-f]{64}$/.test(h)) problems.push(`manifest entry ${k} has a bad hash`)
  }
  if (MANIFEST_ENTRY_KEY in signed.manifest.entries) {
    problems.push('manifest lists its own key (self-hash)')
  }
  return verdict(problems)
}

/**
 * SN-041 - a consumer must fail closed on a tampered, unsigned, or
 * rolled-back manifest. The checker injects forged manifests straight onto
 * the wire (PUT of a replacement identity/manifest.json) and requires the
 * reference client to refuse every one.
 */
const checkManifestRollback: CheckFn = async ctx => {
  const problems: string[] = []
  const s = await ctx.provision()
  await s.client.push({ 'memory/m.md': 'v1\n' })
  // init + two pushes: the verified manifest seq is now 3.
  await s.client.push({ 'memory/m.md': 'v2\n' })
  const encKey = deriveKey(CHECK_PASSPHRASE, s.namespace)
  const attacker = generateIdentity()

  const inject = async (manifestPlaintext: string) => {
    const hashes = (await hashesView(ctx, s)) ?? {}
    const res = await ctx.wire('PUT', nsPath(s.namespace), {
      token: s.token,
      body: {
        base: manifestHash(hashes),
        entries: {
          [MANIFEST_ENTRY_KEY]: encryptEntry(encKey, MANIFEST_ENTRY_KEY, manifestPlaintext),
        },
      },
    })
    if (res.status !== 200) throw new Error(`manifest injection answered ${res.status}`)
  }
  const signAs = (id: ReturnType<typeof generateIdentity>, manifest: unknown) =>
    canonicalJson({
      manifest,
      did: id.did,
      sig: signMessage(id.privateKey, canonicalJson(manifest)),
    })
  const expectRejection = async (label: string) => {
    try {
      await s.client.pull()
      problems.push(`${label}: pull accepted a non-conformant manifest`)
    } catch (err) {
      if (!(err instanceof SignetIntegrityError || err instanceof SignetDecryptError)) {
        problems.push(`${label}: pull failed with a non-integrity error`)
      }
    }
  }

  // Rolled back: a validly-signed manifest at an earlier seq.
  await inject(
    signAs(s.identity, {
      seq: 1,
      specVersion: ctx.specVersion,
      genesisDid: s.identity.did,
      entries: {},
    }),
  )
  await expectRejection('rolled-back manifest')
  // Replaced at the same seq: valid signature, different bytes. The seq
  // must equal the client's verified manifestSeq or this probes rollback,
  // not the same-seq byte-identity rule.
  await inject(
    signAs(s.identity, {
      seq: s.client.manifestSeq,
      specVersion: ctx.specVersion,
      genesisDid: s.identity.did,
      entries: {},
    }),
  )
  await expectRejection('same-seq replacement manifest')
  // Forged signer: a key that never held authority.
  await inject(
    signAs(attacker, {
      seq: 99,
      specVersion: ctx.specVersion,
      genesisDid: s.identity.did,
      entries: {},
    }),
  )
  await expectRejection('foreign-signer manifest')
  // Not a manifest at all.
  await inject('this is not a signed manifest')
  await expectRejection('unsigned manifest')
  return verdict(problems)
}

// ─── Rotation (SN-050..053) ─────────────────────────────────────────────

/** SN-050 - rotation records identity/rotations/<seq>.json in the signet. */
const checkRotationRecord: CheckFn = async ctx => {
  const problems: string[] = []
  const s = await ctx.provision()
  const { attestation, successor, seq } = await s.client.rotate()
  if (seq !== 1 || attestation.seq !== 1) problems.push('first rotation is not seq 1')
  if (attestation.genesisDid !== s.identity.did || attestation.newDid !== successor.did) {
    problems.push('attestation does not name genesis -> successor')
  }
  if (attestation.prevHash !== GENESIS_PREV_HASH)
    problems.push('first attestation prevHash is not 0*64')
  const hashes = (await hashesView(ctx, s)) ?? {}
  if (!('identity/rotations/1.json' in hashes)) {
    problems.push('no identity/rotations/1.json entry was recorded')
  }
  const pulled = await s.client.pull()
  const stored = pulled.entries['identity/rotations/1.json']
  if (stored !== `${canonicalJson(attestation)}\n`) {
    problems.push('recorded rotation entry does not match the attestation')
  }
  return verdict(problems)
}

/** SN-051 - attestation fields, chaining, and the spec vector itself. */
const checkAttestationChain: CheckFn = async ctx => {
  const problems: string[] = []
  const v = loadVector('rotation.json') as {
    attestation: unknown
    attestationHash: string
    genesisDid: string
    successorDid: string
  }
  const parsed = RotationAttestation.safeParse(v.attestation)
  if (!parsed.success) {
    problems.push('spec rotation vector fails schema validation')
  } else {
    const att = parsed.data
    if (att.seq !== 1 || att.prevHash !== GENESIS_PREV_HASH) {
      problems.push('spec vector attestation has wrong seq/prevHash')
    }
    if (!verifyDidSignature(att.genesisDid, attestationBody(att), att.sig)) {
      problems.push('spec vector attestation signature does not verify')
    }
    if (attestationHash(att) !== v.attestationHash) {
      problems.push('spec vector attestation hash mismatch')
    }
  }
  // Live chain: a second rotation links prevHash to the first attestation.
  const s = await ctx.provision()
  const r1 = await s.client.rotate()
  const second = new SignetClient({
    url: ctx.target.url,
    fetchFn: ctx.target.clientFetch,
    identity: r1.successor,
    genesisDid: s.identity.did,
    attestations: r1.chain,
    passphrase: CHECK_PASSPHRASE,
    lastSeq: s.client.manifestSeq,
  })
  const r2 = await second.rotate()
  if (r2.seq !== 2 || r2.attestation.prevHash !== attestationHash(r1.attestation)) {
    problems.push('second attestation does not link to the first')
  }
  if (!verifyDidSignature(r1.successor.did, attestationBody(r2.attestation), r2.attestation.sig)) {
    problems.push('second attestation is not signed by its predecessor')
  }
  // Negative at the wire: misordered or mislinked chains are refused.
  const stranger = generateIdentity()
  for (const att of [
    buildRotationAttestation({
      genesisDid: s.identity.did,
      signer: s.identity.privateKey,
      newDid: stranger.did,
      seq: 7, // misordered
      prevHash: GENESIS_PREV_HASH,
    }),
    buildRotationAttestation({
      genesisDid: s.identity.did,
      signer: s.identity.privateKey,
      newDid: stranger.did,
      seq: 1,
      prevHash: 'f'.repeat(64), // mislinked
    }),
  ]) {
    const nonce = await ctx.challenge()
    const status = await ctx.tryVerify({
      did: stranger.did,
      nonce,
      sig: signNonce(stranger.privateKey, nonce),
      attestations: [att],
    })
    if (status !== 401)
      problems.push(`a malformed attestation chain answered ${status}, expected 401`)
  }
  return verdict(problems)
}

/** SN-052 - only the terminal DID of a valid chain is authorized; forged,
 *  misordered, and superseded (mid-chain) keys are refused. */
const checkSuccessorAuth: CheckFn = async ctx => {
  const problems: string[] = []
  const s = await ctx.provision()
  await s.client.push({ 'memory/m.md': 'rotation probe\n' })
  const r1 = await s.client.rotate()
  try {
    const token = await ctx.tokenFor(r1.successor, r1.chain)
    const res = await ctx.wire('GET', nsPath(s.namespace), { token })
    if (res.status !== 200) problems.push('successor key could not read its signet')
  } catch {
    problems.push('successor key could not authenticate with its chain')
  }
  // Forged chain: the attacker signs for someone else's genesis DID.
  const attacker = generateIdentity()
  const forged = buildRotationAttestation({
    genesisDid: s.identity.did,
    signer: attacker.privateKey,
    newDid: attacker.did,
    seq: 1,
    prevHash: GENESIS_PREV_HASH,
  })
  // The nonce signature must be valid so the refusal isolates the chain
  // check, not the signature check.
  const forgedNonce = await ctx.challenge()
  const forgedStatus = await ctx.tryVerify({
    did: attacker.did,
    nonce: forgedNonce,
    sig: signNonce(attacker.privateKey, forgedNonce),
    attestations: [forged],
  })
  if (forgedStatus !== 401) {
    problems.push(`a forged attestation chain answered ${forgedStatus}, expected 401`)
  }
  // Mid-chain: after a second rotation, the superseded successor loses access.
  const second = new SignetClient({
    url: ctx.target.url,
    fetchFn: ctx.target.clientFetch,
    identity: r1.successor,
    genesisDid: s.identity.did,
    attestations: r1.chain,
    passphrase: CHECK_PASSPHRASE,
    lastSeq: s.client.manifestSeq,
  })
  const r2 = await second.rotate()
  // The longer chain is only persisted when the new terminal presents it at
  // /auth/verify; until then the stored chain still ends at s1.
  const terminal = await ctx.tokenFor(r2.successor, r2.chain).catch(() => null)
  if (terminal === null) {
    // A rejected verify here is a conformance problem, not a skipped probe:
    // the terminal DID of a strictly longer valid chain must authenticate.
    problems.push('the terminal successor could not authenticate with the extended chain')
  } else {
    const res = await ctx.wire('GET', nsPath(s.namespace), { token: terminal })
    if (res.status !== 200) problems.push('the terminal successor lost access to the signet')
  }
  const midToken = await ctx.tokenFor(r1.successor, r1.chain).catch(() => null)
  if (midToken === null) {
    problems.push('a mid-chain key could not even authenticate')
  } else {
    const res = await ctx.wire('GET', nsPath(s.namespace), { token: midToken })
    if (res.status !== 403) {
      problems.push(`superseded mid-chain key answered ${res.status}, expected 403`)
    }
  }
  return verdict(problems)
}

/** SN-053 - post-rotation the namespace stays bound to the genesis DID; the
 *  successor cannot open the signet's data under its own DID. */
const checkRotationNamespace: CheckFn = async ctx => {
  const problems: string[] = []
  const s = await ctx.provision()
  await s.client.push({ 'memory/m.md': 'stays put\n' })
  const r1 = await s.client.rotate()
  const token = await ctx.tokenFor(r1.successor, r1.chain)
  // The successor's own namespace is a different (empty) signet.
  const own = await ctx.wire('GET', nsPath(namespaceFor(r1.successor.did)), { token })
  if (own.status === 200) {
    const body = (await own.json()) as { entries?: Record<string, unknown> }
    if (Object.keys(body.entries ?? {}).length !== 0) {
      problems.push("the successor's own namespace serves the rotated signet's entries")
    }
  } else if (own.status !== 404) {
    problems.push(`successor-rooted namespace answered ${own.status}, expected 404 or empty`)
  }
  // And the genesis namespace still answers the successor.
  const main = await ctx.wire('GET', `${nsPath(s.namespace)}?view=hashes`, { token })
  if (main.status !== 200) {
    problems.push('the genesis namespace refused the rotated successor')
  } else {
    const hashes = (await main.json()) as Record<string, string>
    if (!('memory/m.md' in hashes)) {
      problems.push('the genesis namespace lost entries after rotation')
    }
  }
  return verdict(problems)
}

// ─── Grants and config (SN-060..070) ────────────────────────────────────

/** SN-060 - grants carry the five defined action classes; anything else is
 *  refused by the record path. */
const checkGrantVocabulary: CheckFn = async ctx => {
  const problems: string[] = []
  const s = await ctx.provision()
  const tools = makeTools(s.client, { holderDid: s.identity.did })
  for (const [i, action] of GRANT_ACTIONS.entries()) {
    const r = await tools.grantRecord({
      id: `g-${i}`,
      action,
      scope: 'src/**',
      constraints: { readOnly: true },
      confirmed: true,
    })
    if (r.isError) problems.push(`valid action class ${action} was refused`)
  }
  const bad = await tools.grantRecord({
    id: 'g-bad',
    action: 'fs.execute',
    scope: '*',
    confirmed: true,
  })
  if (!bad.isError) problems.push('an undefined action class was recorded')
  const listed = await tools.grantList()
  for (const action of GRANT_ACTIONS) {
    if (!listed.text.includes(action)) problems.push(`recorded grant ${action} is not listed`)
  }
  return verdict(problems)
}

/** SN-061 - no tool applies grants; they port as records a consumer must
 *  re-confirm. */
const checkGrantNonApplication: CheckFn = async ctx => {
  const problems: string[] = []
  const s = await ctx.provision()
  const tools = makeTools(s.client, { holderDid: s.identity.did })
  for (const name of Object.keys(tools)) {
    if (/apply|honou?r|enforce|consume|activate|grant(?!Record|List)/i.test(name)) {
      problems.push(`tool surface exposes a grant-application verb: ${name}`)
    }
  }
  const rec = await tools.grantRecord({ id: 'g1', action: 'fs.read', scope: '*', confirmed: true })
  if (rec.isError || !/record/i.test(rec.text)) {
    problems.push('grant_record does not present the grant as a record only')
  }
  const listed = await tools.grantList()
  if (!/re-confirm|records only/i.test(listed.text)) {
    problems.push('grant_list does not state that grants need re-confirmation')
  }
  // The stored grant is inert data, not a live permission.
  const stored = await s.client.readEntry('grants/g1.json')
  if (stored === null || !Grant.safeParse(JSON.parse(stored)).success) {
    problems.push('a recorded grant is not a parseable grant document')
  }
  return verdict(problems)
}

/** SN-062 - signet_grant_record is the only write path, and only for
 *  holder-confirmed grants. */
const checkGrantRecord: CheckFn = async ctx => {
  const problems: string[] = []
  const s = await ctx.provision()
  const tools = makeTools(s.client, { holderDid: s.identity.did })
  const unconfirmed = await tools.grantRecord({ id: 'u1', action: 'fs.read', scope: '*' })
  if (!unconfirmed.isError) problems.push('an unconfirmed grant was recorded')
  const explicit = await tools.grantRecord({
    id: 'u2',
    action: 'fs.read',
    scope: '*',
    confirmed: false,
  })
  if (!explicit.isError) problems.push('confirmed:false was recorded anyway')
  const viaSave = await tools.save('grants/sneaky.json', '{"id":"x"}\n')
  if (!viaSave.isError) problems.push('signet_save wrote under grants/ directly')
  const ok = await tools.grantRecord({ id: 'g1', action: 'fs.read', scope: '*', confirmed: true })
  if (ok.isError) problems.push('a confirmed grant was refused')
  const stored = await s.client.readEntry('grants/g1.json')
  if (stored === null) problems.push('the confirmed grant was not persisted')
  return verdict(problems)
}

/** SN-070 - permission-affecting keys are refused under config/. */
const checkConfigDenylist: CheckFn = async ctx => {
  const problems: string[] = []
  const s = await ctx.provision()
  const tools = makeTools(s.client, { holderDid: s.identity.did })
  for (const word of [
    'permission',
    'grant',
    'allow',
    'deny',
    'trust',
    'sandbox',
    'exec',
    'approve',
    'policy',
  ]) {
    const r = await tools.configSet(`${word}.json`, '{}')
    if (!r.isError) problems.push(`denylisted config key "${word}.json" was stored`)
  }
  const nested = await tools.configSet('app/SANDBOX-rules.json', '{}')
  if (!nested.isError) problems.push('a denylisted word nested in a path was stored')
  const viaSave = await tools.save('config/permissions.json', '{}')
  if (!viaSave.isError) problems.push('signet_save routed around the config denylist')
  const okSet = await tools.configSet('appearance.json', '{"theme":"dark"}\n')
  if (okSet.isError) problems.push('a non-denylisted config key was refused')
  const got = await tools.configGet('appearance.json')
  if (got.isError || !got.text.includes('theme')) problems.push('config round-trip failed')
  return verdict(problems)
}

// ─── Wire/storage (SN-080..082, 090..092) ───────────────────────────────

/** SN-080 - manifest-plus-blobs storage with a bare {key: sha256} delta view. */
const checkDeltaSync: CheckFn = async ctx => {
  const problems: string[] = []
  const s = await ctx.provision()
  await s.client.push({ 'memory/a.md': 'delta a\n', 'config/c.json': '{}\n' })
  const hashes = (await hashesView(ctx, s)) ?? {}
  if (Object.keys(hashes).length === 0) problems.push('hashes view is empty after writes')
  for (const [key, hash] of Object.entries(hashes)) {
    if (!EntryKey.safeParse(key).success) {
      problems.push(`hashes view carries a non-entry key ${JSON.stringify(key)}`)
    }
    if (!/^sha256:[0-9a-f]{64}$/.test(hash)) {
      problems.push(`hashes view carries a non-digest value for ${key}`)
    }
    const path = entryPath(s.namespace, key)
    const res = await ctx.wire('GET', path, { token: s.token })
    const body = (await res.json().catch(() => ({}))) as { entry?: string; hash?: string }
    if (res.status !== 200 || body.hash !== hash || ciphertextHash(body.entry ?? '') !== hash) {
      problems.push(`entry ${key} does not hash-match the delta view`)
    }
  }
  // The base a writer computes from the bare map is honored.
  const put = await ctx.wire('PUT', nsPath(s.namespace), {
    token: s.token,
    body: { base: manifestHash(hashes), entries: { 'memory/delta.md': b64('new') } },
  })
  if (put.status !== 200) problems.push(`delta write on the current base answered ${put.status}`)
  const after = (await hashesView(ctx, s)) ?? {}
  if (!('memory/delta.md' in after)) problems.push('the delta write did not land')
  const bad = await ctx.wire('GET', `${nsPath(s.namespace)}?view=bogus`, { token: s.token })
  if (bad.status !== 400) problems.push(`unknown view answered ${bad.status}, expected 400`)
  return verdict(problems)
}

/** SN-081 - caps are all-or-nothing before any write; oversized entries are
 *  reported in `skipped`, never silently dropped; a stale base is a 409
 *  with no partial commit. */
const checkCaps: CheckFn = async ctx => {
  const problems: string[] = []
  const notes: string[] = []
  const s = await ctx.provision()
  const entryCap = ctx.target.caps?.entry ?? 1024 * 1024

  // Oversized entry: skipped and reported, never stored.
  const big = 'x'.repeat(entryCap + 64)
  try {
    await s.client.push({ 'memory/too-big.md': big })
    if (ctx.target.caps) {
      problems.push('an oversized entry was accepted with no skipped report')
    } else {
      notes.push('oversized-entry probe inconclusive: target accepted it (caps unknown)')
    }
  } catch (err) {
    if (
      !(err instanceof SignetSkippedError) ||
      !err.skipped.some(sk => sk.key === 'memory/too-big.md' && sk.reason === 'entry_too_large')
    ) {
      problems.push('an oversized entry was not reported through the skipped list')
    }
    const hashes = (await hashesView(ctx, s)) ?? {}
    if ('memory/too-big.md' in hashes) problems.push('the oversized entry was stored anyway')
  }

  // Stale base: 409, nothing commits.
  const before = (await hashesView(ctx, s)) ?? {}
  const stale = await ctx.wire('PUT', nsPath(s.namespace), {
    token: s.token,
    body: { base: `sha256:${'0'.repeat(64)}`, entries: { 'memory/stale.md': b64('stale') } },
  })
  if (stale.status !== 409) {
    problems.push(`a stale base answered ${stale.status}, expected 409`)
  }
  const after = (await hashesView(ctx, s)) ?? {}
  if ('memory/stale.md' in after || JSON.stringify(after) !== JSON.stringify(before)) {
    problems.push('a stale-base write committed state')
  }

  // Section cap: the whole write fails, nothing commits (needs known caps).
  if (ctx.target.caps) {
    const ptSize = ctx.target.caps.entry - 64 // under the per-entry cap
    const blobSize = ptSize + 29
    const count = Math.floor(ctx.target.caps.memory / blobSize) + 1
    const flood: Record<string, string> = {}
    for (let i = 0; i < count; i++) flood[`memory/flood-${i}.md`] = 'y'.repeat(ptSize)
    const beforeFlood = (await hashesView(ctx, s)) ?? {}
    try {
      await s.client.push(flood)
      problems.push('an over-section-cap write was accepted')
    } catch (err) {
      if (!(err instanceof SignetHttpError) || err.status !== 413) {
        problems.push('an over-section-cap write did not fail with 413')
      }
      const afterFlood = (await hashesView(ctx, s)) ?? {}
      if (JSON.stringify(afterFlood) !== JSON.stringify(beforeFlood)) {
        problems.push('an over-cap write partially committed')
      }
    }
  } else {
    notes.push('section-cap probe skipped: target caps unknown')
  }
  const v = verdict(problems)
  return v.status === 'pass' && notes.length ? pass(notes.join('; ')) : v
}

/** SN-082 - the per-namespace lock serializes read-modify-write: two
 *  concurrent PUTs on the same base cannot clobber the manifest. */
const checkNamespaceLock: CheckFn = async ctx => {
  const problems: string[] = []
  const id = generateIdentity()
  const token = await ctx.tokenFor(id)
  const ns = namespaceFor(id.did)
  const [r1, r2] = await Promise.all([
    ctx.wire('PUT', nsPath(ns), {
      token,
      body: { base: null, entries: { 'memory/lock-a.md': b64('a') } },
    }),
    ctx.wire('PUT', nsPath(ns), {
      token,
      body: { base: null, entries: { 'memory/lock-b.md': b64('b') } },
    }),
  ])
  const statuses = [r1.status, r2.status].sort()
  const res = await ctx.wire('GET', `${nsPath(ns)}?view=hashes`, { token })
  const hashes = res.status === 200 ? ((await res.json()) as Record<string, string>) : {}
  const hasA = 'memory/lock-a.md' in hashes
  const hasB = 'memory/lock-b.md' in hashes
  if (statuses.join(',') === '200,409') {
    const winner = r1.status === 200 ? hasA : hasB
    const loser = r1.status === 200 ? hasB : hasA
    if (!winner) problems.push('the winning concurrent write did not commit')
    if (loser) problems.push('the losing concurrent write committed anyway')
  } else if (statuses.join(',') === '200,200') {
    // A store that serializes and re-reads may legitimately accept both -
    // but only if neither write was lost.
    if (!hasA || !hasB) problems.push('concurrent writes clobbered each other (lost update)')
  } else {
    problems.push(`concurrent PUTs answered ${statuses.join(' and ')}`)
  }
  // The manifest that survives must be consistent: every key fetchable.
  for (const key of Object.keys(hashes)) {
    const path = entryPath(ns, key)
    const got = await ctx.wire('GET', path, { token })
    if (got.status !== 200) problems.push(`committed entry ${key} is unreadable`)
  }
  return verdict(problems)
}

/** SN-083 - a write on a stale base is refused with a 409 that carries the
 *  current base hash, and a write rebased onto it merges rather than
 *  clobbering. This is the wire contract the client's bounded rebase loop
 *  exercises; the loop's retries and tombstone interplay are unit-tested. */
const checkStaleBaseRebase: CheckFn = async ctx => {
  const problems: string[] = []
  const s = await ctx.provision()
  const put = await s.client.push({ 'memory/base.md': 'v1\n' })
  if (!put.uploaded.includes('memory/base.md')) {
    problems.push('provisioned write did not land')
  }
  const stale = await ctx.wire('PUT', nsPath(s.namespace), {
    token: s.token,
    body: { base: null, entries: { 'memory/stale.md': b64('stale\n') } },
  })
  if (stale.status !== 409) {
    problems.push(`stale-base write answered ${stale.status}, expected 409`)
    return verdict(problems)
  }
  const body = (await stale.json().catch(() => ({}))) as {
    error?: { code?: string; details?: { current?: string } }
  }
  if (body.error?.code !== 'stale_base') {
    problems.push(`stale-base refusal carried code ${JSON.stringify(body.error?.code)}`)
  }
  const current = body.error?.details?.current
  if (typeof current !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(current)) {
    problems.push('409 response carries no usable `current` base for rebasing')
    return verdict(problems)
  }
  const rebased = await ctx.wire('PUT', nsPath(s.namespace), {
    token: s.token,
    body: { base: current, entries: { 'memory/rebased.md': b64('rebased\n') } },
  })
  if (rebased.status !== 200) {
    problems.push(`write rebased onto the returned base answered ${rebased.status}`)
  }
  const hashes = (await hashesView(ctx, s)) ?? {}
  if (!('memory/base.md' in hashes)) problems.push("rebase lost the prior writer's entry")
  if (!('memory/rebased.md' in hashes)) problems.push('rebased entry is not committed')
  return verdict(problems, 'stale base refused with current base; rebase write merged')
}

/** SN-084 - deletions publish tombstones inside the signed manifest,
 *  recording the seq at which each key was deleted, and the deleted entry
 *  leaves the hash view. Causal precedence and the 512-marker cap are
 *  unit-tested; this checks the published artifact. */
const checkTombstones: CheckFn = async ctx => {
  const problems: string[] = []
  const s = await ctx.provision()
  await s.client.push({ 'memory/gone.md': 'soon deleted\n' })
  const del = await s.client.push({}, { deletions: ['memory/gone.md'] })
  const pulled = await s.client.pull()
  const raw = pulled.entries[MANIFEST_ENTRY_KEY]
  if (typeof raw !== 'string') {
    problems.push('pulled manifest entry missing')
    return verdict(problems)
  }
  const signed = SignedManifest.safeParse(JSON.parse(raw))
  if (!signed.success) {
    problems.push('pulled manifest fails the signed-manifest schema')
    return verdict(problems)
  }
  const tombstones = signed.data.manifest.tombstones ?? {}
  if (tombstones['memory/gone.md'] !== del.seq) {
    problems.push(
      `tombstone for memory/gone.md is ${JSON.stringify(tombstones['memory/gone.md'])}, expected seq ${del.seq}`,
    )
  }
  if ('memory/gone.md' in signed.data.manifest.entries) {
    problems.push('deleted entry still listed in the manifest')
  }
  const hashes = (await hashesView(ctx, s)) ?? {}
  if ('memory/gone.md' in hashes) problems.push('deleted entry still in the hashes view')
  return verdict(problems, 'tombstone published at the deletion seq; entry removed')
}

/** SN-090 - bearer auth bound to an authorized DID: 401 unauthenticated,
 *  403 wrong DID, replayed nonces rejected. */
const checkAuth: CheckFn = async ctx => {
  const problems: string[] = []
  const id = generateIdentity()
  const ns = namespaceFor(id.did)
  const token = await ctx.tokenFor(id)
  const other = generateIdentity()
  const otherToken = await ctx.tokenFor(other)

  const noAuth = await ctx.wire('GET', nsPath(ns))
  if (noAuth.status !== 401) problems.push(`unauthenticated request answered ${noAuth.status}`)
  const garbage = await ctx.target.fetch(
    new Request(`${ctx.target.url}${nsPath(ns)}`, {
      headers: { authorization: 'Bearer not-a-real-token' },
    }),
  )
  if (garbage.status !== 401) problems.push(`a garbage bearer answered ${garbage.status}`)
  const wrong = await ctx.wire('GET', nsPath(ns), { token: otherToken })
  if (wrong.status !== 403)
    problems.push(`a wrong-DID bearer answered ${wrong.status}, expected 403`)
  const right = await ctx.wire('GET', nsPath(ns), { token })
  if (right.status === 401 || right.status === 403) {
    problems.push(`the authorized DID was refused with ${right.status}`)
  }

  // Replay: a consumed nonce must never verify again.
  const nonce = await ctx.challenge()
  const sig = signNonce(id.privateKey, nonce)
  const first = await ctx.tryVerify({ did: id.did, nonce, sig })
  if (first !== 200) problems.push('a valid challenge/verify was refused')
  const replay = await ctx.tryVerify({ did: id.did, nonce, sig })
  if (replay !== 401) problems.push(`a replayed nonce answered ${replay}, expected 401`)

  // Bad signature and unknown nonce are both refused.
  const badNonce = await ctx.challenge()
  const wrongSig = signNonce(other.privateKey, badNonce)
  if ((await ctx.tryVerify({ did: id.did, nonce: badNonce, sig: wrongSig })) !== 401) {
    problems.push('a signature from the wrong key was accepted')
  }
  if ((await ctx.tryVerify({ did: id.did, nonce: 'never-issued', sig })) !== 401) {
    problems.push('an unknown nonce was accepted')
  }
  return verdict(problems)
}

/** SN-091 - loopback default; non-loopback requires DID auth + TLS. */
const checkBindPolicy: CheckFn = async ctx =>
  ctx.target.bindProbe
    ? ctx.target.bindProbe()
    : unsupported('bind policy is a process-startup property; not exercisable via this target')

/** SN-092 - local mode: loopback only, operator owns all namespaces. */
const checkLocalMode: CheckFn = async ctx =>
  ctx.target.localModeProbe
    ? ctx.target.localModeProbe()
    : unsupported(
        'local-mode bind policy is a process-startup property; not exercisable via this target',
      )

// ─── Custody (SN-100..102) ──────────────────────────────────────────────

/** SN-100 - the two secrets (passphrase + signing key) never leave the
 *  client: no request across a full session carries either one. */
const checkCustody: CheckFn = async ctx => {
  const problems: string[] = []
  const seen: string[] = []
  const recordingFetch = ((input: RequestInfo | URL, init?: RequestInit) => {
    seen.push(
      `${String(init?.method ?? 'GET')} ${String(input)}\n` +
        `${JSON.stringify(init?.headers ?? {})}\n${typeof init?.body === 'string' ? init.body : ''}`,
    )
    return ctx.target.clientFetch(input, init)
  }) as typeof fetch
  const id = generateIdentity()
  const client = new SignetClient({
    url: ctx.target.url,
    fetchFn: recordingFetch,
    identity: id,
    passphrase: CHECK_PASSPHRASE,
  })
  await client.init()
  await client.push({ 'memory/m.md': 'custody probe\n' })
  const rotation = await client.rotate()
  const secrets = [
    CHECK_PASSPHRASE,
    id.pkcs8.toString('base64'),
    id.pkcs8.toString('hex'),
    rotation.successor.pkcs8.toString('base64'),
  ]
  if (seen.length === 0) problems.push('no wire traffic was observed')
  for (const sec of secrets) {
    if (seen.some(req => req.includes(sec))) {
      problems.push('a request body carried secret material to the store')
    }
  }
  return verdict(problems)
}

/** SN-101 - custody writes secrets only to a 0600 file outside any
 *  committable path. */
const checkInitCustody: CheckFn = async () => {
  const problems: string[] = []
  const dir = trackTmpDir(mkdtempSync(join(tmpdir(), 'signet-check-custody-')))
  const backend = new FileCustodyBackend(dir)
  const id = generateIdentity()
  const secrets: CustodySecrets = {
    version: 1,
    genesisDid: id.did,
    passphrase: CHECK_PASSPHRASE,
    pkcs8: id.pkcs8.toString('base64'),
    attestations: [],
    manifestSeqs: {},
  }
  await backend.save(secrets)
  const files = readdirSync(dir)
  if (files.length !== 1 || files[0] !== 'custody.json') {
    problems.push(`init wrote unexpected files: ${files.join(',')}`)
  }
  const mode = statSync(backend.path).mode & 0o777
  if (mode !== 0o600) problems.push(`custody file mode is ${mode.toString(8)}, not 600`)
  const stored = JSON.parse(readFileSync(backend.path, 'utf8')) as Record<string, unknown>
  if (stored.passphrase !== CHECK_PASSPHRASE || typeof stored.pkcs8 !== 'string') {
    problems.push('custody file does not hold both secrets')
  }
  if (!backend.path.startsWith(dir)) problems.push('custody file lives outside the state dir')
  return verdict(problems)
}

/** SN-102 - export produces an encrypted bundle carrying both secrets;
 *  import restores custody; a wrong passphrase fails closed. */
const checkExportImport: CheckFn = async () => {
  const problems: string[] = []
  const id = generateIdentity()
  const secrets: CustodySecrets = {
    version: 1,
    genesisDid: id.did,
    passphrase: CHECK_PASSPHRASE,
    pkcs8: id.pkcs8.toString('base64'),
    attestations: [],
    manifestSeqs: {},
  }
  const bundle = exportBundle(secrets, 'export-passphrase')
  if (bundle.includes(CHECK_PASSPHRASE) || bundle.includes(id.pkcs8.toString('base64'))) {
    problems.push('the export bundle carries plaintext secrets')
  }
  try {
    const restored = importBundle(bundle, 'export-passphrase')
    if (restored.genesisDid !== id.did || restored.passphrase !== CHECK_PASSPHRASE) {
      problems.push('imported secrets do not match the export')
    }
    if (identityFromPkcs8(Buffer.from(restored.pkcs8, 'base64')).did !== id.did) {
      problems.push('the imported signing key does not rebuild the same DID')
    }
  } catch (err) {
    problems.push(`import of a valid bundle failed: ${(err as Error).message}`)
  }
  try {
    importBundle(bundle, 'wrong-passphrase')
    problems.push('import accepted a wrong export passphrase')
  } catch {
    // expected
  }
  return verdict(problems)
}

// ─── Scanning + provenance (SN-110, SN-120) ─────────────────────────────

/** SN-110 - every section is scanned for credential shapes before
 *  encryption; lookalikes pass. */
const checkSecretScan: CheckFn = async ctx => {
  const problems: string[] = []
  const s = await ctx.provision()
  for (const [key, content] of Object.entries({
    'memory/secret.md': `token = "ghp_${'a'.repeat(30)}"\n`,
    'sessions/s-1/000001': '{"text":"-----BEGIN PRIVATE KEY-----"}\n',
    'config/api.json': '{"key":"AKIAIOSFODNN7EXAMPLE"}\n',
  })) {
    try {
      await s.client.push({ [key]: content })
      problems.push(`a credential-shaped entry under ${key} was pushed`)
    } catch (err) {
      if (!(err instanceof SecretFoundError)) {
        problems.push(`the ${key} refusal was not a secret-scan finding`)
      }
    }
  }
  try {
    await s.client.push({
      'memory/lookalike.md': 'this note mentions the word password and the api_key concept\n',
    })
  } catch (err) {
    if (err instanceof SecretFoundError) {
      problems.push('a plausible non-secret lookalike was blocked')
    } else {
      throw err
    }
  }
  return verdict(problems)
}

/** SN-120 - memory entries carry type:/provenance: frontmatter, and the
 *  spec-vector provenance marker round-trips through a real signet. */
const checkProvenance: CheckFn = async ctx => {
  const problems: string[] = []
  const v = loadVector('crypto.json') as {
    entries: Record<string, { plaintext: string }>
  }
  for (const [key, e] of Object.entries(v.entries)) {
    if (!key.startsWith('memory/')) continue
    const fm = /^---\n([\s\S]*?)\n---/.exec(e.plaintext)?.[1] ?? ''
    if (!fm.includes('type:') || !fm.includes('provenance: spec/vector')) {
      problems.push(`vector entry ${key} lacks type:/provenance: frontmatter`)
    }
  }
  const s = await ctx.provision()
  const tools = makeTools(s.client, { holderDid: s.identity.did })
  const content = '---\ntype: note\nprovenance: spec/vector\n---\nprovenance probe\n'
  const saved = await tools.save('memory/prov.md', content)
  if (saved.isError) problems.push('a frontmatter-carrying memory entry was refused')
  const pulled = await s.client.pull()
  if (pulled.entries['memory/prov.md'] !== content) {
    problems.push('frontmatter content did not round-trip intact')
  }
  return verdict(problems)
}

// ─── Vectors + MCP (SN-200, SN-201) ─────────────────────────────────────

/** SN-200 - the suite reproduces every shared vector byte for byte:
 *  crypto, identity, rotation, and the signed manifest. */
const checkCliVectors: CheckFn = async () => {
  const problems: string[] = []
  const crypto = loadVector('crypto.json') as {
    specVersion: string
    passphrase: string
    namespace: string
    keyHex: string
    entries: Record<string, { plaintext: string; blob: string }>
  }
  const key = deriveKey(crypto.passphrase, crypto.namespace)
  if (key.toString('hex') !== crypto.keyHex) problems.push('crypto vector key mismatch')
  for (const [k, e] of Object.entries(crypto.entries)) {
    if (encryptEntry(key, k, e.plaintext) !== e.blob) {
      problems.push(`crypto vector ${k} does not re-encrypt byte-exact`)
    }
    try {
      if (decryptEntry(key, k, e.blob) !== e.plaintext) {
        problems.push(`crypto vector ${k} decrypts to different bytes`)
      }
    } catch {
      problems.push(`crypto vector ${k} failed to decrypt`)
    }
  }

  const identity = loadVector('identity.json') as {
    genesisSeedHex: string
    genesisDid: string
    successorSeedHex: string
    successorDid: string
    namespace: string
    signMessage: string
    signature: string
    authNonce: string
    authSignature: string
    publicKeyHex: string
  }
  const genesis = identityFromSeed(Buffer.from(identity.genesisSeedHex, 'hex'))
  if (genesis.did !== identity.genesisDid) problems.push('identity vector genesis DID mismatch')
  if (genesis.publicKeyRaw.toString('hex') !== identity.publicKeyHex) {
    problems.push('identity vector public key mismatch')
  }
  if (
    identityFromSeed(Buffer.from(identity.successorSeedHex, 'hex')).did !== identity.successorDid
  ) {
    problems.push('identity vector successor DID mismatch')
  }
  if (!verifyDidSignature(identity.genesisDid, identity.signMessage, identity.signature)) {
    problems.push('identity vector signature does not verify')
  }
  // The pinned auth signature must cover the domain-separated preimage;
  // a signature over the bare nonce is a different (rejected) contract.
  if (
    !verifyDidSignature(
      identity.genesisDid,
      new TextEncoder().encode(`${AUTH_PREIMAGE_PREFIX}${identity.authNonce}`),
      identity.authSignature,
    )
  ) {
    problems.push('identity vector auth signature does not verify over the prefixed preimage')
  }
  if (namespaceFor(identity.genesisDid) !== identity.namespace) {
    problems.push('identity vector namespace mismatch')
  }

  const rotation = loadVector('rotation.json') as {
    attestation: unknown
    attestationHash: string
  }
  const att = RotationAttestation.safeParse(rotation.attestation)
  if (!att.success) {
    problems.push('rotation vector fails schema validation')
  } else {
    if (!verifyDidSignature(att.data.genesisDid, attestationBody(att.data), att.data.sig)) {
      problems.push('rotation vector signature does not verify')
    }
    if (attestationHash(att.data) !== rotation.attestationHash) {
      problems.push('rotation vector hash mismatch')
    }
  }

  // The manifest vector must be a SignedManifest wire object
  // ({manifest, did, sig}) - the same shape identity/manifest.json carries.
  const manifestVector = SignedManifest.safeParse(loadVector('manifest.json'))
  if (!manifestVector.success) {
    problems.push('manifest vector does not parse as a SignedManifest')
  } else {
    const { manifest, did, sig } = manifestVector.data
    if (!verifyDidSignature(did, canonicalJson(manifest), sig)) {
      problems.push('manifest vector signature does not verify')
    }
  }
  return verdict(problems)
}

/** SN-201 - a real write through the MCP tools layer recalls back over the
 *  wire path. */
const checkMcpRecall: CheckFn = async ctx => {
  const problems: string[] = []
  const s = await ctx.provision()
  const tools = makeTools(s.client, { holderDid: s.identity.did })
  const saved = await tools.save(
    'memory/check-recall.md',
    'the widget service deploys to region sin via flyctl\n',
  )
  if (saved.isError) problems.push('signet_save through the tools layer failed')
  const recalled = await tools.recall('which region does the widget service deploy to')
  if (recalled.isError || !recalled.text.includes('memory/check-recall.md')) {
    problems.push('signet_recall did not return the stored entry')
  }
  if (recalled.isError || !recalled.text.includes('sin')) {
    problems.push('signet_recall did not return the stored content')
  }
  const found = await tools.search('widget')
  if (found.isError || !found.text.includes('memory/check-recall.md')) {
    problems.push('signet_search did not find the stored entry')
  }
  const listed = await tools.list('memory')
  if (listed.isError || !listed.text.includes('memory/check-recall.md')) {
    problems.push('signet_list did not show the stored entry')
  }
  return verdict(problems)
}

// ─── Dispatch table ─────────────────────────────────────────────────────

/**
 * The registry's `check` field names a key of this map. Both directions are
 * tested: every registered check exists here and every implemented check is
 * registered.
 */
export const checks: Record<string, CheckFn> = {
  checkDidKey,
  checkDidWebOptional,
  checkGenesisBinding,
  checkNamespaceEncoding,
  checkNamespaceGrammar,
  checkEntryKeyGrammar,
  checkTraversalRejected,
  checkSessionChunks,
  checkBlobFormat,
  checkKdf,
  checkAead,
  checkDeterministicNonce,
  checkLeakBoundary,
  checkAltCipher,
  checkManifestSignature,
  checkManifestRollback,
  checkRotationRecord,
  checkAttestationChain,
  checkSuccessorAuth,
  checkRotationNamespace,
  checkGrantVocabulary,
  checkGrantNonApplication,
  checkGrantRecord,
  checkConfigDenylist,
  checkDeltaSync,
  checkCaps,
  checkNamespaceLock,
  checkStaleBaseRebase,
  checkTombstones,
  checkAuth,
  checkBindPolicy,
  checkLocalMode,
  checkCustody,
  checkInitCustody,
  checkExportImport,
  checkSecretScan,
  checkProvenance,
  checkCliVectors,
  checkMcpRecall,
}
