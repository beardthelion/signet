#!/usr/bin/env bun

/**
 * passport CLI — manage and sync an AI Passport: a DID-rooted, end-to-end
 * encrypted envelope of an agent's working state.
 *
 * Usage:
 *   passport init [--force]       create custody (genesis DID + passphrase) and publish
 *   passport push <dir>           encrypt + upload changed entries from <dir>
 *   passport pull <dir>           verify + download + decrypt into <dir>
 *   passport learn <file>         distill session content into memory/ entries (U7)
 *   passport export <file>        write an encrypted custody bundle (PS-102)
 *   passport import <file>        restore custody from a bundle [--force]
 *   passport rotate               rotate the signing key (PS-050)
 *   passport serve                run the store (lazy import)
 *   passport mcp                  run the stdio MCP server (lazy import)
 *
 * Env:
 *   PASSPORT_URL              default http://localhost:8080
 *   PASSPORT_HOME             state dir, default ~/.passport (custody lives here)
 *   PASSPORT_PASSPHRASE       encryption passphrase (falls back to custody)
 *   PASSPORT_SCAN             block (default) | warn | off — pre-encryption scan
 *   PASSPORT_EXPORT_PASSPHRASE  export-bundle passphrase (else prompted)
 *
 * Trust boundary: secrets (passphrase, Ed25519 key) only ever live in the
 * 0600 custody file under PASSPORT_HOME or in this process's memory. The
 * store receives ciphertext only (PS-100/PS-034). Key loss is total loss
 * (PS-103) — there is no recovery path, and init says so.
 */

import { chmodSync } from 'node:fs'
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { createInterface } from 'node:readline'
import { PassportClient } from '../src/client/client.ts'
import {
  type CustodySecrets,
  exportBundle,
  FileCustodyBackend,
  generatePassphrase,
  importBundle,
  loadCustody,
  saveCustody,
} from '../src/client/custody.ts'
import { generateIdentity, namespaceFor } from '../src/client/identity.ts'
import { clientFromCustody, persistManifestSeq } from '../src/client/session.ts'
import { captureSession } from '../src/learn/capture.ts'
import { DEFAULT_URL } from '../src/types/defaults.ts'
import { SECTIONS } from '../src/types/index.ts'

const SECTION_SET: ReadonlySet<string> = new Set(SECTIONS)

// ─── Local filesystem helpers ───────────────────────────────────────────

/** Yield every regular file under dir, as posix-style relative paths. */
async function* walk(dir: string, prefix = ''): AsyncGenerator<string> {
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const rel = prefix ? `${prefix}/${e.name}` : e.name
    if (e.isDirectory()) yield* walk(join(dir, e.name), rel)
    else if (e.isFile()) yield rel
  }
}

/**
 * Map a passport directory into entry key -> plaintext. Only files under a
 * spec section (memory/, config/, sessions/, grants/, identity/) become
 * entries; anything else is reported and skipped, not silently uploaded.
 */
async function readPassportDir(dir: string): Promise<Record<string, string>> {
  const wanted: string[] = []
  const skipped: string[] = []
  for await (const rel of walk(dir)) {
    if (!SECTION_SET.has(rel.split('/')[0]!)) skipped.push(rel)
    else wanted.push(rel)
  }
  const entries: Record<string, string> = {}
  const CHUNK = 8
  for (let i = 0; i < wanted.length; i += CHUNK) {
    const batch = wanted.slice(i, i + CHUNK)
    const contents = await Promise.all(
      batch.map(rel => readFile(join(dir, ...rel.split('/')), 'utf8')),
    )
    for (let j = 0; j < batch.length; j++) entries[batch[j]!] = contents[j]!
  }
  if (skipped.length) {
    console.error(`note: skipped non-section files: ${skipped.join(', ')}`)
  }
  return entries
}

// ─── Custody + client wiring ────────────────────────────────────────────

async function makeClient(): Promise<{ client: PassportClient; secrets: CustodySecrets }> {
  const wired = await clientFromCustody()
  if (!wired) {
    throw new Error('no custody found — run `passport init` or `passport import` first')
  }
  return wired
}

/** Persist the manifest seq the client just verified/published (PS-041). */
async function recordSeq(client: PassportClient, secrets: CustodySecrets): Promise<void> {
  await persistManifestSeq(client, secrets)
}

/** The export passphrase: env first, a hidden prompt second. */
async function exportPassphrase(confirm: boolean): Promise<string> {
  const env = process.env.PASSPORT_EXPORT_PASSPHRASE
  if (env) return env
  const first = await promptSecret('export passphrase: ')
  if (!confirm || !first) return first
  const second = await promptSecret('confirm export passphrase: ')
  if (first !== second) throw new Error('export passphrases do not match')
  return first
}

/** Read a secret from the TTY without echoing it. */
function promptSecret(question: string): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!process.stdin.isTTY) {
      reject(new Error('no TTY to prompt on — set PASSPORT_EXPORT_PASSPHRASE instead'))
      return
    }
    const rl = createInterface({ input: process.stdin, terminal: true })
    const hidden = rl as unknown as { _writeToOutput: (s: string) => void }
    process.stdout.write(question)
    hidden._writeToOutput = () => {}
    rl.question('', answer => {
      rl.close()
      process.stdout.write('\n')
      resolve(answer)
    })
  })
}

// ─── Subcommands ────────────────────────────────────────────────────────

async function cmdInit(force: boolean): Promise<void> {
  const backend = new FileCustodyBackend()
  const existing = await backend.load()
  if (existing && !force) {
    throw new Error(
      `custody already exists at ${backend.describe()} (genesis ${existing.genesisDid}). ` +
        'Refusing to overwrite — a new genesis DID is a new passport. Use --force only if you mean it.',
    )
  }
  const identity = generateIdentity()
  const passphrase = process.env.PASSPORT_PASSPHRASE ?? generatePassphrase()
  const secrets: CustodySecrets = {
    version: 1,
    genesisDid: identity.did,
    passphrase,
    pkcs8: identity.pkcs8.toString('base64'),
    attestations: [],
    manifestSeqs: {},
  }
  // Custody first: the secrets exist on disk before any network call, so a
  // failed publish can never strand an in-memory-only key.
  await backend.save(secrets)

  const client = new PassportClient({
    url: process.env.PASSPORT_URL ?? DEFAULT_URL,
    identity,
    passphrase,
  })
  try {
    await client.init()
    console.log(`published passport to ${process.env.PASSPORT_URL ?? DEFAULT_URL}`)
  } catch (err) {
    console.error(
      `warning: custody is saved but the initial publish failed: ${(err as Error).message}\n` +
        'A later `passport push` will publish it.',
    )
  }
  console.log(`genesis DID: ${identity.did}`)
  console.log(`namespace:   ${namespaceFor(identity.did)}`)
  console.log(`custody:     ${backend.describe()} (0600)`)
  if (!process.env.PASSPORT_PASSPHRASE) {
    console.log(`passphrase (shown once — back it up now):\n\n  ${passphrase}\n`)
  }
  console.log('Key loss is total loss (PS-103): there is no recovery path.')
}

async function cmdPush(dir: string): Promise<void> {
  const { client, secrets } = await makeClient()
  const entries = await readPassportDir(dir)
  const r = await client.push(entries)
  await recordSeq(client, secrets)
  console.log(
    `pushed ${r.namespace}: ${r.uploaded.length} uploaded, ${r.unchanged.length} unchanged -> manifest seq ${r.seq}`,
  )
}

async function cmdPull(dir: string): Promise<void> {
  const { client, secrets } = await makeClient()
  const r = await client.pull()
  for (const [key, plaintext] of Object.entries(r.entries)) {
    const dest = join(dir, ...key.split('/'))
    await mkdir(dirname(dest), { recursive: true })
    await writeFile(dest, plaintext)
  }
  await recordSeq(client, secrets)
  console.log(
    `pulled ${r.namespace} seq ${r.seq}: ${Object.keys(r.entries).length} entries -> ${dir}`,
  )
}

async function cmdLearn(file: string): Promise<void> {
  const { client, secrets } = await makeClient()
  const text = await readFile(file, 'utf8')
  const r = await captureSession(client, text, { harness: 'cli' })
  await recordSeq(client, secrets)
  console.log(
    `learned in ${client.namespace}: ${r.uploaded.length} captured, ` +
      `${r.unchanged.length} unchanged, ${r.blocked.length} blocked by the secret scan`,
  )
  for (const b of r.blocked) console.error(`  blocked ${b.key}: ${b.rules.join(', ')}`)
}

async function cmdExport(file: string): Promise<void> {
  const secrets = await loadCustody()
  if (!secrets) throw new Error('no custody found — nothing to export')
  const pass = await exportPassphrase(true)
  await writeFile(file, exportBundle(secrets, pass), { mode: 0o600 })
  chmodSync(file, 0o600)
  console.log(`wrote encrypted custody bundle to ${file}`)
}

async function cmdImport(file: string, force: boolean): Promise<void> {
  const backend = new FileCustodyBackend()
  if ((await backend.load()) && !force) {
    throw new Error(`custody already exists at ${backend.describe()} — use --force to replace it`)
  }
  const pass = await exportPassphrase(false)
  const secrets = importBundle(await readFile(file, 'utf8'), pass)
  await backend.save(secrets)
  console.log(`restored custody for ${secrets.genesisDid} -> ${backend.describe()} (0600)`)
}

async function cmdRotate(): Promise<void> {
  const { client, secrets } = await makeClient()
  const { attestation, successor, chain } = await client.rotate()
  // The successor becomes the active key; the extended chain is what later
  // /auth/verify calls present (PS-050/052).
  secrets.pkcs8 = successor.pkcs8.toString('base64')
  secrets.attestations = chain
  secrets.manifestSeqs[client.namespace] = client.manifestSeq
  await saveCustody(secrets)
  console.log(`rotated signing key: ${attestation.newDid} (rotation seq ${attestation.seq})`)
  console.log(`namespace unchanged: ${client.namespace}`)
}

// ─── Dispatch ───────────────────────────────────────────────────────────

const argv = process.argv.slice(2)
const force = argv.includes('--force')
const [cmd, a] = argv.filter(x => x !== '--force')

try {
  switch (cmd) {
    case 'init':
      await cmdInit(force)
      break
    case 'push':
      if (!a) usage()
      await cmdPush(a!)
      break
    case 'pull':
      if (!a) usage()
      await cmdPull(a!)
      break
    case 'learn':
      if (!a) usage()
      await cmdLearn(a!)
      break
    case 'export':
      if (!a) usage()
      await cmdExport(a!)
      break
    case 'import':
      if (!a) usage()
      await cmdImport(a!, force)
      break
    case 'rotate':
      await cmdRotate()
      break
    case 'serve':
      // Lazy: the store is a separate unit and may not exist in every build.
      await import('../src/server/index.ts')
      break
    case 'mcp': {
      // Lazy, and resolved through a URL so type-checking does not require
      // the MCP server to exist yet — it is invoked-only.
      const mcpUrl = new URL('../src/mcp/server.ts', import.meta.url).href
      await (await import(mcpUrl)).main()
      break
    }
    default:
      usage()
  }
} catch (err) {
  console.error(`error: ${(err as Error).message}`)
  process.exit(1)
}

function usage(): never {
  console.log(
    'usage:\n' +
      '  passport init [--force]    create custody (genesis DID + passphrase) and publish\n' +
      '  passport push <dir>        encrypt + upload changed entries from <dir>\n' +
      '  passport pull <dir>        verify + download + decrypt into <dir>\n' +
      '  passport learn <file>      distill session content into memory/ entries\n' +
      '  passport export <file>     write an encrypted custody bundle\n' +
      '  passport import <file>     restore custody from a bundle [--force]\n' +
      '  passport rotate            rotate the signing key\n' +
      '  passport serve             run the passport store\n' +
      '  passport mcp               run the stdio MCP server',
  )
  process.exit(1)
}
