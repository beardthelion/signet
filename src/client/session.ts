/**
 * Custody -> PassportClient wiring, shared by the CLI (bin/passport.ts) and
 * the MCP adapter (src/mcp/server.ts). Both build the same client from the
 * same inputs: the custody-held secrets, PASSPORT_URL, the
 * PASSPORT_PASSPHRASE override, the PASSPORT_SCAN policy, and the stored
 * PS-041 manifest seq. Keeping the wiring here means the two entrypoints
 * cannot drift on which env wins or how the seq is restored.
 *
 * Returns null only for "no custody on this machine" so callers keep their
 * own failure idiom (the CLI throws, the MCP server exits before the
 * transport exists). Anything else that fails — unreadable custody, an
 * invalid PASSPORT_SCAN — throws.
 */

import { DEFAULT_URL } from '../types/defaults.ts'
import { PassportClient } from './client.ts'
import { type CustodySecrets, loadCustody, saveCustody } from './custody.ts'
import { identityFromPkcs8, namespaceFor } from './identity.ts'
import { type Finding, scanModeFromEnv } from './secretscan.ts'

export type ClientFromCustodyOptions = {
  /**
   * Scan findings in `warn` mode. Without one the client warns on stderr via
   * console.warn; the MCP server passes a callback that stays off stdout
   * (the protocol channel).
   */
  onScanWarning?: (findings: Finding[]) => void
}

export async function clientFromCustody(
  opts: ClientFromCustodyOptions = {},
): Promise<{ client: PassportClient; secrets: CustodySecrets } | null> {
  const secrets = await loadCustody()
  if (!secrets) return null
  const identity = identityFromPkcs8(Buffer.from(secrets.pkcs8, 'base64'))
  const client = new PassportClient({
    url: process.env.PASSPORT_URL ?? DEFAULT_URL,
    identity,
    genesisDid: secrets.genesisDid,
    attestations: secrets.attestations,
    // PASSPORT_PASSPHRASE overrides; otherwise the custody-held passphrase.
    passphrase: process.env.PASSPORT_PASSPHRASE ?? secrets.passphrase,
    scanMode: scanModeFromEnv(),
    lastSeq: secrets.manifestSeqs[namespaceFor(secrets.genesisDid)] ?? 0,
    onScanWarning: opts.onScanWarning,
  })
  return { client, secrets }
}

/** Persist the manifest seq the client just verified/published (PS-041). */
export async function persistManifestSeq(
  client: PassportClient,
  secrets: CustodySecrets,
): Promise<void> {
  secrets.manifestSeqs[client.namespace] = client.manifestSeq
  await saveCustody(secrets)
}
