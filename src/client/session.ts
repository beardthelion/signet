/**
 * Custody -> SignetClient wiring, shared by the CLI (bin/signet.ts) and
 * the MCP adapter (src/mcp/server.ts). Both build the same client from the
 * same inputs: the custody-held secrets, SIGNET_URL, the
 * SIGNET_PASSPHRASE override, the SIGNET_SCAN policy, and the stored
 * SN-041 manifest seq. Keeping the wiring here means the two entrypoints
 * cannot drift on which env wins or how the seq is restored.
 *
 * Returns null only for "no custody on this machine" so callers keep their
 * own failure idiom (the CLI throws, the MCP server exits before the
 * transport exists). Anything else that fails - unreadable custody, an
 * invalid SIGNET_SCAN - throws.
 */

import { DEFAULT_URL } from '../types/defaults.ts'
import { SignetClient } from './client.ts'
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
): Promise<{ client: SignetClient; secrets: CustodySecrets } | null> {
  const secrets = await loadCustody()
  if (!secrets) return null
  const identity = identityFromPkcs8(Buffer.from(secrets.pkcs8, 'base64'))
  // SIGNET_PASSPHRASE overrides; otherwise the custody-held passphrase.
  // A blank/whitespace value is treated as unset: '' is not a passphrase,
  // and honoring it would derive keys from nothing.
  const envPassphrase = process.env.SIGNET_PASSPHRASE
  const passphrase =
    envPassphrase !== undefined && envPassphrase.trim() !== '' ? envPassphrase : secrets.passphrase
  const client = new SignetClient({
    url: process.env.SIGNET_URL ?? DEFAULT_URL,
    identity,
    genesisDid: secrets.genesisDid,
    attestations: secrets.attestations,
    passphrase,
    scanMode: scanModeFromEnv(),
    lastSeq: secrets.manifestSeqs[namespaceFor(secrets.genesisDid)] ?? 0,
    onScanWarning: opts.onScanWarning,
  })
  return { client, secrets }
}

/** Persist the manifest seq the client just verified/published (SN-041). */
export async function persistManifestSeq(
  client: SignetClient,
  secrets: CustodySecrets,
): Promise<void> {
  secrets.manifestSeqs[client.namespace] = client.manifestSeq
  await saveCustody(secrets)
}
