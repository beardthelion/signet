/**
 * `signet mcp` - a stdio MCP server that exposes the holder's signet to
 * any MCP-capable harness (Claude Code, Cursor, opencode, SDK agents).
 *
 * It is a thin wrapper over SignetClient: the passphrase and the Ed25519
 * holder key live in THIS local process (loaded from the 0600 custody file,
 * SIGNET_PASSPHRASE may override), so encryption/decryption/signing happen
 * here and the remote store still only ever sees ciphertext (SN-100/034).
 * Tool logic is in ./tools.ts; this file just binds it to the MCP protocol.
 *
 * Config (env): SIGNET_URL (default http://localhost:8080),
 * SIGNET_HOME (custody dir), SIGNET_PASSPHRASE (optional override),
 * SIGNET_SCAN (block|warn|off).
 *
 * IMPORTANT: stdout is the MCP protocol channel - never write logs there.
 * All diagnostics go to stderr, and nothing here runs on import: the CLI
 * calls main() explicitly so a misconfigured process exits before the
 * transport exists and never half-serves.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import { clientFromCustody, persistManifestSeq } from '../client/session.ts'
import { DEFAULT_URL } from '../types/defaults.ts'
import { GRANT_ACTIONS, SECTIONS } from '../types/index.ts'
import { SHORT_INSTRUCTIONS, SIGNET_GUIDE } from './guide.ts'
import { makeTools, type ToolResult } from './tools.ts'

const toMcp = (r: ToolResult) => ({
  content: [{ type: 'text' as const, text: r.text }],
  ...(r.isError ? { isError: true } : {}),
})

const stderr = (line: string) => process.stderr.write(`signet mcp: ${line}\n`)

/**
 * Load custody, build the client, bind the tools, connect the transport.
 * Missing custody is fatal: without the two secrets nothing can be decrypted
 * or signed, and a server that starts anyway would only fail on every call.
 */
export async function main(): Promise<void> {
  const wired = await clientFromCustody({
    // Scan warnings in warn mode must not hit stdout; this keeps them on the
    // diagnostics channel.
    onScanWarning: findings =>
      stderr(`${findings.length} potential secret(s) in pushed entries (scan mode warn)`),
  })
  if (!wired) {
    stderr('no custody found - run `signet init` or `signet import` first')
    process.exit(1)
  }
  const { client, secrets } = wired

  const tools = makeTools(client, {
    holderDid: secrets.genesisDid,
    // Persist the manifest seq after every write so the next process still
    // rejects a rolled-back manifest (SN-041 state lives in custody).
    onSync: () => persistManifestSeq(client, secrets),
  })

  const server = new McpServer(
    { name: 'signet', version: '0.1.0' },
    { instructions: SHORT_INSTRUCTIONS },
  )

  // The full usage protocol, fetchable by any MCP client.
  server.registerPrompt(
    'signet_guide',
    {
      title: 'How to use the Signet',
      description:
        'The signet-usage protocol: when to recall, what to save, how grants work as records, and how to wire the server without committing a secret. Read this once at the start of a session.',
    },
    () => ({
      messages: [{ role: 'user', content: { type: 'text', text: SIGNET_GUIDE } }],
    }),
  )

  server.registerTool(
    'signet_save',
    {
      title: 'Save a signet entry',
      description:
        'Persist one entry to the encrypted signet, e.g. "memory/preferences.md". Scanned for credential shapes before encryption (SN-110). Cannot write grants/ (use signet_grant_record) or identity/ (client-managed), and config keys matching the SN-070 denylist are refused.',
      inputSchema: {
        key: z
          .string()
          .describe(
            'Entry key: <section>/<path>, section one of memory|config|sessions (grants/ is written only by signet_grant_record; identity/ is client-managed).',
          ),
        content: z.string().describe('The entry content (markdown, JSON, transcript chunk).'),
      },
    },
    async ({ key, content }) => toMcp(await tools.save(key, content)),
  )

  server.registerTool(
    'signet_recall',
    {
      title: 'Recall relevant entries',
      description:
        'Return the signet entries most relevant to a natural-language query, ranked. Call this before asking the user things a previous session may already know.',
      inputSchema: {
        query: z.string().describe('What you want to remember about.'),
        limit: z.number().int().min(1).max(20).optional().describe('Max results (default 5).'),
      },
    },
    async ({ query, limit }) => toMcp(await tools.recall(query, limit)),
  )

  server.registerTool(
    'signet_get',
    {
      title: 'Fetch a signet entry',
      description:
        'Return the decrypted content of one entry by exact key (e.g. "memory/preferences.md"). Use when you already know the key; use signet_recall or signet_search to find entries.',
      inputSchema: {
        key: z.string().describe('The exact entry key to fetch.'),
      },
    },
    async ({ key }) => toMcp(await tools.get(key)),
  )

  server.registerTool(
    'signet_search',
    {
      title: 'Search signet entries',
      description: 'Literal keyword/substring search over entry keys and content.',
      inputSchema: {
        query: z.string().describe('Substring to search for.'),
      },
    },
    async ({ query }) => toMcp(await tools.search(query)),
  )

  server.registerTool(
    'signet_list',
    {
      title: 'List signet entries',
      description: 'List the entry keys stored in the signet (no content downloaded).',
      inputSchema: {
        section: z
          .enum(SECTIONS)
          .optional()
          .describe('Narrow to one section (memory|config|sessions|grants|identity).'),
      },
    },
    async ({ section }) => toMcp(await tools.list(section)),
  )

  server.registerTool(
    'signet_delete',
    {
      title: 'Delete a signet entry',
      description:
        'Remove one entry. Destructive: the full entry key is required and identity/ or grants/ keys are refused.',
      inputSchema: {
        key: z.string().describe('The exact entry key to delete, e.g. "memory/old-note.md".'),
      },
    },
    async ({ key }) => toMcp(await tools.delete(key)),
  )

  server.registerTool(
    'signet_config_get',
    {
      title: 'Read signet config',
      description: 'Read one config/<key> entry, or every entry under config/ when key is omitted.',
      inputSchema: {
        key: z
          .string()
          .optional()
          .describe('Config key relative to config/, e.g. "settings.json".'),
      },
    },
    async ({ key }) => toMcp(await tools.configGet(key)),
  )

  server.registerTool(
    'signet_config_set',
    {
      title: 'Write signet config',
      description:
        'Write config/<key>. Permission-affecting keys (permission, grant, allow, deny, trust, sandbox, exec, approve, policy) are refused per SN-070 - record those as grants instead.',
      inputSchema: {
        key: z.string().describe('Config key relative to config/, e.g. "settings.json".'),
        value: z.string().describe('The entry content.'),
      },
    },
    async ({ key, value }) => toMcp(await tools.configSet(key, value)),
  )

  server.registerTool(
    'signet_grant_list',
    {
      title: 'List recorded grants',
      description:
        'Enumerate the grants recorded under grants/. Read-only: grants are records a consuming harness must re-confirm with the holder before honoring (SN-061); nothing here applies them.',
    },
    async () => toMcp(await tools.grantList()),
  )

  server.registerTool(
    'signet_grant_record',
    {
      title: 'Record a confirmed grant',
      description:
        'Record a holder-confirmed permission grant under grants/<id>.json (SN-060/062). The holder must have actually confirmed; pass confirmed: true to attest that. Recording is all this does - no grant is ever auto-applied.',
      inputSchema: {
        id: z.string().describe('Grant id; becomes grants/<id>.json.'),
        action: z.enum(GRANT_ACTIONS).describe('Action class (SN-060).'),
        scope: z.string().describe('Free-form pattern the consuming harness interprets.'),
        constraints: z
          .record(z.string(), z.unknown())
          .optional()
          .describe('Free-form matcher fields (SN-060).'),
        granted_by: z.string().optional().describe('Who granted it (default: the holder DID).'),
        granted_at: z.string().optional().describe('ISO timestamp (default: now).'),
        expires_at: z.string().optional().describe('Optional ISO expiry.'),
        confirmed: z
          .literal(true)
          .describe('Must be true: attests the holder explicitly confirmed this grant.'),
      },
    },
    async args => toMcp(await tools.grantRecord(args)),
  )

  server.registerTool(
    'signet_session_push',
    {
      title: 'Mirror a session into the signet',
      description:
        'Write a session as the chunked v2 mirror (SN-023): a JSON index plus per-file chunk entries under sessions/<id>/. The files map is the complete desired member set; only events.jsonl, session.json, checkpoint.json, display.json, authority.json, usage-v2.json, and commit.<hex>.json members are accepted. Content is credential-scanned before encryption (SN-110).',
      inputSchema: {
        session_id: z
          .string()
          .describe('Session id: letters, digits, ".", "_", "-", starting with a letter or digit.'),
        files: z
          .record(z.string(), z.string())
          .describe('Map of member filename to content; the complete desired member set.'),
      },
    },
    async ({ session_id, files }) => toMcp(await tools.sessionPush(session_id, files)),
  )

  server.registerTool(
    'signet_session_pull',
    {
      title: 'Reassemble a mirrored session',
      description:
        'Read back a session mirrored with signet_session_push: verifies the index and every chunk (fail-closed on a torn mirror, SN-023), then returns each member file bounded in size.',
      inputSchema: {
        session_id: z.string().describe('The session id previously mirrored.'),
      },
    },
    async ({ session_id }) => toMcp(await tools.sessionPull(session_id)),
  )

  const transport = new StdioServerTransport()
  await server.connect(transport)
  stderr(`ready • url=${process.env.SIGNET_URL ?? DEFAULT_URL} • namespace=${client.namespace}`)
}
