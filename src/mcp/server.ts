/**
 * `passport mcp` — a stdio MCP server that exposes the holder's passport to
 * any MCP-capable harness (Claude Code, Cursor, opencode, SDK agents).
 *
 * It is a thin wrapper over PassportClient: the passphrase and the Ed25519
 * holder key live in THIS local process (loaded from the 0600 custody file,
 * PASSPORT_PASSPHRASE may override), so encryption/decryption/signing happen
 * here and the remote store still only ever sees ciphertext (PS-100/034).
 * Tool logic is in ./tools.ts; this file just binds it to the MCP protocol.
 *
 * Config (env): PASSPORT_URL (default http://localhost:8080),
 * PASSPORT_HOME (custody dir), PASSPORT_PASSPHRASE (optional override),
 * PASSPORT_SCAN (block|warn|off).
 *
 * IMPORTANT: stdout is the MCP protocol channel — never write logs there.
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
import { PASSPORT_GUIDE, SHORT_INSTRUCTIONS } from './guide.ts'
import { makeTools, type ToolResult } from './tools.ts'

const toMcp = (r: ToolResult) => ({
  content: [{ type: 'text' as const, text: r.text }],
  ...(r.isError ? { isError: true } : {}),
})

const stderr = (line: string) => process.stderr.write(`passport mcp: ${line}\n`)

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
    stderr('no custody found — run `passport init` or `passport import` first')
    process.exit(1)
  }
  const { client, secrets } = wired

  const tools = makeTools(client, {
    holderDid: secrets.genesisDid,
    // Persist the manifest seq after every write so the next process still
    // rejects a rolled-back manifest (PS-041 state lives in custody).
    onSync: () => persistManifestSeq(client, secrets),
  })

  const server = new McpServer(
    { name: 'passport', version: '0.1.0' },
    { instructions: SHORT_INSTRUCTIONS },
  )

  // The full usage protocol, fetchable by any MCP client.
  server.registerPrompt(
    'passport_guide',
    {
      title: 'How to use the AI Passport',
      description:
        'The passport-usage protocol: when to recall, what to save, how grants work as records, and how to wire the server without committing a secret. Read this once at the start of a session.',
    },
    () => ({
      messages: [{ role: 'user', content: { type: 'text', text: PASSPORT_GUIDE } }],
    }),
  )

  server.registerTool(
    'passport_save',
    {
      title: 'Save a passport entry',
      description:
        'Persist one entry to the encrypted passport, e.g. "memory/preferences.md". Scanned for credential shapes before encryption (PS-110). Cannot write grants/ (use passport_grant_record) or identity/ (client-managed), and config keys matching the PS-070 denylist are refused.',
      inputSchema: {
        key: z
          .string()
          .describe(
            'Entry key: <section>/<path>, section one of memory|config|sessions|grants|identity.',
          ),
        content: z.string().describe('The entry content (markdown, JSON, transcript chunk).'),
      },
    },
    async ({ key, content }) => toMcp(await tools.save(key, content)),
  )

  server.registerTool(
    'passport_recall',
    {
      title: 'Recall relevant entries',
      description:
        'Return the passport entries most relevant to a natural-language query, ranked. Call this before asking the user things a previous session may already know.',
      inputSchema: {
        query: z.string().describe('What you want to remember about.'),
        limit: z.number().int().min(1).max(20).optional().describe('Max results (default 5).'),
      },
    },
    async ({ query, limit }) => toMcp(await tools.recall(query, limit)),
  )

  server.registerTool(
    'passport_search',
    {
      title: 'Search passport entries',
      description: 'Literal keyword/substring search over entry keys and content.',
      inputSchema: {
        query: z.string().describe('Substring to search for.'),
      },
    },
    async ({ query }) => toMcp(await tools.search(query)),
  )

  server.registerTool(
    'passport_list',
    {
      title: 'List passport entries',
      description: 'List the entry keys stored in the passport (no content downloaded).',
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
    'passport_delete',
    {
      title: 'Delete a passport entry',
      description:
        'Remove one entry. Destructive: the full entry key is required and identity/ or grants/ keys are refused.',
      inputSchema: {
        key: z.string().describe('The exact entry key to delete, e.g. "memory/old-note.md".'),
      },
    },
    async ({ key }) => toMcp(await tools.delete(key)),
  )

  server.registerTool(
    'passport_config_get',
    {
      title: 'Read passport config',
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
    'passport_config_set',
    {
      title: 'Write passport config',
      description:
        'Write config/<key>. Permission-affecting keys (permission, grant, allow, deny, trust, sandbox, exec, approve, policy) are refused per PS-070 — record those as grants instead.',
      inputSchema: {
        key: z.string().describe('Config key relative to config/, e.g. "settings.json".'),
        value: z.string().describe('The entry content.'),
      },
    },
    async ({ key, value }) => toMcp(await tools.configSet(key, value)),
  )

  server.registerTool(
    'passport_grant_list',
    {
      title: 'List recorded grants',
      description:
        'Enumerate the grants recorded under grants/. Read-only: grants are records a consuming harness must re-confirm with the holder before honoring (PS-061); nothing here applies them.',
    },
    async () => toMcp(await tools.grantList()),
  )

  server.registerTool(
    'passport_grant_record',
    {
      title: 'Record a confirmed grant',
      description:
        'Record a holder-confirmed permission grant under grants/<id>.json (PS-060/062). The holder must have actually confirmed; pass confirmed: true to attest that. Recording is all this does — no grant is ever auto-applied.',
      inputSchema: {
        id: z.string().describe('Grant id; becomes grants/<id>.json.'),
        action: z.enum(GRANT_ACTIONS).describe('Action class (PS-060).'),
        scope: z.string().describe('Free-form pattern the consuming harness interprets.'),
        constraints: z
          .record(z.string(), z.unknown())
          .optional()
          .describe('Free-form matcher fields (PS-060).'),
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

  const transport = new StdioServerTransport()
  await server.connect(transport)
  stderr(`ready • url=${process.env.PASSPORT_URL ?? DEFAULT_URL} • namespace=${client.namespace}`)
}
