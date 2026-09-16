/**
 * The signet-usage guidance the MCP server exposes: a `signet_guide`
 * prompt carrying the full text, and a short form in the server
 * `instructions` every MCP client sees.
 *
 * The text below is the source of truth (there is no sibling SKILL.md in this
 * repo to load). Its sharpest rule is about the config block, not the tools:
 * SN-101 forbids writing secrets into an MCP config block, and harness config
 * files get committed to dotfile repos constantly. So the guide shows the
 * block with only non-secret env, and says in plain terms that the passphrase
 * belongs in custody or in the harness's own secret mechanism - never as a
 * literal in the block.
 */

/**
 * Full guide, served as the `signet_guide` prompt. Covers the tools, the
 * grant model, and how to wire the server into a harness without committing a
 * secret.
 */
export const SIGNET_GUIDE = `# Signet

You have access to a Signet: a DID-rooted, end-to-end-encrypted envelope
of your working state that survives across harnesses and machines. The store
only ever holds ciphertext; decryption happens locally, inside this server.

## Tools

- signet_save(key, content) - write one entry. Keys are <section>/<path>
  with section one of memory, config, sessions, grants, identity. Plaintext
  is scanned for credential shapes before encryption; a save that looks like
  it carries a secret is refused (SN-110).
- signet_recall(query, limit?) - ranked retrieval: the entries most
  relevant to a natural-language query. Call this at the start of a task
  before asking the user things they may have already told a previous session.
- signet_search(query) - literal substring search over keys and content.
- signet_list(section?) - entry keys only, no content.
- signet_delete(key) - remove one entry. Destructive and explicit: the full
  entry key is required.
- signet_config_get(key?) - read config state, one key or all of config/.
- signet_config_set(key, value) - write config/<key>. Keys that look
  permission-affecting (permission, grant, allow, deny, trust, sandbox, exec,
  approve, policy) are refused (SN-070) - that state does not belong in
  config.
- signet_grant_list() - enumerate recorded grants. Read-only.
- signet_grant_record(...) - record a holder-confirmed grant. The write
  requires confirmed: true, and the holder must actually have confirmed.

## Grants are records, not permissions

A grant in the signet is a named record of something the holder agreed to:
{id, action, scope, constraints, granted_by, granted_at, expires_at?}, with
action one of fs.read, fs.write, shell.exec, net.fetch, agent.spawn (SN-060).
Grants are NEVER silently honored across harness boundaries (SN-061): when
you read one that maps to something you want to do, show it to the user and
ask before treating it as permission. There is no tool that applies a grant,
and no stored grant is proof you may act.

## Configuring this server in a harness

Register it as a stdio MCP server, e.g.:

{
  "mcpServers": {
    "signet": {
      "command": "bun",
      "args": ["run", "/absolute/path/to/signet/bin/signet.ts", "mcp"],
      "env": { "SIGNET_URL": "http://localhost:8080" }
    }
  }
}

The passphrase and the holder signing key come from local custody
(~/.signet/, written 0600 by \`signet init\`), so a typical block needs no
secret material at all. NEVER write a passphrase value into a committable
config block (SN-101). If a deployment must supply SIGNET_PASSPHRASE or
SIGNET_HOME through env, use your harness's secret mechanism (a secrets
store, an env-var reference the harness expands at launch, an untracked local
file) rather than a literal in the block. Key loss is total loss (SN-103):
there is no recovery path, and nothing on the server can help.

## Working discipline

- Recall first, then save what is durable: preferences, decisions, conventions,
  learned feedback. Skip transient context and anything obvious from the repo.
- Search before adding to avoid duplicates; delete what is wrong or stale.
- Session transcripts live under sessions/<id>/<seq>; write them in order.
`

/** One-paragraph version embedded in the MCP server `instructions`. */
export const SHORT_INSTRUCTIONS =
  'You have access to a Signet: end-to-end-encrypted working state that ' +
  'survives across harnesses. At the start of a task, call signet_recall to ' +
  'retrieve what prior sessions already knew. Persist durable facts with ' +
  'signet_save; skip transient context and never save secrets. Config keys ' +
  'that look permission-affecting are refused (SN-070): permission state lives ' +
  'in grants/, where signet_grant_record writes only holder-confirmed ' +
  'grants and no tool ever applies one. Call the "signet_guide" prompt for ' +
  'the full protocol.'
