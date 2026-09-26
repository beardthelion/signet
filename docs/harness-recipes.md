# Harness recipes

Attach a signet to any MCP-capable agent. Every recipe does three things:

1. Point the harness at `signet mcp` (stdio). The server holds the custody
   secrets locally and speaks ciphertext to the store only.
2. Give it `SIGNET_URL`. Self-hosted default is `http://localhost:8080`; a
   remote store works over any HTTPS URL.
3. Optionally add a rules/instructions snippet so the agent uses the tools
   unprompted.

Custody must exist on each machine that decrypts: `signet init` on a fresh
identity, or `signet export` / `signet import` to clone an existing one.

## Devin CLI

```bash
devin mcp add signet -s user \
  -e SIGNET_URL=https://your-store.example \
  -- bun /path/to/signet/bin/signet.ts mcp
```

User rule: drop `rules/signet.md` (this repo) into `~/.devin/rules/`.

## Cursor (editor and cursor-agent)

Global `~/.cursor/mcp.json`, or `.cursor/mcp.json` in the project:

```json
{
  "mcpServers": {
    "signet": {
      "command": "bun",
      "args": ["/path/to/signet/bin/signet.ts", "mcp"],
      "env": { "SIGNET_URL": "https://your-store.example" }
    }
  }
}
```

cursor-agent additionally wants `cursor-agent mcp enable signet` (per
project) or `--approve-mcps` at launch. Project rule:
`.cursor/rules/signet.md`.

## Codex CLI

In `~/.codex/config.toml`:

```toml
[mcp_servers.signet]
command = "bun"
args = ["/path/to/signet/bin/signet.ts", "mcp"]

[mcp_servers.signet.env]
SIGNET_URL = "https://your-store.example"
```

Guidance: an `AGENTS.md` in the project root naming the `signet_*` tools and
when to use them.

## Claude Code

Project `.mcp.json` or `claude mcp add`:

```json
{
  "mcpServers": {
    "signet": {
      "command": "bun",
      "args": ["/path/to/signet/bin/signet.ts", "mcp"],
      "env": { "SIGNET_URL": "https://your-store.example" }
    }
  }
}
```

Guidance: a `CLAUDE.md` section naming the tools.

## opencode

`opencode.json` (project or `~/.config/opencode/`):

```json
{
  "mcp": {
    "signet": {
      "type": "local",
      "command": ["bun", "/path/to/signet/bin/signet.ts", "mcp"],
      "environment": { "SIGNET_URL": "https://your-store.example" }
    }
  }
}
```

## The rules snippet

`rules/signet.md` is deliberately narrow: recall before asking the user to
repeat themselves, save on durable preferences/decisions/corrections, never
save secrets or transient state. Broad "always remember everything" rules
pollute the passport with noise that gets recalled into later sessions.
