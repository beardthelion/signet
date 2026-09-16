# signet

Self-sovereign Signet: DID-rooted, end-to-end-encrypted, portable agent
state for people who code with AI.

A signet carries an agent's complete working state - memory, config, session
transcripts, permission grants, and identity - as ciphertext the store can
never read. Switching harnesses stops meaning starting over.

## What's here

- `spec/` - the Signet specification (`SPEC.md`), the conformance clause
  registry (`clauses.json`), the report schema, and shared test vectors
- `src/server/` - crypto-blind sync store (filesystem or S3 blob adapters)
- `src/client/` - signet client: crypto, DID identity, custody, secret scan
- `src/mcp/` - MCP adapter exposing the signet to existing harnesses
- `src/check/` - `signet-check` conformance checker
- `src/learn/` - learning capture: distills sessions into durable memory
- `bin/signet.ts` - the `signet` CLI (`init`, `push`, `pull`, `export`,
  `import`, `serve`, `mcp`)
- `bin/signet-check.ts` - the conformance checker CLI

## Quickstart

```bash
bun install

# start a local crypto-blind store (loopback, single-machine mode)
SIGNET_DATA_DIR=./data bun run bin/signet.ts serve

# create a signet (generates a did:key, custody stays local)
bun run bin/signet.ts init

# write and read state
bun run bin/signet.ts push ./state-dir
bun run bin/signet.ts pull ./state-dir

# expose the signet to MCP-capable harnesses
bun run bin/signet.ts mcp

# check an implementation against the spec
bun run bin/signet-check.ts --target http://localhost:8080
```

## Posture

- The server is crypto-blind: it stores ciphertext, entry keys, sizes, and
  hashes. It never sees plaintext, passphrases, or private keys.
- Identity is `did:key` (required) and `did:web` (optional). Key rotation uses
  signed successor attestations; the namespace stays bound to the genesis DID.
  Key loss is total loss.
- Self-hostable by default on your own hardware or a VPS. A hosted service is
  a later stage, not a dependency.
- Permission grants port as named records a consuming harness re-interprets
  and asks you to confirm. They are never silently applied.

## Development

```bash
bun test              # test suite
bun run type-check    # tsc --noEmit
bunx biome ci         # lint + format check
```

The companion consumer is the `beardthelion/fx` fork, which gains a signet
state layer under `src/core/signet/` and passes the same `spec/vectors/`.
