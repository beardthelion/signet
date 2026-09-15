# passport-suite

Self-sovereign AI Passport: DID-rooted, end-to-end-encrypted, portable agent
state for people who code with AI.

A passport carries an agent's complete working state - memory, config, session
transcripts, permission grants, and identity - as ciphertext the store can
never read. Switching harnesses stops meaning starting over.

## What's here

- `spec/` - the AI Passport specification (`SPEC.md`), the conformance clause
  registry (`clauses.json`), the report schema, and shared test vectors
- `src/server/` - crypto-blind sync store (filesystem or S3 blob adapters)
- `src/client/` - passport client: crypto, DID identity, custody, secret scan
- `src/mcp/` - MCP adapter exposing the passport to existing harnesses
- `src/check/` - `passport-check` conformance checker
- `src/learn/` - learning capture: distills sessions into durable memory
- `bin/passport.ts` - the `passport` CLI (`init`, `push`, `pull`, `export`,
  `import`, `serve`, `mcp`)
- `bin/passport-check.ts` - the conformance checker CLI

## Quickstart

```bash
bun install

# start a local crypto-blind store (loopback, single-machine mode)
PASSPORT_DATA_DIR=./data bun run bin/passport.ts serve

# create a passport (generates a did:key, custody stays local)
bun run bin/passport.ts init

# write and read state
bun run bin/passport.ts push ./state-dir
bun run bin/passport.ts pull ./state-dir

# expose the passport to MCP-capable harnesses
bun run bin/passport.ts mcp

# check an implementation against the spec
bun run bin/passport-check.ts --target http://localhost:8080
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

The companion consumer is the `beardthelion/fx` fork, which gains a passport
state layer under `src/core/passport/` and passes the same `spec/vectors/`.
