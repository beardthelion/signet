# Security

## Supported versions

`main` only. There are no releases; the spec and the conformance checker are the compatibility contract.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository (Security tab -> "Report a vulnerability"). Do not open a public issue for security reports.

## Scope

In scope:

- The crypto-blind sync server (`src/server/`): anything that lets it see plaintext, passphrases, or derived keys, or that breaks namespace authorization, quota, or anti-rollback guarantees.
- The client and custody path (`src/client/`, `bin/`): encryption, key derivation, secret scanning, custody export/import, signed rotation.
- The wire contract and spec (`spec/`, `src/check/`): protocol weaknesses a conformant implementation would inherit.
- The MCP adapter (`src/mcp/`): anything that leaks data across scopes or corrupts the protocol stream.

Out of scope:

- The maintainer's personal deployment (a private instance on private infrastructure). Report protocol bugs, not that host.
- Attacks requiring the victim's passphrase or DID private key; both are client-held secrets the server never sees.
- Findings that only affect a modified deployment.
