# AI Passport Specification

**Spec version:** `passport-spec/0.1`
**Status:** Draft
**Steward:** passport-suite

An AI Passport is a portable, DID-rooted, end-to-end-encrypted envelope of an
agent's complete working state. A conformant store holds only ciphertext and a
small, bounded set of plaintext metadata. A conformant harness reads and writes
the passport as if it were local state.

This document is the normative contract. Implementations include the reference
store, client, and MCP adapter in this repository, plus any third-party
conformant implementation checked by `passport-check`.

Keywords MUST, MUST NOT, SHOULD, and MAY are used per RFC 2119. Clause
identifiers `PS-###` are stable conformance hooks; `spec/clauses.json` is the
machine-readable registry of the same clauses.

## 1. Scope

The passport carries **full agent state** for a single holder:

- `memory/` — durable learned knowledge and notes
- `config/` — harness settings and preferences
- `sessions/` — session transcripts and checkpoints
- `grants/` — recorded permission grants
- `identity/` — DID document material and rotation attestations

Out of scope for this version: execution isolation of agents, sharing or ACLs
between holders, arbitrary file storage, hosted-service operation. Key loss is
total loss by design; there is no recovery path in this version.

## 2. Identity

### 2.1 DID methods

- **PS-001.** `did:key` (Ed25519, multibase `z`-prefixed base58btc of
  `0xed01 || pubkey`) is REQUIRED for every passport.
- **PS-002.** `did:web` is OPTIONAL and MAY serve as a holder's stable public
  alias. `did:web` MUST NOT be used as a namespace root.
- No other DID method is defined by this spec. Implementations MUST reject
  namespaces derived from other methods.

### 2.2 Genesis DID and namespace binding

- **PS-010.** Every passport has exactly one **genesis DID**: the `did:key`
  created at `passport init`. The passport's namespace is derived from the
  genesis DID and never changes.
- **PS-011.** The namespace is `passport:` followed by the **encoded genesis
  DID**: the DID string with every `:` replaced by `_`. Example:
  `did:key:z6Mk...` encodes to `passport:did_key_z6Mk...`. The encoding is
  injective (no colons survive) so one DID cannot alias another's namespace.
- **PS-012.** Encoded namespaces MUST match
  `^passport:did_[a-z]+_[A-Za-z0-9._-]{1,240}$`. Anything else is rejected
  before storage access.

### 2.3 Rotation

- **PS-050.** A rotation replaces the active signing key while the passport
  namespace stays bound to the genesis DID. A rotation is recorded as an entry
  `identity/rotations/<seq>.json` in the passport AND presented to the server
  during authentication.
- **PS-051.** A rotation attestation is a JSON document
  `{genesisDid, newDid, seq, prevHash, sig}` where `seq` is a strictly
  increasing counter starting at 1, `prevHash` is the SHA-256 of the previous
  attestation's canonical JSON (`"0"*64` for `seq=1`), and `sig` is the
  genesis-or-predecessor key's Ed25519 signature over the canonical JSON of
  `{genesisDid, newDid, seq, prevHash}`. The new key's signature is NOT
  required: control of the old key is the whole authorization.
- **PS-052.** A server MUST authorize a request key only if it is the genesis
  DID key, or it terminates a chain of valid attestations rooted at the genesis
  DID with correct `seq` ordering and `prevHash` linkage. Forged, unsigned,
  misordered, or mis-linked attestations MUST be rejected.
- **PS-053.** After rotation the namespace, entry data, and caps remain bound
  to the genesis DID. A successor key MUST NOT be able to open a namespace
  under its own DID.

### 2.4 Key custody

- **PS-100.** Two secrets govern a passport: the **encryption secret**
  (passphrase) and the **holder signing key** (Ed25519 private key). Both live
  client-side only. A store MUST NEVER receive either.
- **PS-101.** `passport init` MUST write secret material only to the OS keychain
  or a `0600` file outside any committable path. It MUST NOT write secrets into
  workspace files, `.fx.json`, MCP config blocks, or the store.
- **PS-102.** `passport export` MUST produce an encrypted bundle containing both
  secrets; `passport import` restores custody on a second machine. The bundle is
  itself passphrase-encrypted.
- **PS-103.** Key loss is total loss. Implementations MUST document this and
  MUST NOT imply recovery.

## 3. Envelope

### 3.1 Entry keys

- **PS-020.** An entry key is a POSIX-ish relative path
  `<section>/<path>` where `<section>` is one of `memory`, `config`,
  `sessions`, `grants`, `identity`, and each path segment matches
  `[A-Za-z0-9][A-Za-z0-9._-]*`.
- **PS-021.** Keys MUST NOT contain `..`, `//`, a leading or trailing `/`,
  backslash, or NUL. Both client and server MUST reject such keys before any
  storage access.
- **PS-022.** Session transcripts are chunked as `sessions/<id>/<seq>` where
  `<id>` is a valid segment and `<seq>` is a zero-padded sequence counter.
  Chunks keep each entry under the entry cap while preserving transcript
  order.

### 3.2 Encryption

- **PS-030.** Every entry is encrypted client-side before storage or transit.
  The wire/storage blob layout is:

  ```
  [ 0x01 version ][ 12-byte nonce ][ 16-byte GCM tag ][ ciphertext ]
  ```

  then base64. The version byte is the migration hook; `0x01` is the only
  defined version.
- **PS-031.** The encryption key is
  `scrypt(passphrase, salt = sha256("passport-suite:" + namespace), 32, {N: 2^15, r: 8, p: 1})`.
  The namespace-bound salt makes derivation deterministic and stateless.
- **PS-032.** The cipher is AES-256-GCM. The **entry key is the AEAD AAD**, so
  a blob is bound to its key and cannot be moved under another.
- **PS-033.** The nonce is deterministic: `HMAC-SHA256(encKey, entryKey || 0x00
  || plaintext)[0:12]`. Identical plaintext produces identical ciphertext,
  which is what enables delta sync by ciphertext hash. The accepted leak is
  "are two entries byte-identical." Implementations MUST NOT substitute random
  nonces without a spec revision.
- **PS-034.** A conformant store sees **only**: entry keys, per-entry
  ciphertext, per-entry size/hash/timestamp, the integrity manifest, rotation
  attestations, and namespace ids. It MUST NOT see plaintext, passphrases, or
  derived keys. This is the documented metadata leak boundary; nothing beyond
  it is permitted to leak.
- **PS-035.** Alternate AEAD for constrained platforms (e.g. Zig `std.crypto`):
  XChaCha20-Poly1305 with a 24-byte deterministic nonce under the same
  HMAC-derived scheme is a spec-sanctioned second cipher, signaled by version
  byte `0x02`. Implementations MUST NOT invent a third.

### 3.3 Integrity manifest

- **PS-040.** Each passport carries `identity/manifest.json`, a holder-signed
  document `{seq, specVersion, genesisDid, entries}` where `entries` maps each
  entry key to the `sha256:` hex of its ciphertext blob. `seq` increments on
  every push.
- **PS-041.** A consumer MUST verify the manifest signature against the current
  authorized key (genesis or a valid rotation successor) and MUST require
  `seq` strictly greater than the last verified `seq`. A tampered, unsigned, or
  rolled-back manifest MUST fail closed.

## 4. Grants and config

### 4.1 Grant vocabulary

- **PS-060.** A grant is `{id, action, scope, constraints, granted_by,
  granted_at, expires_at?}` recorded under `grants/`. `action` is one of the
  defined action classes: `fs.read`, `fs.write`, `shell.exec`, `net.fetch`,
  `agent.spawn`. `scope` and `constraints` are free-form pattern/matcher
  fields a consuming harness interprets under its own action model.
- **PS-061.** Grants are **never silently honored across harness boundaries.**
  A consuming harness maps a stored grant to its own action model and asks the
  holder to confirm before honoring it. There is no automatic grant-application
  path.
- **PS-062.** `passport_grant_record` is the only write path for grants and
  records only holder-confirmed grants.

### 4.2 Config denylist

- **PS-070.** Permission-affecting keys MUST NOT be stored under `config/` or
  written through `config_set`. The denylist matches any key containing
  `permission`, `grant`, `allow`, `deny`, `trust`, `sandbox`, `exec`,
  `approve`, or `policy` (case-insensitive, substring on the dotted key). The
  correct surface for such state is `grants/`.

## 5. Secret scanning

- **PS-110.** Every section, including session chunks, MUST pass a
  credential-shaped secret scan before encryption. Known token shapes (API
  keys, private-key PEM headers, bearer tokens, common cloud/VCS token
  prefixes) are blocked; plausible non-secret lookalikes pass.

## 6. Provenance

- **PS-120.** Memory entries carry YAML frontmatter with `type:` and
  `provenance:`. Learning-captured entries additionally carry
  `learned:<harness>`. Entries written by the conformance suite carry
  `provenance: spec/vector`.

## 7. Wire protocol

### 7.1 Endpoints

- `POST /auth/challenge` — returns `{nonce, expiresAt}`; nonce is random,
  single-use, 120-second expiry.
- `POST /auth/verify` — body `{did, nonce, sig}`; verifies the Ed25519
  signature over `nonce` and returns `{token, expiresAt}` bearer bound to the
  DID.
- `GET /passport/<ns>` — returns the manifest view. `?view=hashes` returns
  `{entryKey: sha256-hash}` for delta sync; `?view=integrity` returns the
  signed integrity manifest.
- `GET /passport/<ns>/<entryKey>` — returns one ciphertext blob.
- `PUT /passport/<ns>` — delta upsert `{base, entries: {key: blob}}`. `base`
  is the manifest hash the writer built from; a stale base returns **409** and
  nothing commits.

### 7.2 Auth and transport

- **PS-090.** Every `/passport/` request requires a bearer token bound to an
  authorized DID for that namespace. Unauthenticated requests are 401;
  wrong-DID are 403. Replay of a used challenge nonce is rejected.
- **PS-091.** The default listener binds loopback only. Non-loopback binding
  MUST require DID authentication and TLS; without both it refuses to start.
- **PS-092.** `local` mode is the single-machine self-host profile: loopback,
  the operator owns all namespaces on that instance.

### 7.3 Storage and caps

- **PS-080.** Storage is manifest-plus-blobs: one manifest plus one ciphertext
  blob per entry. Delta sync via `?view=hashes`.
- **PS-081.** Caps are checked all-or-nothing before any write: per-entry size,
  per-section size floors and ceilings, per-namespace total. An oversized
  entry returns a `skipped` response, never a silent drop. A stale `base`
  returns 409 with no partial commit.
- **PS-082.** Per-namespace locking serializes the read-modify-write so
  concurrent PUTs cannot clobber the manifest.

## 8. Conformance

- `spec/clauses.json` is the registry mapping each `PS-###` clause id to a
  checker function name. The registry and this document MUST stay in sync.
- `spec/vectors/` holds deterministic shared vectors covering encrypt/decrypt,
  rotation, and chunked sessions. TypeScript and Zig implementations MUST both
  pass the same vectors.
- `spec/report-schema.json` defines the checker's output: sorted,
  deterministic, spec-version-stamped JSON with per-clause
  `pass|fail|unsupported`.
