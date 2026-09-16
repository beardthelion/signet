# Signet Specification

**Spec version:** `signet-spec/0.1`
**Status:** Draft
**Steward:** signet

A Signet is a portable, DID-rooted, end-to-end-encrypted envelope of an
agent's complete working state. A conformant store holds only ciphertext and a
small, bounded set of plaintext metadata. A conformant harness reads and writes
the signet as if it were local state.

This document is the normative contract. Implementations include the reference
store, client, and MCP adapter in this repository, plus any third-party
conformant implementation checked by `signet-check`.

Keywords MUST, MUST NOT, SHOULD, and MAY are used per RFC 2119. Clause
identifiers `SN-###` are stable conformance hooks; `spec/clauses.json` is the
machine-readable registry of the same clauses.

## 1. Scope

The signet carries **full agent state** for a single holder:

- `memory/` - durable learned knowledge and notes
- `config/` - harness settings and preferences
- `sessions/` - session transcripts and checkpoints
- `grants/` - recorded permission grants
- `identity/` - DID document material and rotation attestations

Out of scope for this version: execution isolation of agents, sharing or ACLs
between holders, arbitrary file storage, hosted-service operation. Key loss is
total loss by design; there is no recovery path in this version.

## 2. Identity

### 2.1 DID methods

- **SN-001.** `did:key` (Ed25519, multibase `z`-prefixed base58btc of
  `0xed01 || pubkey`) is REQUIRED for every signet.
- **SN-002.** `did:web` is OPTIONAL and MAY serve as a holder's stable public
  alias. `did:web` MUST NOT be used as a namespace root.
- No other DID method is defined by this spec. Implementations MUST reject
  namespaces derived from other methods.

### 2.2 Genesis DID and namespace binding

- **SN-010.** Every signet has exactly one **genesis DID**: the `did:key`
  created at `signet init`. The signet's namespace is derived from the
  genesis DID and never changes.
- **SN-011.** The namespace is `signet:` followed by the **encoded genesis
  DID**: the DID string with every `:` replaced by `_`. Example:
  `did:key:z6Mk...` encodes to `signet:did_key_z6Mk...`. The encoding is
  injective (no colons survive) so one DID cannot alias another's namespace.
- **SN-012.** Encoded namespaces MUST match
  `^signet:did_[a-z]+_[A-Za-z0-9._-]{1,240}$`. Anything else is rejected
  before storage access.

### 2.3 Rotation

- **SN-050.** A rotation replaces the active signing key while the signet
  namespace stays bound to the genesis DID. A rotation is recorded as an entry
  `identity/rotations/<seq>.json` in the signet AND presented to the server
  during authentication.
- **SN-051.** A rotation attestation is a JSON document
  `{genesisDid, newDid, seq, prevHash, sig}` where `seq` is a strictly
  increasing counter starting at 1, `prevHash` is the SHA-256 of the previous
  attestation's canonical JSON (`"0"*64` for `seq=1`), and `sig` is the
  genesis-or-predecessor key's Ed25519 signature over the canonical JSON of
  `{genesisDid, newDid, seq, prevHash}`. The new key's signature is NOT
  required: control of the old key is the whole authorization. A chain longer
  than 64 attestations MUST be rejected.
- **SN-052.** While no rotation chain is stored for a namespace, a server MUST
  authorize only the genesis DID key. Once a valid chain is stored, a server
  MUST authorize only its terminal DID: every earlier key, the genesis key
  included, loses authority. A rotated-out key MUST NOT remain authorized.
  Forged, unsigned, misordered, or mis-linked attestations MUST be rejected,
  and a stored chain that fails re-verification authorizes no key. A stored
  chain MUST NOT be replaced by a presented chain that is not strictly longer.
- **SN-053.** After rotation the namespace, entry data, and caps remain bound
  to the genesis DID. A successor key MUST NOT be able to open a namespace
  under its own DID.

### 2.4 Key custody

- **SN-100.** Two secrets govern a signet: the **encryption secret**
  (passphrase) and the **holder signing key** (Ed25519 private key). Both live
  client-side only. A store MUST NEVER receive either.
- **SN-101.** `signet init` MUST write secret material only to the OS keychain
  or a `0600` file outside any committable path. It MUST NOT write secrets into
  workspace files, `.fx.json`, MCP config blocks, or the store.
- **SN-102.** `signet export` MUST produce an encrypted bundle containing both
  secrets; `signet import` restores custody on a second machine. The bundle is
  itself passphrase-encrypted.
- **SN-103.** Key loss is total loss. Implementations MUST document this and
  MUST NOT imply recovery.

## 3. Envelope

### 3.1 Entry keys

- **SN-020.** An entry key is a POSIX-ish relative path
  `<section>/<path>` where `<section>` is one of `memory`, `config`,
  `sessions`, `grants`, `identity`, and each path segment matches
  `[A-Za-z0-9][A-Za-z0-9._-]*`. An entry key is at most 255 characters.
- **SN-021.** Keys MUST NOT contain `..`, `//`, a leading or trailing `/`,
  backslash, or NUL. Both client and server MUST reject such keys before any
  storage access.
- **SN-022.** Session transcripts are chunked as `sessions/<id>/<seq>` where
  `<id>` is a valid segment and `<seq>` is a sequence counter zero-padded to
  at least 6 digits (`000001`, `000002`, ...). Chunks keep each entry under
  the entry cap while preserving transcript order.

### 3.2 Encryption

- **SN-030.** Every entry is encrypted client-side before storage or transit.
  The wire/storage blob layout is:

  ```
  [ 0x01 version ][ 12-byte nonce ][ 16-byte GCM tag ][ ciphertext ]
  ```

  then base64. The version byte is the migration hook; `0x01` is the only
  defined version.
- **SN-031.** The encryption key is
  `scrypt(passphrase, salt = sha256("signet:" + namespace), 32, {N: 2^15, r: 8, p: 1})`.
  The namespace-bound salt makes derivation deterministic and stateless.
- **SN-032.** The cipher is AES-256-GCM. The **entry key is the AEAD AAD**, so
  a blob is bound to its key and cannot be moved under another.
- **SN-033.** The nonce is deterministic: `HMAC-SHA256(encKey, entryKey || 0x00
  || plaintext)[0:12]`. Identical plaintext produces identical ciphertext,
  which is what enables delta sync by ciphertext hash. The accepted leak is
  "are two entries byte-identical." Implementations MUST NOT substitute random
  nonces without a spec revision.
- **SN-034.** A conformant store sees **only**: entry keys, per-entry
  ciphertext, per-entry size/hash/timestamp, the integrity manifest, rotation
  attestations, and namespace ids. It MUST NOT see plaintext, passphrases, or
  derived keys. This is the documented metadata leak boundary; nothing beyond
  it is permitted to leak.
- **SN-035.** Alternate AEAD for constrained platforms (e.g. Zig `std.crypto`):
  XChaCha20-Poly1305 with a 24-byte deterministic nonce under the same
  HMAC-derived scheme is a spec-sanctioned second cipher, signaled by version
  byte `0x02`. Implementations MUST NOT invent a third.

### 3.3 Integrity manifest

- **SN-040.** Each signet carries `identity/manifest.json`, a holder-signed
  document `{seq, specVersion, genesisDid, entries}` where `entries` maps each
  entry key to the `sha256:` hex of its ciphertext blob. `seq` increments on
  every push. The wire shape is the `SignedManifest` object
  `{manifest, did, sig}`: `manifest` is the document above, `did` is the
  signing key's DID, and `sig` is its Ed25519 signature over the canonical
  JSON of `manifest`. The manifest's own entry key is never listed in
  `entries`; a self-referential hash cannot exist.
- **SN-041.** A consumer MUST verify the manifest signature against the
  authorized keys (genesis or any key a valid rotation chain authorized when
  the manifest was signed) and MUST reject a `seq` lower than the last
  verified `seq`. A manifest re-presented at the SAME `seq` MUST be
  byte-identical to the manifest already verified at that `seq`; equal seq
  with different bytes is a replacement and MUST fail closed, as MUST a
  tampered, unsigned, or rolled-back manifest.

  The **manifest hash** of an entry-hash map is defined as: sort the keys;
  form one `key<TAB>hash` line per entry; join the lines with `\n`; take the
  SHA-256 of the joined text; prefix the lowercase hex digest with `sha256:`.
  This is the digest a PUT's `base` refers to.

## 4. Grants and config

### 4.1 Grant vocabulary

- **SN-060.** A grant is `{id, action, scope, constraints, granted_by,
  granted_at, expires_at?}` recorded under `grants/`. `action` is one of the
  defined action classes: `fs.read`, `fs.write`, `shell.exec`, `net.fetch`,
  `agent.spawn`. `scope` and `constraints` are free-form pattern/matcher
  fields a consuming harness interprets under its own action model.
- **SN-061.** Grants are **never silently honored across harness boundaries.**
  A consuming harness maps a stored grant to its own action model and asks the
  holder to confirm before honoring it. There is no automatic grant-application
  path.
- **SN-062.** `signet_grant_record` is the only write path for grants and
  records only holder-confirmed grants.

### 4.2 Config denylist

- **SN-070.** Permission-affecting keys MUST NOT be stored under `config/` or
  written through `config_set`. The denylist matches any key containing
  `permission`, `grant`, `allow`, `deny`, `trust`, `sandbox`, `exec`,
  `approve`, or `policy` (case-insensitive, substring on the dotted key). The
  correct surface for such state is `grants/`.

## 5. Secret scanning

- **SN-110.** Every section, including session chunks, MUST pass a
  credential-shaped secret scan before encryption. Known token shapes (API
  keys, private-key PEM headers, bearer tokens, common cloud/VCS token
  prefixes) are blocked; plausible non-secret lookalikes pass.

## 6. Provenance

- **SN-120.** Memory entries carry YAML frontmatter with `type:` and
  `provenance:`. Learning-captured entries additionally carry
  `learned:<harness>`. Entries written by the conformance suite carry
  `provenance: spec/vector`.

## 7. Wire protocol

### 7.1 Endpoints

- `GET /health`: unauthenticated liveness; returns `{ok: true, ...}`. It is
  the only route that does not require a bearer token besides the two auth
  endpoints.
- `POST /auth/challenge`: returns `{nonce, expiresAt}`; nonce is random,
  single-use, 120-second expiry.
- `POST /auth/verify`: body `{did, nonce, sig, attestations?}`; verifies the
  Ed25519 signature over the UTF-8 bytes of `"signet-auth:" + nonce` and
  returns `{token, expiresAt}` bearer bound to the DID. The fixed
  `signet-auth:` prefix is REQUIRED domain separation: the same key signs
  manifests and attestations, so a server-chosen nonce must never reproduce
  a signed document of another kind. `attestations`, when present, is the
  rotation chain the DID terminates (SN-051/052).
- `GET /signet/<ns>`: returns the manifest view. `?view=hashes` returns
  `{entryKey: sha256-hash}` for delta sync; `?view=integrity` returns the
  signed integrity manifest. Any other `view` value is a 400.
- `GET /signet/<ns>/<entryKey>`: returns one entry as
  `{namespace, key, entry, hash}`: `entry` is the base64 ciphertext blob and
  `hash` is REQUIRED, the `sha256:` digest of the decoded ciphertext.
- `PUT /signet/<ns>`: delta upsert `{base, entries, deletions?}`.
  `entries` maps entry keys to base64 ciphertext; `deletions` lists entry
  keys to remove. `base` is the manifest hash (SN-041) the writer built
  from, or `null` for a first write; a stale base returns **409** and
  nothing commits. The response is
  `{namespace, base, erasure, accepted, deleted, skipped}` where `skipped`
  lists `{key, reason}` for entries the store refused (reasons include
  `invalid_key`, `invalid_base64`, `entry_too_large`).

### 7.1a Errors

Non-2xx responses carry the envelope `{error: {code, message, details?}}`:
`code` is a stable machine-readable token, `message` is human text, and
`details` is an optional object of structured context. The code vocabulary
is: `bad_request`, `invalid_namespace`, `invalid_key`, `invalid_did`,
`invalid_nonce`, `invalid_signature`, `invalid_attestation`, `unauthorized`,
`forbidden`, `not_found`, `empty`, `entry_not_found`, `entry_unreadable`,
`method_not_allowed`, `payload_too_large`, `rate_limited`, `stale_base`,
`manifest_unreadable`, `section_cap_exceeded`, `namespace_too_large`,
`internal`. Two 404 codes mean "no signet": `empty` (the namespace holds
nothing) and, for reads, `entry_not_found` (the namespace exists but the key
does not). Any other 404 is an unknown route, not an empty signet. A path
under `/signet/` whose percent-encoding cannot be decoded is a **400**
`bad_request`, not a 404: the route matched, the path is undecodable.

### 7.2 Auth and transport

- **SN-090.** Every `/signet/` request requires a bearer token bound to an
  authorized DID for that namespace. Unauthenticated requests are 401;
  wrong-DID are 403. Replay of a used challenge nonce is rejected.
- **SN-091.** The default listener binds loopback only. Non-loopback binding
  MUST require DID authentication and TLS; without both it refuses to start.
- **SN-092.** `local` mode is the single-machine self-host profile: loopback,
  the operator owns all namespaces on that instance.

### 7.3 Storage and caps

- **SN-080.** Storage is manifest-plus-blobs: one manifest plus one ciphertext
  blob per entry. Delta sync via `?view=hashes`.
- **SN-081.** Caps are checked all-or-nothing before any write: per-entry size,
  per-section size floors and ceilings, per-namespace total. An oversized
  entry returns a `skipped` response, never a silent drop. A stale `base`
  returns 409 with no partial commit.
- **SN-082.** Per-namespace locking serializes the read-modify-write so
  concurrent PUTs cannot clobber the manifest.

## 8. Conformance

- `spec/clauses.json` is the registry mapping each `SN-###` clause id to a
  checker function name. The registry and this document MUST stay in sync.
- `spec/vectors/` holds deterministic shared vectors covering encrypt/decrypt,
  identity, rotation, and the signed manifest. TypeScript and Zig
  implementations MUST both pass the same vectors.
- `spec/report-schema.json` defines the checker's output: sorted,
  deterministic, spec-version-stamped JSON with per-clause
  `pass|fail|unsupported`.
- **SN-200.** The suite CLI (`signet-check`) reproduces every shared vector
  byte for byte: crypto, identity, rotation, and the signed manifest.
- **SN-201.** A write through the MCP tools layer recalls back over the wire
  path: `signet_save` followed by `signet_recall`/`signet_search`/
  `signet_list` returns the stored entry.
- **SN-103** is a documentation requirement with no wire-observable behavior;
  it is deliberately absent from the machine-readable registry and MUST NOT
  be reported as `pass`, `fail`, or `unsupported` by a checker.
