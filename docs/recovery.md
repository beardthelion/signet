# Recovery runbook

Two failures can strand a signet: custody loss and anti-rollback lockout.
They have very different endings.

## Custody loss is passport loss

`~/.signet/custody.json` (0600) is the only place the seed and passphrase
exist. If it is lost with no backup, the passport is mathematically
unrecoverable. The server is crypto-blind by design: nothing it stores can
be decrypted without the passphrase, and no admin path can mint a new one.

Prevention is the whole answer:

```sh
signet export ~/signet-custody-backup.json   # prompted for an export passphrase
```

Keep the bundle AND its passphrase on a second device or in a password
manager. A backup that lives only on the machine it backs up is not a
backup. Re-export after `signet rotate` so the bundle carries the current
attestation chain.

## Restore custody on a machine

```sh
signet import ~/signet-custody-backup.json   # prompted for the export passphrase
signet pull <dir>                            # should list your namespace seq + entries
```

`import` refuses to overwrite existing custody unless `--force`. The
restored custody carries the anti-rollback cursor too, so a pull verifies
against the manifest seq the export saw.

To test without touching real custody, point `SIGNET_HOME` at a scratch
dir (this is also the recommended drill):

```sh
SIGNET_HOME=/tmp/drill signet import ~/signet-custody-backup.json
SIGNET_HOME=/tmp/drill signet pull /tmp/drill-out
```

Verified 2026-09-26: import + pull round-trips a full signet (DID, seq,
all sections, decrypted memory content).

## Anti-rollback lockout (store restored from an older backup)

The client persists the highest manifest seq it has verified
(`manifestSeqs` in custody). If the server store is ever restored from an
older backup, or rebuilt from a partial snapshot, the remote manifest seq
is lower than the client's floor and every pull/push fails closed with an
integrity error. That refusal is correct: a seq that goes backwards is
indistinguishable from a server-side rollback attack.

When you have confirmed the older store state is what you actually want
(for example, the live store was wiped and the only copy is an older
filesystem backup), the recovery is a deliberate floor reset plus a
signed republish:

1. Back up custody first: `cp ~/.signet/custody.json ~/.signet/custody.json.bak`.
2. Inspect the remote content with floor-free custody: `SIGNET_HOME=/tmp/x`
   + import your bundle, then edit `/tmp/x/custody.json` and set the
   `manifestSeqs` entry for your namespace to `0`. Pull and review that
   the remote state is what you intend to keep.
3. Apply the same `manifestSeqs` reset in real `~/.signet/custody.json`
   (set the namespace's seq to `0`, or delete the key).
4. `signet pull <dir>` (verifies the older manifest, adopts its seq as
   the new floor), then `signet push <dir>` to republish. The push
   mints a new manifest at the remote's seq + 1, signed by your key, so
   the record stays honest: seq jumps back once, by holder decision,
   then continues forward.
5. If other writers pushed while the store was rolled back, those writes
   are gone from the remote but live in other clients' state. Re-push
   from whichever device still holds the newer local copies.

Lowering `manifestSeqs` by hand is a deliberate holder action, not a
routine fix: do it only after confirming the remote manifest verifies
and the content is what you want. Custody bundles carry `manifestSeqs`,
so an imported backup has the same floor as the export-time custody and
will hit the same lockout until it is reset.

## Rotation aftermath

`signet rotate` moves signing authority to a new DID via a published
attestation chain. Old devices' custody still works: they verify the
chain server-side. But a custody backup taken before rotation does not
contain the newest chain; import it, then pull once so the fresh
attestations land in custody before exporting a new backup.
