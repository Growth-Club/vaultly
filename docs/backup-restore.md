# Backup & Restore Runbook

Vaultly's `backup` and `restore` commands push/pull the **encrypted vault set**
to/from a Cloudflare Worker you run. They never transmit plaintext — only
ciphertext leaves your machine.

Both commands are interactive and are **blocked in agent mode**
(`VAULTLY_AGENT_MODE=1`); run them as a human.

## Remote backup endpoint

Both commands require:

- `--url` / `-u` — the base URL of your backup Worker (e.g. `https://backup.example.workers.dev`).
- `--token` / `-t` — the shared backup API token configured in that Worker.

```
vaultly backup https://backup.example.workers.dev --token <worker-token>
vaultly restore https://backup.example.workers.dev --token <worker-token>
```

`backup` sends a **PUT `{url}/backup`** with bearer-token auth and
`Content-Type: application/json`; `restore` sends a **GET `{url}/backup`** with
the same bearer auth (`main.rs cmd_backup / cmd_restore`). Trailing slashes in
the URL are tolerated.

## Payload shape

The pushed payload is a JSON document containing the **encrypted** vault data
and site config, plus integrity metadata:

```json
{
  "version": 1,
  "checksum": "<sha256 hex of the serialized vault map>",
  "vaults": { "<vault-name>": { "…encrypted VaultFile…" } },
  "config": { "…site config, incl. backup meta…" }
}
```

- **`version`** — the backup format version. The restore side **rejects** any
  version other than `1` before touching a file.
- **`checksum`** — a deterministic SHA-256 over the serialized `vaults` map
  (`vault.rs backup_checksum`), used to detect corruption or tampering in
  transit.
- **`vaults`** — each value is an encrypted, authenticated `VaultFile` (AES-256-GCM),
  so each vault also carries its own integrity on decrypt.
- **`config`** — the store config (salt, policy, and backup metadata). After a
  successful backup the store records `{worker_url, last_backup_at}` in
  `config.backup` (`update_backup_meta`).

## Restore safety (validate-before-write)

`restore` is deliberately **validate-then-write**:

1. **Confirm** — prompts "Restore overwrites existing vaults. Continue?" before
   doing anything.
2. **Fetch** — `GET {url}/backup` (bearer auth). A non-2xx or non-JSON response
   aborts.
3. **Version gate** — reject any payload whose `version` ≠ `1`
   ("unsupported backup version").
4. **Checksum present** — a payload with no `checksum` is rejected
   ("backup has no integrity checksum"); re-run `backup` to regenerate.
5. **Checksum verified** — recompute SHA-256 over the `vaults` map and compare;
   a mismatch aborts with "backup checksum mismatch (data corrupt or tampered)".
6. **Write only after validation** — `restore_encrypted_vaults`
   (`vault.rs`) validates the *entire* payload (every vault name is sanitized and
   every `VaultFile` deserialized + structurally validated) **before** writing
   any file, then writes them and records a `RESTORE` audit entry.

This guarantees a partial or corrupt backup can never leave your store in a
half-restored state.

## Disaster recovery

1. **Confirm you have a backup** — `vaultly status` and `vault_audit` show
   recent activity; confirm a recent `backup` entry in the audit log.
2. **Prefer restoring into a fresh store** so you don't clobber a working store
   by accident — point `VAULTLY_DIR` at an empty directory:
   `VAULTLY_DIR=/tmp/restore-test vaultly restore https://backup.example.workers.dev --token <t>`.
3. **Run restore** with the same Worker URL and token used for backup.
4. **Unlock** with your master password (the same one that encrypted the backup —
   PBKDF2-SHA256 key derivation is deterministic given the store's salt).
5. **Spot-check** a few secrets with `vaultly get <vault> <key>` (human only) to
   confirm integrity.

## Caveats

- The checksum detects **corruption / tampering in transit**, not a malicious
  Worker. A Worker you don't control could serve a *coherent* but
  attacker-supplied bundle — treat the Worker + token as a trusted store.
- Restore writes only your own encrypted store; files remain AES-GCM ciphertext
  until you unlock.
- Backup is refused when there are no vaults, and requires an initialized store.

Covered end-to-end by `crates/vaultly/tests/cli.rs` (`backup_restore_roundtrip`),
which exercises the encrypted-store roundtrip + checksum path at the file layer,
since the live Worker is offline in tests.
