# Vaultly threat model

Vaultly protects personal credentials and Cloudflare credentials on a local
machine while allowing agents to perform approved actions.

## Boundary

```text
Agent ── MCP / agent-mode CLI ──> Vaultly ──> Cloudflare API
                                  │
                                  └── build process (no credentials)
```

The agent can see names, metadata, safe operation results, and scrubbed API
responses. The Vaultly process alone holds the derived encryption key and
constructs authenticated Cloudflare requests.

## Protections

- Vault files use AES-256-GCM and are written atomically with restrictive file
  permissions.
- The master password is never stored in a vault file, audit record, child
  process, or MCP response.
- macOS Keychain provides the human-to-agent unlock bridge; the agent does not
  handle the password.
- Credential values are write-only on the MCP surface. Key listing returns
  names and expiry metadata only.
- Cloudflare responses are scrubbed for credential echoes.
- The audit log is hash-chained and records operation metadata, not values.
- Cloudflare requests use bounded retries for transient failures.
- Deployment is target-bound. A human chooses the account, project, branch,
  local paths, provider, and build command. The agent supplies only a target
  ID.
- Pages builds run with an empty environment. Arbitrary credential-injected
  commands and generic Cloudflare API tools are not available to agents.
- Input names, paths, account IDs, target IDs, and output directories are
  validated before use; symlinked deployment assets are rejected.

## Residual risks

- A compromised host can inspect the Vaultly process memory; host compromise is
  outside the local encryption boundary.
- A human can intentionally register an unsafe deployment target. Registration
  is therefore restricted to validated target adoption or explicit human
  registration, and target metadata is validated before persistence.
- Worker deployment necessarily gives the fixed deployment subprocess the
  approved Cloudflare credential scope. Agents cannot change that subprocess's
  target or command.
- A weak master password reduces the protection of encrypted files.

## Verification

Run the workspace checks from `rust/`:

```bash
cargo check --workspace
cargo test --workspace
```

The MCP integration suite verifies that values never appear in agent output,
retired tools are rejected, locks work, and the audit chain remains intact.
