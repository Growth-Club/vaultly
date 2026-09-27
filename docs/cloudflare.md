# Vaultly + Cloudflare

Vaultly supports the Cloudflare operations needed for personal projects:
credential storage, safe account/domain discovery, write-only Worker secrets,
and target-bound Pages/Worker deployment.

## Credential layout

Create one vault per Cloudflare account. The recommended keys are:

```text
CLOUDFLARE_API_TOKEN
CLOUDFLARE_ACCOUNT_ID
```

Vaultly also accepts the legacy `CLOUDFLARE_EMAIL` and
`CLOUDFLARE_API_KEY` pair for compatibility, but scoped API tokens are safer.
`vaultly cf add` stores the account ID and credential without printing it.

```bash
VAULTLY_HUMAN_MODE=1 vaultly cf add personal --account-id <ACCOUNT_ID>
vaultly cf list
vaultly cf zones personal
vaultly cf pages personal
```

## Agent operations

| MCP tool | Purpose |
|---|---|
| `cf_accounts` | List configured account vaults and optionally check health |
| `cf_account_label` | Manage non-secret account labels |
| `cf_health` | Verify one credential set |
| `cf_zones` | List domains and zone IDs |
| `cf_pages_projects` | Discover Pages projects |
| `cf_workers_list` | Discover Workers |
| `cf_d1_list` | Discover D1 databases |
| `cf_r2_list` | Discover R2 buckets |
| `cf_kv_list` | Discover Workers KV namespaces |
| `cf_secrets` | List, set, or delete Worker secrets; values are write-only |
| `deploy_targets` | List deployment metadata |
| `deploy_target_adopt` | Derive and verify a target from a local Wrangler config |
| `deploy_target` | Deploy one target by ID |

Agents cannot issue arbitrary Cloudflare API paths, choose an account ID for a
deployment, or pass an arbitrary project/build command. Dynamic adoption is
the normal path: it resolves the account from a selected Vaultly Cloudflare
vault, derives the resource from local Wrangler config, and verifies it exists
in that account.

## Deployment safety

The agent normally adopts deployment metadata with `deploy_target_adopt`. A
legacy explicit target can still be registered with `vaultly target add` by a
human when a repository cannot be discovered from Wrangler configuration. The
target contains the provider, vault, vault-bound account ID, project, branch,
project directory, build command, and output directory. Vaultly validates this
record before use.

For agents, the registered record must match exactly and its canonical directory
must be inside the invoking workspace. Worker targets require dynamic adoption;
legacy explicit Worker targets remain available to human callers. The fixed
deployment subprocess is authorized by `Deploy`, while generic `Run` remains
denied. Revalidation after the build catches changed registration, config,
account, expired sessions and active killswitches before credential injection.

For Pages, Vaultly runs the build without Cloudflare credentials, hashes and
uploads the generated assets through the Cloudflare API, and returns only a
structured deployment result. For Workers, Vaultly uses the fixed target data
and passes only the approved Cloudflare credential scope to the deployment
tool. The agent receives no token. The Worker repository and its deployment
tooling must be trusted; no credential boundary can protect a hostile program
that is deliberately given the credential to perform the deployment.

Network requests use bounded retries for transient transport and 5xx failures.
Credential echoes in responses are scrubbed before agent output. All account
and deployment operations are written to the local audit chain.
