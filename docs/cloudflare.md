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
| `cf_secrets` | List, set, or delete Worker secrets; values are write-only |
| `deploy_targets` | List human-approved deployment metadata |
| `deploy_target` | Deploy one target by ID |

Agents cannot issue arbitrary Cloudflare API paths, choose an account for a
deployment, or pass an arbitrary project/build command.

## Deployment safety

Humans register deployment metadata with `vaultly target add`. The target
contains the provider, vault, account ID, project, branch, project directory,
build command, and output directory. Vaultly validates this record before use.

For Pages, Vaultly runs the build without Cloudflare credentials, hashes and
uploads the generated assets through the Cloudflare API, and returns only a
structured deployment result. For Workers, Vaultly uses the fixed target data
and passes only the approved Cloudflare credential scope to the deployment
tool. The agent receives no token.

Network requests use bounded retries for transient transport and 5xx failures.
Credential echoes in responses are scrubbed before agent output. All account
and deployment operations are written to the local audit chain.
