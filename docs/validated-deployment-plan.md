# Validated deployment implementation

## Objective and authority

Make the existing `Deploy` permission sufficient for an approved target in CLI
and MCP. Keep generic `Run` and raw credential reads denied to default agents.
No encryption format or existing vault contents need migration.

## Implementation sequence

1. Separate secret injection/scrubbing from the public generic command API.
   Only `run` checks `Run`; the private deployment path uses `Deploy`.
2. Verify registered metadata, canonical workspace containment and Cloudflare
   account identity before building. Reject legacy Worker targets for agents.
3. Build without inherited credentials. Recheck permission, registration and
   account identity after the build, before any authenticated subprocess.
4. Retain the repository's fixed `npm run deploy` lifecycle so predeploy guards
   execute. Inject only approved Cloudflare keys, reject expired credentials,
   scrub output and audit the authenticated step. Treat signal termination as
   failure. Do not retry publication automatically.
5. Test the actual target deployment with a temporary package and fake secrets,
   including build isolation, denied generic Run, secret filtering, target
   tampering, failed predeploy and lock/policy rechecks. Run CLI/MCP tests and
   compile a release binary.
6. Install the verified binary with a recoverable backup, verify agent mode,
   then attempt the already-requested project deployment through its guards.
   Report deployment and verification separately.

## Trust boundary and limitations

Encryption protects stored credentials; the authorized deployment subprocess
necessarily receives its scoped Cloudflare credential in memory/environment.
Repository scripts, dependencies and PATH-resolved executables are trusted code.
Output redaction cannot prevent malicious scripts from exfiltrating credentials
over the network or writing them to disk. Use least-privilege Cloudflare tokens
and reviewed source. A brokered HTTP transport or isolated deployment runner
would be a separate, larger security boundary.

Workspace checks prevent accidental outside-checkout selection, not isolation
from an adversarial process running as the same OS user. Concurrent repository
modification during deployment is unsupported. Stop after ambiguous publication
failure and inspect remote state before retrying.

## Verification record

- Initial core suite: 107 tests passed.
- MCP security suite: nine tests passed.
- After final hardening: three focused tests passed, covering the actual
  target deployment, denied generic Run, output scrubbing, changed metadata,
  config/account mismatch, expired credentials, predeploy failure, killswitch,
  signal termination, timeout and descendant output pipes.
- CLI version integration test passed after the final changes.
- Unix children use a dedicated process group, cleaned up on completion,
  timeout and cancellation. Output draining is bounded on every platform.
  This does not prevent hostile children from escaping the process group.
- Release installation and production checks are separate from local tests;
  a passing fixture is not proof of production publication.
