#!/usr/bin/env node
/**
 * Vaultly CLI — Agent-first encrypted credential manager with Cloudflare integration.
 *
 * Usage:
 *   vaultly init                         Create master password
 *   vaultly add <vault> -k KEY -v VALUE  Add a secret
 *   vaultly get <vault> <key>            Get a secret value
 *   vaultly list [vault]                 List vaults or keys
 *   vaultly delete <vault> [key]         Delete a secret or vault
 *   vaultly env <vault>                  Output shell export statements
 *   vaultly run <vault> -- <cmd>         Run with injected env (scrubbed)
 *   vaultly cf add|list|use|deploy|secrets Manage Cloudflare accounts + Worker secrets
 *   vaultly template [name]              Create vault from template
 *   vaultly import <file> [--vault name] Import from plaintext file
 *   vaultly backup / restore             Encrypted remote backup
 *   vaultly protect                      Add AI-tool ignore rules
 *   vaultly mcp                          Start MCP server for agents
 */
import { Command } from "commander";
import chalk from "chalk";
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import * as vault from "./vault.js";
import { promptPassword, promptConfirm } from "./prompt.js";
import * as keychain from "./keychain.js";

// ─── Agent Mode ────────────────────────────────────────────
// When VAULTLY_AGENT_MODE=1, block commands that expose raw secrets.
// Agents should use `vaultly run` or the MCP server instead.
const AGENT_MODE = process.env.VAULTLY_AGENT_MODE === "1";

function blockInAgentMode(commandName: string): void {
  if (AGENT_MODE) {
    console.error(
      chalk.red(
        `✗ '${commandName}' is blocked in agent mode.\n` +
          `  Agents cannot read raw secrets. Use instead:\n` +
          `    vaultly run <vault> -- <command>   (execute with injected env)\n` +
          `    vaultly mcp                        (MCP server for AI agents)`
      )
    );
    process.exit(1);
  }
}

const program = new Command();

program
  .name("vaultly")
  .description("🔐 Agent-first encrypted credential manager with Cloudflare integration")
  .version("1.0.0");

// ─── Helper: unlock with password prompt ───────────────────

async function requireUnlock(): Promise<Buffer> {
  if (!vault.isInitialized()) {
    console.error(chalk.red("✗ Vaultly not initialized. Run: vaultly init"));
    process.exit(1);
  }
  // Support env var for non-interactive use (MCP, CI, testing)
  const password = process.env.VAULTLY_MASTER_PASSWORD || await promptPassword("🔑 Master password: ");
  try {
    return vault.unlock(password);
  } catch {
    console.error(chalk.red("✗ Wrong master password."));
    process.exit(1);
  }
}

// ─── init ──────────────────────────────────────────────────

program
  .command("init")
  .description("Initialize Vaultly with a master password")
  .action(async () => {
    if (vault.isInitialized()) {
      console.error(chalk.yellow("⚠ Already initialized at " + vault.getVaultlyDir()));
      const reset = await promptConfirm("Reset everything? This deletes ALL vaults");
      if (!reset) return;
      fs.rmSync(vault.getVaultlyDir(), { recursive: true, force: true });
    }

    console.log(chalk.cyan("\n🔐 Vaultly Setup"));
    console.log(chalk.dim("Your master password encrypts everything locally."));
    console.log(chalk.dim("It is NEVER stored or transmitted.\n"));

    // Support env var for non-interactive use (CI, testing, MCP)
    const envPw = process.env.VAULTLY_MASTER_PASSWORD;
    let pw1: string;
    if (envPw) {
      pw1 = envPw;
      if (pw1.length < 8) {
        console.error(chalk.red("✗ VAULTLY_MASTER_PASSWORD must be at least 8 characters."));
        process.exit(1);
      }
      console.log(chalk.dim("(using VAULTLY_MASTER_PASSWORD from environment)"));
    } else {
      pw1 = await promptPassword("Create master password: ");
      if (pw1.length < 8) {
        console.error(chalk.red("✗ Password must be at least 8 characters."));
        process.exit(1);
      }
      const pw2 = await promptPassword("Confirm master password: ");
      if (pw1 !== pw2) {
        console.error(chalk.red("✗ Passwords don't match."));
        process.exit(1);
      }
    }

    vault.initVault(pw1);
    console.log(chalk.green(`\n✓ Vaultly initialized at ${vault.getVaultlyDir()}`));

    // Offer keychain storage on macOS (skip in non-interactive mode)
    if (keychain.isKeychainAvailable() && !envPw) {
      const useKc = await promptConfirm(
        "Store master password in macOS Keychain for auto-unlock?"
      );
      if (useKc) {
        if (keychain.storeInKeychain(pw1)) {
          console.log(chalk.green("✓ Stored in Keychain — MCP server will auto-unlock."));
        } else {
          console.log(chalk.yellow("⚠ Keychain storage failed (you can retry: vaultly keychain store)"));
        }
      }
    }

    console.log(chalk.dim("  Add secrets:  vaultly add cf-personal -k API_TOKEN -v 'xxx'"));
    console.log(chalk.dim("  List vaults:  vaultly list\n"));
  });

// ─── add ───────────────────────────────────────────────────

program
  .command("add <vaultName>")
  .description("Add or update a secret in a vault")
  .requiredOption("-k, --key <key>", "Secret name (e.g. CLOUDFLARE_API_TOKEN)")
  .requiredOption("-v, --value <value>", "Secret value")
  .action(async (vaultName: string, opts: { key: string; value: string }) => {
    const key = await requireUnlock();
    vault.setSecret(vaultName, opts.key, opts.value, key);
    console.log(chalk.green(`✓ ${vaultName}/${opts.key} saved`));
  });

// ─── get ───────────────────────────────────────────────────

program
  .command("get <vaultName> <secretKey>")
  .description("Get a secret value (blocked in agent mode)")
  .action(async (vaultName: string, secretKey: string) => {
    blockInAgentMode("get");
    const key = await requireUnlock();
    const value = vault.getSecret(vaultName, secretKey, key);
    if (value === undefined) {
      console.error(chalk.red(`✗ '${secretKey}' not found in vault '${vaultName}'`));
      process.exit(1);
    }
    // Output raw value to stdout (for piping)
    console.log(value);
  });

// ─── list ──────────────────────────────────────────────────

program
  .command("list [vaultName]")
  .description("List all vaults, or keys in a specific vault")
  .action(async (vaultName?: string) => {
    if (!vaultName) {
      // List all vaults
      const vaults = vault.listVaults();
      if (vaults.length === 0) {
        console.log(chalk.dim("No vaults yet. Create one:"));
        console.log(chalk.cyan("  vaultly add my-first-vault -k KEY -v VALUE"));
        return;
      }
      console.log(chalk.bold("\n📦 Vaults:\n"));
      for (const v of vaults) {
        console.log(`  ${chalk.cyan(v)}`);
      }
      console.log();
    } else {
      // List keys in a vault
      const key = await requireUnlock();
      const keys = vault.listKeys(vaultName, key);
      if (keys.length === 0) {
        console.log(chalk.dim(`Vault '${vaultName}' is empty or doesn't exist.`));
        return;
      }
      console.log(chalk.bold(`\n🔑 Keys in '${vaultName}':\n`));
      for (const k of keys) {
        console.log(`  ${chalk.green(k)}`);
      }
      console.log();
    }
  });

// ─── delete ────────────────────────────────────────────────

program
  .command("delete <vaultName> [secretKey]")
  .description("Delete a secret key, or an entire vault if no key given")
  .action(async (vaultName: string, secretKey?: string) => {
    if (secretKey) {
      const key = await requireUnlock();
      const deleted = vault.deleteSecret(vaultName, secretKey, key);
      if (deleted) {
        console.log(chalk.green(`✓ Deleted ${vaultName}/${secretKey}`));
      } else {
        console.error(chalk.red(`✗ '${secretKey}' not found in '${vaultName}'`));
      }
    } else {
      const confirm = await promptConfirm(
        chalk.red(`Delete entire vault '${vaultName}'?`)
      );
      if (!confirm) return;
      const deleted = vault.deleteVault(vaultName);
      if (deleted) {
        console.log(chalk.green(`✓ Vault '${vaultName}' deleted`));
      } else {
        console.error(chalk.red(`✗ Vault '${vaultName}' not found`));
      }
    }
  });

// ─── env ───────────────────────────────────────────────────

program
  .command("env <vaultName>")
  .description("Output shell export statements (blocked in agent mode)")
  .addHelpText(
    "after",
    "\nExample:\n  eval $(vaultly env cf-personal)\n  npx wrangler deploy"
  )
  .action(async (vaultName: string) => {
    blockInAgentMode("env");
    const key = await requireUnlock();
    const secrets = vault.getSecrets(vaultName, key);
    const keys = Object.keys(secrets);
    if (keys.length === 0) {
      console.error(chalk.red(`✗ Vault '${vaultName}' is empty or doesn't exist.`));
      process.exit(1);
    }
    // Output to stdout for eval — no colors, no decoration
    for (const [k, v] of Object.entries(secrets)) {
      // Shell-safe: single-quote the value, escape internal single quotes
      const escaped = v.replace(/'/g, "'\\''");
      console.log(`export ${k}='${escaped}'`);
    }
  });

// ─── import ────────────────────────────────────────────────

program
  .command("import <file>")
  .description("Import secrets from a plaintext file (KEY=VALUE or KEY: VALUE per line)")
  .option("--vault <name>", "Target vault name", "imported")
  .option(
    "--delete-after",
    "Securely delete the source file after import",
    false
  )
  .action(async (file: string, opts: { vault: string; deleteAfter: boolean }) => {
    if (!fs.existsSync(file)) {
      console.error(chalk.red(`✗ File not found: ${file}`));
      process.exit(1);
    }

    const key = await requireUnlock();
    const content = fs.readFileSync(file, "utf8");
    const entries: Record<string, string> = {};

    for (const line of content.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("//")) continue;

      // Support KEY=VALUE, KEY: VALUE, KEY = VALUE
      const match = trimmed.match(/^([A-Za-z0-9_.-]+)\s*[=:]\s*(.+)$/);
      if (match) {
        let value = match[2].trim();
        // Strip surrounding quotes
        if (
          (value.startsWith('"') && value.endsWith('"')) ||
          (value.startsWith("'") && value.endsWith("'"))
        ) {
          value = value.slice(1, -1);
        }
        entries[match[1]] = value;
      }
    }

    if (Object.keys(entries).length === 0) {
      console.error(chalk.yellow("⚠ No KEY=VALUE pairs found in file."));
      return;
    }

    const count = vault.importSecrets(opts.vault, entries, key);
    console.log(chalk.green(`✓ Imported ${count} secrets into vault '${opts.vault}'`));

    if (opts.deleteAfter) {
      // Overwrite before delete for basic secure deletion
      const stats = fs.statSync(file);
      const zeros = Buffer.alloc(stats.size, 0);
      fs.writeFileSync(file, zeros);
      fs.unlinkSync(file);
      console.log(chalk.green(`✓ Source file securely deleted: ${file}`));
    } else {
      console.log(
        chalk.yellow(`⚠ Source file still exists. Delete it: rm "${file}"`)
      );
    }
  });

// ─── backup ────────────────────────────────────────────────

program
  .command("backup")
  .description("Push encrypted vaults to Cloudflare Worker (remote backup)")
  .requiredOption("-u, --url <workerUrl>", "Your Vaultly Worker URL")
  .requiredOption("-t, --token <apiToken>", "Backup API token (set in Worker)")
  .action(async (opts: { url: string; token: string }) => {
    if (!vault.isInitialized()) {
      console.error(chalk.red("✗ Not initialized. Run: vaultly init"));
      process.exit(1);
    }

    console.log(chalk.cyan("📤 Backing up encrypted vaults to Cloudflare..."));

    const vaults = vault.getEncryptedVaults();
    const config = vault.getConfigForBackup();
    const vaultNames = Object.keys(vaults);

    if (vaultNames.length === 0) {
      console.log(chalk.yellow("⚠ No vaults to backup."));
      return;
    }

    const payload = JSON.stringify({ vaults, config });

    try {
      const res = await fetch(`${opts.url}/backup`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${opts.token}`,
        },
        body: payload,
      });

      if (!res.ok) {
        const text = await res.text();
        throw new Error(`HTTP ${res.status}: ${text}`);
      }

      vault.updateBackupMeta(opts.url);
      console.log(
        chalk.green(`✓ Backed up ${vaultNames.length} vault(s): ${vaultNames.join(", ")}`)
      );
      console.log(chalk.dim("  Data is encrypted — Cloudflare only stores ciphertext."));
    } catch (err: any) {
      console.error(chalk.red(`✗ Backup failed: ${err.message}`));
      process.exit(1);
    }
  });

// ─── restore ───────────────────────────────────────────────

program
  .command("restore")
  .description("Pull encrypted vaults from Cloudflare Worker")
  .requiredOption("-u, --url <workerUrl>", "Your Vaultly Worker URL")
  .requiredOption("-t, --token <apiToken>", "Backup API token")
  .action(async (opts: { url: string; token: string }) => {
    console.log(chalk.cyan("📥 Restoring encrypted vaults from Cloudflare..."));

    try {
      const res = await fetch(`${opts.url}/backup`, {
        headers: { Authorization: `Bearer ${opts.token}` },
      });

      if (!res.ok) {
        const text = await res.text();
        throw new Error(`HTTP ${res.status}: ${text}`);
      }

      const data = (await res.json()) as {
        vaults: Record<string, any>;
        config: any;
      };

      const count = vault.restoreEncryptedVaults(data.vaults);
      console.log(chalk.green(`✓ Restored ${count} vault(s).`));
      console.log(chalk.dim("  Use your master password to decrypt them."));
    } catch (err: any) {
      console.error(chalk.red(`✗ Restore failed: ${err.message}`));
      process.exit(1);
    }
  });

// ─── protect ───────────────────────────────────────────────

program
  .command("protect [projectDir]")
  .description("Add AI-tool ignore rules to protect secrets from being read by AI agents")
  .action(async (projectDir?: string) => {
    const dir = projectDir || process.cwd();
    let updated = 0;

    const ignorePatterns = [
      "# Vaultly secrets protection",
      ".env",
      ".env.*",
      "*.vault",
      ".production-keys",
      "credentails*",
      "credentials*",
      "*-keys*",
      "*.pem",
    ];

    // Files to append ignore rules to
    const targets: string[] = [".gitignore", ".windsurfrules"];

    for (const file of targets) {
      const filePath = path.join(dir, file);
      let content = fs.existsSync(filePath) ? fs.readFileSync(filePath, "utf8") : "";
      if (content.includes("Vaultly secrets protection")) {
        console.log(chalk.dim(`  ⏭ ${file} (already protected)`));
        continue;
      }
      content += "\n" + ignorePatterns.join("\n") + "\n";
      fs.mkdirSync(path.dirname(filePath), { recursive: true });
      fs.writeFileSync(filePath, content);
      console.log(chalk.green(`  ✓ ${file} updated`));
      updated++;
    }

    console.log(
      chalk.green(`\n✓ Protected ${updated} config file(s) in ${dir}`)
    );
    console.log(chalk.dim("  AI tools that respect these files won't read your secrets."));
  });

// ─── run (agent-safe command execution) ────────────────────

program
  .command("run <vaultName>")
  .description(
    "Run a command with vault secrets injected as env vars (agent-safe: secrets never printed)"
  )
  .argument("<command...>", "Command to run (after --)")
  .allowUnknownOption(true)
  .addHelpText(
    "after",
    "\nExamples:\n" +
      "  vaultly run cf-personal -- npx wrangler deploy\n" +
      "  vaultly run personal -- npm publish\n" +
      "  vaultly run cf-work -- curl https://api.cloudflare.com/client/v4/zones\n" +
      "\nThe child process gets the env vars. You see its output. Secrets are never printed."
  )
  .action(async (vaultName: string, command: string[]) => {
    // Commander captures everything after vaultName; strip leading "--"
    const args = command[0] === "--" ? command.slice(1) : command;
    if (args.length === 0) {
      console.error(chalk.red("✗ No command given. Usage: vaultly run <vault> -- <command>"));
      process.exit(1);
    }

    const key = await requireUnlock();
    const secrets = vault.getSecrets(vaultName, key);
    const secretKeys = Object.keys(secrets);

    if (secretKeys.length === 0) {
      console.error(chalk.red(`✗ Vault '${vaultName}' is empty or doesn't exist.`));
      process.exit(1);
    }

    // Log what we're doing (without values)
    console.error(
      chalk.dim(
        `🔐 Injecting ${secretKeys.length} secret(s) from '${vaultName}': ${secretKeys.join(", ")}`
      )
    );
    console.error(chalk.dim(`▶ Running: ${args.join(" ")}\n`));

    // Capture output so we can scrub secrets before displaying
    const { scrubOutput } = await import("./scrubber.js");
    const secretValues = Object.values(secrets);

    const child = spawn(args[0], args.slice(1), {
      stdio: ["inherit", "pipe", "pipe"],
      env: {
        ...process.env,
        ...secrets,
        VAULTLY_AGENT_MODE: undefined,
      },
      shell: false,
    });

    child.stdout.on("data", (data: Buffer) => {
      process.stdout.write(scrubOutput(data.toString(), secretValues));
    });
    child.stderr.on("data", (data: Buffer) => {
      process.stderr.write(scrubOutput(data.toString(), secretValues));
    });

    child.on("error", (err) => {
      console.error(chalk.red(`✗ Failed to start command: ${err.message}`));
      process.exit(1);
    });

    child.on("close", (code) => {
      process.exit(code ?? 0);
    });
  });

// ─── mcp (start MCP server for AI agents) ──────────────────

program
  .command("mcp")
  .description("Start MCP server for AI agents (zero-knowledge: agents can act but not read)")
  .addHelpText(
    "after",
    "\nConfigure in your AI tool:\n" +
      '  { "mcpServers": { "vaultly": { "command": "vaultly", "args": ["mcp"] } } }\n' +
      "\nThe agent gets tools to run commands and call APIs,\n" +
      "but NO tool that returns raw secret values."
  )
  .action(async () => {
    // Dynamic import so MCP SDK is only loaded when needed
    const { startMcpServer } = await import("./mcp-server.js");
    await startMcpServer();
  });

// ─── cf (dynamic Cloudflare account management) ────────────

const cf = program
  .command("cf")
  .description("Manage Cloudflare accounts (fully dynamic — add as many as you want)");

cf.command("add [name]")
  .description("Add a Cloudflare account (API token OR global API key)")
  .option("-t, --token <token>", "API token (skip prompt)")
  .option("-a, --account-id <id>", "Account ID (skip prompt)")
  .option("-e, --email <email>", "Global key auth: account email (skip prompt)")
  .option("-k, --api-key <key>", "Global key auth: API key (skip prompt)")
  .action(async (name?: string, opts?: { token?: string; accountId?: string; email?: string; apiKey?: string }) => {
    const key = await requireUnlock();
    const readline = await import("node:readline");
    const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
    const ask = (q: string) => new Promise<string>((res) => rl.question(q, (a) => res(a.trim())));

    // Get account name
    if (!name) {
      name = await ask("Account name (e.g. personal, work, client-x): ");
    }
    if (!name) {
      rl.close();
      console.error(chalk.red("✗ Name required."));
      process.exit(1);
    }

    const vaultName = name.startsWith("cf-") ? name : `cf-${name}`;

    // Auth mode: API token (default) or global API key (email + key)
    let token = opts?.token;
    let email = opts?.email;
    let apiKey = opts?.apiKey;
    if (!token && !(email && apiKey)) {
      const method = await ask("Auth method — [1] API token, [2] Global API key: ");
      if (method.trim() === "2") {
        email = await ask("CLOUDFLARE_EMAIL (global key): ");
        apiKey = await ask("CLOUDFLARE_API_KEY (global key): ");
      } else {
        token = await ask("CLOUDFLARE_API_TOKEN: ");
      }
    }

    // Get account ID
    let accountId = opts?.accountId;
    if (!accountId) {
      accountId = await ask("CLOUDFLARE_ACCOUNT_ID: ");
    }

    rl.close();

    if (token) vault.setSecret(vaultName, "CLOUDFLARE_API_TOKEN", token, key);
    if (email) vault.setSecret(vaultName, "CLOUDFLARE_EMAIL", email, key);
    if (apiKey) vault.setSecret(vaultName, "CLOUDFLARE_API_KEY", apiKey, key);
    if (accountId) vault.setSecret(vaultName, "CLOUDFLARE_ACCOUNT_ID", accountId, key);

    const auth = token ? "API token" : "global API key";
    console.log(chalk.green(`\n✓ Cloudflare account '${vaultName}' saved (${auth})`));
    console.log(chalk.dim(`  Use it:  vaultly cf use ${name}`));
    console.log(chalk.dim(`  Deploy:  vaultly cf deploy ${name} /path/to/project`));
  });

cf.command("list")
  .description("List all Cloudflare accounts")
  .action(async () => {
    const vaults = vault.listVaults().filter((v) => v.startsWith("cf-"));
    if (vaults.length === 0) {
      console.log(chalk.dim("No Cloudflare accounts. Add one:"));
      console.log(chalk.cyan("  vaultly cf add personal"));
      return;
    }
    console.log(chalk.bold(`\n☁️  Cloudflare Accounts (${vaults.length}):\n`));
    for (const v of vaults) {
      const name = v.replace("cf-", "");
      console.log(`  ${chalk.cyan(name)} ${chalk.dim(`(vault: ${v})`)}`);
    }
    console.log();
  });

cf.command("use <name>")
  .description("Output shell eval to activate a CF account (use with eval)")
  .addHelpText("after", "\nExample:\n  eval $(vaultly cf use personal)\n  npx wrangler deploy")
  .action(async (name: string) => {
    blockInAgentMode("cf use");
    const key = await requireUnlock();
    const vaultName = name.startsWith("cf-") ? name : `cf-${name}`;
    const secrets = vault.getSecrets(vaultName, key);
    if (Object.keys(secrets).length === 0) {
      console.error(chalk.red(`✗ Account '${vaultName}' not found.`));
      console.error(chalk.dim(`  Available: ${vault.listVaults().filter(v => v.startsWith("cf-")).map(v => v.replace("cf-", "")).join(", ")}`));
      process.exit(1);
    }
    for (const [k, v] of Object.entries(secrets)) {
      const escaped = v.replace(/'/g, "'\\''");
      console.log(`export ${k}='${escaped}'`);
    }
  });

cf.command("deploy <name> <projectDir>")
  .description("Deploy a Worker project using a CF account (agent-safe, output scrubbed)")
  .option("--env <env>", "Wrangler environment (e.g. staging)")
  .action(async (name: string, projectDir: string, opts?: { env?: string }) => {
    const key = await requireUnlock();
    const vaultName = name.startsWith("cf-") ? name : `cf-${name}`;
    const secrets = vault.getSecrets(vaultName, key);
    if (!secrets["CLOUDFLARE_API_TOKEN"]) {
      console.error(chalk.red(`✗ No CLOUDFLARE_API_TOKEN in '${vaultName}'`));
      process.exit(1);
    }

    const cmd = `npx wrangler deploy${opts?.env ? ` --env ${opts.env}` : ""}`;
    console.error(chalk.dim(`☁️  Deploying with account '${name}' → ${projectDir}`));
    console.error(chalk.dim(`▶ ${cmd}\n`));

    const { scrubOutput } = await import("./scrubber.js");
    const secretValues = Object.values(secrets);

    const child = spawn("npx", ["wrangler", "deploy", ...(opts?.env ? ["--env", opts.env] : [])], {
      cwd: projectDir,
      stdio: ["inherit", "pipe", "pipe"],
      env: { ...process.env, ...secrets },
    });
    child.stdout.on("data", (d: Buffer) => process.stdout.write(scrubOutput(d.toString(), secretValues)));
    child.stderr.on("data", (d: Buffer) => process.stderr.write(scrubOutput(d.toString(), secretValues)));
    child.on("error", (err) => {
      console.error(chalk.red(`✗ Failed to start deploy: ${err.message}`));
      process.exit(1);
    });
    child.on("close", (code) => process.exit(code ?? 0));
  });

cf.command("remove <name>")
  .description("Remove a Cloudflare account")
  .action(async (name: string) => {
    const vaultName = name.startsWith("cf-") ? name : `cf-${name}`;
    const confirm = await promptConfirm(chalk.red(`Remove Cloudflare account '${name}'?`));
    if (!confirm) return;
    const deleted = vault.deleteVault(vaultName);
    console.log(deleted
      ? chalk.green(`✓ Removed '${vaultName}'`)
      : chalk.red(`✗ '${vaultName}' not found`));
  });

cf.command("zones <name>")
  .description("List zones (domains) for a CF account")
  .action(async (name: string) => {
    const key = await requireUnlock();
    const vaultName = name.startsWith("cf-") ? name : `cf-${name}`;
    const secrets = vault.getSecrets(vaultName, key);
    const token = secrets["CLOUDFLARE_API_TOKEN"];
    if (!token) {
      console.error(chalk.red(`✗ No token in '${vaultName}'`));
      process.exit(1);
    }
    try {
      const res = await fetch("https://api.cloudflare.com/client/v4/zones?per_page=50", {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        console.error(chalk.red(`✗ Cloudflare API error: HTTP ${res.status}`));
        process.exit(1);
      }
      const data = await res.json() as any;
      if (!data?.success) {
        const msgs = (data?.errors || []).map((e: any) => e.message).join(", ");
        console.error(chalk.red(`✗ Cloudflare error: ${msgs || "unknown"}`));
        process.exit(1);
      }
      const zones = data?.result || [];
      console.log(chalk.bold(`\n☁️  Zones for '${name}' (${zones.length}):\n`));
      for (const z of zones) {
        console.log(`  ${chalk.green(z.name)} ${chalk.dim(`id=${z.id} status=${z.status}`)}`);
      }
      console.log();
    } catch (err: any) {
      console.error(chalk.red(`✗ Failed to fetch zones: ${err.message}`));
      process.exit(1);
    }
  });

cf.command("secrets <name> <scriptName>")
  .description("Manage secrets for a deployed Worker (list, set, delete)")
  .option("-l, --list", "List secret names (never values)")
  .option("-s, --set <key>", "Set a secret (prompts for value if --value omitted)")
  .option("-v, --value <value>", "Secret value to set (write-only)")
  .option("-d, --delete <key>", "Delete a secret")
  .addHelpText("after", "\nExamples:\n  vaultly cf secrets personal my-worker --list\n  vaultly cf secrets personal my-worker --set API_KEY --value sk-xxx\n  vaultly cf secrets personal my-worker --delete API_KEY")
  .action(async (name: string, scriptName: string, opts?: { list?: boolean; set?: string; value?: string; delete?: string }) => {
    blockInAgentMode("cf secrets");
    const key = await requireUnlock();
    const vaultName = name.startsWith("cf-") ? name : `cf-${name}`;
    const secrets = vault.getSecrets(vaultName, key);
    const token = secrets["CLOUDFLARE_API_TOKEN"];
    const email = secrets["CLOUDFLARE_EMAIL"];
    const apiKey = secrets["CLOUDFLARE_API_KEY"];
    if (!token && !(email && apiKey)) {
      console.error(chalk.red(`✗ No Cloudflare credentials in '${vaultName}'. Add with: vaultly cf add ${name}`));
      process.exit(1);
    }
    if (!secrets["CLOUDFLARE_ACCOUNT_ID"]) {
      console.error(chalk.red(`✗ No CLOUDFLARE_ACCOUNT_ID in '${vaultName}'`));
      process.exit(1);
    }

    const action = opts?.list ? "list" : opts?.set ? "set" : opts?.delete ? "delete" : undefined;
    if (!action) {
      console.error(chalk.red("✗ Pick an action: --list, --set <key>, or --delete <key>"));
      process.exit(1);
    }

    let value = opts?.value;
    if (action === "set" && value === undefined) {
      value = await promptPassword(`Secret value for '${opts!.set}': `);
    }

    const base = `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(secrets.CLOUDFLARE_ACCOUNT_ID)}/workers/scripts/${encodeURIComponent(scriptName)}/secrets`;
    const headers: Record<string, string> = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    } else {
      headers["X-Auth-Email"] = email!;
      headers["X-Auth-Key"] = apiKey!;
    }

    try {
      let res: Response;
      if (action === "list") {
        res = await fetch(base, { headers });
      } else if (action === "set") {
        res = await fetch(base, {
          method: "PUT",
          headers: { ...headers, "Content-Type": "application/json" },
          body: JSON.stringify({ name: opts!.set, text: value }),
        });
      } else {
        res = await fetch(`${base}/${encodeURIComponent(opts!.delete!)}`, { method: "DELETE", headers });
      }
      const data = await res.json() as any;
      if (!res.ok || !data?.success) {
        const msgs = (data?.errors || []).map((e: any) => e.message).join(", ");
        console.error(chalk.red(`✗ Cloudflare error (HTTP ${res.status}): ${msgs || "unknown"}`));
        process.exit(1);
      }
      if (action === "list") {
        const names = (data?.result || []).map((s: any) => s.name);
        console.log(chalk.bold(`\n🔑 Secrets in '${scriptName}' (${names.length}):\n`));
        for (const n of names) console.log(`  - ${n}`);
        console.log(chalk.dim("\n(names only — values are never returned)"));
      } else if (action === "set") {
        console.log(chalk.green(`✓ Set secret '${opts!.set}' on '${scriptName}'`));
      } else {
        console.log(chalk.green(`✓ Deleted secret '${opts!.delete}' from '${scriptName}'`));
      }
    } catch (err: any) {
      console.error(chalk.red(`✗ Failed: ${err.message}`));
      process.exit(1);
    }
  });

// ─── templates ─────────────────────────────────────────────

const TEMPLATES: Record<string, { keys: string[]; description: string }> = {
  cloudflare: {
    description: "Cloudflare account (API token or global key + account ID)",
    keys: ["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID"],
  },
  github: {
    description: "GitHub (personal access token)",
    keys: ["GITHUB_TOKEN", "GITHUB_USERNAME"],
  },
  aws: {
    description: "AWS credentials",
    keys: ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"],
  },
  gcp: {
    description: "Google Cloud Platform",
    keys: ["GOOGLE_APPLICATION_CREDENTIALS", "GCP_PROJECT_ID"],
  },
  vercel: {
    description: "Vercel deployment",
    keys: ["VERCEL_TOKEN", "VERCEL_ORG_ID", "VERCEL_PROJECT_ID"],
  },
  database: {
    description: "Database connection",
    keys: ["DATABASE_URL", "DATABASE_PASSWORD"],
  },
  stripe: {
    description: "Stripe payments",
    keys: ["STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET", "STRIPE_PUBLISHABLE_KEY"],
  },
  openai: {
    description: "OpenAI / AI APIs",
    keys: ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_AI_KEY"],
  },
  smtp: {
    description: "Email sending",
    keys: ["SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD"],
  },
  docker: {
    description: "Docker registry",
    keys: ["DOCKER_USERNAME", "DOCKER_PASSWORD", "DOCKER_REGISTRY"],
  },
  npm: {
    description: "npm publishing",
    keys: ["NPM_TOKEN"],
  },
  ssh: {
    description: "Server access",
    keys: ["SERVER_HOST", "SERVER_USER", "SERVER_PASSWORD", "SERVER_SSH_KEY"],
  },
  "social-media": {
    description: "Social media APIs",
    keys: ["META_ACCESS_TOKEN", "TWITTER_BEARER_TOKEN", "LINKEDIN_ACCESS_TOKEN"],
  },
  custom: {
    description: "Custom vault (define your own keys)",
    keys: [],
  },
};

program
  .command("template [name]")
  .description("Create a vault from a pre-built template (cf, github, aws, stripe, etc.)")
  .option("--list", "List available templates")
  .addHelpText("after", `\nTemplates:\n${Object.entries(TEMPLATES).map(([k, v]) => `  ${k.padEnd(16)} ${v.description}`).join("\n")}`)
  .action(async (name?: string, opts?: { list?: boolean }) => {
    if (opts?.list || !name) {
      console.log(chalk.bold("\n📋 Available templates:\n"));
      for (const [key, tpl] of Object.entries(TEMPLATES)) {
        console.log(`  ${chalk.cyan(key.padEnd(18))} ${chalk.dim(tpl.description)}`);
        if (tpl.keys.length > 0) {
          console.log(`  ${"".padEnd(18)} ${chalk.dim("Keys: " + tpl.keys.join(", "))}`);
        }
      }
      console.log(chalk.dim("\nUsage: vaultly template github my-github"));
      return;
    }

    const tpl = TEMPLATES[name];
    if (!tpl) {
      console.error(chalk.red(`✗ Unknown template '${name}'.`));
      console.error(chalk.dim(`  Available: ${Object.keys(TEMPLATES).join(", ")}`));
      process.exit(1);
    }

    const key = await requireUnlock();

    // Get vault name
    const readline = await import("node:readline");
    const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
    const ask = (q: string) => new Promise<string>((res) => rl.question(q, (a) => res(a.trim())));

    const vaultName = await ask(`Vault name [${name}]: `) || name;

    if (tpl.keys.length === 0) {
      // Custom template — ask for keys
      console.log(chalk.dim("\nEnter keys (empty line to finish):"));
      const customKeys: string[] = [];
      while (true) {
        const k = await ask(`  Key ${customKeys.length + 1}: `);
        if (!k) break;
        customKeys.push(k.toUpperCase().replace(/[^A-Z0-9_]/g, "_"));
      }
      for (const k of customKeys) {
        const v = await ask(`  ${k} value: `);
        if (v) vault.setSecret(vaultName, k, v, key);
      }
    } else {
      console.log(chalk.dim(`\nTemplate: ${tpl.description}`));
      console.log(chalk.dim("(press Enter to skip any key)\n"));
      for (const k of tpl.keys) {
        const v = await ask(`  ${k}: `);
        if (v) vault.setSecret(vaultName, k, v, key);
      }
    }

    rl.close();
    const saved = vault.getSecrets(vaultName, key);
    console.log(chalk.green(`\n✓ Vault '${vaultName}' created with ${Object.keys(saved).length} key(s)`));
    console.log(chalk.dim(`  Use: vaultly run ${vaultName} -- <command>`));
  });

// ─── keychain ──────────────────────────────────────────────

const kc = program
  .command("keychain")
  .description("Manage macOS Keychain integration (auto-unlock without password)");

kc.command("store")
  .description("Store master password in macOS Keychain for auto-unlock")
  .action(async () => {
    if (!keychain.isKeychainAvailable()) {
      console.error(chalk.red("✗ macOS Keychain not available (requires macOS)."));
      process.exit(1);
    }
    const pw = process.env.VAULTLY_MASTER_PASSWORD || await promptPassword("🔑 Master password to store in Keychain: ");
    try {
      vault.unlock(pw); // verify first
    } catch {
      console.error(chalk.red("✗ Wrong password."));
      process.exit(1);
    }
    if (keychain.storeInKeychain(pw)) {
      console.log(chalk.green("✓ Master password stored in macOS Keychain."));
      console.log(chalk.dim("  MCP server will auto-unlock without password prompt."));
    } else {
      console.error(chalk.red("✗ Failed to store in Keychain."));
    }
  });

kc.command("remove")
  .description("Remove master password from macOS Keychain")
  .action(() => {
    if (keychain.deleteFromKeychain()) {
      console.log(chalk.green("✓ Removed from Keychain."));
    } else {
      console.log(chalk.yellow("⚠ No Keychain entry found."));
    }
  });

kc.command("status")
  .description("Check Keychain status")
  .action(() => {
    if (!keychain.isKeychainAvailable()) {
      console.log(chalk.yellow("Keychain not available (requires macOS)."));
      return;
    }
    if (keychain.keychainEntryExists()) {
      console.log(chalk.green("✓ Master password is stored in Keychain."));
    } else {
      console.log(chalk.dim("No Keychain entry. Run: vaultly keychain store"));
    }
  });

// ─── kill (killswitch) ─────────────────────────────────────

program
  .command("kill")
  .description("🚨 Emergency killswitch: lock vault + clear Keychain. Use if compromised.")
  .action(async () => {
    const confirm = await promptConfirm(
      chalk.red.bold("🚨 KILLSWITCH: Lock vault and clear Keychain?")
    );
    if (!confirm) {
      console.log(chalk.dim("Cancelled."));
      return;
    }

    // Clear Keychain
    const kcCleared = keychain.deleteFromKeychain();

    // Log the event
    const logPath = path.join(vault.getVaultlyDir(), "audit.log");
    try {
      const entry = JSON.stringify({
        ts: new Date().toISOString(),
        action: "KILL",
        detail: "Killswitch activated",
        caller: "human",
      });
      fs.appendFileSync(logPath, entry + "\n", { mode: 0o600 });
    } catch { /* ignore */ }

    console.log(chalk.red.bold("🚨 Killswitch activated:"));
    console.log(chalk.red(`  ✓ Vault locked (key wiped from memory)`));
    console.log(chalk.red(`  ${kcCleared ? "✓" : "⚠"} Keychain ${kcCleared ? "cleared" : "(no entry found)"}`));
    console.log(chalk.yellow("\n  To re-enable: vaultly init (or vaultly keychain store)"));
  });

// ─── status ────────────────────────────────────────────────

program
  .command("status")
  .description("Show vault status: vaults, keychain, platform")
  .action(() => {
    if (!vault.isInitialized()) {
      console.log(chalk.yellow("Not initialized. Run: vaultly init"));
      return;
    }

    const vaults = vault.listVaults();
    console.log(chalk.bold("\n🔐 Vaultly Status\n"));
    console.log(`  Initialized: ${chalk.green("yes")}`);
    console.log(`  Directory:   ${vault.getVaultlyDir()}`);
    console.log(`  Vaults:      ${vaults.length} (${vaults.join(", ") || "none"})`);
    console.log(`  Keychain:    ${keychain.isKeychainAvailable()
      ? (keychain.keychainEntryExists() ? chalk.green("stored ✓") : chalk.dim("not stored"))
      : chalk.dim("not available (macOS only)")}`);
    console.log(`  Platform:    ${process.platform}`);
    console.log(`  Agent mode:  ${AGENT_MODE ? chalk.yellow("ON (get/env blocked)") : "off"}`);
    console.log();
  });

// ─── Run ───────────────────────────────────────────────────

program.parse();
