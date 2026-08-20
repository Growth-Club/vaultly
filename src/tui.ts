/**
 * Vaultly TUI — interactive menu for humans.
 *
 * `vaultly` (no args) or `vaultly tui` opens this. Everything routes through
 * the VaultEngine (same audit, policy, encryption as CLI/MCP).
 * Human-only: refused when VAULTLY_AGENT_MODE=1.
 */
import {
  select,
  input,
  password,
  confirm,
  Separator,
} from "@inquirer/prompts";
import chalk from "chalk";
import { VaultEngine } from "./engine.js";
import * as keychain from "./keychain.js";
import { TEMPLATES } from "./templates.js";

const AGENT_MODE = process.env.VAULTLY_AGENT_MODE === "1";

export async function startTui(): Promise<void> {
  if (AGENT_MODE) {
    console.error(
      chalk.red(
        "✗ The TUI is blocked in agent mode.\n" +
          "  Agents use: vaultly run <vault> -- <cmd>  or  vaultly mcp"
      )
    );
    process.exit(1);
  }

  if (!process.stdin.isTTY) {
    console.error(
      chalk.yellow("⚠ The TUI is interactive-only. Run it in a terminal (no pipes).")
    );
    process.exit(0);
  }

  const engine = new VaultEngine({ sessionTtlMinutes: 120 });

  if (!engine.isInitialized) {
    console.error(chalk.red("✗ Not initialized. Run: vaultly init"));
    process.exit(1);
  }

  // Unlock: macOS Keychain first, then password prompt
  const keychainPw = keychain.isKeychainAvailable() ? keychain.getFromKeychain() : null;
  if (keychainPw) {
    try {
      engine.unlock(keychainPw);
      console.log(chalk.dim("✓ Unlocked from Keychain\n"));
    } catch {
      // fall through to prompt
    }
  }
  if (!engine.isUnlocked) {
    let pw: string;
    try {
      pw = await password({ message: "🔑 Master password:" });
    } catch {
      process.exit(1);
    }
    try {
      engine.unlock(pw);
    } catch {
      console.error(chalk.red("✗ Wrong master password."));
      process.exit(1);
    }
  }

  console.log(chalk.cyan.bold("\n🔐 Vaultly") + chalk.dim(" — interactive"));
  console.log(chalk.dim("  arrow keys to navigate, enter to select, ctrl+c to exit\n"));

  // ─── Main loop ───────────────────────────────────────────
  for (;;) {
    const action = await select<string>({
      message: "What do you want to do?",
      pageSize: 14,
      choices: [
        new Separator("── Secrets ──"),
        { name: "📋  List vaults & keys", value: "list", description: "See what's stored (names only)" },
        { name: "➕  Add / update a secret", value: "add", description: "Encrypted, write-only for agents" },
        { name: "🔑  Read a secret value", value: "get", description: "Human-only" },
        { name: "🗑️  Delete secret or vault", value: "delete" },
        { name: "▶️  Run command with secrets", value: "run", description: "Output is scrubbed" },
        { name: "📦  Create vault from template", value: "template", description: "github, aws, stripe, ..." },
        new Separator("── Cloudflare ──"),
        { name: "☁️  Add Cloudflare account", value: "cf_add", description: "API token or global key" },
        { name: "🌐  List accounts & zones", value: "cf_zones" },
        { name: "🚀  Deploy a Worker", value: "cf_deploy" },
        { name: "🔐  Worker secrets", value: "cf_secrets", description: "list / set / delete" },
        new Separator("── System ──"),
        { name: "🔒  Keychain (auto-unlock)", value: "keychain" },
        { name: "📊  Status", value: "status" },
        { name: "🚪  Lock & exit", value: "exit" },
      ],
    });

    try {
      switch (action) {
        case "list": await tuiList(engine); break;
        case "add": await tuiAdd(engine); break;
        case "get": await tuiGet(engine); break;
        case "delete": await tuiDelete(engine); break;
        case "run": await tuiRun(engine); break;
        case "template": await tuiTemplate(engine); break;
        case "cf_add": await tuiCfAdd(engine); break;
        case "cf_zones": await tuiCfZones(engine); break;
        case "cf_deploy": await tuiCfDeploy(engine); break;
        case "cf_secrets": await tuiCfSecrets(engine); break;
        case "keychain": await tuiKeychain(); break;
        case "status": tuiStatus(engine); break;
        case "exit":
          engine.lock();
          console.log(chalk.dim("\n🔒 Vault locked. Bye!\n"));
          process.exit(0);
      }
    } catch (err: any) {
      console.error(chalk.red(`✗ ${err.message}`));
    }
    console.log();
  }
}

// ─── Vault helpers ────────────────────────────────────────

async function pickVault(engine: VaultEngine, message = "Vault:"): Promise<string> {
  const vaults = engine.listVaults();
  if (vaults.length === 0) {
    const name = await input({ message: "No vaults yet. New vault name:" });
    return name.trim();
  }
  return select({
    message,
    choices: [
      ...vaults.map((v) => ({ name: v, value: v })),
      new Separator(),
      { name: "➕  New vault...", value: "__new__" },
    ],
  });
}

async function pickKey(engine: VaultEngine, vaultName: string): Promise<string> {
  const keys = engine.listKeys(vaultName);
  return select({
    message: `Key in '${vaultName}':`,
    choices: keys.map((k) => ({ name: k, value: k })),
  });
}

// ─── Actions ──────────────────────────────────────────────

async function tuiList(engine: VaultEngine): Promise<void> {
  const vaults = engine.listVaults();
  if (vaults.length === 0) {
    console.log(chalk.dim("No vaults yet. Pick 'Add a secret' to create one."));
    return;
  }
  for (const v of vaults) {
    const keys = engine.listKeys(v);
    console.log(
      chalk.cyan(`  ${v}`) +
        (keys.length ? chalk.dim(` — ${keys.join(", ")}`) : chalk.dim(" — (empty)"))
    );
  }
}

async function tuiAdd(engine: VaultEngine): Promise<void> {
  const vaultName = await pickVault(engine, "Vault to store in:");
  const key = await input({ message: "Secret name (e.g. GITHUB_TOKEN):" });
  const value = await password({ message: `Value for ${key} (hidden):` });
  if (!key.trim() || !value) {
    console.error(chalk.red("✗ Name and value are required."));
    return;
  }
  engine.addSecret(vaultName, key.trim(), value);
  console.log(chalk.green(`✓ Stored '${key}' in '${vaultName}'`));
}

async function tuiGet(engine: VaultEngine): Promise<void> {
  const vaultName = await pickVault(engine, "Vault:");
  const key = await pickKey(engine, vaultName);
  const value = engine.getSecretValue(vaultName, key);
  console.log(chalk.green(`  ${key}: ${value}`));
}

async function tuiDelete(engine: VaultEngine): Promise<void> {
  const vaults = engine.listVaults();
  if (vaults.length === 0) {
    console.log(chalk.dim("Nothing to delete."));
    return;
  }
  const vaultName = await pickVault(engine, "Delete from vault:");
  const keys = engine.listKeys(vaultName);
  const choice = await select({
    message: `Delete what from '${vaultName}'?`,
    choices: [
      ...keys.map((k) => ({ name: `Secret: ${k}`, value: `k:${k}` })),
      new Separator(),
      { name: `🚨  Whole vault '${vaultName}'`, value: "vault" },
    ],
  });
  if (choice === "vault") {
    const yes = await confirm({ message: `Really delete vault '${vaultName}'? This cannot be undone.` });
    if (!yes) return;
    engine.deleteVault(vaultName);
    console.log(chalk.green(`✓ Deleted vault '${vaultName}'`));
  } else {
    engine.deleteSecret(vaultName, choice.slice(2));
    console.log(chalk.green(`✓ Deleted '${choice.slice(2)}'`));
  }
}

async function tuiRun(engine: VaultEngine): Promise<void> {
  const vaultName = await pickVault(engine, "Vault to inject:");
  const command = await input({ message: "Command (e.g. npx wrangler deploy):" });
  if (!command.trim()) return;
  console.log(chalk.dim(`▶ ${command}\n`));
  const result = await engine.runCommand(vaultName, command.trim());
  console.log(result.stdout);
  if (result.stderr) console.error(result.stderr);
  if (result.scrubbed) console.log(chalk.yellow("⚠ Secret values were scrubbed from output."));
  console.log(chalk.dim(`Exit code: ${result.code}`));
}

async function tuiTemplate(engine: VaultEngine): Promise<void> {
  const name = await select({
    message: "Template:",
    pageSize: 16,
    choices: Object.entries(TEMPLATES).map(([n, t]) => ({
      name: `${n.padEnd(14)} ${chalk.dim(t.description)}`,
      value: n,
    })),
  });
  const tpl = TEMPLATES[name];
  let vaultName = name;
  if (name !== "custom") {
    const keep = await confirm({ message: `Use vault name '${name}'?` });
    if (!keep) vaultName = (await input({ message: "Vault name:" })).trim();
  } else {
    vaultName = (await input({ message: "Vault name:" })).trim();
  }
  const keys = tpl.keys.length
    ? tpl.keys
    : (await input({ message: "Custom key names (comma-separated, e.g. A,B,C):" }))
        .split(",")
        .map((k) => k.trim())
        .filter(Boolean);

  for (const k of keys) {
    const value = await password({ message: `  ${k}:` });
    if (value) engine.addSecret(vaultName, k, value);
  }
  console.log(chalk.green(`✓ Vault '${vaultName}' created with ${keys.length} secret(s)`));
}

async function tuiCfAdd(engine: VaultEngine): Promise<void> {
  const name = await input({ message: "Account name (e.g. personal, work):" });
  const vaultName = name.startsWith("cf-") ? name.trim() : `cf-${name.trim()}`;
  const method = await select({
    message: "Auth method:",
    choices: [
      { name: "API token (recommended, scoped)", value: "token" },
      { name: "Global API key (email + key)", value: "global" },
    ],
  });
  if (method === "token") {
    const token = await password({ message: "CLOUDFLARE_API_TOKEN:" });
    if (token) engine.addSecret(vaultName, "CLOUDFLARE_API_TOKEN", token);
  } else {
    const email = await input({ message: "CLOUDFLARE_EMAIL:" });
    const apiKey = await password({ message: "CLOUDFLARE_API_KEY:" });
    if (email && apiKey) {
      engine.addSecret(vaultName, "CLOUDFLARE_EMAIL", email);
      engine.addSecret(vaultName, "CLOUDFLARE_API_KEY", apiKey);
    }
  }
  const accountId = await input({ message: "CLOUDFLARE_ACCOUNT_ID:" });
  if (accountId) engine.addSecret(vaultName, "CLOUDFLARE_ACCOUNT_ID", accountId);
  console.log(chalk.green(`✓ Cloudflare account '${vaultName}' saved`));
}

async function tuiCfZones(engine: VaultEngine): Promise<void> {
  const cfVaults = engine.listVaults().filter((v) => v.startsWith("cf-"));
  if (cfVaults.length === 0) {
    console.log(chalk.dim("No Cloudflare accounts. Add one first."));
    return;
  }
  const vaultName = await select({ message: "Account:", choices: cfVaults.map((v) => ({ name: v, value: v })) });
  const r = await engine.cloudflareApi(vaultName, "GET", "/zones?per_page=50");
  const zones = ((r.data as any)?.result || []) as any[];
  if (!zones.length) {
    console.log(chalk.dim("No zones found (check token permissions)."));
    return;
  }
  for (const z of zones) {
    console.log(`  ${chalk.green(z.name)} ${chalk.dim(`(${z.status}, id=${z.id})`)}`);
  }
}

async function tuiCfDeploy(engine: VaultEngine): Promise<void> {
  const cfVaults = engine.listVaults().filter((v) => v.startsWith("cf-"));
  if (cfVaults.length === 0) {
    console.log(chalk.dim("No Cloudflare accounts. Add one first."));
    return;
  }
  const vaultName = await select({ message: "Account:", choices: cfVaults.map((v) => ({ name: v, value: v })) });
  const projectDir = await input({ message: "Worker project directory:" });
  if (!projectDir.trim()) return;
  const result = await engine.runCommand(vaultName, "npx wrangler deploy", { cwd: projectDir.trim() });
  console.log(result.stdout);
  if (result.stderr) console.error(result.stderr);
  console.log(chalk.dim(`Exit code: ${result.code}`));
}

async function tuiCfSecrets(engine: VaultEngine): Promise<void> {
  const cfVaults = engine.listVaults().filter((v) => v.startsWith("cf-"));
  if (cfVaults.length === 0) {
    console.log(chalk.dim("No Cloudflare accounts. Add one first."));
    return;
  }
  const vaultName = await select({ message: "Account:", choices: cfVaults.map((v) => ({ name: v, value: v })) });
  const scriptName = await input({ message: "Worker script name:" });
  if (!scriptName.trim()) return;
  const action = await select({
    message: `Secrets for '${scriptName}':`,
    choices: [
      { name: "📋  List", value: "list" },
      { name: "➕  Set a secret", value: "set" },
      { name: "🗑️  Delete a secret", value: "delete" },
    ],
  });
  if (action === "list") {
    const r = await engine.workerSecrets(vaultName, scriptName.trim(), "list");
    const names = ((r.data as any)?.result || []) as any[];
    console.log(
      names.length
        ? names.map((s: any) => `  - ${s.name}`).join("\n")
        : chalk.dim("No secrets on this Worker.")
    );
    return;
  }
  const name = await input({ message: "Secret name:" });
  if (!name.trim()) return;
  if (action === "set") {
    const value = await password({ message: `Value for ${name} (hidden):` });
    if (!value) return;
    await engine.workerSecrets(vaultName, scriptName.trim(), "set", name.trim(), value);
    console.log(chalk.green(`✓ Set '${name}' on '${scriptName}'`));
  } else {
    await engine.workerSecrets(vaultName, scriptName.trim(), "delete", name.trim());
    console.log(chalk.green(`✓ Deleted '${name}' from '${scriptName}'`));
  }
}

async function tuiKeychain(): Promise<void> {
  if (!keychain.isKeychainAvailable()) {
    console.log(chalk.dim("Keychain not available (macOS only)."));
    return;
  }
  const hasEntry = keychain.keychainEntryExists();
  const action = await select({
    message: hasEntry ? "Keychain entry exists. What next?" : "No keychain entry yet.",
    choices: [
      ...(hasEntry
        ? [{ name: "🗑️  Remove entry (password needed every time)", value: "remove" }]
        : []),
      { name: "🔒  Store master password (auto-unlock)", value: "store" },
      { name: "📊  Status", value: "status" },
    ],
  });
  if (action === "store") {
    const pw = await password({ message: "Master password to store:" });
    if (keychain.storeInKeychain(pw)) {
      console.log(chalk.green("✓ Stored — MCP server and TUI will auto-unlock."));
    } else {
      console.error(chalk.red("✗ Failed to store in Keychain."));
    }
  } else if (action === "remove") {
    keychain.deleteFromKeychain();
    console.log(chalk.green("✓ Removed from Keychain."));
  } else {
    tuiKeychainStatus();
  }
}

function tuiKeychainStatus(): void {
  console.log(
    keychain.keychainEntryExists()
      ? chalk.green("  Keychain: stored ✓")
      : chalk.dim("  Keychain: not stored")
  );
}

function tuiStatus(engine: VaultEngine): void {
  const vaults = engine.listVaults();
  const ttlMin = Math.round(engine.sessionExpiresIn / 60000);
  console.log(`  Unlocked: ${chalk.green("yes")} (expires in ${ttlMin} min)`);
  console.log(`  Vaults:   ${vaults.length} (${vaults.join(", ") || "none"})`);
  console.log(
    `  Keychain: ${keychain.isKeychainAvailable()
      ? keychain.keychainEntryExists()
        ? chalk.green("stored ✓")
        : chalk.dim("not stored")
      : chalk.dim("not available (macOS only)")}`
  );
  console.log(`  Directory: ${process.env.VAULTLY_DIR || "~/.vaultly"}`);
}