/**
 * Test setup — redirect all vault storage to a temp dir BEFORE modules load.
 * vault.ts reads VAULTLY_DIR at import time, so this must run first.
 */
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

process.env.VAULTLY_DIR = mkdtempSync(path.join(tmpdir(), "vaultly-test-"));