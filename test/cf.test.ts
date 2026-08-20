import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import { VaultEngine } from "../src/engine.js";
import { initVault } from "../src/vault.js";
import type { CallerContext } from "../src/policy.js";

const dir = () => process.env.VAULTLY_DIR!;
const PASSWORD = "test-master-password";
const agentCtx: CallerContext = { caller: "agent", agentName: "test-agent" };

const TOKEN = "cf-token-abcdef123456";
const EMAIL = "admin@example.com";
const API_KEY = "cf-global-key-secret";
const ACCOUNT = "acc-123";

function mockFetch(json: unknown, status = 200) {
  return vi.fn(async () => new Response(JSON.stringify(json), { status })) as any;
}

describe("engine cloudflare auth modes", () => {
  let engine: VaultEngine;
  let fetchMock: ReturnType<typeof mockFetch>;
  const origFetch = globalThis.fetch;

  beforeEach(() => {
    fs.rmSync(dir(), { recursive: true, force: true });
    fs.mkdirSync(dir(), { recursive: true });
    engine = new VaultEngine();
    initVault(PASSWORD);
    engine.unlock(PASSWORD);
  });

  afterEach(() => {
    engine.lock();
    globalThis.fetch = origFetch;
    vi.restoreAllMocks();
    fs.rmSync(dir(), { recursive: true, force: true });
  });

  it("sends Bearer token auth when CLOUDFLARE_API_TOKEN is present", async () => {
    engine.addSecret("cf", "CLOUDFLARE_API_TOKEN", TOKEN, agentCtx);
    fetchMock = mockFetch({ success: true, result: [] });
    globalThis.fetch = fetchMock;

    const r = await engine.cloudflareApi("cf", "GET", "/zones", undefined, agentCtx);
    expect(r.status).toBe(200);
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toMatch(/\/client\/v4\/zones$/);
    expect(init.headers).toMatchObject({ Authorization: `Bearer ${TOKEN}` });
    expect(init.headers["X-Auth-Email"]).toBeUndefined();
  });

  it("sends X-Auth-Email/X-Auth-Key when global key credentials are present", async () => {
    engine.addSecret("cf", "CLOUDFLARE_EMAIL", EMAIL, agentCtx);
    engine.addSecret("cf", "CLOUDFLARE_API_KEY", API_KEY, agentCtx);
    fetchMock = mockFetch({ success: true, result: [] });
    globalThis.fetch = fetchMock;

    await engine.cloudflareApi("cf", "GET", "/zones", undefined, agentCtx);
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toMatch(/\/client\/v4\/zones$/);
    expect(init.headers).toMatchObject({ "X-Auth-Email": EMAIL, "X-Auth-Key": API_KEY });
    expect(init.headers.Authorization).toBeUndefined();
  });

  it("throws a helpful error when no CF credentials exist", async () => {
    engine.addSecret("cf", "SOMETHING_ELSE", "x", agentCtx);
    await expect(engine.cloudflareApi("cf", "GET", "/zones", undefined, agentCtx)).rejects.toThrow(
      /No Cloudflare credentials/
    );
    await expect(
      engine.cloudflareApi("cf", "GET", "/zones", undefined, agentCtx)
    ).rejects.toThrow(/CLOUDFLARE_EMAIL \+ CLOUDFLARE_API_KEY/);
  });

  it("scrubs credentials from API responses", async () => {
    engine.addSecret("cf", "CLOUDFLARE_EMAIL", EMAIL, agentCtx);
    engine.addSecret("cf", "CLOUDFLARE_API_KEY", API_KEY, agentCtx);
    fetchMock = mockFetch({ success: true, result: { echo: EMAIL, key: API_KEY } });
    globalThis.fetch = fetchMock;

    const r = await engine.cloudflareApi("cf", "GET", "/zones", undefined, agentCtx);
    const text = JSON.stringify(r.data);
    expect(text).not.toContain(EMAIL);
    expect(text).not.toContain(API_KEY);
  });

  it("healthCheck verifies tokens via /user/tokens/verify", async () => {
    engine.addSecret("cf", "CLOUDFLARE_API_TOKEN", TOKEN, agentCtx);
    fetchMock = mockFetch({ success: true, result: { status: "active" } });
    globalThis.fetch = fetchMock;

    const r = await engine.healthCheck("cf", agentCtx);
    expect(r.ok).toBe(true);
    expect(String(fetchMock.mock.calls[0][0])).toMatch(/\/user\/tokens\/verify$/);
  });

  it("healthCheck verifies global keys via /user", async () => {
    engine.addSecret("cf", "CLOUDFLARE_EMAIL", EMAIL, agentCtx);
    engine.addSecret("cf", "CLOUDFLARE_API_KEY", API_KEY, agentCtx);
    fetchMock = mockFetch({ success: true, result: { email: EMAIL } });
    globalThis.fetch = fetchMock;

    const r = await engine.healthCheck("cf", agentCtx);
    expect(r.ok).toBe(true);
    expect(String(fetchMock.mock.calls[0][0])).toMatch(/\/client\/v4\/user$/);
  });

  it("listWorkers works with global key auth", async () => {
    engine.addSecret("cf", "CLOUDFLARE_EMAIL", EMAIL, agentCtx);
    engine.addSecret("cf", "CLOUDFLARE_API_KEY", API_KEY, agentCtx);
    engine.addSecret("cf", "CLOUDFLARE_ACCOUNT_ID", ACCOUNT, agentCtx);
    fetchMock = mockFetch({ success: true, result: [{ id: "worker-a" }, { id: "worker-b" }] });
    globalThis.fetch = fetchMock;

    const r = await engine.listWorkers("cf", agentCtx);
    expect(r.workers).toEqual(["worker-a", "worker-b"]);
    const [, init] = fetchMock.mock.calls[0];
    expect(init.headers).toMatchObject({ "X-Auth-Email": EMAIL, "X-Auth-Key": API_KEY });
  });

  it("workerSecrets lists secret names (never values)", async () => {
    engine.addSecret("cf", "CLOUDFLARE_API_TOKEN", TOKEN, agentCtx);
    engine.addSecret("cf", "CLOUDFLARE_ACCOUNT_ID", ACCOUNT, agentCtx);
    fetchMock = mockFetch({ success: true, result: [{ name: "API_KEY" }, { name: "DB_URL" }] });
    globalThis.fetch = fetchMock;

    const r = await engine.workerSecrets("cf", "my-worker", "list", undefined, undefined, agentCtx);
    expect(r.status).toBe(200);
    const [url] = fetchMock.mock.calls[0];
    expect(String(url)).toMatch(/\/workers\/scripts\/my-worker\/secrets$/);
    expect((r.data as any).result.map((s: any) => s.name)).toEqual(["API_KEY", "DB_URL"]);
  });

  it("workerSecrets sets a secret (value sent, never echoed back)", async () => {
    engine.addSecret("cf", "CLOUDFLARE_API_TOKEN", TOKEN, agentCtx);
    engine.addSecret("cf", "CLOUDFLARE_ACCOUNT_ID", ACCOUNT, agentCtx);
    fetchMock = mockFetch({ success: true, result: { name: "MY_SECRET" } });
    globalThis.fetch = fetchMock;

    const r = await engine.workerSecrets("cf", "my-worker", "set", "MY_SECRET", "raw-value-777", agentCtx);
    expect(r.status).toBe(200);
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toMatch(/\/workers\/scripts\/my-worker\/secrets$/);
    expect(init.method).toBe("PUT");
    expect(JSON.parse(init.body)).toEqual({ name: "MY_SECRET", text: "raw-value-777" });
    expect(JSON.stringify(r.data)).not.toContain("raw-value-777");
  });

  it("workerSecrets deletes a secret", async () => {
    engine.addSecret("cf", "CLOUDFLARE_API_TOKEN", TOKEN, agentCtx);
    engine.addSecret("cf", "CLOUDFLARE_ACCOUNT_ID", ACCOUNT, agentCtx);
    fetchMock = mockFetch({ success: true, result: { id: "deleted" } });
    globalThis.fetch = fetchMock;

    const r = await engine.workerSecrets("cf", "my-worker", "delete", "MY_SECRET", undefined, agentCtx);
    expect(r.status).toBe(200);
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toMatch(/\/workers\/scripts\/my-worker\/secrets\/MY_SECRET$/);
    expect(init.method).toBe("DELETE");
  });

  it("workerSecrets requires name for set/delete and value for set", async () => {
    engine.addSecret("cf", "CLOUDFLARE_API_TOKEN", TOKEN, agentCtx);
    engine.addSecret("cf", "CLOUDFLARE_ACCOUNT_ID", ACCOUNT, agentCtx);
    await expect(engine.workerSecrets("cf", "w", "set", undefined, undefined, agentCtx)).rejects.toThrow(
      /name.*required/
    );
    await expect(engine.workerSecrets("cf", "w", "set", "K", undefined, agentCtx)).rejects.toThrow(
      /value.*required/
    );
    await expect(engine.workerSecrets("cf", "w", "delete", undefined, undefined, agentCtx)).rejects.toThrow(
      /name.*required/
    );
  });
});