import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import worker, { safeEqual } from "../src/index.js";

const TOKEN = "backup-secret-token";
const BACKUP_BODY = JSON.stringify({
  vaults: { github: { version: 1, iv: "ab", authTag: "cd", data: "ef", updatedAt: "x" } },
});

function makeEnv(kv?: Partial<{ put: any; get: any }>) {
  return {
    VAULTLY_KV: {
      put: kv?.put ?? vi.fn().mockResolvedValue(undefined),
      get: kv?.get ?? vi.fn().mockResolvedValue(null),
    },
    BACKUP_TOKEN: TOKEN,
  } as any;
}

function req(url: string, init?: RequestInit, env?: any): Promise<Response> {
  return worker.fetch(new Request(`https://vaultly-backup.example${url}`, init), env ?? makeEnv());
}

describe("safeEqual", () => {
  it("returns true for identical strings", () => {
    expect(safeEqual("abc123", "abc123")).toBe(true);
  });

  it("returns false for different lengths", () => {
    expect(safeEqual("abc", "abcd")).toBe(false);
  });

  it("returns false for same-length different strings", () => {
    expect(safeEqual("abc123", "abc124")).toBe(false);
  });

  it("handles empty strings", () => {
    expect(safeEqual("", "")).toBe(true);
    expect(safeEqual("", "x")).toBe(false);
  });
});

describe("backup worker", () => {
  let kv: { put: any; get: any };

  beforeEach(() => {
    kv = { put: vi.fn().mockResolvedValue(undefined), get: vi.fn().mockResolvedValue(null) };
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("answers /health without auth", async () => {
    const res = await req("/health");
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ status: "ok" });
  });

  it("handles CORS preflight", async () => {
    const res = await req("/backup", { method: "OPTIONS" });
    expect(res.status).toBe(200);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
  });

  it("rejects PUT /backup with a missing token", async () => {
    const res = await req("/backup", { method: "PUT", body: BACKUP_BODY });
    expect(res.status).toBe(401);
    expect(kv.put).not.toHaveBeenCalled();
  });

  it("rejects PUT /backup with a wrong token", async () => {
    const res = await req("/backup", {
      method: "PUT",
      body: BACKUP_BODY,
      headers: { Authorization: "Bearer wrong-token" },
    });
    expect(res.status).toBe(401);
    expect(kv.put).not.toHaveBeenCalled();
  });

  it("rejects PUT /backup with invalid JSON", async () => {
    const res = await req("/backup", {
      method: "PUT",
      body: "not-json",
      headers: { Authorization: `Bearer ${TOKEN}` },
    });
    expect(res.status).toBe(400);
    expect(kv.put).not.toHaveBeenCalled();
  });

  it("rejects PUT /backup without a vaults key", async () => {
    const res = await req("/backup", {
      method: "PUT",
      body: JSON.stringify({ nope: true }),
      headers: { Authorization: `Bearer ${TOKEN}` },
    });
    expect(res.status).toBe(400);
  });

  it("stores a valid backup on PUT", async () => {
    const env = { VAULTLY_KV: kv, BACKUP_TOKEN: TOKEN } as any;
    const res = await req(
      "/backup",
      {
        method: "PUT",
        body: BACKUP_BODY,
        headers: { Authorization: `Bearer ${TOKEN}` },
      },
      env
    );
    expect(res.status).toBe(200);
    expect(kv.put).toHaveBeenCalledWith("vaultly-backup", BACKUP_BODY, expect.objectContaining({ metadata: expect.any(Object) }));
  });

  it("rejects oversized payloads", async () => {
    const big = JSON.stringify({ vaults: { x: "a".repeat(6 * 1024 * 1024) } });
    const env = { VAULTLY_KV: kv, BACKUP_TOKEN: TOKEN } as any;
    const res = await req(
      "/backup",
      {
        method: "PUT",
        body: big,
        headers: { Authorization: `Bearer ${TOKEN}`, "Content-Length": String(big.length) },
      },
      env
    );
    expect(res.status).toBe(413);
    expect(kv.put).not.toHaveBeenCalled();
  });

  it("rejects oversized payloads even without a Content-Length header", async () => {
    const big = JSON.stringify({ vaults: { x: "a".repeat(6 * 1024 * 1024) } });
    const env = { VAULTLY_KV: kv, BACKUP_TOKEN: TOKEN } as any;
    const res = await req(
      "/backup",
      {
        method: "PUT",
        body: big,
        headers: { Authorization: `Bearer ${TOKEN}` },
      },
      env
    );
    expect(res.status).toBe(413);
    expect(kv.put).not.toHaveBeenCalled();
  });

  it("returns 404 on GET when no backup exists", async () => {
    const res = await req("/backup", {
      headers: { Authorization: `Bearer ${TOKEN}` },
    });
    expect(res.status).toBe(404);
  });

  it("returns the stored backup on GET", async () => {
    kv.get.mockResolvedValue(BACKUP_BODY);
    const env = { VAULTLY_KV: kv, BACKUP_TOKEN: TOKEN } as any;
    const res = await worker.fetch(
      new Request("https://vaultly-backup.example/backup", {
        headers: { Authorization: `Bearer ${TOKEN}` },
      }),
      env
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(BACKUP_BODY);
  });

  it("returns 404 for unknown routes", async () => {
    const res = await req("/nope", {
      headers: { Authorization: `Bearer ${TOKEN}` },
    });
    expect(res.status).toBe(404);
  });
});