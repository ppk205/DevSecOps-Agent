import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

// The suite runs in mock mode by default; these cases need the real fetch path.
async function saveKey(profile: string) {
  const client = await import("../client");
  return client.saveKey(profile, { api_key: "k" });
}

beforeEach(() => {
  vi.stubEnv("VITE_MOCK", "0");
  vi.resetModules();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("API client errors", () => {
  it("includes the server's detail so the user sees why a save failed", async () => {
    const detail = "Invalid profile ID: use 3-64 lowercase letters, digits or hyphens";
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(json({ csrf_token: "t" }))
        .mockResolvedValueOnce(json({ detail }, 422)),
    );

    await expect(saveKey("deepseek_test")).rejects.toThrow(detail);
  });

  it("falls back to the status when the body has no string detail", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(json({ csrf_token: "t" }))
        .mockResolvedValueOnce(new Response("oops", { status: 500 })),
    );

    await expect(saveKey("x-y-z")).rejects.toThrow(/→ 500$/);
  });
});
