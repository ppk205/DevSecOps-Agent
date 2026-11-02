import { describe, expect, it } from "vitest";
import { redactSecrets, redactValue } from "../redact";

const FAKE_KEY = "sk-FAKEKEY1234567890abcdef";

describe("redactSecrets (client-side)", () => {
  it("redacts openai-style keys", () => {
    expect(redactSecrets(`calling with ${FAKE_KEY} now`)).not.toContain(FAKE_KEY);
    expect(redactSecrets(`calling with ${FAKE_KEY} now`)).toContain("sk-***REDACTED***");
  });

  it("redacts key=value assignments", () => {
    const line = `deploy failed: api_key=${FAKE_KEY} rejected`;
    const redacted = redactSecrets(line);
    expect(redacted).not.toContain(FAKE_KEY);
    expect(redacted).toContain("api_key=***REDACTED***");
  });

  it("redacts bearer tokens and leaves plain text alone", () => {
    expect(redactSecrets("Authorization: Bearer abcDEF123._-~/xyz==")).toContain("Bearer ***REDACTED***");
    expect(redactSecrets("semgrep: 41 raw observations")).toBe("semgrep: 41 raw observations");
  });
});

describe("redactValue (client-side)", () => {
  it("redacts nested payloads without changing shape", () => {
    const out = redactValue({ note: "ok", auth: { token: `x=${FAKE_KEY}` }, tags: ["a", FAKE_KEY] });
    expect(JSON.stringify(out)).not.toContain(FAKE_KEY);
    expect((out.auth as { token: string }).token).toContain("***REDACTED***");
    expect(out.note).toBe("ok");
  });
});
