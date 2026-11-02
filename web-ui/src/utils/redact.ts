/**
 * Client-side secret redaction for the Logs page.
 * Mirrors the server patterns in src/vulnscan/web/app.py — the server
 * redacts before responding, the SPA redacts again before render.
 */

const PATTERNS: [RegExp, string][] = [
  [/sk-[A-Za-z0-9]{8,}/g, "sk-***REDACTED***"],
  [/AKIA[0-9A-Z]{16}/g, "***REDACTED***"],
  [/xox[baprs]-[A-Za-z0-9-]{8,}/g, "***REDACTED***"],
  [
    /\b(api[_-]?key|secret|token|password|passwd)\s*[:=]\s*['"]?([^\s'",;}]+)/gi,
    "$1=***REDACTED***",
  ],
  [/Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi, "Bearer ***REDACTED***"],
];

/** Redact likely secret material from a single string (client-side). */
export function redactSecrets(text: string): string {
  let redacted = text;
  for (const [pattern, replacement] of PATTERNS) {
    // Fresh global regexes carry lastIndex state — reset before each use.
    pattern.lastIndex = 0;
    redacted = redacted.replace(pattern, replacement);
  }
  return redacted;
}

/** Recursively redact strings inside a JSON-like payload (client-side). */
export function redactValue<T>(value: T): T {
  if (typeof value === "string") return redactSecrets(value) as T;
  if (Array.isArray(value)) return value.map((item) => redactValue(item)) as T;
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      out[key] = redactValue(item);
    }
    return out as T;
  }
  return value;
}
