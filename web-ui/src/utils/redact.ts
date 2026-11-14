/**
 * Che giấu secret phía client cho trang Logs.
 * Phản chiếu các mẫu phía server trong src/vulnscan/web/app.py — server
 * che giấu trước khi phản hồi, SPA che giấu lại trước khi render.
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

/** Che giấu nội dung có khả năng là secret khỏi một chuỗi đơn lẻ (phía client). */
export function redactSecrets(text: string): string {
  let redacted = text;
  for (const [pattern, replacement] of PATTERNS) {
    // Regex global mới giữ trạng thái lastIndex — reset trước mỗi lần dùng.
    pattern.lastIndex = 0;
    redacted = redacted.replace(pattern, replacement);
  }
  return redacted;
}

/** Che giấu đệ quy các chuỗi bên trong payload dạng JSON (phía client). */
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
