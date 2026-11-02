import type {
  Counts,
  FindingSummary,
  ScanSummary,
  Severity,
  VerificationState,
} from "../api/types";

/** Deterministic PRNG so the mock run is identical on every load. */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

interface Template {
  title: string;
  severity: Severity;
  tool: string;
  cwe: string;
  files: string[];
}

const TEMPLATES: Template[] = [
  { title: "SQL injection in repository query", severity: "critical", tool: "semgrep", cwe: "CWE-89", files: ["src/main/java/com/bookstore/dao/BookDao.java", "src/main/java/com/bookstore/dao/OrderDao.java"] },
  { title: "Reflected cross-site scripting", severity: "high", tool: "semgrep", cwe: "CWE-79", files: ["src/main/java/com/bookstore/web/SearchServlet.java", "src/main/webapp/search.jsp"] },
  { title: "Hardcoded database credential", severity: "critical", tool: "semgrep", cwe: "CWE-798", files: ["src/main/resources/application.properties"] },
  { title: "XML external entity expansion", severity: "high", tool: "semgrep", cwe: "CWE-611", files: ["src/main/java/com/bookstore/importer/CatalogParser.java"] },
  { title: "Unsafe deserialization of session cart", severity: "high", tool: "semgrep", cwe: "CWE-502", files: ["src/main/java/com/bookstore/cart/CartCodec.java"] },
  { title: "Path traversal in download handler", severity: "high", tool: "semgrep", cwe: "CWE-22", files: ["src/main/java/com/bookstore/web/DownloadServlet.java"] },
  { title: "Weak BCrypt cost factor", severity: "medium", tool: "semgrep", cwe: "CWE-916", files: ["src/main/java/com/bookstore/auth/PasswordService.java"] },
  { title: "Missing authorization on admin endpoint", severity: "high", tool: "semgrep", cwe: "CWE-862", files: ["src/main/java/com/bookstore/web/AdminServlet.java"] },
  { title: "Server-side request forgery in webhook fetch", severity: "medium", tool: "semgrep", cwe: "CWE-918", files: ["src/main/java/com/bookstore/notify/WebhookClient.java"] },
  { title: "Known vulnerable dependency: commons-fileupload", severity: "high", tool: "odc", cwe: "CWE-1104", files: ["pom.xml"] },
  { title: "Known vulnerable dependency: log4j-core", severity: "critical", tool: "odc", cwe: "CWE-1104", files: ["pom.xml"] },
  { title: "Known vulnerable dependency: jackson-databind", severity: "medium", tool: "odc", cwe: "CWE-1104", files: ["pom.xml"] },
  { title: "Cleartext HTTP form action", severity: "low", tool: "semgrep", cwe: "CWE-319", files: ["src/main/webapp/login.jsp"] },
  { title: "Verbose stack trace on error page", severity: "low", tool: "semgrep", cwe: "CWE-209", files: ["src/main/webapp/error.jsp"] },
  { title: "Cookie without Secure flag", severity: "medium", tool: "semgrep", cwe: "CWE-614", files: ["src/main/java/com/bookstore/web/SessionFilter.java"] },
  { title: "Open redirect after login", severity: "medium", tool: "semgrep", cwe: "CWE-601", files: ["src/main/java/com/bookstore/web/LoginServlet.java"] },
  { title: "LDAP injection in directory lookup", severity: "medium", tool: "semgrep", cwe: "CWE-90", files: ["src/main/java/com/bookstore/auth/LdapAuth.java"] },
  { title: "Insecure randomness for reset tokens", severity: "medium", tool: "semgrep", cwe: "CWE-338", files: ["src/main/java/com/bookstore/auth/TokenService.java"] },
  { title: "Debug endpoint exposed in profile", severity: "info", tool: "semgrep", cwe: "CWE-489", files: ["src/main/resources/application-dev.properties"] },
  { title: "Unvalidated redirect in OAuth callback", severity: "low", tool: "semgrep", cwe: "CWE-601", files: ["src/main/java/com/bookstore/web/OAuthCallback.java"] },
];

const STATUSES: VerificationState[] = ["confirmed", "unresolved", "unresolved", "rejected", "unprocessed", "unresolved", "confirmed", "unprocessed"];

function buildFindings(): FindingSummary[] {
  const rand = mulberry32(20261101);
  const out: FindingSummary[] = [];
  let n = 0;
  // Scripted run: exactly 60 findings, severity mix 4/14/22/14/6.
  const plan: Severity[] = [
    ...Array<Severity>(4).fill("critical"),
    ...Array<Severity>(14).fill("high"),
    ...Array<Severity>(22).fill("medium"),
    ...Array<Severity>(14).fill("low"),
    ...Array<Severity>(6).fill("info"),
  ];
  for (const severity of plan) {
    const pool = TEMPLATES.filter((t) => t.severity === severity);
    const t = pool[Math.floor(rand() * pool.length)];
    const file = t.files[Math.floor(rand() * t.files.length)];
    n += 1;
    out.push({
      id: `mock-f-${String(n).padStart(3, "0")}`,
      title: t.title,
      severity,
      status: STATUSES[Math.floor(rand() * STATUSES.length)],
      tool: t.tool,
      file,
      line: 20 + Math.floor(rand() * 400),
      cwe: t.cwe,
    });
  }
  return out;
}

export const MOCK_FINDINGS: FindingSummary[] = buildFindings();

export function mockCounts(items: FindingSummary[]): Counts {
  const counts: Counts = {
    total: items.length,
    confirmed: 0,
    rejected: 0,
    unresolved: 0,
    unprocessed: 0,
  };
  for (const f of items) counts[f.status] += 1;
  return counts;
}

export function mockSeverity(items: FindingSummary[]): Record<string, number> {
  const tally: Record<string, number> = {};
  for (const f of items) tally[f.severity] = (tally[f.severity] ?? 0) + 1;
  return tally;
}

export function mockTopCwe(items: FindingSummary[]): { cwe: string; count: number }[] {
  const tally = new Map<string, number>();
  for (const f of items) tally.set(f.cwe, (tally.get(f.cwe) ?? 0) + 1);
  return [...tally.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([cwe, count]) => ({ cwe, count }));
}

const STAGE_NAMES = ["intake", "scan", "hunt", "validate", "report"] as const;

export function mockScan(): ScanSummary {
  const now = new Date().toISOString();
  return {
    run_id: 7,
    repo: "https://github.com/example/jva-bookstore",
    commit: "9f3ac41b2e77d05c8f1a6d3b4c9e2f7081a5d6c3",
    status: "completed",
    gate: "fail",
    counts: mockCounts(MOCK_FINDINGS),
    severity: mockSeverity(MOCK_FINDINGS),
    top_cwe: mockTopCwe(MOCK_FINDINGS),
    stages: STAGE_NAMES.map((name, i) => ({
      name,
      status: "completed" as const,
      ordinal: i,
      message: "",
      started_at: now,
      completed_at: now,
    })),
    created_at: now,
  };
}

export const MOCK_SCANS: ScanSummary[] = [
  mockScan(),
  {
    ...mockScan(),
    run_id: 6,
    status: "completed",
    gate: "pass",
    counts: { total: 3, confirmed: 0, rejected: 2, unresolved: 0, unprocessed: 1 },
    created_at: new Date(Date.now() - 86400000).toISOString(),
  },
  {
    ...mockScan(),
    run_id: 5,
    status: "failed",
    gate: "unknown",
    counts: { total: 0, confirmed: 0, rejected: 0, unresolved: 0, unprocessed: 0 },
    stages: STAGE_NAMES.map((name, i) => ({
      name,
      status: (i < 2 ? "completed" : i === 2 ? "failed" : "pending") as "completed" | "failed" | "pending",
      ordinal: i,
      message: i === 2 ? "hunt budget exhausted" : "",
      started_at: new Date(Date.now() - 172800000).toISOString(),
      completed_at: null,
    })),
    created_at: new Date(Date.now() - 172800000).toISOString(),
  },
];
