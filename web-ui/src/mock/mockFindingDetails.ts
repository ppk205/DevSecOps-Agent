import type {
  AiAssessment,
  CodeBlock,
  FindingDetail,
  FindingListItem,
  FindingsQuery,
  ObservationDetail,
  VerificationCheck,
} from "../api/types";
import { applyFindingFilters } from "../api/findingsQuery";
import { MOCK_FINDINGS } from "./mockRun";

/** Mock code excerpts per CWE (scripted fiction for mock mode only). */
const SNIPPETS: Record<string, string[]> = {
  "CWE-89": [
    "String q = \"SELECT * FROM books WHERE title LIKE '%\" + query + \"%'\";",
    "try (Statement st = conn.createStatement();",
    "     ResultSet rs = st.executeQuery(q)) {",
    "  while (rs.next()) { results.add(mapRow(rs)); }",
    "}",
    "// FIX: use a prepared statement with a bound parameter",
    "try (PreparedStatement ps = conn.prepareStatement(",
    "    \"SELECT * FROM books WHERE title LIKE ?\")) {",
    "  ps.setString(1, \"%\" + query + \"%\");",
    "  try (ResultSet rs = ps.executeQuery()) { results.addAll(mapAll(rs)); }",
    "}",
  ],
  "CWE-79": [
    "String name = request.getParameter(\"q\");",
    "out.println(\"<p>Results for \" + name + \"</p>\");",
    "// FIX: HTML-escape untrusted input before reflecting it",
    "out.println(\"<p>Results for \" + esc(name) + \"</p>\");",
  ],
  "CWE-798": [
    "spring.datasource.username=bookstore",
    "spring.datasource.password=s3cr3t-prod-password",
    "// FIX: read the credential from the environment at boot",
    "spring.datasource.password=${DB_PASSWORD}",
  ],
  "CWE-611": [
    "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();",
    "Document doc = dbf.newDocumentBuilder().parse(upload);",
    "// FIX: disallow DOCTYPE before parsing untrusted XML",
    "dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);",
  ],
  "CWE-502": [
    "byte[] blob = cartCookie.getValue().getBytes(UTF_8);",
    "Object cart = new ObjectInputStream(new ByteArrayInputStream(blob)).readObject();",
    "// FIX: deserialize a signed token into a known-safe DTO instead",
  ],
  "CWE-22": [
    "String name = request.getParameter(\"file\");",
    "Path target = DOWNLOAD_DIR.resolve(name).normalize();",
    "Files.copy(target, response.getOutputStream());",
    "// FIX: reject paths that escape DOWNLOAD_DIR after normalize()",
  ],
  "CWE-1104": [
    "<dependency>",
    "  <groupId>org.apache.logging.log4j</groupId>",
    "  <artifactId>log4j-core</artifactId>",
    "  <version>2.14.0</version>",
    "</dependency>",
    "<!-- FIX: upgrade to 2.17.1+ (CVE-2021-44228, CVE-2021-45046) -->",
  ],
};

function snippetFor(cwe: string): string[] {
  return (
    SNIPPETS[cwe] ?? [
      "// evidence excerpt for the reported location",
      "handler(request); // sink reached with untrusted input",
      "// FIX: apply the recommended hardening for this CWE",
    ]
  );
}

function hashSeed(text: string): number {
  let h = 2166136261;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

const EXTRA_TOOL = ["spotbugs", "codeql", "gitleaks"];
const CVSS_BY_SEVERITY: Record<string, string> = {
  critical: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
  high: "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N",
  medium: "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:P/VC:L/VI:L/VA:N",
  low: "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:P/VC:L/VI:N/VA:N",
  info: "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:P/VC:N/VI:N/VA:N",
};

/** Enriched table rows derived from the scripted 60-finding run. */
export const MOCK_FINDING_ITEMS: FindingListItem[] = MOCK_FINDINGS.map((f) => {
  const seed = hashSeed(f.id);
  const scanners = f.tool === "odc" ? ["owasp-dependency-check"] : [f.tool];
  if (seed % 5 === 0 && scanners[0] !== "spotbugs") scanners.push(EXTRA_TOOL[seed % EXTRA_TOOL.length]);
  const order = ["critical", "high", "medium", "low", "info"];
  const aiSeverity =
    seed % 3 === 0
      ? order[Math.min(order.length - 1, Math.max(0, order.indexOf(f.severity) + (seed % 2 === 0 ? -1 : 1)))]
      : f.severity;
  const changed = aiSeverity !== f.severity;
  return {
    id: f.id,
    title: f.title,
    severity: f.severity,
    scanner_severity: f.severity,
    ai_severity: seed % 4 === 3 ? null : aiSeverity,
    ai_changed: seed % 4 === 3 ? false : changed,
    cwe: f.cwe,
    status: f.status,
    scanners,
    file: f.file,
    line: f.line,
    origin: f.cwe === "CWE-1104" ? "dependency" : "source",
  };
});

/** Filtered mock findings (mirrors the live query params, paged). */
export function mockFilteredFindings(scanId: number, query: FindingsQuery) {
  const source = scanId === 7 ? MOCK_FINDING_ITEMS : [];
  const { total, items } = applyFindingFilters(source, {
    ...query,
    pageSize: 10_000,
    page: 1,
  });
  const pageSize = query.pageSize ?? 50;
  const page = Math.max(1, query.page ?? 1);
  return {
    run_id: scanId,
    total,
    page,
    page_size: pageSize,
    items: items.slice((page - 1) * pageSize, page * pageSize),
  };
}

function mockAi(item: FindingListItem): AiAssessment | null {
  if (!item.ai_severity) return null;
  return {
    proposed_severity: item.ai_severity,
    proposed_status: item.status === "confirmed" ? "confirmed" : "unresolved",
    cvss: {
      vector: CVSS_BY_SEVERITY[item.ai_severity] ?? CVSS_BY_SEVERITY.info,
      base_score: item.ai_severity === "critical" ? 9.3 : item.ai_severity === "high" ? 7.5 : 4.8,
      qualitative: item.ai_severity,
      notes: "mock vector: scripted for offline review, not computed",
    },
    confidence: 0.5 + ((hashSeed(item.id) % 40) / 100),
    assumptions: [
      "attacker reaches the affected endpoint without authentication",
      "application runs with the default configuration",
    ],
    rationale: `Tainted flow from user input into ${item.scanners[0]} sink at ${item.file}:${item.line}; severity ${item.scanner_severity} proposed as ${item.ai_severity}.`,
  };
}

function mockChecks(item: FindingListItem): { checks: VerificationCheck[]; decision: FindingDetail["verification"]["decision"] } {
  const outcome =
    item.status === "confirmed" ? "demonstrated" : item.status === "rejected" ? "blocked" : "not_verified";
  const checks: VerificationCheck[] = item.scanners.map((tool) => ({
    claim: `${item.title} at ${item.file}:${item.line}`,
    check: tool === item.scanners[0] ? "laya-01/targeted-replay" : `${tool} detection`,
    outcome,
  }));
  const decision =
    item.status === "confirmed" || item.status === "rejected"
      ? { outcome, previous_status: "unprocessed", new_status: item.status }
      : null;
  return { checks, decision };
}

/** Full mock detail for one finding (drawer + /findings/:id share this). */
export function mockFindingDetail(id: string): FindingDetail | undefined {
  const item = MOCK_FINDING_ITEMS.find((f) => f.id === id);
  if (!item) return undefined;
  const excerpt = snippetFor(item.cwe);
  const observations: ObservationDetail[] = item.scanners.map((tool, i) => ({
    tool,
    rule_id: i === 0 ? `${tool}/rule-${item.cwe.replace("CWE-", "")}` : `${tool}/cross-check`,
    severity: item.scanner_severity,
    message: `${item.title} — evidence from ${tool}`,
    file: item.file,
    line: Math.max(1, item.line - i * 3),
  }));
  const blocks: CodeBlock[] = observations.map((obs, i) => ({
    key: `obs-${i}`,
    tool: obs.tool,
    rule_id: obs.rule_id,
    file: obs.file,
    line: obs.line,
    lines: excerpt.map((text, n) => ({ n: n + 1, text, highlight: n === 1 })),
  }));
  return {
    ...item,
    run_id: 7,
    description: `${item.title} — scripted mock detail for offline review.`,
    additional_cwes: [],
    observations,
    code: {
      blocks,
      taint_path: observations.map((obs, i) => ({
        block: `obs-${i}`,
        file: obs.file,
        line: obs.line,
        label: obs.rule_id,
      })),
    },
    ai: mockAi(item),
    verification: mockChecks(item),
    raw: { finding_id: item.id, mock: true, scanners: item.scanners },
  };
}
