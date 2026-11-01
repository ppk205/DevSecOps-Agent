import type {
  CompareResult,
  LogLine,
  LogsResponse,
  ReportDescriptor,
  ReportFormat,
  ReportsResponse,
} from "../api/types";
import { MOCK_FINDINGS } from "./mockRun";

const FORMATS: ReportFormat[] = ["json", "sarif", "html", "markdown", "txt", "docx", "csv"];

const SUFFIX: Record<ReportFormat, string> = {
  json: "json",
  sarif: "sarif",
  html: "html",
  markdown: "md",
  txt: "txt",
  docx: "docx",
  csv: "csv",
};

/** Reports list mock: html/json/csv pre-generated, rest pending. */
export function mockReports(scanId: number): ReportsResponse {
  const generated: ReportFormat[] = ["json", "html", "csv"];
  const reports: ReportDescriptor[] = FORMATS.map((format) => {
    const ready = generated.includes(format);
    const filename = `run-${scanId}-${format}.${SUFFIX[format]}`;
    return {
      report_id: filename,
      run_id: scanId,
      format,
      filename,
      generated: ready,
      size_bytes: ready ? 4200 + format.length * 733 : null,
      findings: scanId === 7 ? MOCK_FINDINGS.length : 0,
      download_url: ready ? `/api/reports/${filename}/download` : null,
    };
  });
  return {
    run_id: scanId,
    reports,
    final_report: {
      report_id: "final-report.md",
      run_id: scanId,
      format: "markdown",
      filename: "final-report.md",
      generated: true,
      size_bytes: 9218,
      findings: scanId === 7 ? MOCK_FINDINGS.length : 0,
      download_url: `/runs/${scanId}/report`,
    },
    csv_note: "CSV is a flat finding-rows export (finding_id,title,severity,status,tools,file,line,cwe).",
  };
}

/** Compare mock: run 7 (baseline, 60 findings) vs run 6 (3 findings). */
export function mockCompare(scanIds: number[]): CompareResult {
  const baseline = scanIds[0] ?? 7;
  const byScanner = ["semgrep", "odc"].map((tool) => ({
    tool,
    counts: Object.fromEntries(
      scanIds.map((id) => [String(id), id === 6 ? (tool === "odc" ? 3 : 0) : tool === "semgrep" ? 57 : 3]),
    ),
  }));
  const byCwe = ["CWE-89", "CWE-79", "CWE-1104"].map((cwe) => ({
    cwe,
    counts: Object.fromEntries(scanIds.map((id) => [String(id), id === 6 ? 1 : 20])),
  }));
  return {
    baseline,
    scans: scanIds.map((id) => ({
      run_id: id,
      status: "completed",
      gate: id === 6 ? "pass" : "fail",
      total: id === 6 ? 3 : MOCK_FINDINGS.length,
    })),
    by_scanner: byScanner,
    by_cwe: byCwe,
    new: [
      { finding_id: "mock-f-061", title: "New issue only in latest", severity: "medium", status: "unprocessed", seen_in: [6] },
    ],
    fixed: [
      { finding_id: "mock-f-002", title: "Fixed since baseline", severity: "high", status: "rejected" },
    ],
    changed: [
      {
        finding_id: "mock-f-001",
        title: "SQL injection in repository query",
        severity: "critical",
        status: "confirmed",
        baseline_severity: "high",
        baseline_status: "unresolved",
        seen_in: [6],
      },
    ],
  };
}

const LOG_SCRIPT: { level: LogLine["level"]; source: string; kind: string; message: string; data: unknown; finding: string | null }[] = [
  { level: "info", source: "intake", kind: "stage", message: "intake → completed", data: { ordinal: 0, status: "completed" }, finding: null },
  { level: "info", source: "intake", kind: "log", message: "checkout verified at 9f3ac41", data: {}, finding: null },
  { level: "info", source: "scan", kind: "stage", message: "scan → completed", data: { ordinal: 1, status: "completed" }, finding: null },
  { level: "info", source: "scan", kind: "log", message: "semgrep: 41 raw observations", data: { tool: "semgrep" }, finding: null },
  { level: "info", source: "scan", kind: "log", message: "odc: 3 vulnerable dependencies", data: { tool: "odc" }, finding: null },
  { level: "debug", source: "hunt", kind: "ai_step", message: "hunt verdict: reachable sink in BookDao", data: { model: "mock" }, finding: "mock-f-001" },
  { level: "debug", source: "hunt", kind: "ai_proposal", message: "proposed: confirm SQLi mock-f-001, reject XSS mock-f-017", data: {}, finding: "mock-f-001" },
  { level: "info", source: "validate", kind: "verification_result", message: "validate: 18 confirmed / 60 reviewed", data: { confirmed: 18 }, finding: null },
  { level: "warn", source: "validate", kind: "log", message: "token budget at 82% — api_key=***REDACTED*** rotated", data: {}, finding: null },
  { level: "info", source: "report", kind: "stage", message: "report → completed · gate FAIL", data: { ordinal: 4, status: "completed" }, finding: null },
];

/** Log lines mock: 10 scripted lines, one carrying a pre-redacted marker. */
export function mockLogs(
  scanId: number,
  params: { level?: string; source?: string; q?: string; since?: number } = {},
): LogsResponse {
  const all: LogLine[] = LOG_SCRIPT.map((entry, seq) => ({
    seq,
    ts: `2026-11-01T09:${String(2 + seq).padStart(2, "0")}:10+07:00`,
    level: entry.level,
    source: entry.source,
    kind: entry.kind,
    message: entry.message,
    data: entry.data,
    finding_id: entry.finding,
  }));
  const kept = all.filter(
    (line) =>
      line.seq > (params.since ?? -1) &&
      (!params.level || params.level === "all" || line.level === params.level) &&
      (!params.source || params.source === "all" || line.source === params.source) &&
      (!params.q || line.message.toLowerCase().includes(params.q.toLowerCase())),
  );
  return {
    scan_id: scanId,
    lines: kept,
    next_cursor: all.length - 1,
    redacted: true,
    granularity: "Coarse granularity (mock): scripted stage + event lines.",
  };
}
