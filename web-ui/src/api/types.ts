/** Shared API shapes (Phase 1 skeleton — mirrors WEBUI-NOTES endpoint contract). */
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type VerificationState = "confirmed" | "unresolved" | "rejected" | "unprocessed";
export type RunStatus = "queued" | "running" | "completed" | "failed" | "cancelled";
export type EventKind = "log" | "stage" | "ai_step" | "ai_proposal" | "verification_result";

export interface StageSummary {
  name: string;
  status: RunStatus | "pending" | "skipped";
  ordinal: number;
  message: string;
  started_at: string | null;
  completed_at: string | null;
}

export interface Counts {
  total: number;
  confirmed: number;
  rejected: number;
  unresolved: number;
  unprocessed: number;
}

export interface ScanSummary {
  run_id: number;
  repo: string;
  commit: string;
  status: RunStatus;
  gate: "pass" | "fail" | "unknown";
  counts: Counts;
  /** Findings per severity (lower-cased), e.g. {critical: 4}. Phase 2+. */
  severity?: Record<string, number>;
  /** Top CWE tallies, most frequent first. Phase 2+. */
  top_cwe?: { cwe: string; count: number }[];
  stages: StageSummary[];
  created_at: string;
}

export interface FindingSummary {
  id: string;
  title: string;
  severity: Severity;
  status: VerificationState;
  tool: string;
  file: string;
  line: number;
  cwe: string;
}

export interface ScanEvent {
  /** Row id when the backend supplies it (history/SSE payloads do). */
  id?: number;
  seq: number;
  kind: EventKind;
  stage: string | null;
  message: string;
  created_at: string;
  /** Structured payload (status/stage/proposals) when the backend supplies it. */
  payload?: unknown;
}

export interface EventsHistory {
  run_id: number;
  events: ScanEvent[];
  next_cursor: number;
}

/** Phase 3 — live scan snapshot served by GET /api/scans/{id}. */
export interface LiveAssessment {
  finding_id?: string;
  proposed_severity?: string | null;
  proposed_status?: string | null;
  confidence?: number | null;
  rationale?: string | null;
  assumptions?: string[];
  cvss?: {
    vector: string;
    base_score?: number | null;
    qualitative?: string | null;
    notes?: string;
  } | null;
}

export interface LiveDecision {
  finding_id?: string;
  previous_status?: string;
  new_status?: string;
  outcome?: string;
}

export interface LiveScanDetail {
  run_id: number;
  repo: string;
  commit: string;
  status: RunStatus | string;
  gate: string;
  counts: Counts;
  severity: Record<string, number>;
  stages: StageSummary[];
  ai: {
    assessments: LiveAssessment[];
    decisions: LiveDecision[];
    comparison_counts: Record<string, number>;
    usage: Record<string, number>;
  };
  findings_revision: number;
  event_cursor: number;
  event_count: number;
  created_at: string | null;
}

export type LiveConnection =
  | "idle"
  | "connecting"
  | "live"
  | "reconnecting"
  | "polling"
  | "closed";

/** Phase 2 shared shapes (Home / New Scan / Keys). */

export interface ToolHealth {
  tool: string;
  binary: string;
  path: string | null;
  available: boolean;
  version: string | null;
  hint: string | null;
}

export interface GeneralSettings {
  timezone: string;
  timeout: number;
  max_files: number;
  output_dir: string;
  fail_on: string;
  profile: string;
}

export interface KeyEntry {
  profile: string;
  label: string;
  base_url: string;
  api_key_env: string;
  models: string[];
  default_model: string | null;
  configured: boolean;
  masked: string;
}

export interface UsageSummary {
  total_budget: number;
  total_spent: number;
  available: number;
  by_provider: Record<string, number>;
  run_count: number;
}

export interface TopCwe {
  cwe: string;
  count: number;
}

/** Phase 5 — Reports + Logs shapes (mirror the /api contract). */
export type ReportFormat = "json" | "sarif" | "html" | "markdown" | "txt" | "docx" | "csv";

export interface ReportDescriptor {
  report_id: string;
  run_id: number;
  format: ReportFormat;
  filename: string;
  generated: boolean;
  size_bytes: number | null;
  findings: number;
  download_url: string | null;
  status?: string;
}

export interface ReportsResponse {
  run_id: number;
  reports: ReportDescriptor[];
  final_report: ReportDescriptor | null;
  csv_note: string;
}

export interface CompareScanRow {
  run_id: number;
  status: string;
  gate: string | null;
  total: number;
}

export interface CompareEntry {
  finding_id: string;
  title: string;
  severity: string;
  status: string;
  seen_in?: number[];
  baseline_severity?: string;
  baseline_status?: string;
}

export interface CompareResult {
  baseline: number;
  scans: CompareScanRow[];
  by_scanner: { tool: string; counts: Record<string, number> }[];
  by_cwe: { cwe: string; counts: Record<string, number> }[];
  new: CompareEntry[];
  fixed: CompareEntry[];
  changed: CompareEntry[];
}

export type LogLevel = "debug" | "info" | "warn" | "error";

export interface LogLine {
  seq: number;
  ts: string | null;
  level: LogLevel | string;
  source: string;
  kind: string;
  message: string;
  data: unknown;
  finding_id: string | null;
}

export interface LogsResponse {
  scan_id: number;
  lines: LogLine[];
  next_cursor: number;
  redacted: boolean;
  granularity: string;
}

/** Phase 6: AI-fix proposal for one finding. */
export type FixProposalStatus = "proposed" | "applied" | "verified" | "failed";

export interface FixVerification {
  fixed: boolean;
  detail: string;
}

export interface FixProposal {
  id: string;
  finding_id: string;
  status: FixProposalStatus;
  diff: string;
  model: string | null;
  error: string | null;
  overlay_path: string | null;
  verification: FixVerification | null;
}

export interface FixesResponse {
  run_id: number;
  proposals: FixProposal[];
}

export interface FixRequestBody {
  finding_ids: string[] | null;
  provider_profile?: string | null;
  provider_model?: string | null;
}

/** Phase 4: one row of the findings table (scanner vs AI severities). */
export interface FindingListItem {
  id: string;
  title: string;
  severity: Severity;
  scanner_severity: string;
  ai_severity: string | null;
  ai_changed: boolean;
  cwe: string;
  status: string;
  scanners: string[];
  file: string;
  line: number;
  origin: "source" | "dependency";
}

export interface FindingsQuery {
  severities?: string[];
  cwes?: string[];
  scanners?: string[];
  verifications?: string[];
  aiChanged?: boolean | null;
  origin?: "source" | "dependency" | null;
  q?: string;
  sort?: "severity" | "title" | "file" | "status";
  order?: "asc" | "desc";
  page?: number;
  pageSize?: number;
}

export interface FindingsResponse {
  run_id: number;
  total: number;
  page: number;
  page_size: number;
  items: FindingListItem[];
}

export interface CodeLine {
  n: number;
  text: string;
  highlight: boolean;
}

export interface CodeBlock {
  key: string;
  tool: string;
  rule_id: string;
  file: string;
  line: number;
  lines: CodeLine[];
}

export interface TaintStep {
  block: string;
  file: string;
  line: number;
  label: string;
}

export interface ObservationDetail {
  tool: string;
  rule_id: string;
  severity: string;
  message: string;
  file: string;
  line: number;
}

export interface AiAssessment {
  proposed_severity: string | null;
  proposed_status: string | null;
  cvss: {
    vector: string;
    base_score: number | null;
    qualitative: string | null;
    notes: string;
  } | null;
  confidence: number | null;
  assumptions: string[];
  rationale: string;
}

export interface VerificationCheck {
  claim: string;
  check: string;
  outcome: string;
}

/** Phase 4: full drawer/page payload for one finding. */
export interface FindingDetail extends FindingListItem {
  run_id: number;
  description: string;
  additional_cwes: string[];
  observations: ObservationDetail[];
  code: { blocks: CodeBlock[]; taint_path: TaintStep[] };
  ai: AiAssessment | null;
  verification: {
    checks: VerificationCheck[];
    decision: { outcome: string; previous_status: string; new_status: string } | null;
  };
  raw: unknown;
}

/** Task 4: scan-completion notification. */
export type NotificationKind = "scan_completed" | "gate_failed";

export interface ScanNotification {
  id: number;
  run_id: number;
  kind: NotificationKind | string;
  message: string;
  is_read: boolean;
  created_at: string | null;
}

export interface NotificationsResponse {
  notifications: ScanNotification[];
  unread: number;
}
