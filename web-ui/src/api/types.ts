/** Các định dạng API dùng chung (khung Phase 1 — phản chiếu giao ước endpoint WEBUI-NOTES). */
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
  /** Findings theo mức độ nghiêm trọng (viết thường), ví dụ: {critical: 4}. Phase 2+. */
  severity?: Record<string, number>;
  /** Thống kê các CWE hàng đầu, tần suất cao nhất đứng trước. Phase 2+. */
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
  /** Id của dòng khi backend cung cấp (các payload history/SSE có chứa). */
  id?: number;
  seq: number;
  kind: EventKind;
  stage: string | null;
  message: string;
  created_at: string;
  /** Payload có cấu trúc (status/stage/proposals) khi backend cung cấp. */
  payload?: unknown;
}

export interface EventsHistory {
  run_id: number;
  events: ScanEvent[];
  next_cursor: number;
}

/** Phase 3 — snapshot lượt quét trực tiếp do GET /api/scans/{id} phục vụ. */
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
    overall_score?: number | null;
    base_rating?: string | null;
    overall_rating?: string | null;
    nomenclature?: string | null;
    calculation_source?: string | null;
    metric_assumptions_verified?: boolean;
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
  scenario?: {
    profile: string | null;
    mode: string | null;
    laya: boolean | null;
    ai_review: boolean | null;
    ai_report: boolean | null;
    max_ai_findings: number | null;
  } | null;
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

/** Các định dạng dùng chung Phase 2 (Home / New Scan / Keys). */

export interface ScannerOptions {
  tools: ToolHealth[];
  profiles: Record<"fast" | "full", string[]>;
}

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

/** Phase 5 — các định dạng Reports + Logs (phản chiếu giao ước /api). */
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
  ai?: CompareAiRow[];
  benchmark?: { reference_run_id: number | null; rows: BenchmarkRow[] };
  by_scanner: { tool: string; counts: Record<string, number> }[];
  by_cwe: { cwe: string; counts: Record<string, number> }[];
  new: CompareEntry[];
  fixed: CompareEntry[];
  changed: CompareEntry[];
}

export interface BenchmarkRow {
  run_id: number;
  scenario: "A0" | "A1" | "A2" | "A3" | "A4" | "custom";
  profile: string | null;
  commit: string | null;
  model: string | null;
  review_limit: number | null;
  status: string;
  gate: string | null;
  duration_seconds: number | null;
  stage_durations?: { name: string; status: string; duration_seconds: number | null }[];
  scanners: {
    tool: string;
    status: string;
    eligible_units: number | null;
    analyzed_units: number | null;
    skipped_units: number | null;
  }[];
  requests: number | null;
  completed_requests: number | null;
  failed_requests: number | null;
  http_attempts?: number | null;
  max_model_requests?: number | null;
  prompt_tokens: number | null;
  completion_tokens: number | null;
  total_tokens: number | null;
  cost_usd: number | null;
  reviewed: number | null;
  validated: number | null;
  laya_devices: string[];
  laya_timeouts: number | null;
  comparable: boolean;
  comparison_reason: string | null;
  limitations?: string[];
  savings: {
    duration_percent: number | null;
    requests_percent: number | null;
    tokens_percent: number | null;
    cost_percent: number | null;
  } | null;
}

export interface CompareAiRow {
  run_id: number;
  candidates: number;
  agreed: number;
  model_only: number;
  confirmed: number;
  rejected: number;
}

export interface HuntCandidate {
  title: string;
  file: string;
  line: number;
  cwe: string;
  severity: string;
  rationale: string;
  verdict: "agreed" | "model_only";
  finding_id?: string;
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

/** Phase 6: đề xuất AI-fix cho một finding. */
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

/** Nguồn gốc hunt ưu tiên model (metadata.origin của finding). Thiếu nghĩa là từ scanner. */
export type FindingProvenance = "model" | "scanner" | "both";

/** Phase 4: một dòng của bảng findings (mức độ nghiêm trọng từ scanner so với AI). */

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
  model_corroborated: boolean;
  file: string;
  line: number;
  origin: "source" | "dependency";
  /** Nguồn gốc hunt (metadata.origin). Tùy chọn: vắng mặt nghĩa là từ scanner. */
  provenance?: FindingProvenance;
}

export interface FindingsQuery {
  severities?: string[];
  cwes?: string[];
  scanners?: string[];
  verifications?: string[];
  aiChanged?: boolean | null;
  origin?: "source" | "dependency" | null;
  /** Bộ lọc nguồn gốc hunt phía client (tất cả khi null). Không bao giờ gửi tới API. */
  provenance?: FindingProvenance | null;
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
    overall_score?: number | null;
    base_rating?: string | null;
    overall_rating?: string | null;
    nomenclature?: string | null;
    calculation_source?: string | null;
    metric_assumptions_verified?: boolean;
  } | null;
  cvss_score_status?: string;
  cvss_validation_errors?: string[];
  confidence: number | null;
  assumptions: string[];
  rationale: string;
}

export interface VerificationCheck {
  claim: string;
  check: string;
  outcome: string;
}

/** Phase 4: payload đầy đủ dạng drawer/page cho một finding. */
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

/** Task 4: thông báo hoàn tất lượt quét. */
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
// FR-75: environment references only; destination credentials never cross this API.
export interface OutboundChannel {
  enabled: boolean;
  events: string[];
  token_env?: string;
  chat_env?: string;
  webhook_env?: string;
}
export interface OutboundSettings {
  schema_version: 2;
  mode: "manual" | "automatic";
  telegram: OutboundChannel;
  discord: OutboundChannel;
  webhook: OutboundChannel & { url_env: string; signing_key_env: string; allowed_hosts: string[] };
}
export interface OutboundConfig { settings: OutboundSettings; events: Record<string, string> }
export interface OutboundReceipt {
  run_id: string;
  deliveries: Array<{
    channel: string;
    status: string;
    detail: string;
    events: Array<{ kind: string; label: string; message: string }>;
    selected_events: string[];
    delivery_id?: string;
  }>;
}
