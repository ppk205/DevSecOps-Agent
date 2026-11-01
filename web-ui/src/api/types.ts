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
  seq: number;
  kind: EventKind;
  stage: string | null;
  message: string;
  created_at: string;
}

export interface EventsHistory {
  run_id: number;
  events: ScanEvent[];
  next_cursor: number;
}
