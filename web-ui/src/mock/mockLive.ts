import type {
  Counts,
  LiveDecision,
  LiveScanDetail,
  ScanEvent,
  StageSummary,
} from "../api/types";
import { MOCK_FINDINGS } from "./mockRun";

/** Scripted 8-node live run (mock mode): a running scan at ~70% rail. */
const NOW = "2026-11-01T09:08:30+07:00";

const STAGE_STATUS: { name: string; status: StageSummary["status"]; message: string }[] = [
  { name: "intake", status: "completed", message: "Verified commit 9f3ac41" },
  { name: "model_hunt", status: "completed", message: "6 candidates in 4 rounds" },
  { name: "semgrep", status: "completed", message: "41 raw observations" },
  { name: "gitleaks", status: "completed", message: "no secrets exposed" },
  { name: "laya_batch_routing", status: "completed", message: "60 routed in 3 batches" },
  { name: "laya_verification", status: "completed", message: "6 verified: 4 completed, 2 skipped" },
  { name: "targeted_deep_analysis", status: "running", message: "Reviewing finding 41/60" },
  { name: "independent_validation", status: "pending", message: "" },
  { name: "final_report", status: "pending", message: "" },
  { name: "model_scanner_compare", status: "completed", message: "agreed=4 model-only=2 scanner-only=56" },
];

export function mockLiveStages(): StageSummary[] {
  return STAGE_STATUS.map((s, i) => ({
    name: s.name,
    status: s.status,
    ordinal: i,
    message: s.message,
    started_at: NOW,
    completed_at: s.status === "completed" ? NOW : null,
  }));
}

export function mockLiveCounts(): Counts {
  return { total: 41, confirmed: 12, rejected: 5, unresolved: 14, unprocessed: 10 };
}

/** 26-event scripted rail across the 8 nodes (stage/log/ai/verification). */
export const MOCK_LIVE_EVENTS: ScanEvent[] = [
  { seq: 0, kind: "stage", stage: "intake", message: "intake → running", created_at: "2026-11-01T09:00:02+07:00" },
  { seq: 1, kind: "log", stage: "intake", message: "checkout verified at 9f3ac41", created_at: "2026-11-01T09:00:05+07:00" },
  { seq: 2, kind: "stage", stage: "intake", message: "intake → completed · Verified commit 9f3ac41", created_at: "2026-11-01T09:00:06+07:00" },
  { seq: 3, kind: "ai_step", stage: "model_hunt", message: "model_hunt → running · exploring snapshot", created_at: "2026-11-01T09:00:20+07:00" },
  { seq: 4, kind: "ai_step", stage: "model_hunt", message: "round 2: reachable sink in BookDao (CWE-89)", created_at: "2026-11-01T09:01:44+07:00" },
  { seq: 5, kind: "ai_step", stage: "model_hunt", message: "round 4: 6 candidates held for verification", created_at: "2026-11-01T09:03:02+07:00" },
  { seq: 6, kind: "log", stage: "semgrep", message: "semgrep → running", created_at: "2026-11-01T09:03:10+07:00" },
  { seq: 7, kind: "log", stage: "semgrep", message: "semgrep: 41 raw observations", created_at: "2026-11-01T09:04:02+07:00" },
  { seq: 8, kind: "log", stage: "gitleaks", message: "gitleaks: no secrets exposed", created_at: "2026-11-01T09:04:19+07:00" },
  { seq: 9, kind: "stage", stage: "scanners", message: "scanners → completed · 41 observations normalized to 38 findings", created_at: "2026-11-01T09:04:30+07:00" },
  { seq: 10, kind: "ai_step", stage: "laya_batch_routing", message: "routing batch 1/3 · 20 findings", created_at: "2026-11-01T09:04:44+07:00" },
  { seq: 11, kind: "ai_step", stage: "laya_batch_routing", message: "routing batch 3/3 · 60 routed", created_at: "2026-11-01T09:05:31+07:00" },
  { seq: 12, kind: "ai_step", stage: "laya_verification", message: "verifying candidate mock-f-001 against the build", created_at: "2026-11-01T09:05:52+07:00" },
  { seq: 13, kind: "verification_result", stage: "laya_verification", message: "candidate mock-f-001 corroborated by semgrep rule java.lang.security.audit.sqli", created_at: "2026-11-01T09:06:02+07:00" },
  { seq: 14, kind: "verification_result", stage: "model_scanner_compare", message: "agreed=4 model-only=2 scanner-only=56", created_at: "2026-11-01T09:06:20+07:00" },
  { seq: 15, kind: "ai_step", stage: "targeted_deep_analysis", message: "NOW ANALYZING mock-f-001 · SQL injection in repository query", created_at: "2026-11-01T09:06:31+07:00" },
  { seq: 16, kind: "ai_proposal", stage: "targeted_deep_analysis", message: "proposed: confirm mock-f-001 as critical (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H)", created_at: "2026-11-01T09:06:55+07:00", payload: { finding_id: "mock-f-001", cvss: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H" } },
  { seq: 17, kind: "ai_step", stage: "targeted_deep_analysis", message: "NOW ANALYZING mock-f-009 · reflected XSS in SearchServlet", created_at: "2026-11-01T09:07:12+07:00" },
  { seq: 18, kind: "ai_proposal", stage: "targeted_deep_analysis", message: "proposed: confirm mock-f-009 as high (CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N)", created_at: "2026-11-01T09:07:40+07:00", payload: { finding_id: "mock-f-009", cvss: "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N" } },
  { seq: 19, kind: "ai_step", stage: "targeted_deep_analysis", message: "NOW ANALYZING mock-f-017 · hardcoded credential (reject: test fixture)", created_at: "2026-11-01T09:07:58+07:00" },
  { seq: 20, kind: "ai_proposal", stage: "targeted_deep_analysis", message: "proposed: reject mock-f-017 (test-only credential, not reachable)", created_at: "2026-11-01T09:08:11+07:00", payload: { finding_id: "mock-f-017" } },
  { seq: 21, kind: "verification_result", stage: "independent_validation", message: "validated mock-f-001: unprocessed → confirmed (demonstrated sink)", created_at: "2026-11-01T09:08:22+07:00", payload: { finding_id: "mock-f-001" } },
  { seq: 22, kind: "verification_result", stage: "independent_validation", message: "validated mock-f-017: unprocessed → rejected (blocked: test fixture)", created_at: "2026-11-01T09:08:29+07:00", payload: { finding_id: "mock-f-017" } },
  { seq: 23, kind: "ai_step", stage: "targeted_deep_analysis", message: "NOW ANALYZING mock-f-022 · XML external entity expansion", created_at: "2026-11-01T09:08:30+07:00" },
  { seq: 24, kind: "log", stage: "targeted_deep_analysis", message: "review queue 41/60 · 12 confirmed · 5 rejected", created_at: "2026-11-01T09:08:31+07:00" },
  { seq: 25, kind: "log", stage: "final_report", message: "final_report → pending (waits for validation)", created_at: "2026-11-01T09:08:32+07:00" },
];

export const MOCK_LIVE_ASSESSMENTS = [
  {
    finding_id: "mock-f-001",
    proposed_severity: "critical",
    proposed_status: "confirmed",
    confidence: 0.93,
    rationale: "String-concatenated SQL query reaches executeQuery with request-controlled input; no parameterization on the path.",
    assumptions: ["Application runs with a privileged DB role", "Input reaches the sink unescaped"],
    cvss: {
      vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
      base_score: 9.3,
      qualitative: "Critical",
      notes: "Network-reachable SQL injection with full confidentiality/integrity impact.",
    },
  },
  {
    finding_id: "mock-f-009",
    proposed_severity: "high",
    proposed_status: "confirmed",
    confidence: 0.84,
    rationale: "Search term reflected without encoding; output context is HTML body.",
    assumptions: ["Reflected endpoint is authenticated but linkable"],
    cvss: {
      vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N",
      base_score: 8.2,
      qualitative: "High",
      notes: "Stored-or-reflected XSS with session impact.",
    },
  },
  {
    finding_id: "mock-f-017",
    proposed_severity: "low",
    proposed_status: "rejected",
    confidence: 0.71,
    rationale: "Credential literal lives in a test fixture never packaged into the image.",
    assumptions: ["Test sources excluded from the release artifact"],
    cvss: null,
  },
];

export const MOCK_LIVE_DECISIONS: LiveDecision[] = [
  { finding_id: "mock-f-001", previous_status: "unprocessed", new_status: "confirmed", outcome: "demonstrated" },
  { finding_id: "mock-f-017", previous_status: "unprocessed", new_status: "rejected", outcome: "blocked" },
];

/** Scripted live scan detail for the mock live page (running at 41/60). */
export function mockLiveScan(scanId: number): LiveScanDetail {
  const counts = mockLiveCounts();
  return {
    run_id: scanId,
    repo: "https://github.com/example/jva-bookstore",
    commit: "9f3ac41b2e77d05c8f1a6d3b4c9e2f7081a5d6c3",
    status: "running",
    gate: "unknown",
    counts,
    severity: { critical: 3, high: 9, medium: 15, low: 10, info: 4 },
    stages: mockLiveStages(),
    ai: {
      assessments: MOCK_LIVE_ASSESSMENTS,
      decisions: MOCK_LIVE_DECISIONS,
      comparison_counts: { agreed: 4, model_only: 2, scanner_only: 56 },
      usage: { "mock-provider": 1.18 },
    },
    findings_revision: 3,
    event_cursor: MOCK_LIVE_EVENTS.length - 1,
    event_count: MOCK_LIVE_EVENTS.length,
    created_at: "2026-11-01T09:00:01+07:00",
  };
}

/** Findings slice backing the mock live results feed (confirmed first). */
export function mockLiveFindings() {
  return MOCK_FINDINGS.slice(0, 12);
}

/** Events history payload backing the mock live stream + replay. */
export function mockLiveEventsHistory(scanId: number) {
  return { run_id: scanId, events: MOCK_LIVE_EVENTS, next_cursor: MOCK_LIVE_EVENTS.length };
}
