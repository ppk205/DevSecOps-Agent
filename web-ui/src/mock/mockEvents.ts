import type { ScanEvent } from "../api/types";

/** Scripted event rail for the mock run — stage transitions + log lines. */
export const MOCK_EVENTS: ScanEvent[] = [
  { seq: 0, kind: "stage", stage: "intake", message: "intake → running", created_at: "2026-11-01T09:00:02+07:00" },
  { seq: 1, kind: "log", stage: "intake", message: "checkout verified at 9f3ac41", created_at: "2026-11-01T09:00:05+07:00" },
  { seq: 2, kind: "stage", stage: "scan", message: "scan → running (semgrep + odc)", created_at: "2026-11-01T09:00:11+07:00" },
  { seq: 3, kind: "log", stage: "scan", message: "semgrep: 41 raw observations", created_at: "2026-11-01T09:02:44+07:00" },
  { seq: 4, kind: "log", stage: "scan", message: "odc: 3 vulnerable dependencies", created_at: "2026-11-01T09:04:19+07:00" },
  { seq: 5, kind: "stage", stage: "hunt", message: "hunt → running (agentic validation)", created_at: "2026-11-01T09:04:30+07:00" },
  { seq: 6, kind: "ai_step", stage: "hunt", message: "hunt verdict: reachable sink in BookDao", created_at: "2026-11-01T09:06:02+07:00" },
  { seq: 7, kind: "ai_proposal", stage: "hunt", message: "proposed: confirm SQLi mock-f-001, reject XSS mock-f-017", created_at: "2026-11-01T09:07:55+07:00" },
  { seq: 8, kind: "verification_result", stage: "validate", message: "validate: 18 confirmed / 60 reviewed", created_at: "2026-11-01T09:09:31+07:00" },
  { seq: 9, kind: "stage", stage: "report", message: "report → running", created_at: "2026-11-01T09:09:40+07:00" },
  { seq: 10, kind: "stage", stage: "report", message: "report → completed · gate FAIL", created_at: "2026-11-01T09:10:03+07:00" },
];
