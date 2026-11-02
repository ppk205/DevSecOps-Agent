import type {
  EventsHistory,
  FindingSummary,
  FindingsQuery,
  GeneralSettings,
  KeyEntry,
  ReportFormat,
  ScanSummary,
  ToolHealth,
  UsageSummary,
} from "../api/types";
import { MOCK_EVENTS } from "./mockEvents";
import { mockFilteredFindings, mockFindingDetail } from "./mockFindingDetails";
import { MOCK_FINDINGS, MOCK_SCANS, mockCounts } from "./mockRun";
import { mockLiveEventsHistory, mockLiveFindings, mockLiveScan } from "./mockLive";
import { MOCK_GENERAL, MOCK_KEYS, MOCK_TOOLS, MOCK_USAGE } from "./mockPhase2";
import { mockCompare, mockLogs, mockReports } from "./mockReportsLogs";

/** True when the bundle runs without a backend (VITE_MOCK=1 / --mode mock). */
export const isMock: boolean = (import.meta.env.VITE_MOCK ?? "") === "1";

function delay<T>(value: T, ms = 120): Promise<T> {
  return new Promise((resolve) => setTimeout(() => resolve(value), ms));
}

export const mockApi = {
  health: () => delay({ status: "ok", version: "mock", contract: 1 }),
  scans: (): Promise<ScanSummary[]> => delay(MOCK_SCANS),
  scan: (id: number): Promise<ScanSummary> =>
    delay(MOCK_SCANS.find((s) => s.run_id === id) ?? MOCK_SCANS[0]),
  findings: (scanId: number): Promise<{ items: FindingSummary[]; run_id: number }> =>
    delay({ items: scanId === 7 ? MOCK_FINDINGS : [], run_id: scanId }),
  counts: () => delay(mockCounts(MOCK_FINDINGS)),
  eventsHistory: (scanId: number): Promise<EventsHistory> =>
    delay({ run_id: scanId, events: MOCK_EVENTS, next_cursor: MOCK_EVENTS.length }),
  liveScan: (scanId: number) => delay(mockLiveScan(scanId)),
  liveEvents: (scanId: number) => delay(mockLiveEventsHistory(scanId)),
  liveFindings: () => delay(mockLiveFindings()),
  reports: (scanId: number) => delay(mockReports(scanId)),
  generateReport: (scanId: number, format: ReportFormat) =>
    delay({
      ...mockReports(scanId).reports.find((r) => r.format === format)!,
      generated: true,
      download_url: `/api/reports/run-${scanId}-${format}/download`,
      status: "ready",
    }),
  compare: (scanIds: number[]) => delay(mockCompare(scanIds)),
  findingsFiltered: (scanId: number, query: FindingsQuery = {}) =>
    delay(mockFilteredFindings(scanId, query)),
  findingDetail: (id: string) => delay(mockFindingDetail(id)),
  logs: (
    scanId: number,
    params: { level?: string; source?: string; q?: string; since?: number } = {},
  ) => delay(mockLogs(scanId, params)),
  // ---- Phase 2 (Home / New Scan / Keys): scripted fixtures, in-memory writes ----
  tools: (verify?: boolean): Promise<{ tools: ToolHealth[] }> =>
    delay({
      tools: verify
        ? MOCK_TOOLS
        : MOCK_TOOLS.map((t) => ({ ...t, version: t.available ? t.version : null })),
    }),
  settings: (): Promise<{ general: GeneralSettings }> => delay({ general: { ...mockGeneral } }),
  updateSettings: (patch: Partial<GeneralSettings>): Promise<{ general: GeneralSettings }> => {
    Object.assign(mockGeneral, patch);
    return delay({ general: { ...mockGeneral } });
  },
  keys: (): Promise<{ keys: KeyEntry[] }> => delay({ keys: mockKeys.map((k) => ({ ...k })) }),
  saveKey: (
    profile: string,
    body: { api_key: string; base_url?: string; label?: string },
  ): Promise<KeyEntry> => {
    const masked = `••••${body.api_key.slice(-4)}`;
    const existing = mockKeys.find((k) => k.profile === profile);
    const entry: KeyEntry = {
      profile,
      label: body.label ?? existing?.label ?? profile,
      base_url: body.base_url ?? existing?.base_url ?? "https://api.openai.com/v1",
      api_key_env: existing?.api_key_env ?? `${profile.toUpperCase().replace(/-/g, "_")}_API_KEY`,
      models: existing?.models ?? [],
      default_model: existing?.default_model ?? null,
      configured: true,
      masked,
    };
    if (existing) Object.assign(existing, entry);
    else mockKeys.push({ ...entry });
    return delay({ ...entry });
  },
  deleteKey: (profile: string): Promise<{ deleted: boolean; profile: string }> => {
    const index = mockKeys.findIndex((k) => k.profile === profile);
    if (index >= 0) mockKeys.splice(index, 1);
    return delay({ deleted: index >= 0, profile });
  },
  testKey: (profile: string): Promise<{ ok: boolean; profile: string; model: string }> =>
    delay({ ok: true, profile, model: "north-mini-code" }),
  usage: (): Promise<UsageSummary> => delay({ ...MOCK_USAGE }),
  createScan: (body: { repository_url: string; profile?: string }): Promise<{
    run_id: number;
    status: string;
    profile: string;
  }> => delay({ run_id: 8, status: "queued", profile: body.profile ?? "fast" }),
  // ---- AI fix (mock): in-memory proposals per run ----
  requestFix: (
    runId: number,
    body: { finding_ids: string[] | null; provider_profile?: string | null; provider_model?: string | null },
  ): Promise<{ accepted: boolean; run_id: number }> => {
    const ids =
      body.finding_ids ?? MOCK_FINDINGS.slice(0, 3).map((f) => f.id);
    const runStore = mockFixesByRun.get(runId) ?? [];
    for (const fid of ids) {
      if (runStore.some((p) => p.finding_id === fid)) continue;
      runStore.push({
        id: `fix-${fid}`,
        finding_id: fid,
        status: "proposed",
        diff: `--- a/finding/${fid}\n+++ b/finding/${fid}\n@@ remediate @@\n-// vulnerable: ${fid}\n+// remediated: ${fid} (profile ${body.provider_profile ?? "default"})`,
        model: body.provider_model ?? "north-mini-code",
        error: null,
        overlay_path: null,
        verification: null,
      });
    }
    mockFixesByRun.set(runId, runStore);
    return delay({ accepted: true, run_id: runId });
  },
  fetchFixes: (runId: number): Promise<{ run_id: number; proposals: import("../api/types").FixProposal[] }> =>
    delay({ run_id: runId, proposals: (mockFixesByRun.get(runId) ?? []).map((p) => ({ ...p })) }),
  applyFix: (
    runId: number,
    proposalId: string,
  ): Promise<{ id: string; status: string; overlay_path: string | null; verification: import("../api/types").FixVerification | null }> => {
    const runStore = mockFixesByRun.get(runId) ?? [];
    const proposal = runStore.find((p) => p.id === proposalId);
    if (!proposal) return delay({ id: proposalId, status: "failed", overlay_path: null, verification: null });
    proposal.status = "applied";
    proposal.overlay_path = `overlays/run-${runId}/${proposalId}.patch`;
    proposal.verification = { fixed: true, detail: `Re-scan of ${proposal.finding_id}: taint path removed.` };
    return delay({ id: proposal.id, status: proposal.status, overlay_path: proposal.overlay_path, verification: proposal.verification });
  },
};

/** Mutable mock copies so the Keys/Settings pages feel interactive offline. */
const mockFixesByRun = new Map<number, import("../api/types").FixProposal[]>();

/** Test helper: clear in-memory fix proposals between tests. */
export function resetMockFixes(): void {
  mockFixesByRun.clear();
}
const mockGeneral: GeneralSettings = { ...MOCK_GENERAL };
const mockKeys: KeyEntry[] = MOCK_KEYS.map((k) => ({ ...k }));
