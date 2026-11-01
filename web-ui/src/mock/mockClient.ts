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
};

/** Mutable mock copies so the Keys/Settings pages feel interactive offline. */
const mockGeneral: GeneralSettings = { ...MOCK_GENERAL };
const mockKeys: KeyEntry[] = MOCK_KEYS.map((k) => ({ ...k }));
