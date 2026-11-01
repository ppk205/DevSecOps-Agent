import type {
  EventsHistory,
  FindingSummary,
  FindingsQuery,
  ReportFormat,
  ScanSummary,
} from "../api/types";
import { MOCK_EVENTS } from "./mockEvents";
import { mockFilteredFindings, mockFindingDetail } from "./mockFindingDetails";
import { MOCK_FINDINGS, MOCK_SCANS, mockCounts } from "./mockRun";
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
};
