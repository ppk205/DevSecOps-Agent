import type {
  EventsHistory,
  FindingSummary,
  ScanSummary,
} from "../api/types";
import { MOCK_EVENTS } from "./mockEvents";
import { MOCK_FINDINGS, MOCK_SCANS, mockCounts } from "./mockRun";

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
};
