import { isMock, mockApi } from "../mock/mockClient";

const BASE: string = (import.meta.env.VITE_API_BASE as string | undefined) ?? "";

/** Thin fetch wrapper: mock layer when VITE_MOCK=1, FastAPI otherwise. */
async function get<T>(path: string): Promise<T> {
  const response = await fetch(`${BASE}${path}`, {
    headers: { "X-Contract-Version": "1" },
  });
  if (!response.ok) throw new Error(`GET ${path} → ${response.status}`);
  return (await response.json()) as T;
}

export const api = {
  get health() {
    return isMock ? mockApi.health : () => get<{ status: string; version: string }>(`/api/health`);
  },
};

export async function fetchScans(): Promise<import("../api/types").ScanSummary[]> {
  if (isMock) return mockApi.scans();
  const data = await get<{ scans: import("../api/types").ScanSummary[] }>(`/api/scans`);
  return data.scans;
}

export async function fetchScan(id: number) {
  if (isMock) return mockApi.scan(id);
  return get<import("../api/types").ScanSummary>(`/api/scans/${id}`);
}

export async function fetchFindings(scanId: number) {
  if (isMock) return mockApi.findings(scanId);
  return get<{ items: import("../api/types").FindingSummary[] }>(
    `/api/scans/${scanId}/findings`,
  );
}

export async function fetchEventsHistory(scanId: number) {
  if (isMock) return mockApi.eventsHistory(scanId);
  return get<import("../api/types").EventsHistory>(`/api/scans/${scanId}/events/history`);
}

/** SSE tail with graceful fallback: caller polls when the stream closes. */
export function openEventsStream(
  scanId: number,
  onEvent: (kind: string, data: unknown) => void,
  onDone?: () => void,
): () => void {
  if (isMock) {
    // Replay the scripted rail with a stagger, then close like the skeleton.
    const timers: number[] = [];
    mockApi.eventsHistory(scanId).then((history) => {
      history.events.forEach((event, i) => {
        timers.push(
          window.setTimeout(() => onEvent(event.kind, event), 150 * (i + 1)),
        );
      });
      timers.push(window.setTimeout(() => onDone?.(), 150 * (history.events.length + 1)));
    });
    return () => timers.forEach((t) => window.clearTimeout(t));
  }
  const source = new EventSource(`/api/scans/${scanId}/events`);
  source.onmessage = (msg) => onEvent("message", msg.data);
  source.onerror = () => {
    source.close();
    onDone?.();
  };
  return () => source.close();
}
