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

async function postJson<T>(path: string, body: unknown): Promise<T> {
  // Same-origin double-submit CSRF: fetch the token, then POST with it.
  const csrf = await get<{ csrf_token: string }>(`/api/csrf`);
  const response = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Contract-Version": "1",
      "X-CSRF-Token": csrf.csrf_token,
    },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error(`POST ${path} → ${response.status}`);
  return (await response.json()) as T;
}

async function putJson<T>(path: string, body: unknown): Promise<T> {
  const csrf = await get<{ csrf_token: string }>(`/api/csrf`);
  const response = await fetch(`${BASE}${path}`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      "X-Contract-Version": "1",
      "X-CSRF-Token": csrf.csrf_token,
    },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error(`PUT ${path} → ${response.status}`);
  return (await response.json()) as T;
}

async function deleteJson<T>(path: string): Promise<T> {
  const csrf = await get<{ csrf_token: string }>(`/api/csrf`);
  const response = await fetch(`${BASE}${path}`, {
    method: "DELETE",
    headers: { "X-Contract-Version": "1", "X-CSRF-Token": csrf.csrf_token },
  });
  if (!response.ok) throw new Error(`DELETE ${path} → ${response.status}`);
  return (await response.json()) as T;
}

export const api = {
  get health() {
    return isMock ? mockApi.health : () => get<{ status: string; version: string }>(`/api/health`);
  },
};

export const fetchOutboundSettings = () => get<import("./types").OutboundConfig>("/api/outbound/settings");
export const saveOutboundSettings = (settings: import("./types").OutboundSettings) => postJson<import("./types").OutboundConfig>("/api/outbound/settings", settings);
export const fetchOutbound = (runId: string) => get<import("./types").OutboundReceipt>(`/api/scans/${encodeURIComponent(runId)}/outbound`);
export const sendOutbound = (runId: string, events: string[], channels: string[]) => postJson<import("./types").OutboundReceipt>(`/api/scans/${encodeURIComponent(runId)}/outbound`, { events, channels });

export async function fetchScans(): Promise<import("../api/types").ScanSummary[]> {
  if (isMock) return mockApi.scans();
  const data = await get<{ scans: import("../api/types").ScanSummary[] }>(`/api/scans`);
  return data.scans;
}

export async function fetchScan(id: number) {
  if (isMock) return mockApi.scan(id);
  return get<import("../api/types").ScanSummary>(`/api/scans/${id}`);
}

export async function fetchFindings(
  scanId: number,
  query: import("../api/types").FindingsQuery = {},
): Promise<import("../api/types").FindingsResponse> {
  if (isMock) return mockApi.findingsFiltered(scanId, query);
  const { buildFindingsSearch } = await import("../api/findingsQuery");
  return get<import("../api/types").FindingsResponse>(
    `/api/scans/${scanId}/findings${buildFindingsSearch(query)}`,
  );
}

export async function fetchFindingDetail(
  id: string,
  runId?: number,
): Promise<import("../api/types").FindingDetail | undefined> {
  if (isMock) return mockApi.findingDetail(id);
  const search = runId !== undefined ? `?run_id=${runId}` : "";
  return get<import("../api/types").FindingDetail>(`/api/findings/${id}${search}`);
}

export async function fetchReports(
  scanId: number,
): Promise<import("../api/types").ReportsResponse> {
  if (isMock) return mockApi.reports(scanId);
  return get<import("../api/types").ReportsResponse>(
    `/api/scans/${scanId}/reports`,
  );
}

export async function generateReport(
  scanId: number,
  format: import("../api/types").ReportFormat,
): Promise<import("../api/types").ReportDescriptor> {
  if (isMock) return mockApi.generateReport(scanId, format);
  return postJson<import("../api/types").ReportDescriptor>(
    `/api/scans/${scanId}/reports`,
    { format },
  );
}

export async function fetchCompare(
  scanIds: number[],
): Promise<import("../api/types").CompareResult> {
  if (isMock) return mockApi.compare(scanIds);
  return get<import("../api/types").CompareResult>(
    `/api/compare?scan_ids=${scanIds.join(",")}`,
  );
}

export async function fetchHuntCandidates(
  scanId: number,
): Promise<import("../api/types").HuntCandidate[]> {
  if (isMock) return [];
  const data = await get<{ candidates: import("../api/types").HuntCandidate[] }>(
    `/api/scans/${scanId}/hunt`,
  );
  return data.candidates ?? [];
}

export function compareHtmlUrl(scanIds: number[]): string {
  if (isMock) return `#/compare?scan_ids=${scanIds.join(",")}`;
  return `/api/compare?scan_ids=${scanIds.join(",")}&export=html`;
}

export async function fetchLogs(
  scanId: number,
  params: { level?: string; source?: string; q?: string; since?: number } = {},
): Promise<import("../api/types").LogsResponse> {
  const query = new URLSearchParams({ scan_id: String(scanId) });
  if (params.level) query.set("level", params.level);
  if (params.source) query.set("source", params.source);
  if (params.q) query.set("q", params.q);
  if (params.since !== undefined) query.set("since", String(params.since));
  if (isMock) return mockApi.logs(scanId, params);
  return get<import("../api/types").LogsResponse>(`/api/logs?${query}`);
}

/** SSE tail for logs with graceful fallback: caller polls when it closes. */
export function openLogsStream(
  scanId: number,
  params: { level?: string; source?: string; q?: string } = {},
  onEvent: (kind: string, data: unknown) => void,
  onDone?: () => void,
): () => void {
  if (isMock) {
    // Replay the scripted log lines with a stagger, then close like the skeleton.
    const timers: number[] = [];
    mockApi.logs(scanId, params).then((history) => {
      history.lines.forEach((line, i) => {
        timers.push(
          window.setTimeout(() => onEvent("log", line), 120 * (i + 1)),
        );
      });
      timers.push(window.setTimeout(() => onDone?.(), 120 * (history.lines.length + 1)));
    });
    return () => timers.forEach((t) => window.clearTimeout(t));
  }
  const query = new URLSearchParams({ scan_id: String(scanId) });
  if (params.level) query.set("level", params.level);
  if (params.source) query.set("source", params.source);
  if (params.q) query.set("q", params.q);
  const source = new EventSource(`/api/logs/stream?${query}`);
  source.onmessage = (msg) => onEvent("message", msg.data);
  source.onerror = () => {
    source.close();
    onDone?.();
  };
  return () => source.close();
}

export async function fetchEventsHistory(scanId: number) {
  if (isMock) return mockApi.eventsHistory(scanId);
  return get<import("../api/types").EventsHistory>(`/api/scans/${scanId}/events/history`);
}

/** ---- Phase 3: live scan detail, cancel/retry, resilient SSE ---- */

/** Live rail history: scripted 8-node run in mock, same endpoint live. */
export async function fetchLiveEventsHistory(scanId: number) {
  if (isMock) return mockApi.liveEvents(scanId);
  return get<import("../api/types").EventsHistory>(`/api/scans/${scanId}/events/history`);
}
export async function fetchLiveScan(
  scanId: number,
): Promise<import("../api/types").LiveScanDetail> {
  if (isMock) return mockApi.liveScan(scanId);
  return get<import("../api/types").LiveScanDetail>(`/api/scans/${scanId}`);
}

export async function cancelScan(
  scanId: number,
): Promise<{ run_id: number; status: string; cancel_requested: boolean }> {
  if (isMock) {
    return { run_id: scanId, status: "cancelled", cancel_requested: true };
  }
  return postJson(`/api/scans/${scanId}/cancel`, {});
}

export async function retryScan(
  scanId: number,
): Promise<{ run_id: number; status: string; retried_from?: number }> {
  if (isMock) {
    return { run_id: scanId + 1, status: "queued", retried_from: scanId };
  }
  return postJson(`/api/scans/${scanId}/retry`, {});
}

/**
 * Resilient live-event stream: SSE with Last-Event-ID resume, auto-reconnect
 * with backoff, and polling fallback when the stream closes or errors.
 *
 * Returns an unsubscribe function. `onState` reports the connection so the
 * page can render the reconnect banner.
 */
export function openLiveStream(
  scanId: number,
  options: {
    cursor?: number;
    onEvent: (kind: string, data: unknown) => void;
    onState?: (state: import("../api/types").LiveConnection) => void;
    onDone?: (status: string) => void;
  },
): () => void {
  const { onEvent, onState, onDone } = options;
  let cursor = options.cursor ?? -1;
  if (isMock) {
    onState?.("live");
    const timers: number[] = [];
    mockApi.liveEvents(scanId).then((history) => {
      history.events.forEach((event, i) => {
        if (event.seq <= cursor) return;
        timers.push(
          window.setTimeout(() => {
            cursor = Math.max(cursor, event.seq);
            onEvent(event.kind, event);
          }, 140 * (i + 1)),
        );
      });
      timers.push(
        window.setTimeout(() => {
          onState?.("closed");
          onDone?.("running");
        }, 140 * (history.events.length + 1)),
      );
    });
    return () => {
      timers.forEach((t) => window.clearTimeout(t));
      onState?.("closed");
    };
  }

  let stopped = false;
  let source: EventSource | null = null;
  let pollTimer: number | null = null;
  let reconnectTimer: number | null = null;
  let failures = 0;
  let done = false;

  const KINDS = [
    "hello",
    "stage",
    "log",
    "ai_step",
    "ai_proposal",
    "verification_result",
    "done",
    "live",
  ];

  function handlePayload(kind: string, raw: string) {
    let data: unknown = raw;
    try {
      data = JSON.parse(raw) as unknown;
    } catch {
      // keep raw text
    }
    if (kind === "done") {
      done = true;
      const status =
        typeof data === "object" && data !== null
          ? String((data as Record<string, unknown>).status ?? "completed")
          : "completed";
      onDone?.(status);
      cleanup();
      onState?.("closed");
      return;
    }
    if (kind === "hello" || kind === "live") {
      onEvent(kind, data);
      return;
    }
    const seq =
      typeof data === "object" && data !== null
        ? Number((data as Record<string, unknown>).seq)
        : NaN;
    if (Number.isFinite(seq)) cursor = Math.max(cursor, seq);
    onEvent(kind, data);
  }

  function startPolling() {
    if (stopped || done || pollTimer !== null) return;
    onState?.("polling");
    const tick = () => {
      if (stopped || done) return;
      fetchEventsHistory(scanId)
        .then((history) => {
          for (const event of history.events) {
            if (event.seq > cursor) {
              cursor = event.seq;
              onEvent(event.kind, event);
            }
          }
        })
        .catch(() => undefined);
    };
    void tick();
    pollTimer = window.setInterval(tick, 3000);
  }

  function connect() {
    if (stopped || done) return;
    onState?.(failures === 0 ? "connecting" : "reconnecting");
    try {
      source = new EventSource(`/api/scans/${scanId}/events?last_event_id=${cursor}`);
    } catch {
      startPolling();
      return;
    }
    const active = source;
    for (const kind of KINDS) {
      active.addEventListener(kind, ((e: Event) => {
        handlePayload(kind, (e as MessageEvent).data as string);
      }) as EventListener);
    }
    active.onmessage = (msg) => handlePayload("message", msg.data as string);
    active.onerror = () => {
      active.close();
      if (stopped || done) return;
      failures += 1;
      if (failures >= 4) {
        startPolling();
        return;
      }
      onState?.("reconnecting");
      const backoff = Math.min(5000, 800 * failures);
      reconnectTimer = window.setTimeout(() => {
        reconnectTimer = null;
        connect();
      }, backoff);
    };
    active.onopen = () => {
      failures = 0;
      onState?.("live");
    };
  }

  connect();

  function cleanup() {
    source?.close();
    source = null;
    if (pollTimer !== null) {
      window.clearInterval(pollTimer);
      pollTimer = null;
    }
    if (reconnectTimer !== null) {
      window.clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
  }

  return () => {
    stopped = true;
    cleanup();
    onState?.("closed");
  };
}

/** ---- Phase 2: Home / New Scan / Keys (mock-aware) ---- */

export async function fetchTools(
  verify = false,
): Promise<{ tools: import("../api/types").ToolHealth[] }> {
  if (isMock) return mockApi.tools(verify);
  const query = verify ? "?verify=true" : "";
  return get<{ tools: import("../api/types").ToolHealth[] }>(`/api/tools${query}`);
}

export async function fetchGeneralSettings(): Promise<
  import("../api/types").GeneralSettings
> {
  if (isMock) return (await mockApi.settings()).general;
  return (await get<{ general: import("../api/types").GeneralSettings }>(`/api/settings`)).general;
}

export async function updateGeneralSettings(
  patch: Partial<import("../api/types").GeneralSettings>,
): Promise<import("../api/types").GeneralSettings> {
  if (isMock) return (await mockApi.updateSettings(patch)).general;
  return (await putJson<{ general: import("../api/types").GeneralSettings }>(`/api/settings`, patch))
    .general;
}

export async function fetchKeys(): Promise<import("../api/types").KeyEntry[]> {
  if (isMock) return (await mockApi.keys()).keys;
  return (await get<{ keys: import("../api/types").KeyEntry[] }>(`/api/settings/keys`)).keys;
}

export async function saveKey(
  profile: string,
  body: { api_key: string; base_url?: string; label?: string },
): Promise<import("../api/types").KeyEntry> {
  if (isMock) return mockApi.saveKey(profile, body);
  return putJson<import("../api/types").KeyEntry>(
    `/api/settings/keys/${encodeURIComponent(profile)}`,
    body,
  );
}

export async function deleteKey(profile: string): Promise<{ deleted: boolean }> {
  if (isMock) return mockApi.deleteKey(profile);
  return deleteJson<{ deleted: boolean }>(`/api/settings/keys/${encodeURIComponent(profile)}`);
}

export async function testKeyConnection(
  profile: string,
): Promise<{ ok: boolean; profile: string; model: string; error?: string }> {
  if (isMock) return mockApi.testKey(profile);
  return postJson<{ ok: boolean; profile: string; model: string; error?: string }>(
    `/api/settings/keys/${encodeURIComponent(profile)}/test`,
    {},
  );
}

export async function fetchUsage(): Promise<import("../api/types").UsageSummary> {
  if (isMock) return mockApi.usage();
  return get<import("../api/types").UsageSummary>(`/api/usage`);
}

export async function createScan(body: {
  repository_url: string;
  profile?: string;
  tools?: string[];
  ai_review?: boolean;
  provider_profile?: string | null;
  provider_model?: string | null;
  max_ai_findings?: number;
  timeout?: number;
  max_files?: number;
  mode?: string;
}): Promise<{ run_id: number; status: string; profile: string }> {
  if (isMock) return mockApi.createScan(body);
  return postJson<{ run_id: number; status: string; profile: string }>(`/api/scans`, body);
}

/** ---- AI fix: propose / list / apply (mock-aware) ---- */

export async function requestFix(
  runId: number,
  body: import("../api/types").FixRequestBody,
): Promise<{ accepted: boolean; run_id: number }> {
  if (isMock) return mockApi.requestFix(runId, body);
  return postJson<{ accepted: boolean; run_id: number }>(`/api/scans/${runId}/fix`, body);
}

export async function fetchFixes(
  runId: number,
): Promise<import("../api/types").FixesResponse> {
  if (isMock) return mockApi.fetchFixes(runId);
  return get<import("../api/types").FixesResponse>(`/api/scans/${runId}/fixes`);
}

export async function applyFix(
  runId: number,
  proposalId: string,
): Promise<{ id: string; status: string; overlay_path: string | null; verification: import("../api/types").FixVerification | null }> {
  if (isMock) return mockApi.applyFix(runId, proposalId);
  return postJson(`/api/scans/${runId}/fixes/${encodeURIComponent(proposalId)}/apply`, {});
}

/** ---- Task 4: notifications + fix .diff download (mock-aware) ---- */

/** Raw download URL for one proposal's unified diff (anchor href, no fetch). */
export function fixDiffUrl(runId: number, proposalId: string | number): string {
  if (isMock) return `#/scans/${runId}/fixes/${encodeURIComponent(String(proposalId))}/download`;
  return `/api/scans/${runId}/fixes/${encodeURIComponent(String(proposalId))}/download`;
}

export async function fetchNotifications(): Promise<import("../api/types").NotificationsResponse> {
  if (isMock) return { notifications: [], unread: 0 };
  return get<import("../api/types").NotificationsResponse>(`/api/notifications`);
}

export async function ackNotification(
  id: number,
): Promise<import("../api/types").ScanNotification> {
  if (isMock) return { id, run_id: 0, kind: "scan_completed", message: "", is_read: true, created_at: null };
  return postJson<import("../api/types").ScanNotification>(`/api/notifications/${id}/ack`, {});
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
