import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  cancelScan,
  fetchFindings,
  fetchLiveEventsHistory,
  fetchLiveScan,
  fetchScans,
  openLiveStream,
  retryScan,
} from "../api/client";
import type {
  FindingListItem,
  LiveConnection,
  ScanEvent,
} from "../api/types";
import { EmptyState } from "../components/EmptyState";
import { SeverityBadge } from "../components/SeverityBadge";
import { StripeDivider } from "../components/StripeDivider";
import { en } from "../i18n/en";
import { isMock } from "../mock/mockClient";
import { redactSecrets } from "../utils/redact";
import {
  LIVE_NODES,
  aggregateNodeStatuses,
  mapRawStage,
  nodeMessage,
  railProgress,
} from "../utils/liveStages";
import { PageHeader } from "./pages";

type MobileTab = "stages" | "ai" | "results" | "logs";

function toStreamEvent(data: unknown): ScanEvent | null {
  if (typeof data !== "object" || data === null) return null;
  const record = data as Record<string, unknown>;
  if (typeof record.seq !== "number" || typeof record.message !== "string") return null;
  return {
    seq: record.seq,
    kind: (record.kind as ScanEvent["kind"]) ?? "log",
    stage: typeof record.stage === "string" ? record.stage : null,
    message: record.message,
    created_at: typeof record.created_at === "string" ? record.created_at : "",
    payload: record.payload,
  };
}

const SEVERITY_FIRST: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function statusRank(status: string): number {
  if (status === "confirmed") return 0;
  if (status === "unresolved") return 1;
  if (status === "unprocessed") return 2;
  return 3;
}

export function LivePage() {
  const queryClient = useQueryClient();
  const scans = useQuery({ queryKey: ["scans"], queryFn: fetchScans });
  const ids = useMemo(() => (scans.data ?? []).map((s) => s.run_id), [scans.data]);
  const [scanId, setScanId] = useState<number | null>(null);
  const active = scanId ?? ids[0] ?? null;

  const [streamed, setStreamed] = useState<ScanEvent[]>([]);
  const [connection, setConnection] = useState<LiveConnection>("idle");
  const [cancelling, setCancelling] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [scrub, setScrub] = useState<number | null>(null);
  const [paused, setPaused] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const [tab, setTab] = useState<MobileTab>("stages");
  const dockRef = useRef<HTMLDivElement>(null);

  const live = useQuery({
    queryKey: ["liveScan", active],
    queryFn: () => fetchLiveScan(active as number),
    enabled: active !== null,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === "running" || status === "queued" ? 4000 : false;
    },
  });

  const history = useQuery({
    queryKey: ["liveEvents", active],
    queryFn: () => fetchLiveEventsHistory(active as number),
    enabled: active !== null,
  });

  const findings = useQuery({
    queryKey: ["liveFindings", active],
    queryFn: () => fetchFindings(active as number, { pageSize: 100 }),
    enabled: active !== null,
  });

  useEffect(() => {
    setStreamed([]);
    setScrub(null);
    setSelectedNode(null);
    setPaused(false);
    setCancelling(false);
    setActionError(null);
  }, [active]);

  useEffect(() => {
    if (active === null || paused) return;
    const close = openLiveStream(active, {
      cursor: history.data?.next_cursor ?? -1,
      onEvent: (kind, data) => {
        if (kind === "hello" || kind === "live" || kind === "message") return;
        const event = toStreamEvent(data);
        if (!event) return;
        setStreamed((prev) =>
          prev.some((e) => e.seq === event.seq) ? prev : [...prev, event],
        );
      },
      onState: setConnection,
      onDone: () => {
        void queryClient.invalidateQueries({ queryKey: ["liveScan", active] });
        void queryClient.invalidateQueries({ queryKey: ["liveEvents", active] });
      },
    });
    return close;
  }, [active, paused, queryClient, history.data?.next_cursor]);

  useEffect(() => {
    if (!autoScroll || paused) return;
    const dock = dockRef.current;
    if (dock) {
      try {
        dock.scrollTop = dock.scrollHeight;
      } catch {
        // jsdom has no layout — ignore.
      }
    }
  }, [streamed, autoScroll, paused]);

  const merged = useMemo(() => {
    const base = history.data?.events ?? [];
    const extra = streamed.filter((e) => !base.some((b) => b.seq === e.seq));
    return [...base, ...extra].sort((a, b) => a.seq - b.seq);
  }, [history, streamed]);

  const maxSeq = merged.length > 0 ? merged[merged.length - 1].seq : -1;
  const effectiveScrub = scrub ?? maxSeq;
  const replaying = scrub !== null && scrub < maxSeq;
  const visible = replaying ? merged.filter((e) => e.seq <= effectiveScrub) : merged;
  const stageFiltered =
    selectedNode !== null ? visible.filter((e) => mapRawStage(e.stage ?? "") === selectedNode) : visible;

  const statuses = useMemo(
    () => aggregateNodeStatuses(live.data?.stages ?? []),
    [live],
  );
  const progress = railProgress(statuses);
  const runningNode = LIVE_NODES.find((n) => statuses[n.key] === "running")?.key ?? null;
  const detailNode = selectedNode ?? runningNode ?? "intake";
  const detailMessage = nodeMessage(detailNode, live.data?.stages ?? []);

  const aiSteps = useMemo(
    () => visible.filter((e) => e.kind === "ai_step"),
    [visible],
  );
  const proposals = useMemo(
    () => visible.filter((e) => e.kind === "ai_proposal"),
    [visible],
  );
  const verifications = useMemo(
    () => visible.filter((e) => e.kind === "verification_result"),
    [visible],
  );
  const nowAnalyzing = [...aiSteps].reverse()[0] ?? null;

  const items: FindingListItem[] = useMemo(() => {
    const rows = findings.data?.items ?? [];
    return [...rows].sort(
      (a, b) =>
        statusRank(a.status) - statusRank(b.status) ||
        (SEVERITY_FIRST[a.severity] ?? 9) - (SEVERITY_FIRST[b.severity] ?? 9),
    );
  }, [findings.data]);

  const scannerLanes = useMemo(() => {
    const tally = new Map<string, number>();
    for (const item of items) {
      for (const tool of item.scanners) tally.set(tool, (tally.get(tool) ?? 0) + 1);
    }
    return [...tally.entries()].sort((a, b) => b[1] - a[1]);
  }, [items]);

  const scannerHits = useMemo(
    () => items.reduce((sum, item) => sum + Math.max(1, item.scanners.length), 0),
    [items],
  );
  const counts = live.data?.counts;
  const reviewed = (counts?.confirmed ?? 0) + (counts?.rejected ?? 0);
  const total = counts?.total ?? items.length;

  if (scans.isLoading || active === null) {
    if (scans.isLoading) return <p className="text-body">{en.common.loading}</p>;
    return (
      <div>
        <PageHeader title={en.live.title} subtitle={en.live.subtitle} />
        <EmptyState title={en.live.noScans} body={en.live.noScans} />
      </div>
    );
  }

  const status = cancelling ? "cancelling" : String(live.data?.status ?? "queued");
  const terminal = ["completed", "failed", "cancelled"].includes(status);

  function refresh() {
    void queryClient.invalidateQueries({ queryKey: ["liveScan", active] });
    void queryClient.invalidateQueries({ queryKey: ["liveEvents", active] });
    void queryClient.invalidateQueries({ queryKey: ["liveFindings", active] });
  }

  async function onCancel() {
    if (active === null) return;
    setCancelling(true);
    setActionError(null);
    try {
      await cancelScan(active);
      refresh();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setCancelling(false);
    }
  }

  async function onRetry() {
    if (active === null) return;
    setActionError(null);
    try {
      const created = await retryScan(active);
      setScanId(created.run_id);
      void queryClient.invalidateQueries({ queryKey: ["scans"] });
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error));
    }
  }

  const connectionLabel =
    connection === "live" ? "LIVE" : connection === "polling" ? "POLLING"
    : connection === "reconnecting" ? "RECONNECTING"
    : connection === "connecting" ? "CONNECTING" : "REPLAY";

  return (
    <div>
      <PageHeader title={en.live.title} subtitle={en.live.subtitle} />

      <div className="mb-6 flex flex-wrap items-center gap-3">
        <label className="label-m text-[11px] text-muted">
          {en.live.selectScan}{" "}
          <select
            aria-label={en.live.selectScan}
            className="ml-1 border border-hairline bg-canvas px-2 py-1.5 text-sm text-ink"
            value={active}
            onChange={(e) => setScanId(Number(e.target.value))}
          >
            {ids.map((id) => (
              <option key={id} value={id}>
                Scan #{id}
              </option>
            ))}
          </select>
        </label>
        <span
          data-testid="live-status"
          className="label-m border border-hairline px-2 py-1 text-[10px] text-ink"
        >
          {status.toUpperCase()}
        </span>
        <span
          data-testid="live-connection"
          className={`label-m border px-2 py-1 text-[10px] ${
            connection === "live" ? "border-success text-success"
            : connection === "polling" || connection === "reconnecting" ? "border-warning text-warning"
            : "border-hairline text-muted"
          }`}
        >
          {connectionLabel}
          {isMock ? " · MOCK" : ""}
        </span>
        <span className="ml-auto flex gap-2">
          {!terminal && (
            <button
              className="label-m border border-hairline px-3 py-1.5 text-[11px] text-body hover:text-ink"
              onClick={() => void onCancel()}
              disabled={cancelling}
            >
              {cancelling ? en.live.cancelling : en.live.cancel}
            </button>
          )}
          {terminal && (
            <button
              className="label-m border border-hairline px-3 py-1.5 text-[11px] text-body hover:text-ink"
              onClick={() => void onRetry()}
            >
              {en.live.retry}
            </button>
          )}
        </span>
      </div>
      {actionError && (
        <p role="alert" className="mb-4 text-sm text-warning">
          {redactSecrets(actionError)}
        </p>
      )}

      {(connection === "reconnecting" || connection === "polling") && (
        <div
          data-testid="reconnect-banner"
          role="status"
          className="mb-6 border border-warning px-4 py-3 text-sm text-body"
        >
          {connection === "reconnecting" ? en.live.reconnecting : en.live.polling}
        </div>
      )}

      <div className="mb-8">
        <div className="mb-2 flex items-center justify-between">
          <span className="label-m text-xs text-muted">{en.live.stages}</span>
          <span className="text-xs uppercase tracking-widest text-muted">
            {replaying ? `${en.live.replayMode} #${effectiveScrub}` : en.live.liveMode}
          </span>
        </div>
        <StripeDivider progress={progress} />
        <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-8" role="list" aria-label={en.live.stages}>
          {LIVE_NODES.map((node) => {
            const nodeStatus = statuses[node.key];
            const selected = selectedNode === node.key;
            return (
              <button
                key={node.key}
                role="listitem"
                data-testid={`stage-${node.key}`}
                aria-pressed={selected}
                title={node.hint}
                onClick={() => setSelectedNode((prev) => (prev === node.key ? null : node.key))}
                className={`border p-3 text-left ${
                  selected ? "border-ink" : "border-hairline"
                } bg-soft hover:border-body`}
              >
                <div className="label-m text-[11px] text-ink">{node.label}</div>
                <div className="mt-1 text-[11px] uppercase tracking-widest text-muted">{nodeStatus}</div>
                <div
                  aria-hidden
                  className={`mt-2 h-1 w-full ${nodeStatus === "running" ? "stage-running" : "bg-hairline"}`}
                  style={nodeStatus === "completed" ? { background: "#0fa336" } : nodeStatus === "failed" ? { background: "#e22718" } : undefined}
                />
              </button>
            );
          })}
        </div>
      </div>

      <div className="mb-6">
        <label className="label-m text-[11px] text-muted" htmlFor="live-timeline">
          {en.live.timeline}
        </label>
        <input
          id="live-timeline"
          aria-label={en.live.timeline}
          type="range"
          min={-1}
          max={maxSeq}
          value={effectiveScrub}
          onChange={(e) => {
            const value = Number(e.target.value);
            setScrub(value >= maxSeq ? null : value);
          }}
          className="mt-2 w-full"
        />
        <div className="mt-1 flex justify-between text-xs text-muted">
          <span>#-1</span>
          <span data-testid="timeline-cursor">#{effectiveScrub} / #{maxSeq}</span>
        </div>
      </div>

      <div className="mb-6 flex gap-2 md:hidden" role="tablist" aria-label="Live sections">
        {(["stages", "ai", "results", "logs"] as MobileTab[]).map((key) => (
          <button
            key={key}
            role="tab"
            aria-selected={tab === key}
            onClick={() => setTab(key)}
            className={`label-m flex-1 border px-2 py-2 text-[11px] ${
              tab === key ? "border-ink text-ink" : "border-hairline text-muted"
            }`}
          >
            {en.live.tabs[key]}
          </button>
        ))}
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <section aria-label={en.live.stageDetail} className={tab === "stages" ? "" : "hidden md:block"}>
          <div className="card p-6">
            <h2 className="label-m mb-1 text-xs text-muted">{en.live.stageDetail}</h2>
            <p className="text-lg text-ink">{LIVE_NODES.find((n) => n.key === detailNode)?.label}</p>
            {detailMessage && <p className="mt-1 text-sm text-body">{redactSecrets(detailMessage)}</p>}
            <h3 className="label-m mb-2 mt-6 text-[11px] text-muted">{en.live.scannerLanes}</h3>
            {scannerLanes.length === 0 ? (
              <p className="text-sm text-muted">{en.common.emptyTitle}</p>
            ) : (
              <ul className="space-y-2">
                {scannerLanes.map(([tool, count]) => (
                  <li key={tool} className="flex items-center justify-between text-sm">
                    <span className="font-mono text-body">{tool}</span>
                    <span className="text-ink">{count}</span>
                  </li>
                ))}
              </ul>
            )}
            <h3 className="label-m mb-2 mt-6 text-[11px] text-muted">{en.live.normalization}</h3>
            <p data-testid="normalization-counter" className="font-mono text-sm text-body">
              {scannerHits} {en.live.observations} → {total} {en.live.findings}
            </p>
            <h3 className="label-m mb-2 mt-6 text-[11px] text-muted">{en.live.enrichment}</h3>
            <p className="text-sm text-body">
              {live.data?.ai.assessments.length ?? 0} assessments ·{" "}
              {live.data?.ai.decisions.length ?? 0} decisions ·{" "}
              agreed {live.data?.ai.comparison_counts.agreed ?? 0}
            </p>
            {selectedNode && (
              <button
                className="label-m mt-6 text-[11px] text-muted underline"
                onClick={() => setSelectedNode(null)}
              >
                {en.findings.filters.clear}
              </button>
            )}
          </div>
        </section>

        <section aria-label={en.live.aiPanel} className={tab === "ai" ? "" : "hidden md:block"}>
          <div className="card p-6">
            <h2 className="label-m mb-4 text-xs text-muted">{en.live.aiPanel}</h2>
            {nowAnalyzing ? (
              <div data-testid="now-analyzing" className="border border-hairline bg-canvas p-4">
                <div className="label-m text-[11px] text-muted">{en.live.nowAnalyzing}</div>
                <p className="mt-1 text-sm text-ink">{redactSecrets(nowAnalyzing.message)}</p>
              </div>
            ) : (
              <p className="text-sm text-muted">{en.common.emptyTitle}</p>
            )}
            <h3 className="label-m mb-2 mt-6 text-[11px] text-muted">{en.live.reasoningFeed}</h3>
            <ol className="max-h-48 space-y-2 overflow-y-auto">
              {[...aiSteps].reverse().slice(0, 8).map((event) => (
                <li key={event.seq} className="text-[13px] text-body">
                  <span className="mr-2 font-mono text-xs text-muted">#{event.seq}</span>
                  {redactSecrets(event.message)}
                </li>
              ))}
            </ol>
            <h3 className="label-m mb-2 mt-6 text-[11px] text-muted">{en.live.proposals}</h3>
            {(live.data?.ai.assessments ?? []).slice(0, 3).map((assessment, i) => (
              <div key={`${assessment.finding_id ?? i}`} className="mb-3 border border-hairline p-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs text-ink">{assessment.finding_id ?? "proposal"}</span>
                  <span className="text-xs uppercase text-muted">
                    {assessment.proposed_severity ?? ""} · {assessment.confidence ?? ""}
                  </span>
                </div>
                {assessment.cvss && (
                  <p data-testid="cvss-vector" className="mt-1 font-mono text-xs text-body">
                    {assessment.cvss.vector}
                    {typeof assessment.cvss.base_score === "number" ? ` · ${assessment.cvss.base_score}` : ""}
                  </p>
                )}
                {assessment.rationale && (
                  <p className="mt-1 text-[13px] text-body">{assessment.rationale}</p>
                )}
              </div>
            ))}
            <h3 className="label-m mb-2 mt-6 text-[11px] text-muted">{en.live.claimVsCheck}</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-[13px]">
                <thead>
                  <tr className="text-left text-muted">
                    <th className="py-1 pr-3 font-normal">Finding</th>
                    <th className="py-1 pr-3 font-normal">Claim</th>
                    <th className="py-1 font-normal">Check</th>
                  </tr>
                </thead>
                <tbody>
                  {(live.data?.ai.decisions ?? []).map((decision, i) => {
                    const check = verifications.find(
                      (event) =>
                        typeof event.payload === "object" &&
                        event.payload !== null &&
                        (event.payload as Record<string, unknown>).finding_id === decision.finding_id,
                    );
                    return (
                      <tr key={`${decision.finding_id ?? i}`} className="border-t border-hairline">
                        <td className="py-1 pr-3 font-mono text-xs text-ink">{decision.finding_id}</td>
                        <td className="py-1 pr-3 text-body">
                          {decision.previous_status} → {decision.new_status}
                        </td>
                        <td className="py-1 text-body">
                          {check ? redactSecrets(check.message) : (decision.outcome ?? "")}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <p data-testid="queue-progress" className="mt-4 font-mono text-xs text-muted">
              {en.live.queue}: {reviewed}/{total} · {proposals.length} proposals
            </p>
          </div>
        </section>

        <section aria-label={en.live.results} className={tab === "results" ? "" : "hidden md:block"}>
          <div className="card p-6">
            <div className="mb-1 flex items-baseline justify-between">
              <h2 className="label-m text-xs text-muted">{en.live.results}</h2>
              <span className="text-[11px] uppercase tracking-widest text-muted">{en.live.confirmedFirst}</span>
            </div>
            {counts && (
              <p data-testid="results-counters" className="mb-4 font-mono text-xs text-body">
                {counts.confirmed}C · {counts.rejected}R · {counts.unresolved}U · {counts.unprocessed}N · {counts.total} total
              </p>
            )}
            <ul className="max-h-[480px] space-y-3 overflow-y-auto">
              {items.slice(0, 12).map((item) => (
                <li key={item.id} data-testid={`live-finding-${item.id}`} className="border border-hairline p-3">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={item.severity} />
                    <span className="font-mono text-xs text-muted">{item.id}</span>
                    <span className="label-m ml-auto text-[10px] text-muted">{item.status}</span>
                  </div>
                  <p className="mt-1 text-sm text-ink">{item.title}</p>
                  <p className="mt-1 font-mono text-xs text-muted">
                    {item.file}:{item.line} · {item.scanners.join(" + ")}
                  </p>
                </li>
              ))}
            </ul>
          </div>
        </section>
      </div>

      <section aria-label={en.live.logDock} className={`mt-6 ${tab === "logs" ? "" : "hidden md:block"}`}>
        <div className="card">
          <div className="flex flex-wrap items-center gap-3 border-b border-hairline px-4 py-3">
            <h2 className="label-m text-xs text-muted">{en.live.logDock}</h2>
            <span className="font-mono text-xs text-muted">
              {stageFiltered.length}/{visible.length}
            </span>
            <span className="ml-auto flex gap-2">
              <button
                className="label-m text-[11px] text-muted underline"
                onClick={() => setPaused((v) => !v)}
              >
                {paused ? en.live.resume : en.live.pause}
              </button>
              <button
                className="label-m text-[11px] text-muted underline"
                onClick={() => setAutoScroll((v) => !v)}
              >
                {en.live.autoScroll}: {autoScroll ? "on" : "off"}
              </button>
            </span>
          </div>
          <div ref={dockRef} data-testid="log-dock" className="max-h-64 overflow-y-auto px-4 py-2">
            {stageFiltered.slice(-100).map((event) => (
              <div key={event.seq} className="flex gap-3 border-b border-hairline py-1.5 text-[13px] last:border-0">
                <span className="w-10 shrink-0 font-mono text-xs text-muted">#{event.seq}</span>
                <span className="w-24 shrink-0 uppercase text-muted">{event.kind}</span>
                <span className="w-32 shrink-0 truncate text-muted">{event.stage ?? ""}</span>
                <span className="break-words text-body">{redactSecrets(event.message)}</span>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}
