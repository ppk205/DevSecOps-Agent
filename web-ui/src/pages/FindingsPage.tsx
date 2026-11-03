import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { fetchFindings, fetchKeys, fetchScans, requestFix } from "../api/client";
import type { FindingListItem, FindingProvenance, FindingsQuery } from "../api/types";
import { downloadCsv, findingsToCsv } from "../api/findingsQuery";
import { DataTable } from "../components/DataTable";
import { EmptyState } from "../components/EmptyState";
import { FindingDrawer } from "../components/FindingDrawer";
import { FixProposals } from "../components/FixProposals";
import { StatusBadge } from "../components/FindingDetailView";
import { onTabListKeyDown } from "../components/Tabs";
import { SeverityBadge } from "../components/SeverityBadge";
import { StripeDivider } from "../components/StripeDivider";
import { useStrings } from "../i18n/lang";
import { PageHeader } from "./pages";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const PAGE_SIZES = [20, 50, 100];
const VIEWS_KEY = "pitwall.findingViews";

interface SavedView {
  name: string;
  query: FindingsQuery;
}

function loadViews(): SavedView[] {
  try {
    const raw = localStorage.getItem(VIEWS_KEY);
    const parsed: unknown = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? (parsed as SavedView[]) : [];
  } catch {
    return [];
  }
}

function AiDelta({ item }: { item: FindingListItem }) {
  if (!item.ai_severity) return <span className="text-muted">—</span>;
  if (!item.ai_changed) return <span className="text-body">{item.scanner_severity}</span>;
  return (
    <span className="text-body">
      {item.scanner_severity} <span className="text-warning">→ {item.ai_severity}</span>
    </span>
  );
}

function ProvenanceChip({ value }: { value: FindingProvenance }) {
  if (value === "model") {
    return (
      <span
        title="Found by the model hunt (scanner did not corroborate)"
        className="label-m inline-block border border-success px-1.5 py-0.5 text-[10px] text-success"
      >
        AI
      </span>
    );
  }
  if (value === "both") {
    return (
      <span
        title="Model hunt and scanner agree on this finding"
        className="label-m inline-block border border-[#8b5cf6] px-1.5 py-0.5 text-[10px] text-[#a78bfa]"
      >
        Both
      </span>
    );
  }
  return (
    <span
      title="Scanner finding (no model provenance recorded)"
      className="label-m inline-block border border-hairline px-1.5 py-0.5 text-[10px] text-muted"
    >
      Scanner
    </span>
  );
}

/**
 * Hunt provenance for one row. Reads the backend's provenance field plus
 * likely metadata.origin aliases; tolerant of everything missing (scanner).
 */
function provenanceOf(item: FindingListItem): FindingProvenance {
  const raw = item as unknown as Record<string, unknown>;
  const meta = raw.metadata as Record<string, unknown> | null | undefined;
  const candidates: unknown[] = [
    raw.provenance,
    raw.detection_origin,
    raw.hunt_origin,
    meta?.origin,
  ];
  for (const candidate of candidates) {
    const v = String(candidate ?? "").toLowerCase();
    if (v === "model" || v === "scanner" || v === "both") return v;
    if (v === "model_only" || v === "ai") return "model";
    if (v === "scanner_only") return "scanner";
  }
  return item.model_corroborated ? "both" : "scanner";
}

const DEFAULT_QUERY: FindingsQuery = { sort: "severity", order: "asc", page: 1, pageSize: 20 };

export function FindingsPage() {
  const en = useStrings();
  const [query, setQuery] = useState<FindingsQuery>(DEFAULT_QUERY);
  const [openId, setOpenId] = useState<string | null>(null);
  const [selected, setSelected] = useState(0);
  const [views, setViews] = useState<SavedView[]>(loadViews);
  const [viewName, setViewName] = useState("");

  const scansQuery = useQuery({ queryKey: ["scans"], queryFn: fetchScans });
  const scanId = scansQuery.data?.[0]?.run_id ?? 7;
  const queryClient = useQueryClient();
  const [fixAllFeedback, setFixAllFeedback] = useState<string | null>(null);
  const fixAllMutation = useMutation({
    mutationFn: async () => {
      const keys = await fetchKeys();
      const provider_profile = keys.length > 0 ? keys[0].profile : null;
      return requestFix(scanId, { finding_ids: null, provider_profile });
    },
    onSuccess: () => {
      setFixAllFeedback(en.fix.requested);
      void queryClient.invalidateQueries({ queryKey: ["fixes", scanId] });
    },
    onError: (err) => {
      setFixAllFeedback(
        `${en.fix.requestFailed} ${err instanceof Error ? err.message : String(err)}`,
      );
    },
  });

  // Provenance (model/scanner/both) is client-side only: the findings API
  // has no such param yet, so strip it before fetching. When the filter is
  // active, pull up to 1000 rows and paginate locally so counts stay exact.
  const provenanceFilter = query.provenance ?? null;
  const { provenance: _provenanceDrop, ...serverFilters } = query;
  const serverQuery: FindingsQuery = provenanceFilter
    ? { ...serverFilters, page: 1, pageSize: 1000 }
    : serverFilters;

  const findingsQuery = useQuery({
    queryKey: ["findings", scanId, query],
    queryFn: () => fetchFindings(scanId, serverQuery),
  });
  const optionsQuery = useQuery({
    queryKey: ["findings-options", scanId],
    queryFn: () => fetchFindings(scanId, { pageSize: 1000, page: 1 }),
  });

  const options = useMemo(() => {
    const items = optionsQuery.data?.items ?? [];
    const uniq = (pick: (i: FindingListItem) => string | string[]) => {
      const set = new Set<string>();
      for (const item of items) {
        const values = pick(item);
        (Array.isArray(values) ? values : [values]).forEach((v) => set.add(v));
      }
      return [...set].sort();
    };
    return { cwes: uniq((i) => i.cwe), scanners: uniq((i) => i.scanners), statuses: uniq((i) => i.status) };
  }, [optionsQuery.data]);

  const baseItems = findingsQuery.data?.items ?? [];
  const baseTotal = findingsQuery.data?.total ?? 0;

  const { items, total } = useMemo(() => {
    if (!provenanceFilter) return { items: baseItems, total: baseTotal };
    const kept = baseItems.filter((item) => provenanceOf(item) === provenanceFilter);
    const pageSize = query.pageSize ?? 20;
    const page = Math.max(1, query.page ?? 1);
    return { items: kept.slice((page - 1) * pageSize, page * pageSize), total: kept.length };
  }, [baseItems, baseTotal, provenanceFilter, query.page, query.pageSize]);

  useEffect(() => {
    setSelected(0);
  }, [query, scanId]);

  // Table-level J/K + Enter (active only while the drawer is closed).
  useEffect(() => {
    if (openId !== null) return;
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      if (target && (target.tagName === "INPUT" || target.tagName === "SELECT" || target.tagName === "TEXTAREA")) {
        return;
      }
      if (e.key === "j" || e.key === "J") {
        e.preventDefault();
        setSelected((s) => Math.min(items.length - 1, s + 1));
      } else if (e.key === "k" || e.key === "K") {
        e.preventDefault();
        setSelected((s) => Math.max(0, s - 1));
      } else if (e.key === "Enter" && items[selected]) {
        e.preventDefault();
        setOpenId(items[selected].id);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [openId, items, selected]);

  const patch = (p: Partial<FindingsQuery>) =>
    setQuery((q) => ({ ...q, ...p, page: p.page ?? 1 }));
  const toggleSeverity = (sev: string) =>
    setQuery((q) => {
      const current = new Set(q.severities ?? []);
      if (current.has(sev)) current.delete(sev);
      else current.add(sev);
      return { ...q, severities: [...current], page: 1 };
    });
  const toggleSort = (sort: NonNullable<FindingsQuery["sort"]>) =>
    setQuery((q) => ({
      ...q,
      sort,
      order: q.sort === sort && q.order === "asc" ? "desc" : "asc",
      page: 1,
    }));

  const saveView = () => {
    const name = viewName.trim();
    if (!name) return;
    const { page: _drop, ...filters } = query;
    const next = [...views.filter((v) => v.name !== name), { name, query: filters }];
    setViews(next);
    localStorage.setItem(VIEWS_KEY, JSON.stringify(next));
    setViewName("");
  };

  const exportFiltered = async () => {
    const { page: _drop, provenance: _provDrop, ...filters } = query;
    const full = await fetchFindings(scanId, { ...filters, page: 1, pageSize: 10000 });
    const kept = provenanceFilter
      ? full.items.filter((item) => provenanceOf(item) === provenanceFilter)
      : full.items;
    downloadCsv(`findings-run-${scanId}.csv`, findingsToCsv(kept));
  };

  const sortMark = (key: string) =>
    query.sort === key ? (query.order === "asc" ? " ▲" : " ▼") : "";

  const totalPages = Math.max(1, Math.ceil(total / (query.pageSize ?? 20)));

  return (
    <div>
      <PageHeader title={en.findings.title} subtitle={en.findings.subtitle} />
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <button
          onClick={() => fixAllMutation.mutate()}
          disabled={fixAllMutation.isPending}
          className="label-m border border-hairline px-3 py-1.5 text-[11px] text-body transition-colors hover:border-ink hover:text-ink disabled:opacity-40"
        >
          {fixAllMutation.isPending ? en.fix.fixingAll : en.fix.fixAll}
        </button>
        {fixAllFeedback && <span className="text-xs text-muted">{fixAllFeedback}</span>}
      </div>
      <section aria-label={en.fix.proposals} className="card mb-4 p-5">
        <div className="label-m mb-3 text-xs text-ink">{en.fix.proposals}</div>
        <FixProposals runId={scanId} />
      </section>

      <div className="mb-4 flex flex-wrap gap-2" role="tablist" aria-label="Origin">
        {(
          [
            { key: null, label: en.findings.tabs.all },
            { key: "source", label: en.findings.tabs.source },
            { key: "dependency", label: en.findings.tabs.dependency },
          ] as const
        ).map((tab) => {
          const selected = (query.origin ?? null) === tab.key;
          const tabId = tab.key ?? "all";
          return (
          <button
            key={tab.label}
            role="tab"
            data-tab={tabId}
            aria-selected={selected}
            tabIndex={selected ? 0 : -1}
            onClick={() => patch({ origin: tab.key })}
            onKeyDown={(e) =>
              onTabListKeyDown(e, ["all", "source", "dependency"], tabId, (id) =>
                patch({ origin: id === "all" ? null : (id as "source" | "dependency") }),
              )
            }
            className={`label-m border px-3 py-1.5 text-[11px] transition-colors duration-150 ${
              selected
                ? "border-ink text-ink"
                : "border-hairline text-muted hover:text-body"
            }`}
          >
            {tab.label}
          </button>
          );
        })}
      </div>

      <div className="card mb-4 flex flex-wrap items-end gap-4 p-4">
        <label className="flex min-w-52 flex-1 flex-col gap-1">
          <span className="label-m text-[11px] text-muted">Search</span>
          <input
            value={query.q ?? ""}
            onChange={(e) => patch({ q: e.target.value })}
            placeholder={en.findings.searchPlaceholder}
            className="border border-hairline bg-canvas px-3 py-1.5 text-sm text-ink outline-none placeholder:text-muted focus:border-ink"
          />
        </label>
        <div className="flex flex-col gap-1">
          <span className="label-m text-[11px] text-muted">{en.findings.filters.severity}</span>
          <div className="flex gap-1">
            {SEVERITIES.map((sev) => (
              <button
                key={sev}
                onClick={() => toggleSeverity(sev)}
                aria-pressed={(query.severities ?? []).includes(sev)}
                className={`label-m border px-2 py-1.5 text-[11px] transition-colors duration-150 ${
                  (query.severities ?? []).includes(sev)
                    ? "border-ink text-ink"
                    : "border-hairline text-muted hover:text-body"
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>
        {(
          [
            { key: "cwes", label: en.findings.filters.cwe },
            { key: "scanners", label: en.findings.filters.scanner },
            { key: "verifications", label: en.findings.filters.verification },
          ] as const
        ).map((field) => (
          <label key={field.key} className="flex flex-col gap-1">
            <span className="label-m text-[11px] text-muted">{field.label}</span>
            <select
              value={(query[field.key]?.[0] ?? "") as string}
              onChange={(e) =>
                patch({ [field.key]: e.target.value ? [e.target.value] : [] } as Partial<FindingsQuery>)
              }
              className="border border-hairline bg-canvas px-2 py-1.5 text-sm text-ink outline-none focus:border-ink"
            >
              <option value="">{en.findings.allOption}</option>
              {options[field.key === "verifications" ? "statuses" : field.key === "cwes" ? "cwes" : "scanners"].map(
                (value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ),
              )}
            </select>
          </label>
        ))}
        <label className="flex flex-col gap-1">
          <span className="label-m text-[11px] text-muted">{en.findings.filters.aiChanged}</span>
          <select
            value={query.aiChanged === true ? "changed" : query.aiChanged === false ? "unchanged" : ""}
            onChange={(e) =>
              patch({
                aiChanged: e.target.value === "changed" ? true : e.target.value === "unchanged" ? false : null,
              })
            }
            className="border border-hairline bg-canvas px-2 py-1.5 text-sm text-ink outline-none focus:border-ink"
          >
            <option value="">{en.findings.filters.aiChangedOptions.all}</option>
            <option value="changed">{en.findings.filters.aiChangedOptions.changed}</option>
            <option value="unchanged">{en.findings.filters.aiChangedOptions.unchanged}</option>
          </select>
        </label>
        <label className="flex flex-col gap-1">
          <span className="label-m text-[11px] text-muted">Origin</span>
          <select
            value={query.provenance ?? ""}
            onChange={(e) =>
              patch({
                provenance: e.target.value
                  ? (e.target.value as FindingProvenance)
                  : null,
              })
            }
            className="border border-hairline bg-canvas px-2 py-1.5 text-sm text-ink outline-none focus:border-ink"
          >
            <option value="">{en.findings.allOption}</option>
            <option value="model">Model</option>
            <option value="scanner">Scanner</option>
            <option value="both">Both</option>
          </select>
        </label>
        <button
          onClick={() => setQuery(DEFAULT_QUERY)}
          className="label-m border border-hairline px-3 py-1.5 text-[11px] text-muted transition-colors hover:text-ink"
        >
          {en.findings.filters.clear}
        </button>
      </div>

      {views.length > 0 && (
        <div className="mb-4 flex flex-wrap items-center gap-2">
          {views.map((view) => (
            <span key={view.name} className="flex items-center border border-hairline">
              <button
                onClick={() => setQuery({ ...DEFAULT_QUERY, ...view.query, page: 1 })}
                className="label-m px-2 py-1 text-[11px] text-body transition-colors hover:text-ink"
              >
                {view.name}
              </button>
              <button
                aria-label={`Delete ${view.name}`}
                onClick={() => {
                  const next = views.filter((v) => v.name !== view.name);
                  setViews(next);
                  localStorage.setItem(VIEWS_KEY, JSON.stringify(next));
                }}
                className="label-m px-1 text-[11px] text-muted hover:text-ink"
              >
                ✕
              </button>
            </span>
          ))}
        </div>
      )}
      <div className="mb-4 flex items-center gap-2">
        <input
          value={viewName}
          onChange={(e) => setViewName(e.target.value)}
          placeholder={en.findings.filters.chipName}
          className="border border-hairline bg-canvas px-3 py-1.5 text-sm text-ink outline-none placeholder:text-muted focus:border-ink"
        />
        <button
          onClick={saveView}
          className="label-m border border-hairline px-3 py-1.5 text-[11px] text-body transition-colors hover:border-ink hover:text-ink"
        >
          {en.findings.filters.saveChip}
        </button>
        <button
          onClick={exportFiltered}
          className="label-m ml-auto border border-hairline px-3 py-1.5 text-[11px] text-body transition-colors hover:border-ink hover:text-ink"
        >
          {en.findings.export} ({total})
        </button>
      </div>

      {findingsQuery.isLoading ? (
        <p className="text-body">{en.common.loading}</p>
      ) : items.length === 0 ? (
        <EmptyState title={en.findings.emptyFiltered} body={en.common.emptyBody} />
      ) : (
        <div>
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <p className="text-xs uppercase tracking-widest text-muted">
              {(query.page ?? 1) * (query.pageSize ?? 20) - (query.pageSize ?? 20) + 1}–
              {Math.min(total, (query.page ?? 1) * (query.pageSize ?? 20))} {en.findings.pager.of}{" "}
              {total} {en.findings.pager.showing}
            </p>
            <div className="flex items-center gap-1" aria-label="Sort">
              {(["severity", "title", "file", "status"] as const).map((key) => (
                <button
                  key={key}
                  onClick={() => toggleSort(key)}
                  aria-pressed={query.sort === key}
                  className={`label-m border px-2 py-1 text-[10px] transition-colors duration-150 ${
                    query.sort === key
                      ? "border-ink text-ink"
                      : "border-hairline text-muted hover:text-body"
                  }`}
                >
                  {key}
                  {sortMark(key)}
                </button>
              ))}
            </div>
            <p className="label-m hidden text-[11px] text-muted lg:block">{en.findings.shortcuts}</p>
          </div>
          <DataTable
            columns={[
              {
                key: "severity",
                header: `${en.findings.columns.severity}${sortMark("severity")}`,
                render: (f: FindingListItem) => <SeverityBadge severity={f.severity} />,
              },
              {
                key: "title",
                header: `${en.findings.columns.title}${sortMark("title")}`,
                render: (f: FindingListItem) => (
                  <span>
                    <button
                      onClick={() => setOpenId(f.id)}
                      className="block text-left text-ink underline-offset-4 hover:underline"
                    >
                      {f.title}
                      {f.model_corroborated && (
                        <span
                          title="Model hunt independently flagged the same issue"
                          className="label-m ml-2 inline-block border border-success px-1.5 py-0.5 text-[10px] text-success"
                        >
                          AI ✓
                        </span>
                      )}
                    </button>
                    <span className="font-mono text-[10px] text-muted">{f.id}</span>
                  </span>
                ),
              },
              {
                key: "cwe",
                header: en.findings.columns.cwe,
                render: (f: FindingListItem) => <span className="font-mono text-xs">{f.cwe}</span>,
              },
              {
                key: "loc",
                header: `${en.findings.columns.location}${sortMark("file")}`,
                render: (f: FindingListItem) => (
                  <span className="font-mono text-xs">
                    {f.file}:{f.line}
                  </span>
                ),
              },
              {
                key: "scanners",
                header: en.findings.columns.scanners,
                render: (f: FindingListItem) => (
                  <span>
                    {f.scanners.join(", ")}
                    {f.model_corroborated && (
                      <span
                        title="Model hunt independently flagged the same issue"
                        className="label-m ml-2 border border-success px-1.5 py-0.5 text-[10px] text-success"
                      >
                        AI ✓
                      </span>
                    )}
                  </span>
                ),
              },
              {
                key: "origin",
                header: "Origin",
                render: (f: FindingListItem) => <ProvenanceChip value={provenanceOf(f)} />,
              },
              {
                key: "ai",
                header: en.findings.columns.aiVsScanner,
                render: (f: FindingListItem) => <AiDelta item={f} />,
              },
              {
                key: "ver",
                header: `${en.findings.columns.verification}${sortMark("status")}`,
                render: (f: FindingListItem) => <StatusBadge status={f.status} />,
              },
              {
                key: "status",
                header: en.findings.columns.status,
                render: (f: FindingListItem) => <span className="font-mono text-xs">{f.status}</span>,
              },
            ]}
            rows={items}
            rowKey={(f) => f.id}
            emptyTitle={en.findings.emptyFiltered}
          />
          <div className="mt-4 flex flex-wrap items-center gap-3">
            <div className="max-w-xs flex-1">
              <StripeDivider progress={total === 0 ? 0 : (query.page ?? 1) / totalPages} />
            </div>
            <button
              disabled={(query.page ?? 1) <= 1}
              onClick={() => setQuery((q) => ({ ...q, page: (q.page ?? 1) - 1 }))}
              className="label-m border border-hairline px-3 py-1.5 text-[11px] text-body disabled:opacity-40"
            >
              ←
            </button>
            <span className="label-m text-[11px] text-muted">
              {query.page ?? 1} / {totalPages}
            </span>
            <button
              disabled={(query.page ?? 1) >= totalPages}
              onClick={() => setQuery((q) => ({ ...q, page: (q.page ?? 1) + 1 }))}
              className="label-m border border-hairline px-3 py-1.5 text-[11px] text-body disabled:opacity-40"
            >
              →
            </button>
            <label className="label-m ml-auto flex items-center gap-2 text-[11px] text-muted">
              {en.findings.pager.pageSize}
              <select
                value={query.pageSize ?? 20}
                onChange={(e) => setQuery((q) => ({ ...q, pageSize: Number(e.target.value), page: 1 }))}
                className="border border-hairline bg-canvas px-2 py-1 text-ink outline-none"
              >
                {PAGE_SIZES.map((size) => (
                  <option key={size} value={size}>
                    {size}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <p className="mt-2 text-[11px] text-muted">
            {en.findings.sortedBy} {query.sort} ({query.order}).
          </p>
        </div>
      )}

      <FindingDrawer
        findingId={openId}
        runId={scanId}
        onClose={() => setOpenId(null)}
        onPrev={() => {
          const i = items.findIndex((f) => f.id === openId);
          if (i > 0) {
            setSelected(i - 1);
            setOpenId(items[i - 1].id);
          }
        }}
        onNext={() => {
          const i = items.findIndex((f) => f.id === openId);
          if (i >= 0 && i < items.length - 1) {
            setSelected(i + 1);
            setOpenId(items[i + 1].id);
          }
        }}
        hasPrev={items.findIndex((f) => f.id === openId) > 0}
        hasNext={
          items.findIndex((f) => f.id === openId) >= 0 &&
          items.findIndex((f) => f.id === openId) < items.length - 1
        }
      />
    </div>
  );
}
