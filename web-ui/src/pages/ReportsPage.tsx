import { useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  compareHtmlUrl,
  fetchCompare,
  fetchReports,
  fetchScans,
  generateReport,
} from "../api/client";
import type { ReportDescriptor, ReportFormat } from "../api/types";
import { Button } from "../components/Button";
import { DataTable } from "../components/DataTable";
import { EmptyState } from "../components/EmptyState";
import { en } from "../i18n/en";
import { copyText } from "../utils/clipboard";
import { PageHeader } from "./pages";

function formatSize(bytes: number | null): string {
  if (bytes === null) return "—";
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(1)} KB`;
}

function cliCommand(runId: number, format: ReportFormat): string {
  return `vulnscan scan-export ${runId} --fmt ${format} --out artifacts`;
}

function ReportRows({ runId }: { runId: number }) {
  const [generating, setGenerating] = useState<ReportFormat | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [preview, setPreview] = useState<ReportDescriptor | null>(null);
  const [fullscreen, setFullscreen] = useState(false);
  const previewBox = useRef<HTMLDivElement>(null);

  const query = useQuery({
    queryKey: ["reports", runId],
    queryFn: () => fetchReports(runId),
  });

  async function handleGenerate(format: ReportFormat) {
    setGenerating(format);
    setError(null);
    try {
      await generateReport(runId, format);
      // Generation is synchronous server-side; poll until the list flips.
      for (let attempt = 0; attempt < 10; attempt += 1) {
        const refreshed = await query.refetch();
        const entry = refreshed.data?.reports.find((r) => r.format === format);
        if (entry?.generated) break;
        await new Promise((resolve) => setTimeout(resolve, 500));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setGenerating(null);
    }
  }

  if (query.isLoading) return <p className="text-body">{en.common.loading}</p>;
  if (query.isError || !query.data) {
    return (
      <EmptyState
        title="Reports unavailable"
        body={query.error instanceof Error ? query.error.message : en.common.emptyBody}
        actionLabel={en.common.retry}
        onAction={() => query.refetch()}
      />
    );
  }

  const { reports, final_report: finalReport } = query.data;
  const htmlReport = reports.find((r) => r.format === "html");

  return (
    <div>
      {error && (
        <p role="alert" className="mb-4 border border-hairline px-4 py-3 text-sm text-body">
          Generate failed: {error}
        </p>
      )}
      <DataTable
        columns={[
          { key: "fmt", header: "Format", render: (r: ReportDescriptor) => <span className="text-ink">{r.format}</span> },
          { key: "size", header: "Size", render: (r: ReportDescriptor) => formatSize(r.size_bytes) },
          { key: "count", header: "Findings", render: (r: ReportDescriptor) => String(r.findings) },
          {
            key: "status",
            header: "Status",
            render: (r: ReportDescriptor) =>
              generating === r.format ? (
                <span className="text-muted">Generating…</span>
              ) : r.generated ? (
                <span className="text-ink">Ready</span>
              ) : (
                <span className="text-muted">Missing</span>
              ),
          },
          {
            key: "actions",
            header: "Actions",
            render: (r: ReportDescriptor) => (
              <span className="flex flex-wrap gap-2">
                {r.generated && r.download_url ? (
                  <a className="label-m text-xs text-ink underline" href={r.download_url} download>
                    Download
                  </a>
                ) : (
                  <Button
                    variant="secondary"
                    size="sm"
                    disabled={generating !== null}
                    onClick={() => handleGenerate(r.format)}
                  >
                    Generate
                  </Button>
                )}
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    void copyText(cliCommand(runId, r.format)).then((ok) =>
                      setCopied(ok ? `${runId}:${r.format}` : null),
                    );
                  }}
                  title="Copy the CLI command that regenerates this artifact"
                >
                  {copied === `${runId}:${r.format}` ? "Copied" : "Copy CLI command"}
                </Button>
              </span>
            ),
          },
        ]}
        rows={reports}
        rowKey={(r) => r.format}
      />
      {finalReport?.download_url && (
        <p className="mt-3 text-sm text-body">
          Final narrative:{" "}
          <a className="text-ink underline" href={finalReport.download_url} download>
            {finalReport.filename} ({formatSize(finalReport.size_bytes)})
          </a>{" "}
          · legacy txt/docx/final-report links stay in the server-rendered UI.
        </p>
      )}
      {htmlReport?.generated && htmlReport.download_url && (
        <div className="mt-8">
          <div className="mb-3 flex items-center gap-3">
            <h2 className="label-m text-sm text-ink">HTML preview (sandboxed)</h2>
            <Button variant="secondary" size="sm" onClick={() => setPreview(htmlReport)}>
              Preview
            </Button>
          </div>
          {preview && (
            <div
              ref={previewBox}
              className={fullscreen ? "fixed inset-0 z-50 bg-canvas p-6" : "card overflow-hidden"}
            >
              <div className="mb-2 flex items-center gap-3 px-2 pt-2">
                <span className="font-mono text-xs text-muted">{preview.filename}</span>
                <span className="ml-auto flex gap-2">
                  <Button variant="ghost" size="sm" onClick={() => setFullscreen((v) => !v)}>
                    {fullscreen ? "Exit fullscreen" : "Fullscreen"}
                  </Button>
                  <Button variant="ghost" size="sm" onClick={() => { setPreview(null); setFullscreen(false); }}>
                    {en.common.close}
                  </Button>
                </span>
              </div>
              {/* sandbox="" — no scripts, no same-origin access from the artifact. */}
              <iframe
                title={`Preview of ${preview.filename}`}
                src={preview.download_url ?? undefined}
                sandbox=""
                className="h-[480px] w-full border-0 bg-white"
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ComparePanel({ scanIds }: { scanIds: number[] }) {
  const [selected, setSelected] = useState<number[]>(scanIds.slice(0, 2));
  const ready = selected.length >= 2;
  const compare = useQuery({
    queryKey: ["compare", ...selected],
    queryFn: () => fetchCompare(selected),
    enabled: ready,
  });

  function toggle(id: number) {
    setSelected((prev) => (prev.includes(id) ? prev.filter((s) => s !== id) : [...prev, id].slice(-6)));
  }

  return (
    <div className="mt-12">
      <h2 className="label-m mb-3 text-sm text-ink">Compare scans</h2>
      <div className="mb-4 flex flex-wrap gap-2">
        {scanIds.map((id) => (
          <label key={id} className="label-m flex cursor-pointer items-center gap-2 border border-hairline px-3 py-1.5 text-[11px] text-body">
            <input
              type="checkbox"
              checked={selected.includes(id)}
              onChange={() => toggle(id)}
              aria-label={`Select scan ${id}`}
            />
            #{id}
          </label>
        ))}
      </div>
      {!ready && <p className="text-sm text-muted">Select at least 2 scans to compare.</p>}
      {ready && compare.isLoading && <p className="text-body">{en.common.loading}</p>}
      {ready && compare.data && (
        <div>
          <div className="grid gap-6 lg:grid-cols-2">
            <div className="card p-6">
              <div className="label-m mb-3 text-xs text-muted">Per scanner</div>
              <DataTable
                columns={[
                  { key: "tool", header: "Scanner", render: (r: { tool: string }) => r.tool },
                  ...compare.data.scans.map((s) => ({
                    key: `run-${s.run_id}`,
                    header: `#${s.run_id}`,
                    render: (r: { counts: Record<string, number> }) => String(r.counts[String(s.run_id)] ?? 0),
                  })),
                ]}
                rows={compare.data.by_scanner}
                rowKey={(r) => r.tool}
              />
            </div>
            <div className="card p-6">
              <div className="label-m mb-3 text-xs text-muted">Per CWE</div>
              <DataTable
                columns={[
                  { key: "cwe", header: "CWE", render: (r: { cwe: string }) => r.cwe },
                  ...compare.data.scans.map((s) => ({
                    key: `run-${s.run_id}`,
                    header: `#${s.run_id}`,
                    render: (r: { counts: Record<string, number> }) => String(r.counts[String(s.run_id)] ?? 0),
                  })),
                ]}
                rows={compare.data.by_cwe}
                rowKey={(r) => r.cwe}
              />
            </div>
          </div>
          <div className="mt-6 grid gap-6 lg:grid-cols-3">
            {(
              [
                ["New", compare.data.new],
                ["Fixed", compare.data.fixed],
                ["Changed", compare.data.changed],
              ] as const
            ).map(([label, entries]) => (
              <div key={label} className="card p-6">
                <div className="label-m mb-3 text-xs text-muted">
                  {label} ({entries.length})
                </div>
                {entries.length === 0 ? (
                  <p className="text-sm text-muted">None.</p>
                ) : (
                  <ul className="space-y-2 text-sm text-body">
                    {entries.map((entry) => (
                      <li key={entry.finding_id}>
                        <span className="font-mono text-xs text-ink">{entry.finding_id}</span>{" "}
                        {entry.title}{" "}
                        <span className="text-muted">
                          {entry.severity}/{entry.status}
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            ))}
          </div>
          <p className="mt-4 text-sm text-body">
            <a className="text-ink underline" href={compareHtmlUrl(selected)}>
              Export comparison as HTML
            </a>{" "}
            <span className="text-muted">(baseline #{compare.data.baseline})</span>
          </p>
        </div>
      )}
    </div>
  );
}

export function ReportsPage() {
  const scans = useQuery({ queryKey: ["scans"], queryFn: fetchScans });
  const ids = useMemo(() => (scans.data ?? []).map((s) => s.run_id), [scans.data]);
  const [runId, setRunId] = useState<number | null>(null);
  const active = runId ?? ids[0] ?? null;

  return (
    <div>
      <PageHeader title={en.reports.title} subtitle={en.reports.subtitle} />
      {scans.isLoading || active === null ? (
        <p className="text-body">{en.common.loading}</p>
      ) : (
        <div>
          <label className="label-m mb-2 block text-[11px] text-muted" htmlFor="report-scan">
            Scan
          </label>
          <select
            id="report-scan"
            className="mb-6 border border-hairline bg-canvas px-3 py-2 text-sm text-ink"
            value={active}
            onChange={(e) => setRunId(Number(e.target.value))}
          >
            {ids.map((id) => (
              <option key={id} value={id}>
                Scan #{id}
              </option>
            ))}
          </select>
          <ReportRows key={active} runId={active} />
          <ComparePanel scanIds={ids} />
        </div>
      )}
    </div>
  );
}
