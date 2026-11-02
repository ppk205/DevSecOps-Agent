import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { fetchScans, fetchTools } from "../api/client";
import type { ScanSummary, Severity } from "../api/types";
import { Banner } from "../components/Banner";
import { Button } from "../components/Button";
import { DataTable } from "../components/DataTable";
import { SeverityBars } from "../components/charts/SeverityBars";
import { SeverityDonut } from "../components/charts/SeverityDonut";
import { EmptyState } from "../components/EmptyState";
import { SpecCell } from "../components/SpecCell";
import { StripeDivider } from "../components/StripeDivider";
import { useStrings } from "../i18n/lang";
import { tokens } from "../tokens";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

function shortRepo(repo: string): string {
  const tail = repo.split("/").slice(-1)[0];
  return tail || repo;
}

function ToolHealthStrip() {
  const en = useStrings();
  const toolsQuery = useQuery({ queryKey: ["tools"], queryFn: () => fetchTools(false) });
  if (toolsQuery.isLoading) return <p className="text-body">{en.common.loading}</p>;
  if (toolsQuery.isError || !toolsQuery.data) return null;
  return (
    <div className="grid grid-cols-1 gap-2 sm:grid-cols-2" role="list" aria-label={en.home.toolHealth}>
      {toolsQuery.data.tools.map((tool) => (
        <span
          key={tool.tool}
          role="listitem"
          title={tool.available ? (tool.version ?? tool.binary) : (tool.hint ?? tool.binary)}
          className="label-m flex items-center gap-2.5 rounded-md border border-hairline bg-elevated px-3 py-2.5 text-[11px] text-body"
        >
          <span
            aria-hidden
            className="inline-block h-2 w-2 shrink-0 rounded-full"
            style={{
              background: tool.available ? tokens.color.success : tokens.color.mRed,
              boxShadow: `0 0 6px ${tool.available ? tokens.color.success : tokens.color.mRed}`,
            }}
          />
          <span className="truncate">{tool.tool}</span>
          <span className="ml-auto shrink-0 text-muted">{tool.available ? (tool.version ?? "ready") : "missing"}</span>
        </span>
      ))}
    </div>
  );
}

export function HomePage() {
  const en = useStrings();
  const scansQuery = useQuery({ queryKey: ["scans"], queryFn: fetchScans });
  if (scansQuery.isLoading) return <p className="text-body">{en.common.loading}</p>;
  if (scansQuery.isError) {
    return (
      <Banner tone="error" title={en.home.loadFailed}>
        {String(scansQuery.error)}
      </Banner>
    );
  }
  const scans = scansQuery.data ?? [];
  const latest: ScanSummary | undefined = scans[0];
  const severity = latest?.severity ?? {};
  const bars = SEVERITY_ORDER.filter((sev) => (severity[sev] ?? 0) > 0).map((sev) => ({
    label: sev,
    value: severity[sev] ?? 0,
    severity: sev,
  }));
  const cweBars = (latest?.top_cwe ?? []).map((row) => ({
    label: row.cwe,
    value: row.count,
    severity: "low" as Severity,
  }));

  return (
    <div>
      {/* Hero band */}
      <section className="mb-10 border border-hairline bg-soft p-8 md:p-12">
        <p className="label-m text-xs text-muted">{en.home.title}</p>
        <h1 className="display-4 mt-2">{en.home.heroTitle}</h1>
        <p className="mt-3 max-w-2xl text-body">{en.home.heroSubtitle}</p>
        <div className="mt-6 flex max-w-xs flex-col gap-3 sm:flex-row">
          <Link to="/scans/new" className="no-underline">
            <Button variant="primary">{en.home.heroPrimary}</Button>
          </Link>
          <Link to="/findings" className="no-underline">
            <Button variant="secondary">{en.home.heroSecondary}</Button>
          </Link>
        </div>
        <div className="mt-8 max-w-xs">
          <StripeDivider />
        </div>
      </section>

      {/* KPI spec-cells */}
      {latest ? (
        <section
          aria-label={en.home.keyFigures}
          className="mb-10 grid grid-cols-2 gap-4 md:grid-cols-6"
        >
          <SpecCell label={en.home.kpiRun} value={`#${latest.run_id}`} />
          <SpecCell label={en.home.kpiRepo} value={shortRepo(latest.repo)} />
          <SpecCell label={en.home.kpiGate} value={latest.gate.toUpperCase()} />
          <SpecCell label={en.home.kpiStatus} value={latest.status.toUpperCase()} />
          <SpecCell label={en.home.kpiFindings} value={String(latest.counts.total)} />
          <SpecCell label={en.home.kpiConfirmed} value={String(latest.counts.confirmed)} />
        </section>
      ) : (
        <div className="mb-10">
          <EmptyState />
        </div>
      )}

      {/* Latest scan + severity charts */}
      <section className="mb-10 grid gap-6 lg:grid-cols-2">
        <div className="card p-6">
          <div className="label-m mb-4 text-xs text-muted">{en.home.latestScan}</div>
          {latest ? (
            <div className="flex flex-col gap-6 md:flex-row md:items-center">
              <SeverityDonut counts={latest.counts} />
              <div className="space-y-2 text-sm">
                <div className="text-ink">
                  #{latest.run_id} · {shortRepo(latest.repo)}
                </div>
                <div className="font-mono text-xs text-muted">{latest.commit.slice(0, 12)}</div>
                <div className="text-body">
                  Gate {latest.gate.toUpperCase()} · {latest.status.toUpperCase()}
                </div>
                <Link to="/live" className="label-m text-[11px] text-ink no-underline">
                  {en.common.viewAll} →
                </Link>
              </div>
            </div>
          ) : (
            <EmptyState />
          )}
        </div>
        <div className="card p-6">
          <div className="label-m mb-4 text-xs text-muted">{en.home.severityMix}</div>
          {bars.length > 0 ? (
            <SeverityBars data={bars} />
          ) : (
            <EmptyState
              title={en.common.emptyTitle}
              body={en.home.emptySeverity}
            />
          )}
        </div>
      </section>

      {/* Top CWE + tool health */}
      <section className="mb-10 grid gap-6 lg:grid-cols-2">
        <div className="card p-6">
          <div className="label-m mb-4 text-xs text-muted">{en.home.topCwe}</div>
          {cweBars.length > 0 ? (
            <SeverityBars data={cweBars} />
          ) : (
            <EmptyState title={en.common.emptyTitle} body={en.home.emptyCwe} />
          )}
        </div>
        <div className="card p-6">
          <div className="label-m mb-4 text-xs text-muted">{en.home.toolHealth}</div>
          <ToolHealthStrip />
          <div className="mt-4">
            <Link to="/keys" className="label-m inline-block rounded-md border border-hairline px-3 py-2 text-[11px] text-body no-underline transition-colors hover:border-ink hover:text-ink">
              {en.home.manageScanners} →
            </Link>
          </div>
        </div>
      </section>

      {/* HOW IT WORKS — 8-stage band */}
      <section className="mb-10">
        <h2 className="label-m mb-4 text-xs text-muted">{en.home.howItWorks}</h2>
        <ol className="grid grid-cols-2 gap-px bg-hairline md:grid-cols-4">
          {en.home.steps.map((step, i) => (
            <li key={step} className="bg-soft p-4">
              <div className="font-mono text-xs text-muted">{String(i + 1).padStart(2, "0")}</div>
              <div className="mt-1 text-sm text-ink">{step}</div>
            </li>
          ))}
        </ol>
      </section>

      {/* Scan history */}
      <section className="mb-10">
        <h2 className="label-m mb-4 text-xs text-muted">{en.home.history}</h2>
        <DataTable
          columns={[
            {
              key: "run",
              header: en.home.cols.run,
              render: (s: ScanSummary) => <span className="text-ink">#{s.run_id}</span>,
            },
            {
              key: "repo",
              header: en.home.cols.repository,
              render: (s: ScanSummary) => shortRepo(s.repo),
            },
            {
              key: "gate",
              header: en.home.cols.gate,
              render: (s: ScanSummary) => s.gate.toUpperCase(),
            },
            {
              key: "status",
              header: en.home.cols.status,
              render: (s: ScanSummary) => s.status,
            },
            {
              key: "findings",
              header: en.home.cols.findings,
              render: (s: ScanSummary) => String(s.counts.total),
            },
          ]}
          rows={scans}
          rowKey={(s) => String(s.run_id)}
        />
      </section>

      {/* Pre-footer CTA band */}
      <section className="card flex flex-col items-start gap-4 p-8 md:flex-row md:items-center">
        <div className="flex-1">
          <h2 className="text-xl text-ink">{en.home.ctaTitle}</h2>
          <p className="mt-1 text-sm text-body">{en.home.ctaBody}</p>
        </div>
        <Link to="/scans/new" className="no-underline">
          <Button variant="primary">{en.home.ctaButton}</Button>
        </Link>
      </section>
    </div>
  );
}
