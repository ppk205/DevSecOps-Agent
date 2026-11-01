import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchScan, fetchScans } from "../api/client";
import type { ScanSummary } from "../api/types";
import { DataTable } from "../components/DataTable";
import { SeverityDonut } from "../components/charts/SeverityDonut";
import { EmptyState } from "../components/EmptyState";
import { SeverityBadge } from "../components/SeverityBadge";
import { SpecCell } from "../components/SpecCell";
import { StageNode } from "../components/StageNode";
import { StripeDivider } from "../components/StripeDivider";
import { VerificationBadge } from "../components/VerificationBadge";
import { en } from "../i18n/en";
import { MOCK_FINDINGS } from "../mock/mockRun";
import type { FindingSummary } from "../api/types";

function PageHeader({ title, subtitle }: { title: string; subtitle: string }) {
  return (
    <div className="mb-10">
      <h1 className="display-4">{title}</h1>
      <p className="mt-2 text-body">{subtitle}</p>
      <div className="mt-6 max-w-xs">
        <StripeDivider />
      </div>
    </div>
  );
}

function HomePage() {
  const { data, isLoading } = useQuery({ queryKey: ["scans"], queryFn: fetchScans });
  const latest: ScanSummary | undefined = data?.[0];
  if (isLoading) return <p className="text-body">{en.common.loading}</p>;
  return (
    <div>
      <PageHeader title={en.home.title} subtitle={en.home.subtitle} />
      {latest && (
        <div className="mb-10 grid grid-cols-2 gap-4 md:grid-cols-4">
          <SpecCell label="Latest run" value={`#${latest.run_id}`} />
          <SpecCell label="Repository" value={latest.repo} />
          <SpecCell label="Gate" value={latest.gate.toUpperCase()} />
          <SpecCell label="Status" value={latest.status.toUpperCase()} />
        </div>
      )}
      <div className="grid gap-6 lg:grid-cols-2">
        <div className="card p-6">
          <div className="label-m mb-4 text-xs text-muted">Gate posture</div>
          {latest ? (
            <SeverityDonut counts={latest.counts} />
          ) : (
            <EmptyState />
          )}
        </div>
        <div className="card p-6">
          <div className="label-m mb-4 text-xs text-muted">Recent scans</div>
          <DataTable
            columns={[
              { key: "run", header: "Run", render: (s: ScanSummary) => <span className="text-ink">#{s.run_id}</span> },
              { key: "repo", header: "Repository", render: (s: ScanSummary) => s.repo.split("/").slice(-1)[0] },
              { key: "gate", header: "Gate", render: (s: ScanSummary) => s.gate.toUpperCase() },
              { key: "status", header: "Status", render: (s: ScanSummary) => s.status },
            ]}
            rows={data ?? []}
            rowKey={(s) => String(s.run_id)}
          />
        </div>
      </div>
    </div>
  );
}

function PlaceholderPage({ title, subtitle }: { title: string; subtitle: string }) {
  return (
    <div>
      <PageHeader title={title} subtitle={subtitle} />
      <EmptyState
        title="Phase 1 scaffold"
        body="This surface lands in its phase milestone. The shell, tokens, and mock layer are live — content follows."
      />
    </div>
  );
}

function FindingsPage() {
  // Phase 1: mock table preview over the scripted ~60 findings.
  const [filter, setFilter] = useState<string>("all");
  const rows: FindingSummary[] = MOCK_FINDINGS.filter(
    (f) => filter === "all" || f.severity === filter,
  );
  return (
    <div>
      <PageHeader title={en.findings.title} subtitle={en.findings.subtitle} />
      <div className="mb-4 flex gap-2">
        {["all", "critical", "high", "medium", "low", "info"].map((s) => (
          <button
            key={s}
            onClick={() => setFilter(s)}
            className={`label-m border px-3 py-1.5 text-[11px] transition-colors duration-150 ${
              filter === s ? "border-ink text-ink" : "border-hairline text-muted hover:text-body"
            }`}
          >
            {s}
          </button>
        ))}
      </div>
      <DataTable
        columns={[
          { key: "id", header: "ID", render: (f: FindingSummary) => <span className="font-mono text-xs">{f.id}</span> },
          { key: "title", header: "Title", render: (f: FindingSummary) => <span className="text-ink">{f.title}</span> },
          { key: "sev", header: "Severity", render: (f: FindingSummary) => <SeverityBadge severity={f.severity} /> },
          { key: "ver", header: "State", render: (f: FindingSummary) => <VerificationBadge state={f.status} /> },
          { key: "tool", header: "Tool", render: (f: FindingSummary) => f.tool },
          { key: "loc", header: "Location", render: (f: FindingSummary) => <span className="font-mono text-xs">{f.file}:{f.line}</span> },
        ]}
        rows={rows}
        rowKey={(f) => f.id}
      />
    </div>
  );
}

function LivePage() {
  const { data, isLoading } = useQuery({ queryKey: ["scan", 7], queryFn: () => fetchScan(7) });
  if (isLoading || !data) return <p className="text-body">{en.common.loading}</p>;
  const done = data.stages.filter((s) => s.status === "completed").length;
  return (
    <div>
      <PageHeader title={en.live.title} subtitle={en.live.subtitle} />
      <div className="mb-8">
        <StripeDivider progress={data.stages.length ? done / data.stages.length : 0} />
        <p className="mt-2 text-xs uppercase tracking-widest text-muted">
          {done}/{data.stages.length} stages complete
        </p>
      </div>
      <div className="card flex flex-col gap-6 p-6 md:flex-row md:items-center">
        {data.stages.map((s, i) => (
          <StageNodeShim key={s.name} name={s.name} status={s.status} last={i === data.stages.length - 1} />
        ))}
      </div>
    </div>
  );
}

function StageNodeShim(props: { name: string; status: string; last: boolean }) {
  const ok = ["pending", "running", "completed", "failed", "skipped"] as const;
  const status = (ok as readonly string[]).includes(props.status) ? (props.status as (typeof ok)[number]) : "pending";
  return <StageNode name={props.name} status={status} last={props.last} />;
}

export { HomePage, FindingsPage, LivePage, PlaceholderPage, PageHeader };
