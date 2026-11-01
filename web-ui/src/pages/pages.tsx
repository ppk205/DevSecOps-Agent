import { useQuery } from "@tanstack/react-query";
import { fetchScan, fetchScans } from "../api/client";
import type { ScanSummary } from "../api/types";
import { DataTable } from "../components/DataTable";
import { SeverityDonut } from "../components/charts/SeverityDonut";
import { EmptyState } from "../components/EmptyState";
import { SpecCell } from "../components/SpecCell";
import { StageNode } from "../components/StageNode";
import { StripeDivider } from "../components/StripeDivider";
import { en } from "../i18n/en";

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

export { HomePage, LivePage, PlaceholderPage, PageHeader };
