import { useState } from "react";
import { Banner } from "../components/Banner";
import { Button, IconButton } from "../components/Button";
import { DataTable } from "../components/DataTable";
import { Drawer } from "../components/Drawer";
import { EmptyState } from "../components/EmptyState";
import { SeverityBadge } from "../components/SeverityBadge";
import { SpecCell } from "../components/SpecCell";
import { StageNode } from "../components/StageNode";
import { StripeDivider } from "../components/StripeDivider";
import { Tabs } from "../components/Tabs";
import { TextLink } from "../components/TextLink";
import { VerificationBadge } from "../components/VerificationBadge";
import { SeverityBars } from "../components/charts/SeverityBars";
import { SeverityDonut } from "../components/charts/SeverityDonut";
import { PageHeader } from "./pages";
import { useStrings } from "../i18n/lang";
import { tokens, type Severity, type VerificationState } from "../tokens";
import { MOCK_FINDINGS } from "../mock/mockRun";
import type { FindingSummary } from "../api/types";

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-16">
      <h2 className="label-m mb-6 text-sm text-ink">{title}</h2>
      <div className="card p-6">{children}</div>
    </section>
  );
}

/** Hidden route: renders every token and component. Not in nav. */
export function StyleguidePage() {
  const en = useStrings();
  const [tab, setTab] = useState("tokens");
  const [drawer, setDrawer] = useState(false);
  const severities: Severity[] = ["critical", "high", "medium", "low", "info"];
  const states: VerificationState[] = ["confirmed", "unresolved", "rejected", "unprocessed"];
  const counts = { total: 60, confirmed: 18, rejected: 9, unresolved: 21, unprocessed: 12 };

  return (
    <div>
      <PageHeader title={en.styleguide.title} subtitle={en.styleguide.subtitle} />
      <Tabs
        tabs={[
          { id: "tokens", label: "Tokens" },
          { id: "components", label: "Components" },
          { id: "charts", label: "Charts" },
        ]}
        active={tab}
        onChange={setTab}
      />
      <div className="mt-8">
        {tab === "tokens" && (
          <Section title="Color tokens">
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              {Object.entries(tokens.color).map(([name, value]) => (
                <div key={name} className="border border-hairline">
                  <div className="h-12" style={{ background: value as string }} />
                  <div className="p-2 font-mono text-xs text-body">
                    {name}
                    <br />
                    {value as string}
                  </div>
                </div>
              ))}
            </div>
            <div className="mt-6">
              <div className="label-m mb-2 text-[11px] text-muted">M stripe (divider/rail only)</div>
              <StripeDivider />
            </div>
            <div className="mt-6 space-y-4">
              <div className="display-2">Display / 56</div>
              <p>Body 300, 16px/1.5 — the quick brown fox and the lazy scanner.</p>
              <div className="label-m text-muted">Label / 14 · 700 · 1.5 tracking</div>
            </div>
          </Section>
        )}
        {tab === "components" && (
          <>
            <Section title="Buttons / Links">
              <div className="flex flex-wrap items-center gap-3">
                <Button>Primary</Button>
                <Button variant="secondary">Secondary</Button>
                <Button variant="danger">Danger</Button>
                <Button variant="ghost">Ghost</Button>
                <Button disabled>Disabled</Button>
                <IconButton label="Refresh">↻</IconButton>
                <TextLink to="/findings">Findings →</TextLink>
              </div>
            </Section>
            <Section title="Badges">
              <div className="flex flex-wrap gap-2">
                {severities.map((s) => (
                  <SeverityBadge key={s} severity={s} />
                ))}
              </div>
              <div className="mt-3 flex flex-wrap gap-2">
                {states.map((s) => (
                  <VerificationBadge key={s} state={s} />
                ))}
              </div>
            </Section>
            <Section title="Stage rail">
              <div className="flex flex-col gap-4 md:flex-row">
                <StageNode name="scan" status="completed" />
                <StageNode name="hunt" status="running" />
                <StageNode name="validate" status="pending" />
                <StageNode name="report" status="pending" last />
              </div>
              <div className="mt-6">
                <StripeDivider progress={0.4} />
              </div>
            </Section>
            <Section title="Spec cells">
              <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
                <SpecCell label="Run" value="#7" />
                <SpecCell label="Commit" value="9f3ac41…" mono />
                <SpecCell label="Gate" value="FAIL" />
                <SpecCell label="Toolchain" value="semgrep + odc" />
              </div>
            </Section>
            <Section title="Table (first 5 mock findings)">
              <DataTable
                columns={[
                  { key: "id", header: "ID", render: (f: FindingSummary) => f.id },
                  { key: "title", header: "Title", render: (f: FindingSummary) => f.title },
                  { key: "sev", header: "Severity", render: (f: FindingSummary) => <SeverityBadge severity={f.severity} /> },
                ]}
                rows={MOCK_FINDINGS.slice(0, 5)}
                rowKey={(f) => f.id}
              />
            </Section>
            <Section title="Banners / Empty / Drawer">
              <div className="space-y-3">
                <Banner tone="info" title="Heads up">Skeleton endpoints return fixed shapes.</Banner>
                <Banner tone="warn" title="Budget">Hunt spend at 62% of the USD 50 cap.</Banner>
                <Banner tone="error" title="Gate failed">4 critical findings confirmed.</Banner>
                <Banner tone="success" title="Report ready">final-report.md generated.</Banner>
              </div>
              <div className="mt-6">
                <EmptyState
                  actionLabel="Open drawer"
                  onAction={() => setDrawer(true)}
                />
              </div>
              <Drawer open={drawer} title="Evidence drawer" onClose={() => setDrawer(false)}>
                <p className="text-sm text-body">Drawer content: evidence, hunks, verdict trail.</p>
              </Drawer>
            </Section>
          </>
        )}
        {tab === "charts" && (
          <Section title="Hand-drawn SVG (no chart lib)">
            <div className="grid gap-10 lg:grid-cols-2">
              <SeverityDonut counts={counts} />
              <SeverityBars
                data={[
                  { label: "critical", value: 4, severity: "critical" },
                  { label: "high", value: 14, severity: "high" },
                  { label: "medium", value: 22, severity: "medium" },
                  { label: "low", value: 14, severity: "low" },
                  { label: "info", value: 6, severity: "info" },
                ]}
              />
            </div>
          </Section>
        )}
      </div>
    </div>
  );
}
