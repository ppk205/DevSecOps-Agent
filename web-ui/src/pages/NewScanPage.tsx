import { useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  createScan,
  fetchKeys,
  fetchScans,
  fetchTools,
  fetchUsage,
} from "../api/client";
import { Banner } from "../components/Banner";
import { Button } from "../components/Button";
import { useStrings } from "../i18n/lang";

const FAIL_ON = ["critical", "high", "medium", "low", "info", "none"] as const;

function Toggle(props: { label: string; detail: string; on: boolean; onChange: (next: boolean) => void }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={props.on}
      aria-label={props.label}
      onClick={() => props.onChange(!props.on)}
      className={`mt-3 w-full border p-3 text-left ${props.on ? "border-ink" : "border-hairline"}`}
    >
      <div className="label-m text-sm text-ink">{props.label}</div>
      <div className="mt-1 text-xs text-muted">{props.detail}</div>
    </button>
  );
}

function shellQuote(value: string): string {
  return /[^A-Za-z0-9_@%+=:,./-]/.test(value) ? `'${value.replace(/'/g, `'\\''`)}'` : value;
}

export function NewScanPage() {
  const en = useStrings();
  const [repo, setRepo] = useState("https://github.com/example/jva-bookstore");
  const [profile, setProfile] = useState<"fast" | "full">("fast");
  const [toolOverrides, setToolOverrides] = useState<string[] | null>(null);
  // Off by default: no source excerpt goes to a provider until the user allows it.
  const [allowCloud, setAllowCloud] = useState(false);
  const [aiReview, setAiReview] = useState(true);
  const [aiReport, setAiReport] = useState(true);
  const [hunt, setHunt] = useState(true);
  const [laya, setLaya] = useState(true);
  const [failOn, setFailOn] = useState("high");
  const [providerProfile, setProviderProfile] = useState("");
  const [providerModel, setProviderModel] = useState("");
  const [maxAi, setMaxAi] = useState(10);
  const [commit, setCommit] = useState("");
  const [timeout, setTimeout] = useState(600);
  const [maxFiles, setMaxFiles] = useState(100000);

  const scansQuery = useQuery({ queryKey: ["scans"], queryFn: fetchScans });
  const toolsQuery = useQuery({ queryKey: ["tools"], queryFn: () => fetchTools(false) });
  const usageQuery = useQuery({ queryKey: ["usage"], queryFn: fetchUsage });
  const keysQuery = useQuery({ queryKey: ["keys"], queryFn: fetchKeys });
  const useHunt = allowCloud && hunt;
  const useReview = allowCloud && aiReview;
  const useReport = allowCloud && aiReport;
  const usesModel = useHunt || useReview || useReport;
  const profiles = toolsQuery.data?.profiles;
  const selectedTools = toolOverrides ?? profiles?.[profile] ?? [];
  const cliNeedsConfig = toolOverrides !== null || maxFiles !== 100000;
  const startMutation = useMutation({
    mutationFn: () =>
      createScan({
        repository_url: repo.trim(),
        commit_sha: commit.trim() || null,
        profile,
        tools: toolOverrides,
        ai_review: useReview,
        ai_report: useReport,
        laya,
        fail_on: failOn,
        allow_cloud_model: allowCloud,
        provider_profile: (usesModel && providerProfile) || null,
        provider_model: (usesModel && providerModel) || null,
        max_ai_findings: maxAi,
        timeout,
        max_files: maxFiles,
        mode: useHunt ? "hunt" : "deterministic",
      }),
  });

  const recentTargets = useMemo(() => {
    const seen = new Set<string>();
    for (const s of scansQuery.data ?? []) {
      if (s.repo && !seen.has(s.repo)) seen.add(s.repo);
      if (seen.size >= 5) break;
    }
    return [...seen];
  }, [scansQuery.data]);

  const estimate = useMemo(() => (useReview ? maxAi * 0.012 : 0), [useReview, maxAi]);
  const remaining = usageQuery.data?.available;

  const cli = useMemo(() => {
    const parts = ["devsecops-agent scan-run", `--checkout ${shellQuote(repo.trim() || "<repo>")}`, `--profile ${profile}`];
    if (commit.trim()) parts.push(`--commit ${shellQuote(commit.trim())}`);
    if (timeout !== 600) parts.push(`--timeout ${timeout}`);
    if (failOn !== "high") parts.push(`--fail-on ${failOn}`);
    if (!laya) parts.push("--no-laya");
    parts.push(useHunt ? "--mode hunt" : "--mode deterministic");
    if (useReview) parts.push("--ai-review", `--max-ai-findings ${maxAi}`);
    if (useReport) parts.push("--ai-report");
    if (usesModel) {
      if (providerProfile) parts.push(`--provider ${shellQuote(providerProfile)}`);
      if (providerModel) parts.push(`--model ${shellQuote(providerModel)}`);
    }
    return parts.join(" ");
  }, [repo, profile, commit, timeout, failOn, laya, useHunt, useReview, useReport, usesModel, providerProfile, providerModel, maxAi]);

  return (
    <div>
      <div className="mb-10">
        <h1 className="display-4">{en.newScan.title}</h1>
        <p className="mt-2 text-body">{en.newScan.subtitle}</p>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,1fr)_360px]">
        <div className="space-y-6">
          {/* Target */}
          <section className="card p-6">
            <h2 className="label-m mb-4 text-xs text-muted">{en.newScan.target}</h2>
            <input
              aria-label={en.newScan.target}
              className="w-full border border-hairline bg-canvas px-3 py-2 text-sm text-ink"
              value={repo}
              onChange={(e) => setRepo(e.target.value)}
              placeholder={en.newScan.targetPlaceholder}
              list="recent-targets"
            />
            <datalist id="recent-targets">
              {recentTargets.map((t) => (
                <option key={t} value={t} />
              ))}
            </datalist>
            {recentTargets.length > 0 && (
              <div className="mt-3 flex flex-wrap gap-2">
                <span className="label-m text-[11px] text-muted">{en.newScan.recentTargets}:</span>
                {recentTargets.map((t) => (
                  <button
                    key={t}
                    type="button"
                    onClick={() => setRepo(t)}
                    className="label-m border border-hairline px-2 py-1 text-[11px] text-body hover:text-ink"
                  >
                    {t.split("/").slice(-1)[0]}
                  </button>
                ))}
              </div>
            )}
          </section>

          {/* Profile */}
          <section className="card p-6">
            <h2 className="label-m mb-4 text-xs text-muted">{en.newScan.profile}</h2>
            <div className="grid gap-3 sm:grid-cols-2" role="radiogroup" aria-label={en.newScan.profile}>
              <button
                type="button"
                role="radio"
                aria-checked={profile === "fast"}
                onClick={() => {
                  setProfile("fast");
                  setToolOverrides(null);
                }}
                className={`border p-4 text-left ${profile === "fast" ? "border-ink" : "border-hairline"}`}
              >
                <div className="label-m text-sm text-ink">{en.newScan.fast}</div>
                <div className="mt-1 text-xs text-muted">{profiles?.fast.join(" · ")}</div>
              </button>
              <button
                type="button"
                role="radio"
                aria-checked={profile === "full"}
                onClick={() => {
                  setProfile("full");
                  setToolOverrides(null);
                }}
                className={`border p-4 text-left ${profile === "full" ? "border-ink" : "border-hairline"}`}
              >
                <div className="label-m text-sm text-ink">{en.newScan.deep}</div>
                <div className="mt-1 text-xs text-muted">{profiles?.full.join(" · ")}</div>
              </button>
            </div>
          </section>

          {/* Scanners */}
          <section className="card p-6">
            <h2 className="label-m mb-4 text-xs text-muted">{en.newScan.scanners}</h2>
            <div className="grid gap-3 sm:grid-cols-2">
              {toolsQuery.data?.tools.map((status) => {
                const name = status.tool;
                const on = selectedTools.includes(name);
                return (
                  <button
                    key={name}
                    type="button"
                    role="switch"
                    aria-checked={on}
                    aria-label={name}
                    onClick={() => setToolOverrides(
                      on ? selectedTools.filter((tool) => tool !== name) : [...selectedTools, name],
                    )}
                    className={`border p-4 text-left ${on ? "border-ink" : "border-hairline"}`}
                  >
                    <div className="flex items-center gap-2">
                      <span
                        aria-hidden
                        className="inline-block h-2 w-2"
                        style={{ background: status?.available ? "#0fa336" : "#e22718" }}
                      />
                      <span className="label-m text-sm text-ink">{name}</span>
                    </div>
                    <div className="mt-1 text-xs text-muted">
                      {toolsQuery.isLoading
                        ? en.common.loading
                        : status?.available
                          ? (status.version ?? "ready")
                          : (status?.hint ?? "missing")}
                    </div>
                  </button>
                );
              })}
            </div>
            <Toggle label={en.newScan.laya} detail={en.newScan.layaDetail} on={laya} onChange={setLaya} />
          </section>

          {/* Cloud model */}
          <section className="card p-6">
            <h2 className="label-m mb-1 text-xs text-muted">{en.newScan.cloudModel}</h2>
            <Toggle
              label={en.newScan.allowCloud}
              detail={allowCloud ? en.newScan.allowCloudOn : en.newScan.allowCloudOff}
              on={allowCloud}
              onChange={setAllowCloud}
            />
            {allowCloud && (
              <>
                <div className="grid gap-3 sm:grid-cols-3">
                  <Toggle label={en.newScan.hunt} detail={en.newScan.huntDetail} on={hunt} onChange={setHunt} />
                  <Toggle label={en.newScan.aiReview} detail={en.newScan.aiReviewDetail} on={aiReview} onChange={setAiReview} />
                  <Toggle label={en.newScan.aiReport} detail={en.newScan.aiReportDetail} on={aiReport} onChange={setAiReport} />
                </div>
                <div className="mt-4 grid gap-3 sm:grid-cols-2">
                  <label className="block">
                    <span className="label-m text-[11px] text-muted">{en.newScan.providerProfile}</span>
                    <input
                      className="mt-1 w-full border border-hairline bg-canvas px-3 py-2 text-sm text-ink"
                      value={providerProfile}
                      onChange={(e) => setProviderProfile(e.target.value)}
                      placeholder={en.newScan.providerAuto}
                      list="provider-profiles"
                    />
                    <datalist id="provider-profiles">
                      {(keysQuery.data ?? []).map((k) => (
                        <option key={k.profile} value={k.profile} />
                      ))}
                    </datalist>
                  </label>
                  <label className="block">
                    <span className="label-m text-[11px] text-muted">{en.newScan.providerModel}</span>
                    <input
                      className="mt-1 w-full border border-hairline bg-canvas px-3 py-2 text-sm text-ink"
                      value={providerModel}
                      onChange={(e) => setProviderModel(e.target.value)}
                      placeholder={en.newScan.modelDefault}
                    />
                  </label>
                  {aiReview && (
                    <label className="block">
                      <span className="label-m text-[11px] text-muted">{en.newScan.maxAiFindings}</span>
                      <input
                        type="number"
                        min={1}
                        max={500}
                        className="mt-1 w-full border border-hairline bg-canvas px-3 py-2 text-sm text-ink"
                        value={maxAi}
                        onChange={(e) => setMaxAi(Number(e.target.value) || 10)}
                      />
                    </label>
                  )}
                  {aiReview && (
                    <p className="self-end text-xs text-muted">
                      {en.newScan.aiEstimate}: ${estimate.toFixed(2)}
                      {remaining !== undefined && ` · $${remaining.toFixed(2)} ${en.newScan.aiBudget}`}
                    </p>
                  )}
                </div>
              </>
            )}
          </section>

          {/* Advanced */}
          <section className="card p-6">
            <details>
              <summary className="label-m cursor-pointer text-xs text-muted">
                {en.newScan.advanced}
              </summary>
              <div className="mt-4 grid gap-3 sm:grid-cols-2">
                <label className="block">
                  <span className="label-m text-[11px] text-muted">{en.newScan.commit}</span>
                  <input
                    className="mt-1 w-full border border-hairline bg-canvas px-3 py-2 font-mono text-sm text-ink"
                    value={commit}
                    onChange={(e) => setCommit(e.target.value)}
                    placeholder={en.newScan.commitPlaceholder}
                  />
                </label>
                <label className="block">
                  <span className="label-m text-[11px] text-muted">{en.newScan.timeout}</span>
                  <input
                    type="number"
                    min={1}
                    className="mt-1 w-full border border-hairline bg-canvas px-3 py-2 text-sm text-ink"
                    value={timeout}
                    onChange={(e) => setTimeout(Number(e.target.value) || 600)}
                  />
                </label>
                <label className="block">
                  <span className="label-m text-[11px] text-muted">{en.newScan.maxFiles}</span>
                  <input
                    type="number"
                    min={1}
                    className="mt-1 w-full border border-hairline bg-canvas px-3 py-2 text-sm text-ink"
                    value={maxFiles}
                    onChange={(e) => setMaxFiles(Number(e.target.value) || 100000)}
                  />
                </label>
                <label className="block">
                  <span className="label-m text-[11px] text-muted">{en.newScan.failOn}</span>
                  <select
                    className="mt-1 w-full border border-hairline bg-canvas px-3 py-2 text-sm text-ink"
                    value={failOn}
                    onChange={(e) => setFailOn(e.target.value)}
                  >
                    {FAIL_ON.map((level) => (
                      <option key={level} value={level}>
                        {level}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
            </details>
          </section>
        </div>

        {/* Sticky review panel */}
        <aside className="min-w-0 lg:sticky lg:top-6 lg:self-start">
          <div className="card space-y-4 p-6">
            <h2 className="label-m text-xs text-muted">{en.newScan.review}</h2>
            <dl className="space-y-2 text-sm">
              <div className="flex justify-between gap-4">
                <dt className="text-muted">{en.newScan.reviewTarget}</dt>
                <dd className="break-all text-right font-mono text-xs text-ink">{repo || "—"}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-muted">{en.newScan.reviewProfile}</dt>
                <dd className="text-ink">{profile.toUpperCase()}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-muted">{en.newScan.reviewScanners}</dt>
                <dd className="text-right text-ink">
                  {selectedTools.join(", ") || "—"}
                </dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-muted">{en.newScan.reviewAi}</dt>
                <dd className="text-ink">
                  {usesModel
                    ? [useHunt && en.newScan.hunt, useReview && en.newScan.aiReview, useReport && en.newScan.aiReport]
                        .filter(Boolean)
                        .join(", ")
                    : en.newScan.aiOffShort}
                </dd>
              </div>
            </dl>
            {useHunt && <p className="text-xs text-muted">{en.newScan.huntScannerScope}</p>}
            {cliNeedsConfig ? (
              <p className="text-xs text-muted">{en.newScan.cliConfigRequired}</p>
            ) : <div>
              <div className="label-m mb-2 text-[11px] text-muted">{en.newScan.cliPreview}</div>
              <pre className="overflow-x-auto border border-hairline bg-canvas p-3 font-mono text-xs text-body">
                {cli}
              </pre>
            </div>}
            {startMutation.isError && (
              <Banner tone="error" title={en.newScan.startFailed}>
                {String(startMutation.error)}
              </Banner>
            )}
            {startMutation.isSuccess && (
              <Banner tone="success" title={`${en.newScan.launched} #${startMutation.data.run_id}`}>
                {en.newScan.launchedBody}{" "}
                <Link to="/" className="text-ink">
                  {en.nav.home}
                </Link>{" "}
                · <Link to="/live" className="text-ink">{en.nav.live}</Link>
              </Banner>
            )}
            <Button
              variant="primary"
              className="w-full"
              disabled={!repo.trim() || startMutation.isPending}
              onClick={() => startMutation.mutate()}
            >
              {startMutation.isPending ? en.common.loading : en.newScan.start}
            </Button>
          </div>
        </aside>
      </div>
    </div>
  );
}
