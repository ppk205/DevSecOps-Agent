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
import { en } from "../i18n/en";

const SCANNERS = ["semgrep", "gitleaks", "spotbugs", "owasp-dependency-check"] as const;

function shellQuote(value: string): string {
  return /[^A-Za-z0-9_@%+=:,./-]/.test(value) ? `'${value.replace(/'/g, `'\\''`)}'` : value;
}

export function NewScanPage() {
  const [repo, setRepo] = useState("https://github.com/example/jva-bookstore");
  const [profile, setProfile] = useState<"fast" | "full">("fast");
  const [tools, setTools] = useState<Record<string, boolean>>({
    semgrep: true,
    gitleaks: true,
    spotbugs: false,
    "owasp-dependency-check": false,
  });
  const [aiReview, setAiReview] = useState(false);
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
  const startMutation = useMutation({
    mutationFn: () =>
      createScan({
        repository_url: repo.trim(),
        profile,
        tools: SCANNERS.filter((t) => tools[t]),
        ai_review: aiReview,
        provider_profile: providerProfile || null,
        provider_model: providerModel || null,
        max_ai_findings: maxAi,
        timeout,
        max_files: maxFiles,
      }),
  });

  const toolStatus = useMemo(() => {
    const map = new Map<string, { available: boolean; version: string | null; hint: string | null }>();
    for (const t of toolsQuery.data?.tools ?? []) {
      map.set(t.tool, { available: t.available, version: t.version, hint: t.hint });
    }
    return map;
  }, [toolsQuery.data]);

  const recentTargets = useMemo(() => {
    const seen = new Set<string>();
    for (const s of scansQuery.data ?? []) {
      if (s.repo && !seen.has(s.repo)) seen.add(s.repo);
      if (seen.size >= 5) break;
    }
    return [...seen];
  }, [scansQuery.data]);

  const estimate = useMemo(() => (aiReview ? maxAi * 0.012 : 0), [aiReview, maxAi]);
  const remaining = usageQuery.data?.available;

  const cli = useMemo(() => {
    const parts = ["devsecops-agent scan", `--checkout ${shellQuote(repo.trim() || "<repo>")}`, `--profile ${profile}`];
    const enabled = SCANNERS.filter((t) => tools[t]);
    if (enabled.length > 0) parts.push(`--tools ${enabled.join(",")}`);
    if (commit.trim()) parts.push(`--commit ${shellQuote(commit.trim())}`);
    if (timeout !== 600) parts.push(`--timeout ${timeout}`);
    if (maxFiles !== 100000) parts.push(`--max-files ${maxFiles}`);
    if (aiReview) {
      parts.push("--ai-review");
      if (providerProfile) parts.push(`--provider ${shellQuote(providerProfile)}`);
      if (providerModel) parts.push(`--model ${shellQuote(providerModel)}`);
      parts.push(`--max-ai-findings ${maxAi}`);
    }
    return parts.join(" ");
  }, [repo, profile, tools, commit, timeout, maxFiles, aiReview, providerProfile, providerModel, maxAi]);

  return (
    <div>
      <div className="mb-10">
        <h1 className="display-4">{en.newScan.title}</h1>
        <p className="mt-2 text-body">{en.newScan.subtitle}</p>
      </div>

      <div className="grid gap-6 lg:grid-cols-[1fr_360px]">
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
                onClick={() => setProfile("fast")}
                className={`border p-4 text-left ${profile === "fast" ? "border-ink" : "border-hairline"}`}
              >
                <div className="label-m text-sm text-ink">{en.newScan.fast}</div>
                <div className="mt-1 text-xs text-muted">{en.newScan.fastDetail}</div>
              </button>
              <button
                type="button"
                role="radio"
                aria-checked={false}
                aria-disabled="true"
                disabled
                title={en.newScan.deepDetail}
                className="cursor-not-allowed border border-hairline p-4 text-left opacity-40"
              >
                <div className="label-m text-sm text-ink">{en.newScan.deep}</div>
                <div className="mt-1 text-xs text-muted">{en.newScan.deepDetail}</div>
              </button>
            </div>
          </section>

          {/* Scanners */}
          <section className="card p-6">
            <h2 className="label-m mb-4 text-xs text-muted">{en.newScan.scanners}</h2>
            <div className="grid gap-3 sm:grid-cols-2">
              {SCANNERS.map((name) => {
                const status = toolStatus.get(name);
                const on = tools[name] ?? false;
                return (
                  <button
                    key={name}
                    type="button"
                    role="switch"
                    aria-checked={on}
                    aria-label={name}
                    onClick={() => setTools((prev) => ({ ...prev, [name]: !prev[name] }))}
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
          </section>

          {/* AI review */}
          <section className="card p-6">
            <div className="mb-4 flex items-center justify-between">
              <h2 className="label-m text-xs text-muted">{en.newScan.aiReview}</h2>
              <button
                type="button"
                role="switch"
                aria-checked={aiReview}
                aria-label={en.newScan.aiReview}
                onClick={() => setAiReview((v) => !v)}
                className={`label-m border px-3 py-1.5 text-[11px] ${aiReview ? "border-ink text-ink" : "border-hairline text-muted"}`}
              >
                {aiReview ? en.newScan.aiOn : en.newScan.aiOff}
              </button>
            </div>
            {aiReview && (
              <div className="grid gap-3 sm:grid-cols-2">
                <label className="block">
                  <span className="label-m text-[11px] text-muted">{en.newScan.providerProfile}</span>
                  <input
                    className="mt-1 w-full border border-hairline bg-canvas px-3 py-2 text-sm text-ink"
                    value={providerProfile}
                    onChange={(e) => setProviderProfile(e.target.value)}
                    placeholder="kios-free"
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
                    placeholder="beam-free"
                  />
                </label>
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
                <p className="self-end text-xs text-muted">
                  {en.newScan.aiEstimate}: ${estimate.toFixed(2)}
                  {remaining !== undefined && ` · $${remaining.toFixed(2)} ${en.newScan.aiBudget}`}
                </p>
              </div>
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
                    placeholder="optional commit SHA"
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
              </div>
            </details>
          </section>
        </div>

        {/* Sticky review panel */}
        <aside className="lg:sticky lg:top-6 lg:self-start">
          <div className="card space-y-4 p-6">
            <h2 className="label-m text-xs text-muted">{en.newScan.review}</h2>
            <dl className="space-y-2 text-sm">
              <div className="flex justify-between gap-4">
                <dt className="text-muted">Target</dt>
                <dd className="break-all text-right font-mono text-xs text-ink">{repo || "—"}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-muted">Profile</dt>
                <dd className="text-ink">{profile.toUpperCase()}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-muted">Scanners</dt>
                <dd className="text-right text-ink">
                  {SCANNERS.filter((t) => tools[t]).join(", ") || "—"}
                </dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-muted">AI</dt>
                <dd className="text-ink">
                  {aiReview ? `on · $${estimate.toFixed(2)} est.` : "off"}
                </dd>
              </div>
            </dl>
            <div>
              <div className="label-m mb-2 text-[11px] text-muted">{en.newScan.cliPreview}</div>
              <pre className="overflow-x-auto border border-hairline bg-canvas p-3 font-mono text-xs text-body">
                {cli}
              </pre>
            </div>
            {startMutation.isError && (
              <Banner tone="error" title="Start failed">
                {String(startMutation.error)}
              </Banner>
            )}
            {startMutation.isSuccess && (
              <Banner tone="success" title={`${en.newScan.launched} #${startMutation.data.run_id}`}>
                {en.newScan.launchedBody}{" "}
                <Link to="/" className="text-ink">
                  Home
                </Link>{" "}
                · <Link to="/live" className="text-ink">Live</Link>
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
