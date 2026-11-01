import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  deleteKey,
  fetchGeneralSettings,
  fetchKeys,
  fetchTools,
  fetchUsage,
  saveKey,
  testKeyConnection,
  updateGeneralSettings,
} from "../api/client";
import type { GeneralSettings } from "../api/types";
import { Banner } from "../components/Banner";
import { Button } from "../components/Button";
import { useStrings } from "../i18n/lang";
import { tokens } from "../tokens";

function Section({
  title,
  body,
  children,
}: {
  title: string;
  body: string;
  children: React.ReactNode;
}) {
  return (
    <section className="card mb-6 p-6">
      <h2 className="label-m text-xs text-muted">{title}</h2>
      <p className="mt-1 text-sm text-body">{body}</p>
      <div className="mt-4">{children}</div>
    </section>
  );
}

export function KeysPage() {
  const en = useStrings();
  const queryClient = useQueryClient();
  const [verifyMode, setVerifyMode] = useState(false);
  const keysQuery = useQuery({ queryKey: ["keys"], queryFn: fetchKeys });
  const toolsQuery = useQuery({
    queryKey: ["tools", verifyMode],
    queryFn: () => fetchTools(verifyMode),
  });
  const usageQuery = useQuery({ queryKey: ["usage"], queryFn: fetchUsage });
  const settingsQuery = useQuery({ queryKey: ["settings"], queryFn: fetchGeneralSettings });

  const [profile, setProfile] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [label, setLabel] = useState("");
  const [testResult, setTestResult] = useState<string | null>(null);
  const [form, setForm] = useState<Partial<GeneralSettings>>({});
  const [savedNote, setSavedNote] = useState(false);

  const invalidateKeys = () => queryClient.invalidateQueries({ queryKey: ["keys"] });

  const saveMutation = useMutation({
    mutationFn: () =>
      saveKey(profile.trim().toLowerCase(), {
        api_key: apiKey,
        base_url: baseUrl || undefined,
        label: label || undefined,
      }),
    onSuccess: () => {
      setApiKey("");
      invalidateKeys();
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteKey(id),
    onSuccess: () => invalidateKeys(),
  });

  const testMutation = useMutation({
    mutationFn: (id: string) => testKeyConnection(id),
    onSuccess: (result) =>
      setTestResult(result.ok ? `ok · ${result.model}` : `failed · ${result.error ?? "unknown"}`),
    onError: (error) => setTestResult(`failed · ${String(error)}`),
  });

  const settingsMutation = useMutation({
    mutationFn: (patch: Partial<GeneralSettings>) => updateGeneralSettings(patch),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["settings"] });
      setSavedNote(true);
    },
  });

  const keys = keysQuery.data ?? [];
  const usage = usageQuery.data;
  const settings = { ...(settingsQuery.data ?? {}), ...form };
  const spentPct = usage ? Math.min(100, (usage.total_spent / usage.total_budget) * 100) : 0;

  return (
    <div>
      <div className="mb-10">
        <h1 className="display-4">{en.apiKeys.title}</h1>
        <p className="mt-2 text-body">{en.apiKeys.subtitle}</p>
      </div>

      {/* AI PROVIDER */}
      <Section title={en.apiKeys.provider} body={en.apiKeys.providerBody}>
        <div className="grid gap-3 md:grid-cols-2">
          <label className="block">
            <span className="label-m text-[11px] text-muted">{en.apiKeys.profileLabel}</span>
            <input
              className="mt-1 w-full border border-hairline bg-canvas px-3 py-2 text-sm text-ink"
              value={profile}
              onChange={(e) => {
                setProfile(e.target.value);
                setTestResult(null);
              }}
              placeholder={en.apiKeys.newProfilePlaceholder}
              list="keys-profiles"
            />
            <datalist id="keys-profiles">
              {keys.map((k) => (
                <option key={k.profile} value={k.profile} />
              ))}
            </datalist>
          </label>
          <label className="block">
            <span className="label-m text-[11px] text-muted">{en.apiKeys.keyLabel}</span>
            <input
              type="password"
              autoComplete="new-password"
              className="mt-1 w-full border border-hairline bg-canvas px-3 py-2 font-mono text-sm text-ink"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder={en.apiKeys.keyPlaceholder}
            />
          </label>
          <label className="block">
            <span className="label-m text-[11px] text-muted">{en.apiKeys.baseUrl}</span>
            <input
              className="mt-1 w-full border border-hairline bg-canvas px-3 py-2 text-sm text-ink"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="https://api.openai.com/v1"
            />
          </label>
          <label className="block">
            <span className="label-m text-[11px] text-muted">{en.apiKeys.labelField}</span>
            <input
              className="mt-1 w-full border border-hairline bg-canvas px-3 py-2 text-sm text-ink"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="My provider"
            />
          </label>
        </div>
        <div className="mt-4 flex flex-wrap gap-2">
          <Button
            variant="primary"
            size="sm"
            disabled={!profile.trim() || !apiKey || saveMutation.isPending}
            onClick={() => saveMutation.mutate()}
          >
            {en.apiKeys.saveKey}
          </Button>
          <Button
            variant="secondary"
            size="sm"
            disabled={!profile.trim() || testMutation.isPending}
            onClick={() => testMutation.mutate(profile.trim().toLowerCase())}
          >
            {en.apiKeys.testConnection}
          </Button>
        </div>
        {saveMutation.isError && (
          <div className="mt-4">
            <Banner tone="error" title={en.apiKeys.saveFailed}>
              {String(saveMutation.error)}
            </Banner>
          </div>
        )}
        {testResult && (
          <p className="mt-3 font-mono text-xs text-body" role="status">
            {testResult}
          </p>
        )}
        <div className="mt-6">
          {keysQuery.isLoading ? (
            <p className="text-body">{en.common.loading}</p>
          ) : keys.length === 0 ? (
            <p className="text-sm text-muted">{en.apiKeys.noKeys}</p>
          ) : (
            <ul className="divide-y divide-hairline border border-hairline">
              {keys.map((k) => (
                <li key={k.profile} className="flex flex-wrap items-center gap-3 p-3">
                  <span
                    aria-hidden
                    className="inline-block h-2 w-2"
                    style={{ background: k.configured ? tokens.color.success : tokens.color.mRed }}
                  />
                  <span className="label-m text-xs text-ink">{k.profile}</span>
                  <span className="text-xs text-muted">{k.label}</span>
                  <span className="font-mono text-xs text-body">{k.masked || en.apiKeys.notSet}</span>
                  <span className="ml-auto flex gap-2">
                    <Button
                      variant="secondary"
                      size="sm"
                      disabled={testMutation.isPending}
                      onClick={() => {
                        setProfile(k.profile);
                        testMutation.mutate(k.profile);
                      }}
                    >
                      {en.apiKeys.testConnection}
                    </Button>
                    <Button
                      variant="danger"
                      size="sm"
                      disabled={deleteMutation.isPending}
                      onClick={() => deleteMutation.mutate(k.profile)}
                    >
                      {en.apiKeys.deleteKey}
                    </Button>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </Section>

      {/* SCANNER TOOLS */}
      <Section title={en.apiKeys.scanners} body={en.apiKeys.scannersBody}>
        <div className="mb-3 flex gap-2">
          <Button variant="secondary" size="sm" onClick={() => setVerifyMode(false)}>
            {en.apiKeys.detect}
          </Button>
          <Button variant="secondary" size="sm" onClick={() => setVerifyMode(true)}>
            {en.apiKeys.verify}
          </Button>
        </div>
        {toolsQuery.isLoading ? (
          <p className="text-body">{en.common.loading}</p>
        ) : (
          <ul className="divide-y divide-hairline border border-hairline">
            {(toolsQuery.data?.tools ?? []).map((t) => (
              <li key={t.tool} className="flex flex-wrap items-center gap-3 p-3">
                <span
                  aria-hidden
                  className="inline-block h-2 w-2"
                  style={{ background: t.available ? tokens.color.success : tokens.color.mRed }}
                />
                <span className="label-m text-xs text-ink">{t.tool}</span>
                <span className="font-mono text-xs text-body">{t.binary}</span>
                <span className="font-mono text-xs text-muted">{t.path ?? t.hint ?? en.apiKeys.missing}</span>
                {t.version && <span className="font-mono text-xs text-body">{t.version}</span>}
              </li>
            ))}
          </ul>
        )}
      </Section>

      {/* USAGE & BUDGET */}
      <Section title={en.apiKeys.usage} body={en.apiKeys.usageBody}>
        {usage ? (
          <div>
            <div className="flex justify-between text-xs text-muted">
              <span>
                ${usage.total_spent.toFixed(2)} {en.apiKeys.spent} / ${usage.total_budget.toFixed(0)}
              </span>
              <span>
                ${usage.available.toFixed(2)} {en.apiKeys.remaining}
              </span>
            </div>
            <div
              className="mt-2 h-2 w-full bg-elevated"
              role="progressbar"
              aria-valuenow={Math.round(spentPct)}
              aria-valuemin={0}
              aria-valuemax={100}
            >
              <div className="h-2" style={{ width: `${spentPct}%`, background: tokens.color.mRed }} />
            </div>
            {Object.entries(usage.by_provider).map(([provider, spent]) => (
              <div key={provider} className="mt-2 flex justify-between text-sm">
                <span className="text-body">{provider}</span>
                <span className="font-mono text-xs text-ink">${spent.toFixed(2)}</span>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-body">{en.common.loading}</p>
        )}
      </Section>

      {/* GENERAL */}
      <Section title={en.apiKeys.general} body={en.apiKeys.generalBody}>
        <div className="grid gap-3 md:grid-cols-2">
          <label className="block">
            <span className="label-m text-[11px] text-muted">{en.apiKeys.timezone}</span>
            <input
              className="mt-1 w-full border border-hairline bg-canvas px-3 py-2 text-sm text-ink"
              value={settings.timezone ?? ""}
              onChange={(e) => {
                setForm((f) => ({ ...f, timezone: e.target.value }));
                setSavedNote(false);
              }}
            />
          </label>
          <label className="block">
            <span className="label-m text-[11px] text-muted">{en.apiKeys.timeoutSecs}</span>
            <input
              type="number"
              className="mt-1 w-full border border-hairline bg-canvas px-3 py-2 text-sm text-ink"
              value={settings.timeout ?? ""}
              onChange={(e) => {
                setForm((f) => ({ ...f, timeout: Number(e.target.value) }));
                setSavedNote(false);
              }}
            />
          </label>
          <label className="block">
            <span className="label-m text-[11px] text-muted">{en.apiKeys.maxFiles}</span>
            <input
              type="number"
              className="mt-1 w-full border border-hairline bg-canvas px-3 py-2 text-sm text-ink"
              value={settings.max_files ?? ""}
              onChange={(e) => {
                setForm((f) => ({ ...f, max_files: Number(e.target.value) }));
                setSavedNote(false);
              }}
            />
          </label>
          <label className="block">
            <span className="label-m text-[11px] text-muted">{en.apiKeys.outputDir}</span>
            <input
              className="mt-1 w-full border border-hairline bg-canvas px-3 py-2 text-sm text-ink"
              value={settings.output_dir ?? ""}
              onChange={(e) => {
                setForm((f) => ({ ...f, output_dir: e.target.value }));
                setSavedNote(false);
              }}
            />
          </label>
        </div>
        <div className="mt-4 flex items-center gap-3">
          <Button
            variant="primary"
            size="sm"
            disabled={Object.keys(form).length === 0 || settingsMutation.isPending}
            onClick={() => settingsMutation.mutate(form)}
          >
            {en.apiKeys.saveSettings}
          </Button>
          {savedNote && (
            <span className="text-xs text-body" role="status">
              {en.apiKeys.saved}
            </span>
          )}
        </div>
        {settingsMutation.isError && (
          <div className="mt-4">
            <Banner tone="error" title={en.apiKeys.saveFailed}>
              {String(settingsMutation.error)}
            </Banner>
          </div>
        )}
      </Section>
    </div>
  );
}
