import { useRef, useState } from "react";
import type { ModelEntry, ModelTemplate, RemoteMessage, ReplyResult } from "../../api/remote";
import { useStrings } from "../../i18n/lang";
import { Button } from "../Button";

export function ModelManager({ models, templates = [], onSend, disabled }: {
  models: ModelEntry[];
  templates?: ModelTemplate[];
  onSend: (message: RemoteMessage) => Promise<ReplyResult>;
  disabled: boolean;
}) {
  const s = useStrings().remote;
  const [open, setOpen] = useState(false);
  const [alias, setAlias] = useState("");
  const [template, setTemplate] = useState("custom");
  const [protocol, setProtocol] = useState("openai_compatible");
  const [baseUrl, setBaseUrl] = useState("");
  const [modelIds, setModelIds] = useState("");
  const [key, setKey] = useState("");
  const [keyAlias, setKeyAlias] = useState("");
  const [saving, setSaving] = useState(false);
  const locked = useRef(false);
  const [notice, setNotice] = useState("");
  const field = "mt-1 block w-full border border-hairline bg-canvas p-2 text-ink";
  const submit = async (message: RemoteMessage) => {
    if (locked.current || disabled) return;
    locked.current = true;
    setSaving(true);
    setKey("");
    setNotice("");
    try {
      const result = await onSend(message);
      // Never echo a response to a key-bearing request: only show fixed text.
      setNotice(result.ok ? s.savedModel : s.failed);
    } catch { setNotice(s.failed); }
    finally { locked.current = false; setSaving(false); }
  };
  return <section className="border border-hairline bg-soft p-4" aria-label={s.modelsTitle}>
    <div className="flex flex-wrap items-center justify-between gap-2"><h2 className="label-m text-ink">{s.modelsTitle}</h2><Button type="button" variant="secondary" size="sm" onClick={() => { setOpen(!open); setKey(""); setKeyAlias(""); }}>{s.addModel}</Button></div>
    <ul className="mt-2 space-y-2">{models.map((model) => <li key={model.alias} className="flex flex-wrap items-center gap-2 border-b border-hairline py-2 text-sm">
      <span className="break-all text-ink">{model.alias}:{model.default_model}</span><span>{model.local ? s.local : s.cloud} · {model.key_set ? s.keySet : s.keyMissing}</span>
      <Button type="button" size="sm" variant="ghost" disabled={disabled || saving} onClick={() => { setKeyAlias(model.alias); setKey(""); setOpen(false); }}>{s.replaceKey}</Button>
      <Button type="button" size="sm" variant="ghost" disabled={disabled || saving} onClick={() => void submit({ type: "model_remove", alias: model.alias })}>{s.removeModel}</Button>
    </li>)}</ul>
    {keyAlias && <form className="mt-4 space-y-3" onSubmit={(e) => { e.preventDefault(); void submit({ type: "model_key", alias: keyAlias, key }); }}>
      <p className="text-sm text-ink">{keyAlias}</p>
      <label className="block text-sm">{s.key}<input type="password" autoComplete="new-password" value={key} onChange={(e) => setKey(e.target.value)} className={field} /></label>
      <Button type="submit" disabled={disabled || saving}>{s.replaceKey}</Button>
      <Button type="button" variant="ghost" onClick={() => { setKey(""); setKeyAlias(""); }}>{s.cancel}</Button>
    </form>}
    {open && <form className="mt-4 grid gap-3 sm:grid-cols-2" onSubmit={(e) => {
      e.preventDefault();
      void submit({ type: "model_add", alias: alias.trim(), template: template === "custom" ? null : template, model_protocol: protocol, base_url: baseUrl.trim(), models: modelIds.split(/\r?\n/).map((m) => m.trim()).filter(Boolean), key });
    }}>
      <p className="text-sm text-muted sm:col-span-2">{s.modelHint}</p>
      <label className="text-sm">{s.alias}<input required pattern="[a-z0-9-]{1,32}" value={alias} onChange={(e) => setAlias(e.target.value)} className={field} autoComplete="off" /></label>
      <label className="text-sm">{s.template}<select value={template} className={field} onChange={(e) => {
        setTemplate(e.target.value);
        const entry = templates.find((item) => item.id === e.target.value);
        if (entry) {
          setProtocol(entry.protocol);
          setBaseUrl(entry.base_url);
          // The first model ID is the saved default in the model_add contract.
          const ids = entry.default_model ? [entry.default_model, ...entry.models] : entry.models;
          setModelIds([...new Set(ids)].join("\n"));
        }
      }}><option value="custom">{s.custom}</option>{templates.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}</select></label>
      <label className="text-sm">{s.protocol}<select value={protocol} onChange={(e) => setProtocol(e.target.value)} className={field}><option value="openai_compatible">openai_compatible</option><option value="openai_chat_completions">openai_chat_completions</option><option value="anthropic_messages">anthropic_messages</option></select></label>
      <label className="text-sm">{s.baseUrl}<input required type="url" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} className={field} autoComplete="off" /></label>
      <label className="text-sm">{s.modelIds}<textarea required value={modelIds} onChange={(e) => setModelIds(e.target.value)} className={field} rows={2} /></label>
      <label className="text-sm">{s.key}<input type="password" autoComplete="new-password" value={key} onChange={(e) => setKey(e.target.value)} className={field} /></label>
      <p className="text-xs text-muted sm:col-span-2">{s.keyHint}</p>
      <div className="flex gap-2 sm:col-span-2"><Button type="submit" disabled={disabled || saving}>{s.saveModel}</Button><Button type="button" variant="ghost" onClick={() => { setOpen(false); setKey(""); }}>{s.cancel}</Button></div>
    </form>}
    {notice && <p aria-live="polite" className="mt-2 text-sm">{notice}</p>}
  </section>;
}
