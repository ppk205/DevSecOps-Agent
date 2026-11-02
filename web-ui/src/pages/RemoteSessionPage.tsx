import { useEffect, useRef, useState } from "react";
import { getState, login, send, subscribe } from "../api/remote";
import type { Mode, ModelEntry, ModelTemplate, PendingReview, PermissionRequest, ReadyInfo, RemoteEvent, RemoteMessage, RemoteState, ReplyResult, Usage } from "../api/remote";
import { Button } from "../components/Button";
import { CommandMenu } from "../components/remote/CommandMenu";
import { GateDialog } from "../components/remote/GateDialog";
import { ModelManager } from "../components/remote/ModelManager";
import { Transcript, type TranscriptEntry } from "../components/remote/Transcript";
import { useLang, useStrings } from "../i18n/lang";
import { redactSecrets } from "../utils/redact";

export function RemoteSessionPage() {
  const s = useStrings().remote;
  const { lang, setLang } = useLang();
  const bootstrap = useRef<Promise<void> | null>(null);
  const appliedSeq = useRef(-1);
  const seen = useRef(new Set<number>());
  const localId = useRef(0);
  const pendingRef = useRef<PermissionRequest | null>(null);
  const posting = useRef(false);
  const startInFlight = useRef(false);
  const sessionStarted = useRef(false);
  const [attempt, setAttempt] = useState(0);
  const [attached, setAttached] = useState(false);
  const [connection, setConnection] = useState<"connecting" | "connected" | "reconnecting">("connecting");
  const [fatal, setFatal] = useState("");
  const [notice, setNotice] = useState("");
  const [ready, setReady] = useState<ReadyInfo | null>(null);
  const [models, setModels] = useState<ModelEntry[]>([]);
  const [templates, setTemplates] = useState<ModelTemplate[]>([]);
  const [totals, setTotals] = useState<Usage>({});
  const [busy, setBusy] = useState(false);
  const [sending, setSending] = useState(false);
  const [starting, setStarting] = useState(false);
  const [started, setStarted] = useState(false);
  const [request, setRequest] = useState<PermissionRequest | null>(null);
  const [pending, setPending] = useState<PendingReview[]>([]);
  const [entries, setEntries] = useState<TranscriptEntry[]>([]);
  const [message, setMessage] = useState("");
  const [showCommands, setShowCommands] = useState(false);
  const [showModels, setShowModels] = useState(false);
  const [target, setTarget] = useState("");
  const [model, setModel] = useState("");
  const [mode, setMode] = useState<Mode>("ask");
  const [autoMessage, setAutoMessage] = useState<RemoteMessage | null>(null);
  const field = "mt-1 block w-full border border-hairline bg-canvas p-2 text-ink";
  const disabled = !attached || connection !== "connected";

  const applyRequest = (next: PermissionRequest | null) => { pendingRef.current = next; setRequest(next); };

  useEffect(() => {
    let stopped = false;
    let unsubscribe: (() => void) | undefined;
    setFatal("");
    setConnection("connecting");
    const restore = (state: RemoteState) => {
      if (stopped || state.seq < appliedSeq.current) return;
      appliedSeq.current = state.seq;
      setReady(state.ready);
      if (state.models) setModels(state.models);
      setTotals(state.totals || {});
      setBusy(state.busy);
      const hasStarted = state.started ?? !!state.ready;
      sessionStarted.current = hasStarted;
      setStarted(hasStarted);
      startInFlight.current = !hasStarted && state.busy;
      setStarting(startInFlight.current);
      if (!hasStarted && state.ready) {
        setTarget(state.ready.target);
        setModel(`${state.ready.provider}:${state.ready.model}`);
        setMode(state.ready.mode);
      }
      applyRequest(state.pending_request || null);
      setPending(state.pending_reviews || []);
    };
    const refresh = async () => {
      setConnection("reconnecting");
      try { restore(await getState()); if (!stopped) setConnection("connected"); }
      catch { if (!stopped) { setNotice(s.failed); setConnection("reconnecting"); } }
    };
    const receive = (event: RemoteEvent) => {
      if (stopped || seen.current.has(event.seq)) return;
      seen.current.add(event.seq);
      if (["text_delta", "tool_call", "tool_result", "error", "gate_result", "done", "remote"].includes(event.type)) {
        // Do not retain the login URL/token even in component state.
        const safeEvent = event.type === "remote" ? { ...event, url: undefined } : event;
        setEntries((old) => [...old, { id: `event-${event.seq}`, event: safeEvent }]);
      }
      // Snapshot is authoritative for current state; old replay is transcript only.
      if (event.seq <= appliedSeq.current) return;
      appliedSeq.current = event.seq;
      switch (event.type) {
        case "models": setModels(event.items); setTemplates(event.templates || []); break;
        case "ready":
          setReady(event);
          if (!sessionStarted.current) { startInFlight.current = true; setStarting(true); setBusy(true); }
          break;
        case "permission_request": applyRequest(event); break;
        case "gate_result":
          if (pendingRef.current?.request_id === event.request_id) { applyRequest(null); setNotice(`${s.answered} ${event.person}`); }
          if (event.mode) setReady((old) => old ? { ...old, mode: event.mode! } : old);
          break;
        case "pending": setPending(event.items); break;
        case "usage":
          setTotals((old) => ({ ...old, ...event }));
          if (event.provider || event.model) setReady((old) => old ? { ...old, provider: event.provider || old.provider, model: event.model || old.model } : old);
          break;
        case "tool_call": case "text_delta": setBusy(true); break;
        case "done":
          if (startInFlight.current) { sessionStarted.current = event.reason === "completed"; setStarted(sessionStarted.current); startInFlight.current = false; }
          setBusy(false); setStarting(false); break;
        case "error": setNotice(event.message); setStarting(false); break;
        case "remote": if (event.off) setConnection("reconnecting"); break;
      }
    };
    const connect = async () => {
      try {
        if (!bootstrap.current) {
          const token = new URLSearchParams(window.location.hash.slice(1)).get("t");
          if (token !== null) window.history.replaceState(window.history.state, "", window.location.pathname + window.location.search);
          bootstrap.current = token ? login(token) : Promise.resolve();
        }
        await bootstrap.current;
        if (stopped) return;
        restore(await getState());
        if (stopped) return;
        setAttached(true);
        unsubscribe = subscribe(0, receive, {
          onStatus: (status) => { if (!stopped) setConnection(status); },
          onReconnect: refresh,
        });
        const hello = await send({ type: "hello" });
        if (!stopped && !hello.ok) setNotice(hello.error || s.failed);
      } catch { if (!stopped) { setFatal(s.loginFailed); setAttached(false); } }
    };
    void connect();
    return () => { stopped = true; unsubscribe?.(); };
    // Language switches must not replay a one-time login or reconnect the stream.
  }, [attempt]);

  const relay = async (msg: RemoteMessage): Promise<ReplyResult> => {
    if (disabled) return { ok: false, error: s.reconnecting };
    try { return await send(msg); }
    catch { return { ok: false, error: s.failed }; }
  };

  const transmit = async (msg: RemoteMessage, text?: string) => {
    if (posting.current || disabled) return;
    posting.current = true;
    setSending(true);
    setNotice("");
    // User messages are echoed as numbered text_delta(role=user) events by the host.
    // Commands are local transcript entries because the protocol has no command echo.
    const entryId = text && msg.type === "command" ? `local-${++localId.current}` : undefined;
    if (text && entryId) setEntries((old) => [...old, { id: entryId, text }]);
    if (msg.type === "user_message") setBusy(true);
    if (msg.type === "start") { startInFlight.current = true; setStarting(true); }
    const result = await relay(msg);
    posting.current = false;
    setSending(false);
    if (!result.ok) {
      if (entryId) setEntries((old) => old.filter((entry) => entry.id !== entryId));
      setNotice(result.error || s.failed);
      if (msg.type === "user_message") setBusy(false);
      if (msg.type === "start") { startInFlight.current = false; setStarting(false); }
      return;
    }
    if (text) setMessage("");
  };

  const submitMessage = () => {
    const text = message.trim();
    if (!text || !started || sending || busy || request || disabled) return;
    if (text === "/keys" || text === "/model add") { setShowModels(true); setMessage(""); setShowCommands(false); return; }
    const parts = text.replace(/^\//, "").split(/\s+/);
    const msg: RemoteMessage = text.startsWith("/") ? { type: "command", name: parts[0], args: parts.slice(1) } : { type: "user_message", text };
    if (msg.type === "command" && msg.name === "mode" && msg.args[0] === "auto") { setAutoMessage(msg); return; }
    setShowCommands(false);
    void transmit(msg, text);
  };

  return <main tabIndex={-1} className="mx-auto min-h-screen max-w-6xl space-y-4 p-4 sm:p-6" onKeyDown={(e) => {
    if (e.key === "Escape" && !request && !autoMessage) { e.preventDefault(); setShowCommands(false); if (busy) void transmit({ type: "interrupt" }); }
    if (request || autoMessage || (e.target as HTMLElement).closest("input, textarea, select, button")) return;
    if (e.key === "?" || e.key === "/") { e.preventDefault(); setShowCommands(true); }
    if (pending[0] && !disabled && !sending && (e.key === "x" || (e.key === "r" && started && !busy))) {
      e.preventDefault();
      void transmit({ type: "command", name: "pending", args: [e.key === "r" ? "review" : "dismiss", pending[0].id] });
    }
  }}>
    <header className="flex flex-wrap items-center justify-between gap-3 border-b border-hairline pb-4">
      <div><p className="label-m text-muted">PIT WALL</p><h1 className="display-4">{s.title}</h1><p className="mt-2 text-sm">{s.subtitle}</p></div>
      <div className="flex items-center gap-3"><span className="text-xs text-muted">{s[connection]}</span><Button variant="secondary" size="sm" type="button" onClick={() => setLang(lang === "en" ? "vi" : "en")}>{lang === "en" ? "VI" : "EN"}</Button></div>
    </header>
    {fatal ? <div role="alert" className="border border-mred p-4"><p>{fatal}</p><Button type="button" variant="secondary" className="mt-3" onClick={() => { bootstrap.current = null; setAttempt((old) => old + 1); }}>{s.retry}</Button></div> : <>
      <p role="status" aria-live="polite" className="break-words text-sm text-muted">{notice ? redactSecrets(notice) : ""}</p>
      {attached && <>
        {ready ? <section aria-label={s.title} className="border border-hairline bg-soft p-4">
          <dl className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-3">
            {[[s.target, ready.target], [s.provider, ready.provider], [s.model, ready.model], [s.mode, ready.mode], [s.tokens, totals.total_tokens ?? s.unknown], [s.cost, totals.total_cost_usd ?? s.unknown]].map(([label, value]) => <div key={label}><dt className="text-xs text-muted">{label}</dt><dd className="break-all text-ink">{value}</dd></div>)}
          </dl><p className="mt-3 break-all text-xs text-muted">{s.commit}: {ready.commit} · {ready.local ? s.local : s.cloud} · {busy ? s.busy : s.idle}{ready.dirty && ` · ${s.dirty}`}</p>
        </section> : null}
        {!started && <form className="grid gap-3 border border-hairline bg-soft p-4 sm:grid-cols-2" onSubmit={(e) => {
          e.preventDefault();
          const msg: RemoteMessage = { type: "start", target: target.trim(), model, mode };
          if (mode === "auto") setAutoMessage(msg); else void transmit(msg);
        }}>
          <label className="text-sm">{s.target}<input value={target} disabled={!!ready} onChange={(e) => setTarget(e.target.value)} required className={field} /></label>
          <label className="text-sm">{s.model}<select value={model} disabled={!!ready} onChange={(e) => setModel(e.target.value)} required className={field}><option value="">—</option>{ready ? <option value={`${ready.provider}:${ready.model}`}>{ready.provider}:{ready.model}</option> : models.flatMap((entry) => (entry.models.length ? entry.models : [entry.default_model]).map((id) => <option key={`${entry.alias}:${id}`} value={`${entry.alias}:${id}`}>{entry.alias}:{id} · {entry.local ? s.local : s.cloud} · {entry.key_set ? s.keySet : s.keyMissing}</option>))}</select></label>
          <label className="text-sm">{s.mode}<select value={mode} disabled={!!ready} onChange={(e) => setMode(e.target.value as Mode)} className={field}><option value="ask">ask</option><option value="auto">auto</option></select></label>
          <div className="self-end"><Button type="submit" disabled={disabled || sending || starting || !!request || !target.trim() || !model}>{starting ? s.starting : s.start}</Button></div>
          {models.length === 0 && !ready && <p className="text-sm text-muted sm:col-span-2">{s.noModels}</p>}
        </form>}
        {pending.length > 0 && <section aria-label={s.pending} className="space-y-3 border border-mblue p-4"><h2 className="label-m text-ink">{s.pending}</h2>{pending.map((review) => <article key={review.id} className="space-y-2">
          <p className="break-words text-sm">{review.ref || s.folderChange} · {review.files.length} {s.files} · {review.source}</p>
          <details className="text-xs"><summary className="cursor-pointer">{s.files}</summary><ul>{review.files.map((file) => <li key={file} className="break-all">{file}</li>)}</ul></details>
          <div className="flex flex-wrap gap-2"><Button type="button" size="sm" disabled={disabled || !started || busy || sending || !!request} onClick={() => void transmit({ type: "command", name: "pending", args: ["review", review.id] })}>[r] {s.reviewNow}</Button><Button type="button" variant="secondary" size="sm" disabled={disabled || sending} onClick={() => void transmit({ type: "command", name: "pending", args: ["dismiss", review.id] })}>[x] {s.dismiss}</Button></div>
        </article>)}</section>}
        <Transcript entries={entries} />
        {ready && started && <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); submitMessage(); }}>
          {showCommands && <CommandMenu key={message.split(/\s/)[0]} query={message.startsWith("/") ? message.slice(1).split(/\s/)[0] : ""} onClose={() => setShowCommands(false)} onSelect={(name) => { setMessage(`/${name} `); setShowCommands(false); }} />}
          <label className="block text-sm">{s.message}<textarea value={message} disabled={disabled || sending || !!request} onChange={(e) => { setMessage(e.target.value); setShowCommands(e.target.value.startsWith("/") && !e.target.value.includes(" ")); }} rows={3} className={field} onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) { e.preventDefault(); submitMessage(); }
            if (e.key === "?" && message === "") { e.preventDefault(); setShowCommands(true); }
          }} /></label>
          <div className="flex flex-wrap gap-2"><Button type="submit" disabled={disabled || busy || sending || !!request || !message.trim()}>{s.send}</Button><Button type="button" variant="secondary" disabled={disabled || sending || !busy} onClick={() => void transmit({ type: "interrupt" })}>{s.interrupt}</Button><Button type="button" variant="ghost" onClick={() => setShowCommands(!showCommands)}>/ {s.commands}</Button><Button type="button" variant="ghost" onClick={() => setShowModels(!showModels)}>{s.modelsTitle}</Button></div>
        </form>}
        {(!ready || showModels) && <ModelManager models={models} templates={templates} onSend={relay} disabled={disabled || busy || !!request} />}
      </>}
    </>}
    <footer className="border-t border-hairline pt-3 text-xs text-muted">{s.hints}</footer>
    {request && <GateDialog key={`${request.request_id}:${request.seq}`} request={request} disabled={disabled} onReply={relay} onClose={(text) => {
      if (pendingRef.current?.request_id === request.request_id) applyRequest(null);
      if (text) setNotice(text);
    }} />}
    {autoMessage && <div role="dialog" aria-modal="true" aria-label={s.autoConfirm} className="fixed inset-0 z-40 flex items-center justify-center bg-black/80 p-4" onKeyDown={(e) => { if (e.key === "Escape") { e.stopPropagation(); setAutoMessage(null); } }}><section className="max-w-lg space-y-4 border border-hairline bg-card p-5"><p>{s.autoConfirm}</p><div className="flex flex-wrap gap-2"><Button type="button" disabled={disabled || sending || !!request} onClick={() => { const msg = autoMessage.type === "command" ? { ...autoMessage, args: ["auto", "confirm"] } : autoMessage; setAutoMessage(null); void transmit(msg, msg.type === "command" ? "/mode auto confirm" : undefined); }}>{s.confirmAuto}</Button><Button type="button" variant="secondary" onClick={() => setAutoMessage(null)}>{s.cancel}</Button></div></section></div>}
  </main>;
}
