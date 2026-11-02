import { useEffect, useRef, useState, type KeyboardEvent } from "react";
import type { PermissionReply, PermissionRequest, ReplyResult } from "../../api/remote";
import { useStrings } from "../../i18n/lang";
import { redactSecrets, redactValue } from "../../utils/redact";
import { Button } from "../Button";

interface Props {
  request: PermissionRequest;
  onReply: (reply: PermissionReply) => Promise<ReplyResult>;
  onClose: (notice?: string) => void;
  disabled?: boolean;
}

/** Presentation only. The host validates choices, edits, confirmations and first-reply wins. */
export function GateDialog({ request, onReply, onClose, disabled = false }: Props) {
  const s = useStrings().remote;
  const dialog = useRef<HTMLDivElement>(null);
  const diffRef = useRef<HTMLDivElement>(null);
  const reasonRef = useRef<HTMLTextAreaElement>(null);
  const inFlight = useRef(false);
  const [sending, setSending] = useState(false);
  const [selected, setSelected] = useState(-1);
  const [confirm, setConfirm] = useState("");
  const [reason, setReason] = useState("");
  const [edits, setEdits] = useState(JSON.stringify(redactValue(request.payload), null, 2));
  const [error, setError] = useState("");
  const [diffEnd, setDiffEnd] = useState(false);
  const diff = typeof request.payload.diff === "string" ? redactSecrets(request.payload.diff) : "";
  const isFix = request.gate === "G6";
  const word = request.gate === "G0" ? "send" : isFix ? "apply" : "";
  const dangerous = request.dangerous || !!word;

  useEffect(() => { if (disabled) { setSelected(-1); setConfirm(""); } }, [disabled]);

  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    dialog.current?.focus();
    const resetSelection = () => { setSelected(-1); setConfirm(""); };
    const visibility = () => { if (document.hidden) resetSelection(); };
    window.addEventListener("blur", resetSelection);
    document.addEventListener("visibilitychange", visibility);
    return () => {
      window.removeEventListener("blur", resetSelection);
      document.removeEventListener("visibilitychange", visibility);
      previous?.focus();
    };
  }, []);

  const checkDiffEnd = () => {
    const element = diffRef.current;
    if (diff && element && element.clientHeight > 0 && element.scrollTop + element.clientHeight >= element.scrollHeight - 1) setDiffEnd(true);
  };

  const keyFor = (choice: string) => {
    if (choice === "reject") return request.gate === "G5" || isFix ? "r" : "n";
    return ({ approve: "y", edit: "e", confirm: "c", need_more: "m", apply: "a", defer: "d" } as Record<string, string>)[choice];
  };
  const blocked = (choice: string) => disabled || sending ||
    (choice !== "undecided" && isFix && (!diff || !diffEnd)) ||
    ((choice === "approve" || choice === "apply") && !!word && confirm !== word);

  const answer = async (choice: string) => {
    if (inFlight.current || blocked(choice)) return;
    setError("");
    if (choice === "reject" && !reason.trim()) {
      setError(s.reasonRequired);
      reasonRef.current?.focus();
      return;
    }
    let parsed: Record<string, unknown> | undefined;
    if (choice === "edit") {
      try {
        parsed = JSON.parse(edits);
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error();
      } catch { setError(s.invalidEdits); return; }
    }
    inFlight.current = true;
    setSending(true);
    try {
      const result = await onReply({
        type: "permission_reply", request_id: request.request_id, choice,
        reason: reason.trim(), ...(parsed ? { edits: parsed } : {}),
        ...(word && (choice === "approve" || choice === "apply") ? { confirm } : {}),
      });
      if (result.ok) onClose(choice === "undecided" ? s.undecided : undefined);
      else if (result.error?.startsWith("already answered by")) onClose(redactSecrets(result.error));
      else setError(redactSecrets(result.error || s.failed));
    } catch { setError(s.failed); }
    finally { inFlight.current = false; setSending(false); }
  };

  const onKey = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); void answer("undecided"); return; }
    if (event.key === "Tab") {
      const nodes = [...(dialog.current?.querySelectorAll<HTMLElement>('button:not(:disabled), input, textarea, select, [tabindex="0"]') ?? [])];
      const first = nodes[0];
      const last = nodes[nodes.length - 1];
      if (event.shiftKey && (document.activeElement === first || document.activeElement === dialog.current)) { event.preventDefault(); last?.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
      return;
    }
    if ((event.target as HTMLElement).matches("input, textarea, select, [role=region]")) return;
    if (["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"].includes(event.key)) {
      event.preventDefault();
      const direction = event.key === "ArrowLeft" || event.key === "ArrowUp" ? -1 : 1;
      setSelected((index) => index < 0 ? (direction > 0 ? 0 : request.choices.length - 1) : (index + direction + request.choices.length) % request.choices.length);
    } else if (event.key === "Enter") {
      // Do not let the browser implicitly activate a focused/default button.
      if ((event.target as HTMLElement).dataset.closeGate) return;
      event.preventDefault();
      if (selected >= 0) void answer(request.choices[selected]);
    } else {
      const choice = request.choices.find((item) => keyFor(item) === event.key.toLowerCase());
      if (choice) { event.preventDefault(); void answer(choice); }
    }
  };

  return <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-3 sm:p-6">
    <div ref={dialog} role="dialog" aria-modal="true" aria-labelledby="remote-gate-title" tabIndex={-1} onKeyDown={onKey}
      className={`flex max-h-full w-full max-w-4xl flex-col border bg-soft ${dangerous ? "border-mred" : "border-hairline"}`}>
      <header className="border-b border-hairline p-4">
        <p className={`label-m ${dangerous ? "text-mred" : "text-muted"}`}>{request.gate} · {request.mode} {dangerous && `· ${s.dangerous}`}</p>
        <h2 id="remote-gate-title" className="text-xl font-bold text-ink">{redactSecrets(request.title)}</h2>
        <p className="whitespace-pre-wrap break-words">{redactSecrets(request.detail)}</p>
      </header>
      <div className="space-y-4 overflow-y-auto p-4">
        <section><h3 className="label-m">{s.recommendation}</h3><p className="whitespace-pre-wrap break-words">{redactSecrets(request.ai_recommendation) || s.unknown}</p></section>
        <section><h3 className="label-m">{s.payload}</h3><pre className="whitespace-pre-wrap break-all bg-canvas p-3 text-xs">{JSON.stringify(redactValue(request.payload), null, 2)}</pre></section>
        {isFix && <section>
          <h3 className="label-m">{s.diff}</h3>
          <div ref={diffRef} role="region" aria-label={s.diff} tabIndex={0}
            className="max-h-64 overflow-auto border border-hairline bg-canvas p-3 text-sm"
            onScroll={checkDiffEnd} onFocus={checkDiffEnd} onClick={checkDiffEnd}>
            <code className="whitespace-pre-wrap break-all">{diff || s.noDiff}</code>
          </div>
          <p className="text-xs text-muted">{diffEnd ? s.diffRead : s.diffHint}</p>
        </section>}
        {word && <label className="block text-sm">{isFix ? s.confirmApply : s.confirmSend}
          <input autoComplete="off" spellCheck={false} value={confirm} onChange={(e) => setConfirm(e.target.value)} className="mt-1 block w-full border border-hairline bg-canvas p-2 text-ink" />
        </label>}
        <label className="block text-sm">{s.reason}<textarea ref={reasonRef} value={reason} onChange={(e) => setReason(e.target.value)} className="mt-1 block w-full border border-hairline bg-canvas p-2 text-ink" rows={2} /></label>
        {request.choices.includes("edit") && <label className="block text-sm">{s.edits}<textarea value={edits} onChange={(e) => setEdits(e.target.value)} rows={5} spellCheck={false} className="mt-1 block w-full border border-hairline bg-canvas p-2 font-mono text-xs text-ink" /></label>}
        {error && <p role="alert" className="text-mred">{error}</p>}
      </div>
      <footer className="border-t border-hairline p-4">
        <div className="flex flex-wrap gap-2">
          {request.choices.map((choice, index) => <Button key={choice} type="button" disabled={blocked(choice)}
            variant={dangerous && (choice === "apply" || choice === "approve") ? "danger" : "secondary"}
            className={selected === index ? "outline outline-2 outline-white" : ""}
            onFocus={() => setSelected(index)} onClick={() => void answer(choice)}>
            {keyFor(choice) && `[${keyFor(choice)}] `}{s.choices[choice as keyof typeof s.choices] || choice}
          </Button>)}
          <Button data-close-gate="true" variant="ghost" type="button" disabled={disabled || sending} onFocus={() => setSelected(-1)} onClick={() => void answer("undecided")}>{s.closeGate}</Button>
        </div>
        <p className="mt-3 text-xs text-muted">{s.gateHints}</p>
      </footer>
    </div>
  </div>;
}
