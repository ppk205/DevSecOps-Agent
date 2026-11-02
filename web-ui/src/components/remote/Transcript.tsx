import type { RemoteEvent } from "../../api/remote";
import { useStrings } from "../../i18n/lang";
import { redactSecrets, redactValue } from "../../utils/redact";

export type TranscriptEntry = { id: string; event: RemoteEvent } | { id: string; text: string };

export function Transcript({ entries }: { entries: TranscriptEntry[] }) {
  const s = useStrings().remote;
  return <section role="log" aria-label={s.transcript} aria-live="polite" aria-relevant="additions" className="min-h-40 space-y-3 overflow-y-auto border border-hairline bg-soft p-4">
    {entries.length === 0 && <p className="text-muted">{s.empty}</p>}
    {entries.map((entry) => {
      if ("text" in entry) return <article key={entry.id}><h3 className="label-m text-xs text-muted">{s.you}</h3><p className="whitespace-pre-wrap break-words text-ink">{redactSecrets(entry.text)}</p></article>;
      const e = entry.event;
      switch (e.type) {
        case "text_delta": return <article key={entry.id}><h3 className={`label-m text-xs ${e.role === "user" ? "text-muted" : "text-mblue"}`}>{e.role === "user" ? s.you : s.ai}</h3><p className="whitespace-pre-wrap break-words">{redactSecrets(e.text)}</p></article>;
        case "tool_call":
        case "tool_result": return <details key={entry.id} className="border border-hairline p-3"><summary className="cursor-pointer break-words text-sm text-ink">{e.type === "tool_call" ? s.toolCall : s.toolResult} · {redactSecrets(e.name)}{e.type === "tool_result" && ` · ${redactSecrets(e.summary)}`}</summary><pre className="mt-2 whitespace-pre-wrap break-all text-xs">{JSON.stringify(redactValue(e.type === "tool_call" ? e.arguments : e.result ?? e.summary), null, 2)}</pre></details>;
        case "error": return <p key={entry.id} className="whitespace-pre-wrap break-words text-mred">{redactSecrets(e.message)}</p>;
        case "gate_result": return <p key={entry.id} className="text-sm text-muted">{e.gate} · {redactSecrets(e.choice)} · {redactSecrets(e.person)}</p>;
        case "done": return <p key={entry.id} className="text-xs text-muted">{s.completed} · {redactSecrets(e.reason)}</p>;
        // Login fragments must never be mirrored into transcript, DOM links or history.
        case "remote": return <p key={entry.id} className="text-sm text-muted">{e.off ? s.remoteOff : s.remoteOn}</p>;
        default: return null;
      }
    })}
  </section>;
}
