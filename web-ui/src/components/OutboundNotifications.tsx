import { useEffect, useRef, useState } from "react";
import { fetchOutbound, fetchOutboundSettings, saveOutboundSettings, sendOutbound } from "../api/client";
import type { OutboundConfig, OutboundReceipt, OutboundSettings } from "../api/types";

const buttonStyle = "border border-hairline px-2 py-1 text-sm disabled:opacity-40";
const toggle = (values: string[], value: string) => values.includes(value) ? values.filter(item => item !== value) : [...values, value];

export function OutboundNotifications() {
  const [open, setOpen] = useState(false);
  const [config, setConfig] = useState<OutboundConfig>();
  const [receipt, setReceipt] = useState<OutboundReceipt>();
  const [runId, setRunId] = useState("");
  const [events, setEvents] = useState<string[]>([]);
  const [channels, setChannels] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const dialogRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    let active = true;
    const previous = document.activeElement as HTMLElement | null;
    dialogRef.current?.focus();
    setBusy(true);
    void fetchOutboundSettings().then(data => { if (active) setConfig(data); }).catch(() => { if (active) setMessage("Cannot load notification settings."); }).finally(() => { if (active) setBusy(false); });
    return () => { active = false; previous?.focus(); };
  }, [open]);
  const change = (settings: OutboundSettings) => config && setConfig({ ...config, settings });
  const operate = async (operation: () => Promise<void>) => {
    setBusy(true); setMessage("");
    try { await operation(); } catch { setMessage("Notification operation failed. Check configuration and retained delivery status."); }
    finally { setBusy(false); }
  };
  const pending = receipt?.deliveries.filter(row => row.status === "pending") ?? [];
  const offered = Array.from(new Map(pending.filter(row => channels.includes(row.channel)).flatMap(row => row.events).map(event => [event.kind, event])).values());
  return <>
    <button type="button" className={buttonStyle} onClick={() => { setOpen(true); setMessage(""); }}>Telegram / Discord</button>
    {open && <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-3" onPointerDown={event => event.stopPropagation()}>
      <div ref={dialogRef} tabIndex={-1} role="dialog" aria-modal="true" aria-label="Outbound notifications" className="max-h-[90vh] w-full max-w-2xl space-y-3 overflow-auto border border-hairline bg-elevated p-4 text-body" onKeyDown={event => {
        if (event.key === "Escape") { event.stopPropagation(); setOpen(false); }
        if (event.key === "Tab") {
          const items = Array.from(dialogRef.current?.querySelectorAll<HTMLElement>("button:not(:disabled),input:not(:disabled),select:not(:disabled)") ?? []);
          const first = items[0], last = items[items.length - 1];
          if (event.shiftKey && (document.activeElement === first || document.activeElement === dialogRef.current)) { event.preventDefault(); last?.focus(); }
          else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
        }
      }}>
        <div className="flex justify-between"><h2>Outbound notifications</h2><button type="button" className={buttonStyle} onClick={() => setOpen(false)}>Close</button></div>
        <p className="text-sm">Choose the events each destination receives. Automatic mode applies saved rules to future scans. Manual mode retains drafts for your selection.</p>
        {config && <fieldset disabled={busy} className="space-y-3">
          <label className="block">Delivery mode <select aria-label="Delivery mode" className="bg-elevated" value={config.settings.mode} onChange={event => change({ ...config.settings, mode: event.target.value as OutboundSettings["mode"] })}><option value="manual">Ask after each scan</option><option value="automatic">Send automatically</option></select></label>
          <div className="grid gap-3 sm:grid-cols-2">{(["telegram", "discord"] as const).map(channel => <fieldset key={channel} className="space-y-1 border border-hairline p-2">
            <legend>{channel === "telegram" ? "Telegram" : "Discord"}</legend>
            <label className="block"><input type="checkbox" checked={config.settings[channel].enabled} onChange={event => change({ ...config.settings, [channel]: { ...config.settings[channel], enabled: event.target.checked } })} aria-label={`${channel === "telegram" ? "Telegram" : "Discord"} enabled`} /> Enabled</label>
            {Object.entries(config.events).map(([kind, label]) => <label key={kind} className="block text-sm"><input type="checkbox" aria-label={`${channel === "telegram" ? "Telegram" : "Discord"}: ${label}`} checked={config.settings[channel].events.includes(kind)} onChange={() => change({ ...config.settings, [channel]: { ...config.settings[channel], events: toggle(config.settings[channel].events, kind) } })} /> {label}</label>)}
          </fieldset>)}</div>
          <p className="text-sm text-muted">Save the bot token, chat ID and Discord webhook through the masked Keys page or CLI <code>env set</code>. This form stores event preferences only.</p>
          <button type="button" className={buttonStyle} onClick={() => void operate(async () => { setConfig(await saveOutboundSettings(config.settings)); setMessage("Preferences saved. No messages sent."); })}>Save preferences</button>
        </fieldset>}
        <fieldset disabled={busy} className="space-y-2 border-t border-hairline pt-3">
          <legend>Review retained deliveries</legend>
          <label>Run ID <input className="border border-hairline bg-elevated px-2" value={runId} onChange={event => { setRunId(event.target.value); setReceipt(undefined); setChannels([]); setEvents([]); }} /></label>
          <button type="button" disabled={!runId.trim() || busy} className={buttonStyle} onClick={() => void operate(async () => { setReceipt(await fetchOutbound(runId.trim())); setChannels([]); setEvents([]); })}>Load deliveries</button>
          {receipt?.deliveries.map(row => <div key={row.channel} className="text-sm">
            <p>{row.channel}: {row.status} — {row.detail}</p>
            {row.status === "pending" && <label><input type="checkbox" checked={channels.includes(row.channel)} onChange={() => { setChannels(toggle(channels, row.channel)); setEvents([]); }} /> Send to {row.channel}</label>}
          </div>)}
          {offered.map(event => <label key={event.kind} className="block text-sm"><input type="checkbox" checked={events.includes(event.kind)} onChange={() => setEvents(toggle(events, event.kind))} /> {event.message}</label>)}
          <button type="button" disabled={busy || !events.length || !channels.length} className={buttonStyle} onClick={() => void operate(async () => { const relevant = pending.filter(row => channels.includes(row.channel) && row.events.some(event => events.includes(event.kind))).map(row => row.channel); setReceipt(await sendOutbound(receipt!.run_id, events, relevant)); setChannels([]); setEvents([]); setMessage("Delivery status recorded."); })}>Send selected summaries now</button>
        </fieldset>
        <p role="status" className="text-sm">{busy ? "Working…" : message}</p>
      </div>
    </div>}
  </>;
}
