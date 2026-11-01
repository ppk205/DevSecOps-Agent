import { useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { fetchLogs, fetchScans, openLogsStream } from "../api/client";
import type { LogLine } from "../api/types";
import { Button } from "../components/Button";
import { EmptyState } from "../components/EmptyState";
import { en } from "../i18n/en";
import { copyText } from "../utils/clipboard";
import { redactSecrets, redactValue } from "../utils/redact";
import { PageHeader } from "./pages";

const LEVELS = ["all", "debug", "info", "warn", "error"];
const FINDING_RE = /\b((?:[a-z0-9]+-)?f-\d{3,})\b/g;

function toLogLine(data: unknown): LogLine | null {
  const line = (typeof data === "string" ? safeParse(data) : data) as LogLine | null;
  if (!line || typeof line.seq !== "number" || typeof line.message !== "string") return null;
  return line;
}

function safeParse(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

/** Highlight regex matches and linkify finding ids inside a message. */
function renderMessage(message: string, highlight: RegExp | null): ReactNode {
  const safe = redactSecrets(message);
  const parts: ReactNode[] = [];
  let last = 0;
  FINDING_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  const pushText = (text: string, key: string) => {
    if (!highlight) {
      parts.push(<span key={key}>{text}</span>);
      return;
    }
    highlight.lastIndex = 0;
    let hLast = 0;
    let hMatch: RegExpExecArray | null;
    let n = 0;
    // eslint-disable-next-line no-cond-assign
    while ((hMatch = highlight.exec(text)) !== null) {
      if (hMatch.index > hLast) parts.push(<span key={`${key}-t${n}`}>{text.slice(hLast, hMatch.index)}</span>);
      parts.push(
        <mark key={`${key}-m${n}`} className="bg-mblue px-0.5 text-ink">
          {hMatch[0]}
        </mark>,
      );
      hLast = hMatch.index + hMatch[0].length;
      n += 1;
      if (hMatch[0].length === 0) highlight.lastIndex += 1;
      if (n > 200) break;
    }
    if (hLast < text.length) parts.push(<span key={`${key}-rest`}>{text.slice(hLast)}</span>);
  };
  let n = 0;
  // eslint-disable-next-line no-cond-assign
  while ((match = FINDING_RE.exec(safe)) !== null) {
    if (match.index > last) pushText(safe.slice(last, match.index), `t${n}`);
    parts.push(
      <Link key={`f${n}`} to="/findings" className="font-mono text-xs text-ink underline">
        {match[0]}
      </Link>,
    );
    last = match.index + match[0].length;
    n += 1;
    if (n > 200) break;
  }
  if (last < safe.length) pushText(safe.slice(last), "tail");
  if (parts.length === 0) pushText(safe, "only");
  return <>{parts}</>;
}

function LogRow({
  line,
  highlight,
  wrap,
}: {
  line: LogLine;
  highlight: RegExp | null;
  wrap: boolean;
}) {
  const [expanded, setExpanded] = useState(false);
  const safe = redactValue(line.data);
  const hasData = safe !== null && typeof safe === "object" && Object.keys(safe as object).length > 0;
  return (
    <div className="border-b border-hairline px-4 py-2 last:border-0 hover:bg-elevated">
      <div className={`flex gap-3 text-[13px] ${wrap ? "" : "whitespace-nowrap"}`}>
        <span className="w-10 shrink-0 font-mono text-xs text-muted">#{line.seq}</span>
        <span className="w-14 shrink-0 uppercase text-muted">{line.level}</span>
        <Link to="/live" className="w-20 shrink-0 text-muted underline" title="Open live pipeline">
          {line.source}
        </Link>
        <span className={`text-body ${wrap ? "break-words" : "overflow-hidden text-ellipsis"}`}>
          {renderMessage(line.message, highlight)}
        </span>
        <span className="ml-auto flex shrink-0 gap-2">
          {line.finding_id && (
            <Link to="/findings" className="font-mono text-xs text-ink underline">
              {line.finding_id}
            </Link>
          )}
          {hasData && (
            <button className="label-m text-[11px] text-muted underline" onClick={() => setExpanded((v) => !v)}>
              {expanded ? "Hide JSON" : "JSON"}
            </button>
          )}
        </span>
      </div>
      {expanded && (
        <pre className="mt-2 overflow-x-auto bg-soft p-3 font-mono text-xs text-body">
          {JSON.stringify(safe, null, 2)}
        </pre>
      )}
    </div>
  );
}

function download(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}

export function LogsPage() {
  const scans = useQuery({ queryKey: ["scans"], queryFn: fetchScans });
  const ids = useMemo(() => (scans.data ?? []).map((s) => s.run_id), [scans.data]);
  const [scanId, setScanId] = useState<number | null>(null);
  const [level, setLevel] = useState("all");
  const [source, setSource] = useState("all");
  const [search, setSearch] = useState("");
  const highlight = useMemo<{ re: RegExp | null; error: string | null }>(() => {
    if (!search) return { re: null, error: null };
    try {
      return { re: new RegExp(search, "gi"), error: null };
    } catch {
      return { re: null, error: "Invalid regex — showing unfiltered lines." };
    }
  }, [search]);
  const regexError = highlight.error;
  const highlightRe = highlight.re;
  const [paused, setPaused] = useState(false);
  const [wrap, setWrap] = useState(true);
  const [copied, setCopied] = useState(false);
  const [streamed, setStreamed] = useState<LogLine[]>([]);
  const [buffered, setBuffered] = useState<LogLine[]>([]);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  const active = scanId ?? ids[0] ?? null;

  const history = useQuery({
    queryKey: ["logs", active, level, source],
    queryFn: () => fetchLogs(active as number, { level, source }),
    enabled: active !== null,
  });

  useEffect(() => {
    setStreamed([]);
    setBuffered([]);
  }, [active, level, source]);

  useEffect(() => {
    if (active === null) return;
    const close = openLogsStream(
      active,
      { level, source },
      (_kind, data) => {
        const line = toLogLine(data);
        if (!line) return;
        if (pausedRef.current) {
          setBuffered((prev) => (prev.some((l) => l.seq === line.seq) ? prev : [...prev, line]));
        } else {
          setStreamed((prev) => (prev.some((l) => l.seq === line.seq) ? prev : [...prev, line]));
        }
      },
    );
    return close;
  }, [active, level, source]);

  if (scans.isLoading || active === null) return <p className="text-body">{en.common.loading}</p>;

  const base = history.data?.lines ?? [];
  const merged = [...base, ...streamed.filter((l) => !base.some((b) => b.seq === l.seq))].sort(
    (a, b) => a.seq - b.seq,
  );
  const sources = [...new Set(merged.map((l) => l.source))].sort();
  const visible = highlightRe
    ? merged.filter((l) => {
        highlightRe.lastIndex = 0;
        return highlightRe.test(redactSecrets(l.message));
      })
    : merged;

  function resume() {
    setStreamed((prev) => {
      const extra = buffered.filter((l) => !prev.some((p) => p.seq === l.seq));
      return [...prev, ...extra];
    });
    setBuffered([]);
    setPaused(false);
  }

  const logText = visible.map((l) => `[${l.ts ?? "?"}] [${l.level}] [${l.source}] ${redactSecrets(l.message)}`).join("\n");

  return (
    <div>
      <PageHeader title={en.logs.title} subtitle={en.logs.subtitle} />
      <div className="mb-4 flex flex-wrap items-end gap-3">
        <label className="label-m text-[11px] text-muted">
          Scan{" "}
          <select
            aria-label="Scan"
            className="ml-1 border border-hairline bg-canvas px-2 py-1.5 text-sm text-ink"
            value={active}
            onChange={(e) => setScanId(Number(e.target.value))}
          >
            {ids.map((id) => (
              <option key={id} value={id}>
                Scan #{id}
              </option>
            ))}
          </select>
        </label>
        <label className="label-m text-[11px] text-muted">
          Level{" "}
          <select
            aria-label="Level"
            className="ml-1 border border-hairline bg-canvas px-2 py-1.5 text-sm text-ink"
            value={level}
            onChange={(e) => setLevel(e.target.value)}
          >
            {LEVELS.map((l) => (
              <option key={l} value={l}>
                {l}
              </option>
            ))}
          </select>
        </label>
        <label className="label-m text-[11px] text-muted">
          Source{" "}
          <select
            aria-label="Source"
            className="ml-1 border border-hairline bg-canvas px-2 py-1.5 text-sm text-ink"
            value={source}
            onChange={(e) => setSource(e.target.value)}
          >
            <option value="all">all</option>
            {sources.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
        <label className="label-m text-[11px] text-muted">
          Search (regex){" "}
          <input
            aria-label="Search"
            className="ml-1 border border-hairline bg-canvas px-2 py-1.5 text-sm text-ink"
            value={search}
            placeholder="error|warn"
            onChange={(e) => setSearch(e.target.value)}
          />
        </label>
        <span className="ml-auto flex flex-wrap gap-2">
          <Button variant="secondary" size="sm" onClick={() => (paused ? resume() : setPaused(true))}>
            {paused ? "Resume" : "Pause"}
          </Button>
          <Button variant="ghost" size="sm" onClick={() => setWrap((v) => !v)}>
            Wrap: {wrap ? "on" : "off"}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              void copyText(logText).then((ok) => {
                setCopied(ok);
                setTimeout(() => setCopied(false), 1500);
              });
            }}
          >
            {copied ? "Copied" : "Copy"}
          </Button>
          <Button variant="ghost" size="sm" onClick={() => download(`scan-${active}.log`, `${logText}\n`, "text/plain")}>
            .log
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() =>
              download(`scan-${active}.jsonl`, `${visible.map((l) => JSON.stringify(l)).join("\n")}\n`, "application/jsonl")
            }
          >
            .jsonl
          </Button>
        </span>
      </div>

      {regexError && <p className="mb-2 text-sm text-muted">{regexError}</p>}
      {history.data && (
        <p className="mb-2 text-xs text-muted">
          {history.data.granularity} · server-side redaction {history.data.redacted ? "on" : "off"} · client redaction on
        </p>
      )}

      {paused && buffered.length > 0 && (
        <button
          className="label-m mb-3 border border-warning px-3 py-1.5 text-[11px] text-warning"
          onClick={resume}
        >
          {buffered.length} new line{buffered.length === 1 ? "" : "s"} — resume to view
        </button>
      )}

      {history.isLoading ? (
        <p className="text-body">{en.common.loading}</p>
      ) : history.isError ? (
        <EmptyState
          title="Logs unavailable"
          body={history.error instanceof Error ? history.error.message : en.common.emptyBody}
          actionLabel={en.common.retry}
          onAction={() => history.refetch()}
        />
      ) : visible.length === 0 ? (
        <EmptyState title="No log lines" body="Adjust the level, source, or search filters." />
      ) : (
        <div className={`card ${wrap ? "" : "overflow-x-auto"}`}>
          {visible.map((line) => (
            <LogRow key={line.seq} line={line} highlight={highlightRe} wrap={wrap} />
          ))}
        </div>
      )}
    </div>
  );
}
