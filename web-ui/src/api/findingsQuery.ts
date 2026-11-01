import type { FindingListItem, FindingsQuery } from "./types";

const SEVERITY_RANK = ["critical", "high", "medium", "low", "info", "undetermined"];

function rank(severity: string): number {
  const i = SEVERITY_RANK.indexOf(severity.toLowerCase());
  return i === -1 ? SEVERITY_RANK.length : i;
}

/** Serialize a findings query to `?a=b&…` (used for the live API call). */
export function buildFindingsSearch(query: FindingsQuery): string {
  const params = new URLSearchParams();
  if (query.severities?.length) params.set("severity", query.severities.join(","));
  if (query.cwes?.length) params.set("cwe", query.cwes.join(","));
  if (query.scanners?.length) params.set("scanner", query.scanners.join(","));
  if (query.verifications?.length) params.set("verification", query.verifications.join(","));
  if (query.aiChanged !== null && query.aiChanged !== undefined) {
    params.set("ai_changed", query.aiChanged ? "true" : "false");
  }
  if (query.origin) params.set("origin", query.origin);
  if (query.q?.trim()) params.set("q", query.q.trim());
  params.set("sort", query.sort ?? "severity");
  params.set("order", query.order ?? "asc");
  params.set("page", String(query.page ?? 1));
  params.set("page_size", String(query.pageSize ?? 50));
  return `?${params.toString()}`;
}

/**
 * Client-side filter/sort/page over finding rows. The live backend applies
 * the same semantics server-side; the mock layer reuses this so both modes
 * behave identically (and it is unit-testable without a backend).
 */
export function applyFindingFilters(
  items: FindingListItem[],
  query: FindingsQuery,
): { total: number; items: FindingListItem[] } {
  const terms = (query.q ?? "").toLowerCase().split(/\s+/).filter(Boolean);
  const filtered = items.filter((item) => {
    if (query.severities?.length && !query.severities.includes(item.severity)) return false;
    if (
      query.cwes?.length &&
      !query.cwes.some((want) => {
        const cwe = item.cwe.toLowerCase();
        const w = want.toLowerCase();
        if (cwe.includes(w)) return true;
        const digits = (s: string) => s.replace(/\D/g, "");
        return digits(w) !== "" && digits(cwe).includes(digits(w));
      })
    )
      return false;
    if (
      query.scanners?.length &&
      !query.scanners.some((want) =>
        item.scanners.some((tool) => tool.toLowerCase().includes(want.toLowerCase())),
      )
    )
      return false;
    if (query.verifications?.length && !query.verifications.includes(item.status)) return false;
    if (query.aiChanged !== null && query.aiChanged !== undefined && item.ai_changed !== query.aiChanged)
      return false;
    if (query.origin && item.origin !== query.origin) return false;
    if (terms.length) {
      const blob = [item.id, item.title, item.file, item.cwe, item.status, ...item.scanners]
        .join(" ")
        .toLowerCase();
      if (!terms.every((t) => blob.includes(t))) return false;
    }
    return true;
  });

  const order = query.order === "desc" ? -1 : 1;
  const sorted = [...filtered].sort((a, b) => {
    switch (query.sort) {
      case "title":
        return a.title.localeCompare(b.title) * order;
      case "file":
        return (a.file.localeCompare(b.file) || a.line - b.line) * order;
      case "status":
        return a.status.localeCompare(b.status) * order;
      default:
        return (rank(a.severity) - rank(b.severity) || a.title.localeCompare(b.title)) * order;
    }
  });

  const page = Math.max(1, query.page ?? 1);
  const pageSize = query.pageSize ?? 50;
  return { total: sorted.length, items: sorted.slice((page - 1) * pageSize, page * pageSize) };
}

/** Download the currently filtered set as CSV (mock and live modes share this). */
export function findingsToCsv(items: FindingListItem[]): string {
  const cell = (value: string | number | boolean | null): string => {
    const text = value === null ? "" : String(value);
    return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  };
  const header = "id,title,severity,scanner_severity,ai_severity,ai_changed,cwe,status,scanners,file,line,origin";
  const rows = items.map((i) =>
    [
      i.id,
      i.title,
      i.severity,
      i.scanner_severity,
      i.ai_severity,
      i.ai_changed,
      i.cwe,
      i.status,
      i.scanners.join("|"),
      i.file,
      i.line,
      i.origin,
    ]
      .map(cell)
      .join(","),
  );
  return [header, ...rows].join("\n");
}

export function downloadCsv(filename: string, csv: string): void {
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
