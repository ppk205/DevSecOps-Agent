import { describe, expect, it } from "vitest";
import {
  applyFindingFilters,
  buildFindingsSearch,
  findingsToCsv,
} from "../findingsQuery";
import type { FindingListItem } from "../types";

function row(partial: Partial<FindingListItem> & { id: string }): FindingListItem {
  return {
    title: `Title ${partial.id}`,
    severity: "medium",
    scanner_severity: "medium",
    ai_severity: null,
    ai_changed: false,
    cwe: "CWE-79",
    status: "unprocessed",
    scanners: ["semgrep"],
    model_corroborated: false,
    file: "src/App.java",
    line: 10,
    origin: "source",
    ...partial,
  };
}

const ITEMS: FindingListItem[] = [
  row({ id: "F-1", severity: "critical", status: "confirmed", ai_changed: true, ai_severity: "critical" }),
  row({ id: "F-2", severity: "high", cwe: "CWE-89", scanners: ["spotbugs"], file: "Dao.java" }),
  row({
    id: "F-3",
    severity: "low",
    cwe: "CWE-1104",
    origin: "dependency",
    scanners: ["owasp-dependency-check"],
    file: "pom.xml",
  }),
];

describe("applyFindingFilters", () => {
  it("filters by severity set", () => {
    const { total, items } = applyFindingFilters(ITEMS, { severities: ["critical"] });
    expect(total).toBe(1);
    expect(items[0].id).toBe("F-1");
  });

  it("filters by CWE digits and scanner substring", () => {
    expect(applyFindingFilters(ITEMS, { cwes: ["89"] }).items.map((i) => i.id)).toEqual(["F-2"]);
    expect(applyFindingFilters(ITEMS, { scanners: ["spot"] }).items.map((i) => i.id)).toEqual(["F-2"]);
  });

  it("filters by origin and ai_changed", () => {
    expect(applyFindingFilters(ITEMS, { origin: "dependency" }).items.map((i) => i.id)).toEqual(["F-3"]);
    expect(applyFindingFilters(ITEMS, { aiChanged: true }).items.map((i) => i.id)).toEqual(["F-1"]);
    expect(applyFindingFilters(ITEMS, { aiChanged: false }).total).toBe(2);
  });

  it("matches free-text query across fields", () => {
    expect(applyFindingFilters(ITEMS, { q: "dao.java" }).items.map((i) => i.id)).toEqual(["F-2"]);
    expect(applyFindingFilters(ITEMS, { q: "F-3 pom" }).items.map((i) => i.id)).toEqual(["F-3"]);
  });

  it("sorts by severity rank then paginates", () => {
    const { total, items } = applyFindingFilters(ITEMS, { sort: "severity", page: 2, pageSize: 2 });
    expect(total).toBe(3);
    expect(items.map((i) => i.id)).toEqual(["F-3"]);
  });

  it("sorts by title descending", () => {
    const { items } = applyFindingFilters(ITEMS, { sort: "title", order: "desc" });
    expect(items[0].id).toBe("F-3");
  });
});

describe("buildFindingsSearch", () => {
  it("serializes the query for the live API", () => {
    const search = buildFindingsSearch({
      severities: ["critical", "high"],
      origin: "source",
      aiChanged: true,
      q: "sql",
      sort: "file",
      order: "desc",
      page: 2,
      pageSize: 20,
    });
    expect(search).toContain("severity=critical%2Chigh");
    expect(search).toContain("origin=source");
    expect(search).toContain("ai_changed=true");
    expect(search).toContain("sort=file");
    expect(search).toContain("page=2");
  });
});

describe("findingsToCsv", () => {
  it("emits a header plus one row per finding", () => {
    const csv = findingsToCsv(ITEMS);
    const lines = csv.split("\n");
    expect(lines[0]).toBe(
      "id,title,severity,scanner_severity,ai_severity,ai_changed,cwe,status,scanners,file,line,origin",
    );
    expect(lines).toHaveLength(4);
    expect(lines[1]).toContain("F-1");
  });
});
