import { describe, expect, it } from "vitest";
import { MOCK_FINDINGS, MOCK_SCANS, mockCounts } from "../mockRun";

describe("mock run", () => {
  it("scripts ~60 findings", () => {
    expect(MOCK_FINDINGS.length).toBe(60);
    expect(new Set(MOCK_FINDINGS.map((f) => f.id)).size).toBe(60);
  });

  it("matches the severity plan 4/14/22/14/6", () => {
    const tally = (sev: string) => MOCK_FINDINGS.filter((f) => f.severity === sev).length;
    expect(tally("critical")).toBe(4);
    expect(tally("high")).toBe(14);
    expect(tally("medium")).toBe(22);
    expect(tally("low")).toBe(14);
    expect(tally("info")).toBe(6);
  });

  it("counts agree with the scan summary", () => {
    expect(mockCounts(MOCK_FINDINGS)).toEqual(MOCK_SCANS[0].counts);
  });
});
