import { describe, expect, it } from "vitest";
import { MOCK_FINDING_ITEMS, mockFilteredFindings, mockFindingDetail } from "../mockFindingDetails";

describe("mock finding details (Phase 4)", () => {
  it("enriches all 60 scripted findings", () => {
    expect(MOCK_FINDING_ITEMS).toHaveLength(60);
    expect(MOCK_FINDING_ITEMS[0]).toMatchObject({ origin: expect.any(String) });
    expect(MOCK_FINDING_ITEMS.some((f) => f.origin === "dependency")).toBe(true);
    expect(MOCK_FINDING_ITEMS.some((f) => f.ai_changed)).toBe(true);
  });

  it("filters like the live endpoint", () => {
    const dep = mockFilteredFindings(7, { origin: "dependency" });
    expect(dep.total).toBeGreaterThan(0);
    expect(dep.items.every((i) => i.origin === "dependency")).toBe(true);
  });

  it("returns a full detail payload", () => {
    const detail = mockFindingDetail(MOCK_FINDING_ITEMS[0].id);
    expect(detail).toBeDefined();
    expect(detail!.code.blocks.length).toBeGreaterThan(0);
    expect(detail!.code.taint_path.length).toBeGreaterThan(0);
    expect(detail!.observations.length).toBeGreaterThan(0);
    expect(detail!.verification.checks.length).toBeGreaterThan(0);
  });

  it("returns undefined for an unknown id", () => {
    expect(mockFindingDetail("nope")).toBeUndefined();
  });
});
