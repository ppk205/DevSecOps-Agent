import { describe, expect, it } from "vitest";
import {
  aggregateNodeStatuses,
  mapRawStage,
  nodeMessage,
  railProgress,
} from "../liveStages";
import type { StageSummary } from "../../api/types";

function stage(name: string, status: string, message = ""): StageSummary {
  return { name, status: status as StageSummary["status"], ordinal: 0, message, started_at: null, completed_at: null };
}

describe("liveStages mapping", () => {
  it("folds per-tool and legacy names onto the 8 nodes", () => {
    expect(mapRawStage("semgrep")).toBe("scanners");
    expect(mapRawStage("owasp-dependency-check")).toBe("scanners");
    expect(mapRawStage("model_scanner_compare")).toBe("laya_verification");
    expect(mapRawStage("scan")).toBe("scanners");
    expect(mapRawStage("unknown-tool")).toBe("scanners");
  });

  it("aggregates worst-status-wins per node", () => {
    const statuses = aggregateNodeStatuses([
      stage("semgrep", "completed"),
      stage("gitleaks", "running"),
      stage("intake", "completed"),
    ]);
    expect(statuses.scanners).toBe("running");
    expect(statuses.intake).toBe("completed");
    expect(statuses.final_report).toBe("pending");
  });

  it("surfaces partial (yellow) instead of collapsing to pending", () => {
    const statuses = aggregateNodeStatuses([
      stage("targeted_deep_analysis", "partial"),
      stage("independent_validation", "completed"),
    ]);
    expect(statuses.targeted_deep_analysis).toBe("partial");
    expect(statuses.independent_validation).toBe("completed");
  });

  it("prefers the running message for node detail", () => {
    const message = nodeMessage("scanners", [
      stage("semgrep", "completed", "semgrep ok"),
      stage("gitleaks", "running", "gitleaks scanning"),
    ]);
    expect(message).toBe("gitleaks scanning");
  });

  it("computes rail progress with running counting half", () => {
    const statuses = aggregateNodeStatuses([stage("intake", "completed")]);
    const progress = railProgress(statuses);
    expect(progress).toBeCloseTo(1 / 8, 5);
  });
});
