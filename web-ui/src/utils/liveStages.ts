import type { StageSummary } from "../api/types";

/** The 8 canonical live-pipeline nodes (Phase 3 rail). */
export interface LiveNode {
  key: string;
  label: string;
  hint: string;
}

export const LIVE_NODES: LiveNode[] = [
  { key: "intake", label: "Intake", hint: "Pin commit, freeze snapshot" },
  { key: "model_hunt", label: "Model hunt", hint: "Agentic candidate sweep" },
  { key: "scanners", label: "Scanners", hint: "Semgrep · Gitleaks · SpotBugs · ODC" },
  { key: "laya_batch_routing", label: "Batch routing", hint: "Route findings to the advisory model" },
  { key: "laya_verification", label: "Verification", hint: "Laya checks vs the build" },
  { key: "targeted_deep_analysis", label: "Deep analysis", hint: "Targeted AI review + CVSS" },
  { key: "independent_validation", label: "Validation", hint: "Independent confirm / reject" },
  { key: "final_report", label: "Report", hint: "Gate + evidence bundle" },
];

/** Raw pipeline stage names produced by ScanService (incl. legacy + per-tool). */
const RAW_TO_NODE: Record<string, string> = {
  intake: "intake",
  model_hunt: "model_hunt",
  semgrep: "scanners",
  gitleaks: "scanners",
  spotbugs: "scanners",
  "owasp-dependency-check": "scanners",
  scanners: "scanners",
  scan: "scanners",
  hunt: "model_hunt",
  laya_batch_routing: "laya_batch_routing",
  laya_verification: "laya_verification",
  model_scanner_compare: "laya_verification",
  validate: "laya_verification",
  targeted_deep_analysis: "targeted_deep_analysis",
  independent_validation: "independent_validation",
  final_report: "final_report",
  report: "final_report",
  execution: "final_report",
};

/** Fold a raw ScanService stage name onto one of the 8 rail nodes. */
export function mapRawStage(raw: string): string {
  return RAW_TO_NODE[raw] ?? "scanners";
}

export type NodeStatus = "pending" | "running" | "completed" | "failed" | "skipped" | "partial";

/** Aggregate raw stage rows onto the 8 nodes: worst-status-wins. */
export function aggregateNodeStatuses(stages: StageSummary[]): Record<string, NodeStatus> {
  const rank: Record<NodeStatus, number> = {
    failed: 0,
    running: 1,
    partial: 2,
    pending: 3,
    skipped: 4,
    completed: 5,
  };
  const out: Record<string, NodeStatus> = {};
  for (const node of LIVE_NODES) out[node.key] = "pending";
  const buckets = new Map<string, StageSummary[]>();
  for (const stage of stages) {
    const node = mapRawStage(stage.name);
    const list = buckets.get(node) ?? [];
    list.push(stage);
    buckets.set(node, list);
  }
  for (const [node, list] of buckets) {
    let best: NodeStatus = "completed";
    let bestRank = 99;
    for (const stage of list) {
      const raw = String(stage.status ?? "pending");
      const candidate: NodeStatus =
        raw === "queued" ? "pending"
        : raw === "cancelled" ? "skipped"
        : (Object.keys(rank) as NodeStatus[]).includes(raw as NodeStatus) ? (raw as NodeStatus) : "pending";
      if (rank[candidate] < bestRank) {
        bestRank = rank[candidate];
        best = candidate;
      }
    }
    out[node] = best;
  }
  return out;
}

/** Latest message across the raw stages folded into a node (for detail). */
export function nodeMessage(nodeKey: string, stages: StageSummary[]): string {
  const relevant = stages.filter((s) => mapRawStage(s.name) === nodeKey && s.message);
  if (relevant.length === 0) return "";
  const running = relevant.find((s) => s.status === "running");
  return (running ?? relevant[relevant.length - 1]).message;
}

/** Rail progress 0..1 across the 8 nodes (completed counts, running/partial half). */
export function railProgress(statuses: Record<string, NodeStatus>): number {
  let score = 0;
  for (const node of LIVE_NODES) {
    const status = statuses[node.key];
    if (status === "completed") score += 1;
    else if (status === "running" || status === "partial") score += 0.5;
    else if (status === "failed") score += 0.75;
  }
  return score / LIVE_NODES.length;
}
