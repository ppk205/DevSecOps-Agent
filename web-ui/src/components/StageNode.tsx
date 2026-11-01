import { tokens } from "../tokens";

export type StageStatus = "pending" | "running" | "completed" | "failed" | "skipped";

const DOT: Record<StageStatus, string> = {
  pending: tokens.color.hairline,
  running: tokens.color.mBlueDark,
  completed: tokens.color.success,
  failed: tokens.color.mRed,
  skipped: tokens.color.muted,
};

interface StageNodeProps {
  name: string;
  status: StageStatus;
  last?: boolean;
}

/** One node of the pipeline rail: status dot, label, connector. */
export function StageNode({ name, status, last = false }: StageNodeProps) {
  return (
    <div className="flex flex-1 items-center" data-testid={`stage-${name}`}>
      <div className="flex items-center gap-3">
        <span
          aria-hidden
          className="inline-block h-3 w-3"
          style={{
            background: status === "completed" ? DOT[status] : "transparent",
            border: `2px solid ${DOT[status]}`,
          }}
        />
        <div>
          <div className="label-m text-xs text-ink">{name}</div>
          <div className="text-xs uppercase tracking-widest text-muted">{status}</div>
        </div>
      </div>
      {!last && <div aria-hidden className="mx-4 h-px flex-1 bg-hairline" />}
    </div>
  );
}
