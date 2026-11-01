import { severityColor, type Severity } from "../tokens";

const LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  const color = severityColor[severity];
  return (
    <span
      data-testid={`severity-${severity}`}
      className="label-m inline-flex items-center gap-2 border border-hairline bg-soft px-2.5 py-1 text-xs"
      style={{ color }}
    >
      <span
        aria-hidden
        className="inline-block h-2 w-2"
        style={{ background: color }}
      />
      {LABEL[severity]}
    </span>
  );
}
