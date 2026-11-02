import { useStrings } from "../i18n/lang";
import { severityColor, type Severity } from "../tokens";

export function SeverityBadge({ severity }: { severity: Severity }) {
  const en = useStrings();
  const color = severityColor[severity];
  return (
    <span
      data-testid={`severity-${severity}`}
      className="label-m inline-flex items-center gap-2 border border-hairline bg-soft px-2.5 py-1 text-xs text-ink"
    >
      <span
        aria-hidden
        className="inline-block h-2 w-2"
        style={{ background: color }}
      />
      {en.severity[severity]}
    </span>
  );
}
