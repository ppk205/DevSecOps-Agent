import { severityColor, type Severity } from "../../tokens";

export interface BarDatum {
  label: string;
  value: number;
  severity: Severity;
}

/** Hand-drawn SVG bar strip — e.g. findings per severity. No chart library. */
export function SeverityBars({ data }: { data: BarDatum[] }) {
  const max = Math.max(...data.map((d) => d.value), 1);
  const barH = 26;
  const gap = 10;
  const height = data.length * (barH + gap);
  const width = 420;
  // Long labels (e.g. CWE-UNCLASSIFIED) overflowed the fixed 110px gutter
  // and the bar painted over the tail. Size the gutter from the longest label.
  const labelW = Math.min(
    210,
    Math.max(110, ...data.map((d) => d.label.length * 7 + 16)),
  );
  const barMax = width - labelW - 44;

  return (
    <svg
      width="100%"
      viewBox={`0 0 ${width} ${height}`}
      role="img"
      aria-label="Findings per severity"
      preserveAspectRatio="xMidYMid meet"
    >
      {data.map((d, i) => {
        const w = Math.max(2, (d.value / max) * barMax);
        const y = i * (barH + gap);
        return (
          <g key={d.label}>
            <text x="0" y={y + 17} fill="#7e7e7e" fontSize="11" letterSpacing="1.5">
              {d.label.toUpperCase()}
            </text>
            <rect x={labelW} y={y} width={w} height={barH} fill={severityColor[d.severity]} opacity="0.85" />
            <text x={labelW + 6 + w} y={y + 17} fill="#bbbbbb" fontSize="12">
              {d.value}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
