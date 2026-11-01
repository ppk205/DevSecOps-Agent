import type { Counts } from "../../api/types";
import { tokens } from "../../tokens";

/** Hand-drawn SVG donut — severity mix. No chart library. */
export function SeverityDonut({ counts, size = 180 }: { counts: Counts; size?: number }) {
  const segments: { value: number; color: string; label: string }[] = [
    { value: counts.confirmed, color: tokens.color.mRed, label: "confirmed" },
    { value: counts.unresolved, color: tokens.color.warning, label: "unresolved" },
    { value: counts.rejected, color: tokens.color.muted, label: "rejected" },
    { value: counts.unprocessed, color: tokens.color.mBlueDark, label: "unprocessed" },
  ];
  const total = segments.reduce((a, s) => a + s.value, 0) || 1;
  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;

  return (
    <figure className="flex items-center gap-6">
      <svg
        width={size}
        height={size}
        viewBox="0 0 180 180"
        role="img"
        aria-label={`Findings by verification state, ${counts.total} total`}
      >
        <circle cx="90" cy="90" r={radius} fill="none" stroke={tokens.color.hairline} strokeWidth="22" />
        {segments.map((seg) => {
          const frac = seg.value / total;
          const el = (
            <circle
              key={seg.label}
              cx="90"
              cy="90"
              r={radius}
              fill="none"
              stroke={seg.color}
              strokeWidth="22"
              strokeDasharray={`${frac * circumference} ${circumference}`}
              strokeDashoffset={-offset * circumference}
              transform="rotate(-90 90 90)"
            />
          );
          offset += frac;
          return el;
        })}
        <text x="90" y="86" textAnchor="middle" fill={tokens.color.ink} fontSize="30" fontWeight="700">
          {counts.total}
        </text>
        <text x="90" y="106" textAnchor="middle" fill={tokens.color.muted} fontSize="11" letterSpacing="1.5">
          FINDINGS
        </text>
      </svg>
      <figcaption className="space-y-2">
        {segments.map((seg) => (
          <div key={seg.label} className="flex items-center gap-2 text-xs uppercase tracking-widest text-body">
            <span aria-hidden className="inline-block h-2 w-2" style={{ background: seg.color }} />
            {seg.label} · {seg.value}
          </div>
        ))}
      </figcaption>
    </figure>
  );
}
