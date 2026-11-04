import type { LiveAssessment } from "../api/types";

/** Calculation is separate from source-evidence validation. */
export function CvssSummary({ cvss }: { cvss: NonNullable<LiveAssessment["cvss"]> }) {
  const computed = cvss.calculation_source === "FIRST CVSS v4.0";
  return <span className="break-words">
    <code className="break-all">{cvss.vector}</code>
    {typeof cvss.base_score === "number"
      ? <span className="ml-2 text-muted">Base: {cvss.base_score}</span>
      : <span className="ml-2 text-muted">Unscored</span>}
    {typeof cvss.overall_score === "number" && cvss.nomenclature && cvss.nomenclature !== "CVSS-B" &&
      <span className="ml-2 text-muted">{cvss.nomenclature}: {cvss.overall_score}</span>}
    <span className="mt-1 block text-xs text-muted">
      {computed ? "Score calculation does not verify metric assumptions." : "Legacy score; calculation source unavailable."}
    </span>
  </span>;
}
