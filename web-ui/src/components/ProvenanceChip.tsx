import type { FindingListItem, FindingProvenance } from "../api/types";

/** Resolve hunt provenance; absent means scanner-found. */
export function provenanceOf(item: Pick<FindingListItem, "provenance">): FindingProvenance {
  const value = item.provenance;
  if (value === "model" || value === "both" || value === "scanner") return value;
  return "scanner";
}

export function ProvenanceChip({ value }: { value: FindingProvenance }) {
  if (value === "model") {
    return (
      <span
        title="Found by the model hunt (scanner did not corroborate)"
        className="label-m inline-block border border-success px-1.5 py-0.5 text-[10px] text-success"
      >
        AI
      </span>
    );
  }
  if (value === "both") {
    return (
      <span
        title="Model hunt and scanner agree on this finding"
        className="label-m inline-block border border-[#8b5cf6] px-1.5 py-0.5 text-[10px] text-[#a78bfa]"
      >
        Both
      </span>
    );
  }
  return (
    <span
      title="Scanner finding (no model provenance recorded)"
      className="label-m inline-block border border-hairline px-1.5 py-0.5 text-[10px] text-muted"
    >
      Scanner
    </span>
  );
}
