import { verificationColor, type VerificationState } from "../tokens";

const LABEL: Record<VerificationState, string> = {
  confirmed: "Confirmed",
  unresolved: "Unresolved",
  rejected: "Rejected",
  unprocessed: "Unprocessed",
};

export function VerificationBadge({ state }: { state: VerificationState }) {
  const color = verificationColor[state];
  return (
    <span
      data-testid={`verification-${state}`}
      className="label-m inline-flex items-center gap-2 border border-hairline bg-soft px-2.5 py-1 text-xs"
      style={{ color }}
    >
      <span
        aria-hidden
        className="inline-block h-2 w-2 rounded-full"
        style={{ border: `2px solid ${color}` }}
      />
      {LABEL[state]}
    </span>
  );
}
