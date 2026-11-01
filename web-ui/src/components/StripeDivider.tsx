interface StripeDividerProps {
  /** 0..1 fraction of the M-gradient rail shown as complete. Omit for a plain stripe. */
  progress?: number;
}

/** 4px M-stripe divider; with `progress`, a hairline-tracked completion rail. */
export function StripeDivider({ progress }: StripeDividerProps) {
  if (progress === undefined) {
    return <div aria-hidden className="stripe-m w-full" />;
  }
  const pct = Math.max(0, Math.min(1, progress)) * 100;
  return (
    <div aria-hidden className="relative h-1 w-full bg-hairline">
      <div
        className="stripe-m absolute inset-y-0 left-0"
        style={{ width: `${pct}%` }}
      />
    </div>
  );
}
