interface SpecCellProps {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}

/** Label-over-value spec cell for run metadata grids. */
export function SpecCell({ label, value, mono = false }: SpecCellProps) {
  return (
    <div className="border-l-2 border-hairline pl-3">
      <div className="label-m text-[11px] text-muted">{label}</div>
      <div className={`mt-1 text-sm text-ink ${mono ? "font-mono break-all" : ""}`}>
        {value}
      </div>
    </div>
  );
}
