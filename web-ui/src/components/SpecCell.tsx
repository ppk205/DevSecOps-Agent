interface SpecCellProps {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}

/** Ô thông số với nhãn nằm trên giá trị cho lưới metadata của lượt chạy. */
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
