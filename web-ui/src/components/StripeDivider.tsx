interface StripeDividerProps {
  /** Tỷ lệ 0..1 của thanh M-gradient hiển thị đã hoàn thành. Bỏ qua để có sọc đơn thuần. */
  progress?: number;
}

/** Đường phân chia dải sọc M 4px; với `progress`, là thanh hoàn thành theo dõi đường mảnh. */
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
