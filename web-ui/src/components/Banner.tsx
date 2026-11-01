import { tokens } from "../tokens";

type BannerTone = "info" | "warn" | "error" | "success";

const ACCENT: Record<BannerTone, string> = {
  info: tokens.color.mBlueDark,
  warn: tokens.color.warning,
  error: tokens.color.mRed,
  success: tokens.color.success,
};

interface BannerProps {
  tone?: BannerTone;
  title: string;
  children?: React.ReactNode;
}

export function Banner({ tone = "info", title, children }: BannerProps) {
  return (
    <div
      role={tone === "error" ? "alert" : "status"}
      className="card border-l-4 p-4"
      style={{ borderLeftColor: ACCENT[tone] }}
    >
      <div className="label-m text-xs text-ink">{title}</div>
      {children && <div className="mt-1 text-sm text-body">{children}</div>}
    </div>
  );
}
