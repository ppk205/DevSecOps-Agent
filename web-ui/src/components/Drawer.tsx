import { useEffect } from "react";
import { en } from "../i18n/en";

interface DrawerProps {
  open: boolean;
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}

/** Right slide-over evidence drawer. Escape closes; content scrolls. */
export function Drawer({ open, title, onClose, children }: DrawerProps) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50" role="dialog" aria-modal="true" aria-label={title}>
      <button
        aria-label={en.common.close}
        onClick={onClose}
        className="absolute inset-0 h-full w-full cursor-default bg-black/70"
      />
      <aside className="absolute right-0 top-0 flex h-full w-full max-w-xl flex-col border-l border-hairline bg-soft">
        <div className="flex items-center justify-between border-b border-hairline p-5">
          <div className="label-m text-sm text-ink">{title}</div>
          <button
            onClick={onClose}
            aria-label={en.common.close}
            className="label-m text-xs text-muted transition-colors duration-150 hover:text-ink"
          >
            ✕ {en.common.close}
          </button>
        </div>
        <div className="stripe-m" aria-hidden />
        <div className="flex-1 overflow-y-auto p-5">{children}</div>
      </aside>
    </div>
  );
}
