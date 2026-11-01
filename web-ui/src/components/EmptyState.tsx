import { en } from "../i18n/en";
import { Button } from "./Button";

interface EmptyStateProps {
  title?: string;
  body?: string;
  actionLabel?: string;
  onAction?: () => void;
}

export function EmptyState({ title, body, actionLabel, onAction }: EmptyStateProps) {
  return (
    <div className="card flex flex-col items-center p-12 text-center">
      <div
        aria-hidden
        className="icon-btn flex h-12 w-12 items-center justify-center border border-hairline text-muted"
      >
        ◌
      </div>
      <div className="label-m mt-6 text-sm text-ink">{title ?? en.common.emptyTitle}</div>
      <p className="mt-2 max-w-md text-sm text-body">{body ?? en.common.emptyBody}</p>
      {actionLabel && onAction && (
        <Button variant="secondary" size="sm" className="mt-6" onClick={onAction}>
          {actionLabel}
        </Button>
      )}
    </div>
  );
}
