import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ackNotification, fetchNotifications } from "../api/client";
import { useStrings } from "../i18n/lang";

/**
 * Task 4: chuông ở header với poll số lượng chưa đọc + panel dropdown có xác nhận (ack).
 * Poll GET /api/notifications mỗi 15 giây; ack sử dụng đường dẫn CSRF postJson.
 * Panel được định vị tuyệt đối bên trong wrapper tương đối này; chính navbar
 * phải duy trì overflow-visible để việc mở chuông không bao giờ tạo
 * thanh cuộn trên navbar. Đóng khi nhấp bên ngoài / Escape.
 */
export function NotificationsBell() {
  const t = useStrings();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: PointerEvent) => {
      if (rootRef.current && !rootRef.current.contains(event.target as Node)) {
        setOpen(false);
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);
  const { data } = useQuery({
    queryKey: ["notifications"],
    queryFn: fetchNotifications,
    refetchInterval: 15000,
  });
  const ackMutation = useMutation({
    mutationFn: (id: number) => ackNotification(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["notifications"] });
    },
  });

  const notifications = data?.notifications ?? [];
  const unread = data?.unread ?? 0;

  return (
    <div ref={rootRef} className="relative">
      <button
        type="button"
        data-testid="notifications-bell"
        aria-label={t.notifications.title}
        aria-expanded={open}
        onClick={() => setOpen((value) => !value)}
        className="label-m relative inline-flex h-8 w-8 items-center justify-center text-base leading-none text-muted transition-colors duration-150 ease-out hover:text-body"
      >
        <span aria-hidden className="leading-none">🔔</span>
        {unread > 0 && (
          <span
            data-testid="notifications-unread"
            className="absolute right-0 top-0 border border-hairline bg-elevated px-1 text-[10px] leading-tight text-ink"
          >
            {unread}
          </span>
        )}
      </button>
      {open && (
        <div
          data-testid="notifications-panel"
          className="absolute right-0 z-50 mt-2 w-80 border border-hairline bg-elevated p-3 shadow-lg"
        >
          <p className="label-m mb-2 text-[11px] text-muted">{t.notifications.title}</p>
          {notifications.length === 0 ? (
            <p data-testid="notifications-empty" className="text-sm text-muted">
              {t.notifications.empty}
            </p>
          ) : (
            <ul className="max-h-64 space-y-2 overflow-auto">
              {notifications.map((notification) => (
                <li
                  key={notification.id}
                  data-testid={`notification-${notification.id}`}
                  className="border border-hairline p-2"
                >
                  <p className="text-sm text-body">{notification.message}</p>
                  <div className="mt-1 flex items-center justify-between">
                    <span className="font-mono text-xs text-muted">
                      #{notification.run_id} · {notification.kind}
                    </span>
                    {!notification.is_read && (
                      <button
                        type="button"
                        data-testid={`notification-ack-${notification.id}`}
                        onClick={() => ackMutation.mutate(notification.id)}
                        disabled={ackMutation.isPending}
                        className="label-m border border-hairline px-2 py-1 text-[10px] text-body transition-colors hover:border-ink hover:text-ink disabled:opacity-40"
                      >
                        {t.notifications.markRead}
                      </button>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
