import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { fetchFindingDetail } from "../api/client";
import { en } from "../i18n/en";
import { Drawer } from "./Drawer";
import { FindingDetailView } from "./FindingDetailView";

interface FindingDrawerProps {
  findingId: string | null;
  runId: number;
  onClose: () => void;
  onPrev: () => void;
  onNext: () => void;
  hasPrev: boolean;
  hasNext: boolean;
}

/** Evidence drawer: header badges, viewers, Esc/J/K navigation, V raw JSON. */
export function FindingDrawer({
  findingId,
  runId,
  onClose,
  onPrev,
  onNext,
  hasPrev,
  hasNext,
}: FindingDrawerProps) {
  const [showRaw, setShowRaw] = useState(false);
  const { data: detail, isLoading } = useQuery({
    queryKey: ["finding", runId, findingId],
    queryFn: () => fetchFindingDetail(findingId ?? "", runId),
    enabled: findingId !== null,
  });

  useEffect(() => {
    setShowRaw(false);
  }, [findingId]);

  const toggleRaw = useCallback(() => setShowRaw((v) => !v), []);

  useEffect(() => {
    if (findingId === null) return;
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      if (target && (target.tagName === "INPUT" || target.tagName === "SELECT" || target.tagName === "TEXTAREA")) {
        return;
      }
      if (e.key === "j" || e.key === "J") {
        e.preventDefault();
        onNext();
      } else if (e.key === "k" || e.key === "K") {
        e.preventDefault();
        onPrev();
      } else if (e.key === "v" || e.key === "V") {
        e.preventDefault();
        toggleRaw();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [findingId, onNext, onPrev, toggleRaw]);

  return (
    <Drawer open={findingId !== null} title={findingId ?? ""} onClose={onClose}>
      {isLoading || !detail ? (
        <p className="text-body">{en.common.loading}</p>
      ) : (
        <div>
          <div className="mb-4 flex items-center justify-between">
            <div className="flex gap-2">
              <button
                onClick={onPrev}
                disabled={!hasPrev}
                className="label-m border border-hairline px-2 py-1 text-[11px] text-muted transition-colors hover:text-ink disabled:opacity-40"
              >
                ← {en.findingDetail.previous} (K)
              </button>
              <button
                onClick={onNext}
                disabled={!hasNext}
                className="label-m border border-hairline px-2 py-1 text-[11px] text-muted transition-colors hover:text-ink disabled:opacity-40"
              >
                {en.findingDetail.next} (J) →
              </button>
            </div>
            <Link
              to={`/findings/${findingId}`}
              className="label-m text-[11px] text-muted no-underline transition-colors hover:text-ink"
            >
              Full page →
            </Link>
          </div>
          <FindingDetailView detail={detail} showRaw={showRaw} onToggleRaw={toggleRaw} />
        </div>
      )}
    </Drawer>
  );
}
