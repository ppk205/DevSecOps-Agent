import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { fetchFindingDetail, requestFix } from "../api/client";
import { useStrings } from "../i18n/lang";
import { Drawer } from "./Drawer";
import { FindingDetailView } from "./FindingDetailView";
import { FixProposals } from "./FixProposals";

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
  const en = useStrings();
  const [showRaw, setShowRaw] = useState(false);
  const [fixFeedback, setFixFeedback] = useState<string | null>(null);
  const [allowCloudFix, setAllowCloudFix] = useState(false);
  const queryClient = useQueryClient();
  const { data: detail, isLoading } = useQuery({
    queryKey: ["finding", runId, findingId],
    queryFn: () => fetchFindingDetail(findingId ?? "", runId),
    enabled: findingId !== null,
  });

  const fixMutation = useMutation({
    mutationFn: () =>
      requestFix(runId, {
        finding_ids: findingId ? [findingId] : null,
        ...(allowCloudFix ? { allow_cloud_model: true } : {}),
      }),
    onSuccess: () => {
      setFixFeedback(en.fix.requested);
      void queryClient.invalidateQueries({ queryKey: ["fixes", runId] });
    },
    onError: (err) => {
      setFixFeedback(
        `${en.fix.requestFailed} ${err instanceof Error ? err.message : String(err)}`,
      );
    },
    onSettled: () => setAllowCloudFix(false),
  });

  useEffect(() => {
    setShowRaw(false);
    setFixFeedback(null);
    setAllowCloudFix(false);
  }, [findingId, runId]);

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
          <div className="mb-4 flex flex-wrap items-center gap-2">
            <label className="flex items-center gap-2 text-xs text-muted">
              <input
                type="checkbox"
                checked={allowCloudFix}
                disabled={fixMutation.isPending}
                onChange={(event) => setAllowCloudFix(event.target.checked)}
              />
              {en.fix.allowCloud}
            </label>
            <button
              onClick={() => fixMutation.mutate()}
              disabled={fixMutation.isPending}
              className="label-m border border-hairline px-3 py-1.5 text-[11px] text-body transition-colors hover:border-ink hover:text-ink disabled:opacity-40"
            >
              {fixMutation.isPending ? en.fix.proposing : en.fix.proposeFix}
            </button>
            {fixFeedback && <span className="text-xs text-muted">{fixFeedback}</span>}
          </div>
          <FindingDetailView detail={detail} showRaw={showRaw} onToggleRaw={toggleRaw} />
          <section aria-label={en.fix.proposals} className="card mt-4 p-5">
            <div className="label-m mb-3 text-xs text-ink">{en.fix.proposals}</div>
            <FixProposals runId={runId} findingId={findingId} />
          </section>
        </div>
      )}
    </Drawer>
  );
}
