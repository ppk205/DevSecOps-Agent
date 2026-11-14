import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { fetchFindingDetail } from "../api/client";
import { FindingDetailView } from "../components/FindingDetailView";
import { useStrings } from "../i18n/lang";

/** Trang đầy đủ có thể deep-link cho một finding (drawer là chế độ xem nhanh). */
export function FindingDetailPage() {
  const en = useStrings();
  const { id } = useParams<{ id: string }>();
  const [showRaw, setShowRaw] = useState(false);
  const { data: detail, isLoading } = useQuery({
    queryKey: ["finding", "page", id],
    queryFn: () => fetchFindingDetail(id ?? ""),
    enabled: Boolean(id),
  });

  return (
    <div className="mx-auto max-w-4xl">
      <Link
        to="/findings"
        className="label-m mb-6 inline-block text-xs text-muted no-underline transition-colors hover:text-ink"
      >
        ← {en.findings.title}
      </Link>
      {isLoading || !detail ? (
        <p className="text-body">{en.common.loading}</p>
      ) : (
        <FindingDetailView detail={detail} showRaw={showRaw} onToggleRaw={() => setShowRaw((v) => !v)} />
      )}
    </div>
  );
}
