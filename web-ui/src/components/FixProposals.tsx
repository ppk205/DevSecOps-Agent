import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { applyFix, fetchFixes, fixDiffUrl } from "../api/client";
import type { FixProposal, FixProposalStatus } from "../api/types";
import { useStrings } from "../i18n/lang";

function chipClasses(status: FixProposalStatus): string {
  const base =
    "label-m inline-flex items-center border px-2.5 py-1 text-xs";
  if (status === "verified") return `${base} border-green-700 text-green-700`;
  if (status === "failed") return `${base} border-red-700 text-red-700`;
  return `${base} border-yellow-600 text-yellow-700`;
}

/** Status chip: green = verified, yellow = proposed|applied, red = failed. */
export function FixStatusChip({ status }: { status: FixProposalStatus }) {
  const t = useStrings();
  const label =
    status === "proposed"
      ? t.fix.status.proposed
      : status === "applied"
        ? t.fix.status.applied
        : status === "verified"
          ? t.fix.status.verified
          : t.fix.status.failed;
  return (
    <span data-testid={`fix-status-${status}`} className={chipClasses(status)}>
      {label}
    </span>
  );
}

function ProposalCard({
  runId,
  proposal,
}: {
  runId: number;
  proposal: FixProposal;
}) {
  const t = useStrings();
  const queryClient = useQueryClient();
  const [applyError, setApplyError] = useState<string | null>(null);
  const applyMutation = useMutation({
    mutationFn: () => applyFix(runId, proposal.id),
    onSuccess: () => {
      setApplyError(null);
      void queryClient.invalidateQueries({ queryKey: ["fixes", runId] });
    },
    onError: (err) => {
      setApplyError(err instanceof Error ? err.message : String(err));
    },
  });

  const actionable = proposal.status === "proposed" || proposal.status === "failed";

  return (
    <li
      data-testid={`fix-proposal-${proposal.id}`}
      className="border border-hairline p-4"
    >
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <FixStatusChip status={proposal.status} />
        <span className="font-mono text-xs text-muted">{proposal.finding_id}</span>
        {proposal.model && (
          <span className="text-xs text-muted">
            {t.fix.modelLabel}: {proposal.model}
          </span>
        )}
      </div>
      {proposal.diff ? (
        <pre className="max-h-64 overflow-auto whitespace-pre-wrap bg-canvas p-3 font-mono text-xs text-body">
          {proposal.diff}
        </pre>
      ) : null}
      {proposal.overlay_path && (
        <p className="mt-2 font-mono text-xs text-muted">{proposal.overlay_path}</p>
      )}
      {proposal.verification && (
        <p className="mt-2 text-sm text-body">
          <span className="label-m text-[11px] text-muted">{t.fix.verification}: </span>
          {proposal.verification.fixed ? "✓ " : "✕ "}
          {proposal.verification.detail}
        </p>
      )}
      {proposal.error && (
        <p className="mt-2 text-sm text-red-700">
          <span className="label-m text-[11px]">{t.fix.errorLabel}: </span>
          {proposal.error}
        </p>
      )}
      {applyError && (
        <p className="mt-2 text-sm text-red-700">
          <span className="label-m text-[11px]">{t.fix.applyFailed} </span>
          {applyError}
        </p>
      )}
      {actionable && (
        <button
          onClick={() => applyMutation.mutate()}
          disabled={applyMutation.isPending}
          className="label-m mt-3 border border-hairline px-3 py-1.5 text-[11px] text-body transition-colors hover:border-ink hover:text-ink disabled:opacity-40"
        >
          {applyMutation.isPending ? t.fix.applying : t.fix.apply}
        </button>
      )}
      {(proposal.status === "proposed" || proposal.status === "verified") && proposal.diff ? (
        <a
          data-testid={`fix-download-${proposal.id}`}
          href={fixDiffUrl(runId, proposal.id)}
          download={`proposal-${proposal.id}.diff`}
          className="label-m ml-2 mt-3 inline-block border border-hairline px-3 py-1.5 text-[11px] text-body no-underline transition-colors hover:border-ink hover:text-ink"
        >
          {t.fix.downloadDiff}
        </a>
      ) : null}
    </li>
  );
}

interface FixProposalsProps {
  runId: number;
  /** When set, only proposals for this finding are shown. */
  findingId?: string | null;
}

/**
 * Proposals view: lists each fix proposal with status chip, diff,
 * Apply button, verification detail and error text. Polls GET fixes
 * while any proposal is still proposed/applied.
 */
export function FixProposals({ runId, findingId }: FixProposalsProps) {
  const t = useStrings();
  const { data, isLoading } = useQuery({
    queryKey: ["fixes", runId],
    queryFn: () => fetchFixes(runId),
    refetchInterval: (query) => {
      const proposals = query.state.data?.proposals ?? [];
      return proposals.some((p) => p.status === "proposed" || p.status === "applied")
        ? 2000
        : false;
    },
  });

  if (isLoading) return <p className="text-body">{t.common.loading}</p>;
  const proposals = (data?.proposals ?? []).filter((p) =>
    findingId ? p.finding_id === findingId : true,
  );
  if (proposals.length === 0) {
    return <p className="text-sm text-muted">{t.fix.noProposals}</p>;
  }
  return (
    <ul className="space-y-3">
      {proposals.map((proposal) => (
        <ProposalCard key={proposal.id} runId={runId} proposal={proposal} />
      ))}
    </ul>
  );
}
