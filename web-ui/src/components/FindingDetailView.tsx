import type { FindingDetail } from "../api/types";
import { useStrings } from "../i18n/lang";
import type { VerificationState } from "../tokens";
import { CodeViewer } from "./CodeViewer";
import { SeverityBadge } from "./SeverityBadge";
import { VerificationBadge } from "./VerificationBadge";

const KNOWN_STATES: readonly string[] = ["confirmed", "unresolved", "rejected", "unprocessed"];

export function isVerificationState(value: string): value is VerificationState {
  return (KNOWN_STATES as readonly string[]).includes(value);
}

export function StatusBadge({ status }: { status: string }) {
  if (isVerificationState(status)) return <VerificationBadge state={status} />;
  return (
    <span className="label-m inline-flex items-center border border-hairline bg-soft px-2.5 py-1 text-xs text-body">
      {status}
    </span>
  );
}

interface FindingDetailViewProps {
  detail: FindingDetail;
  showRaw: boolean;
  onToggleRaw: () => void;
}

/** Shared finding detail body: drawer and /findings/:id render this. */
export function FindingDetailView({ detail, showRaw, onToggleRaw }: FindingDetailViewProps) {
  const en = useStrings();
  return (
    <div>
      <header className="mb-6">
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <SeverityBadge severity={detail.severity} />
          <StatusBadge status={detail.status} />
          <span className="label-m border border-hairline px-2 py-1 font-mono text-[11px] text-body">
            {detail.cwe}
          </span>
          <span className="label-m border border-hairline px-2 py-1 text-[11px] text-muted">
            {detail.origin}
          </span>
        </div>
        <h2 className="display-4">{detail.title}</h2>
        <p className="mt-2 font-mono text-xs text-muted">
          {detail.id} · {detail.file}:{detail.line} · {detail.scanners.join(", ")}
        </p>
        {detail.description && <p className="mt-3 text-sm text-body">{detail.description}</p>}
      </header>

      <section aria-label={en.findingDetail.assessment} className="card mb-4 p-5">
        <div className="label-m mb-3 text-xs text-ink">{en.findingDetail.assessment}</div>
        {detail.ai ? (
          <dl className="grid gap-3 text-sm">
            <div className="flex gap-2">
              <dt className="label-m w-28 shrink-0 text-[11px] text-muted">{en.findingDetail.aiSeverity}</dt>
              <dd className="text-ink">
                {detail.scanner_severity} → {detail.ai.proposed_severity ?? "—"}
                {detail.ai_changed && <span className="ml-2 text-warning">(changed)</span>}
              </dd>
            </div>
            {detail.ai.cvss && (
              <div className="flex gap-2">
                <dt className="label-m w-28 shrink-0 text-[11px] text-muted">{en.findingDetail.cvss}</dt>
                <dd className="font-mono text-xs text-body">
                  {detail.ai.cvss.vector}
                  {detail.ai.cvss.base_score !== null && (
                    <span className="ml-2 text-muted">score {detail.ai.cvss.base_score}</span>
                  )}
                </dd>
              </div>
            )}
            {detail.ai.confidence !== null && (
              <div className="flex gap-2">
                <dt className="label-m w-28 shrink-0 text-[11px] text-muted">{en.findingDetail.confidence}</dt>
                <dd className="text-body">{(detail.ai.confidence ?? 0).toFixed(2)}</dd>
              </div>
            )}
            {detail.ai.assumptions.length > 0 && (
              <div>
                <dt className="label-m mb-1 text-[11px] text-muted">{en.findingDetail.assumptions}</dt>
                <dd>
                  <ul className="list-disc space-y-1 pl-5 text-body">
                    {detail.ai.assumptions.map((assumption, i) => (
                      <li key={i}>{assumption}</li>
                    ))}
                  </ul>
                </dd>
              </div>
            )}
            {detail.ai.rationale && (
              <div>
                <dt className="label-m mb-1 text-[11px] text-muted">{en.findingDetail.rationale}</dt>
                <dd className="text-body">{detail.ai.rationale}</dd>
              </div>
            )}
          </dl>
        ) : (
          <p className="text-sm text-muted">{en.findingDetail.noAssessment}</p>
        )}
      </section>

      <section aria-label={en.findingDetail.scanners} className="card mb-4 p-5">
        <div className="label-m mb-3 text-xs text-ink">{en.findingDetail.scanners}</div>
        <ul className="space-y-2">
          {detail.observations.map((obs, i) => (
            <li key={i} className="border-b border-hairline pb-2 text-sm last:border-0 last:pb-0">
              <span className="label-m mr-2 text-[11px] text-ink">{obs.tool}</span>
              <span className="font-mono text-xs text-muted">{obs.rule_id}</span>
              <p className="mt-1 text-body">{obs.message}</p>
              <p className="font-mono text-xs text-muted">
                {obs.file}:{obs.line}
              </p>
            </li>
          ))}
        </ul>
      </section>

      <section aria-label={en.findingDetail.evidence} className="mb-4">
        <div className="label-m mb-3 text-xs text-ink">{en.findingDetail.evidence}</div>
        <CodeViewer blocks={detail.code.blocks} taintPath={detail.code.taint_path} />
      </section>

      <section aria-label={en.findingDetail.verification} className="card mb-4 overflow-x-auto p-5">
        <div className="label-m mb-3 text-xs text-ink">{en.findingDetail.verification}</div>
        {detail.verification.checks.length > 0 ? (
          <table className="w-full border-collapse text-left text-sm">
            <thead>
              <tr className="border-b border-hairline">
                <th scope="col" className="label-m px-2 py-2 text-[11px] text-muted">
                  Claim
                </th>
                <th scope="col" className="label-m px-2 py-2 text-[11px] text-muted">
                  Check
                </th>
                <th scope="col" className="label-m px-2 py-2 text-[11px] text-muted">
                  Outcome
                </th>
              </tr>
            </thead>
            <tbody>
              {detail.verification.checks.map((check, i) => (
                <tr key={i} className="border-b border-hairline last:border-0">
                  <td className="px-2 py-2 text-body">{check.claim}</td>
                  <td className="px-2 py-2 font-mono text-xs text-body">{check.check}</td>
                  <td className="px-2 py-2">
                    <span className="label-m border border-hairline px-2 py-0.5 text-[11px] text-body">
                      {check.outcome}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="text-sm text-muted">{en.findingDetail.noVerification}</p>
        )}
        {detail.verification.decision && (
          <p className="mt-3 font-mono text-xs text-muted">
            decision: {detail.verification.decision.previous_status} →{" "}
            {detail.verification.decision.new_status} ({detail.verification.decision.outcome})
          </p>
        )}
      </section>

      <section className="card p-5">
        <button
          onClick={onToggleRaw}
          className="label-m text-xs text-muted transition-colors duration-150 hover:text-ink"
        >
          {showRaw ? "▾" : "▸"} {en.findingDetail.rawJson} (V)
        </button>
        {showRaw && (
          <pre className="mt-3 max-h-96 overflow-auto bg-canvas p-4 font-mono text-xs text-body">
            {JSON.stringify(detail.raw, null, 2)}
          </pre>
        )}
      </section>
    </div>
  );
}
