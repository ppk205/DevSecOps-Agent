import { useCallback } from "react";
import type { CodeBlock, TaintStep } from "../api/types";
import { useStrings } from "../i18n/lang";

interface CodeViewerProps {
  blocks: CodeBlock[];
  taintPath: TaintStep[];
}

/**
 * Evidence code viewer. Source renders as plain text only (React-escaped,
 * never innerHTML) so untrusted scanner snippets cannot inject markup.
 */
export function CodeViewer({ blocks, taintPath }: CodeViewerProps) {
  const en = useStrings();
  const jumpTo = useCallback((blockKey: string) => {
    const reduced = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
    document
      .getElementById(`code-${blockKey}`)
      ?.scrollIntoView({ behavior: reduced ? "auto" : "smooth", block: "center" });
  }, []);

  if (blocks.length === 0) {
    return (
      <div className="card p-6 text-center">
        <div className="label-m text-sm text-ink">{en.common.emptyTitle}</div>
        <p className="mt-2 text-sm text-body">{en.common.emptyBody}</p>
      </div>
    );
  }

  return (
    <div>
      {taintPath.length > 0 && (
        <div className="mb-4">
          <div className="label-m mb-2 text-[11px] text-muted">{en.findingDetail.taintPath}</div>
          <ol className="flex flex-wrap items-center gap-2">
            {taintPath.map((step, i) => (
              <li key={`${step.block}-${i}`} className="flex items-center gap-2">
                {i > 0 && (
                  <span aria-hidden className="text-muted">
                    →
                  </span>
                )}
                <button
                  onClick={() => jumpTo(step.block)}
                  title={`${step.file}:${step.line}`}
                  className="label-m border border-hairline bg-soft px-2 py-1 font-mono text-[11px] text-body transition-colors duration-150 hover:border-ink hover:text-ink"
                >
                  {step.label || step.file}:{step.line}
                </button>
              </li>
            ))}
          </ol>
        </div>
      )}
      {blocks.map((block) => (
        <figure key={block.key} id={`code-${block.key}`} className="card mb-4 scroll-mt-4 overflow-hidden">
          <figcaption className="flex flex-wrap items-center gap-2 border-b border-hairline bg-soft px-4 py-2">
            <span className="font-mono text-xs text-ink">
              {block.file}:{block.line}
            </span>
            <span className="label-m text-[10px] text-muted">{block.tool}</span>
            {block.rule_id && (
              <span className="label-m border border-hairline px-1.5 py-0.5 font-mono text-[10px] text-body">
                {block.rule_id}
              </span>
            )}
          </figcaption>
          <pre className="overflow-x-auto bg-canvas p-0 font-mono text-xs leading-5">
            {block.lines.map((line) => (
              <div
                key={line.n}
                className={`flex px-4 ${line.highlight ? "bg-[rgba(226,39,24,0.12)]" : ""}`}
              >
                <span aria-hidden className="w-8 shrink-0 select-none text-right text-muted">
                  {line.n}
                </span>
                <code className="whitespace-pre-wrap break-all pl-3 text-body">{line.text}</code>
              </div>
            ))}
          </pre>
        </figure>
      ))}
    </div>
  );
}
