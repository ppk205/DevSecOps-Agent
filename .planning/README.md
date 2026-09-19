# Project Planning Package

Status: revised planning package ready for review; implementation and experiments have not started. This directory contains the accuracy revision; the original `.planning/` package remains the baseline.

This English package is intended for a collaborator or an agent harness. Start here, then read the project plan and handoff guide. All three files can be shared together without the conversation history.

## Reading order

1. [PROJECT-PLAN.md](PROJECT-PLAN.md) — agreed application scope, architecture, testing protocol, milestones, and completion criteria.
2. [AGENT-HANDOFF.md](AGENT-HANDOFF.md) — implementation task order, ownership boundaries, dependencies, acceptance gates, and copyable agent prompts.
3. In the original workspace, also read the root `AGENTS.md` before editing anything. It governs the thesis and document-generation workflow.

Read the project plan's accuracy table first for requirements and acceptance evidence, then section 3 for shared interfaces and section 4 for evaluation safeguards. Use T00–T10 in the handoff guide for ownership, dependencies, and completion gates. All additions describe planned work; no detection improvement has been measured.

## Project context

Build a local application that detects and classifies the severity of vulnerabilities in Java Servlet/JSP source code, with Agentic AI assisting conventional scanners. AI is a supporting tool; its conclusions require independent mechanical validation.

The thesis is by Tran Doan Hoa (23162026) and Nguyen Minh Khoi (23162046), supervised by Nguyen Thi Thanh Van. The authoritative thesis context is `DeCuongChiTiet_Nhom5_23162026_23162046_NoiDung_v4.docx` in the original workspace. The introduction and Chapter 1 contain the research foundation; later chapters do not contain completed experiments.

The sole experimental application is [JVA-bookstore](https://github.com/Moseyuh333/JVA-bookstore), pinned to commit `dd48d1240fdbc3e5b2ffe8b0a2e3ad65e10d57f5`. Read-only inspection found a Maven WAR project configured for Java 11, javax Servlet, PostgreSQL, 97 main-source Java files, and 38 JSP files. No `src/test` suite was present. Compilation and runtime behavior have not been verified.

## Decisions to preserve

- Python/FastAPI, Jinja templates, SQLite/SQLAlchemy, a separate worker, and a shared CLI/service layer.
- Local dashboard; one scan at a time; no hosted multi-user platform in the first release.
- Java Servlet/JSP is the language being scanned. Python is the scanner application's implementation language, not an expansion of research scope.
- Semgrep CE, SpotBugs/FindSecBugs, OWASP Dependency-Check, and Gitleaks form the planned scanner set.
- CodeQL is an experimental addition compared with that existing combination; it does not imply complete cross-file or JSP coverage.
- BYOK and configurable Chat Completions-compatible providers, including compatible OpenCode Zen models. Other wire protocols need explicit adapters.
- Three evidence levels: static verification, isolated function tests, and optional targeted application sandbox checks. No DAST scanner.
- Two students, 17 weeks, provisional USD 50 AI-usage budget.
- The precision-improvement hypothesis permits at most five percentage points of observed known-case recall loss.
- Reports distinguish confirmed, rejected with evidence, unresolved, and unprocessed findings. Missing evidence never means safe.
- No automatic remediation, fabricated results, or model access to hidden evaluation labels.

The source-code scope is 12 groups: CWE-89, 78, 79, 22, 434, 918, 611, 502, 798, 327, 330, and the combined authorization group CWE-862/639. CWE-1395 is a separate dependency track. This explicit counting convention resolves an ambiguity in the thesis wording; it does not silently edit the thesis. Use actual advisory CWE labels where available rather than relabeling every dependency advisory as CWE-1395.

## Research questions

The revision adds seven accuracy requirements, with unchanged IDs across this package:

| ID | Planned scope |
| --- | --- |
| ACC-01 | Cross-function/cross-file flows and early CodeQL comparison, with extraction/query provenance and explicit coverage limits. |
| ACC-02 | Versioned Java security models and finding-specific route/filter/caller/sink context, developed only on development cases. |
| ACC-03 | Independently reviewed role/resource/operation/ownership policy; missing or disputed expectations remain unresolved. |
| ACC-04 | JSP output-context analysis for HTML text, attributes, URLs, and embedded JavaScript, retaining original positions. |
| ACC-05 | Custom-rule regression suites with vulnerable, difficult safe, and meaning-preserving variants. |
| ACC-06 | Reviewed differential procedures with functionality checks and distinct execution outcomes; structural evidence where execution is unsuitable. |
| ACC-07 | Eligible/analyzed file coverage, unsupported constructs, per-CWE capability, and reasons for missed findings. |

The coordinator owns shared contracts and policy documentation; T02 owns detection/models/context, T03 execution, T04 agent retrieval, T05 validation, T06 presentation, and T07 evaluation. T08–T10 require frozen accuracy checks, comparisons, and reproducible evidence. Both students review intended permissions and reference security observations; generated tests cannot define ground truth.

Compare scanner additions and application-specific models separately from AI assessment on frozen observations. Report per-CWE precision, recall, F1, unresolved rate, and verification coverage with counts, separate Java/JSP coverage, and a separate dependency track. Expected labels, fixed-variant references, and judgments stay outside scanner/agent inputs; the evaluator pairs independent variant results. Keep related variants in the same split and freeze tuning before held-out evaluation.

The planned 24 held-out vulnerable cases mean one miss changes recall by about 4.17 percentage points. The five-point recall-loss criterion is descriptive, not a statistical guarantee; correlated variants do not add independent examples. Report uncertainty, policy assumptions, model overfitting risk, and verification limits. Passing a fixed-variant test does not prove general safety.

Run cross-file and JSP feasibility in weeks 1–2, detection improvements in weeks 3–8, and verification/regression work in weeks 9–12. Keep the dashboard minimal and the 17-week horizon and provisional USD 50 budget unchanged. Report schedule impacts rather than silently removing accuracy requirements.

The research questions remain:

1. Does AI-assisted triage improve precision without exceeding the agreed recall-loss tolerance?
2. How closely do evidence-backed CVSS v4.0 assessments match independently reviewed reference assessments?
3. How do verification levels differ in false-positive reduction, missed findings, runtime, and model cost?
4. How does the proposed application compare with individual tools, their deterministic combination, and a non-agentic model configuration?

## What exists and what comes next

This package contains plans only. It does not contain application code, a target checkout, API credentials, completed ground truth, or measured results. Dataset sizes, budgets, and milestones are planned targets.

Begin with task T00 in the handoff guide: inspect the pinned target, establish the SRS and shared contracts, and attempt a reproducible isolated build. The future `docs/SRS.md`, `docs/IMPLEMENTATION-PLAN.md`, and `docs/TEST-PLAN.md` are implementation deliverables; they are not present in this package.

The source Word documents, `.document-work/` scripts, and thesis headings are outside the implementation tasks. In particular, never modify the original cover/contents Word file. Pending cover wording, thesis length, and illustrations do not block application work.

## Sharing and starting an agent harness

Send the entire `planning-accuracy-revision` directory. In a fresh implementation workspace, install these three reviewed files together as `.planning/` before using the copyable startup prompt; do not mix baseline and revised files. Have the coordinator read them and establish contracts before assigning implementation tasks. Do not let every agent independently choose schemas, dependencies, or source versions. Use the startup prompt and task template in [AGENT-HANDOFF.md](AGENT-HANDOFF.md). Application implementation should use a new directory, as requested by the user.
